package federatedauth

import (
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
	"testing"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
)

func TestSAMLSharedFederatedPlannerBindsExactSubjectTupleAndMappingPins(t *testing.T) {
	projection, state := samlPlannerProjectionFixture(t)
	keyring := federatedPlannerKeyring(t)
	var observed FederatedPlanningLookup
	planner, err := NewSAMLSharedFederatedPlanner(SAMLSharedFederatedPlannerOptions{
		Source: federatedPlanningStateSourceFunc(func(
			_ context.Context,
			lookup FederatedPlanningLookup,
		) (FederatedPlanningState, error) {
			observed = cloneFederatedPlanningLookup(lookup)
			return state, nil
		}),
		Keyring: keyring,
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := planner.PlanSAMLAuthentication(context.Background(), SAMLPlanningRequest{
		Authentication: projection, Action: "session.create",
	})
	if err != nil {
		t.Fatalf("PlanSAMLAuthentication() error=%v", err)
	}
	pins := projection.Consumption.Pins
	if observed.Protocol != ProtocolSAML || observed.Provider != pins.Provider || observed.BindingID != pins.BindingID ||
		observed.BindingRevision != pins.BindingRevision || observed.AuthorizationRevision != pins.AuthorizationRevision ||
		observed.SubjectFormat != identity.UTF8ExactSubject || len(observed.SubjectAliases) != 1 {
		t.Fatalf("lookup=%v", observed)
	}
	if plan.Mapping == nil || plan.Mapping.Disposition() != identity.LDAPPlanAdmitted ||
		plan.Mapping.IdentityAction() != identity.LDAPIdentityCreateUserAndExternalIdentity ||
		plan.Subject == nil || plan.Subject.ExternalIdentityID != state.ExternalIdentityID ||
		plan.BindingRevision != pins.BindingRevision || plan.AuthorizationRevision != pins.AuthorizationRevision ||
		!slices.Equal(plan.RoleIDs, []identity.EntityID{serviceID(113)}) ||
		!slices.Equal(plan.SecurityGroupIDs, []identity.EntityID{serviceID(112)}) {
		t.Fatalf("plan=%+v", plan)
	}
	decrypted, err := keyring.DecryptExternalSubject(identity.ExternalSubjectContext{
		Provider: pins.Provider, ExternalIdentityID: state.ExternalIdentityID,
	}, plan.Subject.Envelope)
	if err != nil {
		t.Fatalf("DecryptExternalSubject() error=%v", err)
	}
	aliases, aliasErr := keyring.SubjectAliases(pins.Provider, decrypted)
	decrypted.Clear()
	if aliasErr != nil || !slices.Equal(aliases, plan.Subject.Aliases) {
		t.Fatalf("aliases=%#v error=%v", aliases, aliasErr)
	}
}

func TestCanonicalSAMLSubjectIsDomainSeparatedAcrossEveryIdentityComponent(t *testing.T) {
	base := SAMLSubjectIdentity{
		Source: federatedsaml.SubjectPersistentNameID, Name: "NameID", Format: testSAMLPersistentNameID,
		Value: "ExactSubject",
	}
	keyring := federatedPlannerKeyring(t)
	provider := identity.ProviderContext{
		Scope: identity.TenantProviderScope, TenantID: serviceID(121), ProviderID: serviceID(122),
	}
	aliases := make([]identity.SubjectAlias, 0, 5)
	for _, input := range []struct {
		issuer  string
		subject SAMLSubjectIdentity
	}{
		{issuer: "https://idp.example/A", subject: base},
		{issuer: "https://idp.example/a", subject: base},
		{issuer: "https://idp.example/A", subject: func() SAMLSubjectIdentity { value := base; value.Value = "exactsubject"; return value }()},
		{issuer: "https://idp.example/A", subject: func() SAMLSubjectIdentity {
			value := base
			value.Source = federatedsaml.SubjectImmutableAttribute
			return value
		}()},
		{issuer: "https://idp.example/A", subject: func() SAMLSubjectIdentity { value := base; value.Format = "urn:other"; return value }()},
	} {
		subject, err := identity.CanonicalSAMLSubjectTuple(
			input.issuer, string(input.subject.Source), input.subject.Name, input.subject.Format, input.subject.Value,
		)
		if err != nil {
			t.Fatalf("CanonicalSAMLSubjectTuple() error=%v", err)
		}
		values, err := keyring.SubjectAliases(provider, subject)
		subject.Clear()
		if err != nil || len(values) != 1 {
			t.Fatalf("SubjectAliases()=%v,%v", values, err)
		}
		aliases = append(aliases, values[0])
	}
	for left := range aliases {
		for right := left + 1; right < len(aliases); right++ {
			if aliases[left] == aliases[right] {
				t.Fatalf("aliases %d and %d collided", left, right)
			}
		}
	}
}

func TestSAMLSharedFederatedPlannerRejectsHostileOrStaleInputsWithoutStateMutation(t *testing.T) {
	projection, state := samlPlannerProjectionFixture(t)
	calls := 0
	planner, err := NewSAMLSharedFederatedPlanner(SAMLSharedFederatedPlannerOptions{
		Source: federatedPlanningStateSourceFunc(func(context.Context, FederatedPlanningLookup) (FederatedPlanningState, error) {
			calls++
			return state, nil
		}),
		Keyring: federatedPlannerKeyring(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*SAMLPlanningRequest){
		"wrong action": func(value *SAMLPlanningRequest) { value.Action = "session.read" },
		"missing binding revision": func(value *SAMLPlanningRequest) {
			value.Authentication.Consumption.Pins.BindingRevision = 0
		},
		"control subject": func(value *SAMLPlanningRequest) { value.Authentication.Subject.Value = "subject\nsecret" },
		"unsorted groups": func(value *SAMLPlanningRequest) { value.Authentication.Groups = []string{"z", "a"} },
		"transient persistent subject": func(value *SAMLPlanningRequest) {
			value.Authentication.Subject.Format = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
		},
		"primary evidence elevated": func(value *SAMLPlanningRequest) {
			value.Authentication.Evidence[0].Level = identity.AssuranceMFA
		},
		"primary evidence stale revision": func(value *SAMLPlanningRequest) {
			revision := *value.Authentication.Evidence[0].TrustRuleRevision + 1
			value.Authentication.Evidence[0].TrustRuleRevision = &revision
		},
		"oversized scalar projection": func(value *SAMLPlanningRequest) {
			value.Authentication.Scalars = make([]NamedValue, federatedsaml.DefaultLimits().MaxMappedScalars+1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			request := SAMLPlanningRequest{Authentication: cloneSAMLAuthenticationProjection(projection), Action: "session.create"}
			mutate(&request)
			before := calls
			if _, err := planner.PlanSAMLAuthentication(context.Background(), request); !errors.Is(err, ErrAuthentication) || calls != before {
				t.Fatalf("error=%v calls=%d before=%d", err, calls, before)
			}
		})
	}

	stale := state
	stale.BindingRevision++
	planner.source = federatedPlanningStateSourceFunc(func(context.Context, FederatedPlanningLookup) (FederatedPlanningState, error) {
		calls++
		return stale, nil
	})
	if _, err := planner.PlanSAMLAuthentication(context.Background(), SAMLPlanningRequest{
		Authentication: projection, Action: "session.create",
	}); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("stale state error=%v", err)
	}
}

func TestSAMLSharedFederatedPlannerHonorsCancellationAfterPlanningLoad(t *testing.T) {
	projection, state := samlPlannerProjectionFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	planner, err := NewSAMLSharedFederatedPlanner(SAMLSharedFederatedPlannerOptions{
		Source: federatedPlanningStateSourceFunc(func(
			context.Context,
			FederatedPlanningLookup,
		) (FederatedPlanningState, error) {
			cancel()
			return state, nil
		}),
		Keyring: federatedPlannerKeyring(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan, err := planner.PlanSAMLAuthentication(ctx, SAMLPlanningRequest{
		Authentication: projection, Action: "session.create",
	}); !errors.Is(err, ErrAuthentication) || plan.PlanRevision != 0 {
		t.Fatalf("PlanSAMLAuthentication() = %s, %v", plan, err)
	}
}

func TestSAMLPlannerFormattingNeverExposesIdentityMaterial(t *testing.T) {
	projection, _ := samlPlannerProjectionFixture(t)
	formatted := []string{
		projection.String(),
		SAMLPlanningRequest{Authentication: projection, Action: "session.create"}.String(),
		(&SAMLSharedFederatedPlanner{}).String(),
	}
	for _, value := range formatted {
		for _, secret := range []string{"issuer-secret", "ExactSubject", "private@example.test", "incident-command"} {
			if strings.Contains(value, secret) {
				t.Fatalf("format leaked %q: %s", secret, value)
			}
		}
	}
}

func samlPlannerProjectionFixture(t *testing.T) (SAMLAuthenticationProjection, FederatedPlanningState) {
	t.Helper()
	oidcProjection, state := federatedPlannerFixture(t)
	pins := oidcProjection.OIDCCompletion.Pins
	var transactionID federatedsaml.TransactionID
	transactionID[0] = 1
	consumption := federatedsaml.ConsumptionRequest{
		TransactionID: transactionID, MaterialID: serviceID(19), ExpectedVersion: 1,
		Pins: federatedsaml.TransactionPins{
			Provider: pins.Provider, BindingID: pins.BindingID, ProviderRevision: pins.ProviderRevision,
			BindingRevision: pins.BindingRevision, ConfigurationRevision: pins.ConfigurationRevision,
			SecurityRevision: pins.SecurityRevision, MappingRevision: pins.MappingRevision,
			AuthorizationRevision: pins.AuthorizationRevision, AssurancePolicyRevision: pins.AssurancePolicyRevision,
			MetadataRevision: 17, MetadataDigest: sha256.Sum256([]byte("metadata")), SPKeyRevision: 18,
			ConfigurationDigest: sha256.Sum256([]byte("configuration")),
		},
		ResponseID: "_response", AssertionID: "_assertion", ConsumedAt: serviceTestNow,
		ReturnPath: "/cases",
	}
	return SAMLAuthenticationProjection{
		TenantID: oidcProjection.TenantID, Provider: oidcProjection.Subject.Provider,
		BindingID: oidcProjection.Subject.BindingID, Issuer: "https://issuer-secret.example",
		Subject: SAMLSubjectIdentity{
			Source: federatedsaml.SubjectPersistentNameID, Name: "NameID", Format: testSAMLPersistentNameID,
			Value: "ExactSubject",
		},
		AuthenticatedAt: oidcProjection.AuthenticatedAt, ValidUntil: oidcProjection.ValidUntil,
		Scalars:  append([]NamedValue(nil), oidcProjection.Scalars...),
		Profiles: append([]ProfileValue(nil), oidcProjection.Profiles...),
		Groups:   append([]string(nil), oidcProjection.Groups...), Evidence: cloneEvidence(oidcProjection.Evidence),
		Consumption: consumption,
	}, state
}

func FuzzCanonicalSAMLSubjectNeverConflatesTupleBoundaries(f *testing.F) {
	f.Add("https://idp.example", "NameID", testSAMLPersistentNameID, "subject")
	f.Add("issuer:4:name", "name", "format", "value")
	f.Fuzz(func(t *testing.T, issuer, name, format, value string) {
		if len(issuer)+len(name)+len(format)+len(value) > 3_500 {
			t.Skip()
		}
		_, _ = identity.CanonicalSAMLSubjectTuple(
			issuer, string(federatedsaml.SubjectPersistentNameID), name, format, value,
		)
	})
}
