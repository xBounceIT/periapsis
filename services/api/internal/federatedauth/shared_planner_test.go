package federatedauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

type federatedPlanningStateSourceFunc func(
	context.Context,
	FederatedPlanningLookup,
) (FederatedPlanningState, error)

func (function federatedPlanningStateSourceFunc) LoadFederatedPlanningState(
	ctx context.Context,
	lookup FederatedPlanningLookup,
) (FederatedPlanningState, error) {
	return function(ctx, lookup)
}

func TestSharedFederatedPlannerUsesImmutableSubjectLookupAndSharedConsequences(t *testing.T) {
	projection, state := federatedPlannerFixture(t)
	var observed FederatedPlanningLookup
	keyring := federatedPlannerKeyring(t)
	planner, err := NewSharedFederatedPlanner(SharedFederatedPlannerOptions{
		Source: federatedPlanningStateSourceFunc(func(
			_ context.Context,
			lookup FederatedPlanningLookup,
		) (FederatedPlanningState, error) {
			observed = lookup
			return state, nil
		}),
		Keyring: keyring,
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := planner.PlanFederatedAuthentication(context.Background(), PlanningRequest{
		Authentication: projection, Action: "session.create",
	})
	if err != nil {
		t.Fatalf("PlanFederatedAuthentication() error = %v", err)
	}
	pins := projection.OIDCCompletion.Pins
	if observed.Provider != pins.Provider || observed.BindingID != pins.BindingID ||
		observed.SubjectFormat != identity.UTF8ExactSubject || len(observed.SubjectAliases) != 1 ||
		observed.MappingRevision != pins.MappingRevision || observed.AuthorizationRevision != pins.AuthorizationRevision {
		t.Fatalf("lookup = %s", observed)
	}
	if plan.Mapping == nil || plan.Mapping.Disposition() != identity.LDAPPlanAdmitted ||
		plan.Mapping.IdentityAction() != identity.LDAPIdentityCreateUserAndExternalIdentity ||
		plan.Mapping.ProviderAccessAction() != identity.LDAPProviderAccessEnsure ||
		!slices.Equal(plan.RoleIDs, []identity.EntityID{serviceID(113)}) ||
		!slices.Equal(plan.SecurityGroupIDs, []identity.EntityID{serviceID(112)}) ||
		plan.BindingRevision != pins.BindingRevision || plan.ConfigurationRevision != pins.ConfigurationRevision ||
		plan.SecurityRevision != pins.SecurityRevision || plan.MappingRevision != pins.MappingRevision ||
		plan.AuthorizationRevision != pins.AuthorizationRevision || plan.PolicyRevision != pins.AssurancePolicyRevision ||
		plan.Subject == nil || plan.Subject.ExternalIdentityID != state.ExternalIdentityID {
		t.Fatalf("plan = %+v mapping=%v", plan, plan.Mapping)
	}
	decrypted, err := keyring.DecryptExternalSubject(identity.ExternalSubjectContext{
		Provider: pins.Provider, ExternalIdentityID: state.ExternalIdentityID,
	}, plan.Subject.Envelope)
	if err != nil {
		t.Fatalf("DecryptExternalSubject() error = %v", err)
	}
	decryptedAliases, err := keyring.SubjectAliases(pins.Provider, decrypted)
	decrypted.Clear()
	if err != nil || !slices.Equal(decryptedAliases, plan.Subject.Aliases) {
		t.Fatalf("protected subject aliases = %#v, %v", decryptedAliases, err)
	}
}

func TestSharedFederatedPlannerSeparatesPlatformProviderFromTenantAdmission(t *testing.T) {
	projection, state := federatedPlannerFixture(t)
	admission := identity.TenantAdmissionContext{
		TenantID: projection.TenantID, BindingID: projection.Subject.BindingID,
	}
	provider := identity.ProviderContext{
		Scope: identity.PlatformProviderScope, ProviderID: serviceID(130),
	}
	projection.Admission = admission
	projection.Subject.Provider = provider
	projection.OIDCCompletion.Pins.Provider = provider
	projection.OIDCCompletion.Pins.BindingID = identity.EntityID{}
	projection.OIDCCompletion.Pins.Admission = admission
	evidence, ok := providerPrimaryEvidence(
		provider, admission.BindingID, projection.AuthenticatedAt, projection.ValidUntil,
		projection.OIDCCompletion.Pins.SecurityRevision,
	)
	if !ok {
		t.Fatal("platform evidence fixture rejected")
	}
	projection.Evidence = []identity.AssuranceEvidence{evidence}
	state.Mapping.Provider = provider
	state.Mapping.TenantID = admission.TenantID
	state.Mapping.BindingID = admission.BindingID
	poisoned := cloneFederatedPlanningState(state)
	state.Mapping.NoMatchPolicy = identity.LDAPNoMatchProviderAccessOnly
	state.Mapping.Rules = nil
	state.Mapping.SecurityGroups = nil
	state.Mapping.LiveAssignments = nil
	state.Mapping.RolePolicies = nil
	state.Mapping.ExistingEffectiveRoleIDs = nil
	state.Mapping.Delegation = nil
	state.Mapping.LiveOwnedEdges = nil

	var observed FederatedPlanningLookup
	keyring := federatedPlannerKeyring(t)
	planner, err := NewSharedFederatedPlanner(SharedFederatedPlannerOptions{
		Source: federatedPlanningStateSourceFunc(func(
			_ context.Context,
			lookup FederatedPlanningLookup,
		) (FederatedPlanningState, error) {
			observed = lookup
			return state, nil
		}),
		Keyring: keyring,
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := planner.PlanFederatedAuthentication(context.Background(), PlanningRequest{
		Authentication: projection, Action: "session.create",
	})
	if err != nil || plan.Subject == nil || observed.Provider != provider || observed.Admission != admission ||
		observed.TenantID != admission.TenantID || observed.BindingID != admission.BindingID ||
		plan.Mapping == nil || plan.Mapping.Reason() != identity.LDAPPlanReasonProviderAccessOnly ||
		len(plan.RoleIDs) != 0 || len(plan.SecurityGroupIDs) != 0 ||
		len(plan.Mapping.MatchedRuleIDs()) != 0 || len(plan.Mapping.ProspectiveOperatorTeamAssignments()) != 0 ||
		len(plan.Mapping.Changes()) != 0 || !validPlan(plan, projection) {
		t.Fatalf("platform plan=%+v error=%v lookup=%+v", plan, err, observed)
	}
	decrypted, err := keyring.DecryptExternalSubject(identity.ExternalSubjectContext{
		Provider: provider, ExternalIdentityID: state.ExternalIdentityID,
	}, plan.Subject.Envelope)
	if err != nil {
		t.Fatalf("provider-wide subject provenance failed: %v", err)
	}
	decrypted.Clear()

	poisonedPlanner, _ := NewSharedFederatedPlanner(SharedFederatedPlannerOptions{
		Source: federatedPlanningStateSourceFunc(func(context.Context, FederatedPlanningLookup) (FederatedPlanningState, error) {
			return poisoned, nil
		}),
		Keyring: keyring,
	})
	if _, err = poisonedPlanner.PlanFederatedAuthentication(context.Background(), PlanningRequest{
		Authentication: projection, Action: "session.create",
	}); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("platform provider authorization snapshot accepted: %v", err)
	}
	canonicalSubject, err := identity.CanonicalOIDCIssuerSubject(
		projection.Subject.Issuer, projection.Subject.Value,
	)
	if err != nil {
		t.Fatal(err)
	}
	poisonedObservation, err := federatedMappingObservation(projection, canonicalSubject)
	canonicalSubject.Clear()
	if err != nil {
		t.Fatal(err)
	}
	poisonedMapping, err := identity.PlanFederatedMapping(poisonedObservation, poisoned.Mapping)
	if err != nil || poisonedMapping.Disposition() != identity.LDAPPlanAdmitted ||
		len(poisonedMapping.ProspectiveRoleIDs()) == 0 {
		t.Fatalf("poisoned platform mapping fixture = %s, %v", poisonedMapping, err)
	}
	poisonedPlan := plan
	poisonedPlan.Mapping = &poisonedMapping
	poisonedPlan.RoleIDs = poisonedMapping.ProspectiveRoleIDs()
	poisonedPlan.SecurityGroupIDs = poisonedMapping.ProspectiveSecurityGroupIDs()
	if validPlan(poisonedPlan, projection) {
		t.Fatal("service boundary accepted provider-derived platform authority")
	}

	projection.Admission.TenantID = serviceID(131)
	called := false
	planner, _ = NewSharedFederatedPlanner(SharedFederatedPlannerOptions{
		Source: federatedPlanningStateSourceFunc(func(context.Context, FederatedPlanningLookup) (FederatedPlanningState, error) {
			called = true
			return state, nil
		}),
		Keyring: keyring,
	})
	if _, err = planner.PlanFederatedAuthentication(context.Background(), PlanningRequest{
		Authentication: projection, Action: "session.create",
	}); !errors.Is(err, ErrAuthentication) || called {
		t.Fatalf("substituted admission error=%v lookupCalled=%t", err, called)
	}
}

func TestPlatformOIDCPlanActionsRejectImpossibleAdmissionStates(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		identity identity.LDAPIdentityPlanAction
		access   identity.LDAPProviderAccessPlanAction
		want     bool
	}{
		{
			name:     "repeat exact live grant",
			identity: identity.LDAPIdentityNoChange,
			access:   identity.LDAPProviderAccessNoChange,
			want:     true,
		},
		{
			name:     "existing identity repairs missing grant",
			identity: identity.LDAPIdentityNoChange,
			access:   identity.LDAPProviderAccessEnsure,
			want:     true,
		},
		{
			name:     "first JIT creates identity and grant",
			identity: identity.LDAPIdentityCreateUserAndExternalIdentity,
			access:   identity.LDAPProviderAccessEnsure,
			want:     true,
		},
		{
			name:     "new identity cannot claim unchanged access",
			identity: identity.LDAPIdentityCreateUserAndExternalIdentity,
			access:   identity.LDAPProviderAccessNoChange,
		},
		{
			name:     "authentication cannot suspend access",
			identity: identity.LDAPIdentityNoChange,
			access:   identity.LDAPProviderAccessSuspend,
		},
		{
			name:     "unknown identity action fails closed",
			identity: identity.LDAPIdentityPlanAction(255),
			access:   identity.LDAPProviderAccessEnsure,
		},
		{
			name:     "unknown access action fails closed",
			identity: identity.LDAPIdentityNoChange,
			access:   identity.LDAPProviderAccessPlanAction(255),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := validPlatformOIDCPlanActions(test.identity, test.access); got != test.want {
				t.Fatalf("validPlatformOIDCPlanActions(%d, %d) = %t, want %t", test.identity, test.access, got, test.want)
			}
		})
	}
}

func TestSharedFederatedPlannerRejectsEveryStaleOrCrossTenantSnapshot(t *testing.T) {
	projection, valid := federatedPlannerFixture(t)
	for name, mutate := range map[string]func(*FederatedPlanningState){
		"binding":           func(value *FederatedPlanningState) { value.BindingRevision++ },
		"provider revision": func(value *FederatedPlanningState) { value.ProviderRevision++ },
		"security":          func(value *FederatedPlanningState) { value.SecurityRevision++ },
		"policy":            func(value *FederatedPlanningState) { value.AssurancePolicyRevision++ },
		"configuration":     func(value *FederatedPlanningState) { value.Mapping.ConfigurationRevision++ },
		"mapping":           func(value *FederatedPlanningState) { value.Mapping.RuleSetRevision++ },
		"authorization":     func(value *FederatedPlanningState) { value.Mapping.AuthorizationRevision++ },
		"tenant":            func(value *FederatedPlanningState) { value.Mapping.TenantID = serviceID(120) },
		"provider": func(value *FederatedPlanningState) {
			value.Mapping.Provider.TenantID = serviceID(120)
		},
		"identity tuple": func(value *FederatedPlanningState) { value.UserID = serviceID(121) },
		"unexpected subject match for new identity": func(value *FederatedPlanningState) {
			value.SubjectMatch = &FederatedSubjectMatch{
				ExternalIdentityID: value.ExternalIdentityID,
				Alias:              identity.SubjectAlias{KeyVersion: 1, Digest: [sha256.Size]byte{1}},
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			state := valid
			mutate(&state)
			planner, _ := NewSharedFederatedPlanner(SharedFederatedPlannerOptions{
				Source: federatedPlanningStateSourceFunc(func(
					context.Context,
					FederatedPlanningLookup,
				) (FederatedPlanningState, error) {
					return state, nil
				}),
				Keyring: federatedPlannerKeyring(t),
			})
			if _, err := planner.PlanFederatedAuthentication(context.Background(), PlanningRequest{
				Authentication: projection, Action: "session.create",
			}); !errors.Is(err, ErrAuthentication) {
				t.Fatalf("PlanFederatedAuthentication() error = %v", err)
			}
		})
	}
}

func TestSharedFederatedPlannerRejectsOverflowingPersistentRevisionsBeforeLookup(t *testing.T) {
	projection, _ := federatedPlannerFixture(t)
	projection.OIDCCompletion.Pins.ProviderRevision = ^uint64(0)
	called := false
	planner, _ := NewSharedFederatedPlanner(SharedFederatedPlannerOptions{
		Source: federatedPlanningStateSourceFunc(func(
			context.Context,
			FederatedPlanningLookup,
		) (FederatedPlanningState, error) {
			called = true
			return FederatedPlanningState{}, nil
		}),
		Keyring: federatedPlannerKeyring(t),
	})
	if _, err := planner.PlanFederatedAuthentication(context.Background(), PlanningRequest{
		Authentication: projection, Action: "session.create",
	}); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("PlanFederatedAuthentication() error = %v", err)
	}
	if called {
		t.Fatal("overflowing revision reached persistence")
	}
}

func TestSharedFederatedPlannerHonorsCancellationAfterPlanningLoad(t *testing.T) {
	projection, state := federatedPlannerFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	planner, err := NewSharedFederatedPlanner(SharedFederatedPlannerOptions{
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
	if plan, err := planner.PlanFederatedAuthentication(ctx, PlanningRequest{
		Authentication: projection, Action: "session.create",
	}); !errors.Is(err, ErrAuthentication) || plan.PlanRevision != 0 {
		t.Fatalf("PlanFederatedAuthentication() = %s, %v", plan, err)
	}
}

func TestSharedFederatedPlannerBindsExistingIdentityToExactReturnedAlias(t *testing.T) {
	projection, state := federatedPlannerFixture(t)
	state.UserID = serviceID(116)
	state.IdentityEpoch = 7
	state.Mapping.ProviderAccess.ExternalIdentityExists = true
	state.Mapping.ProviderAccess.UserActive = true
	state.Mapping.ProviderAccess.TenantMembershipExists = true
	state.Mapping.ProviderAccess.TenantMembershipActive = true
	state.Mapping.ProviderAccess.AccessGrantLive = true

	for name, mismatch := range map[string]string{
		"exact": "", "mismatched digest": "digest", "mismatched identity": "identity",
	} {
		t.Run(name, func(t *testing.T) {
			planner, err := NewSharedFederatedPlanner(SharedFederatedPlannerOptions{
				Source: federatedPlanningStateSourceFunc(func(
					_ context.Context,
					lookup FederatedPlanningLookup,
				) (FederatedPlanningState, error) {
					alias := lookup.SubjectAliases[0]
					if mismatch == "digest" {
						alias.Digest[0] ^= 0xff
					}
					match := FederatedSubjectMatch{
						ExternalIdentityID: state.ExternalIdentityID, Alias: alias,
					}
					if mismatch == "identity" {
						match.ExternalIdentityID = serviceID(117)
					}
					state.SubjectMatch = &match
					return state, nil
				}),
				Keyring: federatedPlannerKeyring(t),
			})
			if err != nil {
				t.Fatal(err)
			}
			plan, planErr := planner.PlanFederatedAuthentication(context.Background(), PlanningRequest{
				Authentication: projection, Action: "session.create",
			})
			if mismatch == "" {
				if planErr != nil || plan.UserID != state.UserID || plan.IdentityEpoch != state.IdentityEpoch {
					t.Fatalf("existing identity plan = %+v, %v", plan, planErr)
				}
			} else if !errors.Is(planErr, ErrAuthentication) {
				t.Fatalf("mismatched alias error = %v", planErr)
			}
		})
	}
}

func TestSharedFederatedPlannerDefensivelyOwnsLookupAliases(t *testing.T) {
	projection, state := federatedPlannerFixture(t)
	var sourceAlias identity.SubjectAlias
	planner, err := NewSharedFederatedPlanner(SharedFederatedPlannerOptions{
		Source: federatedPlanningStateSourceFunc(func(
			_ context.Context,
			lookup FederatedPlanningLookup,
		) (FederatedPlanningState, error) {
			sourceAlias = lookup.SubjectAliases[0]
			clear(lookup.SubjectAliases[0].Digest[:])
			return state, nil
		}),
		Keyring: federatedPlannerKeyring(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := planner.PlanFederatedAuthentication(context.Background(), PlanningRequest{
		Authentication: projection, Action: "session.create",
	})
	if err != nil || plan.Subject == nil || len(plan.Subject.Aliases) != 1 ||
		plan.Subject.Aliases[0] != sourceAlias {
		t.Fatalf("plan alias ownership = %+v, %v", plan.Subject, err)
	}
}

func TestCloneFederatedPlanningStateOwnsRequirementAndSubjectMatch(t *testing.T) {
	_, original := federatedPlannerFixture(t)
	deadline := serviceTestNow.Add(time.Hour)
	original.Requirement.EnrollmentDeadline = &deadline
	original.SubjectMatch = &FederatedSubjectMatch{
		ExternalIdentityID: original.ExternalIdentityID,
		Alias:              identity.SubjectAlias{KeyVersion: 1, Digest: [sha256.Size]byte{1}},
	}
	clone := cloneFederatedPlanningState(original)
	original.Requirement.PolicyRevisions[0].Revision++
	*original.Requirement.EnrollmentDeadline = original.Requirement.EnrollmentDeadline.Add(time.Hour)
	original.SubjectMatch.ExternalIdentityID = serviceID(119)
	if clone.Requirement.PolicyRevisions[0].Revision == original.Requirement.PolicyRevisions[0].Revision ||
		clone.Requirement.EnrollmentDeadline.Equal(*original.Requirement.EnrollmentDeadline) ||
		clone.SubjectMatch.ExternalIdentityID == original.SubjectMatch.ExternalIdentityID {
		t.Fatal("cloned planning state retained mutable source storage")
	}
}

func TestNewSharedFederatedPlannerRequiresSourceAndKeyring(t *testing.T) {
	source := federatedPlanningStateSourceFunc(func(
		context.Context,
		FederatedPlanningLookup,
	) (FederatedPlanningState, error) {
		return FederatedPlanningState{}, nil
	})
	for name, options := range map[string]SharedFederatedPlannerOptions{
		"missing source":  {Keyring: federatedPlannerKeyring(t)},
		"missing keyring": {Source: source},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewSharedFederatedPlanner(options); !errors.Is(err, ErrInvalidOptions) {
				t.Fatalf("NewSharedFederatedPlanner() error = %v", err)
			}
		})
	}
}

func TestSharedFederatedPlannerNoMatchDeniesAndNeverFallsBackToEmail(t *testing.T) {
	projection, state := federatedPlannerFixture(t)
	projection.Groups = []string{"unmapped-group"}
	projection.Scalars[0].Value = "Finance"
	projection.Profiles[0].Value = "same-as-an-existing-local-user@example.test"
	var lookup FederatedPlanningLookup
	planner, _ := NewSharedFederatedPlanner(SharedFederatedPlannerOptions{
		Source: federatedPlanningStateSourceFunc(func(
			_ context.Context,
			value FederatedPlanningLookup,
		) (FederatedPlanningState, error) {
			lookup = value
			return state, nil
		}),
		Keyring: federatedPlannerKeyring(t),
	})
	if _, err := planner.PlanFederatedAuthentication(context.Background(), PlanningRequest{
		Authentication: projection, Action: "session.create",
	}); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("PlanFederatedAuthentication() error = %v", err)
	}
	if len(lookup.SubjectAliases) != 1 || strings.Contains(lookup.String(), "same-as-an-existing") {
		t.Fatalf("lookup used mutable profile: %s", lookup)
	}
}

func TestSharedFederatedPlannerFormattingRedactsIdentityMaterial(t *testing.T) {
	projection, state := federatedPlannerFixture(t)
	planner, err := NewSharedFederatedPlanner(SharedFederatedPlannerOptions{
		Source: federatedPlanningStateSourceFunc(func(context.Context, FederatedPlanningLookup) (FederatedPlanningState, error) {
			return state, nil
		}),
		Keyring: federatedPlannerKeyring(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	lookup, subject, ok := planner.oidcFederatedPlanningLookup(projection)
	if !ok {
		t.Fatal("valid lookup rejected")
	}
	subject.Clear()
	formatted := lookup.String() + "|" + state.String()
	for _, canary := range []string{"issuer-private", "immutable-subject", "private-email", "DFIR"} {
		if strings.Contains(formatted, canary) {
			t.Fatalf("format leaked %q: %s", canary, formatted)
		}
	}
}

func federatedPlannerFixture(t *testing.T) (AuthenticationProjection, FederatedPlanningState) {
	t.Helper()
	tenantID := serviceID(101)
	provider := identity.ProviderContext{
		Scope: identity.TenantProviderScope, TenantID: tenantID, ProviderID: serviceID(102),
	}
	bindingID := serviceID(103)
	completion := oidcCompletionFixture(provider, bindingID, "/cases")
	completion.Pins.BindingRevision = 11
	completion.Pins.ConfigurationRevision = 12
	completion.Pins.SecurityRevision = 13
	completion.Pins.MappingRevision = 14
	completion.Pins.AuthorizationRevision = 15
	completion.Pins.AssurancePolicyRevision = 16
	evidence, ok := providerPrimaryEvidence(
		provider, bindingID, serviceTestNow.Add(-time.Minute), serviceTestNow.Add(time.Hour),
		completion.Pins.SecurityRevision,
	)
	if !ok {
		t.Fatal("evidence fixture rejected")
	}
	projection := AuthenticationProjection{
		Protocol: ProtocolOIDC, TenantID: tenantID,
		Subject: ExternalSubject{
			Provider: provider, BindingID: bindingID,
			Issuer: "https://issuer-private.example", Value: "immutable-subject",
		},
		AuthenticatedAt: serviceTestNow.Add(-time.Minute), ValidUntil: serviceTestNow.Add(time.Hour),
		Scalars:  []NamedValue{{Name: "department", Value: "DFIR"}},
		Profiles: []ProfileValue{{Field: "email", Value: "private-email@example.test"}},
		Groups:   []string{"incident-command"}, Evidence: []identity.AssuranceEvidence{evidence},
		OIDCCompletion: completion,
	}
	groupMatcher, err := identity.CompileFederatedMappingMatcher(identity.FederatedMappingMatcherSpec{
		Kind: identity.FederatedMappingGroupEquals, Value: "incident-command",
	})
	if err != nil {
		t.Fatal(err)
	}
	state := FederatedPlanningState{
		PlanRevision: 21, ProviderRevision: completion.Pins.ProviderRevision,
		ExternalIdentityID:      serviceID(115),
		BindingRevision:         completion.Pins.BindingRevision,
		SecurityRevision:        completion.Pins.SecurityRevision,
		AssurancePolicyRevision: completion.Pins.AssurancePolicyRevision,
		Mapping: identity.FederatedPlanningSnapshot{
			TenantID: tenantID, Provider: provider, BindingID: bindingID,
			ConfigurationRevision: int64(completion.Pins.ConfigurationRevision),
			RuleSetRevision:       int64(completion.Pins.MappingRevision),
			AuthorizationRevision: int64(completion.Pins.AuthorizationRevision),
			JITMode:               identity.LDAPJITCreate, NoMatchPolicy: identity.LDAPNoMatchDeny,
			ProviderAccess: identity.LDAPProviderAccessState{
				SourceID: serviceID(104), AccessEpochID: serviceID(105),
			},
			Rules: []identity.FederatedMappingRule{{
				RuleID: serviceID(106), RuleEpochID: serviceID(107), SourceID: serviceID(108),
				Revision: 1, Priority: 1, Enabled: true, Matcher: groupMatcher,
				Mode: identity.LDAPReconciliationAuthoritative, SecurityGroupID: serviceID(112),
				RoleIDs: []identity.EntityID{serviceID(113)},
			}},
			SecurityGroups: []identity.LDAPSecurityGroupPolicy{{SecurityGroupID: serviceID(112)}},
			RolePolicies:   []identity.LDAPRolePolicy{{RoleID: serviceID(113)}},
		},
		Requirement: identity.EffectiveAssuranceRequirement{
			Level:           identity.AssurancePrimary,
			PolicyRevisions: []identity.AssurancePolicyRevision{{PolicyID: serviceID(114), Revision: 16}},
		},
		HasEnrollableFactor: true,
	}
	return projection, state
}

func federatedPlannerKeyring(t *testing.T) identity.Keyring {
	t.Helper()
	keyring, err := identity.NewKeyring(1, map[int16][]byte{
		1: bytes.Repeat([]byte{0x7a}, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	return keyring
}
