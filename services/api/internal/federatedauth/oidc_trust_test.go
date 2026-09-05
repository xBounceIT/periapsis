package federatedauth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

type oidcTrustSnapshotSourceFunc func(context.Context, OIDCTrustLookup) (OIDCTrustSnapshot, error)

func TestFederatedRevisionValidatorsUseJSONSafeCeiling(t *testing.T) {
	t.Parallel()

	if !validDatabaseRevision(maximumJSONSafeRevision) ||
		!validSAMLRevision(maximumJSONSafeRevision) {
		t.Fatal("last JSON-safe federated revision was rejected")
	}
	if validDatabaseRevision(maximumJSONSafeRevision+1) ||
		validSAMLRevision(maximumJSONSafeRevision+1) {
		t.Fatal("federated revision beyond the JSON-safe ceiling was accepted")
	}
	if !validDatabaseSuccessorRevision(maximumJSONSafeRevision-1) ||
		validDatabaseSuccessorRevision(maximumJSONSafeRevision) ||
		!validSAMLSuccessorRevision(maximumJSONSafeRevision-1) ||
		validSAMLSuccessorRevision(maximumJSONSafeRevision) {
		t.Fatal("federated successor headroom was not enforced")
	}
}

func (function oidcTrustSnapshotSourceFunc) LoadOIDCTrustSnapshot(
	ctx context.Context,
	lookup OIDCTrustLookup,
) (OIDCTrustSnapshot, error) {
	return function(ctx, lookup)
}

func TestPinnedOIDCTrustResolverMatchesExactACRAndRequiredAMR(t *testing.T) {
	request := oidcTrustRequestFixture()
	acr := request.ACR
	firstID, secondID := serviceID(70), serviceID(71)
	wantedLookup := oidcTrustLookupFromRequest(request)
	resolver := mustOIDCTrustResolver(t, oidcTrustSnapshotSourceFunc(func(
		_ context.Context,
		lookup OIDCTrustLookup,
	) (OIDCTrustSnapshot, error) {
		if lookup != wantedLookup {
			t.Fatalf("lookup = %+v, want %+v", lookup, wantedLookup)
		}
		return OIDCTrustSnapshot{OIDCTrustLookup: lookup, Rules: []OIDCTrustRule{
			{
				RuleID: secondID, Revision: 12, Enabled: true, Level: identity.AssuranceMFA,
				RequiredAMR: []string{"mfa", "pwd"}, MaximumAuthenticationAge: 20 * time.Minute,
			},
			{
				RuleID: firstID, Revision: 11, Enabled: true, Level: identity.AssurancePhishingResistant,
				ACR: &acr, RequiredAMR: []string{"hwk", "mfa"}, MaximumAuthenticationAge: 10 * time.Minute,
			},
		}}, nil
	}))
	evidence, err := resolver.ResolveOIDCAssurance(context.Background(), request)
	if err != nil {
		t.Fatalf("ResolveOIDCAssurance() error = %v", err)
	}
	if len(evidence) != 2 || evidence[0].Level != identity.AssurancePhishingResistant ||
		evidence[1].Level != identity.AssuranceMFA || evidence[0].TrustRuleRevision == nil ||
		*evidence[0].TrustRuleRevision != int64(request.SecurityRevision) ||
		evidence[1].TrustRuleRevision == nil ||
		*evidence[1].TrustRuleRevision != int64(request.SecurityRevision) || evidence[0].ExpiresAt == nil ||
		!evidence[0].ExpiresAt.Equal(request.AuthenticatedAt.Add(10*time.Minute)) {
		t.Fatalf("evidence = %+v", evidence)
	}
	for _, proof := range evidence {
		if proof.Source.ProviderID != request.Provider.ProviderID || proof.Source.BindingID != request.BindingID ||
			proof.Source.Local || proof.FactorRevision != nil {
			t.Fatalf("invalid evidence source: %+v", proof)
		}
	}
}

func TestPinnedOIDCTrustResolverAcceptsPlatformProviderTenantAdmission(t *testing.T) {
	request := oidcTrustRequestFixture()
	request.Provider = identity.ProviderContext{
		Scope: identity.PlatformProviderScope, ProviderID: serviceID(75),
	}
	request.Admission = identity.TenantAdmissionContext{
		TenantID: request.TenantID, BindingID: request.BindingID,
	}
	resolver := mustOIDCTrustResolver(t, oidcTrustSnapshotSourceFunc(func(
		_ context.Context,
		lookup OIDCTrustLookup,
	) (OIDCTrustSnapshot, error) {
		return OIDCTrustSnapshot{OIDCTrustLookup: lookup}, nil
	}))
	evidence, err := resolver.ResolveOIDCAssurance(context.Background(), request)
	if err != nil || len(evidence) != 0 {
		t.Fatalf("ResolveOIDCAssurance() = %+v, %v", evidence, err)
	}

	request.Admission.BindingID = serviceID(76)
	if _, err = resolver.ResolveOIDCAssurance(context.Background(), request); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("substituted admission error = %v", err)
	}
}

func TestPinnedOIDCTrustResolverIsCaseSensitiveAndDefaultsToNoTrust(t *testing.T) {
	request := oidcTrustRequestFixture()
	configuredACR := request.ACR
	rules := []OIDCTrustRule{{
		RuleID: serviceID(72), Revision: 1, Enabled: true, Level: identity.AssuranceMFA,
		ACR: &configuredACR, RequiredAMR: []string{"mfa"}, MaximumAuthenticationAge: time.Hour,
	}}
	resolver := mustOIDCTrustResolver(t, oidcTrustSnapshotSourceFunc(func(
		_ context.Context,
		lookup OIDCTrustLookup,
	) (OIDCTrustSnapshot, error) {
		return OIDCTrustSnapshot{OIDCTrustLookup: lookup, Rules: rules}, nil
	}))
	for name, mutate := range map[string]func(*OIDCTrustRequest){
		"acr": func(value *OIDCTrustRequest) { value.ACR = strings.ToUpper(value.ACR) },
		"amr": func(value *OIDCTrustRequest) { value.AMR = []string{"MFA"} },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := request
			mutate(&candidate)
			evidence, err := resolver.ResolveOIDCAssurance(context.Background(), candidate)
			if err != nil || len(evidence) != 0 {
				t.Fatalf("ResolveOIDCAssurance() = %+v, %v", evidence, err)
			}
		})
	}
}

func TestPinnedOIDCTrustResolverRejectsStaleSnapshotPins(t *testing.T) {
	request := oidcTrustRequestFixture()
	for name, mutate := range map[string]func(*OIDCTrustSnapshot){
		"tenant":            func(value *OIDCTrustSnapshot) { value.TenantID = serviceID(80) },
		"provider":          func(value *OIDCTrustSnapshot) { value.Provider.ProviderID = serviceID(81) },
		"binding":           func(value *OIDCTrustSnapshot) { value.BindingID = serviceID(82) },
		"provider revision": func(value *OIDCTrustSnapshot) { value.ProviderRevision++ },
		"binding revision":  func(value *OIDCTrustSnapshot) { value.BindingRevision++ },
		"security revision": func(value *OIDCTrustSnapshot) { value.SecurityRevision++ },
		"policy revision":   func(value *OIDCTrustSnapshot) { value.AssurancePolicyRevision++ },
	} {
		t.Run(name, func(t *testing.T) {
			resolver := mustOIDCTrustResolver(t, oidcTrustSnapshotSourceFunc(func(
				_ context.Context,
				lookup OIDCTrustLookup,
			) (OIDCTrustSnapshot, error) {
				snapshot := OIDCTrustSnapshot{OIDCTrustLookup: lookup}
				mutate(&snapshot)
				return snapshot, nil
			}))
			if _, err := resolver.ResolveOIDCAssurance(context.Background(), request); !errors.Is(err, ErrAuthentication) {
				t.Fatalf("ResolveOIDCAssurance() error = %v", err)
			}
		})
	}
}

func TestPinnedOIDCTrustResolverHonorsCancellationAfterPersistence(t *testing.T) {
	request := oidcTrustRequestFixture()
	ctx, cancel := context.WithCancel(context.Background())
	resolver := mustOIDCTrustResolver(t, oidcTrustSnapshotSourceFunc(func(
		_ context.Context,
		lookup OIDCTrustLookup,
	) (OIDCTrustSnapshot, error) {
		cancel()
		return OIDCTrustSnapshot{OIDCTrustLookup: lookup}, nil
	}))
	if evidence, err := resolver.ResolveOIDCAssurance(ctx, request); !errors.Is(err, ErrAuthentication) || len(evidence) != 0 {
		t.Fatalf("ResolveOIDCAssurance() = %+v, %v", evidence, err)
	}
}

func TestPinnedOIDCTrustResolverRejectsMalformedInputsAndRules(t *testing.T) {
	request := oidcTrustRequestFixture()
	called := false
	resolver := mustOIDCTrustResolver(t, oidcTrustSnapshotSourceFunc(func(
		_ context.Context,
		lookup OIDCTrustLookup,
	) (OIDCTrustSnapshot, error) {
		called = true
		return OIDCTrustSnapshot{OIDCTrustLookup: lookup}, nil
	}))
	for name, mutate := range map[string]func(*OIDCTrustRequest){
		"zero revision": func(value *OIDCTrustRequest) { value.SecurityRevision = 0 },
		"overflow":      func(value *OIDCTrustRequest) { value.ProviderRevision = ^uint64(0) },
		"platform": func(value *OIDCTrustRequest) {
			value.Provider.Scope = identity.PlatformProviderScope
			value.Provider.TenantID = identity.EntityID{}
		},
	} {
		t.Run(name, func(t *testing.T) {
			called = false
			candidate := request
			mutate(&candidate)
			if _, err := resolver.ResolveOIDCAssurance(context.Background(), candidate); !errors.Is(err, ErrAuthentication) {
				t.Fatalf("ResolveOIDCAssurance() error = %v", err)
			}
			if called {
				t.Fatal("malformed request reached persistence")
			}
		})
	}

	for name, mutate := range map[string]func(*OIDCTrustRequest){
		"unsorted amr":  func(value *OIDCTrustRequest) { value.AMR = []string{"pwd", "mfa"} },
		"duplicate amr": func(value *OIDCTrustRequest) { value.AMR = []string{"mfa", "mfa"} },
		"directional":   func(value *OIDCTrustRequest) { value.ACR = "trusted\u202e" },
		"over limit": func(value *OIDCTrustRequest) {
			value.AMR = make([]string, maximumOIDCTrustAMRValues+1)
		},
	} {
		t.Run("untrusted evidence "+name, func(t *testing.T) {
			called = false
			candidate := request
			mutate(&candidate)
			evidence, err := resolver.ResolveOIDCAssurance(context.Background(), candidate)
			if err != nil || len(evidence) != 0 {
				t.Fatalf("ResolveOIDCAssurance() = %+v, %v", evidence, err)
			}
			if !called {
				t.Fatal("untrusted evidence skipped exact policy recheck")
			}
		})
	}

	validACR := request.ACR
	for name, rule := range map[string]OIDCTrustRule{
		"empty condition": {
			RuleID: serviceID(83), Revision: 1, Level: identity.AssuranceMFA,
			MaximumAuthenticationAge: time.Hour,
		},
		"primary upgrade": {
			RuleID: serviceID(83), Revision: 1, Level: identity.AssurancePrimary,
			ACR: &validACR, MaximumAuthenticationAge: time.Hour,
		},
		"unsorted amr": {
			RuleID: serviceID(83), Revision: 1, Level: identity.AssuranceMFA,
			RequiredAMR: []string{"pwd", "mfa"}, MaximumAuthenticationAge: time.Hour,
		},
		"unbounded age": {
			RuleID: serviceID(83), Revision: 1, Level: identity.AssuranceMFA,
			ACR: &validACR, MaximumAuthenticationAge: maximumOIDCTrustEvidenceAge + time.Second,
		},
	} {
		t.Run("rule "+name, func(t *testing.T) {
			badResolver := mustOIDCTrustResolver(t, oidcTrustSnapshotSourceFunc(func(
				_ context.Context,
				lookup OIDCTrustLookup,
			) (OIDCTrustSnapshot, error) {
				return OIDCTrustSnapshot{OIDCTrustLookup: lookup, Rules: []OIDCTrustRule{rule}}, nil
			}))
			if _, err := badResolver.ResolveOIDCAssurance(context.Background(), request); !errors.Is(err, ErrAuthentication) {
				t.Fatalf("ResolveOIDCAssurance() error = %v", err)
			}
		})
	}
}

func TestOIDCTrustTypesAlwaysRedact(t *testing.T) {
	const canary = "private-trust-value"
	acr := canary
	values := []any{
		OIDCTrustRequest{ACR: canary, AMR: []string{canary}},
		OIDCTrustRule{ACR: &acr, RequiredAMR: []string{canary}},
		OIDCTrustLookup{},
		OIDCTrustSnapshot{Rules: []OIDCTrustRule{{ACR: &acr}}},
		&PinnedOIDCTrustResolver{},
	}
	for _, value := range values {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if output := fmt.Sprintf(format, value); strings.Contains(output, canary) {
				t.Fatalf("%T leaked with %s: %s", value, format, output)
			}
		}
	}
}

func oidcTrustRequestFixture() OIDCTrustRequest {
	tenantID := serviceID(1)
	return OIDCTrustRequest{
		TenantID: tenantID,
		Provider: identity.ProviderContext{
			Scope: identity.TenantProviderScope, TenantID: tenantID, ProviderID: serviceID(2),
		},
		BindingID: serviceID(3), ProviderRevision: 4, BindingRevision: 5,
		SecurityRevision: 6, AssurancePolicyRevision: 7,
		AuthenticatedAt: serviceTestNow.Add(-time.Minute), ValidUntil: serviceTestNow.Add(time.Hour),
		ACR: "urn:periapsis:assurance:mfa", AMR: []string{"hwk", "mfa", "pwd"},
	}
}

func oidcTrustLookupFromRequest(request OIDCTrustRequest) OIDCTrustLookup {
	return OIDCTrustLookup{
		TenantID: request.TenantID, Provider: request.Provider, BindingID: request.BindingID,
		ProviderRevision: request.ProviderRevision, BindingRevision: request.BindingRevision,
		SecurityRevision: request.SecurityRevision, AssurancePolicyRevision: request.AssurancePolicyRevision,
	}
}

func mustOIDCTrustResolver(t *testing.T, source OIDCTrustSnapshotSource) *PinnedOIDCTrustResolver {
	t.Helper()
	resolver, err := NewPinnedOIDCTrustResolver(source)
	if err != nil {
		t.Fatalf("NewPinnedOIDCTrustResolver() error = %v", err)
	}
	return resolver
}
