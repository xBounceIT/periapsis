package platformsamlauth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
)

func TestApplicationStartAndCompleteDirectSAMLImmediateSession(t *testing.T) {
	harness := newTestHarness(t, identity.AssuranceMFA, false)
	lookup := StartLookup{Begin: testBegin(70), LoginKey: "provider-a"}
	authority := StartAuthority{Lookup: lookup, ReturnPath: "/incidents?view=mine", Audit: harness.audit}
	grant := StartGrant{Authority: authority, Pins: harness.pins}
	harness.configurations.start = StartConfigurationSnapshot{
		Grant: grant,
		Configuration: ConfigurationSnapshot{
			Pins: harness.pins, ProviderKind: ProviderKindSAML, Authentication: harness.configuration,
		},
	}

	start, err := harness.application.Start(context.Background(), StartRequest{
		Lookup: lookup, ReturnPath: authority.ReturnPath, Audit: harness.audit,
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if start.TransactionID() != harness.start.TransactionID() ||
		string(start.BrowserHandle()) != string(harness.start.BrowserHandle()) {
		t.Fatalf("Start() = %q, want %q", start.String(), harness.start.String())
	}
	harness.protocol.guard.Lock()
	started := harness.protocol.startRequest
	harness.protocol.guard.Unlock()
	if started.Grant != grant || started.Protocol.Configuration.Authority != federatedsaml.DirectPlatformCeremonyAuthority ||
		started.Protocol.Configuration.Provider.Scope != identity.PlatformProviderScope ||
		started.Protocol.Configuration.Provider.TenantID != (identity.EntityID{}) ||
		started.Protocol.Configuration.BindingID != (identity.EntityID{}) ||
		started.Protocol.Configuration.SPEntityID != harness.configuration.SPEntityID ||
		started.Protocol.Configuration.SPEntityID != "https://sp.example.test/api/v1/auth/platform/saml/provider-a/metadata" ||
		len(started.Protocol.Configuration.Mapping.Scalars) != 0 ||
		len(started.Protocol.Configuration.Mapping.Profiles) != 0 || started.Protocol.Configuration.Mapping.Groups != nil {
		t.Fatalf("StartDirectSAML request lost direct authority: %#v", started)
	}

	outcome, err := harness.application.Complete(context.Background(), harness.request)
	if err != nil {
		t.Fatalf("Complete() error = %v", err)
	}
	if outcome.Disposition != ImmediateSession || outcome.UserID != testID(42) ||
		outcome.SessionID != testID(52) || outcome.ContinuationID != (identity.EntityID{}) ||
		outcome.ReturnPath != harness.consumption.ReturnPath || outcome.Credential == nil {
		t.Fatalf("Complete() = %#v", outcome)
	}
	browser, ok := outcome.Credential.Consume()
	if !ok || browser.Kind != BrowserSessionCredential || browser.SessionID != outcome.SessionID ||
		len(browser.SessionToken) == 0 || len(browser.CSRFToken) == 0 || len(browser.Receipt) != 0 {
		t.Fatalf("browser credential = %#v, %t", browser, ok)
	}
	browser.Destroy()

	harness.apply.guard.Lock()
	applied := cloneApplyRequest(harness.apply.request)
	applyCalls, recoveries, rejects := harness.apply.applyCalls, harness.apply.recoveryCalls, harness.apply.rejectCalls
	harness.apply.guard.Unlock()
	defer clearApplyRequest(&applied)
	if applyCalls != 1 || recoveries != 0 || rejects != 0 || !validApplyRequest(applied) ||
		applied.Authority.Pins.Authority != federatedsaml.DirectPlatformCeremonyAuthority ||
		applied.Authority.Pins.Provider.TenantID != (identity.EntityID{}) ||
		applied.Authority.Pins.BindingID != (identity.EntityID{}) || applied.Plan.Provenance.ProviderKind != ProviderKindSAML ||
		applied.Plan.Provenance.PlatformAuthorityID != testID(45) ||
		applied.Plan.Provenance.PlatformAuthorityRevision != 46 ||
		applied.SessionAudience != SessionAudience || applied.RecoveryRestricted ||
		applied.Authority.ResponseID != "_response" || applied.Authority.AssertionID != "_assertion" ||
		!applied.Authority.HasSessionIndex || !applied.Authority.HasSessionMaterial ||
		applied.ProofDigest != applyProofDigest(applied) {
		t.Fatalf("ApplyDirectSAML request = %#v, calls=%d/%d/%d", applied, applyCalls, recoveries, rejects)
	}
	formatted := fmt.Sprintf("%#v", applied)
	for _, secret := range []string{"subject-secret-value", "logout-secret-value", "logout-session-secret"} {
		if strings.Contains(formatted, secret) {
			t.Fatalf("ApplyRequest formatting leaked %q: %s", secret, formatted)
		}
	}
	plaintext, err := harness.keyring.DecryptDirectPlatformSAMLSessionMaterial(
		identity.DirectPlatformSAMLSessionMaterialContext{
			Provider: applied.Authority.Pins.Provider, MaterialID: applied.Authority.MaterialID,
			PlatformLoginRevision: applied.Authority.Pins.PlatformLoginRevision,
		},
		applied.ProtectedSessionMaterial.Envelope,
	)
	if err != nil || !strings.Contains(string(plaintext), "logout-secret-value") {
		clear(plaintext)
		t.Fatalf("protected logout material was not direct-authority decryptable: %v", err)
	}
	clear(plaintext)
}

func TestApplicationRejectsEveryExactPinAndTrustProjectionDrift(t *testing.T) {
	tests := map[string]func(*PlanningState){
		"provider revision":       func(state *PlanningState) { state.Pins.Protocol.ProviderRevision++ },
		"platform login revision": func(state *PlanningState) { state.Pins.Protocol.PlatformLoginRevision++ },
		"configuration revision":  func(state *PlanningState) { state.Pins.Protocol.ConfigurationRevision++ },
		"security revision":       func(state *PlanningState) { state.Pins.Protocol.SecurityRevision++ },
		"plan revision":           func(state *PlanningState) { state.Pins.Protocol.PlanRevision++ },
		"assurance revision":      func(state *PlanningState) { state.Pins.Protocol.AssurancePolicyRevision++ },
		"metadata revision":       func(state *PlanningState) { state.Pins.Protocol.MetadataRevision++ },
		"metadata digest":         func(state *PlanningState) { state.Pins.Protocol.MetadataDigest[0] ^= 1 },
		"SP key revision":         func(state *PlanningState) { state.Pins.Protocol.SPKeyRevision++ },
		"configuration digest":    func(state *PlanningState) { state.Pins.Protocol.ConfigurationDigest[0] ^= 1 },
		"floor policy":            func(state *PlanningState) { state.Pins.PlatformFloorPolicyID = testID(92) },
		"floor revision":          func(state *PlanningState) { state.Pins.PlatformFloorPolicyRevision++ },
		"trust rule revision":     func(state *PlanningState) { state.TrustRules[0].Revision++ },
		"trust rule class":        func(state *PlanningState) { state.TrustRules[0].ClassRef = "urn:test:other" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			harness := newTestHarness(t, identity.AssuranceMFA, false)
			harness.planning.mutate = func(state *PlanningState, _ PlanningLookup) { mutate(state) }
			outcome, err := harness.application.Complete(context.Background(), harness.request)
			if !errors.Is(err, ErrAuthenticationDenied) || outcome != (Outcome{}) {
				t.Fatalf("Complete() = %#v, %v", outcome, err)
			}
			harness.apply.guard.Lock()
			calls := harness.apply.applyCalls
			harness.apply.guard.Unlock()
			if calls != 0 {
				t.Fatalf("ApplyDirectSAML called %d times", calls)
			}
		})
	}
}

func TestApplyProofDigestIsStableAndBindsAuditAndReplayAuthority(t *testing.T) {
	harness := newTestHarness(t, identity.AssuranceMFA, false)
	outcome, err := harness.application.Complete(context.Background(), harness.request)
	if err != nil {
		t.Fatal(err)
	}
	outcome.Credential.Destroy()
	harness.apply.guard.Lock()
	request := cloneApplyRequest(harness.apply.request)
	harness.apply.guard.Unlock()
	defer clearApplyRequest(&request)
	baseline := applyProofDigest(request)
	deterministic := cloneApplyRequest(request)
	repeated := applyProofDigest(deterministic)
	clearApplyRequest(&deterministic)
	if baseline == ([32]byte{}) || baseline != repeated {
		t.Fatal("apply proof digest is not deterministic")
	}
	mutations := map[string]func(*ApplyRequest){
		"request audit":      func(value *ApplyRequest) { value.Audit.RequestID = testID(93) },
		"response replay":    func(value *ApplyRequest) { value.Authority.ResponseID = "_other_response" },
		"assertion replay":   func(value *ApplyRequest) { value.Authority.AssertionID = "_other_assertion" },
		"session replay":     func(value *ApplyRequest) { value.Authority.SessionIndexDigest[0] ^= 1 },
		"metadata pin":       func(value *ApplyRequest) { value.Plan.Pins.Protocol.MetadataDigest[0] ^= 1 },
		"platform authority": func(value *ApplyRequest) { value.Plan.Provenance.PlatformAuthorityRevision++ },
	}
	for name, mutate := range mutations {
		candidate := cloneApplyRequest(request)
		mutate(&candidate)
		if digest := applyProofDigest(candidate); digest == baseline {
			clearApplyRequest(&candidate)
			t.Fatalf("%s substitution did not change proof digest", name)
		}
		clearApplyRequest(&candidate)
	}
}

func TestApplicationCreatesOnlyTOTPContinuationWhenLocalFloorRequiresIt(t *testing.T) {
	harness := newTestHarness(t, identity.AssuranceMFA, true)
	outcome, err := harness.application.Complete(context.Background(), harness.request)
	if err != nil {
		t.Fatalf("Complete() error = %v", err)
	}
	if outcome.Disposition != TOTPContinuation || outcome.SessionID != (identity.EntityID{}) ||
		outcome.ContinuationID != testID(55) || outcome.Credential == nil {
		t.Fatalf("Complete() = %#v", outcome)
	}
	material, ok := outcome.Credential.Consume()
	if !ok || material.Kind != BrowserContinuationCredential || material.ContinuationID != outcome.ContinuationID ||
		len(material.Receipt) == 0 || len(material.SessionToken) != 0 || len(material.CSRFToken) != 0 {
		t.Fatalf("continuation browser credential = %#v, %t", material, ok)
	}
	material.Destroy()
	harness.apply.guard.Lock()
	applied := harness.apply.request
	harness.apply.guard.Unlock()
	if !applied.Session.IsZero() || applied.Continuation.IsZero() ||
		applied.Continuation.FactorID() != testID(48) || applied.Continuation.FactorRevision() != 49 {
		t.Fatalf("continuation apply = %#v", applied)
	}
}

func TestApplicationDeniesPhishingResistantFloorWhenOnlyLocalTOTPCouldContinue(t *testing.T) {
	harness := newTestHarness(t, identity.AssurancePhishingResistant, true)
	outcome, err := harness.application.Complete(context.Background(), harness.request)
	if !errors.Is(err, ErrAuthenticationDenied) || outcome != (Outcome{}) {
		t.Fatalf("Complete() = %#v, %v", outcome, err)
	}
	harness.apply.guard.Lock()
	applyCalls, rejects := harness.apply.applyCalls, harness.apply.rejectCalls
	harness.apply.guard.Unlock()
	if applyCalls != 0 || rejects == 0 {
		t.Fatalf("apply/reject calls = %d/%d", applyCalls, rejects)
	}
}

func TestApplicationFailsClosedForAuthorityPinsIdentityAndAssurance(t *testing.T) {
	tests := map[string]func(*testHarness){
		"tenant authority": func(h *testHarness) {
			h.protocol.consumption.Pins.Authority = federatedsaml.TenantCeremonyAuthority
		},
		"tenant provider scope": func(h *testHarness) {
			h.protocol.consumption.Pins.Provider.Scope = identity.TenantProviderScope
			h.protocol.consumption.Pins.Provider.TenantID = testID(90)
		},
		"configuration pin drift": func(h *testHarness) {
			h.planning.mutate = func(state *PlanningState, _ PlanningLookup) {
				state.Pins.Protocol.ConfigurationRevision++
			}
		},
		"provider kind substitution": func(h *testHarness) {
			h.planning.mutate = func(state *PlanningState, _ PlanningLookup) { state.ProviderKind = "oidc" }
		},
		"identity ambiguity": func(h *testHarness) {
			h.planning.mutate = func(state *PlanningState, lookup PlanningLookup) {
				duplicate := state.Matches[0]
				duplicate.ExternalIdentityID = testID(91)
				duplicate.Alias = lookup.SubjectAliases[0]
				state.Matches = append(state.Matches, duplicate)
			}
		},
		"inactive user": func(h *testHarness) {
			h.planning.mutate = func(state *PlanningState, _ PlanningLookup) { state.Matches[0].UserActive = false }
		},
		"unprotected authority": func(h *testHarness) {
			h.planning.mutate = func(state *PlanningState, _ PlanningLookup) {
				state.Matches[0].ProtectedPlatformAuthorityLive = false
			}
		},
		"assertion mapping consequence": func(h *testHarness) {
			h.protocol.consumption.Authentication.Scalars = []federatedsaml.NamedScalar{{Name: "role", Value: "admin"}}
			h.protocol.validated.proof = cloneProof(h.protocol.consumption.Authentication)
		},
		"unsafe authn context": func(h *testHarness) {
			h.protocol.consumption.Authentication.AuthnContext = "URN:TEST:MFA"
			h.protocol.validated.proof = cloneProof(h.protocol.consumption.Authentication)
			h.planning.mutate = func(state *PlanningState, _ PlanningLookup) {
				state.LiveConfirmedTOTPFactors = nil
			}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			harness := newTestHarness(t, identity.AssuranceMFA, false)
			mutate(&harness)
			outcome, err := harness.application.Complete(context.Background(), harness.request)
			if !errors.Is(err, ErrAuthenticationDenied) || outcome != (Outcome{}) {
				t.Fatalf("Complete() = %#v, %v", outcome, err)
			}
			harness.apply.guard.Lock()
			applyCalls := harness.apply.applyCalls
			harness.apply.guard.Unlock()
			if applyCalls != 0 {
				t.Fatalf("ApplyDirectSAML called %d times", applyCalls)
			}
			harness.protocol.guard.Lock()
			consumeCalls, abortCalls := harness.protocol.consumeCalls, harness.protocol.abortCalls
			harness.protocol.guard.Unlock()
			if consumeCalls > 0 && abortCalls == 0 {
				t.Fatalf("claimed failure was not terminalized: consume=%d abort=%d", consumeCalls, abortCalls)
			}
		})
	}
}

func TestApplicationDeniesProtocolReplayAndConsumeCollision(t *testing.T) {
	for _, category := range []ApplyCategory{ApplyProtocolReplay, ApplyStale, ApplyCollision, ApplyDenied} {
		t.Run(string(category), func(t *testing.T) {
			harness := newTestHarness(t, identity.AssuranceMFA, false)
			harness.apply.applyCategory = category
			outcome, err := harness.application.Complete(context.Background(), harness.request)
			if !errors.Is(err, ErrAuthenticationDenied) || outcome != (Outcome{}) {
				t.Fatalf("Complete() = %#v, %v", outcome, err)
			}
			harness.apply.guard.Lock()
			applyCalls, rejects := harness.apply.applyCalls, harness.apply.rejectCalls
			harness.apply.guard.Unlock()
			if applyCalls != 1 || rejects == 0 {
				t.Fatalf("apply/reject calls = %d/%d", applyCalls, rejects)
			}
		})
	}
}

func TestApplicationRecoversOnlyExactAmbiguousCommit(t *testing.T) {
	t.Run("exact proof succeeds after cancellation", func(t *testing.T) {
		harness := newTestHarness(t, identity.AssuranceMFA, false)
		ctx, cancel := context.WithCancel(context.Background())
		harness.apply.applyErr = errors.New("ambiguous commit")
		harness.apply.recovery = RecoveryResult{Matched: true}
		harness.apply.onApply = cancel
		outcome, err := harness.application.Complete(ctx, harness.request)
		if err != nil || outcome.SessionID != testID(52) {
			t.Fatalf("Complete() = %#v, %v", outcome, err)
		}
		harness.apply.guard.Lock()
		recoveries, recoveryCtxErr := harness.apply.recoveryCalls, harness.apply.recoveryCtxErr
		harness.apply.guard.Unlock()
		if recoveries != 1 || recoveryCtxErr != nil {
			t.Fatalf("recovery calls/context = %d/%v", recoveries, recoveryCtxErr)
		}
	})

	t.Run("no match preserves unavailable result", func(t *testing.T) {
		harness := newTestHarness(t, identity.AssuranceMFA, false)
		harness.apply.applyErr = errors.New("work failed")
		outcome, err := harness.application.Complete(context.Background(), harness.request)
		if !errors.Is(err, ErrAuthenticationUnavailable) || outcome != (Outcome{}) {
			t.Fatalf("Complete() = %#v, %v", outcome, err)
		}
		harness.apply.guard.Lock()
		recoveries, rejects := harness.apply.recoveryCalls, harness.apply.rejectCalls
		harness.apply.guard.Unlock()
		if recoveries != 1 || rejects == 0 {
			t.Fatalf("recovery/reject calls = %d/%d", recoveries, rejects)
		}
	})

	t.Run("mismatched recovery cannot mask error", func(t *testing.T) {
		harness := newTestHarness(t, identity.AssuranceMFA, false)
		harness.apply.applyErr = errors.New("ambiguous commit")
		harness.apply.recovery = RecoveryResult{Matched: true, Result: ApplyResult{
			Category: ApplyAlreadyApplied, SessionID: testID(99),
		}}
		outcome, err := harness.application.Complete(context.Background(), harness.request)
		if !errors.Is(err, ErrAuthenticationUnavailable) || outcome != (Outcome{}) {
			t.Fatalf("Complete() = %#v, %v", outcome, err)
		}
	})
}

func TestApplicationTreatsMalformedSuccessfulApplyProjectionAsAmbiguous(t *testing.T) {
	t.Run("exact recovery restores result", func(t *testing.T) {
		harness := newTestHarness(t, identity.AssuranceMFA, false)
		harness.apply.resultMutate = func(result *ApplyResult) { result.SessionID = testID(99) }
		harness.apply.recovery = RecoveryResult{Matched: true}
		outcome, err := harness.application.Complete(context.Background(), harness.request)
		if err != nil || outcome.SessionID != testID(52) || outcome.Credential == nil {
			t.Fatalf("Complete() = %#v, %v", outcome, err)
		}
		outcome.Credential.Destroy()
		harness.apply.guard.Lock()
		recoveries, cleanups, active := harness.apply.recoveryCalls, harness.apply.cleanupCalls, harness.apply.active
		harness.apply.guard.Unlock()
		if recoveries != 1 || cleanups != 0 || !active {
			t.Fatalf("recovery/cleanup/active = %d/%d/%t", recoveries, cleanups, active)
		}
	})

	t.Run("no proof match compensates potential commit", func(t *testing.T) {
		harness := newTestHarness(t, identity.AssuranceMFA, false)
		harness.apply.resultMutate = func(result *ApplyResult) { result.SessionID = testID(99) }
		outcome, err := harness.application.Complete(context.Background(), harness.request)
		if !errors.Is(err, ErrAuthenticationUnavailable) || outcome != (Outcome{}) {
			t.Fatalf("Complete() = %#v, %v", outcome, err)
		}
		harness.apply.guard.Lock()
		recoveries, cleanups, active, reason := harness.apply.recoveryCalls, harness.apply.cleanupCalls,
			harness.apply.active, harness.apply.cleanupReason
		harness.apply.guard.Unlock()
		if recoveries != 1 || cleanups == 0 || active || reason != CleanupInvalidOutcome {
			t.Fatalf("recovery/cleanup/active/reason = %d/%d/%t/%q", recoveries, cleanups, active, reason)
		}
	})

	t.Run("recovered commit is compensated when protocol later fails", func(t *testing.T) {
		harness := newTestHarness(t, identity.AssuranceMFA, false)
		harness.apply.resultMutate = func(result *ApplyResult) { result.SessionID = testID(99) }
		harness.apply.recovery = RecoveryResult{Matched: true}
		harness.protocol.afterConsumeErr = errors.New("protocol delivery failed")
		outcome, err := harness.application.Complete(context.Background(), harness.request)
		if err == nil || outcome != (Outcome{}) {
			t.Fatalf("Complete() = %#v, %v", outcome, err)
		}
		harness.apply.guard.Lock()
		cleanups, active := harness.apply.cleanupCalls, harness.apply.active
		harness.apply.guard.Unlock()
		if cleanups == 0 || active {
			t.Fatalf("cleanup/active = %d/%t", cleanups, active)
		}
	})
}

func TestApplicationDestroysCredentialWhenProtocolFailsAfterSuccessfulConsumer(t *testing.T) {
	for _, mode := range []string{"error after consumer", "double consume"} {
		t.Run(mode, func(t *testing.T) {
			harness := newTestHarness(t, identity.AssuranceMFA, false)
			if mode == "double consume" {
				harness.protocol.consumeTwice = true
			} else {
				harness.protocol.afterConsumeErr = errors.New("protocol failed after consumer")
			}
			outcome, err := harness.application.Complete(context.Background(), harness.request)
			if err == nil || outcome != (Outcome{}) {
				t.Fatalf("Complete() = %#v, %v", outcome, err)
			}
			harness.protocol.guard.Lock()
			credential := harness.protocol.capturedCredential
			abortCalls := harness.protocol.abortCalls
			harness.protocol.guard.Unlock()
			if credential == nil {
				t.Fatal("protocol did not capture the committed credential")
			}
			if material, ok := credential.Consume(); ok {
				material.Destroy()
				t.Fatal("credential plaintext remained consumable after failed protocol return")
			}
			if abortCalls == 0 {
				t.Fatal("protocol failure after claim was not terminalized")
			}
			harness.apply.guard.Lock()
			cleanupCalls, active, cleanupReason := harness.apply.cleanupCalls, harness.apply.active, harness.apply.cleanupReason
			harness.apply.guard.Unlock()
			if cleanupCalls == 0 || active || cleanupReason != CleanupProtocolFailed {
				t.Fatalf("committed result cleanup = calls:%d active:%t reason:%q", cleanupCalls, active, cleanupReason)
			}
		})
	}
}

func TestApplicationCompensatesCommittedApplyWhenCredentialReleaseFails(t *testing.T) {
	harness := newTestHarness(t, identity.AssuranceMFA, false)
	original := harness.application.credentials
	var reservation *CredentialReservation
	harness.application.credentials = credentialIssuerFunc(func(request CredentialRequest) (*CredentialReservation, error) {
		created, err := original.ReserveDirectSAMLCredential(request)
		reservation = created
		return created, err
	})
	harness.apply.onApply = func() { reservation.Destroy() }

	outcome, err := harness.application.Complete(context.Background(), harness.request)
	if !errors.Is(err, ErrAuthenticationUnavailable) || outcome != (Outcome{}) {
		t.Fatalf("Complete() = %#v, %v", outcome, err)
	}
	harness.apply.guard.Lock()
	cleanupCalls, active, reason := harness.apply.cleanupCalls, harness.apply.active, harness.apply.cleanupReason
	harness.apply.guard.Unlock()
	if cleanupCalls == 0 || active || reason != CleanupCredentialReleaseFailed {
		t.Fatalf("committed result cleanup = calls:%d active:%t reason:%q", cleanupCalls, active, reason)
	}
}

func TestApplicationRejectsBuggyProtocolResolverAndNilConsumerContext(t *testing.T) {
	for name, mutate := range map[string]func(*fakeProtocol){
		"duplicate resolver":   func(protocol *fakeProtocol) { protocol.resolveTwice = true },
		"nil consumer context": func(protocol *fakeProtocol) { protocol.nilConsumerContext = true },
	} {
		t.Run(name, func(t *testing.T) {
			harness := newTestHarness(t, identity.AssuranceMFA, false)
			mutate(harness.protocol)
			outcome, err := harness.application.Complete(context.Background(), harness.request)
			if !errors.Is(err, ErrAuthenticationDenied) || outcome != (Outcome{}) {
				t.Fatalf("Complete() = %#v, %v", outcome, err)
			}
			harness.protocol.guard.Lock()
			abortCalls := harness.protocol.abortCalls
			harness.protocol.guard.Unlock()
			if abortCalls == 0 {
				t.Fatal("buggy protocol callback was not terminalized")
			}
		})
	}
}

func TestApplicationCancellationAndReturnPathValidationFailClosed(t *testing.T) {
	harness := newTestHarness(t, identity.AssuranceMFA, false)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if outcome, err := harness.application.Complete(canceled, harness.request); !errors.Is(err, ErrAuthenticationUnavailable) || outcome != (Outcome{}) {
		t.Fatalf("Complete(canceled) = %#v, %v", outcome, err)
	}

	invalidPaths := []string{
		`/\evil.example`, `//evil.example`, `/a//b`, `/a/../b`, `/a/%2e%2e/b`, `/a#fragment`,
		"/a\r\nb", "https://evil.example/a", "/a%2Fb",
	}
	for _, value := range invalidPaths {
		if validReturnPath(value) {
			t.Errorf("validReturnPath(%q) = true", value)
		}
	}
	for _, value := range []string{"/", "/incidents", "/incidents?view=mine"} {
		if !validReturnPath(value) {
			t.Errorf("validReturnPath(%q) = false", value)
		}
	}
}

func TestApplicationStringFormsRedactSubjectAndBrowserMaterial(t *testing.T) {
	harness := newTestHarness(t, identity.AssuranceMFA, false)
	values := []any{
		harness.application, harness.proof, harness.consumption, harness.request,
		harness.pins, harness.planning.state.Matches[0], harness.planning.state,
	}
	for _, value := range values {
		formatted := fmt.Sprintf("%#v", value)
		for _, secret := range []string{
			"subject-secret-value", "logout-secret-value", "logout-session-secret",
			string(harness.request.BrowserHandle), string(harness.request.RawForm),
		} {
			if strings.Contains(formatted, secret) {
				t.Fatalf("%T GoString leaked secret %q: %s", value, secret, formatted)
			}
		}
	}
}

func TestApplicationRecoveryIsDeadlineBounded(t *testing.T) {
	harness := newTestHarness(t, identity.AssuranceMFA, false)
	harness.apply.applyErr = errors.New("ambiguous")
	harness.apply.onRecover = func(ctx context.Context) { <-ctx.Done() }
	started := time.Now()
	_, err := harness.application.Complete(context.Background(), harness.request)
	if !errors.Is(err, ErrAuthenticationUnavailable) {
		t.Fatalf("Complete() error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatalf("recovery exceeded bound: %s", elapsed)
	}
}
