package mfa

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

func TestTOTPStepUpBindsActionAndAudienceAndEmitsOnlyNewEvidence(t *testing.T) {
	fixture := newStepUpFixture(t)
	start, err := fixture.stepUp.Start(context.Background(), StepUpStartRequest{
		Binding: fixture.binding, AllowedFactors: []FactorKind{FactorRecoveryCode, FactorTOTP},
	})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := fixture.stepUp.CompleteTOTP(context.Background(), TOTPCompletionRequest{
		ChallengeID: start.ChallengeID(), BrowserHandle: start.BrowserHandle(),
		ExpectedBinding: expectedStepUpBinding(start.Binding()),
		FactorID:        fixture.store.totp.ID, Code: []byte("123456"),
		Session: mfaTestSessionReservation(fixture.binding, SessionAuthenticationTOTP),
	})
	if err != nil {
		t.Fatal(err)
	}
	if artifact.TenantID != fixture.binding.TenantID || artifact.UserID != fixture.binding.UserID ||
		artifact.SessionID != fixture.binding.SessionID || artifact.SessionFamilyID != fixture.binding.SessionFamilyID ||
		artifact.Action != "case.export" || artifact.Audience != "tenant-console" ||
		artifact.SessionVersion != 11 || artifact.RecoveryRestricted ||
		artifact.NewEvidence.Level != identity.AssuranceMFA ||
		artifact.NewEvidence.Kind != identity.AssuranceEvidenceFactor ||
		artifact.NewEvidence.FactorRevision == nil || *artifact.NewEvidence.FactorRevision != 7 ||
		len(fixture.binding.BaselineEvidence) != 1 {
		t.Fatalf("artifact = %#v", artifact)
	}
	fixture.verifier.mu.Lock()
	calls := fixture.verifier.calls
	fixture.verifier.mu.Unlock()
	if calls != 1 {
		t.Fatal("TOTP verification port was not called exactly once")
	}
}

func TestTOTPInsufficientForPhishingResistanceNeverRotatesSession(t *testing.T) {
	fixture := newStepUpFixture(t)
	fixture.binding.Requirement.Level = identity.AssurancePhishingResistant
	start, err := fixture.stepUp.Start(context.Background(), StepUpStartRequest{
		Binding: fixture.binding, AllowedFactors: []FactorKind{FactorTOTP},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = fixture.stepUp.CompleteTOTP(context.Background(), TOTPCompletionRequest{
		ChallengeID: start.ChallengeID(), BrowserHandle: start.BrowserHandle(),
		ExpectedBinding: expectedStepUpBinding(start.Binding()),
		FactorID:        fixture.store.totp.ID, Code: []byte("123456"),
		Session: mfaTestSessionReservation(fixture.binding, SessionAuthenticationTOTP),
	})
	if !errors.Is(err, ErrAssuranceInsufficient) {
		t.Fatalf("got %v", err)
	}
	fixture.store.mu.Lock()
	calls := fixture.store.consumerCalls
	state := fixture.store.challenges[start.ChallengeID()].State
	fixture.store.mu.Unlock()
	if calls != 0 || state != ChallengeFailed {
		t.Fatal("insufficient factor reached session consumer or remained replayable")
	}
}

func TestRecoveryIsOneUseAndAlwaysRestricted(t *testing.T) {
	fixture := newStepUpFixture(t)
	code := []byte("RECOVERY-CODE-1234")
	first, err := fixture.stepUp.Start(context.Background(), StepUpStartRequest{
		Binding: fixture.binding, AllowedFactors: []FactorKind{FactorRecoveryCode},
	})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := fixture.stepUp.CompleteRecovery(context.Background(), RecoveryCompletionRequest{
		ChallengeID: first.ChallengeID(), BrowserHandle: first.BrowserHandle(), Code: code,
		ExpectedBinding: expectedStepUpBinding(first.Binding()),
		ExpectedSetID:   fixture.store.recovery.ID,
		Session:         mfaTestSessionReservation(fixture.binding, SessionAuthenticationRecovery),
	})
	if err != nil || !artifact.RecoveryRestricted || artifact.NewEvidence.Kind != identity.AssuranceEvidenceRecovery ||
		artifact.NewEvidence.Level == identity.AssurancePhishingResistant {
		t.Fatalf("recovery artifact = %#v, %v", artifact, err)
	}

	second, err := fixture.stepUp.Start(context.Background(), StepUpStartRequest{
		Binding: fixture.binding, AllowedFactors: []FactorKind{FactorRecoveryCode},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = fixture.stepUp.CompleteRecovery(context.Background(), RecoveryCompletionRequest{
		ChallengeID: second.ChallengeID(), BrowserHandle: second.BrowserHandle(), Code: code,
		ExpectedBinding: expectedStepUpBinding(second.Binding()),
		ExpectedSetID:   fixture.store.recovery.ID,
		Session:         mfaTestSessionReservation(fixture.binding, SessionAuthenticationRecovery),
	}); !errors.Is(err, ErrFactorRejected) {
		t.Fatalf("reused recovery code = %v", err)
	}
}

func TestRecoveryCodeRaceAcrossChallengesHasOneWinner(t *testing.T) {
	fixture := newStepUpFixture(t)
	starts := make([]StepUpStartArtifact, 2)
	for index := range starts {
		var err error
		starts[index], err = fixture.stepUp.Start(context.Background(), StepUpStartRequest{
			Binding: fixture.binding, AllowedFactors: []FactorKind{FactorRecoveryCode},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	var winners atomic.Int32
	var wait sync.WaitGroup
	for _, start := range starts {
		wait.Add(1)
		go func(start StepUpStartArtifact) {
			defer wait.Done()
			if _, err := fixture.stepUp.CompleteRecovery(context.Background(), RecoveryCompletionRequest{
				ChallengeID: start.ChallengeID(), BrowserHandle: start.BrowserHandle(),
				ExpectedBinding: expectedStepUpBinding(start.Binding()),
				ExpectedSetID:   fixture.store.recovery.ID,
				Code:            []byte("RECOVERY-CODE-1234"),
				Session:         mfaTestSessionReservation(fixture.binding, SessionAuthenticationRecovery),
			}); err == nil {
				winners.Add(1)
			} else if !errors.Is(err, ErrFactorRejected) {
				t.Errorf("unexpected error: %v", err)
			}
		}(start)
	}
	wait.Wait()
	if winners.Load() != 1 {
		t.Fatalf("recovery winners = %d", winners.Load())
	}
}

func TestPostPrimaryContinuationCannotBeReusedAsSessionStepUp(t *testing.T) {
	fixture := newStepUpFixture(t)
	fixture.binding.Flow = FlowPostPrimaryContinuation
	fixture.binding.ContinuationID = mfaID(5)
	fixture.binding.SessionID = identity.EntityID{}
	fixture.binding.SessionFamilyID = identity.EntityID{}
	start, err := fixture.stepUp.Start(context.Background(), StepUpStartRequest{
		Binding: fixture.binding, AllowedFactors: []FactorKind{FactorTOTP},
	})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := fixture.stepUp.CompleteTOTP(context.Background(), TOTPCompletionRequest{
		ChallengeID: start.ChallengeID(), BrowserHandle: start.BrowserHandle(),
		ExpectedBinding: expectedStepUpBinding(start.Binding()),
		FactorID:        fixture.store.totp.ID, Code: []byte("123456"),
		Session:        mfaTestSessionReservation(fixture.binding, SessionAuthenticationTOTP),
		ContinuationID: fixture.binding.ContinuationID, ContinuationReceiptDigest: [32]byte{1},
	})
	if err != nil || artifact.ContinuationID != fixture.binding.ContinuationID ||
		artifact.SessionID != (identity.EntityID{}) || artifact.SessionFamilyID != (identity.EntityID{}) {
		t.Fatalf("continuation artifact = %#v, %v", artifact, err)
	}
}

func TestContinuationStepUpRejectsMixedPossessionBeforeFactorVerification(t *testing.T) {
	for name, configure := range map[string]func(*TOTPCompletionRequest){
		"missing receipt": func(request *TOTPCompletionRequest) {
			request.ContinuationID = mfaID(5)
		},
		"wrong continuation": func(request *TOTPCompletionRequest) {
			request.ContinuationID = mfaID(99)
			request.ContinuationReceiptDigest = [32]byte{1}
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newStepUpFixture(t)
			fixture.binding.Flow = FlowPostPrimaryContinuation
			fixture.binding.ContinuationID = mfaID(5)
			fixture.binding.SessionID = identity.EntityID{}
			fixture.binding.SessionFamilyID = identity.EntityID{}
			start, err := fixture.stepUp.Start(context.Background(), StepUpStartRequest{
				Binding: fixture.binding, AllowedFactors: []FactorKind{FactorTOTP},
			})
			if err != nil {
				t.Fatal(err)
			}
			request := TOTPCompletionRequest{
				ChallengeID: start.ChallengeID(), BrowserHandle: start.BrowserHandle(),
				ExpectedBinding: expectedStepUpBinding(start.Binding()),
				FactorID:        fixture.store.totp.ID, Code: []byte("123456"),
				Session: mfaTestSessionReservation(fixture.binding, SessionAuthenticationTOTP),
			}
			configure(&request)
			if _, err := fixture.stepUp.CompleteTOTP(context.Background(), request); !errors.Is(err, ErrFactorRejected) {
				t.Fatalf("CompleteTOTP() error = %v", err)
			}
			fixture.verifier.mu.Lock()
			verificationCalls := fixture.verifier.calls
			fixture.verifier.mu.Unlock()
			fixture.store.mu.Lock()
			consumerCalls := fixture.store.consumerCalls
			fixture.store.mu.Unlock()
			if verificationCalls != 0 || consumerCalls != 0 {
				t.Fatalf("calls = verifier %d consumer %d, want zero", verificationCalls, consumerCalls)
			}
		})
	}
}

func TestStepUpCompletionRejectsLiveAuthorityDriftBeforeFactorIO(t *testing.T) {
	tests := []struct {
		name   string
		factor FactorKind
		mutate func(*StepUpCompletionBinding)
	}{
		{
			name: "TOTP anchor version", factor: FactorTOTP,
			mutate: func(value *StepUpCompletionBinding) { value.AnchorVersion++ },
		},
		{
			name: "recovery anchor expiry", factor: FactorRecoveryCode,
			mutate: func(value *StepUpCompletionBinding) { value.AnchorExpiresAt = value.AnchorExpiresAt.Add(time.Second) },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newStepUpFixture(t)
			start, err := fixture.stepUp.Start(context.Background(), StepUpStartRequest{
				Binding: fixture.binding, AllowedFactors: []FactorKind{test.factor},
			})
			if err != nil {
				t.Fatal(err)
			}
			expected := expectedStepUpBinding(start.Binding())
			test.mutate(&expected)
			if test.factor == FactorTOTP {
				_, err = fixture.stepUp.CompleteTOTP(context.Background(), TOTPCompletionRequest{
					ChallengeID: start.ChallengeID(), BrowserHandle: start.BrowserHandle(),
					ExpectedBinding: expected, FactorID: fixture.store.totp.ID, Code: []byte("123456"),
					Session: mfaTestSessionReservation(fixture.binding, SessionAuthenticationTOTP),
				})
			} else {
				_, err = fixture.stepUp.CompleteRecovery(context.Background(), RecoveryCompletionRequest{
					ChallengeID: start.ChallengeID(), BrowserHandle: start.BrowserHandle(),
					ExpectedBinding: expected, ExpectedSetID: fixture.store.recovery.ID,
					Code:    []byte("RECOVERY-CODE-1234"),
					Session: mfaTestSessionReservation(fixture.binding, SessionAuthenticationRecovery),
				})
			}
			if !errors.Is(err, ErrFactorRejected) {
				t.Fatalf("completion error = %v", err)
			}
			fixture.store.mu.Lock()
			defer fixture.store.mu.Unlock()
			if fixture.store.totpLoadCalls != 0 || fixture.store.recoveryLoads != 0 ||
				fixture.store.consumerCalls != 0 || fixture.store.challenges[start.ChallengeID()].State != ChallengeFailed ||
				fixture.store.lastFailure.Reason != ChallengeFailureFactor {
				t.Fatalf("loads = %d/%d, completes = %d, state = %d, failure = %#v",
					fixture.store.totpLoadCalls, fixture.store.recoveryLoads, fixture.store.consumerCalls,
					fixture.store.challenges[start.ChallengeID()].State, fixture.store.lastFailure)
			}
		})
	}
}

func TestChallengeReplayRaceHasExactlyOneWinner(t *testing.T) {
	fixture := newStepUpFixture(t)
	start, err := fixture.stepUp.Start(context.Background(), StepUpStartRequest{
		Binding: fixture.binding, AllowedFactors: []FactorKind{FactorTOTP},
	})
	if err != nil {
		t.Fatal(err)
	}
	var winners atomic.Int32
	var wait sync.WaitGroup
	for range 32 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if _, completeErr := fixture.stepUp.CompleteTOTP(context.Background(), TOTPCompletionRequest{
				ChallengeID: start.ChallengeID(), BrowserHandle: start.BrowserHandle(),
				ExpectedBinding: expectedStepUpBinding(start.Binding()),
				FactorID:        fixture.store.totp.ID, Code: []byte("123456"),
				Session: mfaTestSessionReservation(fixture.binding, SessionAuthenticationTOTP),
			}); completeErr == nil {
				winners.Add(1)
			} else if !errors.Is(completeErr, ErrStepUpRejected) {
				t.Errorf("unexpected error: %v", completeErr)
			}
		}()
	}
	wait.Wait()
	if winners.Load() != 1 {
		t.Fatalf("winners = %d", winners.Load())
	}
}

func TestTOTPTimeStepRaceAcrossChallengesHasOneConsumerWinner(t *testing.T) {
	fixture := newStepUpFixture(t)
	first, err := fixture.stepUp.Start(context.Background(), StepUpStartRequest{
		Binding: fixture.binding, AllowedFactors: []FactorKind{FactorTOTP},
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := fixture.stepUp.Start(context.Background(), StepUpStartRequest{
		Binding: fixture.binding, AllowedFactors: []FactorKind{FactorTOTP},
	})
	if err != nil {
		t.Fatal(err)
	}
	var winners atomic.Int32
	var wait sync.WaitGroup
	for _, start := range []StepUpStartArtifact{first, second} {
		wait.Add(1)
		go func(start StepUpStartArtifact) {
			defer wait.Done()
			if _, completeErr := fixture.stepUp.CompleteTOTP(context.Background(), TOTPCompletionRequest{
				ChallengeID: start.ChallengeID(), BrowserHandle: start.BrowserHandle(),
				ExpectedBinding: expectedStepUpBinding(start.Binding()),
				FactorID:        fixture.store.totp.ID, Code: []byte("123456"),
				Session: mfaTestSessionReservation(fixture.binding, SessionAuthenticationTOTP),
			}); completeErr == nil {
				winners.Add(1)
			} else if !errors.Is(completeErr, ErrFactorRejected) {
				t.Errorf("unexpected error: %v", completeErr)
			}
		}(start)
	}
	wait.Wait()
	if winners.Load() != 1 {
		t.Fatalf("TOTP winners = %d", winners.Load())
	}
}

func TestStepUpRejectsCrossTenantMalformedAndExpiredArtifacts(t *testing.T) {
	tests := map[string]func(*stepUpFixture, *StepUpStartRequest){
		"missing audience": func(_ *stepUpFixture, request *StepUpStartRequest) {
			request.Binding.Audience = ""
		},
		"duplicate factor": func(_ *stepUpFixture, request *StepUpStartRequest) {
			request.AllowedFactors = []FactorKind{FactorTOTP, FactorTOTP}
		},
		"missing baseline": func(_ *stepUpFixture, request *StepUpStartRequest) {
			request.Binding.BaselineEvidence = nil
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newStepUpFixture(t)
			request := StepUpStartRequest{Binding: fixture.binding, AllowedFactors: []FactorKind{FactorTOTP}}
			mutate(&fixture, &request)
			_, err := fixture.stepUp.Start(context.Background(), request)
			if !errors.Is(err, ErrInvalidStepUp) {
				t.Fatalf("got %v", err)
			}
		})
	}

	fixture := newStepUpFixture(t)
	crossTenantBinding := fixture.binding
	crossTenantBinding.TenantID = mfaID(99)
	crossTenant, err := fixture.stepUp.Start(context.Background(), StepUpStartRequest{
		Binding: crossTenantBinding, AllowedFactors: []FactorKind{FactorTOTP},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = fixture.stepUp.CompleteTOTP(context.Background(), TOTPCompletionRequest{
		ChallengeID: crossTenant.ChallengeID(), BrowserHandle: crossTenant.BrowserHandle(),
		ExpectedBinding: expectedStepUpBinding(crossTenant.Binding()),
		FactorID:        fixture.store.totp.ID, Code: []byte("123456"),
		Session: mfaTestSessionReservation(crossTenantBinding, SessionAuthenticationTOTP),
	}); !errors.Is(err, ErrFactorRejected) {
		t.Fatalf("cross-tenant factor = %v", err)
	}

	fixture = newStepUpFixture(t)
	start, err := fixture.stepUp.Start(context.Background(), StepUpStartRequest{
		Binding: fixture.binding, AllowedFactors: []FactorKind{FactorTOTP},
	})
	if err != nil {
		t.Fatal(err)
	}
	*fixture.now = start.ExpiresAt()
	if _, err = fixture.stepUp.CompleteTOTP(context.Background(), TOTPCompletionRequest{
		ChallengeID: start.ChallengeID(), BrowserHandle: start.BrowserHandle(),
		ExpectedBinding: expectedStepUpBinding(start.Binding()),
		FactorID:        fixture.store.totp.ID, Code: []byte("123456"),
		Session: mfaTestSessionReservation(fixture.binding, SessionAuthenticationTOTP),
	}); !errors.Is(err, ErrStepUpRejected) {
		t.Fatalf("expiry = %v", err)
	}
}

func TestStepUpRejectsUninventoriedKeyVersions(t *testing.T) {
	fixture := newStepUpFixture(t)
	fixture.store.totp.Secret.KeyVersion = maximumMFAKeyVersion + 1
	start, err := fixture.stepUp.Start(context.Background(), StepUpStartRequest{
		Binding: fixture.binding, AllowedFactors: []FactorKind{FactorTOTP},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = fixture.stepUp.CompleteTOTP(context.Background(), TOTPCompletionRequest{
		ChallengeID: start.ChallengeID(), BrowserHandle: start.BrowserHandle(),
		ExpectedBinding: expectedStepUpBinding(start.Binding()),
		FactorID:        fixture.store.totp.ID, Code: []byte("123456"),
		Session: mfaTestSessionReservation(fixture.binding, SessionAuthenticationTOTP),
	}); !errors.Is(err, ErrFactorRejected) {
		t.Fatalf("oversized TOTP key version = %v", err)
	}

	fixture = newStepUpFixture(t)
	fixture.store.recovery.DigestKeyVersion = maximumMFAKeyVersion + 1
	start, err = fixture.stepUp.Start(context.Background(), StepUpStartRequest{
		Binding: fixture.binding, AllowedFactors: []FactorKind{FactorRecoveryCode},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = fixture.stepUp.CompleteRecovery(context.Background(), RecoveryCompletionRequest{
		ChallengeID: start.ChallengeID(), BrowserHandle: start.BrowserHandle(),
		ExpectedBinding: expectedStepUpBinding(start.Binding()),
		ExpectedSetID:   fixture.store.recovery.ID,
		Code:            []byte("RECOVERY-CODE-1234"),
		Session:         mfaTestSessionReservation(fixture.binding, SessionAuthenticationRecovery),
	}); !errors.Is(err, ErrFactorRejected) {
		t.Fatalf("oversized recovery key version = %v", err)
	}
}

func TestRecoveryRestrictedSessionCanStepUpWithAcceptedFactor(t *testing.T) {
	fixture := newStepUpFixture(t)
	fixture.binding.AnchorRecoveryRestricted = true
	fixture.binding.BaselineEvidence[0].Kind = identity.AssuranceEvidenceRecovery
	if _, err := fixture.stepUp.Start(context.Background(), StepUpStartRequest{
		Binding: fixture.binding, AllowedFactors: []FactorKind{FactorTOTP},
	}); err != nil {
		t.Fatalf("repair step-up = %v", err)
	}

	fixture = newStepUpFixture(t)
	fixture.binding.AnchorRecoveryRestricted = true
	if _, err := fixture.stepUp.Start(context.Background(), StepUpStartRequest{
		Binding: fixture.binding, AllowedFactors: []FactorKind{FactorTOTP},
	}); !errors.Is(err, ErrInvalidStepUp) {
		t.Fatalf("restricted step-up without recovery evidence = %v", err)
	}
}

func TestStepUpFormattingAndErrorsNeverExposeProofs(t *testing.T) {
	canary := "RECOVERY-CODE-SECRET-CANARY"
	values := []any{
		PendingChallenge{}, StepUpStartArtifact{browserHandle: []byte(canary)},
		TOTPVerificationRequest{Code: []byte(canary)}, RecoveryDigestRequest{Code: []byte(canary)},
		TOTPCompletionRequest{Code: []byte(canary)}, RecoveryCompletionRequest{Code: []byte(canary)},
		ProtectedTOTPSecret{Ciphertext: []byte(canary)},
		TOTPFactor{Secret: ProtectedTOTPSecret{Ciphertext: []byte(canary)}}, StepUpArtifact{},
		StepUpBinding{Audience: canary}, TOTPCompletion{Binding: StepUpBinding{Audience: canary}},
		RecoveryCompletion{Binding: StepUpBinding{Audience: canary}},
	}
	for _, value := range values {
		if formatted := fmt.Sprintf("%#v", value); strings.Contains(formatted, canary) {
			t.Fatalf("unsafe format %T: %s", value, formatted)
		}
	}
	fixture := newStepUpFixture(t)
	fixture.verifier.err = errors.New(canary)
	start, err := fixture.stepUp.Start(context.Background(), StepUpStartRequest{
		Binding: fixture.binding, AllowedFactors: []FactorKind{FactorTOTP},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = fixture.stepUp.CompleteTOTP(context.Background(), TOTPCompletionRequest{
		ChallengeID: start.ChallengeID(), BrowserHandle: start.BrowserHandle(),
		ExpectedBinding: expectedStepUpBinding(start.Binding()),
		FactorID:        fixture.store.totp.ID, Code: []byte("123456"),
		Session: mfaTestSessionReservation(fixture.binding, SessionAuthenticationTOTP),
	})
	if !errors.Is(err, ErrFactorRejected) || strings.Contains(err.Error(), canary) {
		t.Fatalf("unsafe error = %v", err)
	}
}

func TestStepUpStartArtifactCanBeDestroyedAfterTransport(t *testing.T) {
	fixture := newStepUpFixture(t)
	artifact, err := fixture.stepUp.Start(context.Background(), StepUpStartRequest{
		Binding: fixture.binding, AllowedFactors: []FactorKind{FactorTOTP},
	})
	if err != nil {
		t.Fatal(err)
	}
	artifact.Destroy()
	if len(artifact.BrowserHandle()) != 0 || len(artifact.AllowedFactors()) != 0 ||
		artifact.Binding().TenantID != (identity.EntityID{}) {
		t.Fatalf("artifact survived Destroy: %#v", artifact)
	}
}

func TestFactorFailureTerminalizesAfterRequestCancellation(t *testing.T) {
	fixture := newStepUpFixture(t)
	start, err := fixture.stepUp.Start(context.Background(), StepUpStartRequest{
		Binding: fixture.binding, AllowedFactors: []FactorKind{FactorTOTP},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	fixture.verifier.hook = cancel
	fixture.verifier.err = errors.New("factor rejected")
	_, err = fixture.stepUp.CompleteTOTP(ctx, TOTPCompletionRequest{
		ChallengeID: start.ChallengeID(), BrowserHandle: start.BrowserHandle(),
		ExpectedBinding: expectedStepUpBinding(start.Binding()),
		FactorID:        fixture.store.totp.ID, Code: []byte("123456"),
		Session: mfaTestSessionReservation(fixture.binding, SessionAuthenticationTOTP),
	})
	if !errors.Is(err, ErrFactorRejected) {
		t.Fatalf("got %v", err)
	}
	fixture.store.mu.Lock()
	defer fixture.store.mu.Unlock()
	if fixture.store.failContext != nil || fixture.store.challenges[start.ChallengeID()].State != ChallengeFailed {
		t.Fatalf("fail context = %v, state = %d", fixture.store.failContext,
			fixture.store.challenges[start.ChallengeID()].State)
	}
}

func FuzzFactorProofValidation(f *testing.F) {
	f.Add([]byte("123456"), []byte("RECOVERY-CODE-1234"))
	f.Add([]byte(" 123456"), []byte(" recovery-code "))
	f.Fuzz(func(t *testing.T, totp, recovery []byte) {
		if validTOTPCode(totp) {
			for _, character := range totp {
				if character < '0' || character > '9' {
					t.Fatal("non-digit TOTP accepted")
				}
			}
		}
		if validRecoveryCode(recovery) && strings.TrimSpace(string(recovery)) != string(recovery) {
			t.Fatal("non-canonical recovery code accepted")
		}
	})
}
