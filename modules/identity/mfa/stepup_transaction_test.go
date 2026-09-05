package mfa

import (
	"context"
	"errors"
	"testing"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

func TestStepUpRejectsIncompleteAtomicSessionAndAuditResults(t *testing.T) {
	tests := map[string]func(*FactorCompletionResult){
		"missing audit": func(result *FactorCompletionResult) { result.AuditID = identity.EntityID{} },
		"wrong tenant":  func(result *FactorCompletionResult) { result.TenantID = mfaID(99) },
		"wrong user":    func(result *FactorCompletionResult) { result.UserID = mfaID(99) },
		"wrong identity epoch": func(result *FactorCompletionResult) {
			result.IdentityEpoch++
		},
		"same session":        func(result *FactorCompletionResult) { result.NewSessionID = mfaID(4) },
		"wrong family":        func(result *FactorCompletionResult) { result.NewSessionFamilyID = mfaID(99) },
		"fake continuation":   func(result *FactorCompletionResult) { result.ConsumedContinuationID = mfaID(98) },
		"missing new session": func(result *FactorCompletionResult) { result.NewSessionID = identity.EntityID{} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newStepUpFixture(t)
			fixture.store.resultMutate = mutate
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
			if !errors.Is(err, ErrFactorRejected) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestContinuationResultNamesNewSessionAndConsumedAnchor(t *testing.T) {
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
	if err != nil || artifact.NewSessionID == (identity.EntityID{}) ||
		artifact.NewSessionFamilyID == (identity.EntityID{}) || artifact.ContinuationID != mfaID(5) {
		t.Fatalf("artifact = %#v, err = %v", artifact, err)
	}
}

func TestContinuationCompletionRejectsResultOutsideExactReservation(t *testing.T) {
	for _, test := range []struct {
		name   string
		factor FactorKind
		mutate func(*FactorCompletionResult)
	}{
		{
			name: "TOTP wrong reserved session", factor: FactorTOTP,
			mutate: func(result *FactorCompletionResult) { result.NewSessionID = mfaID(99) },
		},
		{
			name: "recovery wrong reserved family", factor: FactorRecoveryCode,
			mutate: func(result *FactorCompletionResult) { result.NewSessionFamilyID = mfaID(98) },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newStepUpFixture(t)
			fixture.binding.Flow = FlowPostPrimaryContinuation
			fixture.binding.ContinuationID = mfaID(5)
			fixture.binding.SessionID = identity.EntityID{}
			fixture.binding.SessionFamilyID = identity.EntityID{}
			fixture.store.resultMutate = test.mutate
			start, err := fixture.stepUp.Start(context.Background(), StepUpStartRequest{
				Binding: fixture.binding, AllowedFactors: []FactorKind{test.factor},
			})
			if err != nil {
				t.Fatal(err)
			}
			if test.factor == FactorTOTP {
				_, err = fixture.stepUp.CompleteTOTP(context.Background(), TOTPCompletionRequest{
					ChallengeID: start.ChallengeID(), BrowserHandle: start.BrowserHandle(),
					ExpectedBinding: expectedStepUpBinding(start.Binding()),
					FactorID:        fixture.store.totp.ID, Code: []byte("123456"),
					Session:        mfaTestSessionReservation(fixture.binding, SessionAuthenticationTOTP),
					ContinuationID: fixture.binding.ContinuationID, ContinuationReceiptDigest: [32]byte{1},
				})
			} else {
				_, err = fixture.stepUp.CompleteRecovery(context.Background(), RecoveryCompletionRequest{
					ChallengeID: start.ChallengeID(), BrowserHandle: start.BrowserHandle(),
					ExpectedBinding: expectedStepUpBinding(start.Binding()), ExpectedSetID: fixture.store.recovery.ID,
					Code:           []byte("RECOVERY-CODE-1234"),
					Session:        mfaTestSessionReservation(fixture.binding, SessionAuthenticationRecovery),
					ContinuationID: fixture.binding.ContinuationID, ContinuationReceiptDigest: [32]byte{1},
				})
			}
			if !errors.Is(err, ErrFactorRejected) {
				t.Fatalf("completion error = %v", err)
			}
		})
	}
}
