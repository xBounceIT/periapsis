package mfa

import (
	"context"
	"errors"
	"testing"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

func TestMFARevisionCeilingDistinguishesStoredPinsFromSuccessorVersions(t *testing.T) {
	const wantMaximum = uint64(9_007_199_254_740_991)
	if maximumStoredVersion != wantMaximum {
		t.Fatalf("maximumStoredVersion = %d", maximumStoredVersion)
	}
	if !validStoredVersion(wantMaximum) || validStoredVersion(wantMaximum+1) ||
		!validStoredRevision(int64(wantMaximum)) || validStoredRevision(int64(wantMaximum+1)) {
		t.Fatal("stored revision ceiling is not inclusive and JSON-safe")
	}
	if !validStoredSuccessorVersion(wantMaximum-1) || validStoredSuccessorVersion(wantMaximum) {
		t.Fatal("successor revision did not retain one unit of headroom")
	}
}

func TestStepUpBindingAcceptsMaximumPinsAndRequiresAnchorHeadroom(t *testing.T) {
	newBinding := func() StepUpBinding {
		fixture := newStepUpFixture(t)
		binding := fixture.binding
		binding.IdentityEpoch = maximumStoredVersion
		binding.AnchorVersion = maximumStoredVersion - 1
		binding.Requirement.PolicyRevisions[0].Revision = int64(maximumStoredVersion)
		*binding.BaselineEvidence[0].FactorRevision = int64(maximumStoredVersion)
		return binding
	}

	fixture := newStepUpFixture(t)
	if _, err := fixture.stepUp.Start(context.Background(), StepUpStartRequest{
		Binding: newBinding(), AllowedFactors: []FactorKind{FactorTOTP},
	}); err != nil {
		t.Fatalf("maximum passive pins with successor headroom were rejected: %v", err)
	}

	for name, mutate := range map[string]func(*StepUpBinding){
		"anchor at maximum":      func(value *StepUpBinding) { value.AnchorVersion = maximumStoredVersion },
		"identity above maximum": func(value *StepUpBinding) { value.IdentityEpoch = maximumStoredVersion + 1 },
		"policy above maximum": func(value *StepUpBinding) {
			value.Requirement.PolicyRevisions[0].Revision = int64(maximumStoredVersion + 1)
		},
		"evidence above maximum": func(value *StepUpBinding) {
			*value.BaselineEvidence[0].FactorRevision = int64(maximumStoredVersion + 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newStepUpFixture(t)
			binding := newBinding()
			mutate(&binding)
			if _, err := fixture.stepUp.Start(context.Background(), StepUpStartRequest{
				Binding: binding, AllowedFactors: []FactorKind{FactorTOTP},
			}); !errors.Is(err, ErrInvalidStepUp) {
				t.Fatalf("Start() error = %v", err)
			}
		})
	}
}

func TestTOTPCompletionAcceptsMaximumSecurityPinAndRequiresRecordHeadroom(t *testing.T) {
	fixture := newStepUpFixture(t)
	fixture.store.totp.RecordVersion = maximumStoredVersion - 1
	fixture.store.totp.SecurityRevision = int64(maximumStoredVersion)
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
		Session: mfaTestSessionReservation(fixture.binding, SessionAuthenticationTOTP),
	})
	if err != nil || artifact.NewEvidence.FactorRevision == nil ||
		*artifact.NewEvidence.FactorRevision != int64(maximumStoredVersion) ||
		fixture.store.totp.RecordVersion != maximumStoredVersion {
		t.Fatalf("maximum security pin completion = %#v, %v", artifact, err)
	}

	for name, configure := range map[string]func(*TOTPFactor){
		"record without headroom": func(value *TOTPFactor) { value.RecordVersion = maximumStoredVersion },
		"security above maximum": func(value *TOTPFactor) {
			value.SecurityRevision = int64(maximumStoredVersion + 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newStepUpFixture(t)
			configure(&fixture.store.totp)
			start, startErr := fixture.stepUp.Start(context.Background(), StepUpStartRequest{
				Binding: fixture.binding, AllowedFactors: []FactorKind{FactorTOTP},
			})
			if startErr != nil {
				t.Fatal(startErr)
			}
			_, completeErr := fixture.stepUp.CompleteTOTP(context.Background(), TOTPCompletionRequest{
				ChallengeID: start.ChallengeID(), BrowserHandle: start.BrowserHandle(),
				ExpectedBinding: expectedStepUpBinding(start.Binding()),
				FactorID:        fixture.store.totp.ID, Code: []byte("123456"),
				Session: mfaTestSessionReservation(fixture.binding, SessionAuthenticationTOTP),
			})
			if !errors.Is(completeErr, ErrFactorRejected) {
				t.Fatalf("CompleteTOTP() error = %v", completeErr)
			}
		})
	}
}

func TestRecoveryAndClaimedChallengeRequireSuccessorHeadroom(t *testing.T) {
	fixture := newStepUpFixture(t)
	binding := fixture.binding
	if !validRecoverySet(RecoverySet{
		ID: fixture.store.recovery.ID, TenantID: binding.TenantID, UserID: binding.UserID,
		RecordVersion: maximumStoredVersion - 1, SecurityRevision: int64(maximumStoredVersion),
		Status: FactorActive, DigestKeyVersion: 1,
	}, binding) {
		t.Fatal("maximum recovery security pin with record headroom was rejected")
	}
	withoutHeadroom := fixture.store.recovery
	withoutHeadroom.RecordVersion = maximumStoredVersion
	if validRecoverySet(withoutHeadroom, binding) {
		t.Fatal("recovery set without record-version headroom was accepted")
	}

	claimed := ClaimedChallenge{PendingChallenge: PendingChallenge{
		ID: ChallengeID{1}, BrowserDigest: [32]byte{1}, Binding: binding,
		AllowedFactors: []FactorKind{FactorTOTP}, CreatedAt: mfaTestNow,
		ExpiresAt: mfaTestNow.Add(fixture.stepUp.challengeTTL), State: ChallengeClaimed,
		Version: maximumStoredVersion - 1,
	}, ClaimedAt: mfaTestNow}
	if !validClaimedChallenge(mfaTestNow, claimed, FactorTOTP) {
		t.Fatal("claimed challenge with completion headroom was rejected")
	}
	claimed.Version = maximumStoredVersion
	if validClaimedChallenge(mfaTestNow, claimed, FactorTOTP) {
		t.Fatal("claimed challenge without completion headroom was accepted")
	}
}

func TestSessionRevalidationAcceptsMaximumStoredRevisionsAndRejectsMaximumPlusOne(t *testing.T) {
	session, live := localSessionFixture()
	session.Version = maximumStoredVersion
	session.IdentityEpoch, live.IdentityEpoch = maximumStoredVersion, maximumStoredVersion
	session.Primary.PrimaryRevision, live.PrimaryRevision = int64(maximumStoredVersion), int64(maximumStoredVersion)
	session.Primary.SessionInvalidationEpoch = maximumStoredVersion
	live.SessionInvalidationEpoch = maximumStoredVersion
	session.PolicyRevisions[0].Revision = int64(maximumStoredVersion)
	live.Requirement.PolicyRevisions[0].Revision = int64(maximumStoredVersion)
	for index := range session.Evidence {
		revision := int64(maximumStoredVersion)
		session.Evidence[index].Evidence.FactorRevision = &revision
		live.Factors[index].Revision = revision
	}
	if result := RevalidateSession(mfaTestNow, session, live); result.Decision == SessionDeny {
		t.Fatalf("maximum stored revisions were denied: %#v", result)
	}

	for name, mutate := range map[string]func(*SessionSnapshot, *LiveSessionProjection){
		"primary revision": func(value *SessionSnapshot, _ *LiveSessionProjection) {
			value.Primary.PrimaryRevision = int64(maximumStoredVersion + 1)
		},
		"policy revision": func(value *SessionSnapshot, _ *LiveSessionProjection) {
			value.PolicyRevisions[0].Revision = int64(maximumStoredVersion + 1)
		},
		"factor revision": func(value *SessionSnapshot, _ *LiveSessionProjection) {
			revision := int64(maximumStoredVersion + 1)
			value.Evidence[0].Evidence.FactorRevision = &revision
		},
		"live factor revision": func(_ *SessionSnapshot, value *LiveSessionProjection) {
			value.Factors[0].Revision = int64(maximumStoredVersion + 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidateSession, candidateLive := session, live
			candidateSession.Evidence = cloneSessionEvidenceForRevisionTest(session.Evidence)
			candidateSession.PolicyRevisions = append([]identity.AssurancePolicyRevision(nil), session.PolicyRevisions...)
			candidateLive.Factors = append([]FactorState(nil), live.Factors...)
			candidateLive.Requirement = cloneRequirement(live.Requirement)
			mutate(&candidateSession, &candidateLive)
			if result := RevalidateSession(mfaTestNow, candidateSession, candidateLive); result.Decision != SessionDeny {
				t.Fatalf("result = %#v", result)
			}
		})
	}
}

func cloneSessionEvidenceForRevisionTest(values []SessionEvidence) []SessionEvidence {
	result := append([]SessionEvidence(nil), values...)
	for index := range result {
		if result[index].Evidence.FactorRevision != nil {
			revision := *result[index].Evidence.FactorRevision
			result[index].Evidence.FactorRevision = &revision
		}
	}
	return result
}
