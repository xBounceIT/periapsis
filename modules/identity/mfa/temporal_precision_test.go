package mfa

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestStepUpObservedInstantsRetainMicrosecondsWhileDeadlinesAreMilliseconds(t *testing.T) {
	fixture := newStepUpFixture(t)
	observed := mfaTestNow.Add(123_456 * time.Microsecond)
	*fixture.now = observed
	start, err := fixture.stepUp.Start(context.Background(), StepUpStartRequest{
		Binding: fixture.binding, AllowedFactors: []FactorKind{FactorTOTP},
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.store.mu.Lock()
	pending := fixture.store.challenges[start.ChallengeID()]
	fixture.store.mu.Unlock()
	if !pending.CreatedAt.Equal(observed) || pending.CreatedAt.Nanosecond()%int(time.Millisecond) == 0 ||
		pending.ExpiresAt.Nanosecond()%int(time.Millisecond) != 0 || !start.ExpiresAt().Equal(pending.ExpiresAt) {
		t.Fatalf("created/deadline = %s / %s", pending.CreatedAt, pending.ExpiresAt)
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
	fixture.store.mu.Lock()
	claimedAt := fixture.store.lastClaimedAt
	fixture.store.mu.Unlock()
	if !claimedAt.Equal(observed) || claimedAt.Nanosecond()%int(time.Millisecond) == 0 ||
		!artifact.NewEvidence.AuthenticatedAt.Equal(observed) ||
		artifact.NewEvidence.AuthenticatedAt.Nanosecond()%int(time.Millisecond) == 0 {
		t.Fatalf("claimed/completed = %s / %s", claimedAt, artifact.NewEvidence.AuthenticatedAt)
	}
}

func TestStepUpRejectsSubMillisecondDeadlines(t *testing.T) {
	fixture := newStepUpFixture(t)
	fixture.binding.AnchorExpiresAt = fixture.binding.AnchorExpiresAt.Add(time.Microsecond)
	if _, err := fixture.stepUp.Start(context.Background(), StepUpStartRequest{
		Binding: fixture.binding, AllowedFactors: []FactorKind{FactorTOTP},
	}); !errors.Is(err, ErrInvalidStepUp) {
		t.Fatalf("sub-millisecond anchor deadline error = %v", err)
	}

	fixture = newStepUpFixture(t)
	claimed := ClaimedChallenge{PendingChallenge: PendingChallenge{
		ID: ChallengeID{1}, BrowserDigest: [32]byte{1}, Binding: fixture.binding,
		AllowedFactors: []FactorKind{FactorTOTP}, CreatedAt: mfaTestNow,
		ExpiresAt: mfaTestNow.Add(fixture.stepUp.challengeTTL).Add(time.Microsecond),
		State:     ChallengeClaimed, Version: 2,
	}, ClaimedAt: mfaTestNow}
	if validClaimedChallenge(mfaTestNow, claimed, FactorTOTP) {
		t.Fatal("sub-millisecond challenge deadline was accepted")
	}
}

func TestSessionSnapshotUsesMicrosecondIssueTimeAndMillisecondDeadlines(t *testing.T) {
	session, live := localSessionFixture()
	observed := mfaTestNow.Add(456 * time.Microsecond)
	session.IssuedAt = session.IssuedAt.Add(456 * time.Microsecond)
	if result := RevalidateSession(observed, session, live); result.Decision == SessionDeny {
		t.Fatalf("microsecond issue time was denied: %#v", result)
	}

	for name, mutate := range map[string]func(*SessionSnapshot){
		"idle": func(value *SessionSnapshot) {
			value.IdleExpiresAt = value.IdleExpiresAt.Add(time.Microsecond)
		},
		"absolute": func(value *SessionSnapshot) {
			value.AbsoluteExpiresAt = value.AbsoluteExpiresAt.Add(time.Microsecond)
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := session
			mutate(&candidate)
			if result := RevalidateSession(observed, candidate, live); result.Decision != SessionDeny {
				t.Fatalf("sub-millisecond deadline result = %#v", result)
			}
		})
	}
}
