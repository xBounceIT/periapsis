package webauthn

import (
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

type authenticationConsumerFunc func(context.Context, AuthenticationCompletion) (AuthenticationApplyResult, error)

func (function authenticationConsumerFunc) CompleteAuthentication(
	ctx context.Context,
	completion AuthenticationCompletion,
) (AuthenticationApplyResult, error) {
	return function(ctx, completion)
}

type registrationConsumerFunc func(context.Context, RegistrationCompletion) (Credential, error)

func (function registrationConsumerFunc) CompleteRegistration(
	ctx context.Context,
	completion RegistrationCompletion,
) (Credential, error) {
	return function(ctx, completion)
}

func TestAuthenticationConsumerReceivesExactAnchorAndUserVerificationPins(t *testing.T) {
	fixture := newKernelFixture(t)
	if _, _, err := fixture.register(); err != nil {
		t.Fatal(err)
	}
	start, err := fixture.startAuthentication(AuthenticationKnownUser)
	if err != nil {
		t.Fatal(err)
	}
	called := 0
	consumer := authenticationConsumerFunc(func(ctx context.Context, completion AuthenticationCompletion) (AuthenticationApplyResult, error) {
		called++
		if completion.Binding.SessionID != fixture.binding.SessionID ||
			completion.Binding.SessionFamilyID != fixture.binding.SessionFamilyID ||
			completion.Binding.AnchorVersion != fixture.binding.AnchorVersion || !completion.UserVerified ||
			completion.ExpectedSecurityRevision != 1 || completion.ExpectedBackupEligible ||
			completion.ExpectedBackedUp {
			t.Fatalf("completion = %#v", completion)
		}
		return fixture.repository.CompleteAuthentication(ctx, completion)
	})
	_, err = fixture.kernel.FinishAuthenticationWithConsumer(context.Background(), AuthenticationResponse{
		CeremonyID: start.CeremonyID(), BrowserHandle: start.BrowserHandle(), CredentialID: fixture.credentialID,
		ClientDataJSON: []byte("client-data"), AuthenticatorData: []byte("authenticator-data"),
		Signature: []byte("signature"), UserHandle: fixture.userHandle,
	}, consumer)
	if err != nil || called != 1 {
		t.Fatalf("calls = %d, err = %v", called, err)
	}
}

func TestCeremonyBindingRequiresExactSessionOrContinuationVersion(t *testing.T) {
	fixture := newKernelFixture(t)
	tests := map[string]func(*CeremonyBinding){
		"missing session": func(binding *CeremonyBinding) { binding.SessionID = identity.EntityID{} },
		"missing family":  func(binding *CeremonyBinding) { binding.SessionFamilyID = identity.EntityID{} },
		"missing version": func(binding *CeremonyBinding) { binding.AnchorVersion = 0 },
		"missing epoch":   func(binding *CeremonyBinding) { binding.IdentityEpoch = 0 },
		"expired anchor":  func(binding *CeremonyBinding) { binding.AnchorExpiresAt = fixture.now.Add(-time.Millisecond) },
		"noncanonical deadline": func(binding *CeremonyBinding) {
			binding.AnchorExpiresAt = binding.AnchorExpiresAt.Add(time.Microsecond)
		},
		"mixed anchors": func(binding *CeremonyBinding) { binding.ContinuationID = testID(9) },
		"future evidence": func(binding *CeremonyBinding) {
			binding.BaselineEvidence[0].AuthenticatedAt = fixture.now.Add(time.Minute)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			binding := fixture.binding
			binding.Purpose = PurposeStepUpAuthentication
			mutate(&binding)
			_, err := fixture.kernel.StartAuthentication(context.Background(), AuthenticationStartRequest{
				RP: fixture.rp, Binding: binding, Policy: fixture.registrationPolicy(), Mode: AuthenticationKnownUser,
				UserHandle: fixture.userHandle, AllowedCredentialIDs: [][]byte{fixture.credentialID},
			})
			if !errors.Is(err, ErrCeremonyRejected) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestObservedInstantsRetainMicrosecondsWhileDeadlinesAreMilliseconds(t *testing.T) {
	fixture := newKernelFixture(t)
	observed := testNow.Add(123_456 * time.Microsecond)
	*fixture.now = observed
	start, err := fixture.kernel.StartRegistration(context.Background(), RegistrationStartRequest{
		RP: fixture.rp, Binding: fixture.binding, Policy: fixture.registrationPolicy(), UserHandle: fixture.userHandle,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.repository.mu.Lock()
	pending := fixture.repository.ceremonies[start.CeremonyID()]
	fixture.repository.mu.Unlock()
	if !pending.CreatedAt.Equal(observed) || pending.CreatedAt.Nanosecond()%int(time.Millisecond) == 0 ||
		pending.ExpiresAt.Nanosecond()%int(time.Millisecond) != 0 || !start.ExpiresAt().Equal(pending.ExpiresAt) {
		t.Fatalf("created/deadline = %s / %s", pending.CreatedAt, pending.ExpiresAt)
	}

	var completedAt time.Time
	consumer := registrationConsumerFunc(func(ctx context.Context, completion RegistrationCompletion) (Credential, error) {
		completedAt = completion.CompletedAt
		return fixture.repository.CompleteRegistration(ctx, completion)
	})
	if _, err := fixture.kernel.FinishRegistrationWithConsumer(context.Background(), RegistrationResponse{
		CeremonyID: start.CeremonyID(), BrowserHandle: start.BrowserHandle(), CredentialID: fixture.credentialID,
		ClientDataJSON: []byte("client-data"), AttestationObject: []byte("attestation"),
	}, consumer); err != nil {
		t.Fatal(err)
	}
	if !completedAt.Equal(observed) || completedAt.Nanosecond()%int(time.Millisecond) == 0 {
		t.Fatalf("completedAt = %s", completedAt)
	}
}

func TestAuthenticationConsumerCannotLieAboutBackupProjection(t *testing.T) {
	fixture := newKernelFixture(t)
	if _, _, err := fixture.register(); err != nil {
		t.Fatal(err)
	}
	start, err := fixture.startAuthentication(AuthenticationKnownUser)
	if err != nil {
		t.Fatal(err)
	}
	consumer := authenticationConsumerFunc(func(_ context.Context, completion AuthenticationCompletion) (AuthenticationApplyResult, error) {
		return AuthenticationApplyResult{
			CredentialVersion: completion.ExpectedCredentialVersion + 1,
			SecurityRevision:  completion.ExpectedSecurityRevision,
			Status:            CredentialActive, SignCount: completion.ObservedSignCount,
			BackupEligible: !completion.BackupEligible, BackedUp: completion.BackedUp,
		}, nil
	})
	_, err = fixture.kernel.FinishAuthenticationWithConsumer(context.Background(), AuthenticationResponse{
		CeremonyID: start.CeremonyID(), BrowserHandle: start.BrowserHandle(), CredentialID: fixture.credentialID,
		ClientDataJSON: []byte("client-data"), AuthenticatorData: []byte("authenticator-data"),
		Signature: []byte("signature"), UserHandle: fixture.userHandle,
	}, consumer)
	if !errors.Is(err, ErrCredentialRejected) {
		t.Fatalf("got %v", err)
	}
}

func TestAuthenticationConsumerCannotLieAboutSecurityRevision(t *testing.T) {
	fixture := newKernelFixture(t)
	if _, _, err := fixture.register(); err != nil {
		t.Fatal(err)
	}
	start, err := fixture.startAuthentication(AuthenticationKnownUser)
	if err != nil {
		t.Fatal(err)
	}
	consumer := authenticationConsumerFunc(func(_ context.Context, completion AuthenticationCompletion) (AuthenticationApplyResult, error) {
		return AuthenticationApplyResult{
			CredentialVersion: completion.ExpectedCredentialVersion + 1,
			SecurityRevision:  completion.ExpectedSecurityRevision + 1,
			Status:            CredentialActive, SignCount: completion.ObservedSignCount,
			BackupEligible: completion.BackupEligible, BackedUp: completion.BackedUp,
		}, nil
	})
	_, err = fixture.kernel.FinishAuthenticationWithConsumer(context.Background(), AuthenticationResponse{
		CeremonyID: start.CeremonyID(), BrowserHandle: start.BrowserHandle(), CredentialID: fixture.credentialID,
		ClientDataJSON: []byte("client-data"), AuthenticatorData: []byte("authenticator-data"),
		Signature: []byte("signature"), UserHandle: fixture.userHandle,
	}, consumer)
	if !errors.Is(err, ErrCredentialRejected) {
		t.Fatalf("got %v", err)
	}
}

func TestRegistrationConsumerCannotMutateKernelExpectedCredential(t *testing.T) {
	fixture := newKernelFixture(t)
	start, err := fixture.kernel.StartRegistration(context.Background(), RegistrationStartRequest{
		RP: fixture.rp, Binding: fixture.binding, Policy: fixture.registrationPolicy(), UserHandle: fixture.userHandle,
	})
	if err != nil {
		t.Fatal(err)
	}
	consumer := registrationConsumerFunc(func(_ context.Context, completion RegistrationCompletion) (Credential, error) {
		completion.Credential.ID[0] ^= 0xff
		return completion.Credential, nil
	})
	_, err = fixture.kernel.FinishRegistrationWithConsumer(context.Background(), RegistrationResponse{
		CeremonyID: start.CeremonyID(), BrowserHandle: start.BrowserHandle(), CredentialID: fixture.credentialID,
		ClientDataJSON: []byte("client-data"), AttestationObject: []byte("attestation"),
		Transports: []CredentialTransport{TransportInternal},
	}, consumer)
	if !errors.Is(err, ErrCredentialRejected) {
		t.Fatalf("got %v", err)
	}
}
