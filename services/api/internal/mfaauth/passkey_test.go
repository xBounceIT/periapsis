package mfaauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/modules/identity/webauthn"
)

type passkeyPlanSourceStub struct {
	registration   PasskeyRegistrationPlan
	authentication PasskeyAuthenticationPlan
}

func (source *passkeyPlanSourceStub) ResolvePasskeyRegistration(
	context.Context,
	PasskeyLookup,
) (PasskeyRegistrationPlan, error) {
	return source.registration, nil
}

func (source *passkeyPlanSourceStub) ResolvePasskeyAuthentication(
	context.Context,
	PasskeyLookup,
) (PasskeyAuthenticationPlan, error) {
	return source.authentication, nil
}

type passkeyKernelStub struct {
	registrationCompletion       webauthn.RegistrationCompletion
	authenticationCompletion     webauthn.AuthenticationCompletion
	registrationUserID           identity.EntityID
	authenticationUserID         identity.EntityID
	registrationArtifactMutate   func(*webauthn.RegistrationArtifact)
	authenticationArtifactMutate func(*webauthn.AuthenticationArtifact)
}

func (*passkeyKernelStub) StartRegistration(context.Context, webauthn.RegistrationStartRequest) (webauthn.StartArtifact, error) {
	return webauthn.StartArtifact{}, webauthn.ErrCeremonyRejected
}

func (*passkeyKernelStub) StartAuthentication(context.Context, webauthn.AuthenticationStartRequest) (webauthn.StartArtifact, error) {
	return webauthn.StartArtifact{}, webauthn.ErrCeremonyRejected
}

func (kernel *passkeyKernelStub) FinishRegistrationWithConsumer(
	ctx context.Context,
	_ webauthn.RegistrationResponse,
	consumer webauthn.RegistrationConsumer,
) (webauthn.RegistrationArtifact, error) {
	credential, err := consumer.CompleteRegistration(ctx, kernel.registrationCompletion)
	if err != nil {
		return webauthn.RegistrationArtifact{}, err
	}
	artifact := webauthn.RegistrationArtifact{
		TenantID: credential.TenantID, UserID: credential.UserID, IdentityEpoch: credential.IdentityEpoch,
		CredentialVersion: credential.Version,
		Discoverable:      credential.Discoverable, BackupEligible: credential.BackupEligible,
		BackedUp: credential.BackedUp, Transports: append([]webauthn.CredentialTransport(nil), credential.Transports...),
	}
	if kernel.registrationArtifactMutate != nil {
		kernel.registrationArtifactMutate(&artifact)
	}
	return artifact, nil
}

func (kernel *passkeyKernelStub) FinishAuthenticationWithConsumer(
	ctx context.Context,
	_ webauthn.AuthenticationResponse,
	consumer webauthn.AuthenticationConsumer,
) (webauthn.AuthenticationArtifact, error) {
	result, err := consumer.CompleteAuthentication(ctx, kernel.authenticationCompletion)
	if err != nil {
		return webauthn.AuthenticationArtifact{}, err
	}
	if kernel.authenticationCompletion.CounterDisposition == webauthn.CounterCloneSuspected {
		return webauthn.AuthenticationArtifact{}, webauthn.ErrCredentialCloneSuspected
	}
	evidence, _ := passkeyEvidence(kernel.authenticationCompletion)
	artifact := webauthn.AuthenticationArtifact{
		TenantID: kernel.authenticationCompletion.Binding.TenantID, UserID: kernel.authenticationUserID,
		IdentityEpoch:      kernel.authenticationCompletion.ExpectedIdentityEpoch,
		CredentialVersion:  result.CredentialVersion,
		CredentialDigest:   sha256.Sum256(kernel.authenticationCompletion.CredentialID),
		Evidence:           evidence,
		CounterUnsupported: kernel.authenticationCompletion.CounterDisposition == webauthn.CounterUnsupported,
		BackupStateChanged: kernel.authenticationCompletion.ExpectedBackupEligible !=
			kernel.authenticationCompletion.BackupEligible ||
			kernel.authenticationCompletion.ExpectedBackedUp != kernel.authenticationCompletion.BackedUp,
	}
	if kernel.authenticationArtifactMutate != nil {
		kernel.authenticationArtifactMutate(&artifact)
	}
	return artifact, nil
}

type passkeyTransactionStub struct {
	registrationResult    PasskeyRegistrationApplyResult
	authenticationResult  PasskeyAuthenticationApplyResult
	registrationErr       error
	authenticationErr     error
	registrationRequest   PasskeyRegistrationApply
	authenticationRequest PasskeyAuthenticationApply
	registrationCalls     int
	authenticationCalls   int
	registrationMutate    func(*PasskeyRegistrationApply)
	authenticationMutate  func(*PasskeyAuthenticationApply)
}

func (transaction *passkeyTransactionStub) CompletePasskeyRegistration(
	_ context.Context,
	request PasskeyRegistrationApply,
) (PasskeyRegistrationApplyResult, error) {
	transaction.registrationCalls++
	if transaction.registrationMutate != nil {
		transaction.registrationMutate(&request)
	}
	transaction.registrationRequest = request
	return transaction.registrationResult, transaction.registrationErr
}

func (transaction *passkeyTransactionStub) CompletePasskeyAuthentication(
	_ context.Context,
	request PasskeyAuthenticationApply,
) (PasskeyAuthenticationApplyResult, error) {
	transaction.authenticationCalls++
	if transaction.authenticationMutate != nil {
		transaction.authenticationMutate(&request)
	}
	transaction.authenticationRequest = request
	return transaction.authenticationResult, transaction.authenticationErr
}

func TestPasskeyAuthenticationCouplesCounterSessionPolicyAndAudit(t *testing.T) {
	completedAt := testNow.Add(123 * time.Microsecond)
	binding := webauthn.CeremonyBinding{
		Purpose: webauthn.PurposeStepUpAuthentication, TenantID: testID(1), UserID: testID(2),
		IdentityEpoch: 4, SessionID: testID(3), SessionFamilyID: testID(4), AnchorVersion: 7,
		AnchorExpiresAt: testNow.Add(30 * time.Minute), Action: "case.export", Audience: "tenant-console",
		Requirement: testRequirement(), BaselineEvidence: testPasskeyEvidence(identity.AssurancePrimary),
	}
	completion := webauthn.AuthenticationCompletion{
		CeremonyID: ceremonyID(1), ExpectedCeremonyVersion: 2, Binding: binding,
		ResolvedUserID: testID(2), ExpectedIdentityEpoch: 4,
		CredentialID: []byte{1, 2, 3}, ExpectedCredentialVersion: 5, ExpectedSecurityRevision: 5,
		CompletedAt:       completedAt,
		ExpectedSignCount: 4, ObservedSignCount: 5, CounterDisposition: webauthn.CounterAdvance,
		UserVerified: true,
	}
	credentialResult := webauthn.AuthenticationApplyResult{
		CredentialVersion: 6, SecurityRevision: 5, Status: webauthn.CredentialActive, SignCount: 5,
	}
	transaction := &passkeyTransactionStub{authenticationResult: PasskeyAuthenticationApplyResult{
		Outcome: ApplyCommitted, Credential: credentialResult, TenantID: testID(1), UserID: testID(2), IdentityEpoch: 4,
		AuditID: testID(50), Mutation: SessionRotate, NewSessionID: testID(6),
		NewSessionFamilyID: testID(4), SessionVersion: 8,
	}}
	kernel := &passkeyKernelStub{authenticationCompletion: completion, authenticationUserID: testID(2)}
	service := newPasskeyService(t, kernel, transaction)
	command := testPasskeyAuthenticationCommand(
		completion, testSessionReservation(t, testNow, mfa.SessionAuthenticationPasskey, 6, 4), [32]byte{},
	)
	result, err := service.FinishAuthentication(context.Background(), command)
	if err != nil || result.Apply.NewSessionID != testID(6) ||
		transaction.authenticationRequest.Audit.Kind != AuditPasskeyStepUp ||
		transaction.authenticationRequest.Session.Mutation != SessionRotate ||
		transaction.authenticationRequest.Session.ExpectedSessionID != testID(3) ||
		transaction.authenticationRequest.Session.ExpectedAnchorVersion != 7 ||
		!transaction.authenticationRequest.Completion.UserVerified ||
		!transaction.authenticationRequest.Audit.OccurredAt.Equal(completedAt) {
		t.Fatalf("result = %#v, request = %#v, err = %v", result, transaction.authenticationRequest, err)
	}
}

func TestPresenceOnlyPrimaryCannotCommitSessionForMFARequirement(t *testing.T) {
	binding := webauthn.CeremonyBinding{
		Purpose: webauthn.PurposePrimaryAuthentication, TenantID: testID(1), UserID: testID(2),
		IdentityEpoch: 4, Action: "login", Audience: "tenant-console", Requirement: testRequirement(),
	}
	completion := webauthn.AuthenticationCompletion{
		CeremonyID: ceremonyID(1), ExpectedCeremonyVersion: 2, Binding: binding,
		ResolvedUserID: testID(2), ExpectedIdentityEpoch: 4,
		CredentialID: []byte{1}, ExpectedCredentialVersion: 5, ExpectedSecurityRevision: 5, CompletedAt: testNow,
		ExpectedSignCount: 4, ObservedSignCount: 5, CounterDisposition: webauthn.CounterAdvance,
	}
	transaction := &passkeyTransactionStub{}
	service := newPasskeyService(t, &passkeyKernelStub{
		authenticationCompletion: completion, authenticationUserID: testID(2),
	}, transaction)
	_, err := service.FinishAuthentication(context.Background(), FinishPasskeyAuthenticationCommand{})
	if !errors.Is(err, ErrAuthentication) || transaction.authenticationCalls != 0 {
		t.Fatalf("err = %v, transaction calls = %d", err, transaction.authenticationCalls)
	}
}

func TestDiscoverablePrimaryPinsResolvedUserAndLiveIdentityEpoch(t *testing.T) {
	binding := webauthn.CeremonyBinding{
		Purpose: webauthn.PurposePrimaryAuthentication, TenantID: testID(1),
		Action: "login", Audience: "tenant-console", Requirement: testRequirement(),
	}
	completion := webauthn.AuthenticationCompletion{
		CeremonyID: ceremonyID(1), ExpectedCeremonyVersion: 2, Binding: binding,
		ResolvedUserID: testID(2), ExpectedIdentityEpoch: 9,
		CredentialID: []byte{1}, ExpectedCredentialVersion: 5, ExpectedSecurityRevision: 5, CompletedAt: testNow,
		ExpectedSignCount: 4, ObservedSignCount: 5, CounterDisposition: webauthn.CounterAdvance,
		UserVerified: true,
	}
	transaction := &passkeyTransactionStub{authenticationResult: PasskeyAuthenticationApplyResult{
		Outcome: ApplyCommitted,
		Credential: webauthn.AuthenticationApplyResult{
			CredentialVersion: 6, SecurityRevision: 5, Status: webauthn.CredentialActive, SignCount: 5,
		},
		TenantID: testID(1), UserID: testID(2), IdentityEpoch: 9,
		AuditID: testID(50), Mutation: SessionCreate,
		NewSessionID: testID(6), NewSessionFamilyID: testID(7), SessionVersion: 1,
	}}
	service := newPasskeyService(t, &passkeyKernelStub{
		authenticationCompletion: completion, authenticationUserID: testID(2),
	}, transaction)
	command := testPasskeyAuthenticationCommand(
		completion, testSessionReservation(t, testNow, mfa.SessionAuthenticationPasskey, 6, 7), [32]byte{},
	)
	result, err := service.FinishAuthentication(context.Background(), command)
	request := transaction.authenticationRequest
	if err != nil || result.Apply.UserID != testID(2) || request.Audit.UserID != testID(2) ||
		request.Session.ExpectedIdentityEpoch != 9 || request.Session.Mutation != SessionCreate {
		t.Fatalf("result = %#v, request = %#v, err = %v", result, request, err)
	}
}

func TestContinuationPasskeyRejectsMixedPossessionBeforeTransaction(t *testing.T) {
	binding := webauthn.CeremonyBinding{
		Purpose: webauthn.PurposeContinuationAuthentication, TenantID: testID(1), UserID: testID(2),
		IdentityEpoch: 4, ContinuationID: testID(5), AnchorVersion: 7,
		AnchorExpiresAt: testNow.Add(30 * time.Minute), Action: "session.create", Audience: "api",
		Requirement: testRequirement(), BaselineEvidence: testPasskeyEvidence(identity.AssurancePrimary),
	}
	completion := webauthn.AuthenticationCompletion{
		CeremonyID: ceremonyID(1), ExpectedCeremonyVersion: 2, Binding: binding,
		ResolvedUserID: testID(2), ExpectedIdentityEpoch: 4,
		CredentialID: []byte{1}, ExpectedCredentialVersion: 5, ExpectedSecurityRevision: 5, CompletedAt: testNow,
		ExpectedSignCount: 4, ObservedSignCount: 5, CounterDisposition: webauthn.CounterAdvance,
		UserVerified: true,
	}
	for name, configure := range map[string]func(*CompletionTicketResolutionInput){
		"missing receipt": func(resolution *CompletionTicketResolutionInput) {
			resolution.ContinuationReceiptDigest = [32]byte{}
		},
		"wrong continuation": func(resolution *CompletionTicketResolutionInput) {
			resolution.ContinuationID = testID(99)
		},
	} {
		t.Run(name, func(t *testing.T) {
			transaction := &passkeyTransactionStub{}
			service := newPasskeyService(t, &passkeyKernelStub{
				authenticationCompletion: completion, authenticationUserID: testID(2),
			}, transaction)
			command := testPasskeyAuthenticationCommand(
				completion, testSessionReservation(t, testNow, mfa.SessionAuthenticationPasskey, 6, 7), [32]byte{1},
			)
			configure(&command.Ticket.state.resolution)
			if _, err := service.FinishAuthentication(context.Background(), command); !errors.Is(err, ErrAuthentication) {
				t.Fatalf("FinishAuthentication() error = %v", err)
			}
			if transaction.authenticationCalls != 0 {
				t.Fatalf("transaction calls = %d, want zero", transaction.authenticationCalls)
			}
		})
	}
}

func TestCloneSuspicionCommitsRevocationWithoutCreatingAuthority(t *testing.T) {
	binding := webauthn.CeremonyBinding{
		Purpose: webauthn.PurposeStepUpAuthentication, TenantID: testID(1), UserID: testID(2),
		IdentityEpoch: 4, SessionID: testID(3), SessionFamilyID: testID(4), AnchorVersion: 7,
		AnchorExpiresAt: testNow.Add(30 * time.Minute), Action: "case.export", Audience: "tenant-console",
		Requirement: testRequirement(), BaselineEvidence: testPasskeyEvidence(identity.AssurancePrimary),
	}
	completion := webauthn.AuthenticationCompletion{
		CeremonyID: ceremonyID(1), ExpectedCeremonyVersion: 2, Binding: binding,
		ResolvedUserID: testID(2), ExpectedIdentityEpoch: 4,
		CredentialID: []byte{1}, ExpectedCredentialVersion: 5, ExpectedSecurityRevision: 5, CompletedAt: testNow,
		ExpectedSignCount: 4, ObservedSignCount: 4, CounterDisposition: webauthn.CounterCloneSuspected,
	}
	transaction := &passkeyTransactionStub{authenticationResult: PasskeyAuthenticationApplyResult{
		Outcome: ApplyCommitted,
		Credential: webauthn.AuthenticationApplyResult{
			CredentialVersion: 6, SecurityRevision: 6,
			Status: webauthn.CredentialCloneSuspected, SignCount: 4,
		},
		TenantID: testID(1), UserID: testID(2), IdentityEpoch: 4, AuditID: testID(50),
		Mutation: SessionRevoke, RevokedAnchorID: testID(3), SessionVersion: 8,
	}}
	service := newPasskeyService(t, &passkeyKernelStub{
		authenticationCompletion: completion, authenticationUserID: testID(2),
	}, transaction)
	command := testPasskeyAuthenticationCommand(
		completion, testSessionReservation(t, testNow, mfa.SessionAuthenticationPasskey, 6, 4), [32]byte{},
	)
	_, err := service.FinishAuthentication(context.Background(), command)
	request := transaction.authenticationRequest
	if !errors.Is(err, ErrAuthentication) || transaction.authenticationCalls != 1 ||
		request.Audit.Kind != AuditPasskeyCloneDetected || request.Session.Mutation != SessionRevoke ||
		request.Session.ExpectedSessionID != testID(3) || request.Session.ExpectedIdentityEpoch != 4 ||
		request.Session.ExpectedAnchorExpiry != binding.AnchorExpiresAt ||
		transaction.authenticationResult.NewSessionID != (identity.EntityID{}) {
		t.Fatalf("request = %#v, calls = %d, err = %v", request, transaction.authenticationCalls, err)
	}
}

func TestTransactionCannotMutateStoredAuthenticationExpectation(t *testing.T) {
	binding := webauthn.CeremonyBinding{
		Purpose: webauthn.PurposeStepUpAuthentication, TenantID: testID(1), UserID: testID(2),
		IdentityEpoch: 4, SessionID: testID(3), SessionFamilyID: testID(4), AnchorVersion: 7,
		AnchorExpiresAt: testNow.Add(30 * time.Minute), Action: "case.export", Audience: "tenant-console",
		Requirement: testRequirement(), BaselineEvidence: testPasskeyEvidence(identity.AssurancePrimary),
	}
	completion := webauthn.AuthenticationCompletion{
		CeremonyID: ceremonyID(1), ExpectedCeremonyVersion: 2, Binding: binding,
		ResolvedUserID: testID(2), ExpectedIdentityEpoch: 4,
		CredentialID: []byte{1, 2, 3}, ExpectedCredentialVersion: 5, ExpectedSecurityRevision: 5,
		CompletedAt:       testNow,
		ExpectedSignCount: 4, ObservedSignCount: 5, CounterDisposition: webauthn.CounterAdvance,
		UserVerified: true,
	}
	transaction := &passkeyTransactionStub{
		authenticationResult: PasskeyAuthenticationApplyResult{
			Outcome: ApplyCommitted,
			Credential: webauthn.AuthenticationApplyResult{
				CredentialVersion: 6, SecurityRevision: 5,
				Status: webauthn.CredentialActive, SignCount: 5,
			},
			TenantID: testID(1), UserID: testID(2), IdentityEpoch: 4,
			AuditID: testID(50), Mutation: SessionRotate,
			NewSessionID: testID(6), NewSessionFamilyID: testID(4), SessionVersion: 8,
		},
		authenticationMutate: func(request *PasskeyAuthenticationApply) {
			request.Completion.CredentialID[0] = 0xff
			*request.Completion.Binding.BaselineEvidence[0].FactorRevision = 999
		},
	}
	kernel := &passkeyKernelStub{authenticationCompletion: completion, authenticationUserID: testID(2)}
	service := newPasskeyService(t, kernel, transaction)
	command := testPasskeyAuthenticationCommand(
		completion, testSessionReservation(t, testNow, mfa.SessionAuthenticationPasskey, 6, 4), [32]byte{},
	)
	if _, err := service.FinishAuthentication(context.Background(), command); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(kernel.authenticationCompletion.CredentialID, []byte{1, 2, 3}) ||
		*kernel.authenticationCompletion.Binding.BaselineEvidence[0].FactorRevision != 2 {
		t.Fatal("transaction mutated the kernel-owned completion expectation")
	}
}

func TestPasskeyTransactionCannotClaimWrongSessionFamilyOrUser(t *testing.T) {
	baseBinding := webauthn.CeremonyBinding{
		Purpose: webauthn.PurposeStepUpAuthentication, TenantID: testID(1), UserID: testID(2),
		IdentityEpoch: 4, SessionID: testID(3), SessionFamilyID: testID(4), AnchorVersion: 7,
		AnchorExpiresAt: testNow.Add(30 * time.Minute), Action: "case.export", Audience: "tenant-console",
		Requirement: testRequirement(), BaselineEvidence: testPasskeyEvidence(identity.AssurancePrimary),
	}
	for name, mutate := range map[string]func(*PasskeyAuthenticationApplyResult){
		"wrong family":           func(result *PasskeyAuthenticationApplyResult) { result.NewSessionFamilyID = testID(99) },
		"wrong reserved session": func(result *PasskeyAuthenticationApplyResult) { result.NewSessionID = testID(98) },
		"wrong user":             func(result *PasskeyAuthenticationApplyResult) { result.UserID = testID(99) },
		"wrong epoch":            func(result *PasskeyAuthenticationApplyResult) { result.IdentityEpoch++ },
		"same session":           func(result *PasskeyAuthenticationApplyResult) { result.NewSessionID = testID(3) },
		"missing audit":          func(result *PasskeyAuthenticationApplyResult) { result.AuditID = identity.EntityID{} },
		"restriction retained": func(result *PasskeyAuthenticationApplyResult) {
			result.RecoveryRestricted = true
		},
	} {
		t.Run(name, func(t *testing.T) {
			completion := webauthn.AuthenticationCompletion{
				CeremonyID: ceremonyID(1), ExpectedCeremonyVersion: 2, Binding: baseBinding,
				ResolvedUserID: testID(2), ExpectedIdentityEpoch: 4,
				CredentialID: []byte{1}, ExpectedCredentialVersion: 5, ExpectedSecurityRevision: 5,
				CompletedAt:       testNow,
				ExpectedSignCount: 4, ObservedSignCount: 5, CounterDisposition: webauthn.CounterAdvance,
			}
			apply := PasskeyAuthenticationApplyResult{
				Outcome: ApplyCommitted,
				Credential: webauthn.AuthenticationApplyResult{
					CredentialVersion: 6, SecurityRevision: 5,
					Status: webauthn.CredentialActive, SignCount: 5,
				},
				TenantID: testID(1), UserID: testID(2), IdentityEpoch: 4,
				AuditID: testID(50), Mutation: SessionRotate,
				NewSessionID: testID(6), NewSessionFamilyID: testID(4), SessionVersion: 8,
			}
			mutate(&apply)
			transaction := &passkeyTransactionStub{authenticationResult: apply}
			service := newPasskeyService(t, &passkeyKernelStub{
				authenticationCompletion: completion, authenticationUserID: testID(2),
			}, transaction)
			command := testPasskeyAuthenticationCommand(
				completion, testSessionReservation(t, testNow, mfa.SessionAuthenticationPasskey, 6, 4), [32]byte{},
			)
			_, err := service.FinishAuthentication(context.Background(), command)
			if !errors.Is(err, ErrAuthentication) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestPasskeyRegistrationRejectsResultOutsideExactReservation(t *testing.T) {
	binding := webauthn.CeremonyBinding{
		Purpose: webauthn.PurposeRegistration, TenantID: testID(1), UserID: testID(2),
		IdentityEpoch: 4, SessionID: testID(3), SessionFamilyID: testID(4), AnchorVersion: 7,
		AnchorExpiresAt: testNow.Add(30 * time.Minute), Action: "passkey.enroll", Audience: "tenant-console",
		Requirement: testRequirement(), BaselineEvidence: testPasskeyEvidence(identity.AssuranceMFA),
	}
	credential := webauthn.Credential{
		ID: []byte{1}, PublicKey: bytes.Repeat([]byte{2}, 32), TenantID: testID(1), UserID: testID(2),
		IdentityEpoch: 4, RPID: "auth.example.com", RPRevision: 1, Version: 1, SecurityRevision: 1,
		Status: webauthn.CredentialActive, Discoverable: true, UserVerification: true,
	}
	completion := webauthn.RegistrationCompletion{
		CeremonyID: ceremonyID(1), ExpectedCeremonyVersion: 2, Binding: binding,
		CompletedAt: testNow, Credential: credential,
	}
	transaction := &passkeyTransactionStub{registrationResult: PasskeyRegistrationApplyResult{
		Outcome: ApplyCommitted, Credential: credential, AuditID: testID(50), Mutation: SessionRotate,
		NewSessionID: testID(99), NewSessionFamilyID: testID(4), SessionVersion: 8,
	}}
	service := newPasskeyService(t, &passkeyKernelStub{registrationCompletion: completion}, transaction)
	command := testPasskeyRegistrationCommand(
		completion, testSessionReservation(t, testNow, mfa.SessionAuthenticationPasskey, 6, 4), [32]byte{},
	)
	command.DisplayName = "Primary passkey"
	if _, err := service.FinishRegistration(context.Background(), command); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("FinishRegistration() error = %v", err)
	}
}

func TestRegistrationContinuationIsRetainedAndVersionAdvancedAtomically(t *testing.T) {
	binding := webauthn.CeremonyBinding{
		Purpose: webauthn.PurposeRegistration, TenantID: testID(1), UserID: testID(2),
		IdentityEpoch: 4, ContinuationID: testID(5), AnchorVersion: 7,
		AnchorExpiresAt: testNow.Add(30 * time.Minute), Action: "passkey.enroll", Audience: "tenant-console",
		Requirement: testRequirement(), BaselineEvidence: testPasskeyEvidence(identity.AssuranceMFA),
	}
	credential := webauthn.Credential{
		ID: []byte{1}, PublicKey: bytes.Repeat([]byte{2}, 32), TenantID: testID(1), UserID: testID(2),
		IdentityEpoch: 4,
		RPID:          "auth.example.com", RPRevision: 1, Version: 1, SecurityRevision: 1,
		Status:       webauthn.CredentialActive,
		Discoverable: true, UserVerification: true,
	}
	completion := webauthn.RegistrationCompletion{
		CeremonyID: ceremonyID(1), ExpectedCeremonyVersion: 2, Binding: binding,
		CompletedAt: testNow, Credential: credential,
	}
	transaction := &passkeyTransactionStub{registrationResult: PasskeyRegistrationApplyResult{
		Outcome: ApplyCommitted, Credential: credential, AuditID: testID(50),
		Mutation: SessionRetainContinuation, RetainedContinuationID: testID(5), SessionVersion: 8,
	}}
	service := newPasskeyService(t, &passkeyKernelStub{registrationCompletion: completion}, transaction)
	command := testPasskeyRegistrationCommand(completion, mfa.SessionReservation{}, [32]byte{1})
	command.DisplayName = "Primary passkey"
	result, err := service.FinishRegistration(context.Background(), command)
	if err != nil || result.Apply.RetainedContinuationID != testID(5) ||
		transaction.registrationRequest.DisplayName != "Primary passkey" ||
		transaction.registrationRequest.Audit.Kind != AuditPasskeyEnrolled ||
		transaction.registrationRequest.Session.Mutation != SessionRetainContinuation {
		t.Fatalf("result = %#v, request = %#v, err = %v", result, transaction.registrationRequest, err)
	}
}

func TestPasskeyRegistrationRejectsMissingOrUnsafeDisplayNameBeforeClaim(t *testing.T) {
	t.Parallel()

	for _, displayName := range []string{"", " padded", "unsafe\nname", strings.Repeat("x", 121)} {
		service := newPasskeyService(t, &passkeyKernelStub{}, &passkeyTransactionStub{})
		if _, err := service.FinishRegistration(context.Background(), FinishPasskeyRegistrationCommand{
			DisplayName: displayName,
		}); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("displayName %q error = %v", displayName, err)
		}
	}
}

func TestPasskeyPlansPinDeploymentRPAndRejectWeakUV(t *testing.T) {
	rp, err := webauthn.CompileRelyingParty("auth.example.com", []string{"https://auth.example.com"}, 3)
	if err != nil {
		t.Fatal(err)
	}
	localRevision := int64(3)
	authority, err := NewAuthoritySnapshot(authorityInput([]identity.AssuranceEvidence{{
		Level: identity.AssuranceMFA, Kind: identity.AssuranceEvidenceFactor,
		Source: identity.AssuranceSource{Local: true}, AuthenticatedAt: testNow, FactorRevision: &localRevision,
	}}, false, mfa.FlowExistingSession))
	if err != nil {
		t.Fatal(err)
	}
	policy := webauthn.CeremonyPolicy{
		RequireUserPresence: true, UserVerification: webauthn.UserVerificationRequired,
		ResidentKey: webauthn.ResidentKeyPreferred, Attestation: webauthn.AttestationNone,
	}
	plan, err := NewPasskeyRegistrationPlan(testID(3), authority, rp, policy)
	if err != nil || plan.request.RP.Revision() != 3 || plan.request.Binding.AnchorVersion != 5 {
		t.Fatalf("plan = %#v, err = %v", plan, err)
	}
	policy.UserVerification = webauthn.UserVerificationPreferred
	if _, err := NewPasskeyRegistrationPlan(testID(3), authority, rp, policy); err == nil {
		t.Fatal("registration accepted preferred user verification")
	}
	authority.resolved.Requirement.Level = identity.AssurancePhishingResistant
	if _, err := NewStepUpPasskeyPlan(testID(3), authority, rp, policy); err == nil {
		t.Fatal("phishing-resistant step-up accepted preferred user verification")
	}
}

func TestPrimaryPasskeyPlanRequiresUserVerificationForMFA(t *testing.T) {
	rp, err := webauthn.CompileRelyingParty("auth.example.com", []string{"https://auth.example.com"}, 3)
	if err != nil {
		t.Fatal(err)
	}
	policyContext := mfa.PolicyContext{TenantID: testID(1), Action: "login"}
	input := PrimaryPasskeyPlanInput{
		ReferenceID: testID(9), LoadedAt: testNow, TenantID: testID(1), UserID: testID(2), IdentityEpoch: 4,
		Action: "login", Audience: "tenant-console", PolicyContext: policyContext,
		Policies: []mfa.ScopedPolicy{{
			Scope: mfa.PolicyTenantBaseline, TenantID: testID(1),
			Policy: identity.AssurancePolicy{ID: testID(10), Revision: 3, Level: identity.AssuranceMFA},
		}},
		RP: rp, Mode: webauthn.AuthenticationKnownUser,
		UserHandle: bytes.Repeat([]byte{1}, 32), CredentialIDs: [][]byte{{1, 2, 3}},
		Policy: webauthn.CeremonyPolicy{
			RequireUserPresence: true, UserVerification: webauthn.UserVerificationPreferred,
			ResidentKey: webauthn.ResidentKeyPreferred, Attestation: webauthn.AttestationNone,
		},
	}
	if _, err := NewPrimaryPasskeyPlan(input); err == nil {
		t.Fatal("MFA primary plan accepted preferred user verification")
	}
	input.Policy.UserVerification = webauthn.UserVerificationRequired
	plan, err := NewPrimaryPasskeyPlan(input)
	if err != nil || plan.request.Binding.IdentityEpoch != 4 || plan.request.Binding.Audience != "tenant-console" {
		t.Fatalf("plan = %#v, err = %v", plan, err)
	}
}

func TestPasskeyFormattingRedactsBrowserAndCredentialMaterial(t *testing.T) {
	canary := "PASSKEY-RAW-MATERIAL-CANARY"
	values := []any{
		FinishPasskeyAuthenticationCommand{Response: webauthn.AuthenticationResponse{Signature: []byte(canary)}},
		PasskeyAuthenticationResult{},
		PasskeyAuthenticationApply{Completion: webauthn.AuthenticationCompletion{CredentialID: []byte(canary)}},
		FinishPasskeyRegistrationCommand{Response: webauthn.RegistrationResponse{AttestationObject: []byte(canary)}},
		PrimaryPasskeyPlanInput{Action: canary, Audience: canary, UserHandle: []byte(canary)},
		PasskeyRegistrationPlan{request: webauthn.RegistrationStartRequest{UserHandle: []byte(canary)}},
		PasskeyAuthenticationPlan{request: webauthn.AuthenticationStartRequest{UserHandle: []byte(canary)}},
		PasskeyRegistrationApplyResult{Credential: webauthn.Credential{ID: []byte(canary), PublicKey: []byte(canary)}},
		PasskeyAuthenticationApplyResult{UserID: testID(2)},
	}
	for _, value := range values {
		if formatted := fmt.Sprintf("%#v", value); strings.Contains(formatted, canary) {
			t.Fatalf("unsafe format %T: %s", value, formatted)
		}
	}
}

func newPasskeyService(t *testing.T, kernel PasskeyKernel, transaction PasskeyTransaction) *Passkey {
	t.Helper()
	service, err := NewPasskey(PasskeyOptions{
		Plans: &passkeyPlanSourceStub{}, Admissions: &gateStub{decision: AdmissionDecision{Outcome: AdmissionAllowed}},
		Kernel: kernel, Transactions: transaction, Now: func() time.Time { return testNow },
		OperationTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func testRequirement() identity.EffectiveAssuranceRequirement {
	return identity.EffectiveAssuranceRequirement{
		Level:           identity.AssuranceMFA,
		PolicyRevisions: []identity.AssurancePolicyRevision{{PolicyID: testID(10), Revision: 3}},
	}
}

func testPasskeyEvidence(level identity.AssuranceLevel) []identity.AssuranceEvidence {
	revision := int64(2)
	return []identity.AssuranceEvidence{{
		Level: level, Kind: identity.AssuranceEvidenceFactor,
		Source: identity.AssuranceSource{Local: true}, AuthenticatedAt: testNow, FactorRevision: &revision,
	}}
}

func ceremonyID(value byte) webauthn.CeremonyID {
	var id webauthn.CeremonyID
	id[31] = value
	return id
}
