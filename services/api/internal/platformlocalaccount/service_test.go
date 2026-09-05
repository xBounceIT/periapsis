package platformlocalaccount

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/modules/identity/localaccount"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

var serviceTestNow = time.Date(2026, 8, 30, 12, 0, 0, 123_000_000, time.UTC)

const testGeneratedPasswordPHC = "$argon2id$v=19$m=65536,t=3,p=1$AQIDBAUGBwgJCgsMDQ4PEA$AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"

type localAccountRepositoryStub struct {
	calls int
	list  func(context.Context, ListParams) ([]Account, error)
	get   func(context.Context, GetParams) (Account, error)
	apply func(context.Context, ApplyParams) (ApplyResult, error)
}

func (stub *localAccountRepositoryStub) List(ctx context.Context, params ListParams) ([]Account, error) {
	stub.calls++
	if stub.list == nil {
		return nil, authentication.ErrUnavailable
	}
	return stub.list(ctx, params)
}

func (stub *localAccountRepositoryStub) Get(ctx context.Context, params GetParams) (Account, error) {
	stub.calls++
	if stub.get == nil {
		return Account{}, authentication.ErrUnavailable
	}
	return stub.get(ctx, params)
}

func (stub *localAccountRepositoryStub) Apply(ctx context.Context, params ApplyParams) (ApplyResult, error) {
	stub.calls++
	if stub.apply == nil {
		return ApplyResult{}, authentication.ErrUnavailable
	}
	return stub.apply(ctx, params)
}

type passwordHasherStub struct {
	hashCalls   int
	verifyCalls int
}

type totpEnrollmentSecurityStub struct{}

func (totpEnrollmentSecurityStub) New(
	_ context.Context,
	request NewTOTPEnrollmentRequest,
) (TOTPEnrollmentMaterial, error) {
	context, err := pendingTOTPContext(request)
	if err != nil {
		return TOTPEnrollmentMaterial{}, err
	}
	secret := "JBSWY3DPEHPK3PXP"
	return TOTPEnrollmentMaterial{
		ProtectedSecret: testEncryptedTOTP(context), DisplaySecret: []byte(secret),
		ProvisioningURI: []byte("otpauth://totp/Periapsis:" + request.AccountID.String() +
			"?issuer=Periapsis&secret=" + secret),
	}, nil
}

func (totpEnrollmentSecurityStub) Confirm(
	_ context.Context,
	request ConfirmTOTPEnrollmentRequest,
) (ConfirmedTOTPFactor, error) {
	context, err := authentication.CredentialTOTPContextAtRevision(
		request.Pending.FactorID, request.Pending.UserID, request.Pending.FactorRevision,
	)
	if err != nil {
		return ConfirmedTOTPFactor{}, err
	}
	return ConfirmedTOTPFactor{
		FactorID: request.Pending.FactorID, Revision: request.Pending.FactorRevision,
		ProtectedSecret: testEncryptedTOTP(context), AcceptedCounter: 123,
		EncryptionAlgorithm: "aes-256-gcm", OTPAlgorithm: "SHA1", Digits: 6, PeriodSeconds: 30,
	}, nil
}

type countingTOTPEnrollmentSecurity struct {
	confirmCalls int
}

func (security *countingTOTPEnrollmentSecurity) New(
	ctx context.Context,
	request NewTOTPEnrollmentRequest,
) (TOTPEnrollmentMaterial, error) {
	return (totpEnrollmentSecurityStub{}).New(ctx, request)
}

func (security *countingTOTPEnrollmentSecurity) Confirm(
	ctx context.Context,
	request ConfirmTOTPEnrollmentRequest,
) (ConfirmedTOTPFactor, error) {
	security.confirmCalls++
	return (totpEnrollmentSecurityStub{}).Confirm(ctx, request)
}

func testEncryptedTOTP(context string) authentication.EncryptedSecret {
	return authentication.EncryptedSecret{
		Ciphertext: bytes.Repeat([]byte{0x42}, 32), Nonce: bytes.Repeat([]byte{0x24}, 12),
		AAD: []byte(context), KeyVersion: 1,
	}
}

func (stub *passwordHasherStub) Hash(password []byte) ([]byte, error) {
	stub.hashCalls++
	return []byte(testGeneratedPasswordPHC), nil
}

func (stub *passwordHasherStub) Verify(password, encoded []byte) bool {
	stub.verifyCalls++
	return bytes.HasSuffix(encoded, password)
}

func TestInviteIssuesOneOwnedTokenAndReplaysWithoutSecret(t *testing.T) {
	repository := &localAccountRepositoryStub{}
	service := newTestService(t, repository, &passwordHasherStub{})
	input := validInviteInput(t)
	var observed ApplyParams
	repository.apply = func(_ context.Context, params ApplyParams) (ApplyResult, error) {
		observed = params
		plan, err := params.Plan(PlanningState{FreshLocalMFA: true, ProtectedWorkflow: true})
		if err != nil {
			return ApplyResult{}, err
		}
		if plan.Audit != localaccount.AuditInvited || !plan.IssueInvitation ||
			params.CanonicalLoginIdentifier != "new.admin@example.test" || params.DisplayName != "New Admin" ||
			params.IssueCeremonyTokenExpiresAt != serviceTestNow.Add(ceremonyLifetime) {
			t.Fatalf("invite params/plan = %#v / %#v", params, plan)
		}
		account := invitedAccount(uuid.UUID(plan.AccountID), uuid.UUID(plan.UserID))
		return params.ValidateResult(ApplyResult{Account: account, ArtifactIssued: true})
	}
	result, err := service.Invite(context.Background(), manageSession(), input)
	if err != nil || result.Replayed || result.Account.Status != StatusInvited {
		t.Fatalf("Invite() = %#v, %v", result, err)
	}
	defer result.Destroy()
	material, ok := result.Artifact.Consume()
	if !ok || !validOpaqueToken(material.CeremonyToken) || len(material.TOTPSecret) == 0 ||
		len(material.ProvisioningURI) == 0 {
		t.Fatalf("invitation material = %q, %t", material, ok)
	}
	material.Destroy()
	if duplicate, duplicateOK := result.Artifact.Consume(); duplicateOK ||
		len(duplicate.CeremonyToken)+len(duplicate.TOTPSecret)+len(duplicate.ProvisioningURI) != 0 {
		t.Fatal("one-time invitation token was consumable twice")
	}
	if observed.IssueCeremonyTokenDigest == ([sha256.Size]byte{}) ||
		strings.Contains(fmt.Sprintf("%#v", observed), "new.admin@example.test") {
		t.Fatalf("unsafe apply formatting or missing digest: %#v", observed)
	}

	repository.apply = func(_ context.Context, params ApplyParams) (ApplyResult, error) {
		return params.ValidateResult(ApplyResult{Account: invitedAccount(localTestID(80), localTestID(81)), Replayed: true})
	}
	replay, err := service.Invite(context.Background(), manageSession(), input)
	if err != nil || !replay.Replayed {
		t.Fatalf("Invite() replay = %#v, %v", replay, err)
	}
	if leaked, leakedOK := replay.Artifact.Consume(); leakedOK ||
		len(leaked.CeremonyToken)+len(leaked.TOTPSecret)+len(leaked.ProvisioningURI) != 0 {
		t.Fatal("idempotent replay reissued invitation material")
	}
}

func TestActivationReplayInvokesNoEnrollmentCallbackAndReturnsNoArtifact(t *testing.T) {
	repository := &localAccountRepositoryStub{}
	service := newTestService(t, repository, &passwordHasherStub{})
	enrollment := &countingTOTPEnrollmentSecurity{}
	service.enrollment = enrollment
	accountID := localTestID(30)
	tag, _ := EntityTag(1)
	repository.apply = func(_ context.Context, params ApplyParams) (ApplyResult, error) {
		if params.ConfirmTOTPEnrollment == nil || params.Plan == nil || params.ValidateResult == nil {
			t.Fatal("activation callbacks were not supplied")
		}
		return params.ValidateResult(ApplyResult{
			Account: activeAccount(accountID, localTestID(31), 2), Replayed: true,
		})
	}
	result, err := service.Activate(context.Background(), manageSession(), accountID, ActivationInput{
		Reason: "Complete reviewed recovery enrollment", IdempotencyKey: "local-activate-0001",
		ExpectedEntityTag: &tag, CeremonyToken: base64Token(0x41),
		NewPassword: []byte("correct horse battery staple"), FactorProof: []byte("123456"), Event: testEvent(),
	})
	if err != nil || !result.Replayed || enrollment.confirmCalls != 0 {
		t.Fatalf("Activate(replay) = %#v, %v, confirm calls=%d", result, err, enrollment.confirmCalls)
	}
	if artifact, ok := result.Artifact.Consume(); ok || len(artifact.CeremonyToken) != 0 ||
		len(artifact.TOTPSecret) != 0 || len(artifact.ProvisioningURI) != 0 {
		t.Fatalf("activation replay artifact = %#v, %t", artifact, ok)
	}

	repository.apply = func(_ context.Context, params ApplyParams) (ApplyResult, error) {
		return params.ValidateResult(ApplyResult{
			Account: activeAccount(localTestID(32), localTestID(33), 2), Replayed: true,
		})
	}
	_, err = service.Activate(context.Background(), manageSession(), accountID, ActivationInput{
		Reason: "Complete reviewed recovery enrollment", IdempotencyKey: "local-activate-0001",
		ExpectedEntityTag: &tag, CeremonyToken: base64Token(0x42),
		NewPassword: []byte("correct horse battery staple"), FactorProof: []byte("123456"), Event: testEvent(),
	})
	if !errors.Is(err, authentication.ErrUnavailable) || enrollment.confirmCalls != 0 {
		t.Fatalf("Activate(cross-account replay) = %v, confirm calls=%d", err, enrollment.confirmCalls)
	}

	repository.apply = func(_ context.Context, params ApplyParams) (ApplyResult, error) {
		return params.ValidateResult(ApplyResult{
			Account: activeAccount(accountID, localTestID(31), 3), Replayed: true,
		})
	}
	_, err = service.Activate(context.Background(), manageSession(), accountID, ActivationInput{
		Reason: "Complete reviewed recovery enrollment", IdempotencyKey: "local-activate-0001",
		ExpectedEntityTag: &tag, CeremonyToken: base64Token(0x42),
		NewPassword: []byte("correct horse battery staple"), FactorProof: []byte("123456"), Event: testEvent(),
	})
	if !errors.Is(err, authentication.ErrUnavailable) || enrollment.confirmCalls != 0 {
		t.Fatalf("Activate(wrong-revision replay) = %v, confirm calls=%d", err, enrollment.confirmCalls)
	}
}

func TestLifecyclePlansCASRecoveryFloorAndConsequenceCompleteRecovery(t *testing.T) {
	repository := &localAccountRepositoryStub{}
	service := newTestService(t, repository, &passwordHasherStub{})
	account := activeAccount(localTestID(10), localTestID(11), 4)
	tag, _ := EntityTag(account.Revision)
	input := TransitionInput{
		Reason: "Emergency credential repair", IdempotencyKey: "local-recovery-0001",
		ExpectedEntityTag: &tag, Event: testEvent(),
	}

	repository.apply = func(_ context.Context, params ApplyParams) (ApplyResult, error) {
		snapshot, err := plannerSnapshot(account)
		if err != nil {
			t.Fatal(err)
		}
		_, err = params.Plan(PlanningState{
			Snapshot: snapshot, RecoveryFleet: localaccount.RecoveryFleet{CurrentPrincipalReady: true},
			FreshLocalMFA: true, ProtectedWorkflow: true,
		})
		return ApplyResult{}, err
	}
	account.ProtectedRecoveryPrincipal = true
	repository.get = func(context.Context, GetParams) (Account, error) { return account, nil }
	if _, err := service.Recover(context.Background(), manageSession(), account.ID, input); !errors.Is(err, ErrTransitionConflict) {
		t.Fatalf("Recover(last ready) = %v", err)
	}

	repository.apply = func(_ context.Context, params ApplyParams) (ApplyResult, error) {
		snapshot, err := plannerSnapshot(account)
		if err != nil {
			t.Fatal(err)
		}
		plan, err := params.Plan(PlanningState{
			Snapshot:      snapshot,
			RecoveryFleet: localaccount.RecoveryFleet{CurrentPrincipalReady: true, OtherReadyHumanPrincipals: 1},
			FreshLocalMFA: true, ProtectedWorkflow: true,
		})
		if err != nil {
			return ApplyResult{}, err
		}
		if !plan.RevokeSessions || !plan.RetireChallenges || !plan.RotateCredential ||
			!plan.RevokeFactors || !plan.RetireRecoverySets || !plan.RecheckRecoveryFloor ||
			!plan.IssueRecoveryContinuation {
			t.Fatalf("incomplete recovery plan: %#v", plan)
		}
		next := account
		next.Status = StatusRecoveryRestricted
		next.Revision = plan.NextRevision
		next.IdentityEpoch = plan.NextIdentityEpoch
		next.CredentialStatus = CredentialPending
		next.CredentialVersion++
		next.ConfirmedAcceptableFactors = 0
		next.RecoveryStartedAt = cloneTime(&serviceTestNow)
		next.UpdatedAt = serviceTestNow
		return params.ValidateResult(ApplyResult{Account: next, ArtifactIssued: true})
	}
	result, err := service.Recover(context.Background(), manageSession(), account.ID, input)
	if err != nil || result.Account.Status != StatusRecoveryRestricted || result.Replayed {
		t.Fatalf("Recover() = %#v, %v", result, err)
	}
	defer result.Destroy()
	if artifact, ok := result.Artifact.Consume(); !ok || !validOpaqueToken(artifact.CeremonyToken) ||
		len(artifact.TOTPSecret) == 0 || len(artifact.ProvisioningURI) == 0 {
		t.Fatalf("recovery artifact invalid: %q, %t", artifact, ok)
	} else {
		artifact.Destroy()
	}
}

func TestActivationConsumesOnlyDigestAndRejectsStaleOrUnreadyState(t *testing.T) {
	repository := &localAccountRepositoryStub{}
	service := newTestService(t, repository, &passwordHasherStub{})
	accountID, userID := localTestID(20), localTestID(21)
	tag, _ := EntityTag(1)
	token := base64Token(0x42)
	input := ActivationInput{
		Reason: "Enrollment verified", IdempotencyKey: "local-activate-0001",
		ExpectedEntityTag: &tag, CeremonyToken: token,
		NewPassword: []byte("correct horse battery staple"), FactorProof: []byte("123456"), Event: testEvent(),
	}
	repository.apply = func(_ context.Context, params ApplyParams) (ApplyResult, error) {
		if params.CeremonyTokenDigest == ([sha256.Size]byte{}) || len(params.ReplacementPasswordPHC) < 32 {
			t.Fatalf("activation material crossed repository incorrectly: %#v", params)
		}
		pendingRequest := NewTOTPEnrollmentRequest{
			AccountID: accountID, UserID: userID, FactorID: localTestID(22),
			Purpose: TOTPEnrollmentInvite, Version: initialTOTPEnrollmentVersion,
			CeremonyTokenDigest: params.CeremonyTokenDigest,
		}
		pendingContext, contextErr := pendingTOTPContext(pendingRequest)
		if contextErr != nil {
			return ApplyResult{}, contextErr
		}
		factor, factorErr := params.ConfirmTOTPEnrollment(PendingTOTPEnrollment{
			AccountID: accountID, UserID: userID, FactorID: pendingRequest.FactorID,
			Purpose: TOTPEnrollmentInvite, Version: initialTOTPEnrollmentVersion,
			FactorRevision: initialTOTPFactorRevision, CeremonyTokenDigest: params.CeremonyTokenDigest,
			ProtectedSecret: testEncryptedTOTP(pendingContext), ExpiresAt: serviceTestNow.Add(time.Minute),
		}, nil)
		if factorErr != nil {
			return ApplyResult{}, factorErr
		}
		defer factor.Destroy()
		if err := params.ValidatePasswordHistory(nil); err != nil {
			return ApplyResult{}, err
		}
		snapshot := localaccount.Snapshot{
			AccountID: [16]byte(accountID), UserID: [16]byte(userID), Revision: 1, IdentityEpoch: 1,
			Status: localaccount.StatusInvited, LoginIdentifier: localaccount.LoginIdentifierVerified,
			Credential: localaccount.CredentialActive, ConfirmedAcceptableFactors: 1,
		}
		plan, err := params.Plan(PlanningState{Snapshot: snapshot, FreshLocalMFA: true, ProtectedWorkflow: true})
		if err != nil {
			return ApplyResult{}, err
		}
		activatedAt := serviceTestNow
		account := Account{
			ID: accountID, UserID: userID, DisplayName: "New Admin", LoginIdentifier: "new.admin@example.test",
			Status: StatusActive, LoginIdentifierStatus: LoginIdentifierVerified,
			CredentialStatus: CredentialActive, CredentialVersion: 1, ConfirmedAcceptableFactors: 1,
			Revision: plan.NextRevision, IdentityEpoch: plan.NextIdentityEpoch,
			InvitedAt: serviceTestNow.Add(-time.Minute), ActivatedAt: &activatedAt, UpdatedAt: serviceTestNow,
		}
		return params.ValidateResult(ApplyResult{Account: account})
	}
	result, err := service.Activate(context.Background(), manageSession(), accountID, input)
	if err != nil || result.Account.Status != StatusActive {
		t.Fatalf("Activate() = %#v, %v", result, err)
	}
	if !allZero(token) || !allZero(input.NewPassword) || !allZero(input.FactorProof) {
		t.Fatal("activation secret buffers were not cleared")
	}

	staleToken := base64Token(0x43)
	stale := input
	stale.CeremonyToken = staleToken
	stale.NewPassword = []byte("another correct horse password")
	stale.FactorProof = []byte("654321")
	repository.apply = func(_ context.Context, params ApplyParams) (ApplyResult, error) {
		if err := params.ValidatePasswordHistory(nil); err != nil {
			return ApplyResult{}, err
		}
		snapshot := localaccount.Snapshot{
			AccountID: [16]byte(accountID), UserID: [16]byte(userID), Revision: 2, IdentityEpoch: 2,
			Status: localaccount.StatusActive, LoginIdentifier: localaccount.LoginIdentifierVerified,
			Credential: localaccount.CredentialActive, ConfirmedAcceptableFactors: 1,
		}
		_, err := params.Plan(PlanningState{Snapshot: snapshot, FreshLocalMFA: true, ProtectedWorkflow: true})
		return ApplyResult{}, err
	}
	if _, err := service.Activate(context.Background(), manageSession(), accountID, stale); !errors.Is(err, ErrPreconditionFailed) {
		t.Fatalf("Activate(stale) = %v", err)
	}
}

func TestActivationRejectsPendingFactorBoundToDifferentUser(t *testing.T) {
	repository := &localAccountRepositoryStub{}
	service := newTestService(t, repository, &passwordHasherStub{})
	accountID, accountUserID, pendingUserID := localTestID(20), localTestID(21), localTestID(23)
	tag, _ := EntityTag(1)
	repository.apply = func(_ context.Context, params ApplyParams) (ApplyResult, error) {
		pendingRequest := NewTOTPEnrollmentRequest{
			AccountID: accountID, UserID: pendingUserID, FactorID: localTestID(22),
			Purpose: TOTPEnrollmentInvite, Version: initialTOTPEnrollmentVersion,
			CeremonyTokenDigest: params.CeremonyTokenDigest,
		}
		pendingContext, err := pendingTOTPContext(pendingRequest)
		if err != nil {
			return ApplyResult{}, err
		}
		factor, err := params.ConfirmTOTPEnrollment(PendingTOTPEnrollment{
			AccountID: accountID, UserID: pendingUserID, FactorID: pendingRequest.FactorID,
			Purpose: TOTPEnrollmentInvite, Version: initialTOTPEnrollmentVersion,
			FactorRevision: initialTOTPFactorRevision, CeremonyTokenDigest: params.CeremonyTokenDigest,
			ProtectedSecret: testEncryptedTOTP(pendingContext), ExpiresAt: serviceTestNow.Add(time.Minute),
		}, nil)
		if err != nil {
			return ApplyResult{}, err
		}
		defer factor.Destroy()
		if err := params.ValidatePasswordHistory(nil); err != nil {
			return ApplyResult{}, err
		}
		_, err = params.Plan(PlanningState{Snapshot: localaccount.Snapshot{
			AccountID: [16]byte(accountID), UserID: [16]byte(accountUserID), Revision: 1, IdentityEpoch: 1,
			Status: localaccount.StatusInvited, LoginIdentifier: localaccount.LoginIdentifierVerified,
			Credential: localaccount.CredentialActive, ConfirmedAcceptableFactors: 1,
		}, FreshLocalMFA: true, ProtectedWorkflow: true})
		return ApplyResult{}, err
	}

	_, err := service.Activate(context.Background(), manageSession(), accountID, ActivationInput{
		Reason: "Enrollment verified", IdempotencyKey: "local-activate-user-binding-0001",
		ExpectedEntityTag: &tag, CeremonyToken: base64Token(0x44),
		NewPassword: []byte("correct horse battery staple"), FactorProof: []byte("123456"), Event: testEvent(),
	})
	if !errors.Is(err, authentication.ErrUnavailable) {
		t.Fatalf("Activate(cross-user pending factor) = %v", err)
	}
}

func TestPasswordRotationHashesClearsChecksHistoryAndRevokesSessions(t *testing.T) {
	repository := &localAccountRepositoryStub{}
	hasher := &passwordHasherStub{}
	service := newTestService(t, repository, hasher)
	account := activeAccount(localTestID(30), localTestID(31), 7)
	tag, _ := EntityTag(account.Revision)
	password := []byte("correct horse battery staple")
	input := PasswordTransitionInput{
		Reason: "Scheduled credential rotation", IdempotencyKey: "local-password-0001",
		ExpectedEntityTag: &tag, NewPassword: password, Event: testEvent(),
	}
	var persistedPHC []byte
	repository.apply = func(_ context.Context, params ApplyParams) (ApplyResult, error) {
		persistedPHC = params.ReplacementPasswordPHC
		history := [][]byte{[]byte("$argon2id$v=19$m=65536,t=3,p=1$old-salt$old-password")}
		if err := params.ValidatePasswordHistory(history); err != nil {
			return ApplyResult{}, err
		}
		snapshot, _ := plannerSnapshot(account)
		plan, err := params.Plan(PlanningState{Snapshot: snapshot, FreshLocalMFA: true, ProtectedWorkflow: true})
		if err != nil {
			return ApplyResult{}, err
		}
		if !plan.RotateCredential || !plan.RevokeSessions || !plan.RetireChallenges || !plan.RecheckRecoveryFloor {
			t.Fatalf("incomplete rotation plan: %#v", plan)
		}
		next := account
		next.Revision, next.IdentityEpoch = plan.NextRevision, plan.NextIdentityEpoch
		next.CredentialVersion++
		next.UpdatedAt = serviceTestNow
		return params.ValidateResult(ApplyResult{Account: next})
	}
	result, err := service.RotatePassword(context.Background(), manageSession(), account.ID, input)
	if err != nil || result.Account.CredentialVersion != account.CredentialVersion+1 {
		t.Fatalf("RotatePassword() = %#v, %v", result, err)
	}
	if !allZero(password) || !allZero(persistedPHC) || hasher.hashCalls != 1 || hasher.verifyCalls != 1 {
		t.Fatalf("password lifecycle not cleared/checked: password=%v phc=%v hash=%d verify=%d", password, persistedPHC, hasher.hashCalls, hasher.verifyCalls)
	}

	reusedPassword := []byte("previous password material")
	reused := input
	reused.NewPassword = reusedPassword
	repository.apply = func(_ context.Context, params ApplyParams) (ApplyResult, error) {
		if err := params.ValidatePasswordHistory([][]byte{append([]byte("$argon2id$v=19$m=65536,t=3,p=1$history$"), reusedPassword...)}); err != nil {
			return ApplyResult{}, err
		}
		return ApplyResult{}, errors.New("unexpected apply")
	}
	if _, err := service.RotatePassword(context.Background(), manageSession(), account.ID, reused); !errors.Is(err, ErrPasswordReused) {
		t.Fatalf("RotatePassword(reused) = %v", err)
	}
	if !allZero(reusedPassword) {
		t.Fatal("reused password buffer was not cleared")
	}
}

func TestReadAuthorizationPaginationAndCrossTenantDenialAreFailClosed(t *testing.T) {
	repository := &localAccountRepositoryStub{}
	service := newTestService(t, repository, &passwordHasherStub{})
	first := activeAccount(localTestID(40), localTestID(41), 1)
	second := activeAccount(localTestID(42), localTestID(43), 1)
	third := activeAccount(localTestID(44), localTestID(45), 1)
	repository.list = func(_ context.Context, params ListParams) ([]Account, error) {
		if params.Limit != 3 || params.IncludeDisabled {
			t.Fatalf("List params = %#v", params)
		}
		return []Account{first, second, third}, nil
	}
	page, err := service.List(context.Background(), readSession(), ListInput{Limit: 2})
	if err != nil || len(page.Items) != 2 || page.NextCursor == nil || *page.NextCursor != second.ID {
		t.Fatalf("List() = %#v, %v", page, err)
	}

	tenantID := localTestID(90)
	tenantOnly := authentication.Session{
		ID: localTestID(91), User: authentication.User{ID: localTestID(92)}, ActiveTenantID: &tenantID,
		AuthenticationMethod: "totp", Permissions: []authorization.Permission{authorization.PermissionPlatformIdentityAccountRead},
	}
	before := repository.calls
	if _, err := service.List(context.Background(), tenantOnly, ListInput{}); !errors.Is(err, authentication.ErrForbidden) || repository.calls != before {
		t.Fatalf("tenant-only platform read = %v, calls=%d", err, repository.calls)
	}

	repository.get = func(context.Context, GetParams) (Account, error) {
		return Account{}, authentication.ErrNotFound
	}
	for _, candidate := range []uuid.UUID{localTestID(93), localTestID(94)} {
		if _, err := service.Get(context.Background(), readSession(), candidate); !errors.Is(err, authentication.ErrNotFound) {
			t.Fatalf("non-oracular direct lookup %s = %v", candidate, err)
		}
	}
}

func TestServiceRejectsUntrustedAuthorityAndMalformedInputsBeforePersistence(t *testing.T) {
	repository := &localAccountRepositoryStub{}
	service := newTestService(t, repository, &passwordHasherStub{})
	account := activeAccount(localTestID(50), localTestID(51), 2)
	tag, _ := EntityTag(account.Revision)
	input := TransitionInput{
		Reason: "Disable compromised credential", IdempotencyKey: "local-disable-0001",
		ExpectedEntityTag: &tag, Event: testEvent(),
	}
	repository.apply = func(_ context.Context, params ApplyParams) (ApplyResult, error) {
		snapshot, _ := plannerSnapshot(account)
		_, err := params.Plan(PlanningState{Snapshot: snapshot, FreshLocalMFA: false, ProtectedWorkflow: true})
		return ApplyResult{}, err
	}
	if _, err := service.Disable(context.Background(), manageSession(), account.ID, input); !errors.Is(err, ErrTransitionConflict) {
		t.Fatalf("Disable(no step-up) = %v", err)
	}

	malformed := input
	malformed.Reason = "bad\nreason"
	before := repository.calls
	if _, err := service.Disable(context.Background(), manageSession(), account.ID, malformed); !errors.Is(err, authentication.ErrInvalidInput) || repository.calls != before {
		t.Fatalf("Disable(malformed) = %v, calls=%d", err, repository.calls)
	}
	if _, err := service.Disable(nil, manageSession(), account.ID, input); !errors.Is(err, authentication.ErrUnavailable) {
		t.Fatalf("Disable(nil context) = %v", err)
	}
}

func TestRepositoryTransitionAndEnrollmentCallbacksAreOneShot(t *testing.T) {
	t.Run("plan", func(t *testing.T) {
		repository := &localAccountRepositoryStub{}
		service := newTestService(t, repository, &passwordHasherStub{})
		account := activeAccount(localTestID(50), localTestID(51), 2)
		tag, _ := EntityTag(account.Revision)
		repository.apply = func(_ context.Context, params ApplyParams) (ApplyResult, error) {
			snapshot, _ := plannerSnapshot(account)
			snapshot.Revision++
			if _, err := params.Plan(PlanningState{Snapshot: snapshot, FreshLocalMFA: true, ProtectedWorkflow: true}); !errors.Is(err, ErrPreconditionFailed) {
				t.Fatalf("first Plan() error = %v", err)
			}
			snapshot.Revision--
			_, err := params.Plan(PlanningState{Snapshot: snapshot, FreshLocalMFA: true, ProtectedWorkflow: true})
			return ApplyResult{}, err
		}
		_, err := service.Disable(context.Background(), manageSession(), account.ID, TransitionInput{
			Reason: "Disable compromised credential", IdempotencyKey: "local-disable-once-0001",
			ExpectedEntityTag: &tag, Event: testEvent(),
		})
		if !errors.Is(err, authentication.ErrUnavailable) {
			t.Fatalf("second Plan() = %v", err)
		}
	})

	t.Run("factor", func(t *testing.T) {
		repository := &localAccountRepositoryStub{}
		enrollment := &countingTOTPEnrollmentSecurity{}
		service := newTestService(t, repository, &passwordHasherStub{})
		service.enrollment = enrollment
		accountID, userID := localTestID(52), localTestID(53)
		tag, _ := EntityTag(1)
		repository.apply = func(_ context.Context, params ApplyParams) (ApplyResult, error) {
			pending := func(id uuid.UUID) PendingTOTPEnrollment {
				request := NewTOTPEnrollmentRequest{
					AccountID: id, UserID: userID, FactorID: localTestID(54), Purpose: TOTPEnrollmentInvite,
					Version: initialTOTPEnrollmentVersion, CeremonyTokenDigest: params.CeremonyTokenDigest,
				}
				context, _ := pendingTOTPContext(request)
				return PendingTOTPEnrollment{
					AccountID: id, UserID: userID, FactorID: request.FactorID, Purpose: request.Purpose,
					Version: request.Version, FactorRevision: initialTOTPFactorRevision,
					CeremonyTokenDigest: request.CeremonyTokenDigest, ProtectedSecret: testEncryptedTOTP(context),
					ExpiresAt: serviceTestNow.Add(time.Minute),
				}
			}
			if _, err := params.ConfirmTOTPEnrollment(pending(localTestID(55)), nil); !errors.Is(err, authentication.ErrUnavailable) {
				t.Fatalf("first ConfirmTOTPEnrollment() error = %v", err)
			}
			_, err := params.ConfirmTOTPEnrollment(pending(accountID), nil)
			return ApplyResult{}, err
		}
		_, err := service.Activate(context.Background(), manageSession(), accountID, ActivationInput{
			Reason: "Enrollment verified", IdempotencyKey: "local-activate-once-0001",
			ExpectedEntityTag: &tag, CeremonyToken: base64Token(0x45),
			NewPassword: []byte("correct horse battery staple"), FactorProof: []byte("123456"), Event: testEvent(),
		})
		if !errors.Is(err, authentication.ErrUnavailable) || enrollment.confirmCalls != 0 {
			t.Fatalf("second ConfirmTOTPEnrollment() = %v, calls=%d", err, enrollment.confirmCalls)
		}
	})
}

func newTestService(t *testing.T, repository Repository, passwords PasswordHasher) *Service {
	t.Helper()
	ids := []uuid.UUID{
		localTestID(1), localTestID(2), localTestID(3), localTestID(4),
		localTestID(5), localTestID(6), localTestID(7), localTestID(8),
		localTestID(9), localTestID(10), localTestID(11), localTestID(12),
	}
	index := 0
	service, err := NewService(Options{
		Repository: repository, PasswordHasher: passwords, TOTPEnrollment: totpEnrollmentSecurityStub{},
		CommandDigestKey: bytes.Repeat([]byte{0x91}, digestKeyBytes),
		Random:           bytes.NewReader(bytes.Repeat([]byte{0x5a}, 32*32)), Now: func() time.Time { return serviceTestNow },
		NewID: func() (uuid.UUID, error) {
			if index >= len(ids) {
				return uuid.Nil, errors.New("test IDs exhausted")
			}
			value := ids[index]
			index++
			return value, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func validInviteInput(t *testing.T) InviteInput {
	t.Helper()
	return InviteInput{
		DisplayName: "  New Admin  ", LoginIdentifier: "  NEW.ADMIN@EXAMPLE.TEST ",
		ProtectedRecoveryPrincipal: true, Reason: "  Add secondary recovery operator  ",
		IdempotencyKey: "local-invite-0001", Event: testEvent(),
	}
}

func invitedAccount(accountID, userID uuid.UUID) Account {
	return Account{
		ID: accountID, UserID: userID, DisplayName: "New Admin", LoginIdentifier: "new.admin@example.test",
		Status: StatusInvited, LoginIdentifierStatus: LoginIdentifierPending, CredentialStatus: CredentialPending,
		ProtectedRecoveryPrincipal: true, Revision: 1, IdentityEpoch: 1,
		InvitedAt: serviceTestNow, UpdatedAt: serviceTestNow,
	}
}

func activeAccount(accountID, userID uuid.UUID, revision uint64) Account {
	activatedAt := serviceTestNow.Add(-time.Hour)
	return Account{
		ID: accountID, UserID: userID, DisplayName: "Recovery Operator", LoginIdentifier: "recovery@example.test",
		Status: StatusActive, LoginIdentifierStatus: LoginIdentifierVerified, CredentialStatus: CredentialActive,
		CredentialVersion: 3, ConfirmedAcceptableFactors: 1, Revision: revision, IdentityEpoch: revision + 2,
		InvitedAt: serviceTestNow.Add(-2 * time.Hour), ActivatedAt: &activatedAt, UpdatedAt: activatedAt,
	}
}

func testEvent() authentication.EventContext {
	return authentication.EventContext{
		RequestID: localTestID(70), CorrelationID: localTestID(71),
		RemoteAddress: netip.MustParseAddr("192.0.2.10"), UserAgent: "local-account-test/1.0",
	}
}

func readSession() authentication.Session {
	return authentication.Session{
		ID: localTestID(60), User: authentication.User{ID: localTestID(61)}, AuthenticationMethod: "totp",
		Permissions: []authorization.Permission{authorization.PermissionPlatformIdentityAccountRead},
	}
}

func manageSession() authentication.Session {
	session := readSession()
	session.Permissions = append(session.Permissions, authorization.PermissionPlatformIdentityAccountManage)
	return session
}

func localTestID(value byte) uuid.UUID {
	return uuid.MustParse(fmt.Sprintf("01900000-0000-7000-8000-%012x", value))
}

func base64Token(value byte) []byte {
	generator, _ := newSecretGenerator(bytes.NewReader(bytes.Repeat([]byte{value}, opaqueTokenBytes)), bytes.Repeat([]byte{0x81}, digestKeyBytes))
	token, _, _ := generator.issue("ceremony-token")
	return token
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}
