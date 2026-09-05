package httpserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/services/api/internal/platformsamlauth"
)

type runtimePlatformSAMLReadinessFunc func(context.Context) error

func (function runtimePlatformSAMLReadinessFunc) ReadyDirectPlatformSAML(ctx context.Context) error {
	return function(ctx)
}

type runtimePlatformSAMLTOTPApplicationStub struct {
	start    func(context.Context, platformsamlauth.StartDirectSAMLTOTPCommand) (platformsamlauth.DirectSAMLTOTPStartArtifact, error)
	complete func(context.Context, platformsamlauth.CompleteDirectSAMLTOTPCommand) (platformsamlauth.DirectSAMLTOTPCompletionOutcome, error)
}

func (stub *runtimePlatformSAMLTOTPApplicationStub) Start(ctx context.Context, command platformsamlauth.StartDirectSAMLTOTPCommand) (platformsamlauth.DirectSAMLTOTPStartArtifact, error) {
	if stub != nil && stub.start != nil {
		return stub.start(ctx, command)
	}
	return platformsamlauth.DirectSAMLTOTPStartArtifact{}, errors.New("unexpected start")
}

func (stub *runtimePlatformSAMLTOTPApplicationStub) Complete(ctx context.Context, command platformsamlauth.CompleteDirectSAMLTOTPCommand) (platformsamlauth.DirectSAMLTOTPCompletionOutcome, error) {
	if stub != nil && stub.complete != nil {
		return stub.complete(ctx, command)
	}
	return platformsamlauth.DirectSAMLTOTPCompletionOutcome{}, errors.New("unexpected complete")
}

func TestRuntimePlatformSAMLContinuationReadinessFailsClosed(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	stub := &runtimePlatformSAMLTOTPApplicationStub{start: func(context.Context, platformsamlauth.StartDirectSAMLTOTPCommand) (platformsamlauth.DirectSAMLTOTPStartArtifact, error) {
		calls.Add(1)
		return platformsamlauth.DirectSAMLTOTPStartArtifact{}, nil
	}}
	service, err := NewRuntimePlatformSAMLContinuation(RuntimePlatformSAMLContinuationOptions{
		TOTP: stub,
		Readiness: runtimePlatformSAMLReadinessFunc(func(context.Context) error {
			return errors.New("schema not ready")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if start, err := service.StartTOTP(context.Background(), PlatformSAMLStartTOTPCommand{}); !errors.Is(err, errFederatedTransportUnavailable) ||
		start.ChallengeID != (mfa.ChallengeID{}) || start.BrowserHandle != nil ||
		start.FactorID != (identity.EntityID{}) || !start.ExpiresAt.IsZero() || calls.Load() != 0 {
		t.Fatalf("StartTOTP() = %#v, %v, calls=%d", start, err, calls.Load())
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := service.Ready(canceled); !errors.Is(err, errFederatedTransportUnavailable) {
		t.Fatalf("Ready(canceled) = %v", err)
	}
}

func TestRuntimePlatformSAMLContinuationCopiesAndClearsHTTPProof(t *testing.T) {
	t.Parallel()
	var capturedHandle, capturedCode []byte
	stub := &runtimePlatformSAMLTOTPApplicationStub{complete: func(_ context.Context, command platformsamlauth.CompleteDirectSAMLTOTPCommand) (platformsamlauth.DirectSAMLTOTPCompletionOutcome, error) {
		capturedHandle, capturedCode = command.BrowserHandle, command.Code
		return platformsamlauth.DirectSAMLTOTPCompletionOutcome{}, platformsamlauth.ErrAuthenticationDenied
	}}
	service, err := NewRuntimePlatformSAMLContinuation(RuntimePlatformSAMLContinuationOptions{
		TOTP: stub, Readiness: runtimePlatformSAMLReadinessFunc(func(context.Context) error { return nil }),
	})
	if err != nil {
		t.Fatal(err)
	}
	originalHandle := federatedOpaque(0xc1)
	originalCode := []byte("123456")
	_, err = service.CompleteTOTP(context.Background(), PlatformSAMLCompleteTOTPCommand{
		BrowserHandle: originalHandle, Code: originalCode,
	})
	if !errors.Is(err, platformsamlauth.ErrAuthenticationDenied) {
		t.Fatalf("CompleteTOTP() error = %v", err)
	}
	if !allZeroRuntimePlatformSAMLBytes(capturedHandle) || !allZeroRuntimePlatformSAMLBytes(capturedCode) {
		t.Fatalf("runtime-owned proof not cleared: handle=%x code=%x", capturedHandle, capturedCode)
	}
	if allZeroRuntimePlatformSAMLBytes(originalHandle) || allZeroRuntimePlatformSAMLBytes(originalCode) {
		t.Fatal("runtime cleared caller-owned proof")
	}
}

func TestRuntimePlatformSAMLContinuationMapsApplicationArtifactsAndFinalizer(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 30, 19, 0, 0, 0, time.UTC)
	continuationID := runtimePlatformSAMLEntityID(t)
	userID := runtimePlatformSAMLEntityID(t)
	factorID := runtimePlatformSAMLEntityID(t)
	sessionID := runtimePlatformSAMLEntityID(t)
	familyID := runtimePlatformSAMLEntityID(t)
	receiptDigest := sha256.Sum256([]byte("runtime-platform-saml-receipt"))
	audit := platformsamlauth.AuditContext{
		RequestID: runtimePlatformSAMLEntityID(t), CorrelationID: runtimePlatformSAMLEntityID(t),
		RemoteAddress: netip.MustParseAddr("203.0.113.70"), UserAgent: "runtime-platform-saml-test/1",
	}
	store := &runtimePlatformSAMLTOTPStore{
		now: now, continuationID: continuationID, userID: userID, factorID: factorID,
		receiptDigest: receiptDigest, factorRevision: 7, userRevision: 8,
		sessionID: sessionID, counter: 41,
	}
	issuer := runtimePlatformSAMLCredentialIssuer{
		now: now, sessionID: sessionID, familyID: familyID,
	}
	application, err := platformsamlauth.NewDirectSAMLTOTPApplication(platformsamlauth.DirectSAMLTOTPApplicationOptions{
		Store: store, Verifier: runtimePlatformSAMLTOTPVerifier{counter: 41}, Credentials: issuer,
		Random: bytes.NewReader(bytes.Repeat([]byte{0xd1}, 64)), Now: func() time.Time { return now },
		ChallengeTTL: 5 * time.Minute, OperationTimeout: time.Second, RecoveryTimeout: 25 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	var readinessCalls atomic.Int32
	service, err := NewRuntimePlatformSAMLContinuation(RuntimePlatformSAMLContinuationOptions{
		TOTP: application, Readiness: runtimePlatformSAMLReadinessFunc(func(context.Context) error {
			readinessCalls.Add(1)
			return nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	start, err := service.StartTOTP(context.Background(), PlatformSAMLStartTOTPCommand{
		ContinuationID: continuationID, ReceiptDigest: receiptDigest, Audit: audit,
	})
	if err != nil || start.ChallengeID == (mfa.ChallengeID{}) || start.FactorID != factorID ||
		!start.ExpiresAt.Equal(now.Add(5*time.Minute)) || !validMFABrowserHandle(string(start.BrowserHandle)) {
		t.Fatalf("StartTOTP() = %#v, %v", start, err)
	}
	defer start.Destroy()
	outcome, err := service.CompleteTOTP(context.Background(), PlatformSAMLCompleteTOTPCommand{
		ChallengeID: start.ChallengeID, ContinuationID: continuationID, ReceiptDigest: receiptDigest,
		BrowserHandle: start.BrowserHandle, FactorID: factorID, Code: []byte("123456"), Audit: audit,
	})
	if err != nil || outcome.UserID != userID || outcome.SessionID != sessionID || outcome.FactorID != factorID ||
		interfaceIsNil(outcome.Credential) || interfaceIsNil(outcome.Delivery) || readinessCalls.Load() != 2 {
		t.Fatalf("CompleteTOTP() = %#v, %v, readiness=%d", outcome, err, readinessCalls.Load())
	}
	material, consumed := outcome.Credential.Consume()
	if !consumed || material.Kind != platformsamlauth.BrowserSessionCredential || material.SessionID != sessionID {
		t.Fatalf("credential = %s, consumed=%t", material, consumed)
	}
	material.Destroy()
	finalizer := outcome.Delivery
	outcome.Destroy()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := finalizer.CompensateBrowserDelivery(canceled); err != nil || store.cleanupCalls.Load() != 1 ||
		store.cleanup.Result.SessionID != sessionID || store.cleanup.Reason != platformsamlauth.CleanupDeliveryFailed {
		t.Fatalf("compensation = %v, calls=%d, request=%s", err, store.cleanupCalls.Load(), store.cleanup)
	}
}

type runtimePlatformSAMLTOTPStore struct {
	now            time.Time
	continuationID identity.EntityID
	userID         identity.EntityID
	factorID       identity.EntityID
	receiptDigest  [sha256.Size]byte
	factorRevision uint64
	userRevision   uint64
	sessionID      identity.EntityID
	counter        int64
	challengeID    mfa.ChallengeID
	browserDigest  platformsamlauth.DirectSAMLTOTPBrowserDigest
	expiresAt      time.Time
	cleanupCalls   atomic.Int32
	cleanup        platformsamlauth.DirectSAMLTOTPCleanupRequest
}

func (store *runtimePlatformSAMLTOTPStore) BeginDirectSAMLTOTP(_ context.Context, request platformsamlauth.DirectSAMLTOTPBeginRequest) (platformsamlauth.DirectSAMLTOTPChallenge, error) {
	if request.ContinuationID != store.continuationID || request.ReceiptDigest != store.receiptDigest ||
		request.ExpectedContinuationVersion != 1 {
		return platformsamlauth.DirectSAMLTOTPChallenge{}, errors.New("wrong start authority")
	}
	store.challengeID, store.browserDigest, store.expiresAt = request.ChallengeID, request.BrowserDigest, request.ExpiresAt
	return platformsamlauth.DirectSAMLTOTPChallenge{
		ChallengeID: request.ChallengeID, ContinuationID: request.ContinuationID,
		UserID: store.userID, FactorID: store.factorID, ExpectedContinuationVersion: 1,
		FactorRevision: store.factorRevision, UserAuthenticationRevision: store.userRevision,
		State: platformsamlauth.DirectSAMLTOTPChallengePending, Version: 1, ExpiresAt: request.ExpiresAt,
	}, nil
}

func (store *runtimePlatformSAMLTOTPStore) LoadDirectSAMLTOTP(_ context.Context, lookup platformsamlauth.DirectSAMLTOTPLookup) (platformsamlauth.DirectSAMLTOTPVerificationSnapshot, error) {
	if lookup.ChallengeID != store.challengeID || lookup.ContinuationID != store.continuationID ||
		lookup.ReceiptDigest != store.receiptDigest || lookup.BrowserDigest != store.browserDigest {
		return platformsamlauth.DirectSAMLTOTPVerificationSnapshot{}, errors.New("wrong continuation proof")
	}
	return platformsamlauth.DirectSAMLTOTPVerificationSnapshot{
		ChallengeID: store.challengeID, ContinuationID: store.continuationID,
		ReceiptDigest: store.receiptDigest, UserID: store.userID, FactorID: store.factorID,
		Secret: platformsamlauth.DirectSAMLProtectedTOTPSecret{
			Ciphertext: []byte("runtime-secret-ciphertext-material"), Nonce: []byte("123456789012"),
			AAD: []byte("runtime-aad"), KeyVersion: 1, EncryptionAlgorithm: "aes-256-gcm",
			OTPAlgorithm: "SHA1", Digits: 6, PeriodSeconds: 30,
		},
		ExpectedContinuationVersion: 1, FactorRevision: store.factorRevision,
		UserAuthenticationRevision: store.userRevision, State: platformsamlauth.DirectSAMLTOTPChallengePending,
		ExpiresAt: store.expiresAt, Version: 1,
	}, nil
}

func (*runtimePlatformSAMLTOTPStore) RecordDirectSAMLTOTPFailure(context.Context, platformsamlauth.DirectSAMLTOTPFailureRequest) (platformsamlauth.DirectSAMLTOTPChallenge, error) {
	return platformsamlauth.DirectSAMLTOTPChallenge{}, errors.New("unexpected failure")
}

func (store *runtimePlatformSAMLTOTPStore) ApplyDirectSAMLTOTP(_ context.Context, request platformsamlauth.DirectSAMLTOTPApplyRequest) (platformsamlauth.DirectSAMLTOTPApplyResult, error) {
	if request.ExpectedContinuationVersion != 1 || request.ExpectedFactorRevision != store.factorRevision ||
		request.ExpectedUserAuthenticationRevision != store.userRevision || request.ExpectedChallengeVersion != 1 ||
		request.Session.SessionID() != store.sessionID || request.AcceptedCounter != store.counter {
		return platformsamlauth.DirectSAMLTOTPApplyResult{}, errors.New("wrong exact apply")
	}
	return platformsamlauth.DirectSAMLTOTPApplyResult{
		Category: platformsamlauth.DirectSAMLTOTPApplySuccess, SessionID: store.sessionID,
		UserID: store.userID, FactorID: store.factorID, FactorRevision: store.factorRevision,
		UserAuthenticationRevision: store.userRevision, AcceptedCounter: store.counter, CompletedAt: store.now,
	}, nil
}

func (*runtimePlatformSAMLTOTPStore) RecoverDirectSAMLTOTPApply(context.Context, platformsamlauth.DirectSAMLTOTPApplyRecoveryLookup) (platformsamlauth.DirectSAMLTOTPApplyRecoveryResult, error) {
	return platformsamlauth.DirectSAMLTOTPApplyRecoveryResult{}, errors.New("unexpected recovery")
}

func (*runtimePlatformSAMLTOTPStore) AbandonDirectSAMLTOTP(context.Context, platformsamlauth.DirectSAMLTOTPAbandonRequest) (platformsamlauth.DirectSAMLTOTPChallenge, error) {
	return platformsamlauth.DirectSAMLTOTPChallenge{}, errors.New("unexpected abandon")
}

func (store *runtimePlatformSAMLTOTPStore) CleanupDirectSAMLTOTPApply(_ context.Context, request platformsamlauth.DirectSAMLTOTPCleanupRequest) error {
	store.cleanupCalls.Add(1)
	store.cleanup = request
	return nil
}

type runtimePlatformSAMLTOTPVerifier struct{ counter int64 }

func (verifier runtimePlatformSAMLTOTPVerifier) VerifyDirectSAMLTOTP(_ context.Context, request platformsamlauth.DirectSAMLTOTPVerificationRequest) (platformsamlauth.DirectSAMLTOTPProof, error) {
	if request.FactorRevision != 7 || request.UserAuthenticationRevision != 8 || string(request.Code) != "123456" {
		return platformsamlauth.DirectSAMLTOTPProof{}, errors.New("wrong verification proof")
	}
	return platformsamlauth.DirectSAMLTOTPProof{Counter: verifier.counter}, nil
}

type runtimePlatformSAMLCredentialIssuer struct {
	now       time.Time
	sessionID identity.EntityID
	familyID  identity.EntityID
}

func (issuer runtimePlatformSAMLCredentialIssuer) ReserveDirectSAMLCredential(request platformsamlauth.CredentialRequest) (*platformsamlauth.CredentialReservation, error) {
	if request.Disposition != platformsamlauth.ImmediateSession || request.TOTP != nil || request.IssuedAt != issuer.now {
		return nil, errors.New("wrong SAML credential request")
	}
	token, csrf := federatedOpaque(0xe1), federatedOpaque(0xe2)
	defer clear(token)
	defer clear(csrf)
	reservation, err := mfa.NewSessionReservation(mfa.SessionMaterial{
		SessionID: issuer.sessionID, FamilyID: issuer.familyID,
		TokenDigest: sha256.Sum256(token), CSRFDigest: sha256.Sum256(csrf),
		AuthenticationMethod: mfa.SessionAuthenticationSAML,
		IdleExpiresAt:        issuer.now.Add(time.Hour), AbsoluteExpiresAt: issuer.now.Add(8 * time.Hour),
	}, issuer.now)
	if err != nil {
		return nil, err
	}
	return platformsamlauth.NewSessionCredentialReservation(reservation, token, csrf)
}

func runtimePlatformSAMLEntityID(t testing.TB) identity.EntityID {
	t.Helper()
	return identity.EntityID(uuid.Must(uuid.NewV7()))
}

func allZeroRuntimePlatformSAMLBytes(value []byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}
