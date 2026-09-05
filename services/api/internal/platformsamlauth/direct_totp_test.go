package platformsamlauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/netip"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
)

var directSAMLTOTPTestNow = time.Date(2026, 8, 30, 18, 0, 0, 0, time.UTC)

type directSAMLTOTPStoreStub struct {
	begin   func(context.Context, DirectSAMLTOTPBeginRequest) (DirectSAMLTOTPChallenge, error)
	load    func(context.Context, DirectSAMLTOTPLookup) (DirectSAMLTOTPVerificationSnapshot, error)
	failure func(context.Context, DirectSAMLTOTPFailureRequest) (DirectSAMLTOTPChallenge, error)
	apply   func(context.Context, DirectSAMLTOTPApplyRequest) (DirectSAMLTOTPApplyResult, error)
	recover func(context.Context, DirectSAMLTOTPApplyRecoveryLookup) (DirectSAMLTOTPApplyRecoveryResult, error)
	abandon func(context.Context, DirectSAMLTOTPAbandonRequest) (DirectSAMLTOTPChallenge, error)
	cleanup func(context.Context, DirectSAMLTOTPCleanupRequest) error
}

func (stub *directSAMLTOTPStoreStub) BeginDirectSAMLTOTP(ctx context.Context, request DirectSAMLTOTPBeginRequest) (DirectSAMLTOTPChallenge, error) {
	if stub != nil && stub.begin != nil {
		return stub.begin(ctx, request)
	}
	return DirectSAMLTOTPChallenge{}, errors.New("unexpected begin")
}

func (stub *directSAMLTOTPStoreStub) LoadDirectSAMLTOTP(ctx context.Context, lookup DirectSAMLTOTPLookup) (DirectSAMLTOTPVerificationSnapshot, error) {
	if stub != nil && stub.load != nil {
		return stub.load(ctx, lookup)
	}
	return DirectSAMLTOTPVerificationSnapshot{}, errors.New("unexpected load")
}

func (stub *directSAMLTOTPStoreStub) RecordDirectSAMLTOTPFailure(ctx context.Context, request DirectSAMLTOTPFailureRequest) (DirectSAMLTOTPChallenge, error) {
	if stub != nil && stub.failure != nil {
		return stub.failure(ctx, request)
	}
	return DirectSAMLTOTPChallenge{}, errors.New("unexpected failure")
}

func (stub *directSAMLTOTPStoreStub) ApplyDirectSAMLTOTP(ctx context.Context, request DirectSAMLTOTPApplyRequest) (DirectSAMLTOTPApplyResult, error) {
	if stub != nil && stub.apply != nil {
		return stub.apply(ctx, request)
	}
	return DirectSAMLTOTPApplyResult{}, errors.New("unexpected apply")
}

func (stub *directSAMLTOTPStoreStub) RecoverDirectSAMLTOTPApply(ctx context.Context, lookup DirectSAMLTOTPApplyRecoveryLookup) (DirectSAMLTOTPApplyRecoveryResult, error) {
	if stub != nil && stub.recover != nil {
		return stub.recover(ctx, lookup)
	}
	return DirectSAMLTOTPApplyRecoveryResult{}, errors.New("unexpected recovery")
}

func (stub *directSAMLTOTPStoreStub) AbandonDirectSAMLTOTP(ctx context.Context, request DirectSAMLTOTPAbandonRequest) (DirectSAMLTOTPChallenge, error) {
	if stub != nil && stub.abandon != nil {
		return stub.abandon(ctx, request)
	}
	return DirectSAMLTOTPChallenge{}, errors.New("unexpected abandon")
}

func (stub *directSAMLTOTPStoreStub) CleanupDirectSAMLTOTPApply(ctx context.Context, request DirectSAMLTOTPCleanupRequest) error {
	if stub != nil && stub.cleanup != nil {
		return stub.cleanup(ctx, request)
	}
	return errors.New("unexpected cleanup")
}

type directSAMLTOTPVerifierFunc func(context.Context, DirectSAMLTOTPVerificationRequest) (DirectSAMLTOTPProof, error)

func (function directSAMLTOTPVerifierFunc) VerifyDirectSAMLTOTP(ctx context.Context, request DirectSAMLTOTPVerificationRequest) (DirectSAMLTOTPProof, error) {
	return function(ctx, request)
}

type directSAMLTOTPReaderFunc func([]byte) (int, error)

func (function directSAMLTOTPReaderFunc) Read(destination []byte) (int, error) {
	return function(destination)
}

func TestDirectSAMLTOTPStartTransfersBrowserHandleExactlyOnce(t *testing.T) {
	t.Parallel()
	fixture := directSAMLTOTPFixture()
	store := &directSAMLTOTPStoreStub{}
	store.begin = func(_ context.Context, request DirectSAMLTOTPBeginRequest) (DirectSAMLTOTPChallenge, error) {
		if request.ExpectedContinuationVersion != 1 || request.ContinuationID != fixture.continuationID ||
			request.ReceiptDigest != fixture.receiptDigest || request.ChallengeID == (mfa.ChallengeID{}) ||
			request.BrowserDigest == (DirectSAMLTOTPBrowserDigest{}) || request.Audit != fixture.audit {
			t.Fatalf("begin request = %s", request)
		}
		return DirectSAMLTOTPChallenge{
			ChallengeID: request.ChallengeID, ContinuationID: request.ContinuationID,
			UserID: fixture.userID, FactorID: fixture.factorID,
			ExpectedContinuationVersion: 1, FactorRevision: fixture.factorRevision,
			UserAuthenticationRevision: fixture.userRevision,
			State:                      DirectSAMLTOTPChallengePending, Version: 1, ExpiresAt: request.ExpiresAt,
		}, nil
	}
	application := directSAMLTOTPTestApplication(t, store, nil, nil, bytes.NewReader(bytes.Repeat([]byte{0x41}, 64)))
	artifact, err := application.Start(context.Background(), StartDirectSAMLTOTPCommand{
		ContinuationID: fixture.continuationID, ReceiptDigest: fixture.receiptDigest, Audit: fixture.audit,
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	copyArtifact := artifact
	handle, consumed := artifact.ConsumeBrowserHandle()
	if !consumed || !canonicalBrowserHandle(handle) || artifact.ChallengeID() == (mfa.ChallengeID{}) ||
		artifact.FactorID() != fixture.factorID || !artifact.ExpiresAt().Equal(directSAMLTOTPTestNow.Add(5*time.Minute)) {
		t.Fatalf("artifact = %s, consumed=%t", artifact, consumed)
	}
	defer clear(handle)
	if second, ok := copyArtifact.ConsumeBrowserHandle(); ok || second != nil {
		clear(second)
		t.Fatalf("copied artifact consumed twice: %q", second)
	}
	artifact.Destroy()
}

func TestNewDirectSAMLTOTPApplicationRejectsTypedNilDependencies(t *testing.T) {
	t.Parallel()
	validStore := &directSAMLTOTPStoreStub{}
	validVerifier := directSAMLTOTPVerifierFunc(func(context.Context, DirectSAMLTOTPVerificationRequest) (DirectSAMLTOTPProof, error) {
		return DirectSAMLTOTPProof{}, errors.New("unused verifier")
	})
	validIssuer := credentialIssuerFunc(func(CredentialRequest) (*CredentialReservation, error) {
		return nil, errors.New("unused issuer")
	})
	base := DirectSAMLTOTPApplicationOptions{
		Store: validStore, Verifier: validVerifier, Credentials: validIssuer,
		ChallengeTTL: 5 * time.Minute, OperationTimeout: time.Second, RecoveryTimeout: 25 * time.Millisecond,
	}
	var nilStore *directSAMLTOTPStoreStub
	var nilVerifier directSAMLTOTPVerifierFunc
	var nilIssuer credentialIssuerFunc
	var nilRandom directSAMLTOTPReaderFunc
	for name, mutate := range map[string]func(*DirectSAMLTOTPApplicationOptions){
		"store":    func(options *DirectSAMLTOTPApplicationOptions) { options.Store = nilStore },
		"verifier": func(options *DirectSAMLTOTPApplicationOptions) { options.Verifier = nilVerifier },
		"issuer":   func(options *DirectSAMLTOTPApplicationOptions) { options.Credentials = nilIssuer },
		"random":   func(options *DirectSAMLTOTPApplicationOptions) { options.Random = nilRandom },
	} {
		t.Run(name, func(t *testing.T) {
			options := base
			mutate(&options)
			if application, err := NewDirectSAMLTOTPApplication(options); !errors.Is(err, ErrInvalidOptions) || application != nil {
				t.Fatalf("NewDirectSAMLTOTPApplication() = %s, %v", application, err)
			}
		})
	}
}

func TestDirectSAMLTOTPCompleteRecoversAmbiguousApplyClearsSecretsAndCompensates(t *testing.T) {
	t.Parallel()
	fixture := directSAMLTOTPFixture()
	returnedCiphertext := []byte("returned-secret-ciphertext-material")
	returnedNonce := []byte("123456789012")
	returnedAAD := []byte("totp_credential:fixture:user:fixture")
	var verifierCiphertext, verifierNonce, verifierAAD, verifierCode []byte
	var applyRequest DirectSAMLTOTPApplyRequest
	var cleanupRequest DirectSAMLTOTPCleanupRequest
	var applyCalls, recoveryCalls, cleanupCalls atomic.Int32
	store := &directSAMLTOTPStoreStub{}
	store.load = func(context.Context, DirectSAMLTOTPLookup) (DirectSAMLTOTPVerificationSnapshot, error) {
		return fixture.snapshot(returnedCiphertext, returnedNonce, returnedAAD), nil
	}
	store.apply = func(_ context.Context, request DirectSAMLTOTPApplyRequest) (DirectSAMLTOTPApplyResult, error) {
		call := applyCalls.Add(1)
		applyRequest = request
		if call == 2 {
			// A replay-looking retry cannot overrule the ambiguity of the first
			// transport error; the application must use read-only recovery.
			return fixture.applyResult(DirectSAMLTOTPApplyReplay), nil
		}
		return DirectSAMLTOTPApplyResult{}, errors.New("ambiguous commit")
	}
	store.recover = func(ctx context.Context, lookup DirectSAMLTOTPApplyRecoveryLookup) (DirectSAMLTOTPApplyRecoveryResult, error) {
		recoveryCalls.Add(1)
		if ctx.Err() != nil || lookup.Request.CompletionRequestDigest == (DirectSAMLTOTPCompletionDigest{}) ||
			lookup.Request.Session.SessionID() != fixture.sessionID {
			t.Fatalf("recovery lookup = %s, context=%v", lookup, ctx.Err())
		}
		return DirectSAMLTOTPApplyRecoveryResult{Matched: true, Result: fixture.applyResult(DirectSAMLTOTPApplyAlreadyApplied)}, nil
	}
	store.cleanup = func(ctx context.Context, request DirectSAMLTOTPCleanupRequest) error {
		call := cleanupCalls.Add(1)
		if ctx.Err() != nil {
			t.Fatalf("cleanup inherited canceled context: %v", ctx.Err())
		}
		cleanupRequest = request
		if call == 1 {
			return errors.New("retry cleanup")
		}
		return nil
	}
	verifier := directSAMLTOTPVerifierFunc(func(_ context.Context, request DirectSAMLTOTPVerificationRequest) (DirectSAMLTOTPProof, error) {
		verifierCiphertext, verifierNonce, verifierAAD, verifierCode = request.Secret.Ciphertext, request.Secret.Nonce, request.Secret.AAD, request.Code
		if request.FactorRevision != fixture.factorRevision || request.UserAuthenticationRevision != fixture.userRevision {
			t.Fatalf("verification revisions = %d/%d", request.FactorRevision, request.UserAuthenticationRevision)
		}
		return DirectSAMLTOTPProof{Counter: fixture.counter}, nil
	})
	application := directSAMLTOTPTestApplication(t, store, verifier, fixture.issuer(t), nil)
	outcome, err := application.Complete(context.Background(), fixture.completeCommand())
	if err != nil {
		t.Fatalf("Complete() error = %v", err)
	}
	if applyCalls.Load() != 2 || recoveryCalls.Load() != 1 || outcome.SessionID != fixture.sessionID ||
		outcome.UserID != fixture.userID || outcome.FactorID != fixture.factorID || outcome.Counter != fixture.counter ||
		outcome.Credential == nil || outcome.Delivery == nil {
		t.Fatalf("outcome = %s, apply=%d recovery=%d", outcome, applyCalls.Load(), recoveryCalls.Load())
	}
	for name, value := range map[string][]byte{
		"store ciphertext": returnedCiphertext, "store nonce": returnedNonce, "store aad": returnedAAD,
		"verifier ciphertext": verifierCiphertext, "verifier nonce": verifierNonce,
		"verifier aad": verifierAAD, "verifier code": verifierCode,
	} {
		if !allZeroDirectSAMLTOTPBytes(value) {
			t.Fatalf("%s was not cleared: %x", name, value)
		}
	}
	material, consumed := outcome.Credential.Consume()
	if !consumed || material.Kind != BrowserSessionCredential || material.SessionID != fixture.sessionID {
		t.Fatalf("credential = %s, consumed=%t", material, consumed)
	}
	material.Destroy()
	finalizer := outcome.Delivery
	outcome.Destroy()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := finalizer.CompensateBrowserDelivery(canceled); err != nil {
		t.Fatalf("CompensateBrowserDelivery() error = %v", err)
	}
	if cleanupCalls.Load() != 2 || cleanupRequest.Reason != CleanupDeliveryFailed ||
		cleanupRequest.Request.CompletionRequestDigest != applyRequest.CompletionRequestDigest ||
		cleanupRequest.Result.SessionID != fixture.sessionID || cleanupRequest.Audit != fixture.audit {
		t.Fatalf("cleanup = %s, calls=%d", cleanupRequest, cleanupCalls.Load())
	}
	if err := finalizer.CompensateBrowserDelivery(context.Background()); err != nil || cleanupCalls.Load() != 2 {
		t.Fatalf("idempotent compensation = %v, calls=%d", err, cleanupCalls.Load())
	}
}

func TestDirectSAMLTOTPApplyRecoveryRejectsSuccessProjection(t *testing.T) {
	t.Parallel()
	fixture := directSAMLTOTPFixture()
	var recoveryCalls atomic.Int32
	store := &directSAMLTOTPStoreStub{
		apply: func(context.Context, DirectSAMLTOTPApplyRequest) (DirectSAMLTOTPApplyResult, error) {
			return DirectSAMLTOTPApplyResult{}, errors.New("ambiguous apply")
		},
		recover: func(context.Context, DirectSAMLTOTPApplyRecoveryLookup) (DirectSAMLTOTPApplyRecoveryResult, error) {
			recoveryCalls.Add(1)
			return DirectSAMLTOTPApplyRecoveryResult{
				Matched: true,
				Result:  fixture.applyResult(DirectSAMLTOTPApplySuccess),
			}, nil
		},
	}
	application := directSAMLTOTPTestApplication(t, store, nil, nil, nil)
	request := fixture.applyRequest(t)
	snapshot := fixture.snapshot(
		[]byte("recovery-secret-ciphertext-material"), []byte("123456789012"),
		[]byte("totp_credential:fixture:user:fixture"),
	)
	defer snapshot.Destroy()
	result, category, certain := application.applyWithRecovery(
		context.Background(), context.Background(), request, snapshot,
	)
	if certain || result != (DirectSAMLTOTPApplyResult{}) || category != "" || recoveryCalls.Load() != 1 {
		t.Fatalf("recovery projection accepted: result=%s category=%q certain=%t calls=%d", result, category, certain, recoveryCalls.Load())
	}
}

func TestDirectSAMLTOTPRejectsCollidingSessionReservationBeforeApply(t *testing.T) {
	t.Parallel()
	fixture := directSAMLTOTPFixture()
	var applyCalls atomic.Int32
	store := &directSAMLTOTPStoreStub{
		load: func(context.Context, DirectSAMLTOTPLookup) (DirectSAMLTOTPVerificationSnapshot, error) {
			return fixture.snapshot(
				[]byte("collision-secret-ciphertext-material"), []byte("123456789012"),
				[]byte("totp_credential:fixture:user:fixture"),
			), nil
		},
		apply: func(context.Context, DirectSAMLTOTPApplyRequest) (DirectSAMLTOTPApplyResult, error) {
			applyCalls.Add(1)
			return DirectSAMLTOTPApplyResult{}, errors.New("unexpected apply")
		},
	}
	issuer := credentialIssuerFunc(func(request CredentialRequest) (*CredentialReservation, error) {
		token, csrf := opaqueCredential(121), opaqueCredential(122)
		defer clear(token)
		defer clear(csrf)
		reservation, err := mfa.NewSessionReservation(mfa.SessionMaterial{
			SessionID: fixture.userID, FamilyID: fixture.familyID,
			TokenDigest: sha256.Sum256(token), CSRFDigest: sha256.Sum256(csrf),
			AuthenticationMethod: mfa.SessionAuthenticationSAML,
			IdleExpiresAt:        request.IssuedAt.Add(time.Hour),
			AbsoluteExpiresAt:    request.IssuedAt.Add(8 * time.Hour),
		}, request.IssuedAt)
		if err != nil {
			return nil, err
		}
		return NewSessionCredentialReservation(reservation, token, csrf)
	})
	application := directSAMLTOTPTestApplication(t, store, directSAMLTOTPVerifierFunc(
		func(context.Context, DirectSAMLTOTPVerificationRequest) (DirectSAMLTOTPProof, error) {
			return DirectSAMLTOTPProof{Counter: fixture.counter}, nil
		},
	), issuer, nil)
	outcome, err := application.Complete(context.Background(), fixture.completeCommand())
	defer outcome.Destroy()
	if !errors.Is(err, ErrAuthenticationUnavailable) || outcome != (DirectSAMLTOTPCompletionOutcome{}) ||
		applyCalls.Load() != 0 {
		t.Fatalf("colliding reservation = %s, %v, apply=%d", outcome, err, applyCalls.Load())
	}
}

func TestDirectSAMLTOTPInvalidProofTerminalizesAtFiveAttempts(t *testing.T) {
	t.Parallel()
	fixture := directSAMLTOTPFixture()
	var guard sync.Mutex
	failures := uint32(0)
	version := uint64(1)
	state := DirectSAMLTOTPChallengePending
	store := &directSAMLTOTPStoreStub{}
	store.load = func(_ context.Context, lookup DirectSAMLTOTPLookup) (DirectSAMLTOTPVerificationSnapshot, error) {
		guard.Lock()
		defer guard.Unlock()
		if state != DirectSAMLTOTPChallengePending {
			return DirectSAMLTOTPVerificationSnapshot{}, errors.New("terminal challenge")
		}
		snapshot := fixture.snapshot(
			[]byte("attempt-secret-ciphertext-material"), []byte("123456789012"),
			[]byte("totp_credential:fixture:user:fixture"),
		)
		snapshot.FailureCount, snapshot.Version, snapshot.State = failures, version, state
		return snapshot, nil
	}
	store.failure = func(_ context.Context, request DirectSAMLTOTPFailureRequest) (DirectSAMLTOTPChallenge, error) {
		guard.Lock()
		defer guard.Unlock()
		if request.ExpectedChallengeVersion != version || request.ExpectedContinuationVersion != 1 ||
			request.ExpectedFactorRevision != fixture.factorRevision ||
			request.ExpectedUserAuthenticationRevision != fixture.userRevision {
			return DirectSAMLTOTPChallenge{}, errors.New("stale failure")
		}
		failures++
		version++
		if failures == maximumDirectSAMLTOTPFailures {
			state = DirectSAMLTOTPChallengeFailed
		}
		return DirectSAMLTOTPChallenge{
			ChallengeID: fixture.challengeID, ContinuationID: fixture.continuationID,
			UserID: fixture.userID, FactorID: fixture.factorID,
			ExpectedContinuationVersion: 1, FactorRevision: fixture.factorRevision,
			UserAuthenticationRevision: fixture.userRevision, FailureCount: failures,
			State: state, Version: version, ExpiresAt: fixture.expiresAt,
		}, nil
	}
	var verifications atomic.Int32
	verifier := directSAMLTOTPVerifierFunc(func(context.Context, DirectSAMLTOTPVerificationRequest) (DirectSAMLTOTPProof, error) {
		verifications.Add(1)
		return DirectSAMLTOTPProof{}, ErrDirectSAMLTOTPInvalidProof
	})
	application := directSAMLTOTPTestApplication(t, store, verifier, fixture.issuer(t), nil)
	for attempt := 1; attempt <= int(maximumDirectSAMLTOTPFailures); attempt++ {
		outcome, err := application.Complete(context.Background(), fixture.completeCommand())
		outcome.Destroy()
		if !errors.Is(err, ErrAuthenticationDenied) {
			t.Fatalf("attempt %d error = %v", attempt, err)
		}
	}
	guard.Lock()
	gotFailures, gotVersion, gotState := failures, version, state
	guard.Unlock()
	if gotFailures != maximumDirectSAMLTOTPFailures || gotVersion != 6 ||
		gotState != DirectSAMLTOTPChallengeFailed || verifications.Load() != 5 {
		t.Fatalf("terminal state = failures:%d version:%d state:%s verifications:%d", gotFailures, gotVersion, gotState, verifications.Load())
	}
	if outcome, err := application.Complete(context.Background(), fixture.completeCommand()); !errors.Is(err, ErrAuthenticationUnavailable) || outcome != (DirectSAMLTOTPCompletionOutcome{}) || verifications.Load() != 5 {
		outcome.Destroy()
		t.Fatalf("terminal replay = %s, %v, verifications=%d", outcome, err, verifications.Load())
	}
}

func TestDirectSAMLTOTPApplyReplayIsTerminalAndNeverRecovered(t *testing.T) {
	t.Parallel()
	fixture := directSAMLTOTPFixture()
	var recoveryCalls, cleanupCalls atomic.Int32
	store := &directSAMLTOTPStoreStub{
		load: func(context.Context, DirectSAMLTOTPLookup) (DirectSAMLTOTPVerificationSnapshot, error) {
			return fixture.snapshot(
				[]byte("replay-secret-ciphertext-material"), []byte("123456789012"),
				[]byte("totp_credential:fixture:user:fixture"),
			), nil
		},
		apply: func(context.Context, DirectSAMLTOTPApplyRequest) (DirectSAMLTOTPApplyResult, error) {
			return fixture.applyResult(DirectSAMLTOTPApplyReplay), nil
		},
		recover: func(context.Context, DirectSAMLTOTPApplyRecoveryLookup) (DirectSAMLTOTPApplyRecoveryResult, error) {
			recoveryCalls.Add(1)
			return DirectSAMLTOTPApplyRecoveryResult{}, nil
		},
		cleanup: func(context.Context, DirectSAMLTOTPCleanupRequest) error {
			cleanupCalls.Add(1)
			return nil
		},
	}
	application := directSAMLTOTPTestApplication(t, store, directSAMLTOTPVerifierFunc(
		func(context.Context, DirectSAMLTOTPVerificationRequest) (DirectSAMLTOTPProof, error) {
			return DirectSAMLTOTPProof{Counter: fixture.counter}, nil
		},
	), fixture.issuer(t), nil)
	outcome, err := application.Complete(context.Background(), fixture.completeCommand())
	defer outcome.Destroy()
	if !errors.Is(err, ErrAuthenticationDenied) || outcome != (DirectSAMLTOTPCompletionOutcome{}) ||
		recoveryCalls.Load() != 0 || cleanupCalls.Load() != 0 {
		t.Fatalf("replay = %s, %v, recovery=%d cleanup=%d", outcome, err, recoveryCalls.Load(), cleanupCalls.Load())
	}
}

func TestDirectSAMLTOTPAbandonCarriesEveryExactRevision(t *testing.T) {
	t.Parallel()
	fixture := directSAMLTOTPFixture()
	var captured DirectSAMLTOTPAbandonRequest
	store := &directSAMLTOTPStoreStub{
		load: func(context.Context, DirectSAMLTOTPLookup) (DirectSAMLTOTPVerificationSnapshot, error) {
			return fixture.snapshot(
				[]byte("abandon-secret-ciphertext-material"), []byte("123456789012"),
				[]byte("totp_credential:fixture:user:fixture"),
			), nil
		},
		abandon: func(_ context.Context, request DirectSAMLTOTPAbandonRequest) (DirectSAMLTOTPChallenge, error) {
			captured = request
			return DirectSAMLTOTPChallenge{
				ChallengeID: fixture.challengeID, ContinuationID: fixture.continuationID,
				UserID: fixture.userID, FactorID: fixture.factorID,
				ExpectedContinuationVersion: 1, FactorRevision: fixture.factorRevision,
				UserAuthenticationRevision: fixture.userRevision, FailureCount: 0,
				State: DirectSAMLTOTPChallengeAbandoned, Version: 2, ExpiresAt: fixture.expiresAt,
			}, nil
		},
	}
	application := directSAMLTOTPTestApplication(t, store, nil, nil, nil)
	err := application.Abandon(context.Background(), AbandonDirectSAMLTOTPCommand{
		ChallengeID: fixture.challengeID, ContinuationID: fixture.continuationID,
		ReceiptDigest: fixture.receiptDigest, BrowserHandle: fixture.browserHandle,
		Reason: DirectSAMLTOTPAbandonCancelled, Audit: fixture.audit,
	})
	if err != nil || captured.ExpectedContinuationVersion != 1 ||
		captured.ExpectedFactorRevision != fixture.factorRevision ||
		captured.ExpectedUserAuthenticationRevision != fixture.userRevision ||
		captured.ExpectedChallengeVersion != 1 || captured.Reason != DirectSAMLTOTPAbandonCancelled {
		t.Fatalf("Abandon() = %v, request=%s", err, captured)
	}
}

func TestDirectSAMLTOTPDeliveryFinalizerSerializesCopies(t *testing.T) {
	t.Parallel()
	fixture := directSAMLTOTPFixture()
	apply := fixture.applyRequest(t)
	result := fixture.applyResult(DirectSAMLTOTPApplySuccess)
	var cleanupCalls atomic.Int32
	store := &directSAMLTOTPStoreStub{cleanup: func(context.Context, DirectSAMLTOTPCleanupRequest) error {
		cleanupCalls.Add(1)
		return nil
	}}
	finalizer := newDirectSAMLTOTPDeliveryFinalizer(store, func() time.Time {
		return directSAMLTOTPTestNow.Add(time.Second)
	}, 25*time.Millisecond, apply, result, fixture.audit)
	if finalizer == nil {
		t.Fatal("newDirectSAMLTOTPDeliveryFinalizer() rejected fixture")
	}
	left, right := *finalizer, *finalizer
	start := make(chan struct{})
	results := make(chan error, 2)
	go func() {
		<-start
		results <- left.ConfirmBrowserDelivery()
	}()
	go func() {
		<-start
		results <- right.CompensateBrowserDelivery(context.Background())
	}()
	close(start)
	first, second := <-results, <-results
	clean := 0
	rejected := 0
	for _, err := range []error{first, second} {
		if err == nil {
			clean++
		} else if errors.Is(err, ErrBrowserDeliveryRejected) {
			rejected++
		} else {
			t.Fatalf("unexpected finalizer result: %v", err)
		}
	}
	if clean != 1 || rejected != 1 || cleanupCalls.Load() > 1 {
		t.Fatalf("finalizer race clean=%d rejected=%d cleanup=%d", clean, rejected, cleanupCalls.Load())
	}
}

func TestDirectSAMLTOTPDeliveryCannotConfirmAfterAmbiguousCompensation(t *testing.T) {
	t.Parallel()
	fixture := directSAMLTOTPFixture()
	apply := fixture.applyRequest(t)
	result := fixture.applyResult(DirectSAMLTOTPApplySuccess)
	var calls atomic.Int32
	var cleanedUpAt []time.Time
	store := &directSAMLTOTPStoreStub{cleanup: func(_ context.Context, request DirectSAMLTOTPCleanupRequest) error {
		cleanedUpAt = append(cleanedUpAt, request.CleanedUpAt)
		if calls.Add(1) <= 2 {
			return errors.New("ambiguous cleanup")
		}
		return nil
	}}
	var clockCalls atomic.Int32
	finalizer := newDirectSAMLTOTPDeliveryFinalizer(store, func() time.Time {
		return directSAMLTOTPTestNow.Add(time.Duration(clockCalls.Add(1)) * time.Second)
	}, 25*time.Millisecond, apply, result, fixture.audit)
	if finalizer == nil {
		t.Fatal("newDirectSAMLTOTPDeliveryFinalizer() rejected fixture")
	}
	copyValue := *finalizer
	if err := finalizer.CompensateBrowserDelivery(context.Background()); !errors.Is(err, ErrBrowserDeliveryUnavailable) {
		t.Fatalf("first compensation = %v", err)
	}
	if err := copyValue.ConfirmBrowserDelivery(); !errors.Is(err, ErrBrowserDeliveryRejected) {
		t.Fatalf("confirm after ambiguous compensation = %v", err)
	}
	if err := copyValue.CompensateBrowserDelivery(context.Background()); err != nil || calls.Load() != 3 ||
		clockCalls.Load() != 1 || len(cleanedUpAt) != 3 || cleanedUpAt[0] != cleanedUpAt[1] ||
		cleanedUpAt[1] != cleanedUpAt[2] {
		t.Fatalf("recovered compensation = %v, calls=%d clock=%d cleaned=%v", err, calls.Load(), clockCalls.Load(), cleanedUpAt)
	}
}

func TestDirectSAMLTOTPTypesCannotCarryOIDCAuthority(t *testing.T) {
	t.Parallel()
	for _, value := range []any{
		StartDirectSAMLTOTPCommand{}, CompleteDirectSAMLTOTPCommand{}, DirectSAMLTOTPLookup{},
		DirectSAMLTOTPFailureRequest{}, DirectSAMLTOTPApplyRequest{}, DirectSAMLTOTPAbandonRequest{},
	} {
		if _, found := reflect.TypeOf(value).FieldByName("Authority"); found {
			t.Fatalf("%T exposes caller-controlled Authority", value)
		}
	}
	continuationID := testID(111)
	receipt := opaqueCredential(112)
	samlDigest, err := ContinuationReceiptDigest(continuationID, receipt)
	if err != nil {
		t.Fatal(err)
	}
	oidcDigest, err := federatedauth.ContinuationReceiptDigest(
		federatedauth.ContinuationAuthorityDirectPlatformOIDC, continuationID, receipt,
	)
	if err != nil || samlDigest == oidcDigest {
		t.Fatalf("cross-protocol receipt digests collided: saml=%x oidc=%x err=%v", samlDigest, oidcDigest, err)
	}
}

type directSAMLTOTPTestFixture struct {
	challengeID    mfa.ChallengeID
	continuationID identity.EntityID
	userID         identity.EntityID
	factorID       identity.EntityID
	sessionID      identity.EntityID
	familyID       identity.EntityID
	receiptDigest  [sha256.Size]byte
	browserHandle  []byte
	factorRevision uint64
	userRevision   uint64
	counter        int64
	expiresAt      time.Time
	audit          AuditContext
}

func directSAMLTOTPFixture() directSAMLTOTPTestFixture {
	var challengeID mfa.ChallengeID
	copy(challengeID[:], bytes.Repeat([]byte{0x31}, sha256.Size))
	return directSAMLTOTPTestFixture{
		challengeID: challengeID, continuationID: testID(101), userID: testID(102), factorID: testID(103),
		sessionID: testID(104), familyID: testID(105),
		receiptDigest: sha256.Sum256([]byte("direct-saml-totp-receipt")), browserHandle: opaqueCredential(106),
		factorRevision: 17, userRevision: 18, counter: 42,
		expiresAt: directSAMLTOTPTestNow.Add(5 * time.Minute),
		audit: AuditContext{
			RequestID: testID(107), CorrelationID: testID(108),
			RemoteAddress: netip.MustParseAddr("198.51.100.107"), UserAgent: "direct-saml-totp-test/1",
		},
	}
}

func (fixture directSAMLTOTPTestFixture) snapshot(ciphertext, nonce, aad []byte) DirectSAMLTOTPVerificationSnapshot {
	return DirectSAMLTOTPVerificationSnapshot{
		ChallengeID: fixture.challengeID, ContinuationID: fixture.continuationID,
		ReceiptDigest: fixture.receiptDigest, UserID: fixture.userID, FactorID: fixture.factorID,
		Secret: DirectSAMLProtectedTOTPSecret{
			Ciphertext: ciphertext, Nonce: nonce, AAD: aad, KeyVersion: 1,
			EncryptionAlgorithm: "aes-256-gcm", OTPAlgorithm: "SHA1", Digits: 6, PeriodSeconds: 30,
		},
		ExpectedContinuationVersion: 1, FactorRevision: fixture.factorRevision,
		UserAuthenticationRevision: fixture.userRevision, State: DirectSAMLTOTPChallengePending,
		ExpiresAt: fixture.expiresAt, Version: 1,
	}
}

func (fixture directSAMLTOTPTestFixture) completeCommand() CompleteDirectSAMLTOTPCommand {
	return CompleteDirectSAMLTOTPCommand{
		ChallengeID: fixture.challengeID, ContinuationID: fixture.continuationID,
		ReceiptDigest: fixture.receiptDigest, BrowserHandle: append([]byte(nil), fixture.browserHandle...),
		FactorID: fixture.factorID, Code: []byte("123456"), Audit: fixture.audit,
	}
}

func (fixture directSAMLTOTPTestFixture) issuer(t testing.TB) CredentialIssuer {
	t.Helper()
	return credentialIssuerFunc(func(request CredentialRequest) (*CredentialReservation, error) {
		if request.Disposition != ImmediateSession || request.TOTP != nil || request.IssuedAt != directSAMLTOTPTestNow {
			return nil, errors.New("unexpected credential request")
		}
		token, csrf := opaqueCredential(109), opaqueCredential(110)
		defer clear(token)
		defer clear(csrf)
		issuedAt := request.IssuedAt.Truncate(time.Millisecond)
		reservation, err := mfa.NewSessionReservation(mfa.SessionMaterial{
			SessionID: fixture.sessionID, FamilyID: fixture.familyID,
			TokenDigest: sha256.Sum256(token), CSRFDigest: sha256.Sum256(csrf),
			AuthenticationMethod: mfa.SessionAuthenticationSAML,
			IdleExpiresAt:        issuedAt.Add(time.Hour), AbsoluteExpiresAt: issuedAt.Add(8 * time.Hour),
		}, issuedAt)
		if err != nil {
			return nil, err
		}
		return NewSessionCredentialReservation(reservation, token, csrf)
	})
}

func (fixture directSAMLTOTPTestFixture) applyResult(category DirectSAMLTOTPApplyCategory) DirectSAMLTOTPApplyResult {
	return DirectSAMLTOTPApplyResult{
		Category: category, SessionID: fixture.sessionID, UserID: fixture.userID,
		FactorID: fixture.factorID, FactorRevision: fixture.factorRevision,
		UserAuthenticationRevision: fixture.userRevision, AcceptedCounter: fixture.counter,
		CompletedAt: directSAMLTOTPTestNow,
	}
}

func (fixture directSAMLTOTPTestFixture) applyRequest(t testing.TB) DirectSAMLTOTPApplyRequest {
	t.Helper()
	reservation := fixture.issuer(t)
	credential, err := reservation.ReserveDirectSAMLCredential(CredentialRequest{
		Disposition: ImmediateSession, IssuedAt: directSAMLTOTPTestNow,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer credential.Destroy()
	request := DirectSAMLTOTPApplyRequest{
		ChallengeID: fixture.challengeID, ContinuationID: fixture.continuationID,
		ReceiptDigest:               fixture.receiptDigest,
		BrowserDigest:               DirectSAMLTOTPBrowserDigest(sha256.Sum256(fixture.browserHandle)),
		ExpectedContinuationVersion: 1, ExpectedFactorRevision: fixture.factorRevision,
		ExpectedUserAuthenticationRevision: fixture.userRevision, ExpectedChallengeVersion: 1,
		AcceptedCounter: fixture.counter, Session: credential.Session(),
		ObservedAt: directSAMLTOTPTestNow, Audit: fixture.audit,
	}
	digest, ok := directSAMLTOTPCompletionRequestDigest(
		fixture.challengeID, fixture.continuationID, fixture.receiptDigest, request.BrowserDigest,
		1, fixture.factorRevision, fixture.userRevision, 1, fixture.counter, request.Session,
	)
	if !ok {
		t.Fatal("completion digest fixture rejected")
	}
	request.CompletionRequestDigest = digest
	return request
}

func directSAMLTOTPTestApplication(
	t testing.TB,
	store DirectSAMLTOTPStore,
	verifier DirectSAMLTOTPVerifier,
	issuer CredentialIssuer,
	random io.Reader,
) *DirectSAMLTOTPApplication {
	t.Helper()
	if verifier == nil {
		verifier = directSAMLTOTPVerifierFunc(func(context.Context, DirectSAMLTOTPVerificationRequest) (DirectSAMLTOTPProof, error) {
			return DirectSAMLTOTPProof{}, errors.New("unused verifier")
		})
	}
	if issuer == nil {
		issuer = credentialIssuerFunc(func(CredentialRequest) (*CredentialReservation, error) {
			return nil, errors.New("unused issuer")
		})
	}
	application, err := NewDirectSAMLTOTPApplication(DirectSAMLTOTPApplicationOptions{
		Store: store, Verifier: verifier, Credentials: issuer, Random: random,
		Now: func() time.Time { return directSAMLTOTPTestNow }, ChallengeTTL: 5 * time.Minute,
		OperationTimeout: time.Second, RecoveryTimeout: 25 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewDirectSAMLTOTPApplication() error = %v", err)
	}
	return application
}
