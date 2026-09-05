package platformoidcauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/netip"
	"reflect"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
)

type directTOTPStoreStub struct {
	begin   func(context.Context, DirectTOTPBeginRequest) (DirectTOTPChallenge, error)
	load    func(context.Context, DirectTOTPLookup) (DirectTOTPVerificationSnapshot, error)
	fail    func(context.Context, DirectTOTPFailureRequest) (DirectTOTPChallenge, error)
	apply   func(context.Context, DirectTOTPApplyRequest) (DirectTOTPApplyResult, error)
	abandon func(context.Context, DirectTOTPAbandonRequest) (DirectTOTPChallenge, error)
}

func (stub *directTOTPStoreStub) BeginDirectTOTP(
	ctx context.Context,
	request DirectTOTPBeginRequest,
) (DirectTOTPChallenge, error) {
	if stub == nil || stub.begin == nil {
		return DirectTOTPChallenge{}, errors.New("unexpected direct TOTP begin")
	}
	return stub.begin(ctx, request)
}

func (stub *directTOTPStoreStub) LoadDirectTOTP(
	ctx context.Context,
	lookup DirectTOTPLookup,
) (DirectTOTPVerificationSnapshot, error) {
	if stub == nil || stub.load == nil {
		return DirectTOTPVerificationSnapshot{}, errors.New("unexpected direct TOTP load")
	}
	return stub.load(ctx, lookup)
}

func (stub *directTOTPStoreStub) RecordDirectTOTPFailure(
	ctx context.Context,
	request DirectTOTPFailureRequest,
) (DirectTOTPChallenge, error) {
	if stub == nil || stub.fail == nil {
		return DirectTOTPChallenge{}, errors.New("unexpected direct TOTP failure")
	}
	return stub.fail(ctx, request)
}

func (stub *directTOTPStoreStub) ApplyDirectTOTP(
	ctx context.Context,
	request DirectTOTPApplyRequest,
) (DirectTOTPApplyResult, error) {
	if stub == nil || stub.apply == nil {
		return DirectTOTPApplyResult{}, errors.New("unexpected direct TOTP apply")
	}
	return stub.apply(ctx, request)
}

func (stub *directTOTPStoreStub) AbandonDirectTOTP(
	ctx context.Context,
	request DirectTOTPAbandonRequest,
) (DirectTOTPChallenge, error) {
	if stub == nil || stub.abandon == nil {
		return DirectTOTPChallenge{}, errors.New("unexpected direct TOTP abandon")
	}
	return stub.abandon(ctx, request)
}

type directTOTPVerifierFunc func(
	context.Context,
	DirectTOTPVerificationRequest,
) (DirectTOTPProof, error)

func (function directTOTPVerifierFunc) VerifyDirectTOTP(
	ctx context.Context,
	request DirectTOTPVerificationRequest,
) (DirectTOTPProof, error) {
	return function(ctx, request)
}

type directTOTPCredentialIssuerFunc func(
	federatedauth.ApplyCredentialRequest,
) (*federatedauth.ApplyCredentialReservation, error)

func (function directTOTPCredentialIssuerFunc) ReserveApplyCredential(
	request federatedauth.ApplyCredentialRequest,
) (*federatedauth.ApplyCredentialReservation, error) {
	return function(request)
}

func TestDirectTOTPStartCreatesExactPossessionBoundChallenge(t *testing.T) {
	now := directTestNow
	continuationID := directTestEntityID(61)
	receiptDigest := sha256.Sum256([]byte("direct continuation receipt"))
	audit := directTOTPAudit()
	randomBytes := append(bytes.Repeat([]byte{0x51}, directTOTPChallengeBytes),
		bytes.Repeat([]byte{0x52}, directTOTPChallengeBytes)...)
	var observed DirectTOTPBeginRequest
	store := &directTOTPStoreStub{begin: func(
		_ context.Context,
		request DirectTOTPBeginRequest,
	) (DirectTOTPChallenge, error) {
		observed = request
		return DirectTOTPChallenge{
			ChallengeID: request.ChallengeID, ContinuationID: request.ContinuationID,
			UserID: directTestEntityID(62), FactorID: directTestEntityID(63),
			UserAuthenticationRevision: 7, TOTPSecurityRevision: 8,
			State: DirectTOTPChallengePending, Version: 1, ExpiresAt: request.ExpiresAt,
		}, nil
	}}
	application := directTOTPTestApplication(t, store,
		directTOTPVerifierFunc(func(context.Context, DirectTOTPVerificationRequest) (DirectTOTPProof, error) {
			return DirectTOTPProof{}, errors.New("unused")
		}), directTOTPCredentialIssuer(t, now, nil), bytes.NewReader(randomBytes), nil)
	artifact, err := application.Start(context.Background(), StartDirectTOTPCommand{
		ContinuationID: continuationID,
		Authority:      federatedauth.ContinuationAuthorityDirectPlatformOIDC,
		ReceiptDigest:  receiptDigest,
		Audit:          audit,
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if observed.ContinuationID != continuationID || observed.ReceiptDigest != receiptDigest ||
		observed.ExpectedContinuationVersion != 1 || observed.CreatedAt != now ||
		observed.ExpiresAt != now.Add(5*time.Minute) || !reflect.DeepEqual(observed.Audit, audit) ||
		artifact.ChallengeID() != observed.ChallengeID || artifact.FactorID() != directTestEntityID(63) ||
		artifact.ExpiresAt() != observed.ExpiresAt ||
		observed.BrowserDigest != DirectTOTPBrowserDigest(sha256.Sum256(artifact.BrowserHandle())) {
		t.Fatalf("start material mismatch: request=%s artifact=%s", observed.String(), artifact.String())
	}
	internalBrowserAlias := artifact.browserHandle
	artifact.Destroy()
	if !allZeroDirectTOTPBytes(internalBrowserAlias) || !reflect.DeepEqual(artifact, DirectTOTPStartArtifact{}) {
		t.Fatal("Destroy did not clear direct TOTP browser material")
	}
}

func TestDirectTOTPStartRejectsTenantAuthorityBeforePersistence(t *testing.T) {
	calls := 0
	store := &directTOTPStoreStub{begin: func(
		context.Context,
		DirectTOTPBeginRequest,
	) (DirectTOTPChallenge, error) {
		calls++
		return DirectTOTPChallenge{}, nil
	}}
	application := directTOTPTestApplication(t, store,
		directTOTPVerifierFunc(func(context.Context, DirectTOTPVerificationRequest) (DirectTOTPProof, error) {
			return DirectTOTPProof{}, errors.New("unused")
		}), directTOTPCredentialIssuer(t, directTestNow, nil), nil, nil)
	artifact, err := application.Start(context.Background(), StartDirectTOTPCommand{
		ContinuationID: directTestEntityID(64), Authority: federatedauth.ContinuationAuthorityTenant,
		ReceiptDigest: sha256.Sum256([]byte("tenant receipt")), Audit: directTOTPAudit(),
	})
	if !errors.Is(err, ErrDirectAuthenticationDenied) ||
		!reflect.DeepEqual(artifact, DirectTOTPStartArtifact{}) || calls != 0 {
		t.Fatalf("tenant authority reached direct start: %s, %v, calls=%d", artifact.String(), err, calls)
	}
}

func TestDirectTOTPCompleteVerifiesAndReleasesCredentialOnlyAfterExactApply(t *testing.T) {
	now := directTestNow
	challengeID := directTOTPTestChallengeID(0x61)
	browser := directBrowserOpaqueCredential(0x62)
	factorID := directTestEntityID(67)
	snapshot := directTOTPTestSnapshot(challengeID, factorID, now)
	expectedSecret := cloneDirectProtectedTOTPSecret(snapshot.Secret)
	defer expectedSecret.Destroy()
	returnedCiphertext := snapshot.Secret.Ciphertext
	returnedNonce := snapshot.Secret.Nonce
	returnedAAD := snapshot.Secret.AAD
	code := []byte("123456")
	verifierCalls := 0
	applyCalls := 0
	store := &directTOTPStoreStub{
		load: func(_ context.Context, lookup DirectTOTPLookup) (DirectTOTPVerificationSnapshot, error) {
			if lookup.ChallengeID != challengeID ||
				lookup.ContinuationID != snapshot.ContinuationID ||
				lookup.Authority != federatedauth.ContinuationAuthorityDirectPlatformOIDC ||
				lookup.ReceiptDigest != directTOTPTestReceiptDigest() ||
				lookup.BrowserDigest != DirectTOTPBrowserDigest(sha256.Sum256(browser)) || lookup.ObservedAt != now {
				t.Fatalf("load lookup = %s", lookup.String())
			}
			return snapshot, nil
		},
		apply: func(_ context.Context, request DirectTOTPApplyRequest) (DirectTOTPApplyResult, error) {
			applyCalls++
			if request.ChallengeID != challengeID || request.ExpectedVersion != snapshot.Version ||
				request.ContinuationID != snapshot.ContinuationID ||
				request.Authority != federatedauth.ContinuationAuthorityDirectPlatformOIDC ||
				request.ReceiptDigest != directTOTPTestReceiptDigest() ||
				request.AcceptedCounter != 100 || request.CompletionRequestDigest == (DirectTOTPCompletionDigest{}) ||
				request.Session.IsZero() || request.ObservedAt != now ||
				request.Session.AuthenticationMethod() != mfa.SessionAuthenticationOIDC {
				t.Fatalf("apply request = %s", request.String())
			}
			return DirectTOTPApplyResult{
				Category: DirectTOTPApplySuccess, SessionID: request.Session.SessionID(),
				UserID: snapshot.UserID, FactorID: snapshot.FactorID,
				TOTPSecurityRevision: snapshot.TOTPSecurityRevision, AcceptedCounter: request.AcceptedCounter,
			}, nil
		},
	}
	application := directTOTPTestApplication(t, store, directTOTPVerifierFunc(func(
		_ context.Context,
		request DirectTOTPVerificationRequest,
	) (DirectTOTPProof, error) {
		verifierCalls++
		if request.UserID != snapshot.UserID || request.FactorID != snapshot.FactorID ||
			string(request.Code) != string(code) || request.At != now ||
			!reflect.DeepEqual(request.Secret, expectedSecret) {
			t.Fatalf("verification request = %s", request.String())
		}
		request.Secret.Ciphertext[0] ^= 0xff
		request.Code[0] = '9'
		return DirectTOTPProof{Counter: 100}, nil
	}), directTOTPCredentialIssuer(t, now, nil), nil, nil)
	outcome, err := application.Complete(
		context.Background(), directTOTPTestCompleteCommand(challengeID, browser, factorID, code),
	)
	if err != nil || verifierCalls != 1 || applyCalls != 1 || outcome.Credential == nil ||
		outcome.UserID != snapshot.UserID || outcome.FactorID != factorID || outcome.Counter != 100 {
		t.Fatalf("Complete() = %s, %v; verifier=%d apply=%d", outcome.String(), err, verifierCalls, applyCalls)
	}
	if !allZeroDirectTOTPBytes(returnedCiphertext) || !allZeroDirectTOTPBytes(returnedNonce) ||
		!allZeroDirectTOTPBytes(returnedAAD) {
		t.Fatal("store-owned secret projection was not cleared")
	}
	if string(code) != "123456" || string(browser) != string(directBrowserOpaqueCredential(0x62)) {
		t.Fatal("Complete mutated caller-owned proof material")
	}
	material, consumed := outcome.Credential.Consume()
	if !consumed || material.Kind != federatedauth.BrowserCredentialSession ||
		material.SessionID != outcome.SessionID || material.Authority != federatedauth.ContinuationAuthorityTenant ||
		len(material.SessionToken) == 0 || len(material.CSRFToken) == 0 || len(material.Receipt) != 0 {
		t.Fatalf("browser credential = %s, consumed=%t", material.String(), consumed)
	}
	material.Destroy()
	outcome.Destroy()
}

func TestDirectTOTPInvalidProofRecordsFailureAfterCallerCancellation(t *testing.T) {
	now := directTestNow
	challengeID := directTOTPTestChallengeID(0x71)
	browser := directBrowserOpaqueCredential(0x72)
	factorID := directTestEntityID(71)
	snapshot := directTOTPTestSnapshot(challengeID, factorID, now)
	ctx, cancel := context.WithCancel(context.Background())
	failureCalls := 0
	credentialCalls := 0
	store := &directTOTPStoreStub{
		load: func(context.Context, DirectTOTPLookup) (DirectTOTPVerificationSnapshot, error) {
			return snapshot, nil
		},
		fail: func(failureContext context.Context, request DirectTOTPFailureRequest) (DirectTOTPChallenge, error) {
			failureCalls++
			if failureContext.Err() != nil || request.ExpectedVersion != snapshot.Version ||
				request.ContinuationID != snapshot.ContinuationID ||
				request.Authority != federatedauth.ContinuationAuthorityDirectPlatformOIDC ||
				request.ReceiptDigest != directTOTPTestReceiptDigest() ||
				request.BrowserDigest != DirectTOTPBrowserDigest(sha256.Sum256(browser)) {
				t.Fatalf("detached failure request = %s context=%v", request.String(), failureContext.Err())
			}
			return directTOTPChallengeFromSnapshot(
				snapshot, DirectTOTPChallengePending, snapshot.Version+1, 1,
			), nil
		},
	}
	issuer := directTOTPCredentialIssuer(t, now, &credentialCalls)
	application := directTOTPTestApplication(t, store, directTOTPVerifierFunc(func(
		context.Context,
		DirectTOTPVerificationRequest,
	) (DirectTOTPProof, error) {
		cancel()
		return DirectTOTPProof{}, ErrDirectTOTPInvalidProof
	}), issuer, nil, nil)
	outcome, err := application.Complete(
		ctx, directTOTPTestCompleteCommand(challengeID, browser, factorID, []byte("000000")),
	)
	if !errors.Is(err, ErrDirectAuthenticationDenied) || outcome != (DirectTOTPCompletionOutcome{}) ||
		failureCalls != 1 || credentialCalls != 0 {
		t.Fatalf("invalid proof = %s, %v; failures=%d credentials=%d", outcome.String(), err, failureCalls, credentialCalls)
	}
}

func TestDirectTOTPVerifierInfrastructureFailureDoesNotConsumeAttempt(t *testing.T) {
	now := directTestNow
	challengeID := directTOTPTestChallengeID(0x73)
	factorID := directTestEntityID(73)
	failures := 0
	store := &directTOTPStoreStub{
		load: func(context.Context, DirectTOTPLookup) (DirectTOTPVerificationSnapshot, error) {
			return directTOTPTestSnapshot(challengeID, factorID, now), nil
		},
		fail: func(context.Context, DirectTOTPFailureRequest) (DirectTOTPChallenge, error) {
			failures++
			return DirectTOTPChallenge{}, nil
		},
	}
	application := directTOTPTestApplication(t, store, directTOTPVerifierFunc(func(
		context.Context,
		DirectTOTPVerificationRequest,
	) (DirectTOTPProof, error) {
		return DirectTOTPProof{}, errors.New("keyring unavailable")
	}), directTOTPCredentialIssuer(t, now, nil), nil, nil)
	if outcome, err := application.Complete(context.Background(), directTOTPTestCompleteCommand(
		challengeID, directBrowserOpaqueCredential(0x74), factorID, []byte("123456"),
	)); !errors.Is(err, ErrDirectAuthenticationDenied) || outcome != (DirectTOTPCompletionOutcome{}) || failures != 0 {
		t.Fatalf("infrastructure failure = %s, %v; failures=%d", outcome.String(), err, failures)
	}
}

func TestDirectTOTPCompleteRejectsSwappedContinuationProjectionBeforeProof(t *testing.T) {
	now := directTestNow
	challengeID := directTOTPTestChallengeID(0x74)
	factorID := directTestEntityID(74)
	snapshot := directTOTPTestSnapshot(challengeID, factorID, now)
	for _, mutate := range []func(*CompleteDirectTOTPCommand){
		func(command *CompleteDirectTOTPCommand) { command.ContinuationID = directTestEntityID(99) },
		func(command *CompleteDirectTOTPCommand) {
			command.ReceiptDigest = sha256.Sum256([]byte("swapped direct continuation receipt"))
		},
	} {
		verifierCalls := 0
		applyCalls := 0
		store := &directTOTPStoreStub{
			load: func(context.Context, DirectTOTPLookup) (DirectTOTPVerificationSnapshot, error) {
				// A poisoned adapter returning the original projection for a
				// swapped caller authority must still be rejected by the app.
				return cloneDirectTOTPVerificationSnapshot(snapshot), nil
			},
			apply: func(context.Context, DirectTOTPApplyRequest) (DirectTOTPApplyResult, error) {
				applyCalls++
				return DirectTOTPApplyResult{}, nil
			},
		}
		application := directTOTPTestApplication(t, store, directTOTPVerifierFunc(func(
			context.Context,
			DirectTOTPVerificationRequest,
		) (DirectTOTPProof, error) {
			verifierCalls++
			return DirectTOTPProof{Counter: 1}, nil
		}), directTOTPCredentialIssuer(t, now, nil), nil, nil)
		command := directTOTPTestCompleteCommand(
			challengeID, directBrowserOpaqueCredential(0x75), factorID, []byte("123456"),
		)
		mutate(&command)
		outcome, err := application.Complete(context.Background(), command)
		if !errors.Is(err, ErrDirectAuthenticationDenied) ||
			outcome != (DirectTOTPCompletionOutcome{}) || verifierCalls != 0 || applyCalls != 0 {
			t.Fatalf("swapped continuation = %s, %v; verifier=%d apply=%d", outcome.String(), err, verifierCalls, applyCalls)
		}
	}
}

func TestDirectTOTPApplyMismatchDestroysReservedBrowserCredential(t *testing.T) {
	now := directTestNow
	challengeID := directTOTPTestChallengeID(0x75)
	factorID := directTestEntityID(75)
	snapshot := directTOTPTestSnapshot(challengeID, factorID, now)
	var reserved *federatedauth.ApplyCredentialReservation
	issuer := directTOTPCredentialIssuer(t, now, nil)
	wrappedIssuer := directTOTPCredentialIssuerFunc(func(
		request federatedauth.ApplyCredentialRequest,
	) (*federatedauth.ApplyCredentialReservation, error) {
		var err error
		reserved, err = issuer.ReserveApplyCredential(request)
		return reserved, err
	})
	store := &directTOTPStoreStub{
		load: func(context.Context, DirectTOTPLookup) (DirectTOTPVerificationSnapshot, error) {
			return snapshot, nil
		},
		apply: func(_ context.Context, request DirectTOTPApplyRequest) (DirectTOTPApplyResult, error) {
			return DirectTOTPApplyResult{
				Category: DirectTOTPApplySuccess, SessionID: directTestEntityID(79),
				UserID: snapshot.UserID, FactorID: snapshot.FactorID,
				TOTPSecurityRevision: snapshot.TOTPSecurityRevision, AcceptedCounter: request.AcceptedCounter,
			}, nil
		},
	}
	application := directTOTPTestApplication(t, store, directTOTPVerifierFunc(func(
		context.Context,
		DirectTOTPVerificationRequest,
	) (DirectTOTPProof, error) {
		return DirectTOTPProof{Counter: 101}, nil
	}), wrappedIssuer, nil, nil)
	if outcome, err := application.Complete(context.Background(), directTOTPTestCompleteCommand(
		challengeID, directBrowserOpaqueCredential(0x76), factorID, []byte("123456"),
	)); !errors.Is(err, ErrDirectAuthenticationDenied) || outcome != (DirectTOTPCompletionOutcome{}) {
		t.Fatalf("mismatched apply = %s, %v", outcome.String(), err)
	}
	if reserved == nil {
		t.Fatal("credential was not reserved")
	}
	if credential, released := reserved.ReleaseBrowserCredential(reserved.Session().SessionID(), identity.EntityID{}); released || credential != nil {
		t.Fatal("rejected apply left browser credential releasable")
	}
}

func TestDirectTOTPAbandonUsesExactLoadedVersion(t *testing.T) {
	now := directTestNow
	challengeID := directTOTPTestChallengeID(0x77)
	browser := directBrowserOpaqueCredential(0x78)
	factorID := directTestEntityID(77)
	snapshot := directTOTPTestSnapshot(challengeID, factorID, now)
	called := 0
	store := &directTOTPStoreStub{
		load: func(context.Context, DirectTOTPLookup) (DirectTOTPVerificationSnapshot, error) {
			return snapshot, nil
		},
		abandon: func(_ context.Context, request DirectTOTPAbandonRequest) (DirectTOTPChallenge, error) {
			called++
			if request.ExpectedVersion != snapshot.Version || request.Reason != DirectTOTPAbandonCancelled ||
				request.ContinuationID != snapshot.ContinuationID ||
				request.Authority != federatedauth.ContinuationAuthorityDirectPlatformOIDC ||
				request.ReceiptDigest != directTOTPTestReceiptDigest() ||
				request.BrowserDigest != DirectTOTPBrowserDigest(sha256.Sum256(browser)) {
				t.Fatalf("abandon request = %s", request.String())
			}
			return directTOTPChallengeFromSnapshot(
				snapshot, DirectTOTPChallengeAbandoned, snapshot.Version+1, 0,
			), nil
		},
	}
	application := directTOTPTestApplication(t, store,
		directTOTPVerifierFunc(func(context.Context, DirectTOTPVerificationRequest) (DirectTOTPProof, error) {
			return DirectTOTPProof{}, errors.New("unused")
		}), directTOTPCredentialIssuer(t, now, nil), nil, nil)
	if err := application.Abandon(context.Background(), AbandonDirectTOTPCommand{
		ChallengeID: challengeID, ContinuationID: snapshot.ContinuationID,
		Authority:     federatedauth.ContinuationAuthorityDirectPlatformOIDC,
		ReceiptDigest: directTOTPTestReceiptDigest(),
		BrowserHandle: browser, Reason: DirectTOTPAbandonCancelled,
		Audit: directTOTPAudit(),
	}); err != nil || called != 1 {
		t.Fatalf("Abandon() error = %v; calls=%d", err, called)
	}
}

func TestDirectTOTPFormattingRedactsProofAndSecretMaterial(t *testing.T) {
	canary := "direct-totp-secret-canary"
	values := []fmtStringer{
		DirectProtectedTOTPSecret{Ciphertext: []byte(canary), Nonce: []byte(canary), AAD: []byte(canary)},
		DirectTOTPVerificationRequest{Code: []byte(canary)},
		CompleteDirectTOTPCommand{BrowserHandle: []byte(canary), Code: []byte(canary)},
		DirectTOTPStartArtifact{browserHandle: []byte(canary)},
	}
	for _, value := range values {
		formatted := value.String()
		if bytes.Contains([]byte(formatted), []byte(canary)) || !bytes.Contains([]byte(formatted), []byte("[REDACTED]")) {
			t.Fatalf("unsafe formatting: %s", formatted)
		}
	}
}

type fmtStringer interface{ String() string }

func directTOTPTestApplication(
	t testing.TB,
	store DirectTOTPStore,
	verifier DirectTOTPVerifier,
	issuer federatedauth.ApplyCredentialIssuer,
	randomSource *bytes.Reader,
	now func() time.Time,
) *DirectTOTPApplication {
	t.Helper()
	var source io.Reader
	if randomSource != nil {
		source = randomSource
	}
	if now == nil {
		now = func() time.Time { return directTestNow }
	}
	application, err := NewDirectTOTPApplication(DirectTOTPApplicationOptions{
		Store: store, Verifier: verifier, Credentials: issuer, Random: source, Now: now,
		ChallengeTTL: 5 * time.Minute, OperationTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("NewDirectTOTPApplication() error = %v", err)
	}
	return application
}

func directTOTPCredentialIssuer(
	t testing.TB,
	now time.Time,
	calls *int,
) federatedauth.ApplyCredentialIssuer {
	t.Helper()
	return directTOTPCredentialIssuerFunc(func(
		request federatedauth.ApplyCredentialRequest,
	) (*federatedauth.ApplyCredentialReservation, error) {
		if calls != nil {
			(*calls)++
		}
		if request.Disposition != federatedauth.ApplySession ||
			request.Method != federatedauth.AuthenticationMethodOIDC ||
			request.ContinuationAuthority != federatedauth.ContinuationAuthorityTenant || request.IssuedAt != now {
			return nil, errors.New("unexpected direct TOTP credential request")
		}
		token := directBrowserOpaqueCredential(0xe1)
		csrf := directBrowserOpaqueCredential(0xe2)
		reservation, err := mfa.NewSessionReservation(mfa.SessionMaterial{
			SessionID: directTestEntityID(81), FamilyID: directTestEntityID(82),
			TokenDigest: sha256.Sum256(token), CSRFDigest: sha256.Sum256(csrf),
			AuthenticationMethod: mfa.SessionAuthenticationOIDC,
			IdleExpiresAt:        now.Add(time.Hour).Truncate(time.Millisecond),
			AbsoluteExpiresAt:    now.Add(8 * time.Hour).Truncate(time.Millisecond),
		}, now.Truncate(time.Millisecond))
		if err != nil {
			return nil, err
		}
		return federatedauth.NewSessionApplyCredentialReservation(reservation, token, csrf)
	})
}

func directTOTPTestSnapshot(
	challengeID DirectTOTPChallengeID,
	factorID identity.EntityID,
	now time.Time,
) DirectTOTPVerificationSnapshot {
	return DirectTOTPVerificationSnapshot{
		ChallengeID: challengeID, ContinuationID: directTestEntityID(65),
		Authority:     federatedauth.ContinuationAuthorityDirectPlatformOIDC,
		ReceiptDigest: directTOTPTestReceiptDigest(),
		UserID:        directTestEntityID(66), FactorID: factorID,
		Secret: DirectProtectedTOTPSecret{
			Ciphertext: bytes.Repeat([]byte{0x91}, 32), Nonce: bytes.Repeat([]byte{0x92}, 12),
			AAD: []byte("totp_credential:fixture:user:fixture"), KeyVersion: 1,
			EncryptionAlgorithm: "aes-256-gcm", OTPAlgorithm: "SHA1", Digits: 6, PeriodSeconds: 30,
		},
		UserAuthenticationRevision: 7, TOTPSecurityRevision: 8,
		ExpiresAt: now.Add(5 * time.Minute), Version: 1,
	}
}

func directTOTPChallengeFromSnapshot(
	snapshot DirectTOTPVerificationSnapshot,
	state DirectTOTPChallengeState,
	version uint64,
	failures uint32,
) DirectTOTPChallenge {
	return DirectTOTPChallenge{
		ChallengeID: snapshot.ChallengeID, ContinuationID: snapshot.ContinuationID,
		UserID: snapshot.UserID, FactorID: snapshot.FactorID,
		UserAuthenticationRevision: snapshot.UserAuthenticationRevision,
		TOTPSecurityRevision:       snapshot.TOTPSecurityRevision, FailureCount: failures,
		State: state, Version: version, ExpiresAt: snapshot.ExpiresAt,
	}
}

func directTOTPTestChallengeID(marker byte) DirectTOTPChallengeID {
	var result DirectTOTPChallengeID
	for index := range result {
		result[index] = marker
	}
	return result
}

func directTOTPTestReceiptDigest() [sha256.Size]byte {
	return sha256.Sum256([]byte("direct-totp-test-continuation-receipt"))
}

func directTOTPTestCompleteCommand(
	challengeID DirectTOTPChallengeID,
	browserHandle []byte,
	factorID identity.EntityID,
	code []byte,
) CompleteDirectTOTPCommand {
	return CompleteDirectTOTPCommand{
		ChallengeID: challengeID, ContinuationID: directTestEntityID(65),
		Authority:     federatedauth.ContinuationAuthorityDirectPlatformOIDC,
		ReceiptDigest: directTOTPTestReceiptDigest(),
		BrowserHandle: browserHandle, FactorID: factorID, Code: code, Audit: directTOTPAudit(),
	}
}

func directTOTPAudit() DirectAuditContext {
	return DirectAuditContext{
		RequestID: directTestEntityID(91), CorrelationID: directTestEntityID(92),
		RemoteAddress: netip.MustParseAddr("198.51.100.91"), UserAgent: "direct-totp-test/1",
	}
}
