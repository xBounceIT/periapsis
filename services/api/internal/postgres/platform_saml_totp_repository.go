package postgres

import (
	"context"
	"crypto/sha256"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/services/api/internal/platformsamlauth"
)

const (
	beginPlatformSAMLTOTPSQL   = `select app.begin_platform_saml_post_primary_totp_v1($1::jsonb)`
	loadPlatformSAMLTOTPSQL    = `select app.load_platform_saml_post_primary_totp_v1($1::jsonb)`
	failPlatformSAMLTOTPSQL    = `select app.record_platform_saml_post_primary_totp_failure_v1($1::jsonb)`
	applyPlatformSAMLTOTPSQL   = `select app.apply_platform_saml_post_primary_totp_v1($1::jsonb)`
	recoverPlatformSAMLTOTPSQL = `select app.recover_platform_saml_post_primary_totp_apply_v1($1::jsonb)`
	abandonPlatformSAMLTOTPSQL = `select app.abandon_platform_saml_post_primary_totp_v1($1::jsonb)`
	cleanupPlatformSAMLTOTPSQL = `select app.cleanup_platform_saml_post_primary_totp_apply_v1($1::jsonb)`
	maximumPlatformSAMLTOTP    = 131072
)

type platformSAMLTOTPChallengeWire struct {
	ChallengeID                 []byte    `json:"challengeId"`
	ContinuationID              string    `json:"continuationId"`
	UserID                      string    `json:"userId"`
	FactorID                    string    `json:"factorId"`
	ExpectedContinuationVersion uint64    `json:"expectedContinuationVersion"`
	FactorRevision              uint64    `json:"factorRevision"`
	UserAuthenticationRevision  uint64    `json:"userAuthenticationRevision"`
	FailureCount                uint32    `json:"failureCount"`
	State                       string    `json:"state"`
	Version                     uint64    `json:"version"`
	ExpiresAt                   time.Time `json:"expiresAt"`
}

type platformSAMLTOTPBeginWire struct {
	ContinuationID              string                `json:"continuationId"`
	ReceiptDigest               []byte                `json:"receiptDigest"`
	ExpectedContinuationVersion uint64                `json:"expectedContinuationVersion"`
	ChallengeID                 []byte                `json:"challengeId"`
	BrowserDigest               []byte                `json:"browserDigest"`
	CreatedAt                   time.Time             `json:"createdAt"`
	ExpiresAt                   time.Time             `json:"expiresAt"`
	Audit                       platformSAMLAuditWire `json:"audit"`
}

type platformSAMLTOTPLookupWire struct {
	ChallengeID    []byte    `json:"challengeId"`
	ContinuationID string    `json:"continuationId"`
	ReceiptDigest  []byte    `json:"receiptDigest"`
	BrowserDigest  []byte    `json:"browserDigest"`
	ObservedAt     time.Time `json:"observedAt"`
}

type platformSAMLTOTPSecretWire struct {
	Ciphertext          []byte `json:"ciphertext"`
	Nonce               []byte `json:"nonce"`
	AAD                 []byte `json:"aad"`
	KeyVersion          int16  `json:"keyVersion"`
	EncryptionAlgorithm string `json:"encryptionAlgorithm"`
	OTPAlgorithm        string `json:"otpAlgorithm"`
	Digits              uint8  `json:"digits"`
	PeriodSeconds       uint16 `json:"periodSeconds"`
}

type platformSAMLTOTPVerificationWire struct {
	platformSAMLTOTPChallengeWire
	ReceiptDigest       []byte                     `json:"receiptDigest"`
	Secret              platformSAMLTOTPSecretWire `json:"secret"`
	LastAcceptedCounter *int64                     `json:"lastAcceptedCounter"`
}

type platformSAMLTOTPMutationWire struct {
	ChallengeID                        []byte                `json:"challengeId"`
	ContinuationID                     string                `json:"continuationId"`
	ReceiptDigest                      []byte                `json:"receiptDigest"`
	BrowserDigest                      []byte                `json:"browserDigest"`
	ExpectedContinuationVersion        uint64                `json:"expectedContinuationVersion"`
	ExpectedFactorRevision             uint64                `json:"expectedFactorRevision"`
	ExpectedUserAuthenticationRevision uint64                `json:"expectedUserAuthenticationRevision"`
	ExpectedChallengeVersion           uint64                `json:"expectedChallengeVersion"`
	ObservedAt                         time.Time             `json:"observedAt"`
	Reason                             string                `json:"reason,omitempty"`
	Audit                              platformSAMLAuditWire `json:"audit"`
}

type platformSAMLTOTPApplyWire struct {
	platformSAMLTOTPMutationWire
	AcceptedCounter         int64                              `json:"acceptedCounter"`
	CompletionRequestDigest []byte                             `json:"completionRequestDigest"`
	Session                 platformSAMLSessionReservationWire `json:"session"`
}

type platformSAMLTOTPApplyResultWire struct {
	Category                   string    `json:"category"`
	SessionID                  string    `json:"sessionId"`
	UserID                     string    `json:"userId"`
	FactorID                   string    `json:"factorId"`
	FactorRevision             uint64    `json:"factorRevision"`
	UserAuthenticationRevision uint64    `json:"userAuthenticationRevision"`
	AcceptedCounter            int64     `json:"acceptedCounter"`
	CompletedAt                time.Time `json:"completedAt"`
}

var _ platformsamlauth.DirectSAMLTOTPStore = (*FederatedAuthRepository)(nil)

func (r *FederatedAuthRepository) BeginDirectSAMLTOTP(ctx context.Context, request platformsamlauth.DirectSAMLTOTPBeginRequest) (platformsamlauth.DirectSAMLTOTPChallenge, error) {
	audit, err := platformSAMLAuditToWire(request.Audit)
	if err != nil || !validPlatformSAMLTOTPIDs(request.ContinuationID, request.ChallengeID) ||
		request.ReceiptDigest == ([sha256.Size]byte{}) || request.BrowserDigest == (platformsamlauth.DirectSAMLTOTPBrowserDigest{}) ||
		request.ExpectedContinuationVersion == 0 || !validPlatformSAMLInstant(request.CreatedAt) ||
		!validPlatformSAMLInstant(request.ExpiresAt) || !request.ExpiresAt.After(request.CreatedAt) {
		return platformsamlauth.DirectSAMLTOTPChallenge{}, errPlatformSAMLPersistence
	}
	wire := platformSAMLTOTPBeginWire{ContinuationID: entityIDWire(request.ContinuationID), ReceiptDigest: request.ReceiptDigest[:], ExpectedContinuationVersion: request.ExpectedContinuationVersion, ChallengeID: request.ChallengeID[:], BrowserDigest: request.BrowserDigest[:], CreatedAt: request.CreatedAt, ExpiresAt: request.ExpiresAt, Audit: audit}
	var response platformSAMLTOTPChallengeWire
	if err = r.queryJSONWithResponseLimit(ctx, beginPlatformSAMLTOTPSQL, wire, &response, maximumPlatformSAMLTOTP); err != nil {
		return platformsamlauth.DirectSAMLTOTPChallenge{}, errPlatformSAMLPersistence
	}
	return platformSAMLTOTPChallengeFromWire(response, request.ChallengeID, request.ContinuationID)
}

func (r *FederatedAuthRepository) LoadDirectSAMLTOTP(ctx context.Context, lookup platformsamlauth.DirectSAMLTOTPLookup) (platformsamlauth.DirectSAMLTOTPVerificationSnapshot, error) {
	if !validPlatformSAMLTOTPIDs(lookup.ContinuationID, lookup.ChallengeID) || lookup.ReceiptDigest == ([sha256.Size]byte{}) || lookup.BrowserDigest == (platformsamlauth.DirectSAMLTOTPBrowserDigest{}) || !validPlatformSAMLInstant(lookup.ObservedAt) {
		return platformsamlauth.DirectSAMLTOTPVerificationSnapshot{}, errPlatformSAMLPersistence
	}
	wire := platformSAMLTOTPLookupWire{ChallengeID: lookup.ChallengeID[:], ContinuationID: entityIDWire(lookup.ContinuationID), ReceiptDigest: lookup.ReceiptDigest[:], BrowserDigest: lookup.BrowserDigest[:], ObservedAt: lookup.ObservedAt}
	var response platformSAMLTOTPVerificationWire
	if err := r.queryJSONWithResponseLimit(ctx, loadPlatformSAMLTOTPSQL, wire, &response, maximumPlatformSAMLTOTP); err != nil {
		return platformsamlauth.DirectSAMLTOTPVerificationSnapshot{}, errPlatformSAMLPersistence
	}
	challenge, err := platformSAMLTOTPChallengeFromWire(response.platformSAMLTOTPChallengeWire, lookup.ChallengeID, lookup.ContinuationID)
	if err != nil || len(response.ReceiptDigest) != sha256.Size || string(response.ReceiptDigest) != string(lookup.ReceiptDigest[:]) || len(response.Secret.Ciphertext) < 17 || len(response.Secret.Nonce) < 12 || len(response.Secret.AAD) == 0 || response.Secret.KeyVersion < 1 {
		clear(response.Secret.Ciphertext)
		clear(response.Secret.Nonce)
		clear(response.Secret.AAD)
		return platformsamlauth.DirectSAMLTOTPVerificationSnapshot{}, errPlatformSAMLPersistence
	}
	return platformsamlauth.DirectSAMLTOTPVerificationSnapshot{ChallengeID: challenge.ChallengeID, ContinuationID: challenge.ContinuationID, ReceiptDigest: lookup.ReceiptDigest, UserID: challenge.UserID, FactorID: challenge.FactorID, Secret: platformsamlauth.DirectSAMLProtectedTOTPSecret{Ciphertext: response.Secret.Ciphertext, Nonce: response.Secret.Nonce, AAD: response.Secret.AAD, KeyVersion: response.Secret.KeyVersion, EncryptionAlgorithm: response.Secret.EncryptionAlgorithm, OTPAlgorithm: response.Secret.OTPAlgorithm, Digits: response.Secret.Digits, PeriodSeconds: response.Secret.PeriodSeconds}, LastAcceptedCounter: response.LastAcceptedCounter, ExpectedContinuationVersion: challenge.ExpectedContinuationVersion, FactorRevision: challenge.FactorRevision, UserAuthenticationRevision: challenge.UserAuthenticationRevision, FailureCount: challenge.FailureCount, State: challenge.State, ExpiresAt: challenge.ExpiresAt, Version: challenge.Version}, nil
}

func (r *FederatedAuthRepository) RecordDirectSAMLTOTPFailure(ctx context.Context, request platformsamlauth.DirectSAMLTOTPFailureRequest) (platformsamlauth.DirectSAMLTOTPChallenge, error) {
	wire, err := platformSAMLTOTPMutationToWire(request.ChallengeID, request.ContinuationID, request.ReceiptDigest, request.BrowserDigest, request.ExpectedContinuationVersion, request.ExpectedFactorRevision, request.ExpectedUserAuthenticationRevision, request.ExpectedChallengeVersion, request.ObservedAt, "", request.Audit)
	if err != nil {
		return platformsamlauth.DirectSAMLTOTPChallenge{}, err
	}
	var response platformSAMLTOTPChallengeWire
	if err = r.queryJSONWithResponseLimit(ctx, failPlatformSAMLTOTPSQL, wire, &response, maximumPlatformSAMLTOTP); err != nil {
		return platformsamlauth.DirectSAMLTOTPChallenge{}, errPlatformSAMLPersistence
	}
	return platformSAMLTOTPChallengeFromWire(response, request.ChallengeID, request.ContinuationID)
}

func (r *FederatedAuthRepository) ApplyDirectSAMLTOTP(ctx context.Context, request platformsamlauth.DirectSAMLTOTPApplyRequest) (platformsamlauth.DirectSAMLTOTPApplyResult, error) {
	base, err := platformSAMLTOTPMutationToWire(request.ChallengeID, request.ContinuationID, request.ReceiptDigest, request.BrowserDigest, request.ExpectedContinuationVersion, request.ExpectedFactorRevision, request.ExpectedUserAuthenticationRevision, request.ExpectedChallengeVersion, request.ObservedAt, "", request.Audit)
	if err != nil || request.AcceptedCounter < 0 || request.CompletionRequestDigest == (platformsamlauth.DirectSAMLTOTPCompletionDigest{}) {
		return platformsamlauth.DirectSAMLTOTPApplyResult{}, errPlatformSAMLPersistence
	}
	session, err := platformSAMLSessionReservationToWire(request.Session, request.ObservedAt)
	if err != nil {
		return platformsamlauth.DirectSAMLTOTPApplyResult{}, err
	}
	wire := platformSAMLTOTPApplyWire{platformSAMLTOTPMutationWire: base, AcceptedCounter: request.AcceptedCounter, CompletionRequestDigest: request.CompletionRequestDigest[:], Session: session}
	var response platformSAMLTOTPApplyResultWire
	if err = r.queryJSONWithResponseLimit(ctx, applyPlatformSAMLTOTPSQL, wire, &response, maximumPlatformSAMLTOTP); err != nil {
		return platformsamlauth.DirectSAMLTOTPApplyResult{}, errPlatformSAMLPersistence
	}
	return platformSAMLTOTPApplyResultFromWire(response, request)
}

func (r *FederatedAuthRepository) RecoverDirectSAMLTOTPApply(ctx context.Context, lookup platformsamlauth.DirectSAMLTOTPApplyRecoveryLookup) (platformsamlauth.DirectSAMLTOTPApplyRecoveryResult, error) {
	request := lookup.Request
	base, err := platformSAMLTOTPMutationToWire(request.ChallengeID, request.ContinuationID, request.ReceiptDigest, request.BrowserDigest, request.ExpectedContinuationVersion, request.ExpectedFactorRevision, request.ExpectedUserAuthenticationRevision, request.ExpectedChallengeVersion, request.ObservedAt, "", request.Audit)
	if err != nil {
		return platformsamlauth.DirectSAMLTOTPApplyRecoveryResult{}, err
	}
	session, err := platformSAMLSessionReservationToWire(request.Session, request.ObservedAt)
	if err != nil {
		return platformsamlauth.DirectSAMLTOTPApplyRecoveryResult{}, err
	}
	wire := platformSAMLTOTPApplyWire{platformSAMLTOTPMutationWire: base, AcceptedCounter: request.AcceptedCounter, CompletionRequestDigest: request.CompletionRequestDigest[:], Session: session}
	var response struct {
		Matched bool                             `json:"matched"`
		Result  *platformSAMLTOTPApplyResultWire `json:"result,omitempty"`
	}
	if err = r.queryJSONWithResponseLimit(ctx, recoverPlatformSAMLTOTPSQL, wire, &response, maximumPlatformSAMLTOTP); err != nil {
		return platformsamlauth.DirectSAMLTOTPApplyRecoveryResult{}, errPlatformSAMLPersistence
	}
	if !response.Matched {
		if response.Result != nil {
			return platformsamlauth.DirectSAMLTOTPApplyRecoveryResult{}, errPlatformSAMLPersistence
		}
		return platformsamlauth.DirectSAMLTOTPApplyRecoveryResult{Matched: false}, nil
	}
	if response.Result == nil {
		return platformsamlauth.DirectSAMLTOTPApplyRecoveryResult{}, errPlatformSAMLPersistence
	}
	result, err := platformSAMLTOTPApplyResultFromWire(*response.Result, request)
	if err != nil || result.Category != platformsamlauth.DirectSAMLTOTPApplyAlreadyApplied {
		return platformsamlauth.DirectSAMLTOTPApplyRecoveryResult{}, errPlatformSAMLPersistence
	}
	return platformsamlauth.DirectSAMLTOTPApplyRecoveryResult{Matched: true, Result: result}, nil
}

func (r *FederatedAuthRepository) AbandonDirectSAMLTOTP(ctx context.Context, request platformsamlauth.DirectSAMLTOTPAbandonRequest) (platformsamlauth.DirectSAMLTOTPChallenge, error) {
	wire, err := platformSAMLTOTPMutationToWire(request.ChallengeID, request.ContinuationID, request.ReceiptDigest, request.BrowserDigest, request.ExpectedContinuationVersion, request.ExpectedFactorRevision, request.ExpectedUserAuthenticationRevision, request.ExpectedChallengeVersion, request.ObservedAt, string(request.Reason), request.Audit)
	if err != nil {
		return platformsamlauth.DirectSAMLTOTPChallenge{}, err
	}
	var response platformSAMLTOTPChallengeWire
	if err = r.queryJSONWithResponseLimit(ctx, abandonPlatformSAMLTOTPSQL, wire, &response, maximumPlatformSAMLTOTP); err != nil {
		return platformsamlauth.DirectSAMLTOTPChallenge{}, errPlatformSAMLPersistence
	}
	return platformSAMLTOTPChallengeFromWire(response, request.ChallengeID, request.ContinuationID)
}

func (r *FederatedAuthRepository) CleanupDirectSAMLTOTPApply(ctx context.Context, request platformsamlauth.DirectSAMLTOTPCleanupRequest) error {
	base, err := platformSAMLTOTPMutationToWire(request.Request.ChallengeID, request.Request.ContinuationID, request.Request.ReceiptDigest, request.Request.BrowserDigest, request.Request.ExpectedContinuationVersion, request.Request.ExpectedFactorRevision, request.Request.ExpectedUserAuthenticationRevision, request.Request.ExpectedChallengeVersion, request.Request.ObservedAt, "", request.Request.Audit)
	if err != nil || request.Reason != platformsamlauth.CleanupDeliveryFailed || !validPlatformSAMLInstant(request.CleanedUpAt) {
		return errPlatformSAMLPersistence
	}
	session, err := platformSAMLSessionReservationToWire(request.Request.Session, request.Request.ObservedAt)
	if err != nil {
		return err
	}
	apply := platformSAMLTOTPApplyWire{platformSAMLTOTPMutationWire: base, AcceptedCounter: request.Request.AcceptedCounter, CompletionRequestDigest: request.Request.CompletionRequestDigest[:], Session: session}
	result := platformSAMLTOTPApplyResultWire{Category: string(request.Result.Category), SessionID: entityIDWire(request.Result.SessionID), UserID: entityIDWire(request.Result.UserID), FactorID: entityIDWire(request.Result.FactorID), FactorRevision: request.Result.FactorRevision, UserAuthenticationRevision: request.Result.UserAuthenticationRevision, AcceptedCounter: request.Result.AcceptedCounter, CompletedAt: request.Result.CompletedAt}
	wire := struct {
		Request     platformSAMLTOTPApplyWire       `json:"request"`
		Result      platformSAMLTOTPApplyResultWire `json:"result"`
		Reason      string                          `json:"reason"`
		CleanedUpAt time.Time                       `json:"cleanedUpAt"`
		Audit       platformSAMLAuditWire           `json:"audit"`
	}{apply, result, string(request.Reason), request.CleanedUpAt, base.Audit}
	var cleaned bool
	if err = r.queryJSONWithResponseLimit(ctx, cleanupPlatformSAMLTOTPSQL, wire, &cleaned, maximumPlatformSAMLTOTP); err != nil || !cleaned {
		return errPlatformSAMLPersistence
	}
	return nil
}

func platformSAMLTOTPMutationToWire(challengeID mfa.ChallengeID, continuationID identity.EntityID, receipt [32]byte, browser platformsamlauth.DirectSAMLTOTPBrowserDigest, continuationVersion, factorRevision, userRevision, challengeVersion uint64, observedAt time.Time, reason string, auditValue platformsamlauth.AuditContext) (platformSAMLTOTPMutationWire, error) {
	audit, err := platformSAMLAuditToWire(auditValue)
	if err != nil || !validPlatformSAMLTOTPIDs(continuationID, challengeID) || receipt == ([32]byte{}) || browser == (platformsamlauth.DirectSAMLTOTPBrowserDigest{}) || continuationVersion == 0 || factorRevision == 0 || userRevision == 0 || challengeVersion == 0 || !validPlatformSAMLInstant(observedAt) {
		return platformSAMLTOTPMutationWire{}, errPlatformSAMLPersistence
	}
	return platformSAMLTOTPMutationWire{ChallengeID: challengeID[:], ContinuationID: entityIDWire(continuationID), ReceiptDigest: receipt[:], BrowserDigest: browser[:], ExpectedContinuationVersion: continuationVersion, ExpectedFactorRevision: factorRevision, ExpectedUserAuthenticationRevision: userRevision, ExpectedChallengeVersion: challengeVersion, ObservedAt: observedAt, Reason: reason, Audit: audit}, nil
}

func platformSAMLTOTPChallengeFromWire(w platformSAMLTOTPChallengeWire, expectedChallenge mfa.ChallengeID, expectedContinuation identity.EntityID) (platformsamlauth.DirectSAMLTOTPChallenge, error) {
	continuation, e1 := parseEntityIDWire(w.ContinuationID, false)
	user, e2 := parseEntityIDWire(w.UserID, false)
	factor, e3 := parseEntityIDWire(w.FactorID, false)
	if e1 != nil || e2 != nil || e3 != nil || len(w.ChallengeID) != len(expectedChallenge) || string(w.ChallengeID) != string(expectedChallenge[:]) || continuation != expectedContinuation || w.ExpectedContinuationVersion == 0 || w.FactorRevision == 0 || w.UserAuthenticationRevision == 0 || w.Version == 0 || !validPlatformSAMLInstant(w.ExpiresAt) || w.FailureCount > 5 {
		return platformsamlauth.DirectSAMLTOTPChallenge{}, errPlatformSAMLPersistence
	}
	state := platformsamlauth.DirectSAMLTOTPChallengeState(w.State)
	switch state {
	case platformsamlauth.DirectSAMLTOTPChallengePending, platformsamlauth.DirectSAMLTOTPChallengeFailed, platformsamlauth.DirectSAMLTOTPChallengeCompleted, platformsamlauth.DirectSAMLTOTPChallengeAbandoned, platformsamlauth.DirectSAMLTOTPChallengeExpired:
	default:
		return platformsamlauth.DirectSAMLTOTPChallenge{}, errPlatformSAMLPersistence
	}
	return platformsamlauth.DirectSAMLTOTPChallenge{ChallengeID: expectedChallenge, ContinuationID: continuation, UserID: user, FactorID: factor, ExpectedContinuationVersion: w.ExpectedContinuationVersion, FactorRevision: w.FactorRevision, UserAuthenticationRevision: w.UserAuthenticationRevision, FailureCount: w.FailureCount, State: state, Version: w.Version, ExpiresAt: platformSAMLUTC(w.ExpiresAt)}, nil
}

func platformSAMLTOTPApplyResultFromWire(w platformSAMLTOTPApplyResultWire, request platformsamlauth.DirectSAMLTOTPApplyRequest) (platformsamlauth.DirectSAMLTOTPApplyResult, error) {
	session, e1 := parseEntityIDWire(w.SessionID, false)
	user, e2 := parseEntityIDWire(w.UserID, false)
	factor, e3 := parseEntityIDWire(w.FactorID, false)
	completed := platformSAMLUTC(w.CompletedAt)
	category := platformsamlauth.DirectSAMLTOTPApplyCategory(w.Category)
	switch category {
	case platformsamlauth.DirectSAMLTOTPApplySuccess, platformsamlauth.DirectSAMLTOTPApplyAlreadyApplied, platformsamlauth.DirectSAMLTOTPApplyStale, platformsamlauth.DirectSAMLTOTPApplyReplay:
	default:
		return platformsamlauth.DirectSAMLTOTPApplyResult{}, errPlatformSAMLPersistence
	}
	if e1 != nil || e2 != nil || e3 != nil || session != request.Session.SessionID() || w.FactorRevision != request.ExpectedFactorRevision || w.UserAuthenticationRevision != request.ExpectedUserAuthenticationRevision || w.AcceptedCounter != request.AcceptedCounter || !completed.Equal(request.ObservedAt) {
		return platformsamlauth.DirectSAMLTOTPApplyResult{}, errPlatformSAMLPersistence
	}
	return platformsamlauth.DirectSAMLTOTPApplyResult{Category: category, SessionID: session, UserID: user, FactorID: factor, FactorRevision: w.FactorRevision, UserAuthenticationRevision: w.UserAuthenticationRevision, AcceptedCounter: w.AcceptedCounter, CompletedAt: completed}, nil
}

func validPlatformSAMLTOTPIDs(continuation identity.EntityID, challenge mfa.ChallengeID) bool {
	return entityIDWire(continuation) != "" && challenge != (mfa.ChallengeID{})
}
