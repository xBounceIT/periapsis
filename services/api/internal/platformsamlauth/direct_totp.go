package platformsamlauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sync"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
)

const (
	directSAMLTOTPChallengeBytes      = sha256.Size
	minimumDirectSAMLTOTPChallengeTTL = time.Minute
	maximumDirectSAMLTOTPChallengeTTL = 10 * time.Minute
	maximumDirectSAMLTOTPFailures     = uint32(5)

	directSAMLTOTPCompletionDigestDomain = "periapsis/platform-saml/direct-totp-completion/v1"
)

var ErrDirectSAMLTOTPInvalidProof = errors.New("invalid direct platform SAML TOTP proof")

type DirectSAMLTOTPBrowserDigest [sha256.Size]byte
type DirectSAMLTOTPCompletionDigest [sha256.Size]byte

type DirectSAMLTOTPChallengeState string

const (
	DirectSAMLTOTPChallengePending   DirectSAMLTOTPChallengeState = "pending"
	DirectSAMLTOTPChallengeFailed    DirectSAMLTOTPChallengeState = "failed"
	DirectSAMLTOTPChallengeCompleted DirectSAMLTOTPChallengeState = "completed"
	DirectSAMLTOTPChallengeAbandoned DirectSAMLTOTPChallengeState = "abandoned"
	DirectSAMLTOTPChallengeExpired   DirectSAMLTOTPChallengeState = "expired"
)

// DirectSAMLTOTPChallenge is a purpose-specific, non-secret projection. Its
// FactorRevision is the exact totp_credentials.security_revision selected by
// the SAML continuation; there is deliberately no second revision alias.
type DirectSAMLTOTPChallenge struct {
	ChallengeID                 mfa.ChallengeID
	ContinuationID              identity.EntityID
	UserID                      identity.EntityID
	FactorID                    identity.EntityID
	ExpectedContinuationVersion uint64
	FactorRevision              uint64
	UserAuthenticationRevision  uint64
	FailureCount                uint32
	State                       DirectSAMLTOTPChallengeState
	Version                     uint64
	ExpiresAt                   time.Time
}

func (challenge DirectSAMLTOTPChallenge) String() string {
	return fmt.Sprintf(
		"platformsamlauth.DirectSAMLTOTPChallenge{challenge:%t,continuation:%t,user:%t,factor:%t,continuationVersion:%t,factorRevision:%t,userRevision:%t,failures:%d,state:%q,version:%t,expires:%t}",
		challenge.ChallengeID != (mfa.ChallengeID{}), challenge.ContinuationID != (identity.EntityID{}),
		challenge.UserID != (identity.EntityID{}), challenge.FactorID != (identity.EntityID{}),
		challenge.ExpectedContinuationVersion != 0, challenge.FactorRevision != 0,
		challenge.UserAuthenticationRevision != 0, challenge.FailureCount, challenge.State,
		challenge.Version != 0, !challenge.ExpiresAt.IsZero(),
	)
}

func (challenge DirectSAMLTOTPChallenge) GoString() string { return challenge.String() }

type DirectSAMLTOTPBeginRequest struct {
	ContinuationID              identity.EntityID
	ReceiptDigest               [sha256.Size]byte
	ExpectedContinuationVersion uint64
	ChallengeID                 mfa.ChallengeID
	BrowserDigest               DirectSAMLTOTPBrowserDigest
	CreatedAt                   time.Time
	ExpiresAt                   time.Time
	Audit                       AuditContext
}

func (request DirectSAMLTOTPBeginRequest) String() string {
	return fmt.Sprintf(
		"platformsamlauth.DirectSAMLTOTPBeginRequest{continuation:%t,continuationVersion:%t,challenge:%t,created:%t,expires:%t,audit:%q,authority:direct_platform_saml,material:[REDACTED]}",
		request.ContinuationID != (identity.EntityID{}), request.ExpectedContinuationVersion != 0,
		request.ChallengeID != (mfa.ChallengeID{}), !request.CreatedAt.IsZero(),
		!request.ExpiresAt.IsZero(), request.Audit.String(),
	)
}

func (request DirectSAMLTOTPBeginRequest) GoString() string { return request.String() }

type DirectSAMLTOTPLookup struct {
	ChallengeID    mfa.ChallengeID
	ContinuationID identity.EntityID
	ReceiptDigest  [sha256.Size]byte
	BrowserDigest  DirectSAMLTOTPBrowserDigest
	ObservedAt     time.Time
}

func (lookup DirectSAMLTOTPLookup) String() string {
	return fmt.Sprintf(
		"platformsamlauth.DirectSAMLTOTPLookup{challenge:%t,continuation:%t,observed:%t,authority:direct_platform_saml,material:[REDACTED]}",
		lookup.ChallengeID != (mfa.ChallengeID{}), lookup.ContinuationID != (identity.EntityID{}),
		!lookup.ObservedAt.IsZero(),
	)
}

func (lookup DirectSAMLTOTPLookup) GoString() string { return lookup.String() }

// DirectSAMLProtectedTOTPSecret is adapter-owned encrypted factor material.
// Every returned slice transfers to the application and is cleared there.
type DirectSAMLProtectedTOTPSecret struct {
	Ciphertext          []byte `json:"-"`
	Nonce               []byte `json:"-"`
	AAD                 []byte `json:"-"`
	KeyVersion          int16
	EncryptionAlgorithm string
	OTPAlgorithm        string
	Digits              uint8
	PeriodSeconds       uint16
}

func (secret DirectSAMLProtectedTOTPSecret) String() string {
	return fmt.Sprintf(
		"platformsamlauth.DirectSAMLProtectedTOTPSecret{keyVersion:%t,encryption:%q,otp:%q,digits:%d,period:%d,material:[REDACTED]}",
		secret.KeyVersion > 0, secret.EncryptionAlgorithm, secret.OTPAlgorithm,
		secret.Digits, secret.PeriodSeconds,
	)
}

func (secret DirectSAMLProtectedTOTPSecret) GoString() string { return secret.String() }

func (secret *DirectSAMLProtectedTOTPSecret) Destroy() {
	if secret == nil {
		return
	}
	clear(secret.Ciphertext)
	clear(secret.Nonce)
	clear(secret.AAD)
	*secret = DirectSAMLProtectedTOTPSecret{}
}

type DirectSAMLTOTPVerificationSnapshot struct {
	ChallengeID                 mfa.ChallengeID
	ContinuationID              identity.EntityID
	ReceiptDigest               [sha256.Size]byte
	UserID                      identity.EntityID
	FactorID                    identity.EntityID
	Secret                      DirectSAMLProtectedTOTPSecret
	LastAcceptedCounter         *int64
	ExpectedContinuationVersion uint64
	FactorRevision              uint64
	UserAuthenticationRevision  uint64
	FailureCount                uint32
	State                       DirectSAMLTOTPChallengeState
	ExpiresAt                   time.Time
	Version                     uint64
}

func (snapshot DirectSAMLTOTPVerificationSnapshot) String() string {
	return fmt.Sprintf(
		"platformsamlauth.DirectSAMLTOTPVerificationSnapshot{challenge:%t,continuation:%t,user:%t,factor:%t,continuationVersion:%t,factorRevision:%t,userRevision:%t,failures:%d,state:%q,expires:%t,version:%t,secret:%q,authority:direct_platform_saml,material:[REDACTED]}",
		snapshot.ChallengeID != (mfa.ChallengeID{}), snapshot.ContinuationID != (identity.EntityID{}),
		snapshot.UserID != (identity.EntityID{}), snapshot.FactorID != (identity.EntityID{}),
		snapshot.ExpectedContinuationVersion != 0, snapshot.FactorRevision != 0,
		snapshot.UserAuthenticationRevision != 0, snapshot.FailureCount, snapshot.State,
		!snapshot.ExpiresAt.IsZero(), snapshot.Version != 0, snapshot.Secret.String(),
	)
}

func (snapshot DirectSAMLTOTPVerificationSnapshot) GoString() string { return snapshot.String() }

func (snapshot *DirectSAMLTOTPVerificationSnapshot) Destroy() {
	if snapshot == nil {
		return
	}
	snapshot.Secret.Destroy()
	if snapshot.LastAcceptedCounter != nil {
		*snapshot.LastAcceptedCounter = 0
	}
	*snapshot = DirectSAMLTOTPVerificationSnapshot{}
}

type DirectSAMLTOTPVerificationRequest struct {
	UserID                     identity.EntityID
	FactorID                   identity.EntityID
	FactorRevision             uint64
	UserAuthenticationRevision uint64
	Secret                     DirectSAMLProtectedTOTPSecret
	Code                       []byte `json:"-"`
	At                         time.Time
	LastAcceptedCounter        *int64
}

func (request DirectSAMLTOTPVerificationRequest) String() string {
	return "platformsamlauth.DirectSAMLTOTPVerificationRequest{authority:direct_platform_saml,proof:[REDACTED]}"
}

func (request DirectSAMLTOTPVerificationRequest) GoString() string { return request.String() }

func (request *DirectSAMLTOTPVerificationRequest) Destroy() {
	if request == nil {
		return
	}
	request.Secret.Destroy()
	clear(request.Code)
	if request.LastAcceptedCounter != nil {
		*request.LastAcceptedCounter = 0
	}
	*request = DirectSAMLTOTPVerificationRequest{}
}

type DirectSAMLTOTPProof struct {
	Counter int64
}

type DirectSAMLTOTPVerifier interface {
	// Invalid user proof returns ErrDirectSAMLTOTPInvalidProof. Keyring,
	// ciphertext, clock, and runtime failures return another error and must not
	// consume a user attempt.
	VerifyDirectSAMLTOTP(context.Context, DirectSAMLTOTPVerificationRequest) (DirectSAMLTOTPProof, error)
}

type DirectSAMLTOTPFailureRequest struct {
	ChallengeID                        mfa.ChallengeID
	ContinuationID                     identity.EntityID
	ReceiptDigest                      [sha256.Size]byte
	BrowserDigest                      DirectSAMLTOTPBrowserDigest
	ExpectedContinuationVersion        uint64
	ExpectedFactorRevision             uint64
	ExpectedUserAuthenticationRevision uint64
	ExpectedChallengeVersion           uint64
	ObservedAt                         time.Time
	Audit                              AuditContext
}

func (request DirectSAMLTOTPFailureRequest) String() string {
	return fmt.Sprintf(
		"platformsamlauth.DirectSAMLTOTPFailureRequest{challenge:%t,continuation:%t,continuationVersion:%t,factorRevision:%t,userRevision:%t,challengeVersion:%t,observed:%t,audit:%q,authority:direct_platform_saml,material:[REDACTED]}",
		request.ChallengeID != (mfa.ChallengeID{}), request.ContinuationID != (identity.EntityID{}),
		request.ExpectedContinuationVersion != 0, request.ExpectedFactorRevision != 0,
		request.ExpectedUserAuthenticationRevision != 0, request.ExpectedChallengeVersion != 0,
		!request.ObservedAt.IsZero(), request.Audit.String(),
	)
}

func (request DirectSAMLTOTPFailureRequest) GoString() string { return request.String() }

type DirectSAMLTOTPApplyRequest struct {
	ChallengeID                        mfa.ChallengeID
	ContinuationID                     identity.EntityID
	ReceiptDigest                      [sha256.Size]byte
	BrowserDigest                      DirectSAMLTOTPBrowserDigest
	ExpectedContinuationVersion        uint64
	ExpectedFactorRevision             uint64
	ExpectedUserAuthenticationRevision uint64
	ExpectedChallengeVersion           uint64
	AcceptedCounter                    int64
	CompletionRequestDigest            DirectSAMLTOTPCompletionDigest
	Session                            mfa.SessionReservation
	ObservedAt                         time.Time
	Audit                              AuditContext
}

func (request DirectSAMLTOTPApplyRequest) String() string {
	return fmt.Sprintf(
		"platformsamlauth.DirectSAMLTOTPApplyRequest{challenge:%t,continuation:%t,continuationVersion:%t,factorRevision:%t,userRevision:%t,challengeVersion:%t,counter:%t,session:%t,observed:%t,audit:%q,authority:direct_platform_saml,material:[REDACTED]}",
		request.ChallengeID != (mfa.ChallengeID{}), request.ContinuationID != (identity.EntityID{}),
		request.ExpectedContinuationVersion != 0, request.ExpectedFactorRevision != 0,
		request.ExpectedUserAuthenticationRevision != 0, request.ExpectedChallengeVersion != 0,
		request.AcceptedCounter >= 0, !request.Session.IsZero(), !request.ObservedAt.IsZero(),
		request.Audit.String(),
	)
}

func (request DirectSAMLTOTPApplyRequest) GoString() string { return request.String() }

type DirectSAMLTOTPApplyCategory string

const (
	DirectSAMLTOTPApplySuccess        DirectSAMLTOTPApplyCategory = "success"
	DirectSAMLTOTPApplyAlreadyApplied DirectSAMLTOTPApplyCategory = "already_applied"
	DirectSAMLTOTPApplyStale          DirectSAMLTOTPApplyCategory = "stale"
	DirectSAMLTOTPApplyReplay         DirectSAMLTOTPApplyCategory = "replay"
)

type DirectSAMLTOTPApplyResult struct {
	Category                   DirectSAMLTOTPApplyCategory
	SessionID                  identity.EntityID
	UserID                     identity.EntityID
	FactorID                   identity.EntityID
	FactorRevision             uint64
	UserAuthenticationRevision uint64
	AcceptedCounter            int64
	CompletedAt                time.Time
}

func (result DirectSAMLTOTPApplyResult) String() string {
	return fmt.Sprintf(
		"platformsamlauth.DirectSAMLTOTPApplyResult{category:%q,session:%t,user:%t,factor:%t,factorRevision:%t,userRevision:%t,counter:%t,completed:%t}",
		result.Category, result.SessionID != (identity.EntityID{}), result.UserID != (identity.EntityID{}),
		result.FactorID != (identity.EntityID{}), result.FactorRevision != 0,
		result.UserAuthenticationRevision != 0, result.AcceptedCounter >= 0, !result.CompletedAt.IsZero(),
	)
}

func (result DirectSAMLTOTPApplyResult) GoString() string { return result.String() }

type DirectSAMLTOTPApplyRecoveryLookup struct {
	Request DirectSAMLTOTPApplyRequest
}

func (lookup DirectSAMLTOTPApplyRecoveryLookup) String() string {
	return fmt.Sprintf("platformsamlauth.DirectSAMLTOTPApplyRecoveryLookup{request:%q}", lookup.Request.String())
}

func (lookup DirectSAMLTOTPApplyRecoveryLookup) GoString() string { return lookup.String() }

type DirectSAMLTOTPApplyRecoveryResult struct {
	Matched bool
	Result  DirectSAMLTOTPApplyResult
}

type DirectSAMLTOTPCleanupRequest struct {
	Request     DirectSAMLTOTPApplyRequest
	Result      DirectSAMLTOTPApplyResult
	Reason      CleanupReason
	CleanedUpAt time.Time
	Audit       AuditContext
}

func (request DirectSAMLTOTPCleanupRequest) String() string {
	return fmt.Sprintf(
		"platformsamlauth.DirectSAMLTOTPCleanupRequest{request:%q,result:%q,reason:%q,cleaned:%t,audit:%q,authority:direct_platform_saml,material:[REDACTED]}",
		request.Request.String(), request.Result.String(), request.Reason,
		!request.CleanedUpAt.IsZero(), request.Audit.String(),
	)
}

func (request DirectSAMLTOTPCleanupRequest) GoString() string { return request.String() }

type DirectSAMLTOTPAbandonReason string

const (
	DirectSAMLTOTPAbandonCancelled  DirectSAMLTOTPAbandonReason = "cancelled"
	DirectSAMLTOTPAbandonExpired    DirectSAMLTOTPAbandonReason = "expired"
	DirectSAMLTOTPAbandonSuperseded DirectSAMLTOTPAbandonReason = "superseded"
)

type DirectSAMLTOTPAbandonRequest struct {
	ChallengeID                        mfa.ChallengeID
	ContinuationID                     identity.EntityID
	ReceiptDigest                      [sha256.Size]byte
	BrowserDigest                      DirectSAMLTOTPBrowserDigest
	ExpectedContinuationVersion        uint64
	ExpectedFactorRevision             uint64
	ExpectedUserAuthenticationRevision uint64
	ExpectedChallengeVersion           uint64
	ObservedAt                         time.Time
	Reason                             DirectSAMLTOTPAbandonReason
	Audit                              AuditContext
}

func (request DirectSAMLTOTPAbandonRequest) String() string {
	return fmt.Sprintf(
		"platformsamlauth.DirectSAMLTOTPAbandonRequest{challenge:%t,continuation:%t,continuationVersion:%t,factorRevision:%t,userRevision:%t,challengeVersion:%t,observed:%t,reason:%q,audit:%q,authority:direct_platform_saml,material:[REDACTED]}",
		request.ChallengeID != (mfa.ChallengeID{}), request.ContinuationID != (identity.EntityID{}),
		request.ExpectedContinuationVersion != 0, request.ExpectedFactorRevision != 0,
		request.ExpectedUserAuthenticationRevision != 0, request.ExpectedChallengeVersion != 0,
		!request.ObservedAt.IsZero(), request.Reason, request.Audit.String(),
	)
}

func (request DirectSAMLTOTPAbandonRequest) GoString() string { return request.String() }

// DirectSAMLTOTPStore is intentionally physically separate from the direct
// OIDC continuation family. Every method executes only the implicit
// direct_platform_saml authority and exact SAML authentication method.
type DirectSAMLTOTPStore interface {
	BeginDirectSAMLTOTP(context.Context, DirectSAMLTOTPBeginRequest) (DirectSAMLTOTPChallenge, error)
	// Load transfers ownership of every returned secret slice, including on
	// error. It returns only a pending exact SAML continuation challenge.
	LoadDirectSAMLTOTP(context.Context, DirectSAMLTOTPLookup) (DirectSAMLTOTPVerificationSnapshot, error)
	// The fifth exact invalid proof terminalizes the challenge as failed.
	// Retrying one request is idempotent and must not increment twice.
	RecordDirectSAMLTOTPFailure(context.Context, DirectSAMLTOTPFailureRequest) (DirectSAMLTOTPChallenge, error)
	// Exact retries return AlreadyApplied with the original result.
	ApplyDirectSAMLTOTP(context.Context, DirectSAMLTOTPApplyRequest) (DirectSAMLTOTPApplyResult, error)
	// Recovery is read-only and matches the complete original Apply request.
	RecoverDirectSAMLTOTPApply(context.Context, DirectSAMLTOTPApplyRecoveryLookup) (DirectSAMLTOTPApplyRecoveryResult, error)
	AbandonDirectSAMLTOTP(context.Context, DirectSAMLTOTPAbandonRequest) (DirectSAMLTOTPChallenge, error)
	// Cleanup is idempotent: it revokes the exact session, terminalizes the
	// challenge as delivery_failed, and is also a safe no-op when Apply did not
	// commit after an ambiguous transport result.
	CleanupDirectSAMLTOTPApply(context.Context, DirectSAMLTOTPCleanupRequest) error
}

type DirectSAMLTOTPApplicationOptions struct {
	Store            DirectSAMLTOTPStore
	Verifier         DirectSAMLTOTPVerifier
	Credentials      CredentialIssuer
	Random           io.Reader
	Now              func() time.Time
	ChallengeTTL     time.Duration
	OperationTimeout time.Duration
	RecoveryTimeout  time.Duration
}

type DirectSAMLTOTPApplication struct {
	store            DirectSAMLTOTPStore
	verifier         DirectSAMLTOTPVerifier
	credentials      CredentialIssuer
	random           io.Reader
	now              func() time.Time
	challengeTTL     time.Duration
	operationTimeout time.Duration
	recoveryTimeout  time.Duration
}

func NewDirectSAMLTOTPApplication(options DirectSAMLTOTPApplicationOptions) (*DirectSAMLTOTPApplication, error) {
	if directSAMLTOTPDependencyIsNil(options.Store) || directSAMLTOTPDependencyIsNil(options.Verifier) ||
		directSAMLTOTPDependencyIsNil(options.Credentials) ||
		options.Random != nil && directSAMLTOTPDependencyIsNil(options.Random) ||
		options.ChallengeTTL < minimumDirectSAMLTOTPChallengeTTL ||
		options.ChallengeTTL > maximumDirectSAMLTOTPChallengeTTL ||
		options.ChallengeTTL%time.Microsecond != 0 ||
		options.OperationTimeout < minimumOperationTimeout ||
		options.OperationTimeout > maximumOperationTimeout ||
		options.OperationTimeout%time.Microsecond != 0 ||
		options.RecoveryTimeout < minimumRecoveryTimeout ||
		options.RecoveryTimeout > maximumRecoveryTimeout ||
		options.RecoveryTimeout%time.Microsecond != 0 {
		return nil, ErrInvalidOptions
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	if options.Now == nil {
		options.Now = func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }
	}
	return &DirectSAMLTOTPApplication{
		store: options.Store, verifier: options.Verifier, credentials: options.Credentials,
		random: options.Random, now: options.Now, challengeTTL: options.ChallengeTTL,
		operationTimeout: options.OperationTimeout, recoveryTimeout: options.RecoveryTimeout,
	}, nil
}

func (application *DirectSAMLTOTPApplication) String() string {
	return fmt.Sprintf(
		"platformsamlauth.DirectSAMLTOTPApplication{configured:%t,authority:direct_platform_saml}",
		application != nil && !directSAMLTOTPDependencyIsNil(application.store) &&
			!directSAMLTOTPDependencyIsNil(application.verifier) &&
			!directSAMLTOTPDependencyIsNil(application.credentials) &&
			!directSAMLTOTPDependencyIsNil(application.random) && application.now != nil,
	)
}

func (application *DirectSAMLTOTPApplication) GoString() string { return application.String() }

type StartDirectSAMLTOTPCommand struct {
	ContinuationID identity.EntityID
	ReceiptDigest  [sha256.Size]byte
	Audit          AuditContext
}

func (command StartDirectSAMLTOTPCommand) String() string {
	return fmt.Sprintf(
		"platformsamlauth.StartDirectSAMLTOTPCommand{continuation:%t,audit:%q,authority:direct_platform_saml,material:[REDACTED]}",
		command.ContinuationID != (identity.EntityID{}), command.Audit.String(),
	)
}

func (command StartDirectSAMLTOTPCommand) GoString() string { return command.String() }

type directSAMLTOTPBrowserHandle struct {
	guard    sync.Mutex
	value    []byte
	consumed bool
}

// DirectSAMLTOTPStartArtifact owns a single-use browser handle. Copies share
// the same ownership cell and cannot consume it twice.
type DirectSAMLTOTPStartArtifact struct {
	challengeID mfa.ChallengeID
	factorID    identity.EntityID
	expiresAt   time.Time
	browser     *directSAMLTOTPBrowserHandle
}

func (artifact DirectSAMLTOTPStartArtifact) ChallengeID() mfa.ChallengeID {
	return artifact.challengeID
}
func (artifact DirectSAMLTOTPStartArtifact) FactorID() identity.EntityID { return artifact.factorID }
func (artifact DirectSAMLTOTPStartArtifact) ExpiresAt() time.Time        { return artifact.expiresAt }

func (artifact DirectSAMLTOTPStartArtifact) ConsumeBrowserHandle() ([]byte, bool) {
	if artifact.browser == nil {
		return nil, false
	}
	artifact.browser.guard.Lock()
	defer artifact.browser.guard.Unlock()
	if artifact.browser.consumed || !canonicalBrowserHandle(artifact.browser.value) {
		artifact.browser.destroyLocked()
		return nil, false
	}
	value := artifact.browser.value
	artifact.browser.value = nil
	artifact.browser.consumed = true
	return value, true
}

func (artifact DirectSAMLTOTPStartArtifact) String() string {
	return "platformsamlauth.DirectSAMLTOTPStartArtifact{authority:direct_platform_saml,material:[REDACTED]}"
}

func (artifact DirectSAMLTOTPStartArtifact) GoString() string { return artifact.String() }

func (artifact *DirectSAMLTOTPStartArtifact) Destroy() {
	if artifact == nil {
		return
	}
	if artifact.browser != nil {
		artifact.browser.guard.Lock()
		artifact.browser.destroyLocked()
		artifact.browser.guard.Unlock()
	}
	*artifact = DirectSAMLTOTPStartArtifact{}
}

func (browser *directSAMLTOTPBrowserHandle) destroyLocked() {
	clear(browser.value)
	browser.value = nil
	browser.consumed = true
}

func (application *DirectSAMLTOTPApplication) Start(
	ctx context.Context,
	command StartDirectSAMLTOTPCommand,
) (DirectSAMLTOTPStartArtifact, error) {
	if application == nil || application.store == nil || application.random == nil ||
		!validUUIDv7(command.ContinuationID) || command.ReceiptDigest == ([sha256.Size]byte{}) ||
		!validAuditContext(command.Audit) {
		return DirectSAMLTOTPStartArtifact{}, ErrAuthenticationDenied
	}
	operation, cancel, now, ok := application.operation(ctx)
	if !ok {
		return DirectSAMLTOTPStartArtifact{}, ErrAuthenticationUnavailable
	}
	defer cancel()
	challengeID, browserHandle, browserDigest, ok := application.newChallengeMaterial()
	if !ok {
		return DirectSAMLTOTPStartArtifact{}, ErrAuthenticationUnavailable
	}
	defer clear(browserHandle)
	expiresAt := now.Add(application.challengeTTL).Truncate(time.Microsecond)
	request := DirectSAMLTOTPBeginRequest{
		ContinuationID: command.ContinuationID, ReceiptDigest: command.ReceiptDigest,
		ExpectedContinuationVersion: 1, ChallengeID: challengeID, BrowserDigest: browserDigest,
		CreatedAt: now, ExpiresAt: expiresAt, Audit: command.Audit,
	}
	var challenge DirectSAMLTOTPChallenge
	var err error
	for range 2 {
		challenge, err = application.store.BeginDirectSAMLTOTP(operation, request)
		if err == nil || operation.Err() != nil {
			break
		}
	}
	if err != nil || operation.Err() != nil {
		return DirectSAMLTOTPStartArtifact{}, ErrAuthenticationUnavailable
	}
	if !validDirectSAMLTOTPStartResult(challenge, request, now) {
		return DirectSAMLTOTPStartArtifact{}, ErrAuthenticationDenied
	}
	return DirectSAMLTOTPStartArtifact{
		challengeID: challengeID, factorID: challenge.FactorID, expiresAt: challenge.ExpiresAt,
		browser: &directSAMLTOTPBrowserHandle{value: append([]byte(nil), browserHandle...)},
	}, nil
}

type CompleteDirectSAMLTOTPCommand struct {
	ChallengeID    mfa.ChallengeID
	ContinuationID identity.EntityID
	ReceiptDigest  [sha256.Size]byte
	BrowserHandle  []byte `json:"-"`
	FactorID       identity.EntityID
	Code           []byte `json:"-"`
	Audit          AuditContext
}

func (command CompleteDirectSAMLTOTPCommand) String() string {
	return "platformsamlauth.CompleteDirectSAMLTOTPCommand{authority:direct_platform_saml,proof:[REDACTED]}"
}

func (command CompleteDirectSAMLTOTPCommand) GoString() string { return command.String() }

type DirectSAMLTOTPCompletionOutcome struct {
	SessionID  identity.EntityID
	UserID     identity.EntityID
	FactorID   identity.EntityID
	Counter    int64
	Credential *BrowserCredential
	Delivery   *DirectSAMLTOTPDeliveryFinalizer
}

func (outcome DirectSAMLTOTPCompletionOutcome) String() string {
	return fmt.Sprintf(
		"platformsamlauth.DirectSAMLTOTPCompletionOutcome{session:%t,user:%t,factor:%t,counter:%t,credential:%t,delivery:%t,authority:direct_platform_saml,material:[REDACTED]}",
		outcome.SessionID != (identity.EntityID{}), outcome.UserID != (identity.EntityID{}),
		outcome.FactorID != (identity.EntityID{}), outcome.Counter >= 0,
		outcome.Credential != nil, outcome.Delivery != nil,
	)
}

func (outcome DirectSAMLTOTPCompletionOutcome) GoString() string { return outcome.String() }

func (outcome *DirectSAMLTOTPCompletionOutcome) Destroy() {
	if outcome == nil {
		return
	}
	if outcome.Credential != nil {
		outcome.Credential.Destroy()
	}
	*outcome = DirectSAMLTOTPCompletionOutcome{}
}

func (application *DirectSAMLTOTPApplication) Complete(
	ctx context.Context,
	command CompleteDirectSAMLTOTPCommand,
) (DirectSAMLTOTPCompletionOutcome, error) {
	if application == nil || application.store == nil || application.verifier == nil ||
		application.credentials == nil || command.ChallengeID == (mfa.ChallengeID{}) ||
		!validDirectSAMLTOTPContinuation(command.ContinuationID, command.ReceiptDigest) ||
		!canonicalBrowserHandle(command.BrowserHandle) || !validUUIDv7(command.FactorID) ||
		!validDirectSAMLTOTPCode(command.Code) || !validAuditContext(command.Audit) {
		return DirectSAMLTOTPCompletionOutcome{}, ErrAuthenticationDenied
	}
	operation, cancel, now, ok := application.operation(ctx)
	if !ok {
		return DirectSAMLTOTPCompletionOutcome{}, ErrAuthenticationUnavailable
	}
	defer cancel()
	browserHandle := append([]byte(nil), command.BrowserHandle...)
	code := append([]byte(nil), command.Code...)
	defer clear(browserHandle)
	defer clear(code)
	browserDigest := DirectSAMLTOTPBrowserDigest(sha256.Sum256(browserHandle))
	lookup := DirectSAMLTOTPLookup{
		ChallengeID: command.ChallengeID, ContinuationID: command.ContinuationID,
		ReceiptDigest: command.ReceiptDigest, BrowserDigest: browserDigest, ObservedAt: now,
	}
	snapshot, err := application.load(operation, lookup)
	defer snapshot.Destroy()
	if err != nil || operation.Err() != nil {
		return DirectSAMLTOTPCompletionOutcome{}, ErrAuthenticationUnavailable
	}
	if !validDirectSAMLTOTPVerificationSnapshot(snapshot, lookup, command.FactorID, now) {
		return DirectSAMLTOTPCompletionOutcome{}, ErrAuthenticationDenied
	}
	verification := DirectSAMLTOTPVerificationRequest{
		UserID: snapshot.UserID, FactorID: snapshot.FactorID,
		FactorRevision:             snapshot.FactorRevision,
		UserAuthenticationRevision: snapshot.UserAuthenticationRevision,
		Secret:                     cloneDirectSAMLProtectedTOTPSecret(snapshot.Secret),
		Code:                       append([]byte(nil), code...), At: now,
		LastAcceptedCounter: cloneDirectSAMLCounter(snapshot.LastAcceptedCounter),
	}
	proof, verifyErr := application.verifier.VerifyDirectSAMLTOTP(operation, verification)
	verification.Destroy()
	if verifyErr != nil {
		if errors.Is(verifyErr, ErrDirectSAMLTOTPInvalidProof) {
			if application.recordFailure(ctx, snapshot, lookup, now, command.Audit) {
				return DirectSAMLTOTPCompletionOutcome{}, ErrAuthenticationDenied
			}
			return DirectSAMLTOTPCompletionOutcome{}, ErrAuthenticationUnavailable
		}
		return DirectSAMLTOTPCompletionOutcome{}, ErrAuthenticationUnavailable
	}
	if proof.Counter < 0 || snapshot.LastAcceptedCounter != nil && proof.Counter <= *snapshot.LastAcceptedCounter {
		return DirectSAMLTOTPCompletionOutcome{}, ErrAuthenticationUnavailable
	}
	credentialRequest := CredentialRequest{Disposition: ImmediateSession, IssuedAt: now}
	reservation, err := application.credentials.ReserveDirectSAMLCredential(credentialRequest)
	if err != nil || reservation == nil {
		if reservation != nil {
			reservation.Destroy()
		}
		return DirectSAMLTOTPCompletionOutcome{}, ErrAuthenticationUnavailable
	}
	session := reservation.Session()
	if !reservation.validFor(credentialRequest) || session.IsZero() || !reservation.Continuation().IsZero() ||
		session.AuthenticationMethod() != mfa.SessionAuthenticationSAML ||
		session.SessionID() == command.ContinuationID || session.SessionID() == snapshot.UserID ||
		session.SessionID() == snapshot.FactorID || session.FamilyID() == command.ContinuationID ||
		session.FamilyID() == snapshot.UserID || session.FamilyID() == snapshot.FactorID {
		reservation.Destroy()
		return DirectSAMLTOTPCompletionOutcome{}, ErrAuthenticationUnavailable
	}
	defer reservation.Destroy()
	completionDigest, ok := directSAMLTOTPCompletionRequestDigest(
		command.ChallengeID, command.ContinuationID, command.ReceiptDigest, browserDigest,
		snapshot.ExpectedContinuationVersion, snapshot.FactorRevision,
		snapshot.UserAuthenticationRevision, snapshot.Version, proof.Counter,
		session,
	)
	if !ok {
		return DirectSAMLTOTPCompletionOutcome{}, ErrAuthenticationUnavailable
	}
	apply := DirectSAMLTOTPApplyRequest{
		ChallengeID: command.ChallengeID, ContinuationID: command.ContinuationID,
		ReceiptDigest: command.ReceiptDigest, BrowserDigest: browserDigest,
		ExpectedContinuationVersion:        snapshot.ExpectedContinuationVersion,
		ExpectedFactorRevision:             snapshot.FactorRevision,
		ExpectedUserAuthenticationRevision: snapshot.UserAuthenticationRevision,
		ExpectedChallengeVersion:           snapshot.Version, AcceptedCounter: proof.Counter,
		CompletionRequestDigest: completionDigest, Session: session,
		ObservedAt: now, Audit: command.Audit,
	}
	result, category, certain := application.applyWithRecovery(operation, ctx, apply, snapshot)
	if category == DirectSAMLTOTPApplyStale || category == DirectSAMLTOTPApplyReplay {
		return DirectSAMLTOTPCompletionOutcome{}, ErrAuthenticationDenied
	}
	if !certain {
		result = directSAMLTOTPSyntheticApplyResult(apply, snapshot)
		return DirectSAMLTOTPCompletionOutcome{
			SessionID: result.SessionID, UserID: result.UserID, FactorID: result.FactorID,
			Counter: result.AcceptedCounter,
			Delivery: newDirectSAMLTOTPDeliveryFinalizer(
				application.store, application.now, application.recoveryTimeout, apply, result, command.Audit,
			),
		}, ErrAuthenticationUnavailable
	}
	finalizer := newDirectSAMLTOTPDeliveryFinalizer(
		application.store, application.now, application.recoveryTimeout, apply, result, command.Audit,
	)
	if finalizer == nil {
		return DirectSAMLTOTPCompletionOutcome{}, ErrAuthenticationUnavailable
	}
	credential, released := reservation.release(result.SessionID, identity.EntityID{})
	if !released || credential == nil {
		if credential != nil {
			credential.Destroy()
		}
		return DirectSAMLTOTPCompletionOutcome{
			SessionID: result.SessionID, UserID: result.UserID, FactorID: result.FactorID,
			Counter: result.AcceptedCounter, Delivery: finalizer,
		}, ErrAuthenticationUnavailable
	}
	return DirectSAMLTOTPCompletionOutcome{
		SessionID: result.SessionID, UserID: result.UserID, FactorID: result.FactorID,
		Counter: result.AcceptedCounter, Credential: credential, Delivery: finalizer,
	}, nil
}

type AbandonDirectSAMLTOTPCommand struct {
	ChallengeID    mfa.ChallengeID
	ContinuationID identity.EntityID
	ReceiptDigest  [sha256.Size]byte
	BrowserHandle  []byte `json:"-"`
	Reason         DirectSAMLTOTPAbandonReason
	Audit          AuditContext
}

func (command AbandonDirectSAMLTOTPCommand) String() string {
	return "platformsamlauth.AbandonDirectSAMLTOTPCommand{authority:direct_platform_saml,material:[REDACTED]}"
}

func (command AbandonDirectSAMLTOTPCommand) GoString() string { return command.String() }

func (application *DirectSAMLTOTPApplication) Abandon(ctx context.Context, command AbandonDirectSAMLTOTPCommand) error {
	if application == nil || application.store == nil || command.ChallengeID == (mfa.ChallengeID{}) ||
		!validDirectSAMLTOTPContinuation(command.ContinuationID, command.ReceiptDigest) ||
		!canonicalBrowserHandle(command.BrowserHandle) || !validDirectSAMLTOTPAbandonReason(command.Reason) ||
		!validAuditContext(command.Audit) {
		return ErrAuthenticationDenied
	}
	operation, cancel, now, ok := application.operation(ctx)
	if !ok {
		return ErrAuthenticationUnavailable
	}
	defer cancel()
	browserHandle := append([]byte(nil), command.BrowserHandle...)
	defer clear(browserHandle)
	lookup := DirectSAMLTOTPLookup{
		ChallengeID: command.ChallengeID, ContinuationID: command.ContinuationID,
		ReceiptDigest: command.ReceiptDigest,
		BrowserDigest: DirectSAMLTOTPBrowserDigest(sha256.Sum256(browserHandle)), ObservedAt: now,
	}
	snapshot, err := application.load(operation, lookup)
	defer snapshot.Destroy()
	if err != nil || operation.Err() != nil {
		return ErrAuthenticationUnavailable
	}
	if !validDirectSAMLTOTPVerificationSnapshot(snapshot, lookup, snapshot.FactorID, now) {
		return ErrAuthenticationDenied
	}
	request := DirectSAMLTOTPAbandonRequest{
		ChallengeID: command.ChallengeID, ContinuationID: command.ContinuationID,
		ReceiptDigest: command.ReceiptDigest, BrowserDigest: lookup.BrowserDigest,
		ExpectedContinuationVersion:        snapshot.ExpectedContinuationVersion,
		ExpectedFactorRevision:             snapshot.FactorRevision,
		ExpectedUserAuthenticationRevision: snapshot.UserAuthenticationRevision,
		ExpectedChallengeVersion:           snapshot.Version, ObservedAt: now,
		Reason: command.Reason, Audit: command.Audit,
	}
	var challenge DirectSAMLTOTPChallenge
	for range 2 {
		challenge, err = application.store.AbandonDirectSAMLTOTP(operation, request)
		if err == nil || operation.Err() != nil {
			break
		}
	}
	if err != nil || operation.Err() != nil {
		return ErrAuthenticationUnavailable
	}
	if !validDirectSAMLTOTPAbandonResult(challenge, snapshot, request) {
		return ErrAuthenticationDenied
	}
	return nil
}

func (application *DirectSAMLTOTPApplication) applyWithRecovery(
	operation context.Context,
	original context.Context,
	request DirectSAMLTOTPApplyRequest,
	snapshot DirectSAMLTOTPVerificationSnapshot,
) (DirectSAMLTOTPApplyResult, DirectSAMLTOTPApplyCategory, bool) {
	var result DirectSAMLTOTPApplyResult
	var err error
	ambiguous := false
	for range 2 {
		result, err = application.store.ApplyDirectSAMLTOTP(operation, request)
		if err != nil {
			ambiguous = true
			if operation.Err() != nil {
				break
			}
			continue
		}
		if validDirectSAMLTOTPApplyResult(result, request, snapshot) {
			return result, result.Category, true
		}
		if validDirectSAMLTOTPApplyFailureResult(result, request, snapshot) && !ambiguous {
			return result, result.Category, true
		}
		// An invalid projection, or a stale/replay response after an earlier
		// ambiguous write, cannot prove that no session committed. Switch to
		// the read-only exact recovery family.
		break
	}
	for range 2 {
		recovery, cancel := context.WithTimeout(detachedContext(original), application.recoveryTimeout)
		recovered, recoverErr := application.store.RecoverDirectSAMLTOTPApply(
			recovery, DirectSAMLTOTPApplyRecoveryLookup{Request: request},
		)
		cancel()
		if recoverErr == nil {
			if recovered.Matched && recovered.Result.Category == DirectSAMLTOTPApplyAlreadyApplied &&
				validDirectSAMLTOTPApplyResult(recovered.Result, request, snapshot) {
				return recovered.Result, recovered.Result.Category, true
			}
			return DirectSAMLTOTPApplyResult{}, "", false
		}
	}
	return DirectSAMLTOTPApplyResult{}, "", false
}

func (application *DirectSAMLTOTPApplication) recordFailure(
	ctx context.Context,
	snapshot DirectSAMLTOTPVerificationSnapshot,
	lookup DirectSAMLTOTPLookup,
	now time.Time,
	audit AuditContext,
) bool {
	request := directSAMLTOTPFailureRequest(snapshot, lookup, now, audit)
	for range 2 {
		operation, cancel := context.WithTimeout(detachedContext(ctx), application.recoveryTimeout)
		result, err := application.store.RecordDirectSAMLTOTPFailure(operation, request)
		cancel()
		if err == nil {
			return validDirectSAMLTOTPFailureResult(result, snapshot, request)
		}
	}
	// A write error can be ambiguous. A read-only load proves that the exact
	// challenge advanced, without risking a second failure increment for the
	// same browser proof. A terminal fifth failure may no longer be loadable;
	// the ABI therefore makes exact retry of RecordFailure idempotent above.
	operation, cancel := context.WithTimeout(detachedContext(ctx), application.recoveryTimeout)
	loaded, err := application.load(operation, lookup)
	cancel()
	defer loaded.Destroy()
	return err == nil && validDirectSAMLTOTPVerificationSnapshot(loaded, lookup, snapshot.FactorID, now) &&
		loaded.Version > snapshot.Version && loaded.FailureCount > snapshot.FailureCount
}

func directSAMLTOTPFailureRequest(
	snapshot DirectSAMLTOTPVerificationSnapshot,
	lookup DirectSAMLTOTPLookup,
	now time.Time,
	audit AuditContext,
) DirectSAMLTOTPFailureRequest {
	return DirectSAMLTOTPFailureRequest{
		ChallengeID: snapshot.ChallengeID, ContinuationID: snapshot.ContinuationID,
		ReceiptDigest: lookup.ReceiptDigest, BrowserDigest: lookup.BrowserDigest,
		ExpectedContinuationVersion:        snapshot.ExpectedContinuationVersion,
		ExpectedFactorRevision:             snapshot.FactorRevision,
		ExpectedUserAuthenticationRevision: snapshot.UserAuthenticationRevision,
		ExpectedChallengeVersion:           snapshot.Version, ObservedAt: now, Audit: audit,
	}
}

func (application *DirectSAMLTOTPApplication) load(
	ctx context.Context,
	lookup DirectSAMLTOTPLookup,
) (DirectSAMLTOTPVerificationSnapshot, error) {
	var lastErr error
	for range 2 {
		returned, err := application.store.LoadDirectSAMLTOTP(ctx, lookup)
		owned := cloneDirectSAMLTOTPVerificationSnapshot(returned)
		returned.Destroy()
		if err == nil {
			return owned, nil
		}
		owned.Destroy()
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	return DirectSAMLTOTPVerificationSnapshot{}, lastErr
}

func (application *DirectSAMLTOTPApplication) operation(
	ctx context.Context,
) (context.Context, context.CancelFunc, time.Time, bool) {
	if application == nil || ctx == nil || ctx.Err() != nil || application.now == nil ||
		application.operationTimeout <= 0 {
		return nil, nil, time.Time{}, false
	}
	now := application.now().UTC().Truncate(time.Microsecond)
	if !validInstant(now) {
		return nil, nil, time.Time{}, false
	}
	operation, cancel := context.WithTimeout(ctx, application.operationTimeout)
	return operation, cancel, now, true
}

func (application *DirectSAMLTOTPApplication) newChallengeMaterial() (
	mfa.ChallengeID,
	[]byte,
	DirectSAMLTOTPBrowserDigest,
	bool,
) {
	challengeRaw := make([]byte, directSAMLTOTPChallengeBytes)
	browserRaw := make([]byte, directSAMLTOTPChallengeBytes)
	defer clear(challengeRaw)
	defer clear(browserRaw)
	if _, err := io.ReadFull(application.random, challengeRaw); err != nil || allZeroDirectSAMLTOTPBytes(challengeRaw) {
		return mfa.ChallengeID{}, nil, DirectSAMLTOTPBrowserDigest{}, false
	}
	if _, err := io.ReadFull(application.random, browserRaw); err != nil || allZeroDirectSAMLTOTPBytes(browserRaw) {
		return mfa.ChallengeID{}, nil, DirectSAMLTOTPBrowserDigest{}, false
	}
	var challengeID mfa.ChallengeID
	copy(challengeID[:], challengeRaw)
	browserHandle := make([]byte, base64.RawURLEncoding.EncodedLen(len(browserRaw)))
	base64.RawURLEncoding.Encode(browserHandle, browserRaw)
	if !canonicalBrowserHandle(browserHandle) {
		clear(browserHandle)
		return mfa.ChallengeID{}, nil, DirectSAMLTOTPBrowserDigest{}, false
	}
	return challengeID, browserHandle, DirectSAMLTOTPBrowserDigest(sha256.Sum256(browserHandle)), true
}

func validDirectSAMLTOTPStartResult(
	challenge DirectSAMLTOTPChallenge,
	request DirectSAMLTOTPBeginRequest,
	now time.Time,
) bool {
	return challenge.ChallengeID == request.ChallengeID && challenge.ContinuationID == request.ContinuationID &&
		validUUIDv7(challenge.UserID) && validUUIDv7(challenge.FactorID) &&
		challenge.UserID != challenge.FactorID && challenge.ContinuationID != challenge.UserID &&
		challenge.ContinuationID != challenge.FactorID &&
		challenge.ExpectedContinuationVersion == request.ExpectedContinuationVersion &&
		validRevision(challenge.FactorRevision) && validRevision(challenge.UserAuthenticationRevision) &&
		challenge.FailureCount == 0 && challenge.State == DirectSAMLTOTPChallengePending &&
		challenge.Version == 1 && challenge.ExpiresAt.Equal(request.ExpiresAt) && challenge.ExpiresAt.After(now)
}

func validDirectSAMLTOTPVerificationSnapshot(
	snapshot DirectSAMLTOTPVerificationSnapshot,
	lookup DirectSAMLTOTPLookup,
	factorID identity.EntityID,
	now time.Time,
) bool {
	return snapshot.ChallengeID == lookup.ChallengeID && snapshot.ContinuationID == lookup.ContinuationID &&
		snapshot.ReceiptDigest == lookup.ReceiptDigest && validDirectSAMLTOTPContinuation(lookup.ContinuationID, lookup.ReceiptDigest) &&
		validUUIDv7(snapshot.UserID) && validUUIDv7(snapshot.FactorID) && snapshot.FactorID == factorID &&
		snapshot.UserID != snapshot.FactorID && snapshot.ContinuationID != snapshot.UserID &&
		snapshot.ContinuationID != snapshot.FactorID &&
		snapshot.ExpectedContinuationVersion == 1 && validRevision(snapshot.FactorRevision) &&
		validRevision(snapshot.UserAuthenticationRevision) &&
		snapshot.State == DirectSAMLTOTPChallengePending && snapshot.FailureCount < maximumDirectSAMLTOTPFailures &&
		snapshot.Version == uint64(snapshot.FailureCount)+1 &&
		validInstant(snapshot.ExpiresAt) && snapshot.ExpiresAt.After(now) &&
		(snapshot.LastAcceptedCounter == nil || *snapshot.LastAcceptedCounter >= 0) &&
		validDirectSAMLProtectedTOTPSecret(snapshot.Secret)
}

func validDirectSAMLProtectedTOTPSecret(secret DirectSAMLProtectedTOTPSecret) bool {
	return secret.KeyVersion > 0 && len(secret.Ciphertext) > 16 && len(secret.Ciphertext) <= 8*1024 &&
		len(secret.Nonce) >= 12 && len(secret.Nonce) <= 24 && len(secret.AAD) > 0 && len(secret.AAD) <= 1024 &&
		(secret.EncryptionAlgorithm == "aes-256-gcm" || secret.EncryptionAlgorithm == "xchacha20-poly1305") &&
		(secret.OTPAlgorithm == "SHA1" || secret.OTPAlgorithm == "SHA256" || secret.OTPAlgorithm == "SHA512") &&
		(secret.Digits == 6 || secret.Digits == 8) && secret.PeriodSeconds >= 15 && secret.PeriodSeconds <= 120
}

func validDirectSAMLTOTPApplyResult(
	result DirectSAMLTOTPApplyResult,
	request DirectSAMLTOTPApplyRequest,
	snapshot DirectSAMLTOTPVerificationSnapshot,
) bool {
	return (result.Category == DirectSAMLTOTPApplySuccess || result.Category == DirectSAMLTOTPApplyAlreadyApplied) &&
		validDirectSAMLTOTPExactApplyProjection(result, request, snapshot)
}

func validDirectSAMLTOTPApplyFailureResult(
	result DirectSAMLTOTPApplyResult,
	request DirectSAMLTOTPApplyRequest,
	snapshot DirectSAMLTOTPVerificationSnapshot,
) bool {
	return (result.Category == DirectSAMLTOTPApplyStale || result.Category == DirectSAMLTOTPApplyReplay) &&
		validDirectSAMLTOTPExactApplyProjection(result, request, snapshot)
}

func validDirectSAMLTOTPExactApplyProjection(
	result DirectSAMLTOTPApplyResult,
	request DirectSAMLTOTPApplyRequest,
	snapshot DirectSAMLTOTPVerificationSnapshot,
) bool {
	return result.SessionID == request.Session.SessionID() && validUUIDv7(result.SessionID) &&
		result.UserID == snapshot.UserID && result.FactorID == snapshot.FactorID &&
		result.FactorRevision == request.ExpectedFactorRevision &&
		result.UserAuthenticationRevision == request.ExpectedUserAuthenticationRevision &&
		result.AcceptedCounter == request.AcceptedCounter && result.CompletedAt.Equal(request.ObservedAt)
}

func validDirectSAMLTOTPFailureResult(
	result DirectSAMLTOTPChallenge,
	snapshot DirectSAMLTOTPVerificationSnapshot,
	request DirectSAMLTOTPFailureRequest,
) bool {
	wantFailures := snapshot.FailureCount + 1
	wantState := DirectSAMLTOTPChallengePending
	if wantFailures == maximumDirectSAMLTOTPFailures {
		wantState = DirectSAMLTOTPChallengeFailed
	}
	return result.ChallengeID == request.ChallengeID && result.ContinuationID == request.ContinuationID &&
		result.UserID == snapshot.UserID && result.FactorID == snapshot.FactorID &&
		result.ExpectedContinuationVersion == request.ExpectedContinuationVersion &&
		result.FactorRevision == request.ExpectedFactorRevision &&
		result.UserAuthenticationRevision == request.ExpectedUserAuthenticationRevision &&
		result.FailureCount == wantFailures && result.State == wantState &&
		result.Version == request.ExpectedChallengeVersion+1 && result.ExpiresAt.Equal(snapshot.ExpiresAt)
}

func validDirectSAMLTOTPAbandonResult(
	result DirectSAMLTOTPChallenge,
	snapshot DirectSAMLTOTPVerificationSnapshot,
	request DirectSAMLTOTPAbandonRequest,
) bool {
	wantState := DirectSAMLTOTPChallengeAbandoned
	if request.Reason == DirectSAMLTOTPAbandonExpired {
		wantState = DirectSAMLTOTPChallengeExpired
	}
	return result.ChallengeID == request.ChallengeID && result.ContinuationID == request.ContinuationID &&
		result.UserID == snapshot.UserID && result.FactorID == snapshot.FactorID &&
		result.ExpectedContinuationVersion == request.ExpectedContinuationVersion &&
		result.FactorRevision == request.ExpectedFactorRevision &&
		result.UserAuthenticationRevision == request.ExpectedUserAuthenticationRevision &&
		result.FailureCount == snapshot.FailureCount && result.State == wantState &&
		result.Version == request.ExpectedChallengeVersion+1 && result.ExpiresAt.Equal(snapshot.ExpiresAt)
}

func directSAMLTOTPSyntheticApplyResult(
	request DirectSAMLTOTPApplyRequest,
	snapshot DirectSAMLTOTPVerificationSnapshot,
) DirectSAMLTOTPApplyResult {
	return DirectSAMLTOTPApplyResult{
		Category: DirectSAMLTOTPApplySuccess, SessionID: request.Session.SessionID(),
		UserID: snapshot.UserID, FactorID: snapshot.FactorID,
		FactorRevision:             request.ExpectedFactorRevision,
		UserAuthenticationRevision: request.ExpectedUserAuthenticationRevision,
		AcceptedCounter:            request.AcceptedCounter, CompletedAt: request.ObservedAt,
	}
}

func directSAMLTOTPCompletionRequestDigest(
	challengeID mfa.ChallengeID,
	continuationID identity.EntityID,
	receiptDigest [sha256.Size]byte,
	browserDigest DirectSAMLTOTPBrowserDigest,
	continuationVersion uint64,
	factorRevision uint64,
	userAuthenticationRevision uint64,
	challengeVersion uint64,
	acceptedCounter int64,
	session mfa.SessionReservation,
) (DirectSAMLTOTPCompletionDigest, bool) {
	if challengeID == (mfa.ChallengeID{}) || !validDirectSAMLTOTPContinuation(continuationID, receiptDigest) ||
		browserDigest == (DirectSAMLTOTPBrowserDigest{}) || !validRevision(continuationVersion) ||
		!validRevision(factorRevision) || !validRevision(userAuthenticationRevision) ||
		!validRevision(challengeVersion) || acceptedCounter < 0 || session.IsZero() ||
		session.AuthenticationMethod() != mfa.SessionAuthenticationSAML {
		return DirectSAMLTOTPCompletionDigest{}, false
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte(directSAMLTOTPCompletionDigestDomain))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write(challengeID[:])
	_, _ = digest.Write(continuationID[:])
	_, _ = digest.Write(receiptDigest[:])
	_, _ = digest.Write(browserDigest[:])
	var number [8]byte
	for _, value := range []uint64{continuationVersion, factorRevision, userAuthenticationRevision, challengeVersion, uint64(acceptedCounter)} {
		binary.BigEndian.PutUint64(number[:], value)
		_, _ = digest.Write(number[:])
	}
	sessionID, familyID := session.SessionID(), session.FamilyID()
	_, _ = digest.Write(sessionID[:])
	_, _ = digest.Write(familyID[:])
	tokenDigest, csrfDigest := session.TokenDigest(), session.CSRFDigest()
	_, _ = digest.Write(tokenDigest[:])
	_, _ = digest.Write(csrfDigest[:])
	binary.BigEndian.PutUint64(number[:], uint64(session.IdleExpiresAt().UnixMicro()))
	_, _ = digest.Write(number[:])
	binary.BigEndian.PutUint64(number[:], uint64(session.AbsoluteExpiresAt().UnixMicro()))
	_, _ = digest.Write(number[:])
	var result DirectSAMLTOTPCompletionDigest
	copy(result[:], digest.Sum(nil))
	return result, result != (DirectSAMLTOTPCompletionDigest{})
}

func validDirectSAMLTOTPContinuation(continuationID identity.EntityID, receiptDigest [sha256.Size]byte) bool {
	return validUUIDv7(continuationID) && receiptDigest != ([sha256.Size]byte{})
}

func validDirectSAMLTOTPCode(value []byte) bool {
	if len(value) != 6 && len(value) != 8 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func validDirectSAMLTOTPAbandonReason(value DirectSAMLTOTPAbandonReason) bool {
	return value == DirectSAMLTOTPAbandonCancelled || value == DirectSAMLTOTPAbandonExpired ||
		value == DirectSAMLTOTPAbandonSuperseded
}

func cloneDirectSAMLProtectedTOTPSecret(value DirectSAMLProtectedTOTPSecret) DirectSAMLProtectedTOTPSecret {
	value.Ciphertext = append([]byte(nil), value.Ciphertext...)
	value.Nonce = append([]byte(nil), value.Nonce...)
	value.AAD = append([]byte(nil), value.AAD...)
	return value
}

func cloneDirectSAMLTOTPVerificationSnapshot(value DirectSAMLTOTPVerificationSnapshot) DirectSAMLTOTPVerificationSnapshot {
	value.Secret = cloneDirectSAMLProtectedTOTPSecret(value.Secret)
	value.LastAcceptedCounter = cloneDirectSAMLCounter(value.LastAcceptedCounter)
	return value
}

func cloneDirectSAMLCounter(value *int64) *int64 {
	if value == nil {
		return nil
	}
	copyValue := *value
	return &copyValue
}

func allZeroDirectSAMLTOTPBytes(value []byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}

func directSAMLTOTPDependencyIsNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
