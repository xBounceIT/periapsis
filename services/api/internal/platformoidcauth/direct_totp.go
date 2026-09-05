package platformoidcauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
)

const (
	directTOTPChallengeBytes      = sha256.Size
	minimumDirectTOTPChallengeTTL = time.Minute
	maximumDirectTOTPChallengeTTL = 10 * time.Minute
	maximumDirectTOTPFailures     = 5

	directTOTPCompletionDigestDomain = "periapsis/platform-oidc/direct-totp-completion/v1"
)

var ErrDirectTOTPInvalidProof = errors.New("invalid direct platform OIDC TOTP proof")

type DirectTOTPChallengeID [directTOTPChallengeBytes]byte
type DirectTOTPBrowserDigest [sha256.Size]byte
type DirectTOTPCompletionDigest [sha256.Size]byte

type DirectTOTPChallengeState string

const (
	DirectTOTPChallengePending   DirectTOTPChallengeState = "pending"
	DirectTOTPChallengeFailed    DirectTOTPChallengeState = "failed"
	DirectTOTPChallengeCompleted DirectTOTPChallengeState = "completed"
	DirectTOTPChallengeAbandoned DirectTOTPChallengeState = "abandoned"
	DirectTOTPChallengeExpired   DirectTOTPChallengeState = "expired"
)

// DirectTOTPChallenge is the non-secret state returned by direct TOTP writes.
// Browser possession is always checked separately through BrowserDigest.
type DirectTOTPChallenge struct {
	ChallengeID                DirectTOTPChallengeID
	ContinuationID             identity.EntityID
	UserID                     identity.EntityID
	FactorID                   identity.EntityID
	UserAuthenticationRevision uint64
	TOTPSecurityRevision       uint64
	FailureCount               uint32
	State                      DirectTOTPChallengeState
	Version                    uint64
	ExpiresAt                  time.Time
}

func (challenge DirectTOTPChallenge) String() string {
	return fmt.Sprintf(
		"platformoidcauth.DirectTOTPChallenge{challenge:%t,continuation:%t,user:%t,factor:%t,userAuthenticationRevision:%t,totpSecurityRevision:%t,failures:%d,state:%q,version:%t,expires:%t}",
		challenge.ChallengeID != (DirectTOTPChallengeID{}),
		challenge.ContinuationID != (identity.EntityID{}), challenge.UserID != (identity.EntityID{}),
		challenge.FactorID != (identity.EntityID{}), challenge.UserAuthenticationRevision != 0,
		challenge.TOTPSecurityRevision != 0, challenge.FailureCount, challenge.State,
		challenge.Version != 0, !challenge.ExpiresAt.IsZero(),
	)
}

func (challenge DirectTOTPChallenge) GoString() string { return challenge.String() }

type DirectTOTPBeginRequest struct {
	ContinuationID              identity.EntityID
	ReceiptDigest               [sha256.Size]byte
	ExpectedContinuationVersion uint64
	ChallengeID                 DirectTOTPChallengeID
	BrowserDigest               DirectTOTPBrowserDigest
	CreatedAt                   time.Time
	ExpiresAt                   time.Time
	Audit                       DirectAuditContext
}

func (request DirectTOTPBeginRequest) String() string {
	return fmt.Sprintf(
		"platformoidcauth.DirectTOTPBeginRequest{continuation:%t,expectedVersion:%t,challenge:%t,created:%t,expires:%t,audit:%q,material:[REDACTED]}",
		request.ContinuationID != (identity.EntityID{}), request.ExpectedContinuationVersion != 0,
		request.ChallengeID != (DirectTOTPChallengeID{}), !request.CreatedAt.IsZero(),
		!request.ExpiresAt.IsZero(), request.Audit.String(),
	)
}

func (request DirectTOTPBeginRequest) GoString() string { return request.String() }

type DirectTOTPLookup struct {
	ChallengeID    DirectTOTPChallengeID
	ContinuationID identity.EntityID
	Authority      federatedauth.ContinuationAuthority
	ReceiptDigest  [sha256.Size]byte
	BrowserDigest  DirectTOTPBrowserDigest
	ObservedAt     time.Time
}

func (lookup DirectTOTPLookup) String() string {
	return fmt.Sprintf(
		"platformoidcauth.DirectTOTPLookup{challenge:%t,continuation:%t,direct:%t,observed:%t,material:[REDACTED]}",
		lookup.ChallengeID != (DirectTOTPChallengeID{}), lookup.ContinuationID != (identity.EntityID{}),
		lookup.Authority == federatedauth.ContinuationAuthorityDirectPlatformOIDC, !lookup.ObservedAt.IsZero(),
	)
}

func (lookup DirectTOTPLookup) GoString() string { return lookup.String() }

// DirectProtectedTOTPSecret is an adapter-owned encrypted factor projection.
// The application never receives plaintext and clears every copied envelope.
type DirectProtectedTOTPSecret struct {
	Ciphertext          []byte `json:"-"`
	Nonce               []byte `json:"-"`
	AAD                 []byte `json:"-"`
	KeyVersion          int16
	EncryptionAlgorithm string
	OTPAlgorithm        string
	Digits              uint8
	PeriodSeconds       uint16
}

func (secret DirectProtectedTOTPSecret) String() string {
	return fmt.Sprintf(
		"platformoidcauth.DirectProtectedTOTPSecret{keyVersion:%t,encryption:%q,otp:%q,digits:%d,period:%d,material:[REDACTED]}",
		secret.KeyVersion > 0, secret.EncryptionAlgorithm, secret.OTPAlgorithm,
		secret.Digits, secret.PeriodSeconds,
	)
}

func (secret DirectProtectedTOTPSecret) GoString() string { return secret.String() }

func (secret *DirectProtectedTOTPSecret) Destroy() {
	if secret == nil {
		return
	}
	clear(secret.Ciphertext)
	clear(secret.Nonce)
	clear(secret.AAD)
	*secret = DirectProtectedTOTPSecret{}
}

type DirectTOTPVerificationSnapshot struct {
	ChallengeID                DirectTOTPChallengeID
	ContinuationID             identity.EntityID
	Authority                  federatedauth.ContinuationAuthority
	ReceiptDigest              [sha256.Size]byte
	UserID                     identity.EntityID
	FactorID                   identity.EntityID
	Secret                     DirectProtectedTOTPSecret
	LastAcceptedCounter        *int64
	UserAuthenticationRevision uint64
	TOTPSecurityRevision       uint64
	ExpiresAt                  time.Time
	Version                    uint64
}

func (snapshot DirectTOTPVerificationSnapshot) String() string {
	return fmt.Sprintf(
		"platformoidcauth.DirectTOTPVerificationSnapshot{challenge:%t,continuation:%t,direct:%t,user:%t,factor:%t,userAuthenticationRevision:%t,totpSecurityRevision:%t,counter:%t,expires:%t,version:%t,secret:%q,material:[REDACTED]}",
		snapshot.ChallengeID != (DirectTOTPChallengeID{}),
		snapshot.ContinuationID != (identity.EntityID{}),
		snapshot.Authority == federatedauth.ContinuationAuthorityDirectPlatformOIDC,
		snapshot.UserID != (identity.EntityID{}),
		snapshot.FactorID != (identity.EntityID{}), snapshot.UserAuthenticationRevision != 0,
		snapshot.TOTPSecurityRevision != 0, snapshot.LastAcceptedCounter != nil,
		!snapshot.ExpiresAt.IsZero(), snapshot.Version != 0, snapshot.Secret.String(),
	)
}

func (snapshot DirectTOTPVerificationSnapshot) GoString() string { return snapshot.String() }

func (snapshot *DirectTOTPVerificationSnapshot) Destroy() {
	if snapshot == nil {
		return
	}
	snapshot.Secret.Destroy()
	if snapshot.LastAcceptedCounter != nil {
		*snapshot.LastAcceptedCounter = 0
	}
	*snapshot = DirectTOTPVerificationSnapshot{}
}

type DirectTOTPVerificationRequest struct {
	UserID              identity.EntityID
	FactorID            identity.EntityID
	FactorRevision      uint64
	Secret              DirectProtectedTOTPSecret
	Code                []byte `json:"-"`
	At                  time.Time
	LastAcceptedCounter *int64
}

func (request DirectTOTPVerificationRequest) String() string {
	return "platformoidcauth.DirectTOTPVerificationRequest{proof:[REDACTED]}"
}

func (request DirectTOTPVerificationRequest) GoString() string { return request.String() }

type DirectTOTPProof struct {
	Counter int64
}

type DirectTOTPVerifier interface {
	// Invalid user proof returns ErrDirectTOTPInvalidProof. Cryptographic or
	// keyring availability failures return another error and do not consume a
	// user attempt.
	VerifyDirectTOTP(context.Context, DirectTOTPVerificationRequest) (DirectTOTPProof, error)
}

type DirectTOTPFailureRequest struct {
	ChallengeID     DirectTOTPChallengeID
	ContinuationID  identity.EntityID
	Authority       federatedauth.ContinuationAuthority
	ReceiptDigest   [sha256.Size]byte
	BrowserDigest   DirectTOTPBrowserDigest
	ExpectedVersion uint64
	ObservedAt      time.Time
	Audit           DirectAuditContext
}

func (request DirectTOTPFailureRequest) String() string {
	return fmt.Sprintf(
		"platformoidcauth.DirectTOTPFailureRequest{challenge:%t,continuation:%t,direct:%t,expectedVersion:%t,observed:%t,audit:%q,material:[REDACTED]}",
		request.ChallengeID != (DirectTOTPChallengeID{}), request.ContinuationID != (identity.EntityID{}),
		request.Authority == federatedauth.ContinuationAuthorityDirectPlatformOIDC, request.ExpectedVersion != 0,
		!request.ObservedAt.IsZero(), request.Audit.String(),
	)
}

func (request DirectTOTPFailureRequest) GoString() string { return request.String() }

type DirectTOTPApplyRequest struct {
	ChallengeID             DirectTOTPChallengeID
	ContinuationID          identity.EntityID
	Authority               federatedauth.ContinuationAuthority
	ReceiptDigest           [sha256.Size]byte
	BrowserDigest           DirectTOTPBrowserDigest
	ExpectedVersion         uint64
	AcceptedCounter         int64
	CompletionRequestDigest DirectTOTPCompletionDigest
	Session                 mfa.SessionReservation
	ObservedAt              time.Time
	Audit                   DirectAuditContext
}

func (request DirectTOTPApplyRequest) String() string {
	return fmt.Sprintf(
		"platformoidcauth.DirectTOTPApplyRequest{challenge:%t,continuation:%t,direct:%t,expectedVersion:%t,counter:%t,session:%t,observed:%t,audit:%q,material:[REDACTED]}",
		request.ChallengeID != (DirectTOTPChallengeID{}), request.ContinuationID != (identity.EntityID{}),
		request.Authority == federatedauth.ContinuationAuthorityDirectPlatformOIDC, request.ExpectedVersion != 0,
		request.AcceptedCounter >= 0, !request.Session.IsZero(), !request.ObservedAt.IsZero(),
		request.Audit.String(),
	)
}

func (request DirectTOTPApplyRequest) GoString() string { return request.String() }

type DirectTOTPApplyCategory string

const (
	DirectTOTPApplySuccess DirectTOTPApplyCategory = "success"
	DirectTOTPApplyStale   DirectTOTPApplyCategory = "stale"
	DirectTOTPApplyReplay  DirectTOTPApplyCategory = "replay"
)

type DirectTOTPApplyResult struct {
	Category             DirectTOTPApplyCategory
	SessionID            identity.EntityID
	UserID               identity.EntityID
	FactorID             identity.EntityID
	TOTPSecurityRevision uint64
	AcceptedCounter      int64
}

func (result DirectTOTPApplyResult) String() string {
	return fmt.Sprintf(
		"platformoidcauth.DirectTOTPApplyResult{category:%q,session:%t,user:%t,factor:%t,totpSecurityRevision:%t,counter:%t}",
		result.Category, result.SessionID != (identity.EntityID{}), result.UserID != (identity.EntityID{}),
		result.FactorID != (identity.EntityID{}), result.TOTPSecurityRevision != 0,
		result.AcceptedCounter >= 0,
	)
}

func (result DirectTOTPApplyResult) GoString() string { return result.String() }

type DirectTOTPAbandonReason string

const (
	DirectTOTPAbandonCancelled  DirectTOTPAbandonReason = "cancelled"
	DirectTOTPAbandonExpired    DirectTOTPAbandonReason = "expired"
	DirectTOTPAbandonSuperseded DirectTOTPAbandonReason = "superseded"
)

type DirectTOTPAbandonRequest struct {
	ChallengeID     DirectTOTPChallengeID
	ContinuationID  identity.EntityID
	Authority       federatedauth.ContinuationAuthority
	ReceiptDigest   [sha256.Size]byte
	BrowserDigest   DirectTOTPBrowserDigest
	ExpectedVersion uint64
	ObservedAt      time.Time
	Reason          DirectTOTPAbandonReason
	Audit           DirectAuditContext
}

func (request DirectTOTPAbandonRequest) String() string {
	return fmt.Sprintf(
		"platformoidcauth.DirectTOTPAbandonRequest{challenge:%t,continuation:%t,direct:%t,expectedVersion:%t,observed:%t,reason:%q,audit:%q,material:[REDACTED]}",
		request.ChallengeID != (DirectTOTPChallengeID{}), request.ContinuationID != (identity.EntityID{}),
		request.Authority == federatedauth.ContinuationAuthorityDirectPlatformOIDC, request.ExpectedVersion != 0,
		!request.ObservedAt.IsZero(), request.Reason, request.Audit.String(),
	)
}

func (request DirectTOTPAbandonRequest) GoString() string { return request.String() }

type DirectTOTPStore interface {
	BeginDirectTOTP(context.Context, DirectTOTPBeginRequest) (DirectTOTPChallenge, error)
	// LoadDirectTOTP transfers ownership of every returned secret slice to the
	// caller, including on error. The application copies and clears it before
	// crossing the verifier boundary.
	LoadDirectTOTP(context.Context, DirectTOTPLookup) (DirectTOTPVerificationSnapshot, error)
	RecordDirectTOTPFailure(context.Context, DirectTOTPFailureRequest) (DirectTOTPChallenge, error)
	ApplyDirectTOTP(context.Context, DirectTOTPApplyRequest) (DirectTOTPApplyResult, error)
	AbandonDirectTOTP(context.Context, DirectTOTPAbandonRequest) (DirectTOTPChallenge, error)
}

type DirectTOTPApplicationOptions struct {
	Store            DirectTOTPStore
	Verifier         DirectTOTPVerifier
	Credentials      federatedauth.ApplyCredentialIssuer
	Random           io.Reader
	Now              func() time.Time
	ChallengeTTL     time.Duration
	OperationTimeout time.Duration
}

type DirectTOTPApplication struct {
	store            DirectTOTPStore
	verifier         DirectTOTPVerifier
	credentials      federatedauth.ApplyCredentialIssuer
	random           io.Reader
	now              func() time.Time
	challengeTTL     time.Duration
	operationTimeout time.Duration
}

func NewDirectTOTPApplication(options DirectTOTPApplicationOptions) (*DirectTOTPApplication, error) {
	if options.Store == nil || options.Verifier == nil || options.Credentials == nil ||
		options.ChallengeTTL < minimumDirectTOTPChallengeTTL ||
		options.ChallengeTTL > maximumDirectTOTPChallengeTTL ||
		options.ChallengeTTL%time.Microsecond != 0 ||
		options.OperationTimeout < minimumDirectOIDCOperationTimeout ||
		options.OperationTimeout > maximumDirectOIDCOperationTimeout ||
		options.OperationTimeout%time.Microsecond != 0 {
		return nil, ErrDirectAuthenticationDenied
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	if options.Now == nil {
		options.Now = func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }
	}
	return &DirectTOTPApplication{
		store: options.Store, verifier: options.Verifier, credentials: options.Credentials,
		random: options.Random, now: options.Now, challengeTTL: options.ChallengeTTL,
		operationTimeout: options.OperationTimeout,
	}, nil
}

func (application *DirectTOTPApplication) String() string {
	return fmt.Sprintf(
		"platformoidcauth.DirectTOTPApplication{configured:%t}",
		application != nil && application.store != nil && application.verifier != nil &&
			application.credentials != nil && application.random != nil && application.now != nil,
	)
}

func (application *DirectTOTPApplication) GoString() string { return application.String() }

type StartDirectTOTPCommand struct {
	ContinuationID identity.EntityID
	Authority      federatedauth.ContinuationAuthority
	ReceiptDigest  [sha256.Size]byte
	Audit          DirectAuditContext
}

func (command StartDirectTOTPCommand) String() string {
	return fmt.Sprintf(
		"platformoidcauth.StartDirectTOTPCommand{continuation:%t,direct:%t,audit:%q,material:[REDACTED]}",
		command.ContinuationID != (identity.EntityID{}),
		command.Authority == federatedauth.ContinuationAuthorityDirectPlatformOIDC,
		command.Audit.String(),
	)
}

func (command StartDirectTOTPCommand) GoString() string { return command.String() }

// DirectTOTPStartArtifact owns the one-use MFA browser handle until HTTP has
// constructed its strict cookie.
type DirectTOTPStartArtifact struct {
	challengeID   DirectTOTPChallengeID
	browserHandle []byte
	factorID      identity.EntityID
	expiresAt     time.Time
}

func (artifact DirectTOTPStartArtifact) ChallengeID() DirectTOTPChallengeID {
	return artifact.challengeID
}
func (artifact DirectTOTPStartArtifact) BrowserHandle() []byte {
	return append([]byte(nil), artifact.browserHandle...)
}
func (artifact DirectTOTPStartArtifact) FactorID() identity.EntityID { return artifact.factorID }
func (artifact DirectTOTPStartArtifact) ExpiresAt() time.Time        { return artifact.expiresAt }
func (artifact DirectTOTPStartArtifact) String() string {
	return "platformoidcauth.DirectTOTPStartArtifact{material:[REDACTED]}"
}
func (artifact DirectTOTPStartArtifact) GoString() string { return artifact.String() }

func (artifact *DirectTOTPStartArtifact) Destroy() {
	if artifact == nil {
		return
	}
	clear(artifact.browserHandle)
	*artifact = DirectTOTPStartArtifact{}
}

func (application *DirectTOTPApplication) Start(
	ctx context.Context,
	command StartDirectTOTPCommand,
) (DirectTOTPStartArtifact, error) {
	if application == nil || application.store == nil || application.random == nil ||
		command.Authority != federatedauth.ContinuationAuthorityDirectPlatformOIDC ||
		!validDirectEntityID(command.ContinuationID) || command.ReceiptDigest == ([sha256.Size]byte{}) ||
		!validDirectAuditContext(command.Audit) {
		return DirectTOTPStartArtifact{}, ErrDirectAuthenticationDenied
	}
	operation, cancel, now, ok := application.operation(ctx)
	if !ok {
		return DirectTOTPStartArtifact{}, ErrDirectAuthenticationDenied
	}
	defer cancel()
	challengeID, browserHandle, browserDigest, ok := application.newChallengeMaterial()
	if !ok {
		return DirectTOTPStartArtifact{}, ErrDirectAuthenticationDenied
	}
	defer clear(browserHandle)
	expiresAt := now.Add(application.challengeTTL).Truncate(time.Microsecond)
	request := DirectTOTPBeginRequest{
		ContinuationID: command.ContinuationID, ReceiptDigest: command.ReceiptDigest,
		ExpectedContinuationVersion: 1, ChallengeID: challengeID, BrowserDigest: browserDigest,
		CreatedAt: now, ExpiresAt: expiresAt, Audit: command.Audit,
	}
	var challenge DirectTOTPChallenge
	var err error
	for range 2 {
		challenge, err = application.store.BeginDirectTOTP(operation, request)
		if err == nil || operation.Err() != nil {
			break
		}
	}
	if err != nil || operation.Err() != nil ||
		!validDirectTOTPStartResult(challenge, request, now) {
		return DirectTOTPStartArtifact{}, ErrDirectAuthenticationDenied
	}
	return DirectTOTPStartArtifact{
		challengeID: challengeID, browserHandle: append([]byte(nil), browserHandle...),
		factorID: challenge.FactorID, expiresAt: challenge.ExpiresAt,
	}, nil
}

type CompleteDirectTOTPCommand struct {
	ChallengeID    DirectTOTPChallengeID
	ContinuationID identity.EntityID
	Authority      federatedauth.ContinuationAuthority
	ReceiptDigest  [sha256.Size]byte
	BrowserHandle  []byte `json:"-"`
	FactorID       identity.EntityID
	Code           []byte `json:"-"`
	Audit          DirectAuditContext
}

func (command CompleteDirectTOTPCommand) String() string {
	return "platformoidcauth.CompleteDirectTOTPCommand{proof:[REDACTED]}"
}

func (command CompleteDirectTOTPCommand) GoString() string { return command.String() }

type DirectTOTPCompletionOutcome struct {
	SessionID  identity.EntityID
	UserID     identity.EntityID
	FactorID   identity.EntityID
	Counter    int64
	Credential *federatedauth.BrowserCredential
}

func (outcome DirectTOTPCompletionOutcome) String() string {
	return fmt.Sprintf(
		"platformoidcauth.DirectTOTPCompletionOutcome{session:%t,user:%t,factor:%t,counter:%t,credential:%t,material:[REDACTED]}",
		outcome.SessionID != (identity.EntityID{}), outcome.UserID != (identity.EntityID{}),
		outcome.FactorID != (identity.EntityID{}), outcome.Counter >= 0, outcome.Credential != nil,
	)
}

func (outcome DirectTOTPCompletionOutcome) GoString() string { return outcome.String() }

func (outcome *DirectTOTPCompletionOutcome) Destroy() {
	if outcome == nil {
		return
	}
	if outcome.Credential != nil {
		outcome.Credential.Destroy()
	}
	*outcome = DirectTOTPCompletionOutcome{}
}

func (application *DirectTOTPApplication) Complete(
	ctx context.Context,
	command CompleteDirectTOTPCommand,
) (DirectTOTPCompletionOutcome, error) {
	if application == nil || application.store == nil || application.verifier == nil ||
		application.credentials == nil || !validDirectTOTPChallengeID(command.ChallengeID) ||
		!validDirectTOTPContinuationAuthority(command.Authority, command.ContinuationID, command.ReceiptDigest) ||
		!validDirectTOTPBrowserHandle(command.BrowserHandle) || !validDirectEntityID(command.FactorID) ||
		!validDirectTOTPCode(command.Code) || !validDirectAuditContext(command.Audit) {
		return DirectTOTPCompletionOutcome{}, ErrDirectAuthenticationDenied
	}
	operation, cancel, now, ok := application.operation(ctx)
	if !ok {
		return DirectTOTPCompletionOutcome{}, ErrDirectAuthenticationDenied
	}
	defer cancel()
	browserHandle := append([]byte(nil), command.BrowserHandle...)
	code := append([]byte(nil), command.Code...)
	defer clear(browserHandle)
	defer clear(code)
	browserDigest := DirectTOTPBrowserDigest(sha256.Sum256(browserHandle))
	lookup := DirectTOTPLookup{
		ChallengeID: command.ChallengeID, ContinuationID: command.ContinuationID,
		Authority: command.Authority, ReceiptDigest: command.ReceiptDigest,
		BrowserDigest: browserDigest, ObservedAt: now,
	}
	snapshot, err := application.load(operation, lookup)
	defer snapshot.Destroy()
	if err != nil || operation.Err() != nil ||
		!validDirectTOTPVerificationSnapshot(snapshot, lookup, command.FactorID, now) {
		return DirectTOTPCompletionOutcome{}, ErrDirectAuthenticationDenied
	}
	verification := DirectTOTPVerificationRequest{
		UserID: snapshot.UserID, FactorID: snapshot.FactorID,
		FactorRevision: snapshot.TOTPSecurityRevision,
		Secret:         cloneDirectProtectedTOTPSecret(snapshot.Secret), Code: append([]byte(nil), code...),
		At: now, LastAcceptedCounter: cloneDirectCounter(snapshot.LastAcceptedCounter),
	}
	proof, verifyErr := application.verifier.VerifyDirectTOTP(operation, verification)
	verification.Secret.Destroy()
	clear(verification.Code)
	if verification.LastAcceptedCounter != nil {
		*verification.LastAcceptedCounter = 0
	}
	if verifyErr != nil {
		if errors.Is(verifyErr, ErrDirectTOTPInvalidProof) {
			application.recordFailure(ctx, snapshot, lookup, now, command.Audit)
		}
		return DirectTOTPCompletionOutcome{}, ErrDirectAuthenticationDenied
	}
	if proof.Counter < 0 || snapshot.LastAcceptedCounter != nil && proof.Counter <= *snapshot.LastAcceptedCounter {
		return DirectTOTPCompletionOutcome{}, ErrDirectAuthenticationDenied
	}
	credentialRequest := federatedauth.ApplyCredentialRequest{
		Disposition: federatedauth.ApplySession, Method: federatedauth.AuthenticationMethodOIDC,
		IssuedAt: now,
	}
	reservation, err := application.credentials.ReserveApplyCredential(credentialRequest)
	if err != nil || reservation == nil || reservation.Session().IsZero() ||
		!reservation.Continuation().IsZero() ||
		!reservation.Session().ValidAt(now.Truncate(time.Millisecond)) ||
		reservation.Session().AuthenticationMethod() != mfa.SessionAuthenticationOIDC {
		if reservation != nil {
			reservation.Destroy()
		}
		return DirectTOTPCompletionOutcome{}, ErrDirectAuthenticationDenied
	}
	defer reservation.Destroy()
	completionDigest, ok := directTOTPCompletionRequestDigest(
		command.ChallengeID, command.ContinuationID, command.Authority, command.ReceiptDigest,
		browserDigest, snapshot.Version, proof.Counter, reservation.Session(),
	)
	if !ok {
		return DirectTOTPCompletionOutcome{}, ErrDirectAuthenticationDenied
	}
	apply := DirectTOTPApplyRequest{
		ChallengeID: command.ChallengeID, ContinuationID: command.ContinuationID,
		Authority: command.Authority, ReceiptDigest: command.ReceiptDigest, BrowserDigest: browserDigest,
		ExpectedVersion: snapshot.Version, AcceptedCounter: proof.Counter,
		CompletionRequestDigest: completionDigest, Session: reservation.Session(),
		ObservedAt: now, Audit: command.Audit,
	}
	var result DirectTOTPApplyResult
	for range 2 {
		result, err = application.store.ApplyDirectTOTP(operation, apply)
		if err == nil || operation.Err() != nil {
			break
		}
	}
	if err != nil || operation.Err() != nil ||
		!validDirectTOTPApplyResult(result, apply, snapshot) {
		return DirectTOTPCompletionOutcome{}, ErrDirectAuthenticationDenied
	}
	credential, released := reservation.ReleaseBrowserCredential(result.SessionID, identity.EntityID{})
	if !released || credential == nil {
		return DirectTOTPCompletionOutcome{}, ErrDirectAuthenticationDenied
	}
	return DirectTOTPCompletionOutcome{
		SessionID: result.SessionID, UserID: result.UserID, FactorID: result.FactorID,
		Counter: result.AcceptedCounter, Credential: credential,
	}, nil
}

type AbandonDirectTOTPCommand struct {
	ChallengeID    DirectTOTPChallengeID
	ContinuationID identity.EntityID
	Authority      federatedauth.ContinuationAuthority
	ReceiptDigest  [sha256.Size]byte
	BrowserHandle  []byte `json:"-"`
	Reason         DirectTOTPAbandonReason
	Audit          DirectAuditContext
}

func (command AbandonDirectTOTPCommand) String() string {
	return "platformoidcauth.AbandonDirectTOTPCommand{material:[REDACTED]}"
}

func (command AbandonDirectTOTPCommand) GoString() string { return command.String() }

func (application *DirectTOTPApplication) Abandon(
	ctx context.Context,
	command AbandonDirectTOTPCommand,
) error {
	if application == nil || application.store == nil || !validDirectTOTPChallengeID(command.ChallengeID) ||
		!validDirectTOTPContinuationAuthority(command.Authority, command.ContinuationID, command.ReceiptDigest) ||
		!validDirectTOTPBrowserHandle(command.BrowserHandle) || !validDirectTOTPAbandonReason(command.Reason) ||
		!validDirectAuditContext(command.Audit) {
		return ErrDirectAuthenticationDenied
	}
	operation, cancel, now, ok := application.operation(ctx)
	if !ok {
		return ErrDirectAuthenticationDenied
	}
	defer cancel()
	browserHandle := append([]byte(nil), command.BrowserHandle...)
	defer clear(browserHandle)
	browserDigest := DirectTOTPBrowserDigest(sha256.Sum256(browserHandle))
	lookup := DirectTOTPLookup{
		ChallengeID: command.ChallengeID, ContinuationID: command.ContinuationID,
		Authority: command.Authority, ReceiptDigest: command.ReceiptDigest,
		BrowserDigest: browserDigest, ObservedAt: now,
	}
	snapshot, err := application.load(operation, lookup)
	defer snapshot.Destroy()
	if err != nil || operation.Err() != nil ||
		!validDirectTOTPVerificationSnapshot(snapshot, lookup, snapshot.FactorID, now) {
		return ErrDirectAuthenticationDenied
	}
	request := DirectTOTPAbandonRequest{
		ChallengeID: command.ChallengeID, ContinuationID: command.ContinuationID,
		Authority: command.Authority, ReceiptDigest: command.ReceiptDigest, BrowserDigest: browserDigest,
		ExpectedVersion: snapshot.Version, ObservedAt: now, Reason: command.Reason, Audit: command.Audit,
	}
	var challenge DirectTOTPChallenge
	for range 2 {
		challenge, err = application.store.AbandonDirectTOTP(operation, request)
		if err == nil || operation.Err() != nil {
			break
		}
	}
	if err != nil || operation.Err() != nil ||
		!validDirectTOTPAbandonResult(challenge, snapshot, request) {
		return ErrDirectAuthenticationDenied
	}
	return nil
}

func (application *DirectTOTPApplication) recordFailure(
	ctx context.Context,
	snapshot DirectTOTPVerificationSnapshot,
	lookup DirectTOTPLookup,
	now time.Time,
	audit DirectAuditContext,
) {
	if ctx == nil {
		return
	}
	operation, cancel := context.WithTimeout(context.WithoutCancel(ctx), application.operationTimeout)
	defer cancel()
	request := DirectTOTPFailureRequest{
		ChallengeID: snapshot.ChallengeID, ContinuationID: lookup.ContinuationID,
		Authority: lookup.Authority, ReceiptDigest: lookup.ReceiptDigest,
		BrowserDigest:   lookup.BrowserDigest,
		ExpectedVersion: snapshot.Version, ObservedAt: now, Audit: audit,
	}
	for range 2 {
		result, err := application.store.RecordDirectTOTPFailure(operation, request)
		if err == nil {
			if validDirectTOTPFailureResult(result, snapshot, request) {
				return
			}
			return
		}
		if operation.Err() != nil {
			return
		}
	}
}

func (application *DirectTOTPApplication) load(
	ctx context.Context,
	lookup DirectTOTPLookup,
) (DirectTOTPVerificationSnapshot, error) {
	var lastErr error
	for range 2 {
		returned, err := application.store.LoadDirectTOTP(ctx, lookup)
		owned := cloneDirectTOTPVerificationSnapshot(returned)
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
	return DirectTOTPVerificationSnapshot{}, lastErr
}

func (application *DirectTOTPApplication) operation(
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

func (application *DirectTOTPApplication) newChallengeMaterial() (
	DirectTOTPChallengeID,
	[]byte,
	DirectTOTPBrowserDigest,
	bool,
) {
	challengeRaw := make([]byte, directTOTPChallengeBytes)
	browserRaw := make([]byte, directTOTPChallengeBytes)
	defer clear(challengeRaw)
	defer clear(browserRaw)
	if _, err := io.ReadFull(application.random, challengeRaw); err != nil || allZeroDirectTOTPBytes(challengeRaw) {
		return DirectTOTPChallengeID{}, nil, DirectTOTPBrowserDigest{}, false
	}
	if _, err := io.ReadFull(application.random, browserRaw); err != nil || allZeroDirectTOTPBytes(browserRaw) {
		return DirectTOTPChallengeID{}, nil, DirectTOTPBrowserDigest{}, false
	}
	var challengeID DirectTOTPChallengeID
	copy(challengeID[:], challengeRaw)
	browserHandle := make([]byte, base64.RawURLEncoding.EncodedLen(len(browserRaw)))
	base64.RawURLEncoding.Encode(browserHandle, browserRaw)
	if !validDirectTOTPBrowserHandle(browserHandle) {
		clear(browserHandle)
		return DirectTOTPChallengeID{}, nil, DirectTOTPBrowserDigest{}, false
	}
	return challengeID, browserHandle, DirectTOTPBrowserDigest(sha256.Sum256(browserHandle)), true
}

func validDirectTOTPStartResult(
	challenge DirectTOTPChallenge,
	request DirectTOTPBeginRequest,
	now time.Time,
) bool {
	return challenge.ChallengeID == request.ChallengeID && challenge.ContinuationID == request.ContinuationID &&
		validDirectEntityID(challenge.UserID) && validDirectEntityID(challenge.FactorID) &&
		challenge.UserID != challenge.FactorID && validDirectRevision(challenge.UserAuthenticationRevision) &&
		validDirectRevision(challenge.TOTPSecurityRevision) && challenge.FailureCount == 0 &&
		challenge.State == DirectTOTPChallengePending && challenge.Version == 1 &&
		challenge.ExpiresAt.Equal(request.ExpiresAt) && challenge.ExpiresAt.After(now)
}

func validDirectTOTPVerificationSnapshot(
	snapshot DirectTOTPVerificationSnapshot,
	lookup DirectTOTPLookup,
	factorID identity.EntityID,
	now time.Time,
) bool {
	if snapshot.ChallengeID != lookup.ChallengeID || snapshot.ContinuationID != lookup.ContinuationID ||
		snapshot.Authority != lookup.Authority || snapshot.ReceiptDigest != lookup.ReceiptDigest ||
		!validDirectTOTPContinuationAuthority(lookup.Authority, lookup.ContinuationID, lookup.ReceiptDigest) ||
		!validDirectEntityID(snapshot.UserID) || !validDirectEntityID(snapshot.FactorID) ||
		snapshot.FactorID != factorID || snapshot.UserID == snapshot.FactorID ||
		!validDirectRevision(snapshot.UserAuthenticationRevision) ||
		!validDirectRevision(snapshot.TOTPSecurityRevision) || snapshot.Version < 1 ||
		snapshot.Version > maximumDirectTOTPFailures ||
		!validInstant(snapshot.ExpiresAt) || !snapshot.ExpiresAt.After(now) ||
		snapshot.LastAcceptedCounter != nil && *snapshot.LastAcceptedCounter < 0 ||
		!validDirectProtectedTOTPSecret(snapshot.Secret) {
		return false
	}
	return true
}

func validDirectProtectedTOTPSecret(secret DirectProtectedTOTPSecret) bool {
	return secret.KeyVersion > 0 && len(secret.Ciphertext) > 16 && len(secret.Ciphertext) <= 8*1024 &&
		len(secret.Nonce) >= 12 && len(secret.Nonce) <= 24 && len(secret.AAD) > 0 && len(secret.AAD) <= 1024 &&
		(secret.EncryptionAlgorithm == "aes-256-gcm" ||
			secret.EncryptionAlgorithm == "xchacha20-poly1305") &&
		(secret.OTPAlgorithm == "SHA1" || secret.OTPAlgorithm == "SHA256" ||
			secret.OTPAlgorithm == "SHA512") &&
		(secret.Digits == 6 || secret.Digits == 8) &&
		secret.PeriodSeconds >= 15 && secret.PeriodSeconds <= 120
}

func validDirectTOTPApplyResult(
	result DirectTOTPApplyResult,
	request DirectTOTPApplyRequest,
	snapshot DirectTOTPVerificationSnapshot,
) bool {
	return result.Category == DirectTOTPApplySuccess && request.ContinuationID == snapshot.ContinuationID &&
		validDirectTOTPContinuationAuthority(request.Authority, request.ContinuationID, request.ReceiptDigest) &&
		result.SessionID == request.Session.SessionID() &&
		validDirectEntityID(result.SessionID) && result.UserID == snapshot.UserID &&
		result.FactorID == snapshot.FactorID && result.TOTPSecurityRevision == snapshot.TOTPSecurityRevision &&
		result.AcceptedCounter == request.AcceptedCounter
}

func validDirectTOTPFailureResult(
	result DirectTOTPChallenge,
	snapshot DirectTOTPVerificationSnapshot,
	request DirectTOTPFailureRequest,
) bool {
	wantFailures := uint32(1)
	if snapshot.Version > 0 {
		// Failure count is not included in the secret-bearing load projection;
		// version 1 is the zero-failure state and each failure increments both.
		wantFailures = uint32(snapshot.Version)
	}
	wantState := DirectTOTPChallengePending
	if wantFailures >= maximumDirectTOTPFailures {
		wantState = DirectTOTPChallengeFailed
	}
	return validDirectTOTPContinuationAuthority(request.Authority, request.ContinuationID, request.ReceiptDigest) &&
		result.ChallengeID == request.ChallengeID && request.ContinuationID == snapshot.ContinuationID &&
		result.ContinuationID == snapshot.ContinuationID &&
		result.UserID == snapshot.UserID && result.FactorID == snapshot.FactorID &&
		result.UserAuthenticationRevision == snapshot.UserAuthenticationRevision &&
		result.TOTPSecurityRevision == snapshot.TOTPSecurityRevision && result.FailureCount == wantFailures &&
		result.State == wantState && result.Version == snapshot.Version+1 &&
		result.ExpiresAt.Equal(snapshot.ExpiresAt)
}

func validDirectTOTPAbandonResult(
	result DirectTOTPChallenge,
	snapshot DirectTOTPVerificationSnapshot,
	request DirectTOTPAbandonRequest,
) bool {
	wantState := DirectTOTPChallengeAbandoned
	if request.Reason == DirectTOTPAbandonExpired {
		wantState = DirectTOTPChallengeExpired
	}
	return validDirectTOTPContinuationAuthority(request.Authority, request.ContinuationID, request.ReceiptDigest) &&
		result.ChallengeID == request.ChallengeID && request.ContinuationID == snapshot.ContinuationID &&
		result.ContinuationID == snapshot.ContinuationID &&
		result.UserID == snapshot.UserID && result.FactorID == snapshot.FactorID &&
		result.UserAuthenticationRevision == snapshot.UserAuthenticationRevision &&
		result.TOTPSecurityRevision == snapshot.TOTPSecurityRevision &&
		result.FailureCount == uint32(snapshot.Version-1) &&
		result.State == wantState && result.Version == snapshot.Version+1 &&
		result.ExpiresAt.Equal(snapshot.ExpiresAt)
}

func directTOTPCompletionRequestDigest(
	challengeID DirectTOTPChallengeID,
	continuationID identity.EntityID,
	authority federatedauth.ContinuationAuthority,
	receiptDigest [sha256.Size]byte,
	browserDigest DirectTOTPBrowserDigest,
	expectedVersion uint64,
	acceptedCounter int64,
	session mfa.SessionReservation,
) (DirectTOTPCompletionDigest, bool) {
	if !validDirectTOTPChallengeID(challengeID) ||
		!validDirectTOTPContinuationAuthority(authority, continuationID, receiptDigest) ||
		browserDigest == (DirectTOTPBrowserDigest{}) ||
		!validDirectRevision(expectedVersion) || acceptedCounter < 0 || session.IsZero() {
		return DirectTOTPCompletionDigest{}, false
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte(directTOTPCompletionDigestDomain))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write(challengeID[:])
	_, _ = digest.Write(continuationID[:])
	_, _ = digest.Write([]byte(authority))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write(receiptDigest[:])
	_, _ = digest.Write(browserDigest[:])
	var number [8]byte
	binary.BigEndian.PutUint64(number[:], expectedVersion)
	_, _ = digest.Write(number[:])
	binary.BigEndian.PutUint64(number[:], uint64(acceptedCounter))
	_, _ = digest.Write(number[:])
	sessionID := session.SessionID()
	familyID := session.FamilyID()
	_, _ = digest.Write(sessionID[:])
	_, _ = digest.Write(familyID[:])
	tokenDigest := session.TokenDigest()
	csrfDigest := session.CSRFDigest()
	_, _ = digest.Write(tokenDigest[:])
	_, _ = digest.Write(csrfDigest[:])
	binary.BigEndian.PutUint64(number[:], uint64(session.IdleExpiresAt().UnixMicro()))
	_, _ = digest.Write(number[:])
	binary.BigEndian.PutUint64(number[:], uint64(session.AbsoluteExpiresAt().UnixMicro()))
	_, _ = digest.Write(number[:])
	var result DirectTOTPCompletionDigest
	copy(result[:], digest.Sum(nil))
	return result, result != (DirectTOTPCompletionDigest{})
}

func validDirectTOTPContinuationAuthority(
	authority federatedauth.ContinuationAuthority,
	continuationID identity.EntityID,
	receiptDigest [sha256.Size]byte,
) bool {
	return authority == federatedauth.ContinuationAuthorityDirectPlatformOIDC &&
		validDirectEntityID(continuationID) && receiptDigest != ([sha256.Size]byte{})
}

func validDirectTOTPChallengeID(value DirectTOTPChallengeID) bool {
	return value != (DirectTOTPChallengeID{})
}

func validDirectTOTPBrowserHandle(value []byte) bool {
	if len(value) != base64.RawURLEncoding.EncodedLen(directTOTPChallengeBytes) {
		return false
	}
	decoded := make([]byte, directTOTPChallengeBytes)
	count, err := base64.RawURLEncoding.Strict().Decode(decoded, value)
	valid := err == nil && count == len(decoded) && !allZeroDirectTOTPBytes(decoded) &&
		base64.RawURLEncoding.EncodeToString(decoded) == string(value)
	clear(decoded)
	return valid
}

func validDirectTOTPCode(value []byte) bool {
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

func validDirectTOTPAbandonReason(value DirectTOTPAbandonReason) bool {
	return value == DirectTOTPAbandonCancelled || value == DirectTOTPAbandonExpired ||
		value == DirectTOTPAbandonSuperseded
}

func cloneDirectProtectedTOTPSecret(value DirectProtectedTOTPSecret) DirectProtectedTOTPSecret {
	value.Ciphertext = append([]byte(nil), value.Ciphertext...)
	value.Nonce = append([]byte(nil), value.Nonce...)
	value.AAD = append([]byte(nil), value.AAD...)
	return value
}

func cloneDirectTOTPVerificationSnapshot(
	value DirectTOTPVerificationSnapshot,
) DirectTOTPVerificationSnapshot {
	value.Secret = cloneDirectProtectedTOTPSecret(value.Secret)
	value.LastAcceptedCounter = cloneDirectCounter(value.LastAcceptedCounter)
	return value
}

func cloneDirectCounter(value *int64) *int64 {
	if value == nil {
		return nil
	}
	copyValue := *value
	return &copyValue
}

func allZeroDirectTOTPBytes(value []byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}
