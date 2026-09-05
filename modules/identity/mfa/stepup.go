package mfa

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"slices"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

const (
	stepUpEntropyBytes          = 32
	minimumStepUpTTL            = time.Minute
	maximumStepUpTTL            = 15 * time.Minute
	minimumStepUpTimeout        = 100 * time.Millisecond
	maximumStepUpTimeout        = time.Minute
	maximumProtectedSecretBytes = 16 * 1024
	maximumTOTPCodeBytes        = 8
	minimumRecoveryCodeBytes    = 16
	maximumRecoveryCodeBytes    = 128
	maximumStoredVersion        = uint64(9_007_199_254_740_991)
	maximumMFAKeyVersion        = uint32(32_767)
)

type ChallengeID [stepUpEntropyBytes]byte

type StepUpFlow uint8

const (
	FlowPostPrimaryContinuation StepUpFlow = iota + 1
	FlowExistingSession
)

type FactorKind uint8

const (
	FactorTOTP FactorKind = iota + 1
	FactorRecoveryCode
)

type ChallengeState uint8

const (
	ChallengePending ChallengeState = iota + 1
	ChallengeClaimed
	ChallengeCompleted
	ChallengeFailed
	ChallengeExpired
)

type ChallengeFailureReason string

const (
	ChallengeFailureExpired ChallengeFailureReason = "expired"
	ChallengeFailureFactor  ChallengeFailureReason = "factor_rejected"
)

// StepUpBinding pins either a post-primary continuation or an exact live
// rotation family. BaselineEvidence is appended once; completion emits only
// the new factor evidence and therefore cannot duplicate the primary proof.
type StepUpBinding struct {
	Flow            StepUpFlow
	TenantID        identity.EntityID
	UserID          identity.EntityID
	IdentityEpoch   uint64
	SessionID       identity.EntityID
	SessionFamilyID identity.EntityID
	ContinuationID  identity.EntityID
	AnchorVersion   uint64
	AnchorExpiresAt time.Time
	// AnchorRecoveryRestricted pins whether the source session is limited to
	// the recovery/repair path. A successful non-recovery factor clears it.
	AnchorRecoveryRestricted bool
	Action                   string
	Audience                 string
	Requirement              identity.EffectiveAssuranceRequirement
	BaselineEvidence         []identity.AssuranceEvidence
}

func (binding StepUpBinding) String() string {
	return fmt.Sprintf("mfa.StepUpBinding{flow:%d,evidence:%d,provenance:[REDACTED]}",
		binding.Flow, len(binding.BaselineEvidence))
}
func (binding StepUpBinding) GoString() string { return binding.String() }

type PendingChallenge struct {
	ID             ChallengeID
	BrowserDigest  [sha256.Size]byte
	Binding        StepUpBinding
	AllowedFactors []FactorKind
	CreatedAt      time.Time
	ExpiresAt      time.Time
	State          ChallengeState
	Version        uint64
}

func (p PendingChallenge) String() string {
	return fmt.Sprintf("mfa.PendingChallenge{flow:%d,state:%d,factors:%d,version:%d,artifacts:[REDACTED]}",
		p.Binding.Flow, p.State, len(p.AllowedFactors), p.Version)
}
func (p PendingChallenge) GoString() string { return p.String() }

func (p ClaimedChallenge) String() string   { return p.PendingChallenge.String() }
func (p ClaimedChallenge) GoString() string { return p.String() }

type ChallengeClaim struct {
	ID                        ChallengeID
	BrowserDigest             [sha256.Size]byte
	Factor                    FactorKind
	ClaimedAt                 time.Time
	ContinuationReceiptDigest [sha256.Size]byte `json:"-"`
}

func (claim ChallengeClaim) String() string   { return "mfa.ChallengeClaim{proof:[REDACTED]}" }
func (claim ChallengeClaim) GoString() string { return claim.String() }

type ClaimedChallenge struct {
	PendingChallenge
	ClaimedAt     time.Time
	ClaimedFactor FactorKind
}

type ChallengeFailure struct {
	ID              ChallengeID
	ExpectedVersion uint64
	FailedAt        time.Time
	State           ChallengeState
	Reason          ChallengeFailureReason
}

type ChallengeRepository interface {
	Create(context.Context, PendingChallenge) error
	Claim(context.Context, ChallengeClaim) (ClaimedChallenge, error)
	// Fail terminalizes the claimed challenge and couples the attempt/lockout
	// update plus a redacted failure audit to the same transaction.
	Fail(context.Context, ChallengeFailure) error
}

type FactorStatus uint8

const (
	FactorActive FactorStatus = iota + 1
	FactorRevoked
)

// ProtectedTOTPSecret is opaque ciphertext. The kernel never decrypts it.
type ProtectedTOTPSecret struct {
	KeyVersion uint32
	Ciphertext []byte
}

func (s ProtectedTOTPSecret) String() string   { return "mfa.ProtectedTOTPSecret{ciphertext:[REDACTED]}" }
func (s ProtectedTOTPSecret) GoString() string { return s.String() }

type TOTPFactor struct {
	ID               identity.EntityID
	TenantID         identity.EntityID
	UserID           identity.EntityID
	RecordVersion    uint64
	SecurityRevision int64
	Status           FactorStatus
	LastCounter      int64
	Secret           ProtectedTOTPSecret
}

func (f TOTPFactor) String() string {
	return fmt.Sprintf("mfa.TOTPFactor{recordVersion:%d,securityRevision:%d,status:%d,secret:[REDACTED]}",
		f.RecordVersion, f.SecurityRevision, f.Status)
}
func (f TOTPFactor) GoString() string { return f.String() }

type RecoverySet struct {
	ID               identity.EntityID
	TenantID         identity.EntityID
	UserID           identity.EntityID
	RecordVersion    uint64
	SecurityRevision int64
	Status           FactorStatus
	DigestKeyVersion uint32
}

type FactorRepository interface {
	LoadTOTP(context.Context, identity.EntityID, identity.EntityID, identity.EntityID) (TOTPFactor, error)
	LoadRecoverySet(context.Context, identity.EntityID, identity.EntityID) (RecoverySet, error)
}

type TOTPVerificationRequest struct {
	TenantID identity.EntityID
	UserID   identity.EntityID
	FactorID identity.EntityID
	Secret   ProtectedTOTPSecret
	Code     []byte
	At       time.Time
}

func (r TOTPVerificationRequest) String() string {
	return "mfa.TOTPVerificationRequest{proof:[REDACTED]}"
}
func (r TOTPVerificationRequest) GoString() string { return r.String() }

type TOTPProof struct {
	Counter int64
}

type TOTPVerifier interface {
	VerifyTOTP(context.Context, TOTPVerificationRequest) (TOTPProof, error)
}

type RecoveryDigestRequest struct {
	SetID      identity.EntityID
	TenantID   identity.EntityID
	UserID     identity.EntityID
	KeyVersion uint32
	Code       []byte
}

func (r RecoveryDigestRequest) String() string   { return "mfa.RecoveryDigestRequest{code:[REDACTED]}" }
func (r RecoveryDigestRequest) GoString() string { return r.String() }

type RecoveryDigester interface {
	DigestRecoveryCode(context.Context, RecoveryDigestRequest) ([sha256.Size]byte, error)
}

// FactorCompletionResult proves that factor replay protection, challenge
// completion, assurance append, and session rotation/continuation transition
// committed atomically in the application adapter.
type FactorCompletionResult struct {
	TenantID               identity.EntityID
	UserID                 identity.EntityID
	IdentityEpoch          uint64
	FactorSecurityRevision int64
	AuditID                identity.EntityID
	NewSessionID           identity.EntityID
	NewSessionFamilyID     identity.EntityID
	ConsumedContinuationID identity.EntityID
	SessionVersion         uint64
	RecoveryRestricted     bool
}

func (result FactorCompletionResult) String() string {
	return fmt.Sprintf("mfa.FactorCompletionResult{sessionVersion:%d,recoveryRestricted:%t,subject:[REDACTED]}",
		result.SessionVersion, result.RecoveryRestricted)
}
func (result FactorCompletionResult) GoString() string { return result.String() }

type StepUpAuditKind string

const (
	AuditTOTPStepUpCompleted StepUpAuditKind = "mfa.totp_step_up_completed"
	AuditRecoveryCodeUsed    StepUpAuditKind = "mfa.recovery_code_used"
)

type SessionMutation uint8

const (
	StepUpSessionRotate SessionMutation = iota + 1
	StepUpSessionCreateFromContinuation
)

// CompletionIntent is a closed transaction plan. The FactorConsumer must
// apply the exact session transition and audit intent in the same commit as
// challenge/factor replay protection.
type CompletionIntent struct {
	Session            SessionMutation
	Audit              StepUpAuditKind
	RecoveryRestricted bool
}

type TOTPCompletion struct {
	ChallengeID               ChallengeID
	ExpectedChallengeVersion  uint64
	Binding                   StepUpBinding
	FactorID                  identity.EntityID
	ExpectedFactorVersion     uint64
	ExpectedSecurityRevision  int64
	Counter                   int64
	CompletedAt               time.Time
	Intent                    CompletionIntent
	Session                   SessionReservation
	ContinuationReceiptDigest [sha256.Size]byte
}

func (completion TOTPCompletion) String() string {
	return "mfa.TOTPCompletion{proof:[REDACTED]}"
}
func (completion TOTPCompletion) GoString() string { return completion.String() }

type RecoveryCompletion struct {
	ChallengeID               ChallengeID
	ExpectedChallengeVersion  uint64
	Binding                   StepUpBinding
	SetID                     identity.EntityID
	ExpectedSetVersion        uint64
	ExpectedSecurityRevision  int64
	CodeDigest                [sha256.Size]byte
	CompletedAt               time.Time
	Intent                    CompletionIntent
	Session                   SessionReservation
	ContinuationReceiptDigest [sha256.Size]byte
}

func (completion RecoveryCompletion) String() string {
	return "mfa.RecoveryCompletion{proof:[REDACTED]}"
}
func (completion RecoveryCompletion) GoString() string { return completion.String() }

type FactorConsumer interface {
	CompleteTOTP(context.Context, TOTPCompletion) (FactorCompletionResult, error)
	CompleteRecovery(context.Context, RecoveryCompletion) (FactorCompletionResult, error)
}

type StepUpOptions struct {
	Challenges       ChallengeRepository
	Factors          FactorRepository
	TOTP             TOTPVerifier
	Recovery         RecoveryDigester
	Consumer         FactorConsumer
	Random           io.Reader
	Now              func() time.Time
	ChallengeTTL     time.Duration
	OperationTimeout time.Duration
}

type StepUp struct {
	challenges       ChallengeRepository
	factors          FactorRepository
	totp             TOTPVerifier
	recovery         RecoveryDigester
	consumer         FactorConsumer
	random           io.Reader
	now              func() time.Time
	challengeTTL     time.Duration
	operationTimeout time.Duration
}

func NewStepUp(options StepUpOptions) (*StepUp, error) {
	if options.Challenges == nil || options.Factors == nil || options.TOTP == nil || options.Recovery == nil ||
		options.Consumer == nil || options.ChallengeTTL < minimumStepUpTTL || options.ChallengeTTL > maximumStepUpTTL ||
		options.OperationTimeout < minimumStepUpTimeout || options.OperationTimeout > maximumStepUpTimeout {
		return nil, ErrInvalidStepUp
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	if options.Now == nil {
		options.Now = func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }
	}
	return &StepUp{
		challenges: options.Challenges, factors: options.Factors, totp: options.TOTP,
		recovery: options.Recovery, consumer: options.Consumer, random: options.Random,
		now: options.Now, challengeTTL: options.ChallengeTTL, operationTimeout: options.OperationTimeout,
	}, nil
}

type StepUpStartRequest struct {
	Binding        StepUpBinding
	AllowedFactors []FactorKind
}

type StepUpStartArtifact struct {
	id            ChallengeID
	browserHandle []byte
	expiresAt     time.Time
	factors       []FactorKind
	binding       StepUpBinding
}

func (a StepUpStartArtifact) ChallengeID() ChallengeID { return a.id }
func (a StepUpStartArtifact) BrowserHandle() []byte    { return append([]byte(nil), a.browserHandle...) }
func (a StepUpStartArtifact) ExpiresAt() time.Time     { return a.expiresAt }
func (a StepUpStartArtifact) AllowedFactors() []FactorKind {
	return append([]FactorKind(nil), a.factors...)
}
func (a StepUpStartArtifact) Binding() StepUpBinding { return cloneStepUpBinding(a.binding) }
func (a StepUpStartArtifact) String() string         { return "mfa.StepUpStartArtifact{artifacts:[REDACTED]}" }
func (a StepUpStartArtifact) GoString() string       { return a.String() }

func (a *StepUpStartArtifact) Destroy() {
	if a == nil {
		return
	}
	clear(a.browserHandle)
	a.browserHandle = nil
	a.factors = nil
	a.binding = StepUpBinding{}
}

func (stepUp *StepUp) Start(ctx context.Context, request StepUpStartRequest) (StepUpStartArtifact, error) {
	now := stepUp.safeNow()
	factors, factorsOK := normalizeFactorKinds(request.AllowedFactors)
	if stepUp == nil || !validStepUpBinding(now, request.Binding) || !factorsOK {
		return StepUpStartArtifact{}, ErrInvalidStepUp
	}
	operation, cancel, ok := stepUp.operationContext(ctx)
	if !ok {
		return StepUpStartArtifact{}, ErrInvalidStepUp
	}
	defer cancel()
	idRaw := make([]byte, stepUpEntropyBytes)
	browserRaw := make([]byte, stepUpEntropyBytes)
	if _, err := io.ReadFull(stepUp.random, idRaw); err != nil {
		clear(idRaw)
		clear(browserRaw)
		return StepUpStartArtifact{}, ErrStepUpRejected
	}
	if _, err := io.ReadFull(stepUp.random, browserRaw); err != nil {
		clear(idRaw)
		clear(browserRaw)
		return StepUpStartArtifact{}, ErrStepUpRejected
	}
	if allZero(idRaw) || allZero(browserRaw) {
		clear(idRaw)
		clear(browserRaw)
		return StepUpStartArtifact{}, ErrStepUpRejected
	}
	defer clear(idRaw)
	defer clear(browserRaw)
	var id ChallengeID
	copy(id[:], idRaw)
	browser := make([]byte, base64.RawURLEncoding.EncodedLen(len(browserRaw)))
	base64.RawURLEncoding.Encode(browser, browserRaw)
	expiresAt := now.Add(stepUp.challengeTTL).Truncate(time.Millisecond)
	if request.Binding.AnchorExpiresAt.Before(expiresAt) {
		expiresAt = request.Binding.AnchorExpiresAt
	}
	pending := PendingChallenge{
		ID: id, BrowserDigest: sha256.Sum256(browser), Binding: cloneStepUpBinding(request.Binding),
		AllowedFactors: append([]FactorKind(nil), factors...), CreatedAt: now,
		ExpiresAt: expiresAt, State: ChallengePending, Version: 1,
	}
	if err := stepUp.challenges.Create(operation, pending); err != nil {
		clear(browser)
		return StepUpStartArtifact{}, ErrStepUpPersistence
	}
	return StepUpStartArtifact{
		id: id, browserHandle: browser, expiresAt: pending.ExpiresAt, factors: factors,
		binding: cloneStepUpBinding(pending.Binding),
	}, nil
}

type TOTPCompletionRequest struct {
	ChallengeID               ChallengeID
	BrowserDigest             [sha256.Size]byte `json:"-"`
	BrowserHandle             []byte            `json:"-"`
	FactorID                  identity.EntityID
	ExpectedBinding           StepUpCompletionBinding
	Code                      []byte
	Session                   SessionReservation
	ContinuationID            identity.EntityID
	ContinuationReceiptDigest [sha256.Size]byte
}

func (r TOTPCompletionRequest) String() string   { return "mfa.TOTPCompletionRequest{proof:[REDACTED]}" }
func (r TOTPCompletionRequest) GoString() string { return r.String() }

type RecoveryCompletionRequest struct {
	ChallengeID               ChallengeID
	BrowserDigest             [sha256.Size]byte `json:"-"`
	BrowserHandle             []byte            `json:"-"`
	ExpectedSetID             identity.EntityID
	ExpectedBinding           StepUpCompletionBinding
	Code                      []byte
	Session                   SessionReservation
	ContinuationID            identity.EntityID
	ContinuationReceiptDigest [sha256.Size]byte
}

func (r RecoveryCompletionRequest) String() string {
	return "mfa.RecoveryCompletionRequest{proof:[REDACTED]}"
}
func (r RecoveryCompletionRequest) GoString() string { return r.String() }

// StepUpCompletionBinding is the action-specific live authority pin resolved
// immediately before a completion artifact is claimed. It deliberately omits
// policy evidence: the claimed challenge retains that immutable payload, while
// this value prevents a stale or substituted anchor from reaching factor I/O.
type StepUpCompletionBinding struct {
	Flow            StepUpFlow
	TenantID        identity.EntityID
	UserID          identity.EntityID
	IdentityEpoch   uint64
	SessionID       identity.EntityID
	SessionFamilyID identity.EntityID
	ContinuationID  identity.EntityID
	AnchorVersion   uint64
	AnchorExpiresAt time.Time
	Action          string
	Audience        string
}

func (binding StepUpCompletionBinding) String() string {
	return "mfa.StepUpCompletionBinding{authority:[REDACTED]}"
}

func (binding StepUpCompletionBinding) GoString() string { return binding.String() }

type StepUpArtifact struct {
	TenantID           identity.EntityID
	UserID             identity.EntityID
	IdentityEpoch      uint64
	SessionFamilyID    identity.EntityID
	SessionID          identity.EntityID
	ContinuationID     identity.EntityID
	NewSessionFamilyID identity.EntityID
	NewSessionID       identity.EntityID
	Action             string
	Audience           string
	SessionVersion     uint64
	NewEvidence        identity.AssuranceEvidence
	RecoveryRestricted bool
}

func (a StepUpArtifact) String() string {
	return fmt.Sprintf("mfa.StepUpArtifact{sessionVersion:%d,recoveryRestricted:%t,evidence:[REDACTED]}",
		a.SessionVersion, a.RecoveryRestricted)
}
func (a StepUpArtifact) GoString() string { return a.String() }

func (stepUp *StepUp) CompleteTOTP(ctx context.Context, request TOTPCompletionRequest) (StepUpArtifact, error) {
	zero := identity.EntityID{}
	browserDigest, browserOK := completionBrowserDigest(request.BrowserDigest, request.BrowserHandle)
	if stepUp == nil || request.ChallengeID == (ChallengeID{}) || request.FactorID == zero ||
		!browserOK || !validStepUpCompletionBinding(request.ExpectedBinding) ||
		!validTOTPCode(request.Code) || request.Session.IsZero() {
		return StepUpArtifact{}, ErrFactorRejected
	}
	claimed, operation, cancel, err := stepUp.claim(
		ctx, request.ChallengeID, browserDigest, FactorTOTP, request.ContinuationReceiptDigest,
	)
	if err != nil {
		return StepUpArtifact{}, err
	}
	defer cancel()
	if !sameStepUpCompletionBinding(request.ExpectedBinding, claimed.Binding) {
		// The failure ABI only updates challenge lifecycle state; it does not
		// increment factor-attempt or account lockout counters.
		stepUp.fail(operation, claimed, ChallengeFailureFactor)
		return StepUpArtifact{}, ErrFactorRejected
	}
	if !validCompletionPossession(claimed.Binding, request.ContinuationID, request.ContinuationReceiptDigest) {
		stepUp.fail(operation, claimed, ChallengeFailureFactor)
		return StepUpArtifact{}, ErrFactorRejected
	}
	factor, loadErr := stepUp.factors.LoadTOTP(operation, claimed.Binding.TenantID, claimed.Binding.UserID, request.FactorID)
	defer clear(factor.Secret.Ciphertext)
	if loadErr != nil || !validTOTPFactor(factor, claimed.Binding, request.FactorID) {
		stepUp.fail(operation, claimed, ChallengeFailureFactor)
		return StepUpArtifact{}, ErrFactorRejected
	}
	verifiedAt := laterStepUpTime(claimed.ClaimedAt, stepUp.safeNow())
	if !request.Session.ValidAt(verifiedAt) {
		stepUp.fail(operation, claimed, ChallengeFailureFactor)
		return StepUpArtifact{}, ErrFactorRejected
	}
	code := append([]byte(nil), request.Code...)
	defer clear(code)
	protectedSecret := cloneProtectedSecret(factor.Secret)
	defer clear(protectedSecret.Ciphertext)
	proof, verifyErr := stepUp.totp.VerifyTOTP(operation, TOTPVerificationRequest{
		TenantID: factor.TenantID, UserID: factor.UserID, FactorID: factor.ID,
		Secret: protectedSecret, Code: code, At: verifiedAt,
	})
	if verifyErr != nil || proof.Counter < 0 || proof.Counter <= factor.LastCounter {
		stepUp.fail(operation, claimed, ChallengeFailureFactor)
		return StepUpArtifact{}, ErrFactorRejected
	}
	revision := factor.SecurityRevision
	evidence := identity.AssuranceEvidence{
		Level: identity.AssuranceMFA, Kind: identity.AssuranceEvidenceFactor,
		Source: identity.AssuranceSource{Local: true}, AuthenticatedAt: verifiedAt, FactorRevision: &revision,
	}
	combined := append(cloneEvidence(claimed.Binding.BaselineEvidence), evidence)
	if identity.EvaluateAssurance(verifiedAt, claimed.Binding.Requirement, combined, false) != identity.AssuranceSatisfied {
		stepUp.fail(operation, claimed, ChallengeFailureFactor)
		return StepUpArtifact{}, ErrAssuranceInsufficient
	}
	result, consumeErr := stepUp.consumer.CompleteTOTP(operation, TOTPCompletion{
		ChallengeID: claimed.ID, ExpectedChallengeVersion: claimed.Version,
		Binding: cloneStepUpBinding(claimed.Binding), FactorID: factor.ID,
		ExpectedFactorVersion: factor.RecordVersion, ExpectedSecurityRevision: factor.SecurityRevision,
		Counter: proof.Counter, CompletedAt: verifiedAt,
		Intent:  completionIntent(claimed.Binding, AuditTOTPStepUpCompleted, false),
		Session: request.Session, ContinuationReceiptDigest: request.ContinuationReceiptDigest,
	})
	if consumeErr != nil || !validFactorCompletionResult(claimed.Binding, result, request.Session, false) ||
		result.FactorSecurityRevision != factor.SecurityRevision {
		return StepUpArtifact{}, ErrFactorRejected
	}
	return newStepUpArtifact(claimed.Binding, result, evidence), nil
}

func (stepUp *StepUp) CompleteRecovery(ctx context.Context, request RecoveryCompletionRequest) (StepUpArtifact, error) {
	browserDigest, browserOK := completionBrowserDigest(request.BrowserDigest, request.BrowserHandle)
	if stepUp == nil || request.ChallengeID == (ChallengeID{}) || !browserOK ||
		request.ExpectedSetID == (identity.EntityID{}) || !validStepUpCompletionBinding(request.ExpectedBinding) ||
		!validRecoveryCode(request.Code) || request.Session.IsZero() {
		return StepUpArtifact{}, ErrFactorRejected
	}
	claimed, operation, cancel, err := stepUp.claim(
		ctx, request.ChallengeID, browserDigest, FactorRecoveryCode, request.ContinuationReceiptDigest,
	)
	if err != nil {
		return StepUpArtifact{}, err
	}
	defer cancel()
	if !sameStepUpCompletionBinding(request.ExpectedBinding, claimed.Binding) {
		stepUp.fail(operation, claimed, ChallengeFailureFactor)
		return StepUpArtifact{}, ErrFactorRejected
	}
	if !validCompletionPossession(claimed.Binding, request.ContinuationID, request.ContinuationReceiptDigest) {
		stepUp.fail(operation, claimed, ChallengeFailureFactor)
		return StepUpArtifact{}, ErrFactorRejected
	}
	set, loadErr := stepUp.factors.LoadRecoverySet(operation, claimed.Binding.TenantID, claimed.Binding.UserID)
	if loadErr != nil || set.ID != request.ExpectedSetID || !validRecoverySet(set, claimed.Binding) {
		stepUp.fail(operation, claimed, ChallengeFailureFactor)
		return StepUpArtifact{}, ErrFactorRejected
	}
	code := append([]byte(nil), request.Code...)
	defer clear(code)
	digest, digestErr := stepUp.recovery.DigestRecoveryCode(operation, RecoveryDigestRequest{
		SetID: set.ID, TenantID: set.TenantID, UserID: set.UserID, KeyVersion: set.DigestKeyVersion,
		Code: code,
	})
	if digestErr != nil || digest == ([sha256.Size]byte{}) {
		stepUp.fail(operation, claimed, ChallengeFailureFactor)
		return StepUpArtifact{}, ErrFactorRejected
	}
	completedAt := laterStepUpTime(claimed.ClaimedAt, stepUp.safeNow())
	if !request.Session.ValidAt(completedAt) {
		stepUp.fail(operation, claimed, ChallengeFailureFactor)
		return StepUpArtifact{}, ErrFactorRejected
	}
	result, consumeErr := stepUp.consumer.CompleteRecovery(operation, RecoveryCompletion{
		ChallengeID: claimed.ID, ExpectedChallengeVersion: claimed.Version,
		Binding: cloneStepUpBinding(claimed.Binding), SetID: set.ID,
		ExpectedSetVersion: set.RecordVersion, ExpectedSecurityRevision: set.SecurityRevision,
		CodeDigest: digest, CompletedAt: completedAt,
		Intent:  completionIntent(claimed.Binding, AuditRecoveryCodeUsed, true),
		Session: request.Session, ContinuationReceiptDigest: request.ContinuationReceiptDigest,
	})
	clear(digest[:])
	if consumeErr != nil || !validFactorCompletionResult(claimed.Binding, result, request.Session, true) ||
		result.FactorSecurityRevision != set.SecurityRevision {
		return StepUpArtifact{}, ErrFactorRejected
	}
	revision := set.SecurityRevision
	evidence := identity.AssuranceEvidence{
		Level: identity.AssuranceMFA, Kind: identity.AssuranceEvidenceRecovery,
		Source: identity.AssuranceSource{Local: true}, AuthenticatedAt: completedAt, FactorRevision: &revision,
	}
	return newStepUpArtifact(claimed.Binding, result, evidence), nil
}

func newStepUpArtifact(binding StepUpBinding, result FactorCompletionResult,
	evidence identity.AssuranceEvidence,
) StepUpArtifact {
	return StepUpArtifact{
		TenantID: binding.TenantID, UserID: binding.UserID, IdentityEpoch: binding.IdentityEpoch,
		SessionID:       binding.SessionID,
		SessionFamilyID: binding.SessionFamilyID,
		ContinuationID:  binding.ContinuationID, Action: binding.Action, Audience: binding.Audience,
		NewSessionID: result.NewSessionID, NewSessionFamilyID: result.NewSessionFamilyID,
		SessionVersion: result.SessionVersion, NewEvidence: evidence,
		RecoveryRestricted: result.RecoveryRestricted,
	}
}

func validFactorCompletionResult(
	binding StepUpBinding,
	result FactorCompletionResult,
	reservation SessionReservation,
	recovery bool,
) bool {
	zero := identity.EntityID{}
	if result.TenantID != binding.TenantID || result.UserID != binding.UserID ||
		result.IdentityEpoch != binding.IdentityEpoch || result.AuditID == zero ||
		result.NewSessionID == zero || result.NewSessionFamilyID == zero ||
		reservation.IsZero() || result.NewSessionID != reservation.SessionID() ||
		result.NewSessionFamilyID != reservation.FamilyID() ||
		!validStoredVersion(result.SessionVersion) || !validStoredRevision(result.FactorSecurityRevision) ||
		result.RecoveryRestricted != recovery {
		return false
	}
	switch binding.Flow {
	case FlowExistingSession:
		return result.NewSessionID != binding.SessionID &&
			result.NewSessionFamilyID == binding.SessionFamilyID && result.ConsumedContinuationID == zero &&
			result.SessionVersion > binding.AnchorVersion
	case FlowPostPrimaryContinuation:
		return result.ConsumedContinuationID == binding.ContinuationID && result.SessionVersion > binding.AnchorVersion
	default:
		return false
	}
}

func completionIntent(binding StepUpBinding, audit StepUpAuditKind, recovery bool) CompletionIntent {
	mutation := StepUpSessionRotate
	if binding.Flow == FlowPostPrimaryContinuation {
		mutation = StepUpSessionCreateFromContinuation
	}
	return CompletionIntent{Session: mutation, Audit: audit, RecoveryRestricted: recovery}
}

func validCompletionPossession(
	binding StepUpBinding,
	continuationID identity.EntityID,
	receiptDigest [sha256.Size]byte,
) bool {
	zeroID := identity.EntityID{}
	zeroDigest := [sha256.Size]byte{}
	switch binding.Flow {
	case FlowExistingSession:
		return continuationID == zeroID && receiptDigest == zeroDigest
	case FlowPostPrimaryContinuation:
		return continuationID == binding.ContinuationID && continuationID != zeroID && receiptDigest != zeroDigest
	default:
		return false
	}
}

func validStepUpCompletionBinding(value StepUpCompletionBinding) bool {
	zero := identity.EntityID{}
	if value.TenantID == zero || value.UserID == zero || !validStoredVersion(value.IdentityEpoch) ||
		!validStoredSuccessorVersion(value.AnchorVersion) || !validMFADeadline(value.AnchorExpiresAt) ||
		!validAudience(value.Action) || !validAudience(value.Audience) {
		return false
	}
	switch value.Flow {
	case FlowExistingSession:
		return value.SessionID != zero && value.SessionFamilyID != zero && value.SessionID != value.SessionFamilyID &&
			value.ContinuationID == zero
	case FlowPostPrimaryContinuation:
		return value.SessionID == zero && value.SessionFamilyID == zero && value.ContinuationID != zero
	default:
		return false
	}
}

func sameStepUpCompletionBinding(expected StepUpCompletionBinding, actual StepUpBinding) bool {
	return expected.Flow == actual.Flow && expected.TenantID == actual.TenantID && expected.UserID == actual.UserID &&
		expected.IdentityEpoch == actual.IdentityEpoch && expected.SessionID == actual.SessionID &&
		expected.SessionFamilyID == actual.SessionFamilyID && expected.ContinuationID == actual.ContinuationID &&
		expected.AnchorVersion == actual.AnchorVersion && expected.AnchorExpiresAt.Equal(actual.AnchorExpiresAt) &&
		expected.Action == actual.Action && expected.Audience == actual.Audience
}

func (stepUp *StepUp) claim(
	ctx context.Context,
	id ChallengeID,
	browserDigest [sha256.Size]byte,
	factor FactorKind,
	receiptDigest [sha256.Size]byte,
) (ClaimedChallenge, context.Context, context.CancelFunc, error) {
	operation, cancel, ok := stepUp.operationContext(ctx)
	if !ok {
		return ClaimedChallenge{}, nil, nil, ErrStepUpRejected
	}
	requestedAt := stepUp.safeNow()
	claimed, err := stepUp.challenges.Claim(operation, ChallengeClaim{
		ID: id, BrowserDigest: browserDigest, Factor: factor, ClaimedAt: requestedAt,
		ContinuationReceiptDigest: receiptDigest,
	})
	postClaim := stepUp.safeNow()
	effectiveAt := laterStepUpTime(claimed.ClaimedAt, postClaim)
	if err != nil || claimed.ID != id || claimed.BrowserDigest != browserDigest ||
		claimed.ClaimedFactor != factor ||
		claimed.ClaimedAt.Before(requestedAt) ||
		claimed.ClaimedAt.After(requestedAt.Add(5*time.Minute+stepUp.operationTimeout)) ||
		!validClaimedChallenge(effectiveAt, claimed, factor) {
		cancel()
		return ClaimedChallenge{}, nil, nil, ErrStepUpRejected
	}
	return claimed, operation, cancel, nil
}

func (stepUp *StepUp) fail(ctx context.Context, claimed ClaimedChallenge, reason ChallengeFailureReason) {
	state := ChallengeFailed
	if reason == ChallengeFailureExpired {
		state = ChallengeExpired
	}
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), stepUp.operationTimeout)
	defer cancel()
	_ = stepUp.challenges.Fail(cleanup, ChallengeFailure{
		ID: claimed.ID, ExpectedVersion: claimed.Version,
		FailedAt: laterStepUpTime(claimed.ClaimedAt, stepUp.safeNow()), State: state, Reason: reason,
	})
}

func completionBrowserDigest(digest [sha256.Size]byte, handle []byte) ([sha256.Size]byte, bool) {
	zero := [sha256.Size]byte{}
	switch {
	case digest != zero && len(handle) == 0:
		return digest, true
	case digest == zero && validOpaque(handle):
		return sha256.Sum256(handle), true
	default:
		return zero, false
	}
}

func laterStepUpTime(left, right time.Time) time.Time {
	if right.After(left) {
		return right
	}
	return left
}

func (stepUp *StepUp) operationContext(ctx context.Context) (context.Context, context.CancelFunc, bool) {
	if stepUp == nil || ctx == nil || ctx.Err() != nil {
		return nil, nil, false
	}
	bounded, cancel := context.WithTimeout(ctx, stepUp.operationTimeout)
	return bounded, cancel, true
}

func (stepUp *StepUp) safeNow() time.Time {
	if stepUp == nil || stepUp.now == nil {
		return time.Time{}
	}
	return stepUp.now().UTC().Truncate(time.Microsecond)
}

func validStepUpBinding(now time.Time, value StepUpBinding) bool {
	zero := identity.EntityID{}
	if value.TenantID == zero || value.UserID == zero || !validStoredVersion(value.IdentityEpoch) ||
		!validAudience(value.Action) || !validAudience(value.Audience) ||
		!validMFADeadline(value.AnchorExpiresAt) || !value.AnchorExpiresAt.After(now) ||
		!validRequirement(now, value.Requirement) || len(value.BaselineEvidence) == 0 ||
		!validEvidence(now, value.BaselineEvidence) {
		return false
	}
	switch value.Flow {
	case FlowPostPrimaryContinuation:
		return value.SessionID == zero && value.SessionFamilyID == zero &&
			value.ContinuationID != zero && validStoredSuccessorVersion(value.AnchorVersion) &&
			!value.AnchorRecoveryRestricted
	case FlowExistingSession:
		if value.SessionID == zero || value.SessionFamilyID == zero ||
			value.ContinuationID != zero || !validStoredSuccessorVersion(value.AnchorVersion) {
			return false
		}
		return !value.AnchorRecoveryRestricted || hasLiveRecoveryEvidence(now, value.BaselineEvidence)
	default:
		return false
	}
}

func hasLiveRecoveryEvidence(now time.Time, values []identity.AssuranceEvidence) bool {
	for _, value := range values {
		if value.Kind == identity.AssuranceEvidenceRecovery && value.Source.Local &&
			!value.AuthenticatedAt.After(now) && (value.ExpiresAt == nil || value.ExpiresAt.After(now)) {
			return true
		}
	}
	return false
}

func normalizeFactorKinds(values []FactorKind) ([]FactorKind, bool) {
	if len(values) == 0 || len(values) > 2 {
		return nil, false
	}
	result := append([]FactorKind(nil), values...)
	slices.Sort(result)
	for index, value := range result {
		if value != FactorTOTP && value != FactorRecoveryCode || index > 0 && value == result[index-1] {
			return nil, false
		}
	}
	return result, true
}

func validClaimedChallenge(now time.Time, value ClaimedChallenge, factor FactorKind) bool {
	factors, factorsOK := normalizeFactorKinds(value.AllowedFactors)
	return value.ID != (ChallengeID{}) && value.State == ChallengeClaimed && value.Version >= 2 &&
		validStoredSuccessorVersion(value.Version) &&
		validMFATime(value.CreatedAt) && validMFADeadline(value.ExpiresAt) && validMFATime(value.ClaimedAt) &&
		!value.ClaimedAt.Before(value.CreatedAt) && !value.ClaimedAt.After(now) && now.Before(value.ExpiresAt) &&
		validStepUpBinding(now, value.Binding) && factorsOK && slices.Equal(factors, value.AllowedFactors) &&
		slices.Contains(value.AllowedFactors, factor)
}

func validTOTPFactor(value TOTPFactor, binding StepUpBinding, factorID identity.EntityID) bool {
	zero := identity.EntityID{}
	return value.ID == factorID && value.ID != zero && value.TenantID == binding.TenantID &&
		value.UserID == binding.UserID && validStoredSuccessorVersion(value.RecordVersion) &&
		validStoredRevision(value.SecurityRevision) &&
		value.Status == FactorActive && value.LastCounter >= -1 &&
		value.Secret.KeyVersion > 0 && value.Secret.KeyVersion <= maximumMFAKeyVersion &&
		len(value.Secret.Ciphertext) >= 16 && len(value.Secret.Ciphertext) <= maximumProtectedSecretBytes
}

func validRecoverySet(value RecoverySet, binding StepUpBinding) bool {
	zero := identity.EntityID{}
	return value.ID != zero && value.TenantID == binding.TenantID && value.UserID == binding.UserID &&
		validStoredSuccessorVersion(value.RecordVersion) && validStoredRevision(value.SecurityRevision) &&
		value.Status == FactorActive && value.DigestKeyVersion > 0 &&
		value.DigestKeyVersion <= maximumMFAKeyVersion
}

func validTOTPCode(value []byte) bool {
	if len(value) < 6 || len(value) > maximumTOTPCodeBytes {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func validRecoveryCode(value []byte) bool {
	if len(value) < minimumRecoveryCodeBytes || len(value) > maximumRecoveryCodeBytes ||
		value[0] == ' ' || value[len(value)-1] == ' ' {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func validOpaque(value []byte) bool {
	if len(value) != base64.RawURLEncoding.EncodedLen(stepUpEntropyBytes) {
		return false
	}
	decoded := make([]byte, stepUpEntropyBytes)
	count, err := base64.RawURLEncoding.Strict().Decode(decoded, value)
	valid := err == nil && count == stepUpEntropyBytes && !allZero(decoded) &&
		base64.RawURLEncoding.EncodeToString(decoded) == string(value)
	clear(decoded)
	return valid
}

func cloneStepUpBinding(value StepUpBinding) StepUpBinding {
	value.Requirement = cloneRequirement(value.Requirement)
	value.BaselineEvidence = cloneEvidence(value.BaselineEvidence)
	return value
}

func cloneProtectedSecret(value ProtectedTOTPSecret) ProtectedTOTPSecret {
	return ProtectedTOTPSecret{KeyVersion: value.KeyVersion, Ciphertext: append([]byte(nil), value.Ciphertext...)}
}

func validMFATime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond()%int(time.Microsecond) == 0
}

func validMFADeadline(value time.Time) bool {
	return validMFATime(value) && value.Nanosecond()%int(time.Millisecond) == 0
}

func allZero(value []byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}

func validStoredVersion(value uint64) bool { return value > 0 && value <= maximumStoredVersion }

func validStoredSuccessorVersion(value uint64) bool {
	return value > 0 && value < maximumStoredVersion
}

func validStoredRevision(value int64) bool {
	return value > 0 && uint64(value) <= maximumStoredVersion
}
