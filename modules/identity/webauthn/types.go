// Package webauthn defines the deployment-bound WebAuthn ceremony kernel.
// Cryptographic parsing and verification are delegated to an admitted library
// adapter; persistence ports own every one-time and counter transition.
package webauthn

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

const (
	artifactEntropyBytes = 32

	minimumCeremonyTTL      = time.Minute
	maximumCeremonyTTL      = 10 * time.Minute
	minimumOperationTimeout = 100 * time.Millisecond
	maximumOperationTimeout = time.Minute

	minimumResponseBytes      = 512
	maximumResponseBytes      = 2 * 1024 * 1024
	minimumCredentialIDBytes  = 1
	maximumCredentialIDBytes  = 4 * 1024
	minimumPublicKeyBytes     = 32
	maximumPublicKeyBytes     = 64 * 1024
	maximumAllowedCredentials = 128
	maximumOrigins            = 16
	maximumActionBytes        = 256
	stableUserHandleBytes     = 32
	maximumJSONSafeRevision   = uint64(9_007_199_254_740_991)
)

var (
	ErrInvalidOptions           = errors.New("invalid WebAuthn kernel options")
	ErrCeremonyRejected         = errors.New("WebAuthn ceremony rejected")
	ErrCeremonyPersistence      = errors.New("WebAuthn ceremony persistence failed")
	ErrVerificationRejected     = errors.New("WebAuthn verification rejected")
	ErrCredentialRejected       = errors.New("WebAuthn credential rejected")
	ErrCredentialCloneSuspected = errors.New("WebAuthn credential clone suspected")
)

// CeremonyID is a random, non-secret lookup identifier. Its zero value is invalid.
type CeremonyID [artifactEntropyBytes]byte

// CeremonyPurpose prevents login, enrollment, continuation, and step-up
// artifacts from being interchanged.
type CeremonyPurpose uint8

const (
	PurposeRegistration CeremonyPurpose = iota + 1
	PurposePrimaryAuthentication
	PurposeContinuationAuthentication
	PurposeStepUpAuthentication
)

// AuthenticationMode distinguishes a known-user allow-list ceremony from a
// discoverable, usernameless passkey ceremony.
type AuthenticationMode uint8

const (
	AuthenticationKnownUser AuthenticationMode = iota + 1
	AuthenticationDiscoverable
)

// UserVerificationRequirement is passed verbatim to the admitted verifier.
type UserVerificationRequirement uint8

const (
	UserVerificationPreferred UserVerificationRequirement = iota + 1
	UserVerificationRequired
)

// ResidentKeyRequirement controls discoverable credential creation.
type ResidentKeyRequirement uint8

const (
	ResidentKeyPreferred ResidentKeyRequirement = iota + 1
	ResidentKeyRequired
)

// AttestationPolicy is deployment-owned. Direct and enterprise policies also
// require an exact metadata revision.
type AttestationPolicy uint8

const (
	AttestationNone AttestationPolicy = iota + 1
	AttestationDirect
	AttestationEnterprise
)

// AttestationType is a safe normalized result from the verification adapter.
type AttestationType uint8

const (
	AttestationTypeNone AttestationType = iota + 1
	AttestationTypeSelf
	AttestationTypeBasic
	AttestationTypeEnterprise
)

// CredentialTransport is a closed safe inventory vocabulary.
type CredentialTransport string

const (
	TransportUSB       CredentialTransport = "usb"
	TransportNFC       CredentialTransport = "nfc"
	TransportBLE       CredentialTransport = "ble"
	TransportInternal  CredentialTransport = "internal"
	TransportHybrid    CredentialTransport = "hybrid"
	TransportSmartCard CredentialTransport = "smart_card"
)

// CredentialStatus is the lifecycle projection needed by the kernel.
type CredentialStatus uint8

const (
	CredentialActive CredentialStatus = iota + 1
	CredentialRevoked
	CredentialCloneSuspected
)

// CeremonyState is the durable one-time state machine.
type CeremonyState uint8

const (
	CeremonyPending CeremonyState = iota + 1
	CeremonyClaimed
	CeremonyCompleted
	CeremonyFailed
	CeremonyExpired
)

// CeremonyFailureReason is safe operational metadata.
type CeremonyFailureReason string

const (
	FailureExpired      CeremonyFailureReason = "expired"
	FailureMalformed    CeremonyFailureReason = "malformed_response"
	FailureVerification CeremonyFailureReason = "verification_rejected"
	FailureCredential   CeremonyFailureReason = "credential_rejected"
)

// Limits bounds attacker-controlled options and responses.
type Limits struct {
	MaxResponseBytes      int
	MaxCredentialIDBytes  int
	MaxPublicKeyBytes     int
	MaxAllowedCredentials int
}

func DefaultLimits() Limits {
	return Limits{
		MaxResponseBytes:      256 * 1024,
		MaxCredentialIDBytes:  1024,
		MaxPublicKeyBytes:     16 * 1024,
		MaxAllowedCredentials: 64,
	}
}

// KernelOptions contains only deployment policy and narrow ports.
type KernelOptions struct {
	Ceremonies       CeremonyRepository
	Credentials      CredentialLookupRepository
	Verifier         Verifier
	Random           io.Reader
	Now              func() time.Time
	CeremonyTTL      time.Duration
	OperationTimeout time.Duration
	Limits           Limits
}

// RelyingParty is an immutable, deployment-compiled RP/origin revision.
type RelyingParty struct {
	id       string
	origins  []string
	revision uint64
}

func (r RelyingParty) ID() string        { return r.id }
func (r RelyingParty) Revision() uint64  { return r.revision }
func (r RelyingParty) Origins() []string { return append([]string(nil), r.origins...) }

func (r RelyingParty) String() string {
	return fmt.Sprintf("webauthn.RelyingParty{revision:%d,origins:%d}", r.revision, len(r.origins))
}
func (r RelyingParty) GoString() string { return r.String() }

// CeremonyBinding pins the exact authorization context. UserID is absent only
// for a discoverable primary ceremony, where the opaque user handle resolves it.
type CeremonyBinding struct {
	Purpose                  CeremonyPurpose
	TenantID                 identity.EntityID
	UserID                   identity.EntityID
	IdentityEpoch            uint64
	SessionID                identity.EntityID
	SessionFamilyID          identity.EntityID
	ContinuationID           identity.EntityID
	AnchorVersion            uint64
	AnchorExpiresAt          time.Time
	AnchorRecoveryRestricted bool
	Action                   string
	Audience                 string
	Requirement              identity.EffectiveAssuranceRequirement
	BaselineEvidence         []identity.AssuranceEvidence
}

// CeremonyPolicy fixes user presence, verification, resident-key, and
// attestation semantics for one immutable ceremony.
type CeremonyPolicy struct {
	RequireUserPresence bool
	UserVerification    UserVerificationRequirement
	ResidentKey         ResidentKeyRequirement
	Attestation         AttestationPolicy
	MetadataRevision    uint64
}

// PendingCeremony is the bounded repository projection. Credential identifiers
// and user handles are public protocol material but are redacted from formatting.
type PendingCeremony struct {
	ID                   CeremonyID
	ChallengeDigest      [sha256.Size]byte
	BrowserDigest        [sha256.Size]byte
	RP                   RelyingParty
	Binding              CeremonyBinding
	Policy               CeremonyPolicy
	Mode                 AuthenticationMode
	UserHandleDigest     [sha256.Size]byte
	AllowedCredentialIDs [][]byte
	CreatedAt            time.Time
	ExpiresAt            time.Time
	State                CeremonyState
	Version              uint64
}

func (p PendingCeremony) String() string {
	return fmt.Sprintf("webauthn.PendingCeremony{purpose:%d,state:%d,allowed:%d,version:%d,artifacts:[REDACTED]}",
		p.Binding.Purpose, p.State, len(p.AllowedCredentialIDs), p.Version)
}
func (p PendingCeremony) GoString() string { return p.String() }

// CeremonyClaim atomically moves one matching pending ceremony to claimed.
type CeremonyClaim struct {
	ID                        CeremonyID
	BrowserDigest             [sha256.Size]byte
	ClaimedAt                 time.Time
	ContinuationReceiptDigest [sha256.Size]byte `json:"-"`
}

// ClaimedCeremony is returned only by the atomic pending-to-claimed transition.
type ClaimedCeremony struct {
	PendingCeremony
	ClaimedAt time.Time
}

// CeremonyFailure marks a claimed ceremony terminal. Claim already supplies
// replay safety if best-effort terminal annotation fails.
type CeremonyFailure struct {
	ID              CeremonyID
	ExpectedVersion uint64
	FailedAt        time.Time
	State           CeremonyState
	Reason          CeremonyFailureReason
}

type CeremonyRepository interface {
	Create(context.Context, PendingCeremony) error
	Claim(context.Context, CeremonyClaim) (ClaimedCeremony, error)
	// Fail terminalizes the claimed ceremony and couples the attempt/lockout
	// update plus a redacted failure audit to the same transaction.
	Fail(context.Context, CeremonyFailure) error
}

// Credential is the exact verifier projection. Private keys never enter it.
type Credential struct {
	ID        []byte
	PublicKey []byte
	TenantID  identity.EntityID
	UserID    identity.EntityID
	// IdentityEpoch is the live User epoch loaded with the credential. It is
	// not credential-owned state; completion rechecks it transactionally.
	IdentityEpoch    uint64
	UserHandleDigest [sha256.Size]byte
	RPID             string
	RPRevision       uint64
	Version          uint64
	// SecurityRevision is the credential authority epoch. It advances only
	// when status or authenticator backup state changes; Version remains the
	// record/WebAuthn ceremony CAS and may advance independently.
	SecurityRevision uint64
	Status           CredentialStatus
	SignCount        uint32
	Discoverable     bool
	UserVerification bool
	BackupEligible   bool
	BackedUp         bool
	Transports       []CredentialTransport
}

func (c Credential) String() string {
	return fmt.Sprintf("webauthn.Credential{status:%d,version:%d,discoverable:%t,backupEligible:%t,backedUp:%t,material:[REDACTED]}",
		c.Status, c.Version, c.Discoverable, c.BackupEligible, c.BackedUp)
}
func (c Credential) GoString() string { return c.String() }

// CredentialLookup contains the exact tenant and response-bound identifiers.
type CredentialLookup struct {
	TenantID     identity.EntityID
	CredentialID []byte
	UserHandle   []byte
	Discoverable bool
}

// RegistrationCompletion must create the globally unique credential and
// complete the claimed ceremony in one transaction.
type RegistrationCompletion struct {
	CeremonyID              CeremonyID
	ExpectedCeremonyVersion uint64
	Binding                 CeremonyBinding
	CompletedAt             time.Time
	Credential              Credential
	AAGUID                  [16]byte
	AttestationFormat       string
	AttestationType         AttestationType
	AttestationTrusted      bool
	MetadataRevision        uint64
}

// CounterDisposition is computed by the pure kernel and enforced again by the
// atomic credential consumer against ExpectedCredentialVersion.
type CounterDisposition uint8

const (
	CounterUnsupported CounterDisposition = iota + 1
	CounterAdvance
	CounterCloneSuspected
)

// AuthenticationCompletion advances or revokes a credential and completes the
// claimed ceremony atomically. CloneSuspected must never create authority.
type AuthenticationCompletion struct {
	CeremonyID                CeremonyID
	ExpectedCeremonyVersion   uint64
	Binding                   CeremonyBinding
	ResolvedUserID            identity.EntityID
	ExpectedIdentityEpoch     uint64
	CredentialID              []byte
	ExpectedCredentialVersion uint64
	// ExpectedSecurityRevision is an internal kernel-to-consumer invariant.
	// Persistence derives the same epoch from locked state and deliberately
	// does not expose this value in the public completion JSON contract.
	ExpectedSecurityRevision uint64
	CompletedAt              time.Time
	ExpectedSignCount        uint32
	ObservedSignCount        uint32
	ExpectedBackupEligible   bool
	ExpectedBackedUp         bool
	CounterDisposition       CounterDisposition
	UserVerified             bool
	BackupEligible           bool
	BackedUp                 bool
}

type AuthenticationApplyResult struct {
	CredentialVersion uint64
	SecurityRevision  uint64
	Status            CredentialStatus
	SignCount         uint32
	BackupEligible    bool
	BackedUp          bool
}

// CredentialLookupRepository is the read-only projection used before
// cryptographic assertion verification. Completion always goes through an
// explicit transaction-owned consumer.
type CredentialLookupRepository interface {
	LoadForAuthentication(context.Context, CredentialLookup) (Credential, error)
}

// RegistrationConsumer and AuthenticationConsumer are transaction-owned
// completion boundaries. Application orchestrators supply a consumer that
// rotates a session or consumes a continuation and appends audit in the same
// transaction as ceremony and credential mutation.
type RegistrationConsumer interface {
	CompleteRegistration(context.Context, RegistrationCompletion) (Credential, error)
}

type AuthenticationConsumer interface {
	CompleteAuthentication(context.Context, AuthenticationCompletion) (AuthenticationApplyResult, error)
}

// RegistrationVerificationRequest supplies bounded raw browser material plus
// exact deployment expectations to an admitted library adapter.
type RegistrationVerificationRequest struct {
	ChallengeDigest   [sha256.Size]byte
	RPID              string
	AllowedOrigins    []string
	Policy            CeremonyPolicy
	CredentialID      []byte
	ClientDataJSON    []byte
	AttestationObject []byte
	// ClientExtensionResults is the bounded JSON object returned by
	// getClientExtensionResults(). v1 admits only credProps.rk so resident-key
	// policy is based on authenticated ceremony output rather than inference.
	ClientExtensionResults []byte
	Transports             []CredentialTransport
}

type RegistrationProof struct {
	ChallengeDigest    [sha256.Size]byte
	Origin             string
	RPIDHash           [sha256.Size]byte
	UserPresent        bool
	UserVerified       bool
	CrossOrigin        bool
	CredentialID       []byte
	PublicKey          []byte
	SignCount          uint32
	Discoverable       bool
	BackupEligible     bool
	BackedUp           bool
	Transports         []CredentialTransport
	AAGUID             [16]byte
	AttestationFormat  string
	AttestationType    AttestationType
	AttestationTrusted bool
	MetadataRevision   uint64
}

// AuthenticationVerificationRequest includes only the exact credential loaded
// from the repository and the claimed ceremony expectations.
type AuthenticationVerificationRequest struct {
	ChallengeDigest   [sha256.Size]byte
	RPID              string
	AllowedOrigins    []string
	Policy            CeremonyPolicy
	Credential        Credential
	CredentialID      []byte
	ClientDataJSON    []byte
	AuthenticatorData []byte
	Signature         []byte
	UserHandle        []byte
}

type AuthenticationProof struct {
	ChallengeDigest [sha256.Size]byte
	Origin          string
	RPIDHash        [sha256.Size]byte
	UserPresent     bool
	UserVerified    bool
	CrossOrigin     bool
	CredentialID    []byte
	UserHandle      []byte
	SignCount       uint32
	BackupEligible  bool
	BackedUp        bool
}

type Verifier interface {
	VerifyRegistration(context.Context, RegistrationVerificationRequest) (RegistrationProof, error)
	VerifyAuthentication(context.Context, AuthenticationVerificationRequest) (AuthenticationProof, error)
}

// RegistrationStartRequest creates a known-user enrollment ceremony.
type RegistrationStartRequest struct {
	RP                   RelyingParty
	Binding              CeremonyBinding
	Policy               CeremonyPolicy
	UserHandle           []byte
	ExcludeCredentialIDs [][]byte
}

// AuthenticationStartRequest creates either a known-user allow-list ceremony
// or a discoverable primary ceremony.
type AuthenticationStartRequest struct {
	RP                   RelyingParty
	Binding              CeremonyBinding
	Policy               CeremonyPolicy
	Mode                 AuthenticationMode
	UserHandle           []byte
	AllowedCredentialIDs [][]byte
}

// StartArtifact contains browser-bound values exactly once. Accessors return copies.
type StartArtifact struct {
	id            CeremonyID
	challenge     []byte
	browserHandle []byte
	expiresAt     time.Time
	rp            RelyingParty
	binding       CeremonyBinding
	policy        CeremonyPolicy
	mode          AuthenticationMode
	userHandle    []byte
	credentialIDs [][]byte
}

func (a StartArtifact) CeremonyID() CeremonyID     { return a.id }
func (a StartArtifact) Challenge() []byte          { return append([]byte(nil), a.challenge...) }
func (a StartArtifact) BrowserHandle() []byte      { return append([]byte(nil), a.browserHandle...) }
func (a StartArtifact) ExpiresAt() time.Time       { return a.expiresAt }
func (a StartArtifact) RelyingParty() RelyingParty { return cloneRP(a.rp) }
func (a StartArtifact) Binding() CeremonyBinding   { return cloneBinding(a.binding) }
func (a StartArtifact) Policy() CeremonyPolicy     { return a.policy }
func (a StartArtifact) Mode() AuthenticationMode   { return a.mode }
func (a StartArtifact) UserHandle() []byte         { return append([]byte(nil), a.userHandle...) }
func (a StartArtifact) CredentialIDs() [][]byte    { return cloneBytes2D(a.credentialIDs) }
func (a StartArtifact) String() string             { return "webauthn.StartArtifact{artifacts:[REDACTED]}" }
func (a StartArtifact) GoString() string           { return a.String() }

func (a *StartArtifact) Destroy() {
	if a == nil {
		return
	}
	clear(a.challenge)
	clear(a.browserHandle)
	clear(a.userHandle)
	for index := range a.credentialIDs {
		clear(a.credentialIDs[index])
	}
	a.challenge = nil
	a.browserHandle = nil
	a.userHandle = nil
	a.credentialIDs = nil
	a.binding = CeremonyBinding{}
}

type RegistrationResponse struct {
	CeremonyID                CeremonyID
	BrowserHandle             []byte
	CredentialID              []byte
	ClientDataJSON            []byte
	AttestationObject         []byte
	ClientExtensionResults    []byte
	Transports                []CredentialTransport
	ContinuationReceiptDigest [sha256.Size]byte `json:"-"`
}

func (r RegistrationResponse) String() string {
	return "webauthn.RegistrationResponse{material:[REDACTED]}"
}
func (r RegistrationResponse) GoString() string { return r.String() }

type AuthenticationResponse struct {
	CeremonyID                CeremonyID
	BrowserHandle             []byte
	CredentialID              []byte
	ClientDataJSON            []byte
	AuthenticatorData         []byte
	Signature                 []byte
	UserHandle                []byte
	ContinuationReceiptDigest [sha256.Size]byte `json:"-"`
}

func (r AuthenticationResponse) String() string {
	return "webauthn.AuthenticationResponse{material:[REDACTED]}"
}
func (r AuthenticationResponse) GoString() string { return r.String() }

type RegistrationArtifact struct {
	TenantID          identity.EntityID
	UserID            identity.EntityID
	IdentityEpoch     uint64
	CredentialVersion uint64
	Discoverable      bool
	BackupEligible    bool
	BackedUp          bool
	Transports        []CredentialTransport
}

func (a RegistrationArtifact) String() string {
	return fmt.Sprintf("webauthn.RegistrationArtifact{credentialVersion:%d,discoverable:%t,subject:[REDACTED]}",
		a.CredentialVersion, a.Discoverable)
}
func (a RegistrationArtifact) GoString() string { return a.String() }

// AuthenticationArtifact is safe input for the later session/step-up consumer.
type AuthenticationArtifact struct {
	TenantID           identity.EntityID
	UserID             identity.EntityID
	IdentityEpoch      uint64
	CredentialVersion  uint64
	CredentialDigest   [sha256.Size]byte
	Evidence           identity.AssuranceEvidence
	CounterUnsupported bool
	BackupStateChanged bool
}

func (a AuthenticationArtifact) String() string {
	return fmt.Sprintf("webauthn.AuthenticationArtifact{credentialVersion:%d,counterUnsupported:%t,backupStateChanged:%t,credential:[REDACTED]}",
		a.CredentialVersion, a.CounterUnsupported, a.BackupStateChanged)
}
func (a AuthenticationArtifact) GoString() string { return a.String() }
