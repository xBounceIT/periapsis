// Package federatedauth coordinates verified protocol artifacts with short,
// transactional JIT, assurance, session, refresh, and revocation ports. It
// owns no HTTP handler, SQL, keyring, or network implementation.
package federatedauth

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/modules/identity/webauthn"
)

var (
	ErrInvalidOptions              = errors.New("invalid federated authentication options")
	ErrInvalidInput                = errors.New("federated authentication input rejected")
	ErrAuthentication              = errors.New("federated authentication rejected")
	ErrIdentityCollision           = errors.New("federated identity collision")
	ErrStaleConfiguration          = errors.New("federated configuration changed")
	ErrSessionRejected             = errors.New("session rejected")
	ErrSessionRevalidationConflict = errors.New("session revalidation authority changed")
	ErrRefreshRejected             = errors.New("OIDC refresh rejected")
	ErrUpstreamLogoutRetry         = errors.New("upstream logout retry failed")
)

type Protocol string

const (
	ProtocolOIDC    Protocol = "oidc"
	ProtocolSAML    Protocol = "saml"
	ProtocolPasskey Protocol = "passkey"
)

// AuthenticationMethod is the closed legacy session summary derived from
// primary provenance. Assurance and step-up are normalized separately and
// must never be encoded as combined method strings.
type AuthenticationMethod string

const (
	AuthenticationMethodOIDC    AuthenticationMethod = "oidc"
	AuthenticationMethodSAML    AuthenticationMethod = "saml"
	AuthenticationMethodPasskey AuthenticationMethod = "passkey"
	AuthenticationMethodLDAP    AuthenticationMethod = "ldap"
)

// ExternalSubject is immutable provider-qualified identity material. Its
// formatting methods never expose issuer or subject values.
type ExternalSubject struct {
	Provider  identity.ProviderContext
	BindingID identity.EntityID
	Issuer    string `json:"-"`
	Value     string `json:"-"`
}

func (subject ExternalSubject) String() string {
	return "federatedauth.ExternalSubject{material:[REDACTED]}"
}
func (subject ExternalSubject) GoString() string { return subject.String() }

type ProfileValue struct {
	Field string
	Value string `json:"-"`
}

func (value ProfileValue) String() string   { return "federatedauth.ProfileValue{material:[REDACTED]}" }
func (value ProfileValue) GoString() string { return value.String() }

type NamedValue struct {
	Name  string
	Value string `json:"-"`
}

func (value NamedValue) String() string   { return "federatedauth.NamedValue{material:[REDACTED]}" }
func (value NamedValue) GoString() string { return value.String() }

// AuthenticationProjection is the protocol-neutral, non-authorizing input to
// the JIT/mapping planner.
type AuthenticationProjection struct {
	Protocol        Protocol
	TenantID        identity.EntityID
	Admission       identity.TenantAdmissionContext
	Subject         ExternalSubject
	AuthenticatedAt time.Time
	ValidUntil      time.Time
	Scalars         []NamedValue
	Profiles        []ProfileValue
	Groups          []string `json:"-"`
	Evidence        []identity.AssuranceEvidence
	OIDCCompletion  *federatedoidc.TransactionCompletion
	SAMLConsumption *federatedsaml.ConsumptionRequest
	Passkey         *webauthn.AuthenticationArtifact
}

func (projection AuthenticationProjection) String() string {
	return fmt.Sprintf("federatedauth.AuthenticationProjection{protocol:%s,groups:%d,material:[REDACTED]}",
		projection.Protocol, len(projection.Groups))
}
func (projection AuthenticationProjection) GoString() string { return projection.String() }

// PlanningRequest must be resolved under tenant RLS but performs no mutation.
// The apply port rechecks every returned revision atomically.
type PlanningRequest struct {
	Authentication AuthenticationProjection
	Action         string
}

func (request PlanningRequest) String() string {
	return fmt.Sprintf(
		"federatedauth.PlanningRequest{protocol:%s,action:%t,material:[REDACTED]}",
		request.Authentication.Protocol, request.Action != "",
	)
}
func (request PlanningRequest) GoString() string { return request.String() }

type AuthenticationPlan struct {
	PlanRevision          uint64
	TenantID              identity.EntityID
	UserID                identity.EntityID // zero only for a collision-safe first JIT
	IdentityEpoch         uint64
	ProviderRevision      uint64
	BindingRevision       uint64
	ConfigurationRevision uint64
	SecurityRevision      uint64
	MappingRevision       uint64
	AuthorizationRevision uint64
	PolicyRevision        uint64
	RoleIDs               []identity.EntityID
	SecurityGroupIDs      []identity.EntityID
	Subject               *ProtectedFederatedSubject
	Mapping               *identity.FederatedMappingPlan
	Requirement           identity.EffectiveAssuranceRequirement
	HasEnrollableFactor   bool
}

func (plan AuthenticationPlan) String() string {
	return fmt.Sprintf(
		"federatedauth.AuthenticationPlan{planRevision:%t,user:%t,identityEpoch:%t,providerRevision:%t,bindingRevision:%t,configurationRevision:%t,securityRevision:%t,mappingRevision:%t,authorizationRevision:%t,policyRevision:%t,roles:%d,groups:%d,subject:%t,mapping:%t,material:[REDACTED]}",
		plan.PlanRevision != 0, plan.UserID != (identity.EntityID{}), plan.IdentityEpoch != 0,
		plan.ProviderRevision != 0, plan.BindingRevision != 0, plan.ConfigurationRevision != 0,
		plan.SecurityRevision != 0, plan.MappingRevision != 0, plan.AuthorizationRevision != 0,
		plan.PolicyRevision != 0, len(plan.RoleIDs), len(plan.SecurityGroupIDs), plan.Subject != nil,
		plan.Mapping != nil,
	)
}
func (plan AuthenticationPlan) GoString() string { return plan.String() }

// ProtectedFederatedSubject is the only immutable-subject representation
// passed to persistence. It contains purpose-separated aliases and an
// authenticated envelope, never raw issuer or subject strings.
type ProtectedFederatedSubject struct {
	ExternalIdentityID identity.EntityID
	Aliases            []identity.SubjectAlias
	Envelope           identity.ExternalSubjectEnvelope
}

func (subject ProtectedFederatedSubject) String() string {
	return fmt.Sprintf(
		"federatedauth.ProtectedFederatedSubject{identity:%t,aliases:%d,envelope:%q,material:[REDACTED]}",
		subject.ExternalIdentityID != (identity.EntityID{}), len(subject.Aliases), subject.Envelope.String(),
	)
}
func (subject ProtectedFederatedSubject) GoString() string { return subject.String() }

// Planner performs bounded identity lookup/mapping and policy resolution. It
// does not create a User or membership.
type Planner interface {
	PlanFederatedAuthentication(context.Context, PlanningRequest) (AuthenticationPlan, error)
}

// OIDCTrustResolver translates exact provider/binding AMR values through one
// immutable configured trust rule set. It never treats an AMR string as
// universal assurance.
type OIDCTrustResolver interface {
	ResolveOIDCAssurance(context.Context, OIDCTrustRequest) ([]identity.AssuranceEvidence, error)
}

type OIDCTrustRequest struct {
	TenantID                identity.EntityID
	Admission               identity.TenantAdmissionContext
	Provider                identity.ProviderContext
	BindingID               identity.EntityID
	ProviderRevision        uint64
	BindingRevision         uint64
	SecurityRevision        uint64
	AssurancePolicyRevision uint64
	AuthenticatedAt         time.Time
	ValidUntil              time.Time
	ACR                     string   `json:"-"`
	AMR                     []string `json:"-"`
}

func (request OIDCTrustRequest) String() string {
	return fmt.Sprintf(
		"federatedauth.OIDCTrustRequest{providerRevision:%t,bindingRevision:%t,securityRevision:%t,policyRevision:%t,acr:%t,amr:%d,material:[REDACTED]}",
		request.ProviderRevision != 0, request.BindingRevision != 0, request.SecurityRevision != 0,
		request.AssurancePolicyRevision != 0, request.ACR != "", len(request.AMR),
	)
}
func (request OIDCTrustRequest) GoString() string { return request.String() }

type ApplyDisposition string

const (
	ApplySession      ApplyDisposition = "session"
	ApplyContinuation ApplyDisposition = "continuation"
)

type ApplyRequest struct {
	Authentication ApplyAuthenticationProjection
	Plan           AuthenticationPlan
	Disposition    ApplyDisposition
	Assurance      identity.AssuranceDecision
	AppliedAt      time.Time
	Session        mfa.SessionReservation
	Continuation   PostPrimaryContinuationReservation
}

func (request ApplyRequest) String() string {
	return fmt.Sprintf(
		"federatedauth.ApplyRequest{protocol:%s,disposition:%s,assurance:%s,applied:%t,plan:%q,material:[REDACTED]}",
		request.Authentication.Protocol, request.Disposition, request.Assurance,
		!request.AppliedAt.IsZero(), request.Plan.String(),
	)
}
func (request ApplyRequest) GoString() string { return request.String() }

// ApplyAuthenticationProjection is the protocol evidence needed by the
// transactional persistence boundary. OIDC issuer, subject, profile, scalar,
// and group claim values are deliberately absent: immutable identity is
// carried only by AuthenticationPlan.Subject and mapped profile consequences
// only by AuthenticationPlan.Mapping.
type ApplyAuthenticationProjection struct {
	Protocol        Protocol
	Method          AuthenticationMethod
	TenantID        identity.EntityID
	Admission       identity.TenantAdmissionContext
	AuthenticatedAt time.Time
	ValidUntil      time.Time
	Evidence        []identity.AssuranceEvidence
	OIDCCompletion  *federatedoidc.TransactionCompletion
	SAMLConsumption *federatedsaml.ConsumptionRequest
	Passkey         *webauthn.AuthenticationArtifact
}

func (projection ApplyAuthenticationProjection) String() string {
	return fmt.Sprintf(
		"federatedauth.ApplyAuthenticationProjection{protocol:%s,method:%s,evidence:%d,material:[REDACTED]}",
		projection.Protocol, projection.Method, len(projection.Evidence),
	)
}
func (projection ApplyAuthenticationProjection) GoString() string { return projection.String() }

type ApplyCategory string

const (
	ApplySuccess   ApplyCategory = "success"
	ApplyReplay    ApplyCategory = "replay"
	ApplyStale     ApplyCategory = "stale"
	ApplyCollision ApplyCategory = "identity_collision"
	ApplyDenied    ApplyCategory = "denied"
)

type ApplyResult struct {
	Category       ApplyCategory
	UserID         identity.EntityID
	SessionID      identity.EntityID
	ContinuationID identity.EntityID
	ReturnPath     string
	Replayed       bool
	Credential     *BrowserCredential
}

func (result ApplyResult) String() string {
	return fmt.Sprintf("federatedauth.ApplyResult{category:%s,return_path:[REDACTED]}", result.Category)
}
func (result ApplyResult) GoString() string { return result.String() }

// TransactionalApplier must, in one short transaction, recheck every plan and
// protocol pin, collision-safe JIT the provider-qualified subject, reconcile
// source-owned mappings, consume replay artifacts, create a continuation or
// session, and append redacted audit. An exact retry of the same request after
// a lost response must return the original result; divergent reuse of a
// protocol replay identifier must fail closed.
type TransactionalApplier interface {
	ApplyFederatedAuthentication(context.Context, ApplyRequest) (ApplyResult, error)
}

type SessionLookup struct {
	SessionID            identity.EntityID
	TenantID             identity.EntityID
	Audience             string
	AuthenticationMethod AuthenticationMethod
	ObservedAt           time.Time
}

type SessionProjection struct {
	Snapshot             mfa.SessionSnapshot
	Live                 mfa.LiveSessionProjection
	AuthenticationMethod AuthenticationMethod
}

type SessionMutation struct {
	SessionID            identity.EntityID
	TenantID             identity.EntityID
	UserID               identity.EntityID
	Audience             string
	AuthenticationMethod AuthenticationMethod
	ExpectedVersion      uint64
	ObservedAt           time.Time
	Decision             mfa.SessionDecision
	Reason               mfa.SessionReason
	Requirement          identity.EffectiveAssuranceRequirement
	Session              mfa.SessionReservation
	Continuation         PostPrimaryContinuationReservation
}

type SessionMutationResult struct {
	Applied        bool
	NewSessionID   identity.EntityID
	ContinuationID identity.EntityID
}

// SessionStore loads all live provenance before authority and atomically
// applies the exact decision against ExpectedVersion.
type SessionStore interface {
	LoadSessionForRevalidation(context.Context, SessionLookup) (SessionProjection, error)
	ApplySessionRevalidation(context.Context, SessionMutation) (SessionMutationResult, error)
}

type SessionResult struct {
	SessionID            identity.EntityID
	TenantID             identity.EntityID
	UserID               identity.EntityID
	AuthenticationMethod AuthenticationMethod
	Decision             mfa.SessionDecision
	Reason               mfa.SessionReason
	AllowAuthority       bool
	AllowIdleTouch       bool
	NewSessionID         identity.EntityID
	ContinuationID       identity.EntityID
	AbsoluteExpiresAt    time.Time
	Credential           *BrowserCredential
}

func (result SessionResult) String() string {
	return fmt.Sprintf("federatedauth.SessionResult{session:%t,tenant:%t,user:%t,method:%s,decision:%s,reason:%s,authority:%t,expiry:%t,credential:%t,material:[REDACTED]}",
		result.SessionID != (identity.EntityID{}), result.TenantID != (identity.EntityID{}),
		result.UserID != (identity.EntityID{}), result.AuthenticationMethod, result.Decision, result.Reason,
		result.AllowAuthority, !result.AbsoluteExpiresAt.IsZero(), result.Credential != nil)
}
func (result SessionResult) GoString() string { return result.String() }

// ProtectedToken is an encrypted keyring artifact and never formats its bytes.
type ProtectedToken struct {
	KeyVersion uint32
	Ciphertext []byte `json:"-"`
}

func (token ProtectedToken) String() string {
	return "federatedauth.ProtectedToken{material:[REDACTED]}"
}
func (token ProtectedToken) GoString() string { return token.String() }

type RefreshTokenContext struct {
	TenantID        identity.EntityID
	MaterialID      identity.EntityID
	SessionFamilyID identity.EntityID
	Provider        identity.ProviderContext
	BindingID       identity.EntityID
	Generation      uint64
}

type TokenProtector interface {
	OpenRefreshToken(context.Context, RefreshTokenContext, ProtectedToken) ([]byte, error)
	SealRefreshToken(context.Context, RefreshTokenContext, []byte) (ProtectedToken, error)
}

type ClientSecretContext struct {
	Provider  identity.ProviderContext
	Admission identity.TenantAdmissionContext
	// BindingID is the provider cryptographic binding. It remains zero for a
	// platform provider even when Admission selects one tenant binding.
	BindingID   identity.EntityID
	Revision    uint64
	Maintenance OIDCMaintenanceSecretProof
}

type OIDCMaintenanceSecretKind string

const (
	OIDCMaintenanceSecretRefresh     OIDCMaintenanceSecretKind = "refresh"
	OIDCMaintenanceSecretLogoutRetry OIDCMaintenanceSecretKind = "logout_retry"
)

// OIDCMaintenanceSecretProof binds historical secret access to one current,
// non-expired worker/API claim. A zero value is required on interactive login.
type OIDCMaintenanceSecretProof struct {
	Kind              OIDCMaintenanceSecretKind
	MaterialID        identity.EntityID
	SessionFamilyID   identity.EntityID
	ClaimVersion      uint64
	RefreshGeneration uint64
	JobID             identity.EntityID
	Attempt           int
}

type ClientSecretSource interface {
	// OpenOIDCClientSecret transfers ownership of a fresh plaintext slice to
	// the caller, which clears it immediately after constructing the exchange.
	OpenOIDCClientSecret(context.Context, ClientSecretContext) ([]byte, error)
}

type RefreshClaimCategory string

const (
	RefreshClaimed RefreshClaimCategory = "claimed"
	RefreshReuse   RefreshClaimCategory = "reuse"
	RefreshStale   RefreshClaimCategory = "stale"
	// RefreshBusy is the idempotent result for the same generation and digest
	// while another worker still owns the live claim lease. It is not evidence
	// of post-rotation reuse and must never revoke the session family.
	RefreshBusy RefreshClaimCategory = "busy"
)

type RefreshCommand struct {
	SessionFamilyID    identity.EntityID
	ExpectedGeneration uint64
	ExpectedDigest     [sha256.Size]byte
}

func (command RefreshCommand) String() string {
	return fmt.Sprintf("federatedauth.RefreshCommand{generation:%d,material:[REDACTED]}", command.ExpectedGeneration)
}

func (command RefreshCommand) GoString() string { return command.String() }

type RefreshSnapshot struct {
	Category RefreshClaimCategory
	// TenantID is the immutable material-origin tenant used for token AAD. It
	// remains zero when a direct-platform session later switches into a tenant.
	TenantID identity.EntityID
	// EffectiveTenantID is the current routing/audit tenant proven by the
	// persisted session lineage. It must never be used as token AAD.
	EffectiveTenantID     identity.EntityID
	MaterialID            identity.EntityID
	SessionFamilyID       identity.EntityID
	Generation            uint64
	Version               uint64
	Provider              identity.ProviderContext
	Admission             identity.TenantAdmissionContext
	BindingID             identity.EntityID
	ClientSecretRevision  uint64
	Endpoint              string `json:"-"`
	ClientAuthentication  federatedoidc.ClientAuthenticationMode
	ClientID              string
	Token                 ProtectedToken
	TokenDigest           [sha256.Size]byte
	ObservedAt            time.Time
	LeaseExpiresAt        time.Time
	MaterialExpiresAt     time.Time
	AbsoluteSessionExpiry time.Time
}

func (snapshot RefreshSnapshot) String() string {
	return fmt.Sprintf("federatedauth.RefreshSnapshot{category:%s,generation:%d,material:[REDACTED]}",
		snapshot.Category, snapshot.Generation)
}
func (snapshot RefreshSnapshot) GoString() string { return snapshot.String() }

type RefreshCompletionOutcome string

const (
	RefreshRotated     RefreshCompletionOutcome = "rotated"
	RefreshSafeToRetry RefreshCompletionOutcome = "safe_to_retry"
	RefreshAmbiguous   RefreshCompletionOutcome = "ambiguous"
	RefreshRejected    RefreshCompletionOutcome = "rejected"
)

type RefreshCompletion struct {
	TenantID            identity.EntityID
	EffectiveTenantID   identity.EntityID
	MaterialID          identity.EntityID
	SessionFamilyID     identity.EntityID
	ExpectedVersion     uint64
	ExpectedGeneration  uint64
	Outcome             RefreshCompletionOutcome
	SuccessorGeneration uint64
	SuccessorDigest     [sha256.Size]byte
	SuccessorToken      ProtectedToken
	AccessExpiresAt     time.Time
	CompletedAt         time.Time
}

func (completion RefreshCompletion) String() string {
	return "federatedauth.RefreshCompletion{material:[REDACTED]}"
}
func (completion RefreshCompletion) GoString() string { return completion.String() }

type RevocationReason string

const (
	RevokeRefreshReuse      RevocationReason = "refresh_reuse"
	RevokeRefreshFailure    RevocationReason = "refresh_failure"
	RevokeRefreshKeyFailure RevocationReason = "refresh_key_failure"
	RevokeSessionDrift      RevocationReason = "session_drift"
)

// RefreshStore Claim atomically transitions the exact generation to claimed.
// The same generation and digest under a live lease returns RefreshBusy;
// only a digest found in bounded consumed history returns RefreshReuse and
// revokes the family in that transaction.
type RefreshStore interface {
	ClaimRefreshRotation(context.Context, RefreshCommand, time.Time) (RefreshSnapshot, error)
	CompleteRefreshRotation(context.Context, RefreshCompletion) error
	RevokeSessionFamily(context.Context, identity.EntityID, RevocationReason, time.Time) error
}

type LogoutRetryJob struct {
	JobID                identity.EntityID
	TenantID             identity.EntityID
	MaterialID           identity.EntityID
	SessionFamilyID      identity.EntityID
	Attempt              int
	MaximumAttempts      int
	ClaimVersion         uint64
	LeaseExpiresAt       time.Time
	NotBefore            time.Time
	Provider             identity.ProviderContext
	Admission            identity.TenantAdmissionContext
	BindingID            identity.EntityID
	ClientSecretRevision uint64
	ClientAuthentication federatedoidc.ClientAuthenticationMode
	ClientID             string
	Endpoint             string `json:"-"`
	RefreshGeneration    uint64
	TokenDigest          [sha256.Size]byte
	MaterialExpiresAt    time.Time
	OpaqueReference      ProtectedToken
}

func (job LogoutRetryJob) String() string {
	return fmt.Sprintf("federatedauth.LogoutRetryJob{attempt:%d,material:[REDACTED]}", job.Attempt)
}
func (job LogoutRetryJob) GoString() string { return job.String() }

type LogoutRetryDisposition string

const (
	LogoutRetryComplete   LogoutRetryDisposition = "succeeded"
	LogoutRetryReschedule LogoutRetryDisposition = "safe_to_retry"
	LogoutRetryAmbiguous  LogoutRetryDisposition = "ambiguous"
	LogoutRetryRejected   LogoutRetryDisposition = "rejected"
)

type LogoutRetryUpdate struct {
	JobID           identity.EntityID
	Attempt         int
	ExpectedVersion uint64
	ObservedAt      time.Time
	NextTryAt       time.Time
	Disposition     LogoutRetryDisposition
}

type LogoutRetryStore interface {
	ClaimLogoutRetry(context.Context, identity.EntityID, time.Time) (LogoutRetryJob, error)
	CompleteLogoutRetry(context.Context, LogoutRetryUpdate) error
}

// LogoutRetryExecutor performs one already-pinned upstream action. A concrete
// implementation must use federatedhttp rather than an ambient client.
type LogoutRetryExecutor interface {
	ExecuteUpstreamLogoutRetry(context.Context, LogoutRetryJob) error
}

// OIDCLogoutMaterialSource decrypts one claimed retry reference under exact
// job/session associated data and returns no database handle or transaction.
type OIDCLogoutMaterialSource interface {
	OpenOIDCLogoutRetry(context.Context, LogoutRetryJob) (federatedoidc.StoredRevocationMaterial, error)
}

// OIDCLogoutRetryExecutor is the concrete network executor for OIDC
// revocation retry jobs.
type OIDCLogoutRetryExecutor struct {
	upstream *federatedoidc.UpstreamHTTP
	material OIDCLogoutMaterialSource
}

func NewOIDCLogoutRetryExecutor(
	upstream *federatedoidc.UpstreamHTTP,
	material OIDCLogoutMaterialSource,
) (*OIDCLogoutRetryExecutor, error) {
	if upstream == nil || material == nil {
		return nil, ErrInvalidOptions
	}
	return &OIDCLogoutRetryExecutor{upstream: upstream, material: material}, nil
}

func (executor *OIDCLogoutRetryExecutor) ExecuteUpstreamLogoutRetry(
	ctx context.Context,
	job LogoutRetryJob,
) error {
	if executor == nil || executor.upstream == nil || executor.material == nil || ctx == nil || ctx.Err() != nil ||
		!validLogoutJobShape(job, job.JobID) {
		return ErrUpstreamLogoutRetry
	}
	material, err := executor.material.OpenOIDCLogoutRetry(ctx, job)
	defer clear(material.Token)
	defer clear(material.ClientSecret)
	if err != nil {
		return ErrUpstreamLogoutRetry
	}
	if err := executor.upstream.RevokeStored(ctx, material); err != nil {
		return errors.Join(ErrUpstreamLogoutRetry, err)
	}
	return nil
}
