// Package platformsamlauth owns the application boundary for direct platform
// SAML authentication. It deliberately has no tenant, JIT-provisioning, role
// mapping, HTTP, or persistence implementation.
package platformsamlauth

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
)

const (
	ProviderKindSAML = "saml"
	DirectSAMLACSURL = "/api/v1/auth/platform/saml/acs"
	SessionAudience  = "api"
)

var (
	ErrInvalidOptions            = errors.New("invalid direct platform SAML options")
	ErrAuthenticationDenied      = errors.New("direct platform SAML authentication failed")
	ErrAuthenticationUnavailable = errors.New("direct platform SAML authentication unavailable")
)

// AuditContext is request-owned attribution. Adapters must persist these
// exact values and must never recover them from ambient context values.
type AuditContext struct {
	RequestID     identity.EntityID
	CorrelationID identity.EntityID
	RemoteAddress netip.Addr
	UserAgent     string `json:"-"`
}

func (audit AuditContext) String() string {
	return fmt.Sprintf(
		"platformsamlauth.AuditContext{request:%t,correlation:%t,remote:%t,userAgent:%t,material:[REDACTED]}",
		audit.RequestID != (identity.EntityID{}), audit.CorrelationID != (identity.EntityID{}),
		audit.RemoteAddress.IsValid(), audit.UserAgent != "",
	)
}

func (audit AuditContext) GoString() string { return audit.String() }

// DirectSAMLPins is the complete immutable direct-login authority. The
// protocol pins bind provider/configuration/security/metadata/SP-key/login,
// plan and assurance revisions. The two extra fields pin the independently
// stored platform MFA floor selected before redirect.
type DirectSAMLPins struct {
	Protocol                    federatedsaml.TransactionPins
	PlatformFloorPolicyID       identity.EntityID
	PlatformFloorPolicyRevision uint64
}

func (pins DirectSAMLPins) String() string {
	return fmt.Sprintf(
		"platformsamlauth.DirectSAMLPins{protocol:%q,floor:%t,floorRevision:%t,digests:[REDACTED]}",
		pins.Protocol.String(), pins.PlatformFloorPolicyID != (identity.EntityID{}),
		pins.PlatformFloorPolicyRevision != 0,
	)
}

func (pins DirectSAMLPins) GoString() string { return pins.String() }

// StartLookup contains only purpose-separated anonymous admission material.
// LoginKey is a public provider locator, not an entity ID or metadata URL.
type StartLookup struct {
	Begin    federatedsaml.AuthenticationBegin
	LoginKey string
}

func (lookup StartLookup) String() string {
	return fmt.Sprintf(
		"platformsamlauth.StartLookup{operation:%t,loginKey:%t,digests:[REDACTED]}",
		lookup.Begin.OperationRunID != (identity.EntityID{}), lookup.LoginKey != "",
	)
}

func (lookup StartLookup) GoString() string { return lookup.String() }

type StartAuthority struct {
	Lookup     StartLookup
	ReturnPath string
	Audit      AuditContext
}

func (authority StartAuthority) String() string {
	return fmt.Sprintf(
		"platformsamlauth.StartAuthority{lookup:%q,returnPath:%t,audit:%q}",
		authority.Lookup.String(), authority.ReturnPath != "", authority.Audit.String(),
	)
}

func (authority StartAuthority) GoString() string { return authority.String() }

// StartGrant is the idempotent result of admitting one anonymous start. The
// transaction adapter must bind the complete grant, not only Protocol pins,
// when it creates the kernel transaction.
type StartGrant struct {
	Authority StartAuthority
	Pins      DirectSAMLPins
}

func (grant StartGrant) String() string {
	return fmt.Sprintf("platformsamlauth.StartGrant{authority:%q,pins:%q}", grant.Authority.String(), grant.Pins.String())
}

func (grant StartGrant) GoString() string { return grant.String() }

type StartSource interface {
	BeginDirectSAMLLogin(context.Context, StartAuthority) (StartGrant, error)
}

// ConfigurationSnapshot is store-owned. SPEntityID and Metadata are loaded
// from the provider projection and are never derived from an HTTP route.
type ConfigurationSnapshot struct {
	Pins           DirectSAMLPins
	ProviderKind   string
	Authentication federatedsaml.Configuration
}

func (snapshot ConfigurationSnapshot) String() string {
	return fmt.Sprintf(
		"platformsamlauth.ConfigurationSnapshot{pins:%q,providerKind:%q,authentication:%q}",
		snapshot.Pins.String(), snapshot.ProviderKind, snapshot.Authentication.String(),
	)
}

func (snapshot ConfigurationSnapshot) GoString() string { return snapshot.String() }

type StartConfigurationSnapshot struct {
	Grant         StartGrant
	Configuration ConfigurationSnapshot
}

type CallbackConfigurationLookup struct {
	Transaction federatedsaml.CallbackConfigurationLookup
}

func (lookup CallbackConfigurationLookup) String() string {
	return fmt.Sprintf("platformsamlauth.CallbackConfigurationLookup{transaction:%q}", lookup.Transaction.String())
}

func (lookup CallbackConfigurationLookup) GoString() string { return lookup.String() }

type CallbackConfigurationSnapshot struct {
	Lookup        CallbackConfigurationLookup
	Configuration ConfigurationSnapshot
}

type ConfigurationSource interface {
	// LoadDirectSAMLStartConfiguration must return the provider projection
	// selected by the exact admitted grant. ResolveDirectSAMLCallbackConfiguration
	// must return the complete DirectSAMLPins persisted with that transaction at
	// start; reconstructing platform-floor pins from current live state is not
	// admissible. SPEntityID remains provider-specific store data in both paths.
	LoadDirectSAMLStartConfiguration(context.Context, StartGrant) (StartConfigurationSnapshot, error)
	ResolveDirectSAMLCallbackConfiguration(context.Context, CallbackConfigurationLookup) (CallbackConfigurationSnapshot, error)
}

// StartProtocolRequest couples the kernel request with the complete start
// grant. A persistence adapter must bind the platform-floor pins in the same
// transaction as federatedsaml.TransactionRepository.CreateReplacing.
type StartProtocolRequest struct {
	Protocol federatedsaml.StartRequest
	Grant    StartGrant
}

// AuthorizationStart is the redacted application projection of the kernel
// start result. NewAuthorizationStart is the only production conversion; a
// ProtocolPort must not synthesize any field from provider routes.
type AuthorizationStart struct {
	transactionID federatedsaml.TransactionID
	redirectURL   string
	material      *authorizationStartMaterial
	expiresAt     time.Time
}

func NewAuthorizationStart(start federatedsaml.AuthorizationStart) (AuthorizationStart, error) {
	handle := start.BrowserHandle()
	result := AuthorizationStart{
		transactionID: start.TransactionID(), redirectURL: start.RedirectURL(),
		material: newAuthorizationStartMaterial(handle), expiresAt: start.ExpiresAt(),
	}
	if !validAuthorizationStartShape(result) {
		result.Destroy()
		return AuthorizationStart{}, ErrAuthenticationDenied
	}
	return result, nil
}

func (start AuthorizationStart) TransactionID() federatedsaml.TransactionID {
	return start.transactionID
}
func (start AuthorizationStart) RedirectURL() string { return start.redirectURL }
func (start AuthorizationStart) BrowserHandle() []byte {
	if start.material == nil {
		return nil
	}
	return start.material.copy()
}
func (start AuthorizationStart) ExpiresAt() time.Time { return start.expiresAt }

func (start AuthorizationStart) String() string {
	return fmt.Sprintf(
		"platformsamlauth.AuthorizationStart{transaction:%t,redirect:%t,browser:%t,expires:%t,material:[REDACTED]}",
		start.transactionID != (federatedsaml.TransactionID{}), start.redirectURL != "",
		start.material != nil && start.material.present(), !start.expiresAt.IsZero(),
	)
}

func (start AuthorizationStart) GoString() string { return start.String() }

type CallbackRequest struct {
	Protocol federatedsaml.ResolvedCallbackRequest
	Audit    AuditContext
}

func (request CallbackRequest) String() string {
	return fmt.Sprintf(
		"platformsamlauth.CallbackRequest{protocol:%q,audit:%q,material:[REDACTED]}",
		request.Protocol.String(), request.Audit.String(),
	)
}

func (request CallbackRequest) GoString() string { return request.String() }

// AuthenticationProof is a defensive application projection of the opaque
// kernel result. SubjectValue and logout material remain redacted and are
// never returned by this package.
type AuthenticationProof struct {
	Issuer          string
	SubjectSource   federatedsaml.SubjectSource
	SubjectName     string
	SubjectFormat   string
	SubjectValue    string `json:"-"`
	Scalars         []federatedsaml.NamedScalar
	Profiles        []federatedsaml.ProfileValue
	Groups          []string `json:"-"`
	AuthnContext    string
	AuthenticatedAt time.Time
	ValidUntil      time.Time
	SessionMaterial federatedsaml.SessionMaterial `json:"-"`
}

func (proof AuthenticationProof) String() string {
	return fmt.Sprintf(
		"platformsamlauth.AuthenticationProof{issuer:%t,source:%q,name:%t,format:%t,scalars:%d,profiles:%d,groups:%d,authnContext:%t,authenticated:%t,validUntil:%t,sessionMaterial:%q,subject:[REDACTED]}",
		proof.Issuer != "", proof.SubjectSource, proof.SubjectName != "", proof.SubjectFormat != "",
		len(proof.Scalars), len(proof.Profiles), len(proof.Groups), proof.AuthnContext != "",
		!proof.AuthenticatedAt.IsZero(), !proof.ValidUntil.IsZero(), proof.SessionMaterial.String(),
	)
}

func (proof AuthenticationProof) GoString() string { return proof.String() }

// ValidatedCallback couples an opaque one-use kernel handle to the exact
// proof observed before consumption. Only the protocol adapter should call
// KernelAuthentication; the application rechecks the proof supplied at
// consumption before any planning or apply.
type ValidatedCallback struct {
	kernel      *federatedsaml.ValidatedAuthentication
	transaction CallbackConfigurationLookup
	proof       AuthenticationProof
}

func NewValidatedCallback(
	authentication *federatedsaml.ValidatedAuthentication,
	transaction federatedsaml.CallbackConfigurationLookup,
) (*ValidatedCallback, error) {
	lookup := CallbackConfigurationLookup{Transaction: transaction}
	if authentication == nil || !validCallbackConfigurationLookup(lookup) {
		return nil, ErrAuthenticationDenied
	}
	proof := authenticationProofFromJIT(authentication.JIT())
	if !validProofShape(proof) {
		return nil, ErrAuthenticationDenied
	}
	return &ValidatedCallback{kernel: authentication, transaction: lookup, proof: proof}, nil
}

func (callback *ValidatedCallback) KernelAuthentication() *federatedsaml.ValidatedAuthentication {
	if callback == nil {
		return nil
	}
	return callback.kernel
}

// Transaction identifies the exact persisted callback claim and lets the
// protocol adapter durably terminalize a validated attempt on every later
// failure without retaining an out-of-band pointer map.
func (callback *ValidatedCallback) Transaction() CallbackConfigurationLookup {
	if callback == nil {
		return CallbackConfigurationLookup{}
	}
	return callback.transaction
}

func (callback *ValidatedCallback) String() string {
	return fmt.Sprintf(
		"platformsamlauth.ValidatedCallback{kernel:%t,transaction:%t,proof:%q}",
		callback != nil && callback.kernel != nil,
		callback != nil && validCallbackConfigurationLookup(callback.transaction), callbackProof(callback).String(),
	)
}

func (callback *ValidatedCallback) GoString() string { return callback.String() }

// Consumption is the exact kernel request passed to the application consumer.
// ResponseID, AssertionID and SessionIndexDigest are persisted as independent
// provider-qualified replay keys by AtomicApplyPort.
type Consumption struct {
	TransactionID      federatedsaml.TransactionID
	MaterialID         identity.EntityID
	ExpectedVersion    uint64
	Pins               federatedsaml.TransactionPins
	ResponseID         string
	AssertionID        string
	SessionIndexDigest [sha256.Size]byte
	HasSessionIndex    bool
	ConsumedAt         time.Time
	ReturnPath         string
	Authentication     AuthenticationProof
}

func NewConsumption(request federatedsaml.ConsumptionRequest) (Consumption, error) {
	consumption := Consumption{
		TransactionID: request.TransactionID, MaterialID: request.MaterialID,
		ExpectedVersion: request.ExpectedVersion, Pins: request.Pins,
		ResponseID: request.ResponseID, AssertionID: request.AssertionID,
		SessionIndexDigest: request.SessionIndexDigest, HasSessionIndex: request.HasSessionIndex,
		ConsumedAt: request.ConsumedAt, ReturnPath: request.ReturnPath,
		Authentication: authenticationProofFromJIT(request.Authentication),
	}
	if !validConsumptionShape(consumption) {
		return Consumption{}, ErrAuthenticationDenied
	}
	return consumption, nil
}

func (consumption Consumption) String() string {
	return fmt.Sprintf(
		"platformsamlauth.Consumption{transaction:%t,material:%t,version:%t,pins:%q,response:%t,assertion:%t,sessionIndex:%t,consumed:%t,returnPath:%t,authentication:%q,replay:[REDACTED]}",
		consumption.TransactionID != (federatedsaml.TransactionID{}), consumption.MaterialID != (identity.EntityID{}),
		consumption.ExpectedVersion != 0, consumption.Pins.String(), consumption.ResponseID != "",
		consumption.AssertionID != "", consumption.HasSessionIndex, !consumption.ConsumedAt.IsZero(),
		consumption.ReturnPath != "", consumption.Authentication.String(),
	)
}

func (consumption Consumption) GoString() string { return consumption.String() }

type Consumer interface {
	ConsumeDirectSAML(context.Context, Consumption) (federatedsaml.ConsumptionResult, error)
}

// ProtocolPort is implemented by the future kernel/transaction adapter. It
// must bridge only a federatedsaml Kernel configured with
// DirectPlatformCeremonyAuthority. Abort is idempotent and must terminalize a
// validated attempt which did not reach a successful atomic apply. Resolver
// and consumer callbacks are synchronous, one-use capabilities: an adapter
// must neither retain them nor invoke them after its method returns.
type ProtocolPort interface {
	StartDirectSAML(context.Context, StartProtocolRequest) (AuthorizationStart, error)
	ValidateDirectSAMLCallbackResolved(context.Context, CallbackRequest, federatedsaml.CallbackConfigurationResolver) (*ValidatedCallback, error)
	ConsumeDirectSAML(context.Context, *ValidatedCallback, Consumer) (federatedsaml.ConsumptionResult, error)
	AbortDirectSAMLCallback(context.Context, *ValidatedCallback, AuditContext) error
}

type IdentityMatch struct {
	ProviderID                     identity.EntityID
	ExternalIdentityID             identity.EntityID
	UserID                         identity.EntityID
	Alias                          identity.SubjectAlias
	IdentityRevision               uint64
	UserAuthenticationRevision     uint64
	PlatformAuthorityID            identity.EntityID
	PlatformAuthorityRevision      uint64
	IdentityLive                   bool
	AliasLive                      bool
	UserActive                     bool
	ProtectedPlatformAuthorityLive bool
}

func (match IdentityMatch) String() string {
	return fmt.Sprintf(
		"platformsamlauth.IdentityMatch{provider:%t,identity:%t,user:%t,alias:%q,identityRevision:%t,userAuthenticationRevision:%t,platformAuthority:%t,platformAuthorityRevision:%t,live:%t}",
		match.ProviderID != (identity.EntityID{}), match.ExternalIdentityID != (identity.EntityID{}),
		match.UserID != (identity.EntityID{}), match.Alias.String(), match.IdentityRevision != 0,
		match.UserAuthenticationRevision != 0, match.PlatformAuthorityID != (identity.EntityID{}),
		match.PlatformAuthorityRevision != 0, match.IdentityLive && match.AliasLive && match.UserActive && match.ProtectedPlatformAuthorityLive,
	)
}

func (match IdentityMatch) GoString() string { return match.String() }

type TrustRule struct {
	RuleID                   identity.EntityID
	Revision                 uint64
	Enabled                  bool
	ClassRef                 string
	Level                    identity.AssuranceLevel
	MaximumAuthenticationAge time.Duration
}

func (rule TrustRule) String() string {
	return fmt.Sprintf(
		"platformsamlauth.TrustRule{id:%t,revision:%t,enabled:%t,classRef:%t,level:%d,maxAge:%s}",
		rule.RuleID != (identity.EntityID{}), rule.Revision != 0, rule.Enabled, rule.ClassRef != "", rule.Level,
		rule.MaximumAuthenticationAge,
	)
}

func (rule TrustRule) GoString() string { return rule.String() }

type TOTPFactor struct {
	FactorID    identity.EntityID
	UserID      identity.EntityID
	Revision    uint64
	Active      bool
	ConfirmedAt *time.Time
}

type PlanningLookup struct {
	TransactionID  federatedsaml.TransactionID
	ObservedAt     time.Time
	Pins           DirectSAMLPins
	SubjectFormat  identity.SubjectFormat
	SubjectAliases []identity.SubjectAlias
}

func (lookup PlanningLookup) String() string {
	return fmt.Sprintf(
		"platformsamlauth.PlanningLookup{transaction:%t,observed:%t,pins:%q,subjectFormat:%d,aliases:%d,subject:[REDACTED]}",
		lookup.TransactionID != (federatedsaml.TransactionID{}), !lookup.ObservedAt.IsZero(), lookup.Pins.String(),
		lookup.SubjectFormat, len(lookup.SubjectAliases),
	)
}

func (lookup PlanningLookup) GoString() string { return lookup.String() }

type PlanningState struct {
	Pins                     DirectSAMLPins
	ProviderKind             string
	ProviderEnabled          bool
	PlatformLoginLive        bool
	ConfigurationLive        bool
	AssurancePolicyLive      bool
	Matches                  []IdentityMatch
	TrustRules               []TrustRule
	PlatformFloor            identity.EffectiveAssuranceRequirement
	LiveConfirmedTOTPFactors []TOTPFactor
}

func (state PlanningState) String() string {
	return fmt.Sprintf(
		"platformsamlauth.PlanningState{pins:%q,providerKind:%q,live:%t,matches:%d,trustRules:%d,floorPolicies:%d,totpFactors:%d}",
		state.Pins.String(), state.ProviderKind,
		state.ProviderEnabled && state.PlatformLoginLive && state.ConfigurationLive && state.AssurancePolicyLive,
		len(state.Matches), len(state.TrustRules), len(state.PlatformFloor.PolicyRevisions), len(state.LiveConfirmedTOTPFactors),
	)
}

func (state PlanningState) GoString() string { return state.String() }

type PlanningStateSource interface {
	LoadDirectSAMLPlanningState(context.Context, PlanningLookup) (PlanningState, error)
}

type Disposition string

const (
	ImmediateSession Disposition = "immediate_session"
	TOTPContinuation Disposition = "totp_continuation"
)

type SelectedAssurance struct {
	Level             identity.AssuranceLevel
	AuthenticatedAt   time.Time
	TrustRuleID       *identity.EntityID
	TrustRuleRevision *uint64
}

func (assurance SelectedAssurance) String() string {
	return fmt.Sprintf(
		"platformsamlauth.SelectedAssurance{level:%d,authenticated:%t,trustRule:%t,trustRevision:%t}",
		assurance.Level, !assurance.AuthenticatedAt.IsZero(), assurance.TrustRuleID != nil,
		assurance.TrustRuleRevision != nil,
	)
}

func (assurance SelectedAssurance) GoString() string { return assurance.String() }

type SubjectObservation struct {
	ExternalIdentityID identity.EntityID
	SubjectFormat      identity.SubjectFormat
	Aliases            []identity.SubjectAlias
	Envelope           identity.ExternalSubjectEnvelope
}

func (subject SubjectObservation) String() string {
	return fmt.Sprintf(
		"platformsamlauth.SubjectObservation{identity:%t,format:%d,aliases:%d,envelope:%q,subject:[REDACTED]}",
		subject.ExternalIdentityID != (identity.EntityID{}), subject.SubjectFormat, len(subject.Aliases), subject.Envelope.String(),
	)
}

func (subject SubjectObservation) GoString() string { return subject.String() }

type TOTPSelection struct {
	FactorID identity.EntityID
	Revision uint64
}

type Provenance struct {
	Provider                   identity.ProviderContext
	ProviderKind               string
	ExternalIdentityID         identity.EntityID
	UserID                     identity.EntityID
	IdentityRevision           uint64
	UserAuthenticationRevision uint64
	PlatformAuthorityID        identity.EntityID
	PlatformAuthorityRevision  uint64
	MatchedAliasKeyVersion     int16
	Issuer                     string `json:"-"`
	AuthnContext               string
	AuthenticatedAt            time.Time
	ValidUntil                 time.Time
	SelectedAssurance          SelectedAssurance
}

func (provenance Provenance) String() string {
	return fmt.Sprintf(
		"platformsamlauth.Provenance{provider:%t,providerKind:%q,identity:%t,user:%t,identityRevision:%t,userAuthenticationRevision:%t,platformAuthority:%t,platformAuthorityRevision:%t,aliasVersion:%t,issuer:%t,authnContext:%t,authenticated:%t,validUntil:%t,assurance:%q,subject:[REDACTED]}",
		provenance.Provider.ProviderID != (identity.EntityID{}), provenance.ProviderKind,
		provenance.ExternalIdentityID != (identity.EntityID{}), provenance.UserID != (identity.EntityID{}),
		provenance.IdentityRevision != 0, provenance.UserAuthenticationRevision != 0,
		provenance.PlatformAuthorityID != (identity.EntityID{}), provenance.PlatformAuthorityRevision != 0,
		provenance.MatchedAliasKeyVersion > 0, provenance.Issuer != "", provenance.AuthnContext != "",
		!provenance.AuthenticatedAt.IsZero(), !provenance.ValidUntil.IsZero(), provenance.SelectedAssurance.String(),
	)
}

func (provenance Provenance) GoString() string { return provenance.String() }

type AuthenticationPlan struct {
	Disposition   Disposition
	Pins          DirectSAMLPins
	Provenance    Provenance
	Subject       SubjectObservation
	Evidence      []identity.AssuranceEvidence
	PlatformFloor identity.EffectiveAssuranceRequirement
	TOTP          *TOTPSelection
}

func (plan AuthenticationPlan) String() string {
	return fmt.Sprintf(
		"platformsamlauth.AuthenticationPlan{disposition:%q,pins:%q,provenance:%q,subject:%q,evidence:%d,floorPolicies:%d,totp:%t}",
		plan.Disposition, plan.Pins.String(), plan.Provenance.String(), plan.Subject.String(),
		len(plan.Evidence), len(plan.PlatformFloor.PolicyRevisions), plan.TOTP != nil,
	)
}

func (plan AuthenticationPlan) GoString() string { return plan.String() }

type ProtectedSessionMaterial struct {
	Envelope identity.SAMLSessionMaterialEnvelope
}

func (material ProtectedSessionMaterial) String() string {
	return fmt.Sprintf("platformsamlauth.ProtectedSessionMaterial{envelope:%q,material:[REDACTED]}", material.Envelope.String())
}

func (material ProtectedSessionMaterial) GoString() string { return material.String() }

// ConsumptionAuthority is the replay/CAS projection allowed to cross the
// atomic persistence boundary. It deliberately excludes AuthenticationProof,
// so plaintext issuer subject material and AuthnContext inputs cannot enter an
// apply or reject request.
type ConsumptionAuthority struct {
	TransactionID      federatedsaml.TransactionID
	MaterialID         identity.EntityID
	ExpectedVersion    uint64
	Pins               federatedsaml.TransactionPins
	ResponseID         string
	AssertionID        string
	SessionIndexDigest [sha256.Size]byte
	HasSessionIndex    bool
	HasSessionMaterial bool
	ConsumedAt         time.Time
	ReturnPath         string
}

func (authority ConsumptionAuthority) String() string {
	return fmt.Sprintf(
		"platformsamlauth.ConsumptionAuthority{transaction:%t,material:%t,version:%t,pins:%q,response:%t,assertion:%t,sessionIndex:%t,sessionMaterial:%t,consumed:%t,returnPath:%t,replay:[REDACTED]}",
		authority.TransactionID != (federatedsaml.TransactionID{}), authority.MaterialID != (identity.EntityID{}),
		authority.ExpectedVersion != 0, authority.Pins.String(), authority.ResponseID != "", authority.AssertionID != "",
		authority.HasSessionIndex, authority.HasSessionMaterial, !authority.ConsumedAt.IsZero(), authority.ReturnPath != "",
	)
}

func (authority ConsumptionAuthority) GoString() string { return authority.String() }

type ApplyRequest struct {
	Authority                ConsumptionAuthority
	Plan                     AuthenticationPlan
	Session                  mfa.SessionReservation
	Continuation             ContinuationReservation
	SessionAudience          string
	RecoveryRestricted       bool
	ProtectedSessionMaterial ProtectedSessionMaterial
	AppliedAt                time.Time
	Audit                    AuditContext
	ProofDigest              [sha256.Size]byte
}

func (request ApplyRequest) String() string {
	return fmt.Sprintf(
		"platformsamlauth.ApplyRequest{authority:%q,plan:%q,session:%t,continuation:%t,audience:%q,recoveryRestricted:%t,sessionMaterial:%q,applied:%t,audit:%q,proof:[REDACTED]}",
		request.Authority.String(), request.Plan.String(), !request.Session.IsZero(), !request.Continuation.IsZero(),
		request.SessionAudience, request.RecoveryRestricted, request.ProtectedSessionMaterial.String(),
		!request.AppliedAt.IsZero(), request.Audit.String(),
	)
}

func (request ApplyRequest) GoString() string { return request.String() }

type ApplyCategory string

const (
	ApplySuccess        ApplyCategory = "success"
	ApplyAlreadyApplied ApplyCategory = "already_applied"
	ApplyProtocolReplay ApplyCategory = "protocol_replay"
	ApplyStale          ApplyCategory = "stale"
	ApplyCollision      ApplyCategory = "collision"
	ApplyDenied         ApplyCategory = "denied"
)

type ApplyResult struct {
	Category       ApplyCategory
	TransactionID  federatedsaml.TransactionID
	ProofDigest    [sha256.Size]byte
	UserID         identity.EntityID
	SessionID      identity.EntityID
	ContinuationID identity.EntityID
	ReturnPath     string
	AppliedAt      time.Time
}

func (result ApplyResult) String() string {
	return fmt.Sprintf(
		"platformsamlauth.ApplyResult{category:%q,transaction:%t,user:%t,session:%t,continuation:%t,returnPath:%t,applied:%t,proof:[REDACTED]}",
		result.Category, result.TransactionID != (federatedsaml.TransactionID{}), result.UserID != (identity.EntityID{}),
		result.SessionID != (identity.EntityID{}), result.ContinuationID != (identity.EntityID{}),
		result.ReturnPath != "", !result.AppliedAt.IsZero(),
	)
}

func (result ApplyResult) GoString() string { return result.String() }

type RecoveryLookup struct {
	Request ApplyRequest
}

type RecoveryResult struct {
	Matched bool
	Result  ApplyResult
}

type RejectReason string

const (
	RejectMalformed   RejectReason = "malformed"
	RejectDenied      RejectReason = "denied"
	RejectStale       RejectReason = "stale"
	RejectCollision   RejectReason = "collision"
	RejectUnavailable RejectReason = "unavailable"
)

type RejectRequest struct {
	Authority  ConsumptionAuthority
	Reason     RejectReason
	RejectedAt time.Time
	Audit      AuditContext
}

type CleanupReason string

const (
	CleanupCredentialReleaseFailed CleanupReason = "credential_release_failed"
	CleanupProtocolFailed          CleanupReason = "protocol_failed"
	CleanupInvalidOutcome          CleanupReason = "invalid_outcome"
	CleanupDeliveryFailed          CleanupReason = "delivery_failed"
)

// CleanupRequest compensates only an exact application result already proved
// committed. The adapter must atomically revoke the new session or consume the
// continuation, terminalize the SAML command, and append a stable audit event.
type CleanupRequest struct {
	Result      ApplyResult
	Reason      CleanupReason
	CleanedUpAt time.Time
	Audit       AuditContext
}

func (request CleanupRequest) String() string {
	return fmt.Sprintf(
		"platformsamlauth.CleanupRequest{result:%q,reason:%q,cleaned:%t,audit:%q,proof:[REDACTED]}",
		request.Result.String(), request.Reason, !request.CleanedUpAt.IsZero(), request.Audit.String(),
	)
}

func (request CleanupRequest) GoString() string { return request.String() }

// AtomicApplyPort owns the future single database transaction. Apply must
// recheck every pin and every provenance revision, consume transaction and
// replay keys, persist only encrypted subject/logout material, append audit,
// and create exactly one tenantless session or purpose-specific continuation.
// It performs no external I/O. Exact retries return ApplyAlreadyApplied.
// CleanupDirectSAML is idempotent compensation for delivery failure after a
// successful Apply: an accepted cleanup leaves no active session or usable
// continuation behind, even when called repeatedly after an ambiguous result.
type AtomicApplyPort interface {
	ApplyDirectSAML(context.Context, ApplyRequest) (ApplyResult, error)
	RecoverDirectSAML(context.Context, RecoveryLookup) (RecoveryResult, error)
	RejectDirectSAML(context.Context, RejectRequest) error
	CleanupDirectSAML(context.Context, CleanupRequest) error
}

type Outcome struct {
	Disposition    Disposition
	UserID         identity.EntityID
	SessionID      identity.EntityID
	ContinuationID identity.EntityID
	ReturnPath     string
	Credential     *BrowserCredential
	delivery       *browserDeliveryAuthority
}

func (outcome Outcome) String() string {
	return fmt.Sprintf(
		"platformsamlauth.Outcome{disposition:%q,user:%t,session:%t,continuation:%t,returnPath:%t,credential:%t,material:[REDACTED]}",
		outcome.Disposition, outcome.UserID != (identity.EntityID{}), outcome.SessionID != (identity.EntityID{}),
		outcome.ContinuationID != (identity.EntityID{}), outcome.ReturnPath != "", outcome.Credential != nil && outcome.delivery != nil,
	)
}

func (outcome Outcome) GoString() string { return outcome.String() }
