package federatedoidc

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
	"net/netip"
	"sync/atomic"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedhttp"
)

const (
	transactionIDBytes  = 32
	opaqueArtifactBytes = 32

	minimumTransactionTTL    = time.Minute
	maximumTransactionTTL    = 15 * time.Minute
	minimumFlowTimeout       = 100 * time.Millisecond
	maximumFlowTimeout       = 2 * time.Minute
	maximumClockSkew         = 5 * time.Minute
	minimumTokenDuration     = time.Minute
	maximumTokenDuration     = 24 * time.Hour
	maximumAuthenticationAge = 30 * 24 * time.Hour

	minimumCallbackQueryBytes     = 128
	maximumCallbackQueryBytes     = 64 * 1024
	minimumTokenResponseBytes     = 1024
	maximumTokenResponseBytes     = 1024 * 1024
	minimumCompactTokenBytes      = 1024
	maximumCompactTokenBytes      = 1024 * 1024
	minimumTokenValueBytes        = 1024
	maximumTokenValueBytes        = 256 * 1024
	minimumClaimValueBytes        = 128
	maximumClaimValueBytes        = 64 * 1024
	minimumClaimCount             = 1
	maximumClaimCount             = 1024
	minimumGroupCount             = 1
	maximumGroupCount             = 4096
	minimumAMRCount               = 1
	maximumAMRCount               = 128
	maximumScopeCount             = 32
	maximumScopeBytes             = 128
	maximumClientIDBytes          = 512
	maximumClientSecretBytes      = 8 * 1024
	maximumAuthorizationCodeBytes = 4 * 1024
	maximumAuthorizationURLBytes  = 16 * 1024
	maximumReturnPathBytes        = 2 * 1024
	maximumProtectedVerifierBytes = 4 * 1024
)

var (
	ErrInvalidFlowOptions       = errors.New("invalid OIDC flow options")
	ErrAuthorizationRejected    = errors.New("OIDC authorization start rejected")
	ErrTransactionPersistence   = errors.New("OIDC transaction persistence failed")
	ErrCallbackRejected         = errors.New("OIDC callback rejected")
	ErrTokenExchangeFailed      = errors.New("OIDC token exchange failed")
	ErrTokenResponseRejected    = errors.New("OIDC token response rejected")
	ErrIDTokenRejected          = errors.New("OIDC ID token rejected")
	ErrJWKSRevisionRestart      = errors.New("OIDC JWKS revision restart required")
	ErrClaimExtractionRejected  = errors.New("OIDC claim extraction rejected")
	ErrUpstreamArtifactRejected = errors.New("OIDC upstream request artifact rejected")
)

// FlowLimits are deployment-owned resource ceilings for one OIDC ceremony.
type FlowLimits struct {
	MaxCallbackQueryBytes int
	MaxTokenResponseBytes int
	MaxCompactTokenBytes  int
	MaxTokenValueBytes    int
	MaxClaimValueBytes    int
	MaxScalarClaims       int
	MaxProfileClaims      int
	MaxGroups             int
	MaxAMRValues          int
}

func DefaultFlowLimits() FlowLimits {
	return FlowLimits{
		MaxCallbackQueryBytes: 16 * 1024,
		MaxTokenResponseBytes: 64 * 1024,
		MaxCompactTokenBytes:  128 * 1024,
		MaxTokenValueBytes:    16 * 1024,
		MaxClaimValueBytes:    4 * 1024,
		MaxScalarClaims:       16,
		MaxProfileClaims:      8,
		MaxGroups:             256,
		MaxAMRValues:          32,
	}
}

// FlowPolicy freezes transaction and token time policy. Clock skew never
// extends MaxTokenAge or MaxTokenLifetime.
type FlowPolicy struct {
	TransactionTTL       time.Duration
	OperationTimeout     time.Duration
	ClockSkew            time.Duration
	MaxTokenAge          time.Duration
	MaxTokenLifetime     time.Duration
	MaxAuthenticationAge time.Duration
	Limits               FlowLimits
}

func DefaultFlowPolicy() FlowPolicy {
	return FlowPolicy{
		TransactionTTL:       5 * time.Minute,
		OperationTimeout:     20 * time.Second,
		ClockSkew:            time.Minute,
		MaxTokenAge:          10 * time.Minute,
		MaxTokenLifetime:     time.Hour,
		MaxAuthenticationAge: 12 * time.Hour,
		Limits:               DefaultFlowLimits(),
	}
}

// TransactionID is a CSPRNG identifier. Its zero value is invalid.
type TransactionID [transactionIDBytes]byte

// Purpose-specific start digests prevent the application boundary from
// accidentally reusing a receipt or one throttle key for another purpose.
// All values are SHA-256 digests of independently domain-separated inputs;
// plaintext network/account/provider locators never enter the transaction
// repository.
type StartReceiptDigest [sha256.Size]byte
type NetworkThrottleDigest [sha256.Size]byte
type AccountThrottleDigest [sha256.Size]byte
type ProviderThrottleDigest [sha256.Size]byte

// AuthorizationBegin binds a public, metered locator resolution to exactly
// one subsequent transaction creation. OperationRunID is API-generated UUIDv7
// and the receipt digest is consumed by CreateReplacing; persistence derives
// tenant/provider authority from that receipt rather than caller context.
type AuthorizationBegin struct {
	OperationRunID identity.EntityID
	ReceiptDigest  StartReceiptDigest
	NetworkDigest  NetworkThrottleDigest
	AccountDigest  AccountThrottleDigest
	ProviderDigest ProviderThrottleDigest
}

// TransactionAuditContext is immutable request attribution carried through
// the protocol kernel to persistence. It is deliberately data-only: callers
// must validate their authority-specific shape before entering the kernel.
// The kernel never recovers audit attribution from context.Context.
type TransactionAuditContext struct {
	RequestID     identity.EntityID
	CorrelationID identity.EntityID
	RemoteAddress netip.Addr
	UserAgent     string `json:"-"`
}

// TransactionState is the closed one-time lifecycle stored by the repository.
type TransactionState string

const (
	TransactionPending   TransactionState = "pending"
	TransactionClaimed   TransactionState = "claimed"
	TransactionCompleted TransactionState = "completed"
	TransactionFailed    TransactionState = "failed"
	TransactionExpired   TransactionState = "expired"
)

// TransactionFailureReason is safe operational metadata, never an upstream value.
type TransactionFailureReason string

const (
	FailureProviderResponse    TransactionFailureReason = "provider_response"
	FailureStaleConfiguration  TransactionFailureReason = "stale_configuration"
	FailureExpired             TransactionFailureReason = "expired"
	FailureTokenExchange       TransactionFailureReason = "token_exchange"
	FailureTokenValidation     TransactionFailureReason = "token_validation"
	FailureIdentityApplication TransactionFailureReason = "identity_application"
)

// CeremonyAuthority identifies which authority family owns an OIDC browser
// ceremony. TenantCeremonyAuthority intentionally remains the zero value so
// existing tenant persistence projections keep their exact wire shape. A
// direct platform ceremony must opt in explicitly.
type CeremonyAuthority uint8

const (
	TenantCeremonyAuthority CeremonyAuthority = iota
	DirectPlatformCeremonyAuthority
)

// TransactionPins bind one ceremony to exact provider and trust revisions.
type TransactionPins struct {
	Authority CeremonyAuthority
	Provider  identity.ProviderContext
	Admission identity.TenantAdmissionContext
	// BindingID is the provider cryptographic binding. It equals
	// Admission.BindingID for a tenant-owned provider and is zero for a
	// platform provider.
	BindingID               identity.EntityID
	ProviderRevision        uint64
	BindingRevision         uint64
	PlatformLoginRevision   uint64
	ConfigurationRevision   uint64
	SecurityRevision        uint64
	PlanRevision            uint64
	MappingRevision         uint64
	AuthorizationRevision   uint64
	AssurancePolicyRevision uint64
	PlatformFloorPolicyID   identity.EntityID
	PlatformFloorRevision   uint64
	ClientSecretRevision    uint64
	DiscoveryRevision       uint64
	DiscoveryDigest         [sha256.Size]byte
	JWKSRevision            uint64
	JWKSDigest              [sha256.Size]byte
}

// TenantAdmission returns the tenant authority pinned before redirect. Tenant-
// provider transactions derive the same context from their original
// Provider/BindingID fields; tenant-bound platform-provider transactions pin
// it explicitly. Direct platform transactions never expose an admission.
func (pins TransactionPins) TenantAdmission() (identity.TenantAdmissionContext, bool) {
	return authorityTenantAdmission(
		pins.Authority, pins.Provider, pins.BindingID, pins.Admission, pins.PlatformLoginRevision,
	)
}

// DirectPlatformLogin returns the exact direct-login policy revision only for
// a structurally direct platform ceremony.
func (pins TransactionPins) DirectPlatformLogin() (uint64, bool) {
	if !validCeremonyAuthority(
		pins.Authority, pins.Provider, pins.BindingID, pins.Admission, pins.BindingRevision,
		pins.MappingRevision, pins.AuthorizationRevision, pins.PlatformLoginRevision,
	) || !validTransactionPinExtensions(pins) {
		return 0, false
	}
	return pins.PlatformLoginRevision, true
}

// ProtectedVerifier is ciphertext produced by the deployment identity
// keyring boundary. Ciphertext remains bounded and is never formatted.
type ProtectedVerifier struct {
	KeyVersion uint32
	Ciphertext []byte
}

// TransactionProtectionContext is authenticated context for PKCE sealing.
type TransactionProtectionContext struct {
	Authority             CeremonyAuthority
	TransactionID         TransactionID
	Provider              identity.ProviderContext
	Admission             identity.TenantAdmissionContext
	BindingID             identity.EntityID
	PlatformLoginRevision uint64
}

func (protection TransactionProtectionContext) TenantAdmission() (identity.TenantAdmissionContext, bool) {
	return authorityTenantAdmission(
		protection.Authority, protection.Provider, protection.BindingID, protection.Admission,
		protection.PlatformLoginRevision,
	)
}

func (protection TransactionProtectionContext) DirectPlatformLogin() (uint64, bool) {
	revision, valid := directPlatformLoginAuthority(
		protection.Authority, protection.Provider, protection.BindingID, protection.Admission,
		protection.PlatformLoginRevision,
	)
	return revision, valid
}

// PKCEVerifierProtector seals and opens the only recoverable transaction
// secret. Implementations must bind every context field as authenticated data
// and must not retain plaintext verifier slices after returning.
type PKCEVerifierProtector interface {
	SealPKCE(context.Context, TransactionProtectionContext, []byte) (ProtectedVerifier, error)
	OpenPKCE(context.Context, TransactionProtectionContext, ProtectedVerifier) ([]byte, error)
}

// PendingTransaction is the bounded persistence projection created before redirect.
type PendingTransaction struct {
	ID                    TransactionID
	MaterialID            identity.EntityID
	StateDigest           [sha256.Size]byte
	BrowserDigest         [sha256.Size]byte
	NonceDigest           [sha256.Size]byte
	Verifier              ProtectedVerifier
	Pins                  TransactionPins
	ClientID              string
	RedirectURI           string
	PostLogoutRedirectURI string
	ReturnPath            string
	Scopes                []string
	AllowRefreshToken     bool
	UseUserInfo           bool
	CreatedAt             time.Time
	ExpiresAt             time.Time
	State                 TransactionState
	Version               uint64
}

// CreateTransactionRequest atomically expires the previous browser-bound
// pending transaction, when present, and creates Current.
type CreateTransactionRequest struct {
	Begin                     AuthorizationBegin
	Current                   PendingTransaction
	PreviousBrowserDigest     [sha256.Size]byte
	HasPreviousBrowserBinding bool
	// ApplicationBrowserBindingDigest is distinct from Current.BrowserDigest,
	// which always hashes the kernel browser handle. Tenant flows leave it zero.
	ApplicationBrowserBindingDigest [sha256.Size]byte
	Audit                           TransactionAuditContext
}

// TransactionClaim contains only digests of independently supplied callback artifacts.
type TransactionClaim struct {
	AttemptID               TransactionID
	StateDigest             [sha256.Size]byte
	BrowserDigest           [sha256.Size]byte
	AuthorizationCodeDigest [sha256.Size]byte
	ClaimedAt               time.Time
	Audit                   TransactionAuditContext
}

// ClaimedTransaction is the exact projection returned by an atomic pending-to-claimed transition.
type ClaimedTransaction struct {
	PendingTransaction
	ClaimAttemptID          TransactionID
	AuthorizationCodeDigest [sha256.Size]byte
	ClaimedAt               time.Time
}

// TransactionFailure marks a claimed transaction terminal. Claimed rows are
// already non-replayable even when best-effort terminal annotation fails.
type TransactionFailure struct {
	ID              TransactionID
	ExpectedVersion uint64
	FailedAt        time.Time
	Reason          TransactionFailureReason
	State           TransactionState
	Audit           TransactionAuditContext
}

// TransactionCompletion is passed to the later JIT/session consumer, which
// must mark the claimed row completed in the same apply transaction.
type TransactionCompletion struct {
	ID              TransactionID
	MaterialID      identity.EntityID
	ExpectedVersion uint64
	Pins            TransactionPins
	CompletedAt     time.Time
	ReturnPath      string
}

// TransactionRepository owns both atomic replay boundaries. CreateReplacing
// must consume Begin exactly once, derive tenant/provider authority from it,
// recheck every Current pin, and atomically replace the browser transaction.
// An exact retry after response loss is idempotent; any divergent replay is
// rejected. Claim selects exactly one pending, unexpired row matching both
// callback digests and changes it to claimed before returning. An exact retry
// with the same claim-attempt ID returns the original claimed projection;
// another attempt never does. Fail is
// idempotent for an exact replay of ID, expected version, timestamp, reason,
// and terminal state.
type TransactionRepository interface {
	CreateReplacing(context.Context, CreateTransactionRequest) error
	Claim(context.Context, TransactionClaim) (ClaimedTransaction, error)
	Fail(context.Context, TransactionFailure) error
}

// EndpointKind is the closed class of a previously discovered and compiled endpoint.
type EndpointKind string

const (
	EndpointToken      EndpointKind = "token"
	EndpointUserInfo   EndpointKind = "userinfo"
	EndpointRevocation EndpointKind = "revocation"
	EndpointEndSession EndpointKind = "end_session"
)

// PinnedEndpoint retains the exact URL and the federatedhttp compiled target.
// Infrastructure ports must enforce DNS/TLS/redirect policy again at use time.
type PinnedEndpoint struct {
	kind   EndpointKind
	url    string
	target federatedhttp.Target
	valid  bool
}

func (endpoint PinnedEndpoint) Kind() EndpointKind           { return endpoint.kind }
func (endpoint PinnedEndpoint) URL() string                  { return endpoint.url }
func (endpoint PinnedEndpoint) Target() federatedhttp.Target { return endpoint.target }

// TokenEndpointCategory is a sanitized result from the deployment-owned POST transport.
type TokenEndpointCategory string

const (
	TokenEndpointSuccess     TokenEndpointCategory = "success"
	TokenEndpointRejected    TokenEndpointCategory = "rejected"
	TokenEndpointUnavailable TokenEndpointCategory = "unavailable"
	TokenEndpointLimited     TokenEndpointCategory = "limit_exceeded"
	TokenEndpointCancelled   TokenEndpointCategory = "cancelled"
)

// TokenExchangeRequest is semantic input to a narrow SSRF-safe POST port.
// The port must not retain any slice and must place the client credential only
// according to ClientAuthentication.
type TokenExchangeRequest struct {
	Endpoint             PinnedEndpoint           `json:"-"`
	GrantType            string                   `json:"-"`
	ClientAuthentication ClientAuthenticationMode `json:"-"`
	ClientID             string                   `json:"-"`
	ClientSecret         []byte                   `json:"-"`
	AuthorizationCode    []byte                   `json:"-"`
	RedirectURI          string                   `json:"-"`
	PKCEVerifier         []byte                   `json:"-"`
}

// TokenEndpointResponse transfers ownership of Body to the kernel.
type TokenEndpointResponse struct {
	Category   TokenEndpointCategory
	StatusCode int
	MediaType  string
	Body       []byte `json:"-"`
}

// TokenEndpointPort is implemented later by the deployment-owned
// credential-bearing federated HTTP boundary. It must never follow redirects,
// must encode client_secret_basic credentials per RFC 6749 section 2.3.1, and
// must not use an ambient proxy, resolver, or default HTTP client.
type TokenEndpointPort interface {
	Exchange(context.Context, TokenExchangeRequest) (TokenEndpointResponse, error)
}

// ClientCredential is an exact secret revision loaded only after callback claim.
type ClientCredential struct {
	Revision uint64
	Secret   []byte `json:"-"`
}

// FlowOptions require deployment-owned persistence, protection, and POST boundaries.
type FlowOptions struct {
	Trust             *Client
	Transactions      TransactionRepository
	VerifierProtector PKCEVerifierProtector
	TokenEndpoint     TokenEndpointPort
	// RedirectURI and PostLogoutRedirectURI are deployment-derived exact
	// application URLs. Provider configuration may reference only these values.
	RedirectURI           string
	PostLogoutRedirectURI string
	CallbackEndpoint      CallbackEndpoint
	Policy                FlowPolicy
}

// CallbackEndpoint is the closed browser callback family owned by a Flow.
// The tenant callback remains the zero value for source compatibility.
type CallbackEndpoint uint8

const (
	TenantOIDCCallbackEndpoint CallbackEndpoint = iota
	DirectPlatformOIDCCallbackEndpoint
)

// Flow coordinates pure protocol artifacts around narrow side-effect ports.
type Flow struct {
	trust                 *Client
	transactions          TransactionRepository
	verifierProtector     PKCEVerifierProtector
	tokenEndpoint         TokenEndpointPort
	redirectURI           string
	postLogoutRedirectURI string
	callbackEndpoint      CallbackEndpoint
	callbackPath          string
	policy                FlowPolicy
	random                io.Reader
	now                   func() time.Time
}

// AuthorizationConfiguration is one exact provider/configuration projection.
// RedirectURI and PostLogoutRedirectURI are deployment-derived application
// URLs; they are never tenant or forwarded-host input.
type AuthorizationConfiguration struct {
	Authority               CeremonyAuthority
	Provider                identity.ProviderContext
	Admission               identity.TenantAdmissionContext
	BindingID               identity.EntityID
	ProviderRevision        uint64
	BindingRevision         uint64
	PlatformLoginRevision   uint64
	ConfigurationRevision   uint64
	SecurityRevision        uint64
	PlanRevision            uint64
	MappingRevision         uint64
	AuthorizationRevision   uint64
	AssurancePolicyRevision uint64
	PlatformFloorPolicyID   identity.EntityID
	PlatformFloorRevision   uint64
	ClientSecretRevision    uint64
	ClientID                string
	RedirectURI             string
	PostLogoutRedirectURI   string
	ExtraScopes             []string
	AllowRefreshToken       bool
	UseUserInfo             bool
	Discovery               DiscoverySnapshot
	JWKS                    JWKSSnapshot
}

// Pins returns the exact public revisions and digests bound into a ceremony.
// It contains no token or client-secret material and lets later persistence
// boundaries reject configuration drift without reconstructing private flow
// state.
func (configuration AuthorizationConfiguration) Pins() TransactionPins {
	return transactionPins(configuration)
}

// TenantAdmission returns the tenant authority selected by this
// configuration. A tenant-owned provider retains its established derivation;
// tenant-bound platform-provider login requires an explicit admission, while
// direct platform login never exposes one.
func (configuration AuthorizationConfiguration) TenantAdmission() (identity.TenantAdmissionContext, bool) {
	return authorityTenantAdmission(
		configuration.Authority, configuration.Provider, configuration.BindingID, configuration.Admission,
		configuration.PlatformLoginRevision,
	)
}

func (configuration AuthorizationConfiguration) DirectPlatformLogin() (uint64, bool) {
	if !validCeremonyAuthority(
		configuration.Authority, configuration.Provider, configuration.BindingID, configuration.Admission,
		configuration.BindingRevision, configuration.MappingRevision, configuration.AuthorizationRevision,
		configuration.PlatformLoginRevision,
	) || !validAuthorityExtensions(configuration) {
		return 0, false
	}
	return configuration.PlatformLoginRevision, true
}

// AuthorizationStart contains only browser-delivery artifacts. Its String
// methods never expose the redirect URL or browser handle.
type AuthorizationStart struct {
	transactionID TransactionID
	redirectURL   string
	browserHandle []byte
	expiresAt     time.Time
	valid         bool
}

func (start AuthorizationStart) TransactionID() TransactionID { return start.transactionID }
func (start AuthorizationStart) RedirectURL() string          { return start.redirectURL }
func (start AuthorizationStart) BrowserHandle() []byte {
	return append([]byte(nil), start.browserHandle...)
}
func (start AuthorizationStart) ExpiresAt() time.Time { return start.expiresAt }

// StartAuthorizationRequest starts one anonymous browser flow.
type StartAuthorizationRequest struct {
	Begin                           AuthorizationBegin
	Configuration                   AuthorizationConfiguration
	ReturnPath                      string
	PreviousBrowserHandle           []byte `json:"-"`
	ApplicationBrowserBindingDigest [sha256.Size]byte
	Audit                           TransactionAuditContext
}

// callbackRequest is retained only for protocol-kernel tests which already
// hold an exact configuration. Public application code must use
// ResolvedCallbackRequest so tenant authority comes from the atomic claim.
type callbackRequest struct {
	Configuration AuthorizationConfiguration
	RawQuery      string `json:"-"`
	BrowserHandle []byte `json:"-"`
}

// ResolvedCallbackRequest deliberately carries no tenant, provider, binding,
// or configuration identifier. The repository claim is the sole authority
// for resolving those values after the state and browser digests win once.
type ResolvedCallbackRequest struct {
	RawQuery      string `json:"-"`
	BrowserHandle []byte `json:"-"`
	Audit         TransactionAuditContext
}

// CallbackConfigurationLookup is the redacted exact pin tuple exposed only
// after a pending transaction has atomically become claimed.
type CallbackConfigurationLookup struct {
	TransactionID   TransactionID
	ExpectedVersion uint64
	Pins            TransactionPins
	ReturnPath      string
}

// CallbackConfigurationResolver loads the immutable configuration and trust
// snapshots selected by the claimed transaction. Implementations must derive
// tenant context from Lookup.Pins and must not accept caller-selected tenant
// context.
type CallbackConfigurationResolver interface {
	ResolveOIDCCallbackConfiguration(context.Context, CallbackConfigurationLookup) (AuthorizationConfiguration, error)
}

const (
	claimedStageReady uint32 = iota + 1
	claimedStageExchanging
	claimedStageExchanged
	claimedStageVerifying
	claimedStageVerified
	claimedStageAborting
	claimedStageAbortRetry
	claimedStageFailed
)

// ClaimedAuthorization is an in-memory, one-use code artifact. Raw code is
// never part of PendingTransaction or repository input.
type ClaimedAuthorization struct {
	owner         *Flow
	record        ClaimedTransaction
	configuration AuthorizationConfiguration
	code          []byte
	audit         TransactionAuditContext
	abortFailure  TransactionFailure
	stage         atomic.Uint32
}

func (claimed *ClaimedAuthorization) TransactionID() TransactionID {
	if claimed == nil {
		return TransactionID{}
	}
	return claimed.record.ID
}

func (claimed *ClaimedAuthorization) ClaimAttemptID() TransactionID {
	if claimed == nil {
		return TransactionID{}
	}
	return claimed.record.ClaimAttemptID
}

func (claimed *ClaimedAuthorization) Pins() TransactionPins {
	if claimed == nil {
		return TransactionPins{}
	}
	return claimed.record.Pins
}

func (claimed *ClaimedAuthorization) AuditContext() TransactionAuditContext {
	if claimed == nil {
		return TransactionAuditContext{}
	}
	return claimed.audit
}

func equalDigest(left, right [sha256.Size]byte) bool {
	return subtle.ConstantTimeCompare(left[:], right[:]) == 1
}
