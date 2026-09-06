package platformoidcauth

import (
	"context"
	"crypto/sha256"
	"fmt"
	"slices"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
	"github.com/periapsis-im/periapsis/services/api/internal/returnpath"
)

const (
	minimumDirectOIDCOperationTimeout = 100 * time.Millisecond
	maximumDirectOIDCOperationTimeout = 2 * time.Minute
)

// DirectOIDCConfigurationPins is the complete immutable browser-ceremony
// authority. Tenant, binding, mapping, and authorization revisions are absent
// by construction and remain zero in the underlying protocol configuration.
type DirectOIDCConfigurationPins struct {
	Provider                    identity.ProviderContext
	ProviderRevision            uint64
	PlatformLoginRevision       uint64
	ConfigurationRevision       uint64
	SecurityRevision            uint64
	PlanRevision                uint64
	AssurancePolicyRevision     uint64
	PlatformFloorPolicyID       identity.EntityID
	PlatformFloorPolicyRevision uint64
	ClientSecretRevision        uint64
	DiscoveryRevision           uint64
	DiscoveryDigest             [sha256.Size]byte
	JWKSRevision                uint64
	JWKSDigest                  [sha256.Size]byte
}

func (pins DirectOIDCConfigurationPins) String() string {
	return fmt.Sprintf(
		"platformoidcauth.DirectOIDCConfigurationPins{provider:%t,providerRevision:%t,loginRevision:%t,configurationRevision:%t,securityRevision:%t,planRevision:%t,assuranceRevision:%t,platformFloor:%t,platformFloorRevision:%t,secretRevision:%t,discoveryRevision:%t,jwksRevision:%t,digests:[REDACTED]}",
		pins.Provider.ProviderID != (identity.EntityID{}), pins.ProviderRevision != 0,
		pins.PlatformLoginRevision != 0, pins.ConfigurationRevision != 0,
		pins.SecurityRevision != 0, pins.PlanRevision != 0, pins.AssurancePolicyRevision != 0,
		pins.PlatformFloorPolicyID != (identity.EntityID{}), pins.PlatformFloorPolicyRevision != 0,
		pins.ClientSecretRevision != 0, pins.DiscoveryRevision != 0, pins.JWKSRevision != 0,
	)
}

func (pins DirectOIDCConfigurationPins) GoString() string { return pins.String() }

type DirectOIDCStartAuthority struct {
	Lookup     DirectOIDCStartLookup
	ReturnPath string
	Audit      DirectAuditContext
}

func (authority DirectOIDCStartAuthority) String() string {
	return fmt.Sprintf(
		"platformoidcauth.DirectOIDCStartAuthority{lookup:%q,returnPath:%t,audit:%q}",
		authority.Lookup.String(), authority.ReturnPath != "", authority.Audit.String(),
	)
}

func (authority DirectOIDCStartAuthority) GoString() string { return authority.String() }

// DirectOIDCStartGrant is the idempotent result of metering one anonymous
// direct start. Persistence must bind Authority, including returnPath and the
// browser capability digest, to these exact pins before returning.
type DirectOIDCStartGrant struct {
	Authority DirectOIDCStartAuthority
	Pins      DirectOIDCConfigurationPins
}

func (grant DirectOIDCStartGrant) String() string {
	return fmt.Sprintf(
		"platformoidcauth.DirectOIDCStartGrant{authority:%q,pins:%q}",
		grant.Authority.String(), grant.Pins.String(),
	)
}

func (grant DirectOIDCStartGrant) GoString() string { return grant.String() }

type DirectOIDCStartSource interface {
	BeginDirectOIDCLogin(context.Context, DirectOIDCStartAuthority) (DirectOIDCStartGrant, error)
}

// DirectOIDCConfiguration admits no projected claim family. ACR and AMR are
// optional ID-token trust evidence only; UserInfo is forbidden. Refresh is an
// explicit offline_access capability whose protected token remains session-
// owned and never becomes platform authority.
type DirectOIDCConfiguration struct {
	Authorization federatedoidc.AuthorizationConfiguration
	IDTokenClaims federatedoidc.ClaimExtractionPolicy
}

func (configuration DirectOIDCConfiguration) String() string {
	return fmt.Sprintf(
		"platformoidcauth.DirectOIDCConfiguration{authorization:%q,idTokenClaims:%q}",
		configuration.Authorization.String(), configuration.IDTokenClaims.String(),
	)
}

func (configuration DirectOIDCConfiguration) GoString() string { return configuration.String() }

type DirectOIDCStartConfigurationSnapshot struct {
	Grant         DirectOIDCStartGrant
	Configuration DirectOIDCConfiguration
}

func (snapshot DirectOIDCStartConfigurationSnapshot) String() string {
	return fmt.Sprintf(
		"platformoidcauth.DirectOIDCStartConfigurationSnapshot{grant:%q,configuration:%q}",
		snapshot.Grant.String(), snapshot.Configuration.String(),
	)
}

func (snapshot DirectOIDCStartConfigurationSnapshot) GoString() string { return snapshot.String() }

type DirectOIDCCallbackConfigurationLookup struct {
	Transaction             federatedoidc.CallbackConfigurationLookup
	BrowserCapabilityDigest DirectBrowserCapabilityDigest
}

func (lookup DirectOIDCCallbackConfigurationLookup) String() string {
	return fmt.Sprintf(
		"platformoidcauth.DirectOIDCCallbackConfigurationLookup{transaction:%t,version:%t,pins:%q,browser:[REDACTED]}",
		lookup.Transaction.TransactionID != (federatedoidc.TransactionID{}),
		lookup.Transaction.ExpectedVersion != 0, lookup.Transaction.Pins.String(),
	)
}

func (lookup DirectOIDCCallbackConfigurationLookup) GoString() string { return lookup.String() }

type DirectOIDCCallbackConfigurationSnapshot struct {
	Lookup        DirectOIDCCallbackConfigurationLookup
	Pins          DirectOIDCConfigurationPins
	ReturnPath    string
	Configuration DirectOIDCConfiguration
}

func (snapshot DirectOIDCCallbackConfigurationSnapshot) String() string {
	return fmt.Sprintf(
		"platformoidcauth.DirectOIDCCallbackConfigurationSnapshot{lookup:%q,pins:%q,returnPath:%t,configuration:%q}",
		snapshot.Lookup.String(), snapshot.Pins.String(), snapshot.ReturnPath != "", snapshot.Configuration.String(),
	)
}

func (snapshot DirectOIDCCallbackConfigurationSnapshot) GoString() string {
	return snapshot.String()
}

type DirectOIDCConfigurationSource interface {
	LoadDirectOIDCStartConfiguration(context.Context, DirectOIDCStartGrant) (DirectOIDCStartConfigurationSnapshot, error)
	ResolveDirectOIDCCallbackConfiguration(context.Context, DirectOIDCCallbackConfigurationLookup) (DirectOIDCCallbackConfigurationSnapshot, error)
}

// DirectOIDCStartAuthorizationRequest couples the protocol-kernel request to
// the metered authority and complete platform policy snapshot which the
// direct transaction adapter must persist. The generic kernel pins
// intentionally cannot represent browser capability, audit, plan, or
// platform-floor authority.
type DirectOIDCStartAuthorizationRequest struct {
	Protocol federatedoidc.StartAuthorizationRequest
	Grant    DirectOIDCStartGrant
}

func (request DirectOIDCStartAuthorizationRequest) String() string {
	return fmt.Sprintf(
		"platformoidcauth.DirectOIDCStartAuthorizationRequest{protocol:%q,grant:%q}",
		request.Protocol.String(), request.Grant.String(),
	)
}

func (request DirectOIDCStartAuthorizationRequest) GoString() string { return request.String() }

// DirectOIDCTransactionPort is exactly the protocol kernel surface needed by
// this direct browser application. It contains no UserInfo or tenant resolver.
type DirectOIDCTransactionPort interface {
	StartDirectAuthorization(context.Context, DirectOIDCStartAuthorizationRequest) (federatedoidc.AuthorizationStart, error)
	ClaimCallbackResolved(context.Context, DirectOIDCCallbackRequest, federatedoidc.CallbackConfigurationResolver) (DirectClaimedAuthorization, error)
	ExchangeCode(context.Context, *federatedoidc.ClaimedAuthorization, federatedoidc.ClientCredential) (*federatedoidc.TokenBundle, error)
	VerifyIDToken(context.Context, *federatedoidc.ClaimedAuthorization, *federatedoidc.TokenBundle, federatedoidc.ClaimExtractionPolicy) (*federatedoidc.VerifiedAuthentication, error)
	TakeSessionMaterial(federatedoidc.AuthorizationConfiguration, *federatedoidc.TokenBundle) (federatedauth.OIDCSessionMaterial, error)
	AbortDirectClaimedAuthorization(context.Context, DirectClaimedAuthorization, DirectAuditContext) error
}

// DirectOIDCCallbackRequest binds one callback's exact request attribution to
// the raw protocol artifacts. The transaction adapter must carry Audit into
// every kernel-owned terminal failure without ambient context values.
type DirectOIDCCallbackRequest struct {
	Protocol federatedoidc.ResolvedCallbackRequest
	Audit    DirectAuditContext
}

func (request DirectOIDCCallbackRequest) String() string {
	return fmt.Sprintf(
		"platformoidcauth.DirectOIDCCallbackRequest{protocol:%q,audit:%q}",
		request.Protocol.String(), request.Audit.String(),
	)
}

func (request DirectOIDCCallbackRequest) GoString() string { return request.String() }

// DirectClaimedAuthorization couples the protocol kernel's one-use in-memory
// handle to the exact repository-generated claim attempt. The latter is
// required by the direct apply CAS and must never be recovered by a later
// transaction lookup that could lose callback-attempt authority.
type DirectClaimedAuthorization struct {
	Authorization  *federatedoidc.ClaimedAuthorization
	ClaimAttemptID federatedoidc.TransactionID
}

func (claimed DirectClaimedAuthorization) String() string {
	return fmt.Sprintf(
		"platformoidcauth.DirectClaimedAuthorization{authorization:%t,attempt:%t,material:[REDACTED]}",
		claimed.Authorization != nil, claimed.ClaimAttemptID != (federatedoidc.TransactionID{}),
	)
}

func (claimed DirectClaimedAuthorization) GoString() string { return claimed.String() }

type DirectOIDCClientSecretLookup struct {
	Pins DirectOIDCConfigurationPins
}

func (lookup DirectOIDCClientSecretLookup) String() string {
	return fmt.Sprintf(
		"platformoidcauth.DirectOIDCClientSecretLookup{pins:%q,material:[REDACTED]}",
		lookup.Pins.String(),
	)
}

func (lookup DirectOIDCClientSecretLookup) GoString() string { return lookup.String() }

// OpenDirectOIDCClientSecret transfers ownership of the returned plaintext to
// the caller. The implementation must use the direct zero-binding secret AAD.
type DirectOIDCClientSecretSource interface {
	OpenDirectOIDCClientSecret(context.Context, DirectOIDCClientSecretLookup) ([]byte, error)
}

type DirectOIDCTrustPlanRequest struct {
	TransactionID  federatedoidc.TransactionID
	ClaimAttemptID federatedoidc.TransactionID
	ObservedAt     time.Time
	Pins           DirectOIDCConfigurationPins
	Proof          *federatedoidc.VerifiedAuthentication
}

func (request DirectOIDCTrustPlanRequest) String() string {
	return fmt.Sprintf(
		"platformoidcauth.DirectOIDCTrustPlanRequest{transaction:%t,claimAttempt:%t,observed:%t,pins:%q,proof:%t,material:[REDACTED]}",
		validTransactionID(request.TransactionID), validTransactionID(request.ClaimAttemptID),
		!request.ObservedAt.IsZero(), request.Pins.String(), request.Proof != nil,
	)
}

func (request DirectOIDCTrustPlanRequest) GoString() string { return request.String() }

type DirectOIDCTrustPlanner interface {
	Plan(context.Context, DirectOIDCTrustPlanRequest) (DirectAuthenticationPlan, error)
}

var _ DirectOIDCTrustPlanner = (*DirectAuthenticationPlanner)(nil)

// DirectOIDCApplyRequest is consumed by one atomic transaction which must
// complete the claimed OIDC transaction CAS, recheck every plan revision,
// observe the encrypted subject/aliases, append redacted audit, and create
// exactly the session or TOTP continuation selected by Plan.
type DirectOIDCApplyRequest struct {
	Plan                    DirectAuthenticationPlan
	ClaimAttemptID          federatedoidc.TransactionID
	Assurance               DirectSelectedAssurance
	ContinuationAuthority   federatedauth.ContinuationAuthority
	Session                 mfa.SessionReservation
	Continuation            federatedauth.PostPrimaryContinuationReservation
	BrowserCapabilityDigest DirectBrowserCapabilityDigest
	ReturnPath              string
	Observation             DirectSubjectObservation
	AppliedAt               time.Time
	Audit                   DirectAuditContext
	MaterialID              identity.EntityID
	SessionMaterial         *federatedauth.ProtectedOIDCSessionMaterial `json:"-"`
	MaterialExpiresAt       time.Time
	Configuration           federatedoidc.AuthorizationConfiguration
}

func (request DirectOIDCApplyRequest) String() string {
	return fmt.Sprintf(
		"platformoidcauth.DirectOIDCApplyRequest{plan:%q,claimAttempt:%t,assurance:%q,directContinuation:%t,session:%t,continuation:%t,browser:[REDACTED],returnPath:%t,observation:%q,applied:%t,audit:%q,material:%t,sessionMaterial:%t,materialExpiry:%t}",
		request.Plan.String(), request.ClaimAttemptID != (federatedoidc.TransactionID{}), request.Assurance.String(),
		request.ContinuationAuthority == federatedauth.ContinuationAuthorityDirectPlatformOIDC,
		!request.Session.IsZero(), !request.Continuation.IsZero(), request.ReturnPath != "",
		request.Observation.String(), !request.AppliedAt.IsZero(), request.Audit.String(),
		request.MaterialID != (identity.EntityID{}), request.SessionMaterial != nil,
		!request.MaterialExpiresAt.IsZero(),
	)
}

func (request DirectOIDCApplyRequest) GoString() string { return request.String() }

type DirectOIDCApplyResult struct {
	Disposition             DirectAuthenticationDisposition
	TransactionID           federatedoidc.TransactionID
	BrowserCapabilityDigest DirectBrowserCapabilityDigest
	UserID                  identity.EntityID
	SessionID               identity.EntityID
	ContinuationID          identity.EntityID
	ReturnPath              string
	AppliedAt               time.Time
}

func (result DirectOIDCApplyResult) String() string {
	return fmt.Sprintf(
		"platformoidcauth.DirectOIDCApplyResult{disposition:%q,transaction:%t,user:%t,session:%t,continuation:%t,returnPath:%t,applied:%t,browser:[REDACTED]}",
		result.Disposition, result.TransactionID != (federatedoidc.TransactionID{}),
		result.UserID != (identity.EntityID{}), result.SessionID != (identity.EntityID{}),
		result.ContinuationID != (identity.EntityID{}), result.ReturnPath != "", !result.AppliedAt.IsZero(),
	)
}

func (result DirectOIDCApplyResult) GoString() string { return result.String() }

type DirectOIDCAtomicApplyPort interface {
	ApplyDirectOIDC(context.Context, DirectOIDCApplyRequest) (DirectOIDCApplyResult, error)
}

// DirectOIDCBrowserOutcome deliberately exposes only the two direct-login
// outcomes. Credential ownership transfers to the caller, which must destroy
// it after building the response. TOTP completion is a later slice.
type DirectOIDCBrowserOutcome struct {
	Disposition    DirectAuthenticationDisposition
	UserID         identity.EntityID
	SessionID      identity.EntityID
	ContinuationID identity.EntityID
	ReturnPath     string
	Credential     *federatedauth.BrowserCredential
}

func (outcome DirectOIDCBrowserOutcome) String() string {
	return fmt.Sprintf(
		"platformoidcauth.DirectOIDCBrowserOutcome{disposition:%q,user:%t,session:%t,continuation:%t,returnPath:%t,credential:%t,material:[REDACTED]}",
		outcome.Disposition, outcome.UserID != (identity.EntityID{}),
		outcome.SessionID != (identity.EntityID{}), outcome.ContinuationID != (identity.EntityID{}),
		outcome.ReturnPath != "", outcome.Credential != nil,
	)
}

func (outcome DirectOIDCBrowserOutcome) GoString() string { return outcome.String() }

type DirectOIDCBrowserApplicationOptions struct {
	Transactions     DirectOIDCTransactionPort
	Starts           DirectOIDCStartSource
	Configurations   DirectOIDCConfigurationSource
	ClientSecrets    DirectOIDCClientSecretSource
	Trust            DirectOIDCTrustPlanner
	Credentials      federatedauth.ApplyCredentialIssuer
	Apply            DirectOIDCAtomicApplyPort
	SessionSealer    federatedauth.OIDCSessionMaterialSealer
	Digester         *DirectOIDCStartDigester
	Now              func() time.Time
	OperationTimeout time.Duration
}

type DirectOIDCBrowserApplication struct {
	transactions     DirectOIDCTransactionPort
	starts           DirectOIDCStartSource
	configurations   DirectOIDCConfigurationSource
	clientSecrets    DirectOIDCClientSecretSource
	trust            DirectOIDCTrustPlanner
	credentials      federatedauth.ApplyCredentialIssuer
	apply            DirectOIDCAtomicApplyPort
	sessionSealer    federatedauth.OIDCSessionMaterialSealer
	digester         *DirectOIDCStartDigester
	now              func() time.Time
	operationTimeout time.Duration
}

func NewDirectOIDCBrowserApplication(
	options DirectOIDCBrowserApplicationOptions,
) (*DirectOIDCBrowserApplication, error) {
	if options.Transactions == nil || options.Starts == nil || options.Configurations == nil ||
		options.ClientSecrets == nil || options.Trust == nil || options.Credentials == nil ||
		options.Apply == nil || options.SessionSealer == nil || options.Digester == nil ||
		options.Now == nil || options.OperationTimeout < minimumDirectOIDCOperationTimeout ||
		options.OperationTimeout > maximumDirectOIDCOperationTimeout ||
		options.OperationTimeout%time.Microsecond != 0 {
		return nil, ErrDirectAuthenticationDenied
	}
	return &DirectOIDCBrowserApplication{
		transactions: options.Transactions, starts: options.Starts, configurations: options.Configurations,
		clientSecrets: options.ClientSecrets, trust: options.Trust, credentials: options.Credentials,
		apply: options.Apply, sessionSealer: options.SessionSealer,
		digester: options.Digester, now: options.Now, operationTimeout: options.OperationTimeout,
	}, nil
}

func (application *DirectOIDCBrowserApplication) String() string {
	return fmt.Sprintf(
		"platformoidcauth.DirectOIDCBrowserApplication{configured:%t}",
		application != nil && application.transactions != nil && application.starts != nil &&
			application.configurations != nil && application.clientSecrets != nil &&
			application.trust != nil && application.credentials != nil &&
			application.apply != nil && application.sessionSealer != nil && application.digester != nil,
	)
}

func (application *DirectOIDCBrowserApplication) GoString() string { return application.String() }

type StartDirectOIDCRequest struct {
	Lookup                  DirectOIDCStartLookup
	ReturnPath              string
	PreviousBrowserHandle   []byte `json:"-"`
	HasAuthenticatedSession bool
	Audit                   DirectAuditContext
}

func (request StartDirectOIDCRequest) String() string {
	return fmt.Sprintf(
		"platformoidcauth.StartDirectOIDCRequest{lookup:%q,returnPath:%t,previousBrowser:%t,authenticatedSession:%t,audit:%q}",
		request.Lookup.String(), request.ReturnPath != "", len(request.PreviousBrowserHandle) != 0,
		request.HasAuthenticatedSession, request.Audit.String(),
	)
}

func (request StartDirectOIDCRequest) GoString() string { return request.String() }

func (application *DirectOIDCBrowserApplication) Start(
	ctx context.Context,
	request StartDirectOIDCRequest,
) (federatedoidc.AuthorizationStart, error) {
	if application == nil || application.transactions == nil || application.starts == nil ||
		application.configurations == nil || request.HasAuthenticatedSession ||
		!validDirectOIDCStartLookup(request.Lookup) || !validDirectReturnPath(request.ReturnPath) ||
		!validDirectAuditContext(request.Audit) {
		return federatedoidc.AuthorizationStart{}, ErrDirectAuthenticationDenied
	}
	operation, cancel, ok := application.operation(ctx)
	if !ok {
		return federatedoidc.AuthorizationStart{}, ErrDirectAuthenticationDenied
	}
	defer cancel()
	authority := DirectOIDCStartAuthority{Lookup: request.Lookup, ReturnPath: request.ReturnPath, Audit: request.Audit}
	grant, err := application.begin(operation, authority)
	if err != nil || grant.Authority != authority || !validDirectOIDCConfigurationPins(grant.Pins) {
		return federatedoidc.AuthorizationStart{}, ErrDirectAuthenticationDenied
	}
	snapshot, err := application.loadStartConfiguration(operation, grant)
	snapshot = cloneDirectOIDCStartConfigurationSnapshot(snapshot)
	if err != nil || operation.Err() != nil || snapshot.Grant != grant ||
		!validDirectOIDCConfiguration(snapshot.Configuration, grant.Pins) {
		return federatedoidc.AuthorizationStart{}, ErrDirectAuthenticationDenied
	}
	previousBrowser := append([]byte(nil), request.PreviousBrowserHandle...)
	defer clear(previousBrowser)
	start, err := application.transactions.StartDirectAuthorization(operation, DirectOIDCStartAuthorizationRequest{
		Protocol: federatedoidc.StartAuthorizationRequest{
			Begin: federatedoidc.AuthorizationBegin{
				OperationRunID: request.Lookup.OperationRunID,
				ReceiptDigest:  federatedoidc.StartReceiptDigest(request.Lookup.ReceiptDigest),
				NetworkDigest:  federatedoidc.NetworkThrottleDigest(request.Lookup.NetworkDigest),
				AccountDigest:  federatedoidc.AccountThrottleDigest(request.Lookup.AccountDigest),
				ProviderDigest: federatedoidc.ProviderThrottleDigest(request.Lookup.ProviderDigest),
			},
			Configuration: snapshot.Configuration.Authorization, ReturnPath: request.ReturnPath,
			PreviousBrowserHandle: previousBrowser,
		},
		Grant: grant,
	})
	if err != nil {
		return federatedoidc.AuthorizationStart{}, ErrDirectAuthenticationDenied
	}
	return start, nil
}

type CompleteDirectOIDCRequest struct {
	RawQuery          string `json:"-"`
	BrowserHandle     []byte `json:"-"`
	BrowserCapability []byte `json:"-"`
	Audit             DirectAuditContext
}

func (request CompleteDirectOIDCRequest) String() string {
	return fmt.Sprintf(
		"platformoidcauth.CompleteDirectOIDCRequest{query:%t,browser:%t,capability:%t,audit:%q,material:[REDACTED]}",
		request.RawQuery != "", len(request.BrowserHandle) != 0, len(request.BrowserCapability) != 0,
		request.Audit.String(),
	)
}

func (request CompleteDirectOIDCRequest) GoString() string { return request.String() }

func (application *DirectOIDCBrowserApplication) Complete(
	ctx context.Context,
	request CompleteDirectOIDCRequest,
) (DirectOIDCBrowserOutcome, error) {
	if application == nil || application.transactions == nil || application.configurations == nil ||
		application.clientSecrets == nil || application.trust == nil || application.apply == nil ||
		application.credentials == nil || application.digester == nil || !validDirectAuditContext(request.Audit) {
		return DirectOIDCBrowserOutcome{}, ErrDirectAuthenticationDenied
	}
	operation, cancel, ok := application.operation(ctx)
	if !ok {
		return DirectOIDCBrowserOutcome{}, ErrDirectAuthenticationDenied
	}
	defer cancel()
	browserCapability := append([]byte(nil), request.BrowserCapability...)
	defer clear(browserCapability)
	browserDigest, err := application.digester.BrowserCapabilityDigest(browserCapability)
	if err != nil {
		return DirectOIDCBrowserOutcome{}, ErrDirectAuthenticationDenied
	}
	resolver := &directOIDCCallbackResolver{
		source: application.configurations, browserCapabilityDigest: browserDigest,
	}
	browserHandle := append([]byte(nil), request.BrowserHandle...)
	defer clear(browserHandle)
	claimed, err := application.transactions.ClaimCallbackResolved(
		operation,
		DirectOIDCCallbackRequest{
			Protocol: federatedoidc.ResolvedCallbackRequest{
				RawQuery: request.RawQuery, BrowserHandle: browserHandle,
			},
			Audit: request.Audit,
		},
		resolver,
	)
	if err != nil || claimed.Authorization == nil || !validTransactionID(claimed.ClaimAttemptID) || !resolver.resolved {
		if claimed.Authorization != nil {
			application.abort(ctx, claimed, request.Audit)
		}
		return DirectOIDCBrowserOutcome{}, ErrDirectAuthenticationDenied
	}
	configuration := resolver.configuration
	secretLookup := DirectOIDCClientSecretLookup{
		Pins: resolver.pins,
	}
	secret, err := application.clientSecrets.OpenDirectOIDCClientSecret(operation, secretLookup)
	secretCopy := append([]byte(nil), secret...)
	clear(secret)
	if err != nil || operation.Err() != nil || len(secretCopy) == 0 {
		clear(secretCopy)
		application.abort(ctx, claimed, request.Audit)
		return DirectOIDCBrowserOutcome{}, ErrDirectAuthenticationDenied
	}
	clientCredential := federatedoidc.ClientCredential{
		Revision: secretLookup.Pins.ClientSecretRevision, Secret: secretCopy,
	}
	bundle, err := application.transactions.ExchangeCode(operation, claimed.Authorization, clientCredential)
	clear(clientCredential.Secret)
	if err != nil || bundle == nil {
		application.abort(ctx, claimed, request.Audit)
		return DirectOIDCBrowserOutcome{}, ErrDirectAuthenticationDenied
	}
	defer bundle.Destroy()
	proof, err := application.transactions.VerifyIDToken(
		operation, claimed.Authorization, bundle, cloneDirectOIDCClaimPolicy(configuration.IDTokenClaims),
	)
	if err != nil || proof == nil {
		application.abort(ctx, claimed, request.Audit)
		return DirectOIDCBrowserOutcome{}, ErrDirectAuthenticationDenied
	}
	sessionMaterial, err := application.transactions.TakeSessionMaterial(configuration.Authorization, bundle)
	bundle.Destroy()
	if err != nil {
		if sessionMaterial != nil {
			sessionMaterial.Destroy()
		}
		application.abort(ctx, claimed, request.Audit)
		return DirectOIDCBrowserOutcome{}, ErrDirectAuthenticationDenied
	}
	if sessionMaterial != nil {
		defer sessionMaterial.Destroy()
	}
	now := application.now()
	if !validInstant(now) {
		application.abort(ctx, claimed, request.Audit)
		return DirectOIDCBrowserOutcome{}, ErrDirectAuthenticationDenied
	}
	plan, err := application.trust.Plan(operation, DirectOIDCTrustPlanRequest{
		TransactionID: resolver.transaction.TransactionID, ClaimAttemptID: claimed.ClaimAttemptID,
		ObservedAt: now, Pins: resolver.pins, Proof: proof,
	})
	plan = cloneDirectAuthenticationPlan(plan)
	if err != nil || operation.Err() != nil ||
		!validDirectPlanForBrowserApply(plan, resolver.pins, resolver.transaction, resolver.returnPath, now) {
		application.abort(ctx, claimed, request.Audit)
		return DirectOIDCBrowserOutcome{}, ErrDirectAuthenticationDenied
	}
	credentialRequest := federatedauth.ApplyCredentialRequest{
		Disposition: directApplyDisposition(plan.Disposition), Method: federatedauth.AuthenticationMethodOIDC,
		ContinuationAuthority: directContinuationAuthority(plan.Disposition), IssuedAt: now,
	}
	credential, err := application.credentials.ReserveApplyCredential(credentialRequest)
	if err != nil || credential == nil || !validDirectCredentialReservation(credential, credentialRequest) {
		if credential != nil {
			credential.Destroy()
		}
		application.abort(ctx, claimed, request.Audit)
		return DirectOIDCBrowserOutcome{}, ErrDirectAuthenticationDenied
	}
	defer credential.Destroy()
	materialID := plan.Completion.MaterialID
	wantIDToken := configuration.Authorization.Discovery.Endpoints().EndSession != ""
	wantRefreshToken := configuration.Authorization.AllowRefreshToken
	wantMaterial := wantIDToken || wantRefreshToken
	if wantMaterial != (sessionMaterial != nil) || !validDirectEntityID(materialID) {
		application.abort(ctx, claimed, request.Audit)
		return DirectOIDCBrowserOutcome{}, ErrDirectAuthenticationDenied
	}
	var protected *federatedauth.ProtectedOIDCSessionMaterial
	if sessionMaterial != nil {
		sealed, sealErr := application.sessionSealer.SealOIDCSessionMaterial(
			operation,
			federatedauth.OIDCSessionMaterialSealContext{
				Provider:    configuration.Authorization.Provider,
				Admission:   configuration.Authorization.Admission,
				MaterialID:  materialID,
				KeepIDToken: wantIDToken, KeepRefreshToken: wantRefreshToken,
			},
			sessionMaterial,
		)
		if sealErr != nil || !sealed.ValidFor(materialID, wantIDToken, wantRefreshToken) {
			sealed.Destroy()
			application.abort(ctx, claimed, request.Audit)
			return DirectOIDCBrowserOutcome{}, ErrDirectAuthenticationDenied
		}
		protected = &sealed
		defer protected.Destroy()
	}
	ownerExpiresAt := credential.Session().AbsoluteExpiresAt()
	if plan.Disposition == DirectAuthenticationTOTPContinuation {
		ownerExpiresAt = credential.Continuation().ExpiresAt()
	}
	materialExpiresAt := plan.ValidUntil
	if ownerExpiresAt.Before(materialExpiresAt) {
		materialExpiresAt = ownerExpiresAt
	}
	protectedForApply := protected.Clone()
	if protectedForApply != nil && protectedForApply.RefreshToken != nil &&
		protectedForApply.AccessExpiresAt.After(materialExpiresAt) {
		protectedForApply.AccessExpiresAt = materialExpiresAt
	}
	applyRequest := DirectOIDCApplyRequest{
		Plan: cloneDirectAuthenticationPlan(plan), ClaimAttemptID: claimed.ClaimAttemptID,
		Assurance:               cloneDirectSelectedAssurance(plan.SelectedAssurance),
		ContinuationAuthority:   directContinuationAuthority(plan.Disposition),
		Session:                 credential.Session(),
		Continuation:            credential.Continuation(),
		BrowserCapabilityDigest: browserDigest,
		ReturnPath:              plan.Completion.ReturnPath,
		Observation:             cloneDirectSubjectObservation(plan.Subject),
		AppliedAt:               now, Audit: request.Audit,
		MaterialID: materialID, SessionMaterial: protectedForApply,
		MaterialExpiresAt: materialExpiresAt,
		Configuration:     configuration.Authorization,
	}
	defer applyRequest.SessionMaterial.Destroy()
	result, err := application.applyDirect(operation, applyRequest)
	if err != nil || operation.Err() != nil || !validDirectOIDCApplyResult(result, applyRequest) {
		application.abort(ctx, claimed, request.Audit)
		return DirectOIDCBrowserOutcome{}, ErrDirectAuthenticationDenied
	}
	browserCredential, released := credential.ReleaseBrowserCredential(result.SessionID, result.ContinuationID)
	if !released || browserCredential == nil {
		if browserCredential != nil {
			browserCredential.Destroy()
		}
		application.abort(ctx, claimed, request.Audit)
		return DirectOIDCBrowserOutcome{}, ErrDirectAuthenticationDenied
	}
	return DirectOIDCBrowserOutcome{
		Disposition: result.Disposition, UserID: result.UserID,
		SessionID: result.SessionID, ContinuationID: result.ContinuationID,
		ReturnPath: result.ReturnPath, Credential: browserCredential,
	}, nil
}

func (application *DirectOIDCBrowserApplication) begin(
	ctx context.Context,
	authority DirectOIDCStartAuthority,
) (DirectOIDCStartGrant, error) {
	var result DirectOIDCStartGrant
	var err error
	for range 2 {
		result, err = application.starts.BeginDirectOIDCLogin(ctx, authority)
		if err == nil || ctx.Err() != nil {
			break
		}
	}
	return result, err
}

func (application *DirectOIDCBrowserApplication) loadStartConfiguration(
	ctx context.Context,
	grant DirectOIDCStartGrant,
) (DirectOIDCStartConfigurationSnapshot, error) {
	var result DirectOIDCStartConfigurationSnapshot
	var err error
	for range 2 {
		result, err = application.configurations.LoadDirectOIDCStartConfiguration(ctx, grant)
		if err == nil || ctx.Err() != nil {
			break
		}
	}
	return result, err
}

func (application *DirectOIDCBrowserApplication) applyDirect(
	ctx context.Context,
	request DirectOIDCApplyRequest,
) (DirectOIDCApplyResult, error) {
	var result DirectOIDCApplyResult
	var err error
	for range 2 {
		if !validDirectApplyCredentialProjection(request) {
			return DirectOIDCApplyResult{}, ErrDirectAuthenticationDenied
		}
		result, err = application.apply.ApplyDirectOIDC(ctx, cloneDirectOIDCApplyRequest(request))
		if err == nil || ctx.Err() != nil {
			break
		}
	}
	return result, err
}

func (application *DirectOIDCBrowserApplication) operation(
	ctx context.Context,
) (context.Context, context.CancelFunc, bool) {
	if application == nil || ctx == nil || ctx.Err() != nil || application.operationTimeout <= 0 {
		return nil, nil, false
	}
	operation, cancel := context.WithTimeout(ctx, application.operationTimeout)
	return operation, cancel, true
}

func (application *DirectOIDCBrowserApplication) abort(
	ctx context.Context,
	claimed DirectClaimedAuthorization,
	audit DirectAuditContext,
) {
	for range 2 {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), application.operationTimeout)
		err := application.transactions.AbortDirectClaimedAuthorization(cleanup, claimed, audit)
		cancel()
		if err == nil {
			return
		}
	}
}

type directOIDCCallbackResolver struct {
	source                  DirectOIDCConfigurationSource
	browserCapabilityDigest DirectBrowserCapabilityDigest
	configuration           DirectOIDCConfiguration
	pins                    DirectOIDCConfigurationPins
	transaction             federatedoidc.CallbackConfigurationLookup
	returnPath              string
	resolved                bool
}

func (resolver *directOIDCCallbackResolver) ResolveOIDCCallbackConfiguration(
	ctx context.Context,
	transaction federatedoidc.CallbackConfigurationLookup,
) (federatedoidc.AuthorizationConfiguration, error) {
	if resolver == nil || resolver.source == nil || resolver.resolved || ctx == nil || ctx.Err() != nil {
		return federatedoidc.AuthorizationConfiguration{}, ErrDirectAuthenticationDenied
	}
	lookup := DirectOIDCCallbackConfigurationLookup{
		Transaction: transaction, BrowserCapabilityDigest: resolver.browserCapabilityDigest,
	}
	if !validDirectOIDCCallbackLookup(lookup) {
		return federatedoidc.AuthorizationConfiguration{}, ErrDirectAuthenticationDenied
	}
	var snapshot DirectOIDCCallbackConfigurationSnapshot
	var err error
	for range 2 {
		snapshot, err = resolver.source.ResolveDirectOIDCCallbackConfiguration(ctx, lookup)
		if err == nil || ctx.Err() != nil {
			break
		}
	}
	snapshot = cloneDirectOIDCCallbackConfigurationSnapshot(snapshot)
	protocolPins, pinsOK := directConfigurationPinsFromTransaction(transaction.Pins)
	if err != nil || ctx.Err() != nil || snapshot.Lookup != lookup || !pinsOK ||
		!validDirectOIDCConfigurationPins(snapshot.Pins) ||
		!sameDirectOIDCProtocolPins(protocolPins, snapshot.Pins) ||
		!validDirectReturnPath(snapshot.ReturnPath) || snapshot.ReturnPath != transaction.ReturnPath ||
		!validDirectOIDCConfiguration(snapshot.Configuration, snapshot.Pins) {
		return federatedoidc.AuthorizationConfiguration{}, ErrDirectAuthenticationDenied
	}
	bound, ok := bindDirectOIDCConfigurationPins(snapshot.Configuration.Authorization, snapshot.Pins)
	if !ok {
		return federatedoidc.AuthorizationConfiguration{}, ErrDirectAuthenticationDenied
	}
	snapshot.Configuration.Authorization = bound
	resolver.configuration = snapshot.Configuration
	resolver.pins = snapshot.Pins
	resolver.transaction = transaction
	resolver.returnPath = transaction.ReturnPath
	resolver.resolved = true
	return bound, nil
}

func validDirectOIDCConfiguration(
	configuration DirectOIDCConfiguration,
	wanted DirectOIDCConfigurationPins,
) bool {
	authorization := configuration.Authorization
	pins, ok := directConfigurationPinsFromAuthorization(authorization)
	if !ok || !validDirectOIDCConfigurationPins(wanted) ||
		!sameDirectOIDCProtocolPins(pins, wanted) || authorization.UseUserInfo {
		return false
	}
	policy := configuration.IDTokenClaims
	if len(policy.Scalars) != 0 || len(policy.Profiles) != 0 || policy.Groups != nil {
		return false
	}
	return (policy.ACR == nil || policy.ACR.Claim == "acr" && !policy.ACR.Required) &&
		(policy.AMR == nil || policy.AMR.Claim == "amr" && !policy.AMR.Required)
}

func directConfigurationPinsFromAuthorization(
	authorization federatedoidc.AuthorizationConfiguration,
) (DirectOIDCConfigurationPins, bool) {
	direct := authorization.Authority == federatedoidc.DirectPlatformCeremonyAuthority &&
		validDirectProvider(authorization.Provider) && authorization.Admission == (identity.TenantAdmissionContext{}) &&
		authorization.BindingID == (identity.EntityID{}) && authorization.BindingRevision == 0 &&
		authorization.MappingRevision == 0 && authorization.AuthorizationRevision == 0 &&
		validDirectRevision(authorization.PlatformLoginRevision)
	discoveryRevision := authorization.Discovery.Revision()
	discoveryDigest := authorization.Discovery.Digest()
	jwksRevision := authorization.JWKS.Revision()
	jwksDigest := authorization.JWKS.Digest()
	pins := DirectOIDCConfigurationPins{
		Provider: authorization.Provider, ProviderRevision: authorization.ProviderRevision,
		PlatformLoginRevision:       authorization.PlatformLoginRevision,
		ConfigurationRevision:       authorization.ConfigurationRevision,
		SecurityRevision:            authorization.SecurityRevision,
		PlanRevision:                authorization.PlanRevision,
		AssurancePolicyRevision:     authorization.AssurancePolicyRevision,
		PlatformFloorPolicyID:       authorization.PlatformFloorPolicyID,
		PlatformFloorPolicyRevision: authorization.PlatformFloorRevision,
		ClientSecretRevision:        authorization.ClientSecretRevision,
		DiscoveryRevision:           discoveryRevision, DiscoveryDigest: discoveryDigest,
		JWKSRevision: jwksRevision, JWKSDigest: jwksDigest,
	}
	return pins, direct && validDirectOIDCProtocolPins(pins) &&
		authorization.JWKS.DiscoveryRevision() == discoveryRevision &&
		authorization.JWKS.DiscoveryDigest() == discoveryDigest
}

func directConfigurationPinsFromTransaction(
	pins federatedoidc.TransactionPins,
) (DirectOIDCConfigurationPins, bool) {
	loginRevision, direct := pins.DirectPlatformLogin()
	result := DirectOIDCConfigurationPins{
		Provider: pins.Provider, ProviderRevision: pins.ProviderRevision,
		PlatformLoginRevision: loginRevision, ConfigurationRevision: pins.ConfigurationRevision,
		SecurityRevision: pins.SecurityRevision, PlanRevision: pins.PlanRevision,
		AssurancePolicyRevision:     pins.AssurancePolicyRevision,
		PlatformFloorPolicyID:       pins.PlatformFloorPolicyID,
		PlatformFloorPolicyRevision: pins.PlatformFloorRevision,
		ClientSecretRevision:        pins.ClientSecretRevision,
		DiscoveryRevision:           pins.DiscoveryRevision, DiscoveryDigest: pins.DiscoveryDigest,
		JWKSRevision: pins.JWKSRevision, JWKSDigest: pins.JWKSDigest,
	}
	return result, direct && validDirectOIDCProtocolPins(result)
}

func validDirectOIDCConfigurationPins(pins DirectOIDCConfigurationPins) bool {
	return validDirectOIDCProtocolPins(pins) && validDirectRevision(pins.PlanRevision) &&
		validDirectEntityID(pins.PlatformFloorPolicyID) &&
		validDirectRevision(pins.PlatformFloorPolicyRevision)
}

func validDirectOIDCProtocolPins(pins DirectOIDCConfigurationPins) bool {
	return validDirectProvider(pins.Provider) && validDirectRevision(pins.ProviderRevision) &&
		validDirectRevision(pins.PlatformLoginRevision) && validDirectRevision(pins.ConfigurationRevision) &&
		validDirectRevision(pins.SecurityRevision) && validDirectRevision(pins.AssurancePolicyRevision) &&
		validDirectRevision(pins.ClientSecretRevision) && validDirectRevision(pins.DiscoveryRevision) &&
		pins.DiscoveryDigest != ([sha256.Size]byte{}) && validDirectRevision(pins.JWKSRevision) &&
		pins.JWKSDigest != ([sha256.Size]byte{})
}

func sameDirectOIDCProtocolPins(left, right DirectOIDCConfigurationPins) bool {
	return left.Provider == right.Provider && left.ProviderRevision == right.ProviderRevision &&
		left.PlatformLoginRevision == right.PlatformLoginRevision &&
		left.ConfigurationRevision == right.ConfigurationRevision &&
		left.SecurityRevision == right.SecurityRevision &&
		left.AssurancePolicyRevision == right.AssurancePolicyRevision &&
		left.ClientSecretRevision == right.ClientSecretRevision &&
		left.DiscoveryRevision == right.DiscoveryRevision && left.DiscoveryDigest == right.DiscoveryDigest &&
		left.JWKSRevision == right.JWKSRevision && left.JWKSDigest == right.JWKSDigest
}

func sameDirectOIDCConfigurationPins(left, right DirectOIDCConfigurationPins) bool {
	return sameDirectOIDCProtocolPins(left, right) && left.PlanRevision == right.PlanRevision &&
		left.PlatformFloorPolicyID == right.PlatformFloorPolicyID &&
		left.PlatformFloorPolicyRevision == right.PlatformFloorPolicyRevision
}

func bindDirectOIDCConfigurationPins(
	authorization federatedoidc.AuthorizationConfiguration,
	pins DirectOIDCConfigurationPins,
) (federatedoidc.AuthorizationConfiguration, bool) {
	current, direct := directConfigurationPinsFromAuthorization(authorization)
	if !direct || !validDirectOIDCConfigurationPins(pins) ||
		!sameDirectOIDCProtocolPins(current, pins) ||
		(current.PlanRevision != 0 || current.PlatformFloorPolicyID != (identity.EntityID{}) ||
			current.PlatformFloorPolicyRevision != 0) && !sameDirectOIDCConfigurationPins(current, pins) {
		return federatedoidc.AuthorizationConfiguration{}, false
	}
	authorization.PlanRevision = pins.PlanRevision
	authorization.PlatformFloorPolicyID = pins.PlatformFloorPolicyID
	authorization.PlatformFloorRevision = pins.PlatformFloorPolicyRevision
	return authorization, true
}

func validDirectOIDCCallbackLookup(lookup DirectOIDCCallbackConfigurationLookup) bool {
	_, direct := directConfigurationPinsFromTransaction(lookup.Transaction.Pins)
	return direct && validTransactionID(lookup.Transaction.TransactionID) &&
		validDirectRevision(lookup.Transaction.ExpectedVersion) &&
		validDirectReturnPath(lookup.Transaction.ReturnPath) &&
		lookup.BrowserCapabilityDigest != (DirectBrowserCapabilityDigest{})
}

func validDirectPlanForBrowserApply(
	plan DirectAuthenticationPlan,
	pins DirectOIDCConfigurationPins,
	transaction federatedoidc.CallbackConfigurationLookup,
	returnPath string,
	now time.Time,
) bool {
	completionPins, direct := directConfigurationPinsFromTransaction(plan.Completion.Pins)
	if !direct || !validDirectOIDCConfigurationPins(pins) ||
		!sameDirectOIDCConfigurationPins(completionPins, pins) || plan.Completion.ID != transaction.TransactionID ||
		plan.Completion.ExpectedVersion != transaction.ExpectedVersion || plan.Completion.Pins != transaction.Pins ||
		plan.Completion.ReturnPath != returnPath || !validDirectReturnPath(returnPath) ||
		!validInstant(plan.Completion.CompletedAt) || plan.Completion.CompletedAt.After(now) ||
		!validDirectEntityID(plan.Completion.MaterialID) || !validInstant(plan.ValidUntil) ||
		!plan.ValidUntil.After(now) ||
		plan.Provider != pins.Provider || plan.ProviderRevision != pins.ProviderRevision ||
		plan.PlatformLoginRevision != pins.PlatformLoginRevision ||
		plan.ConfigurationRevision != pins.ConfigurationRevision || plan.SecurityRevision != pins.SecurityRevision ||
		plan.AssurancePolicyRevision != pins.AssurancePolicyRevision || plan.PlanRevision != pins.PlanRevision ||
		!validDirectRevision(plan.UserAuthenticationRevision) || !validDirectRevision(plan.IdentityRevision) ||
		plan.MatchedAliasKeyVersion < 1 ||
		!validDirectEntityID(plan.UserID) || !validDirectEntityID(plan.ExternalIdentityID) ||
		plan.Subject.ExternalIdentityID != plan.ExternalIdentityID ||
		plan.Subject.SubjectFormat != identity.UTF8ExactSubject || !validDirectSubjectAliases(plan.Subject.Aliases) ||
		!directSubjectAliasKeyVersionPresent(plan.Subject.Aliases, plan.MatchedAliasKeyVersion) ||
		plan.Subject.Envelope.KeyVersion < 1 || plan.Subject.Envelope.Format != identity.UTF8ExactSubject ||
		len(plan.Subject.Envelope.Ciphertext) <= 16 || !validDirectSelectedAssurance(plan.SelectedAssurance) ||
		plan.SelectedAssurance.AuthenticatedAt.After(now) || len(plan.Evidence) == 0 ||
		!validDirectPinnedPlatformFloor(plan.PlatformFloor, pins) || !validSelectedAssuranceEvidence(plan) {
		return false
	}
	decision := identity.EvaluateAssurance(now, plan.PlatformFloor, plan.Evidence, false)
	switch plan.Disposition {
	case DirectAuthenticationImmediateSession:
		return plan.TOTP == nil && decision == identity.AssuranceSatisfied
	case DirectAuthenticationTOTPContinuation:
		return plan.TOTP != nil && validDirectEntityID(plan.TOTP.FactorID) &&
			validDirectRevision(plan.TOTP.Revision) && decision == identity.AssuranceStepUpRequired
	default:
		return false
	}
}

func validDirectPinnedPlatformFloor(
	requirement identity.EffectiveAssuranceRequirement,
	pins DirectOIDCConfigurationPins,
) bool {
	return validDirectRequirementIDs(requirement) && len(requirement.PolicyRevisions) == 1 &&
		requirement.PolicyRevisions[0].PolicyID == pins.PlatformFloorPolicyID &&
		requirement.PolicyRevisions[0].Revision == int64(pins.PlatformFloorPolicyRevision)
}

func validSelectedAssuranceEvidence(plan DirectAuthenticationPlan) bool {
	primary := plan.Evidence[0]
	if primary.Level != identity.AssurancePrimary || primary.Source.Local ||
		!primary.Source.DirectPlatform || primary.Source.ProviderID != plan.Provider.ProviderID ||
		primary.Source.BindingID != (identity.EntityID{}) || primary.Kind != identity.AssuranceEvidenceFactor ||
		primary.FactorRevision != nil || primary.TrustRuleRevision == nil ||
		*primary.TrustRuleRevision != int64(plan.SecurityRevision) {
		return false
	}
	for _, evidence := range plan.Evidence {
		if evidence.Source.Local || !evidence.Source.DirectPlatform ||
			evidence.Source.ProviderID != plan.Provider.ProviderID ||
			evidence.Source.BindingID != (identity.EntityID{}) ||
			evidence.Kind != identity.AssuranceEvidenceFactor || evidence.FactorRevision != nil ||
			evidence.TrustRuleRevision == nil || *evidence.TrustRuleRevision < 1 {
			return false
		}
	}
	selected := plan.SelectedAssurance
	if selected.Level == identity.AssurancePrimary {
		return len(plan.Evidence) == 1 && selected.AuthenticatedAt.Equal(primary.AuthenticatedAt)
	}
	if selected.TrustRuleRevision == nil {
		return false
	}
	for _, evidence := range plan.Evidence[1:] {
		if evidence.Level == selected.Level && evidence.Source.DirectPlatform &&
			evidence.Source.ProviderID == plan.Provider.ProviderID &&
			evidence.Source.BindingID == (identity.EntityID{}) &&
			evidence.TrustRuleRevision != nil &&
			uint64(*evidence.TrustRuleRevision) == *selected.TrustRuleRevision &&
			evidence.AuthenticatedAt.Equal(selected.AuthenticatedAt) {
			return true
		}
	}
	return false
}

func directSubjectAliasKeyVersionPresent(values []identity.SubjectAlias, keyVersion int16) bool {
	for _, value := range values {
		if value.KeyVersion == keyVersion {
			return true
		}
	}
	return false
}

func validDirectOIDCApplyResult(result DirectOIDCApplyResult, request DirectOIDCApplyRequest) bool {
	if !equalDirectSelectedAssurance(request.Assurance, request.Plan.SelectedAssurance) ||
		!equalDirectSubjectObservation(request.Observation, request.Plan.Subject) ||
		request.Configuration.Pins() != request.Plan.Completion.Pins ||
		!validTransactionID(request.ClaimAttemptID) ||
		result.Disposition != request.Plan.Disposition || result.TransactionID != request.Plan.Completion.ID ||
		request.ContinuationAuthority != directContinuationAuthority(request.Plan.Disposition) ||
		!validDirectApplyCredentialProjection(request) || !validDirectAuditContext(request.Audit) ||
		result.BrowserCapabilityDigest != request.BrowserCapabilityDigest ||
		result.UserID != request.Plan.UserID || result.ReturnPath != request.ReturnPath ||
		!validDirectReturnPath(result.ReturnPath) || !result.AppliedAt.Equal(request.AppliedAt) {
		return false
	}
	switch result.Disposition {
	case DirectAuthenticationImmediateSession:
		return validDirectEntityID(result.SessionID) && result.ContinuationID == (identity.EntityID{}) &&
			request.Session.SessionID() == result.SessionID && request.Continuation.IsZero()
	case DirectAuthenticationTOTPContinuation:
		return result.SessionID == (identity.EntityID{}) && validDirectEntityID(result.ContinuationID) &&
			request.Session.IsZero() && request.Continuation.ContinuationID() == result.ContinuationID &&
			request.Continuation.Authority() == federatedauth.ContinuationAuthorityDirectPlatformOIDC
	default:
		return false
	}
}

func validDirectApplyCredentialProjection(request DirectOIDCApplyRequest) bool {
	if !validInstant(request.AppliedAt) || !validTransactionID(request.ClaimAttemptID) ||
		request.BrowserCapabilityDigest == (DirectBrowserCapabilityDigest{}) ||
		!validDirectReturnPath(request.ReturnPath) || !validDirectAuditContext(request.Audit) ||
		!equalDirectSubjectObservation(request.Observation, request.Plan.Subject) ||
		request.MaterialID != request.Plan.Completion.MaterialID || !validDirectEntityID(request.MaterialID) ||
		!validInstant(request.MaterialExpiresAt) || !request.MaterialExpiresAt.After(request.AppliedAt) ||
		request.MaterialExpiresAt.After(request.Plan.ValidUntil) || request.SessionMaterial != nil &&
		!request.SessionMaterial.ValidFor(
			request.MaterialID, request.SessionMaterial.IDToken != nil, request.SessionMaterial.RefreshToken != nil,
		) {
		return false
	}
	switch request.Plan.Disposition {
	case DirectAuthenticationImmediateSession:
		return request.ContinuationAuthority == federatedauth.ContinuationAuthorityTenant &&
			request.Continuation.IsZero() && request.Session.ValidAt(request.AppliedAt.Truncate(time.Millisecond)) &&
			string(request.Session.AuthenticationMethod()) == string(federatedauth.AuthenticationMethodOIDC)
	case DirectAuthenticationTOTPContinuation:
		return request.ContinuationAuthority == federatedauth.ContinuationAuthorityDirectPlatformOIDC &&
			request.Session.IsZero() && request.Continuation.ValidAt(request.AppliedAt) &&
			request.Continuation.Authority() == federatedauth.ContinuationAuthorityDirectPlatformOIDC
	default:
		return false
	}
}

func directApplyDisposition(
	disposition DirectAuthenticationDisposition,
) federatedauth.ApplyDisposition {
	if disposition == DirectAuthenticationImmediateSession {
		return federatedauth.ApplySession
	}
	return federatedauth.ApplyContinuation
}

func validDirectCredentialReservation(
	reservation *federatedauth.ApplyCredentialReservation,
	request federatedauth.ApplyCredentialRequest,
) bool {
	if reservation == nil || request.Method != federatedauth.AuthenticationMethodOIDC ||
		!validInstant(request.IssuedAt) {
		return false
	}
	session := reservation.Session()
	continuation := reservation.Continuation()
	switch request.Disposition {
	case federatedauth.ApplySession:
		return request.ContinuationAuthority == federatedauth.ContinuationAuthorityTenant &&
			continuation.IsZero() && session.ValidAt(request.IssuedAt.Truncate(time.Millisecond)) &&
			string(session.AuthenticationMethod()) == string(federatedauth.AuthenticationMethodOIDC)
	case federatedauth.ApplyContinuation:
		return request.ContinuationAuthority == federatedauth.ContinuationAuthorityDirectPlatformOIDC &&
			session.IsZero() && continuation.ValidAt(request.IssuedAt) &&
			continuation.Authority() == federatedauth.ContinuationAuthorityDirectPlatformOIDC
	default:
		return false
	}
}

func directContinuationAuthority(
	disposition DirectAuthenticationDisposition,
) federatedauth.ContinuationAuthority {
	if disposition == DirectAuthenticationTOTPContinuation {
		return federatedauth.ContinuationAuthorityDirectPlatformOIDC
	}
	return federatedauth.ContinuationAuthorityTenant
}

func cloneDirectOIDCStartConfigurationSnapshot(
	value DirectOIDCStartConfigurationSnapshot,
) DirectOIDCStartConfigurationSnapshot {
	value.Configuration = cloneDirectOIDCConfiguration(value.Configuration)
	return value
}

func cloneDirectOIDCCallbackConfigurationSnapshot(
	value DirectOIDCCallbackConfigurationSnapshot,
) DirectOIDCCallbackConfigurationSnapshot {
	value.Configuration = cloneDirectOIDCConfiguration(value.Configuration)
	return value
}

func cloneDirectOIDCConfiguration(value DirectOIDCConfiguration) DirectOIDCConfiguration {
	value.Authorization.ExtraScopes = append([]string(nil), value.Authorization.ExtraScopes...)
	value.IDTokenClaims = cloneDirectOIDCClaimPolicy(value.IDTokenClaims)
	return value
}

func cloneDirectOIDCClaimPolicy(value federatedoidc.ClaimExtractionPolicy) federatedoidc.ClaimExtractionPolicy {
	value.Scalars = append([]federatedoidc.ScalarClaimRule(nil), value.Scalars...)
	value.Profiles = append([]federatedoidc.ProfileClaimRule(nil), value.Profiles...)
	if value.Groups != nil {
		copyValue := *value.Groups
		value.Groups = &copyValue
	}
	if value.ACR != nil {
		copyValue := *value.ACR
		value.ACR = &copyValue
	}
	if value.AMR != nil {
		copyValue := *value.AMR
		value.AMR = &copyValue
	}
	return value
}

func cloneDirectAuthenticationPlan(value DirectAuthenticationPlan) DirectAuthenticationPlan {
	value.Subject = cloneDirectSubjectObservation(value.Subject)
	value.Evidence = cloneDirectEvidence(value.Evidence)
	value.SelectedAssurance = cloneDirectSelectedAssurance(value.SelectedAssurance)
	value.PlatformFloor = cloneDirectRequirement(value.PlatformFloor)
	if value.TOTP != nil {
		copyValue := *value.TOTP
		value.TOTP = &copyValue
	}
	return value
}

func cloneDirectSubjectObservation(value DirectSubjectObservation) DirectSubjectObservation {
	value.Aliases = append([]identity.SubjectAlias(nil), value.Aliases...)
	value.Envelope.Ciphertext = append([]byte(nil), value.Envelope.Ciphertext...)
	return value
}

func cloneDirectOIDCApplyRequest(value DirectOIDCApplyRequest) DirectOIDCApplyRequest {
	value.Plan = cloneDirectAuthenticationPlan(value.Plan)
	value.Observation = cloneDirectSubjectObservation(value.Observation)
	value.Assurance = cloneDirectSelectedAssurance(value.Assurance)
	value.SessionMaterial = value.SessionMaterial.Clone()
	value.Configuration.ExtraScopes = append([]string(nil), value.Configuration.ExtraScopes...)
	return value
}

func equalDirectSubjectObservation(left, right DirectSubjectObservation) bool {
	return left.ExternalIdentityID == right.ExternalIdentityID && left.SubjectFormat == right.SubjectFormat &&
		slices.Equal(left.Aliases, right.Aliases) && left.Envelope.KeyVersion == right.Envelope.KeyVersion &&
		left.Envelope.Format == right.Envelope.Format && left.Envelope.Nonce == right.Envelope.Nonce &&
		slices.Equal(left.Envelope.Ciphertext, right.Envelope.Ciphertext)
}

func equalDirectSelectedAssurance(left, right DirectSelectedAssurance) bool {
	if left.Level != right.Level || !left.AuthenticatedAt.Equal(right.AuthenticatedAt) ||
		(left.TrustRuleID == nil) != (right.TrustRuleID == nil) ||
		(left.TrustRuleRevision == nil) != (right.TrustRuleRevision == nil) {
		return false
	}
	return (left.TrustRuleID == nil || *left.TrustRuleID == *right.TrustRuleID) &&
		(left.TrustRuleRevision == nil || *left.TrustRuleRevision == *right.TrustRuleRevision)
}

func validDirectReturnPath(value string) bool {
	return returnpath.Valid(value)
}
