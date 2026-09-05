package federatedauth

import (
	"context"
	"crypto/sha256"
	"fmt"
	"regexp"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
)

var (
	tenantOIDCSlugPattern     = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	tenantOIDCLoginKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{2,63}$`)
)

// The three named digest types prevent accidental reuse between rate-limit
// purposes. They are produced by the API's deployment keyring; this package
// never handles or derives that key material.
type OIDCStartReceiptDigest = federatedoidc.StartReceiptDigest
type OIDCNetworkRateDigest = federatedoidc.NetworkThrottleDigest
type OIDCAccountRateDigest = federatedoidc.AccountThrottleDigest
type OIDCProviderRateDigest = federatedoidc.ProviderThrottleDigest

// OIDCStartLookup is the bounded public locator and shared database-metering
// input. No username, email, token, or assertion is accepted here.
type OIDCStartLookup struct {
	OperationRunID identity.EntityID
	ReceiptDigest  OIDCStartReceiptDigest
	TenantSlug     string
	LoginKey       string
	NetworkDigest  OIDCNetworkRateDigest
	AccountDigest  OIDCAccountRateDigest
	ProviderDigest OIDCProviderRateDigest
}

func (lookup OIDCStartLookup) String() string {
	return "federatedauth.OIDCStartLookup{locator:[REDACTED],digests:true}"
}
func (lookup OIDCStartLookup) GoString() string { return lookup.String() }

// TenantOIDCConfiguration binds browser protocol configuration to the exact
// claim projections consumed by the provider-neutral JIT planner. UserInfo is
// additive and may never supply AMR or replace an ID-token value.
type TenantOIDCConfiguration struct {
	Authorization  federatedoidc.AuthorizationConfiguration
	IDTokenClaims  federatedoidc.ClaimExtractionPolicy
	UserInfoClaims federatedoidc.ClaimExtractionPolicy
}

func (configuration TenantOIDCConfiguration) String() string {
	return fmt.Sprintf(
		"federatedauth.TenantOIDCConfiguration{authorization:%q,id_token_claims:%q,userinfo_claims:%q}",
		configuration.Authorization.String(), configuration.IDTokenClaims.String(), configuration.UserInfoClaims.String(),
	)
}
func (configuration TenantOIDCConfiguration) GoString() string { return configuration.String() }

// TenantOIDCConfigurationSource is the future narrow PostgreSQL ABI. Begin
// must meter and commit the one-time receipt plus the exact returned pins
// before returning a generic result. An exact retry of Begin after response
// loss must replay the same snapshot without charging the receipt twice.
// TransactionRepository.CreateReplacing
// consumes that receipt and rechecks the pins; Resolve is called only after
// the callback claim wins and derives tenant context exclusively from pins.
type TenantOIDCConfigurationSource interface {
	BeginTenantOIDCLogin(context.Context, OIDCStartLookup) (TenantOIDCConfiguration, error)
	ResolveTenantOIDCCallback(context.Context, federatedoidc.CallbackConfigurationLookup) (TenantOIDCConfiguration, error)
}

// OIDCUserInfoSource is deliberately narrower than a generic HTTP client.
type OIDCUserInfoSource interface {
	FetchUserInfo(context.Context, *federatedoidc.UserInfoRequest, string) (federatedoidc.UserInfoDocument, error)
}

// OIDCProtocolFlow is the hardened protocol-kernel surface consumed here.
// The production implementation is *federatedoidc.Flow; the interface keeps
// application-ordering tests independent from JOSE fixtures.
type OIDCProtocolFlow interface {
	StartAuthorization(context.Context, federatedoidc.StartAuthorizationRequest) (federatedoidc.AuthorizationStart, error)
	ClaimCallbackResolved(context.Context, federatedoidc.ResolvedCallbackRequest, federatedoidc.CallbackConfigurationResolver) (*federatedoidc.ClaimedAuthorization, error)
	ExchangeCode(context.Context, *federatedoidc.ClaimedAuthorization, federatedoidc.ClientCredential) (*federatedoidc.TokenBundle, error)
	VerifyIDToken(context.Context, *federatedoidc.ClaimedAuthorization, *federatedoidc.TokenBundle, federatedoidc.ClaimExtractionPolicy) (*federatedoidc.VerifiedAuthentication, error)
	BuildUserInfoRequest(federatedoidc.AuthorizationConfiguration, *federatedoidc.TokenBundle) (*federatedoidc.UserInfoRequest, error)
	MergeUserInfo(federatedoidc.VerifiedAuthentication, federatedoidc.UserInfoDocument, federatedoidc.ClaimExtractionPolicy) (federatedoidc.VerifiedAuthentication, error)
	TakeSessionMaterial(federatedoidc.AuthorizationConfiguration, *federatedoidc.TokenBundle) (*federatedoidc.SessionMaterial, error)
	AbortClaimedAuthorization(context.Context, *federatedoidc.ClaimedAuthorization) error
}

type OIDCAuthenticationApplication interface {
	ApplyOIDC(context.Context, OIDCApplicationRequest) (ApplyResult, error)
}

type OIDCLoginOptions struct {
	Flow             OIDCProtocolFlow
	Application      OIDCAuthenticationApplication
	Configurations   TenantOIDCConfigurationSource
	ClientSecrets    ClientSecretSource
	UserInfo         OIDCUserInfoSource
	OperationTimeout time.Duration
}

// OIDCLogin coordinates network-free start, one-time callback claim, secret
// access, network proof validation, shared JIT planning, and atomic apply.
type OIDCLogin struct {
	flow             OIDCProtocolFlow
	application      OIDCAuthenticationApplication
	configurations   TenantOIDCConfigurationSource
	clientSecrets    ClientSecretSource
	userInfo         OIDCUserInfoSource
	operationTimeout time.Duration
}

func NewOIDCLogin(options OIDCLoginOptions) (*OIDCLogin, error) {
	if options.Flow == nil || options.Application == nil || options.Configurations == nil ||
		options.ClientSecrets == nil || options.UserInfo == nil || options.OperationTimeout < minimumOperationTimeout ||
		options.OperationTimeout > maximumOperationTimeout || options.OperationTimeout%time.Microsecond != 0 {
		return nil, ErrInvalidOptions
	}
	return &OIDCLogin{
		flow: options.Flow, application: options.Application, configurations: options.Configurations,
		clientSecrets: options.ClientSecrets, userInfo: options.UserInfo, operationTimeout: options.OperationTimeout,
	}, nil
}

func (login *OIDCLogin) String() string {
	return fmt.Sprintf("federatedauth.OIDCLogin{configured:%t}", login != nil && login.flow != nil)
}
func (login *OIDCLogin) GoString() string { return login.String() }

type StartTenantOIDCLoginRequest struct {
	Lookup                  OIDCStartLookup
	ReturnPath              string
	PreviousBrowserHandle   []byte `json:"-"`
	HasAuthenticatedSession bool
}

func (request StartTenantOIDCLoginRequest) String() string {
	return fmt.Sprintf(
		"federatedauth.StartTenantOIDCLoginRequest{lookup:%q,return_path:%t,previous_browser:%t,authenticated_session:%t}",
		request.Lookup.String(), request.ReturnPath != "", len(request.PreviousBrowserHandle) != 0,
		request.HasAuthenticatedSession,
	)
}
func (request StartTenantOIDCLoginRequest) GoString() string { return request.String() }

func (login *OIDCLogin) Start(
	ctx context.Context,
	request StartTenantOIDCLoginRequest,
) (federatedoidc.AuthorizationStart, error) {
	if login == nil || login.flow == nil || login.configurations == nil || request.HasAuthenticatedSession ||
		!validOIDCStartLookup(request.Lookup) {
		return federatedoidc.AuthorizationStart{}, ErrAuthentication
	}
	operation, cancel, err := login.operation(ctx)
	if err != nil {
		return federatedoidc.AuthorizationStart{}, ErrAuthentication
	}
	defer cancel()
	var configuration TenantOIDCConfiguration
	for range 2 {
		configuration, err = login.configurations.BeginTenantOIDCLogin(operation, request.Lookup)
		if err == nil || operation.Err() != nil {
			break
		}
	}
	configuration = cloneTenantOIDCConfiguration(configuration)
	if err != nil || !validTenantOIDCConfiguration(configuration) {
		return federatedoidc.AuthorizationStart{}, ErrAuthentication
	}
	previousBrowser := append([]byte(nil), request.PreviousBrowserHandle...)
	defer clear(previousBrowser)
	start, err := login.flow.StartAuthorization(operation, federatedoidc.StartAuthorizationRequest{
		Begin: federatedoidc.AuthorizationBegin{
			OperationRunID: request.Lookup.OperationRunID,
			ReceiptDigest:  request.Lookup.ReceiptDigest,
			NetworkDigest:  request.Lookup.NetworkDigest,
			AccountDigest:  request.Lookup.AccountDigest,
			ProviderDigest: request.Lookup.ProviderDigest,
		},
		Configuration: configuration.Authorization, ReturnPath: request.ReturnPath,
		PreviousBrowserHandle: previousBrowser,
	})
	if err != nil {
		return federatedoidc.AuthorizationStart{}, ErrAuthentication
	}
	return start, nil
}

type CompleteTenantOIDCLoginRequest struct {
	RawQuery      string `json:"-"`
	BrowserHandle []byte `json:"-"`
}

func (request CompleteTenantOIDCLoginRequest) String() string {
	return fmt.Sprintf(
		"federatedauth.CompleteTenantOIDCLoginRequest{query:%t,browser:%t}",
		request.RawQuery != "", len(request.BrowserHandle) != 0,
	)
}
func (request CompleteTenantOIDCLoginRequest) GoString() string { return request.String() }

func (login *OIDCLogin) Complete(
	ctx context.Context,
	request CompleteTenantOIDCLoginRequest,
) (ApplyResult, error) {
	if login == nil || login.flow == nil || login.application == nil || login.configurations == nil ||
		login.clientSecrets == nil || login.userInfo == nil {
		return ApplyResult{}, ErrAuthentication
	}
	operation, cancel, err := login.operation(ctx)
	if err != nil {
		return ApplyResult{}, ErrAuthentication
	}
	defer cancel()
	resolver := &tenantOIDCCallbackResolver{source: login.configurations}
	browserHandle := append([]byte(nil), request.BrowserHandle...)
	defer clear(browserHandle)
	claimed, err := login.flow.ClaimCallbackResolved(operation, federatedoidc.ResolvedCallbackRequest{
		RawQuery: request.RawQuery, BrowserHandle: browserHandle,
	}, resolver)
	if err != nil || claimed == nil || !resolver.resolved {
		return ApplyResult{}, ErrAuthentication
	}
	configuration := resolver.configuration
	secret, err := login.clientSecrets.OpenOIDCClientSecret(operation, ClientSecretContext{
		Provider: configuration.Authorization.Provider, Admission: configuration.Authorization.Admission,
		BindingID: configuration.Authorization.BindingID,
		Revision:  configuration.Authorization.ClientSecretRevision,
	})
	if err != nil || len(secret) == 0 {
		clear(secret)
		login.abort(ctx, claimed)
		return ApplyResult{}, ErrAuthentication
	}
	credential := federatedoidc.ClientCredential{
		Revision: configuration.Authorization.ClientSecretRevision,
		Secret:   append([]byte(nil), secret...),
	}
	clear(secret)
	bundle, err := login.flow.ExchangeCode(operation, claimed, credential)
	clear(credential.Secret)
	if err != nil || bundle == nil {
		login.abort(ctx, claimed)
		return ApplyResult{}, ErrAuthentication
	}
	defer bundle.Destroy()
	proof, err := login.flow.VerifyIDToken(operation, claimed, bundle, configuration.IDTokenClaims)
	if err != nil || proof == nil {
		login.abort(ctx, claimed)
		return ApplyResult{}, ErrAuthentication
	}
	if configuration.Authorization.UseUserInfo {
		userInfoRequest, requestErr := login.flow.BuildUserInfoRequest(configuration.Authorization, bundle)
		if requestErr != nil {
			login.abort(ctx, claimed)
			return ApplyResult{}, ErrAuthentication
		}
		defer userInfoRequest.Destroy()
		document, fetchErr := login.userInfo.FetchUserInfo(operation, userInfoRequest, proof.Subject())
		if fetchErr != nil {
			login.abort(ctx, claimed)
			return ApplyResult{}, ErrAuthentication
		}
		merged, mergeErr := login.flow.MergeUserInfo(*proof, document, configuration.UserInfoClaims)
		if mergeErr != nil {
			login.abort(ctx, claimed)
			return ApplyResult{}, ErrAuthentication
		}
		proof = &merged
	}
	sessionMaterial, err := login.flow.TakeSessionMaterial(configuration.Authorization, bundle)
	if err != nil {
		login.abort(ctx, claimed)
		return ApplyResult{}, ErrAuthentication
	}
	if sessionMaterial != nil {
		defer sessionMaterial.Destroy()
	}
	admission, _ := configuration.Authorization.TenantAdmission()
	result, err := login.application.ApplyOIDC(operation, OIDCApplicationRequest{
		TenantID: admission.TenantID, Configuration: configuration.Authorization,
		Proof: proof, Session: sessionMaterial,
	})
	if err != nil || !validCompletedOIDCApplyResult(result, proof.Completion()) {
		if result.Credential != nil {
			result.Credential.Destroy()
		}
		login.abort(ctx, claimed)
		return ApplyResult{}, ErrAuthentication
	}
	return result, nil
}

func validCompletedOIDCApplyResult(
	result ApplyResult,
	completion federatedoidc.TransactionCompletion,
) bool {
	return result.Category == ApplySuccess && result.UserID != (identity.EntityID{}) &&
		result.ReturnPath == completion.ReturnPath &&
		(result.SessionID != (identity.EntityID{})) != (result.ContinuationID != (identity.EntityID{})) &&
		result.Credential.validForResult(result.SessionID, result.ContinuationID)
}

func (login *OIDCLogin) operation(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if ctx == nil || ctx.Err() != nil || login == nil || login.operationTimeout <= 0 {
		return nil, nil, ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, login.operationTimeout)
	return bounded, cancel, nil
}

func (login *OIDCLogin) abort(ctx context.Context, claimed *federatedoidc.ClaimedAuthorization) {
	for range 2 {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), login.operationTimeout)
		err := login.flow.AbortClaimedAuthorization(cleanup, claimed)
		cancel()
		if err == nil {
			return
		}
	}
}

type tenantOIDCCallbackResolver struct {
	source        TenantOIDCConfigurationSource
	configuration TenantOIDCConfiguration
	resolved      bool
}

func (resolver *tenantOIDCCallbackResolver) ResolveOIDCCallbackConfiguration(
	ctx context.Context,
	lookup federatedoidc.CallbackConfigurationLookup,
) (federatedoidc.AuthorizationConfiguration, error) {
	if resolver == nil || resolver.source == nil || resolver.resolved {
		return federatedoidc.AuthorizationConfiguration{}, ErrAuthentication
	}
	var configuration TenantOIDCConfiguration
	var err error
	for range 2 {
		configuration, err = resolver.source.ResolveTenantOIDCCallback(ctx, lookup)
		if err == nil || ctx.Err() != nil {
			break
		}
	}
	configuration = cloneTenantOIDCConfiguration(configuration)
	if err != nil || !validTenantOIDCConfiguration(configuration) {
		return federatedoidc.AuthorizationConfiguration{}, ErrAuthentication
	}
	resolver.configuration = configuration
	resolver.resolved = true
	return configuration.Authorization, nil
}

func validTenantOIDCConfiguration(configuration TenantOIDCConfiguration) bool {
	authorization := configuration.Authorization
	admission, valid := authorization.TenantAdmission()
	if !valid || !validProviderForTenant(authorization.Provider, admission.TenantID) {
		return false
	}
	userinfoEmpty := emptyOIDCClaimPolicy(configuration.UserInfoClaims)
	return authorization.UseUserInfo != userinfoEmpty && configuration.UserInfoClaims.ACR == nil &&
		configuration.UserInfoClaims.AMR == nil
}

func emptyOIDCClaimPolicy(policy federatedoidc.ClaimExtractionPolicy) bool {
	return len(policy.Scalars) == 0 && len(policy.Profiles) == 0 && policy.Groups == nil &&
		policy.ACR == nil && policy.AMR == nil
}

func cloneTenantOIDCConfiguration(value TenantOIDCConfiguration) TenantOIDCConfiguration {
	value.Authorization.ExtraScopes = append([]string(nil), value.Authorization.ExtraScopes...)
	value.IDTokenClaims = cloneOIDCClaimPolicy(value.IDTokenClaims)
	value.UserInfoClaims = cloneOIDCClaimPolicy(value.UserInfoClaims)
	return value
}

func cloneOIDCClaimPolicy(value federatedoidc.ClaimExtractionPolicy) federatedoidc.ClaimExtractionPolicy {
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

func validOIDCStartLookup(lookup OIDCStartLookup) bool {
	receipt := [sha256.Size]byte(lookup.ReceiptDigest)
	network := [sha256.Size]byte(lookup.NetworkDigest)
	account := [sha256.Size]byte(lookup.AccountDigest)
	provider := [sha256.Size]byte(lookup.ProviderDigest)
	return lookup.OperationRunID != (identity.EntityID{}) && lookup.OperationRunID[6]>>4 == 7 &&
		lookup.OperationRunID[8]&0xc0 == 0x80 && receipt != ([sha256.Size]byte{}) &&
		tenantOIDCSlugPattern.MatchString(lookup.TenantSlug) &&
		tenantOIDCLoginKeyPattern.MatchString(lookup.LoginKey) &&
		network != ([sha256.Size]byte{}) && account != ([sha256.Size]byte{}) && provider != ([sha256.Size]byte{}) &&
		receipt != network && receipt != account && receipt != provider &&
		network != account && network != provider && account != provider
}
