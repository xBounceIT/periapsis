package federatedauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
)

type SAMLStartReceiptDigest = federatedsaml.StartReceiptDigest
type SAMLNetworkRateDigest = federatedsaml.NetworkThrottleDigest
type SAMLAccountRateDigest = federatedsaml.AccountThrottleDigest
type SAMLProviderRateDigest = federatedsaml.ProviderThrottleDigest

type SAMLStartLookup struct {
	OperationRunID identity.EntityID
	ReceiptDigest  SAMLStartReceiptDigest
	TenantSlug     string
	LoginKey       string
	NetworkDigest  SAMLNetworkRateDigest
	AccountDigest  SAMLAccountRateDigest
	ProviderDigest SAMLProviderRateDigest
}

func (lookup SAMLStartLookup) String() string {
	return "federatedauth.SAMLStartLookup{locator:[REDACTED],digests:true}"
}
func (lookup SAMLStartLookup) GoString() string { return lookup.String() }

// TenantSAMLConfiguration is the exact immutable provider projection selected
// by a metered start receipt or by transaction pins at the public ACS.
type TenantSAMLConfiguration struct {
	Authentication federatedsaml.Configuration
}

func (configuration TenantSAMLConfiguration) String() string {
	return fmt.Sprintf("federatedauth.TenantSAMLConfiguration{authentication:%q}", configuration.Authentication.String())
}
func (configuration TenantSAMLConfiguration) GoString() string { return configuration.String() }

// TenantSAMLConfigurationSource is the future narrow PostgreSQL ABI. Begin
// meters one public locator and returns an idempotent receipt-bound snapshot.
// Resolve derives tenant/RLS context only from the transaction lookup.
type TenantSAMLConfigurationSource interface {
	BeginTenantSAMLLogin(context.Context, SAMLStartLookup) (TenantSAMLConfiguration, error)
	ResolveTenantSAMLCallback(context.Context, federatedsaml.CallbackConfigurationLookup) (TenantSAMLConfiguration, error)
}

type SAMLConsumptionFlow interface {
	Consume(context.Context, *federatedsaml.ValidatedAuthentication, federatedsaml.AuthenticationConsumer) (federatedsaml.ConsumptionResult, error)
}

type SAMLProtocolFlow interface {
	SAMLConsumptionFlow
	StartAuthentication(context.Context, federatedsaml.StartRequest) (federatedsaml.AuthorizationStart, error)
	ValidateCallbackResolved(context.Context, federatedsaml.ResolvedCallbackRequest, federatedsaml.CallbackConfigurationResolver) (*federatedsaml.ValidatedAuthentication, error)
}

type SAMLAuthenticationApplication interface {
	ApplySAML(context.Context, SAMLConsumptionFlow, TenantSAMLConfiguration, *federatedsaml.ValidatedAuthentication) (ApplyResult, error)
}

type SAMLLoginOptions struct {
	Flow             SAMLProtocolFlow
	Application      SAMLAuthenticationApplication
	Configurations   TenantSAMLConfigurationSource
	OperationTimeout time.Duration
}

type SAMLLogin struct {
	flow             SAMLProtocolFlow
	application      SAMLAuthenticationApplication
	configurations   TenantSAMLConfigurationSource
	operationTimeout time.Duration
}

func NewSAMLLogin(options SAMLLoginOptions) (*SAMLLogin, error) {
	if options.Flow == nil || options.Application == nil || options.Configurations == nil ||
		options.OperationTimeout < minimumOperationTimeout || options.OperationTimeout > maximumOperationTimeout ||
		options.OperationTimeout%time.Microsecond != 0 {
		return nil, ErrInvalidOptions
	}
	return &SAMLLogin{
		flow: options.Flow, application: options.Application, configurations: options.Configurations,
		operationTimeout: options.OperationTimeout,
	}, nil
}

func (login *SAMLLogin) String() string {
	return fmt.Sprintf("federatedauth.SAMLLogin{configured:%t}", login != nil && login.flow != nil)
}
func (login *SAMLLogin) GoString() string { return login.String() }

type StartTenantSAMLLoginRequest struct {
	Lookup                  SAMLStartLookup
	ReturnPath              string
	PreviousBrowserHandle   []byte `json:"-"`
	HasAuthenticatedSession bool
}

func (request StartTenantSAMLLoginRequest) String() string {
	return fmt.Sprintf(
		"federatedauth.StartTenantSAMLLoginRequest{lookup:%q,return_path:%t,previous_browser:%t,authenticated_session:%t}",
		request.Lookup.String(), request.ReturnPath != "", len(request.PreviousBrowserHandle) != 0,
		request.HasAuthenticatedSession,
	)
}
func (request StartTenantSAMLLoginRequest) GoString() string { return request.String() }

func (login *SAMLLogin) Start(
	ctx context.Context,
	request StartTenantSAMLLoginRequest,
) (federatedsaml.AuthorizationStart, error) {
	if login == nil || login.flow == nil || login.configurations == nil || request.HasAuthenticatedSession ||
		!validSAMLStartLookup(request.Lookup) || !validReturnPath(request.ReturnPath) ||
		len(request.PreviousBrowserHandle) != 0 && !validSAMLBrowserHandle(request.PreviousBrowserHandle) {
		return federatedsaml.AuthorizationStart{}, ErrAuthentication
	}
	operation, cancel, err := login.operation(ctx)
	if err != nil {
		return federatedsaml.AuthorizationStart{}, ErrAuthentication
	}
	defer cancel()
	var configuration TenantSAMLConfiguration
	for range 2 {
		configuration, err = login.configurations.BeginTenantSAMLLogin(operation, request.Lookup)
		if err == nil || operation.Err() != nil {
			break
		}
	}
	configuration = cloneTenantSAMLConfiguration(configuration)
	if err != nil || !validTenantSAMLConfiguration(configuration) {
		return federatedsaml.AuthorizationStart{}, ErrAuthentication
	}
	previousBrowser := append([]byte(nil), request.PreviousBrowserHandle...)
	defer clear(previousBrowser)
	start, err := login.flow.StartAuthentication(operation, federatedsaml.StartRequest{
		Begin: federatedsaml.AuthenticationBegin{
			OperationRunID: request.Lookup.OperationRunID,
			ReceiptDigest:  request.Lookup.ReceiptDigest,
			NetworkDigest:  request.Lookup.NetworkDigest,
			AccountDigest:  request.Lookup.AccountDigest,
			ProviderDigest: request.Lookup.ProviderDigest,
		},
		Configuration:         configuration.Authentication,
		ReturnPath:            request.ReturnPath,
		PreviousBrowserHandle: previousBrowser,
		HasLiveSession:        request.HasAuthenticatedSession,
	})
	if err != nil {
		return federatedsaml.AuthorizationStart{}, ErrAuthentication
	}
	return start, nil
}

type CompleteTenantSAMLLoginRequest struct {
	MediaType     string
	RawForm       []byte `json:"-"`
	BrowserHandle []byte `json:"-"`
}

func (request CompleteTenantSAMLLoginRequest) String() string {
	return fmt.Sprintf(
		"federatedauth.CompleteTenantSAMLLoginRequest{media_type:%t,form_bytes:%d,browser:%t}",
		request.MediaType != "", len(request.RawForm), len(request.BrowserHandle) != 0,
	)
}
func (request CompleteTenantSAMLLoginRequest) GoString() string { return request.String() }

func (login *SAMLLogin) Complete(
	ctx context.Context,
	request CompleteTenantSAMLLoginRequest,
) (ApplyResult, error) {
	if login == nil || login.flow == nil || login.application == nil || login.configurations == nil {
		return ApplyResult{}, ErrAuthentication
	}
	limits := federatedsaml.DefaultLimits()
	if len(request.MediaType) == 0 || len(request.MediaType) > 256 || len(request.RawForm) == 0 ||
		len(request.RawForm) > limits.MaxEncodedResponseBytes+4*1024 ||
		!validSAMLBrowserHandle(request.BrowserHandle) {
		return ApplyResult{}, ErrAuthentication
	}
	operation, cancel, err := login.operation(ctx)
	if err != nil {
		return ApplyResult{}, ErrAuthentication
	}
	defer cancel()
	resolver := &tenantSAMLCallbackResolver{source: login.configurations}
	rawForm := append([]byte(nil), request.RawForm...)
	browserHandle := append([]byte(nil), request.BrowserHandle...)
	defer clear(rawForm)
	defer clear(browserHandle)
	validated, err := login.flow.ValidateCallbackResolved(operation, federatedsaml.ResolvedCallbackRequest{
		MediaType: request.MediaType, RawForm: rawForm, BrowserHandle: browserHandle,
	}, resolver)
	if err != nil || validated == nil || !resolver.resolved {
		return ApplyResult{}, ErrAuthentication
	}
	result, err := login.application.ApplySAML(operation, login.flow, resolver.configuration, validated)
	if err != nil || !validCompletedSAMLApplyResult(result) {
		if result.Credential != nil {
			result.Credential.Destroy()
		}
		return ApplyResult{}, ErrAuthentication
	}
	return result, nil
}

func validCompletedSAMLApplyResult(result ApplyResult) bool {
	return result.Category == ApplySuccess && result.UserID != (identity.EntityID{}) && validReturnPath(result.ReturnPath) &&
		(result.SessionID != (identity.EntityID{})) != (result.ContinuationID != (identity.EntityID{})) &&
		result.Credential.validForResult(result.SessionID, result.ContinuationID)
}

func (login *SAMLLogin) operation(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if ctx == nil || ctx.Err() != nil || login == nil || login.operationTimeout <= 0 {
		return nil, nil, ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, login.operationTimeout)
	return bounded, cancel, nil
}

type tenantSAMLCallbackResolver struct {
	source        TenantSAMLConfigurationSource
	configuration TenantSAMLConfiguration
	resolved      bool
}

func (resolver *tenantSAMLCallbackResolver) ResolveSAMLCallbackConfiguration(
	ctx context.Context,
	lookup federatedsaml.CallbackConfigurationLookup,
) (federatedsaml.Configuration, error) {
	if resolver == nil || resolver.source == nil || resolver.resolved {
		return federatedsaml.Configuration{}, ErrAuthentication
	}
	var configuration TenantSAMLConfiguration
	var err error
	for range 2 {
		configuration, err = resolver.source.ResolveTenantSAMLCallback(ctx, lookup)
		if err == nil || ctx.Err() != nil {
			break
		}
	}
	configuration = cloneTenantSAMLConfiguration(configuration)
	if err != nil || !validTenantSAMLConfiguration(configuration) {
		return federatedsaml.Configuration{}, ErrAuthentication
	}
	resolver.configuration = configuration
	resolver.resolved = true
	return configuration.Authentication, nil
}

func validTenantSAMLConfiguration(configuration TenantSAMLConfiguration) bool {
	value := configuration.Authentication
	return value.Provider.Scope == identity.TenantProviderScope && value.Provider.TenantID != (identity.EntityID{}) &&
		value.Provider.ProviderID != (identity.EntityID{}) && value.BindingID != (identity.EntityID{}) &&
		validSAMLRevision(value.ProviderRevision) && validSAMLRevision(value.BindingRevision) &&
		validSAMLRevision(value.ConfigurationRevision) && validSAMLRevision(value.SecurityRevision) &&
		validSAMLRevision(value.MappingRevision) && validSAMLRevision(value.AuthorizationRevision) &&
		validSAMLRevision(value.AssurancePolicyRevision) && validSAMLRevision(value.SPKeyRevision) &&
		validSAMLRevision(value.Metadata.Revision())
}

func validSAMLRevision(value uint64) bool { return value > 0 && value <= maximumJSONSafeRevision }

func validSAMLSuccessorRevision(value uint64) bool {
	return value > 0 && value < maximumJSONSafeRevision
}

func cloneTenantSAMLConfiguration(value TenantSAMLConfiguration) TenantSAMLConfiguration {
	value.Authentication.DecryptionKeyVersions = append([]uint32(nil), value.Authentication.DecryptionKeyVersions...)
	value.Authentication.RequestedAuthnContexts = append([]string(nil), value.Authentication.RequestedAuthnContexts...)
	value.Authentication.Mapping.Scalars = append([]federatedsaml.ScalarAttributeRule(nil), value.Authentication.Mapping.Scalars...)
	value.Authentication.Mapping.Profiles = append([]federatedsaml.ProfileAttributeRule(nil), value.Authentication.Mapping.Profiles...)
	if value.Authentication.Mapping.Groups != nil {
		copyValue := *value.Authentication.Mapping.Groups
		value.Authentication.Mapping.Groups = &copyValue
	}
	value.Authentication.TrustRules = append([]federatedsaml.AuthnContextTrustRule(nil), value.Authentication.TrustRules...)
	return value
}

func validSAMLStartLookup(lookup SAMLStartLookup) bool {
	receipt := [sha256.Size]byte(lookup.ReceiptDigest)
	network := [sha256.Size]byte(lookup.NetworkDigest)
	account := [sha256.Size]byte(lookup.AccountDigest)
	provider := [sha256.Size]byte(lookup.ProviderDigest)
	return lookup.OperationRunID != (identity.EntityID{}) && lookup.OperationRunID[6]>>4 == 7 &&
		lookup.OperationRunID[8]&0xc0 == 0x80 && receipt != ([sha256.Size]byte{}) &&
		tenantOIDCSlugPattern.MatchString(lookup.TenantSlug) && tenantOIDCLoginKeyPattern.MatchString(lookup.LoginKey) &&
		network != ([sha256.Size]byte{}) && account != ([sha256.Size]byte{}) && provider != ([sha256.Size]byte{}) &&
		receipt != network && receipt != account && receipt != provider &&
		network != account && network != provider && account != provider
}

func validSAMLBrowserHandle(value []byte) bool {
	if len(value) != base64.RawURLEncoding.EncodedLen(32) {
		return false
	}
	decoded := make([]byte, 32)
	defer clear(decoded)
	written, err := base64.RawURLEncoding.Strict().Decode(decoded, value)
	canonical := make([]byte, base64.RawURLEncoding.EncodedLen(len(decoded)))
	defer clear(canonical)
	base64.RawURLEncoding.Encode(canonical, decoded)
	if err != nil || written != len(decoded) || !bytes.Equal(canonical, value) {
		return false
	}
	for _, item := range decoded {
		if item != 0 {
			return true
		}
	}
	return false
}
