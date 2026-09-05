package federatedoidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/url"
	"path"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedhttp"
)

const (
	tenantOIDCCallbackPath    = "/api/v1/auth/federated/oidc/callback"
	directOIDCCallbackPath    = "/api/v1/auth/platform/oidc/callback"
	maximumPersistentRevision = uint64(9_007_199_254_740_991)
)

func NewFlow(options FlowOptions) (*Flow, error) {
	return newFlow(options, rand.Reader, func() time.Time {
		return time.Now().UTC().Truncate(time.Millisecond)
	})
}

func newFlow(options FlowOptions, random io.Reader, now func() time.Time) (*Flow, error) {
	callbackPath, callbackOK := callbackPath(options.CallbackEndpoint)
	if options.Trust == nil || options.Trust.http == nil || options.Transactions == nil ||
		options.VerifierProtector == nil || options.TokenEndpoint == nil || random == nil || now == nil ||
		!callbackOK || !validFlowPolicy(options.Policy) || !validDeploymentRedirects(
		options.Trust, options.RedirectURI, options.PostLogoutRedirectURI, callbackPath,
	) {
		return nil, ErrInvalidFlowOptions
	}
	return &Flow{
		trust: options.Trust, transactions: options.Transactions,
		verifierProtector: options.VerifierProtector, tokenEndpoint: options.TokenEndpoint,
		redirectURI: options.RedirectURI, postLogoutRedirectURI: options.PostLogoutRedirectURI,
		callbackEndpoint: options.CallbackEndpoint, callbackPath: callbackPath,
		policy: options.Policy, random: random, now: now,
	}, nil
}

func callbackPath(endpoint CallbackEndpoint) (string, bool) {
	switch endpoint {
	case TenantOIDCCallbackEndpoint:
		return tenantOIDCCallbackPath, true
	case DirectPlatformOIDCCallbackEndpoint:
		return directOIDCCallbackPath, true
	default:
		return "", false
	}
}

func validDeploymentRedirects(client *Client, redirectURI, postLogoutRedirectURI, wantedPath string) bool {
	if client == nil || client.http == nil || redirectURI == "" || wantedPath == "" {
		return false
	}
	if _, err := client.http.CompileTarget(federatedhttp.DocumentOIDCDiscovery, redirectURI); err != nil {
		return false
	}
	parsedRedirect, err := url.Parse(redirectURI)
	if err != nil || parsedRedirect.Path != wantedPath || parsedRedirect.RawPath != "" ||
		parsedRedirect.RawQuery != "" || parsedRedirect.ForceQuery || parsedRedirect.Fragment != "" {
		return false
	}
	if postLogoutRedirectURI == "" {
		return true
	}
	if _, err = client.http.CompileTarget(
		federatedhttp.DocumentOIDCDiscovery,
		postLogoutRedirectURI,
	); err != nil {
		return false
	}
	parsedLogout, err := url.Parse(postLogoutRedirectURI)
	return err == nil && parsedLogout.Scheme == parsedRedirect.Scheme && parsedLogout.Host == parsedRedirect.Host &&
		parsedLogout.RawPath == "" && parsedLogout.RawQuery == "" && !parsedLogout.ForceQuery && parsedLogout.Fragment == ""
}

func validFlowPolicy(policy FlowPolicy) bool {
	return policy.TransactionTTL >= minimumTransactionTTL && policy.TransactionTTL <= maximumTransactionTTL &&
		policy.TransactionTTL%time.Millisecond == 0 &&
		policy.OperationTimeout >= minimumFlowTimeout && policy.OperationTimeout <= maximumFlowTimeout &&
		policy.ClockSkew >= 0 && policy.ClockSkew <= maximumClockSkew &&
		policy.MaxTokenAge >= minimumTokenDuration && policy.MaxTokenAge <= maximumTokenDuration &&
		policy.MaxTokenLifetime >= minimumTokenDuration && policy.MaxTokenLifetime <= maximumTokenDuration &&
		policy.MaxAuthenticationAge >= minimumTokenDuration &&
		policy.MaxAuthenticationAge <= maximumAuthenticationAge &&
		policy.MaxTokenAge%time.Second == 0 && policy.MaxTokenLifetime%time.Second == 0 &&
		policy.MaxAuthenticationAge%time.Second == 0 && validFlowLimits(policy.Limits)
}

func trustSnapshotsFreshAtStart(configuration AuthorizationConfiguration, now time.Time) bool {
	return !now.After(configuration.Discovery.Cache().FreshUntil) &&
		!now.After(configuration.JWKS.Cache().FreshUntil)
}

func validFlowLimits(limits FlowLimits) bool {
	return limits.MaxCallbackQueryBytes >= minimumCallbackQueryBytes &&
		limits.MaxCallbackQueryBytes <= maximumCallbackQueryBytes &&
		limits.MaxTokenResponseBytes >= minimumTokenResponseBytes &&
		limits.MaxTokenResponseBytes <= maximumTokenResponseBytes &&
		limits.MaxCompactTokenBytes >= minimumCompactTokenBytes &&
		limits.MaxCompactTokenBytes <= maximumCompactTokenBytes &&
		limits.MaxTokenValueBytes >= minimumTokenValueBytes &&
		limits.MaxTokenValueBytes <= maximumTokenValueBytes &&
		limits.MaxClaimValueBytes >= minimumClaimValueBytes &&
		limits.MaxClaimValueBytes <= maximumClaimValueBytes &&
		limits.MaxScalarClaims >= minimumClaimCount && limits.MaxScalarClaims <= maximumClaimCount &&
		limits.MaxProfileClaims >= minimumClaimCount && limits.MaxProfileClaims <= maximumClaimCount &&
		limits.MaxGroups >= minimumGroupCount && limits.MaxGroups <= maximumGroupCount &&
		limits.MaxAMRValues >= minimumAMRCount && limits.MaxAMRValues <= maximumAMRCount
}

func (flow *Flow) operationContext(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if flow == nil || ctx == nil || ctx.Err() != nil || flow.policy.OperationTimeout <= 0 {
		return nil, nil, ErrInvalidFlowOptions
	}
	bounded, cancel := context.WithTimeout(ctx, flow.policy.OperationTimeout)
	return bounded, cancel, nil
}

func (flow *Flow) currentTime() (time.Time, bool) {
	if flow == nil || flow.now == nil {
		return time.Time{}, false
	}
	now := flow.now()
	return now, validFlowInstant(now)
}

func validFlowInstant(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond()%int(time.Millisecond) == 0
}

func (flow *Flow) normalizeConfiguration(
	configuration AuthorizationConfiguration,
) (AuthorizationConfiguration, []string, error) {
	if flow == nil || flow.trust == nil || !validCallbackAuthority(flow.callbackEndpoint, configuration.Authority) ||
		!validCeremonyAuthority(
			configuration.Authority, configuration.Provider, configuration.BindingID, configuration.Admission,
			configuration.BindingRevision, configuration.MappingRevision, configuration.AuthorizationRevision,
			configuration.PlatformLoginRevision,
		) || !validAuthorityExtensions(configuration) ||
		!validPersistentRevision(configuration.ProviderRevision) ||
		!validPersistentRevision(configuration.ConfigurationRevision) ||
		!validPersistentRevision(configuration.SecurityRevision) ||
		!validPersistentRevision(configuration.AssurancePolicyRevision) ||
		!validPersistentRevision(configuration.ClientSecretRevision) ||
		!validPersistentRevision(configuration.Discovery.Revision()) ||
		!validPersistentRevision(configuration.JWKS.Revision()) ||
		!validClientID(configuration.ClientID) || !configuration.Discovery.validSnapshot() ||
		!configuration.JWKS.validSnapshot() || configuration.RedirectURI != flow.redirectURI ||
		configuration.PostLogoutRedirectURI != flow.postLogoutRedirectURI ||
		configuration.UseUserInfo && configuration.Discovery.endpoints.UserInfo == "" ||
		configuration.JWKS.DiscoveryRevision() != configuration.Discovery.Revision() ||
		configuration.JWKS.DiscoveryDigest() != configuration.Discovery.Digest() {
		return AuthorizationConfiguration{}, nil, ErrAuthorizationRejected
	}
	if _, err := flow.trust.http.CompileTarget(
		federatedhttp.DocumentOIDCDiscovery,
		configuration.RedirectURI,
	); err != nil {
		return AuthorizationConfiguration{}, nil, ErrAuthorizationRejected
	}
	parsedRedirect, err := url.Parse(configuration.RedirectURI)
	if err != nil || parsedRedirect.Path != flow.callbackPath {
		return AuthorizationConfiguration{}, nil, ErrAuthorizationRejected
	}
	if configuration.PostLogoutRedirectURI != "" {
		if _, compileErr := flow.trust.http.CompileTarget(
			federatedhttp.DocumentOIDCDiscovery,
			configuration.PostLogoutRedirectURI,
		); compileErr != nil {
			return AuthorizationConfiguration{}, nil, ErrAuthorizationRejected
		}
		parsedLogout, parseErr := url.Parse(configuration.PostLogoutRedirectURI)
		if parseErr != nil || parsedLogout.Scheme != parsedRedirect.Scheme ||
			parsedLogout.Host != parsedRedirect.Host {
			return AuthorizationConfiguration{}, nil, ErrAuthorizationRejected
		}
	}
	scopes, err := normalizeScopes(configuration.ExtraScopes, configuration.AllowRefreshToken)
	if err != nil {
		return AuthorizationConfiguration{}, nil, ErrAuthorizationRejected
	}
	configuration.ExtraScopes = append([]string(nil), scopes[1:]...)
	return configuration, scopes, nil
}

func validCallbackAuthority(endpoint CallbackEndpoint, authority CeremonyAuthority) bool {
	return endpoint == TenantOIDCCallbackEndpoint && authority == TenantCeremonyAuthority ||
		endpoint == DirectPlatformOIDCCallbackEndpoint && authority == DirectPlatformCeremonyAuthority
}

func validAuthorityExtensions(configuration AuthorizationConfiguration) bool {
	zeroID := identity.EntityID{}
	switch configuration.Authority {
	case TenantCeremonyAuthority:
		return configuration.PlanRevision == 0 && configuration.PlatformFloorPolicyID == zeroID &&
			configuration.PlatformFloorRevision == 0
	case DirectPlatformCeremonyAuthority:
		return validPersistentRevision(configuration.PlanRevision) &&
			configuration.PlatformFloorPolicyID != zeroID &&
			validPersistentRevision(configuration.PlatformFloorRevision)
	default:
		return false
	}
}

func validProviderBinding(provider identity.ProviderContext, bindingID identity.EntityID) bool {
	zeroID := identity.EntityID{}
	if provider.ProviderID == zeroID {
		return false
	}
	switch provider.Scope {
	case identity.TenantProviderScope:
		return provider.TenantID != zeroID && bindingID != zeroID
	case identity.PlatformProviderScope:
		return provider.TenantID == zeroID && bindingID == zeroID
	default:
		return false
	}
}

func validCeremonyAuthority(
	authority CeremonyAuthority,
	provider identity.ProviderContext,
	bindingID identity.EntityID,
	admission identity.TenantAdmissionContext,
	bindingRevision uint64,
	mappingRevision uint64,
	authorizationRevision uint64,
	platformLoginRevision uint64,
) bool {
	switch authority {
	case TenantCeremonyAuthority:
		_, valid := authorityTenantAdmission(
			authority, provider, bindingID, admission, platformLoginRevision,
		)
		return valid && validPersistentRevision(bindingRevision) &&
			validPersistentRevision(mappingRevision) && validPersistentRevision(authorizationRevision)
	case DirectPlatformCeremonyAuthority:
		_, valid := directPlatformLoginAuthority(
			authority, provider, bindingID, admission, platformLoginRevision,
		)
		return valid && bindingRevision == 0 && mappingRevision == 0 && authorizationRevision == 0
	default:
		return false
	}
}

func authorityTenantAdmission(
	authority CeremonyAuthority,
	provider identity.ProviderContext,
	bindingID identity.EntityID,
	admission identity.TenantAdmissionContext,
	platformLoginRevision uint64,
) (identity.TenantAdmissionContext, bool) {
	if authority != TenantCeremonyAuthority || platformLoginRevision != 0 {
		return identity.TenantAdmissionContext{}, false
	}
	return tenantAdmission(provider, bindingID, admission)
}

func directPlatformLoginAuthority(
	authority CeremonyAuthority,
	provider identity.ProviderContext,
	bindingID identity.EntityID,
	admission identity.TenantAdmissionContext,
	platformLoginRevision uint64,
) (uint64, bool) {
	if authority != DirectPlatformCeremonyAuthority || provider.Scope != identity.PlatformProviderScope ||
		!validProviderBinding(provider, bindingID) || admission != (identity.TenantAdmissionContext{}) ||
		!validPersistentRevision(platformLoginRevision) {
		return 0, false
	}
	return platformLoginRevision, true
}

func tenantAdmission(
	provider identity.ProviderContext,
	bindingID identity.EntityID,
	admission identity.TenantAdmissionContext,
) (identity.TenantAdmissionContext, bool) {
	zeroID := identity.EntityID{}
	zeroAdmission := identity.TenantAdmissionContext{}
	if provider.ProviderID == zeroID {
		return identity.TenantAdmissionContext{}, false
	}
	switch provider.Scope {
	case identity.TenantProviderScope:
		if provider.TenantID == zeroID || bindingID == zeroID {
			return identity.TenantAdmissionContext{}, false
		}
		derived := identity.TenantAdmissionContext{TenantID: provider.TenantID, BindingID: bindingID}
		if admission != zeroAdmission && admission != derived {
			return identity.TenantAdmissionContext{}, false
		}
		return derived, true
	case identity.PlatformProviderScope:
		if provider.TenantID != zeroID || bindingID != zeroID ||
			admission.TenantID == zeroID || admission.BindingID == zeroID {
			return identity.TenantAdmissionContext{}, false
		}
		return admission, true
	default:
		return identity.TenantAdmissionContext{}, false
	}
}

func validPersistentRevision(value uint64) bool {
	return value > 0 && value <= maximumPersistentRevision
}

func validAuthorizationBegin(value AuthorizationBegin) bool {
	operationID := value.OperationRunID
	receipt := [sha256.Size]byte(value.ReceiptDigest)
	network := [sha256.Size]byte(value.NetworkDigest)
	account := [sha256.Size]byte(value.AccountDigest)
	provider := [sha256.Size]byte(value.ProviderDigest)
	return operationID != (identity.EntityID{}) && operationID[6]>>4 == 7 && operationID[8]&0xc0 == 0x80 &&
		receipt != ([sha256.Size]byte{}) && network != ([sha256.Size]byte{}) &&
		account != ([sha256.Size]byte{}) && provider != ([sha256.Size]byte{}) &&
		receipt != network && receipt != account && receipt != provider &&
		network != account && network != provider && account != provider
}

func validClientID(value string) bool {
	if value == "" || len(value) > maximumClientIDBytes || !utf8.ValidString(value) ||
		strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.IsSpace(character) {
			return false
		}
	}
	return true
}

func normalizeScopes(extra []string, allowRefresh bool) ([]string, error) {
	if len(extra) >= maximumScopeCount {
		return nil, ErrAuthorizationRejected
	}
	result := []string{RequiredScopeOpenID}
	seen := map[string]struct{}{RequiredScopeOpenID: {}}
	for _, scope := range extra {
		if !validScope(scope) || scope == "offline_access" && !allowRefresh {
			return nil, ErrAuthorizationRejected
		}
		if _, duplicate := seen[scope]; duplicate {
			return nil, ErrAuthorizationRejected
		}
		seen[scope] = struct{}{}
		result = append(result, scope)
	}
	_, offlineAccess := seen["offline_access"]
	if offlineAccess != allowRefresh {
		return nil, ErrAuthorizationRejected
	}
	slices.Sort(result[1:])
	return result, nil
}

func validScope(value string) bool {
	if value == "" || len(value) > maximumScopeBytes {
		return false
	}
	for index := range value {
		character := value[index]
		if character == 0x21 || character >= 0x23 && character <= 0x5b || character >= 0x5d && character <= 0x7e {
			continue
		}
		return false
	}
	return true
}

func validReturnPath(value string) bool {
	if value == "" || len(value) > maximumReturnPathBytes || !utf8.ValidString(value) ||
		!strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") || strings.ContainsRune(value, '\\') {
		return false
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.Fragment != "" || parsed.RawPath != "" ||
		parsed.Path == "" || strings.Contains(parsed.Path, "//") || path.Clean(parsed.Path) != parsed.Path ||
		parsed.String() != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func generateOpaque(random io.Reader) ([]byte, error) {
	if random == nil {
		return nil, ErrAuthorizationRejected
	}
	raw := make([]byte, opaqueArtifactBytes)
	if _, err := io.ReadFull(random, raw); err != nil {
		clear(raw)
		return nil, ErrAuthorizationRejected
	}
	encoded := make([]byte, base64.RawURLEncoding.EncodedLen(len(raw)))
	base64.RawURLEncoding.Encode(encoded, raw)
	clear(raw)
	return encoded, nil
}

func generateTransactionID(random io.Reader) (TransactionID, error) {
	var id TransactionID
	if random == nil {
		return id, ErrAuthorizationRejected
	}
	if _, err := io.ReadFull(random, id[:]); err != nil || id == (TransactionID{}) {
		clear(id[:])
		return TransactionID{}, ErrAuthorizationRejected
	}
	return id, nil
}

func validOpaque(value []byte) bool {
	if len(value) != base64.RawURLEncoding.EncodedLen(opaqueArtifactBytes) {
		return false
	}
	decoded := make([]byte, opaqueArtifactBytes)
	count, err := base64.RawURLEncoding.Strict().Decode(decoded, value)
	valid := err == nil && count == opaqueArtifactBytes &&
		string(value) == base64.RawURLEncoding.EncodeToString(decoded)
	clear(decoded)
	return valid
}

func validPKCEVerifier(value []byte) bool {
	if len(value) < 43 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || strings.ContainsRune("-._~", rune(character)) {
			continue
		}
		return false
	}
	return true
}

func transactionPins(configuration AuthorizationConfiguration) TransactionPins {
	return TransactionPins{
		Authority: configuration.Authority, Provider: configuration.Provider,
		Admission: configuration.Admission, BindingID: configuration.BindingID,
		ProviderRevision:        configuration.ProviderRevision,
		BindingRevision:         configuration.BindingRevision,
		PlatformLoginRevision:   configuration.PlatformLoginRevision,
		ConfigurationRevision:   configuration.ConfigurationRevision,
		SecurityRevision:        configuration.SecurityRevision,
		PlanRevision:            configuration.PlanRevision,
		MappingRevision:         configuration.MappingRevision,
		AuthorizationRevision:   configuration.AuthorizationRevision,
		AssurancePolicyRevision: configuration.AssurancePolicyRevision,
		PlatformFloorPolicyID:   configuration.PlatformFloorPolicyID,
		PlatformFloorRevision:   configuration.PlatformFloorRevision,
		ClientSecretRevision:    configuration.ClientSecretRevision,
		DiscoveryRevision:       configuration.Discovery.Revision(),
		DiscoveryDigest:         configuration.Discovery.Digest(),
		JWKSRevision:            configuration.JWKS.Revision(),
		JWKSDigest:              configuration.JWKS.Digest(),
	}
}

func newPinnedEndpoint(kind EndpointKind, rawURL string, target federatedhttp.Target) PinnedEndpoint {
	return PinnedEndpoint{
		kind: kind, url: rawURL, target: target,
		valid: rawURL != "" && target != (federatedhttp.Target{}),
	}
}

func (endpoint PinnedEndpoint) validEndpoint(expected EndpointKind) bool {
	return endpoint.valid && endpoint.kind == expected && endpoint.url != "" &&
		endpoint.target != (federatedhttp.Target{})
}

func cloneProtectedVerifier(value ProtectedVerifier) ProtectedVerifier {
	return ProtectedVerifier{KeyVersion: value.KeyVersion, Ciphertext: append([]byte(nil), value.Ciphertext...)}
}

func validProtectedVerifier(value ProtectedVerifier) bool {
	return value.KeyVersion != 0 && len(value.Ciphertext) >= 16 &&
		len(value.Ciphertext) <= maximumProtectedVerifierBytes
}

func digestValue(value []byte) [sha256.Size]byte {
	return sha256.Sum256(value)
}
