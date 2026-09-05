package postgres

import (
	"context"
	"crypto/sha256"
	"net/url"
	"path"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
	"github.com/periapsis-im/periapsis/services/api/internal/platformoidcauth"
)

const (
	beginPlatformOIDCDirectConfigurationSQL   = `select app.begin_platform_oidc_authentication_v1($1::jsonb)`
	resolvePlatformOIDCDirectConfigurationSQL = `select app.resolve_platform_oidc_authentication_configuration_v1($1::jsonb)`
)

var platformOIDCDirectLoginKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{2,63}$`)

type platformOIDCDirectBeginConfigurationWire struct {
	LoginKey string `json:"loginKey"`
}

type platformOIDCDirectPinsWire struct {
	Provider                    federatedProviderBindingWire `json:"provider"`
	ProviderRevision            uint64                       `json:"providerRevision"`
	LoginPolicyRevision         uint64                       `json:"loginPolicyRevision"`
	ConfigurationRevision       uint64                       `json:"configurationRevision"`
	SecurityRevision            uint64                       `json:"securityRevision"`
	PlanRevision                uint64                       `json:"planRevision"`
	AssurancePolicyRevision     uint64                       `json:"assurancePolicyRevision"`
	PlatformFloorPolicyID       string                       `json:"platformFloorPolicyId"`
	PlatformFloorPolicyRevision uint64                       `json:"platformFloorPolicyRevision"`
	ClientSecretRevision        uint64                       `json:"clientSecretRevision"`
	DiscoveryRevision           uint64                       `json:"discoveryRevision"`
	DiscoveryDigest             []byte                       `json:"discoveryDigest"`
	JWKSRevision                uint64                       `json:"jwksRevision"`
	JWKSDigest                  []byte                       `json:"jwksDigest"`
}

type platformOIDCDirectAuthorizationWire struct {
	Provider                    federatedProviderBindingWire `json:"provider"`
	ProviderRevision            uint64                       `json:"providerRevision"`
	LoginPolicyRevision         uint64                       `json:"loginPolicyRevision"`
	ConfigurationRevision       uint64                       `json:"configurationRevision"`
	SecurityRevision            uint64                       `json:"securityRevision"`
	AssurancePolicyRevision     uint64                       `json:"assurancePolicyRevision"`
	PlatformFloorPolicyID       string                       `json:"platformFloorPolicyId"`
	PlatformFloorPolicyRevision uint64                       `json:"platformFloorPolicyRevision"`
	ClientSecretRevision        uint64                       `json:"clientSecretRevision"`
	ClientID                    string                       `json:"clientId"`
	RedirectURI                 string                       `json:"redirectUri"`
	PostLogoutRedirectURI       string                       `json:"postLogoutRedirectUri"`
	ExtraScopes                 []string                     `json:"extraScopes"`
	AllowRefreshToken           bool                         `json:"allowRefreshToken"`
	UseUserInfo                 bool                         `json:"useUserInfo"`
}

type platformOIDCDirectAdmissionPolicyWire struct {
	AccountMode string `json:"accountMode"`
}

type platformOIDCDirectConfigurationWire struct {
	Authorization          platformOIDCDirectAuthorizationWire   `json:"authorization"`
	Issuer                 string                                `json:"issuer"`
	DiscoveryRevision      uint64                                `json:"discoveryRevision"`
	DiscoveryDocument      []byte                                `json:"discoveryDocument"`
	DiscoveryDigest        []byte                                `json:"discoveryDigest"`
	DiscoveryCache         federatedCacheMetadataWire            `json:"discoveryCache"`
	DiscoveryPolicy        oidcTrustPolicyWire                   `json:"discoveryPolicy"`
	JWKSDocument           []byte                                `json:"jwksDocument"`
	JWKSDigest             []byte                                `json:"jwksDigest"`
	JWKSRevision           uint64                                `json:"jwksRevision"`
	JWKSCache              federatedCacheMetadataWire            `json:"jwksCache"`
	IDTokenClaims          federatedoidc.ClaimExtractionPolicy   `json:"idTokenClaims"`
	UserInfoClaims         federatedoidc.ClaimExtractionPolicy   `json:"userInfoClaims"`
	Pins                   platformOIDCDirectPinsWire            `json:"pins"`
	PlatformFloor          assurancePolicyWire                   `json:"platformFloor"`
	RuntimeAdmissionPolicy platformOIDCDirectAdmissionPolicyWire `json:"runtimeAdmissionPolicy"`
}

type platformOIDCDirectCallbackConfigurationLookupWire struct {
	TransactionID           []byte                     `json:"transactionId"`
	ExpectedVersion         uint64                     `json:"expectedVersion"`
	Pins                    platformOIDCDirectPinsWire `json:"pins"`
	BrowserCapabilityDigest []byte                     `json:"browserCapabilityDigest"`
}

type platformOIDCDirectCallbackConfigurationWire struct {
	Pins          platformOIDCDirectPinsWire          `json:"pins"`
	ReturnPath    string                              `json:"returnPath"`
	Configuration platformOIDCDirectConfigurationWire `json:"configuration"`
}

var (
	_ platformoidcauth.DirectOIDCStartSource         = (*FederatedAuthRepository)(nil)
	_ platformoidcauth.DirectOIDCConfigurationSource = (*FederatedAuthRepository)(nil)
)

func (repository *FederatedAuthRepository) BeginDirectOIDCLogin(
	ctx context.Context,
	authority platformoidcauth.DirectOIDCStartAuthority,
) (platformoidcauth.DirectOIDCStartGrant, error) {
	if repository == nil || repository.queryer == nil || repository.oidcClient == nil ||
		ctx == nil || ctx.Err() != nil || !validPlatformOIDCDirectStartAuthority(authority) {
		return platformoidcauth.DirectOIDCStartGrant{}, errFederatedAuthPersistence
	}
	response, err := repository.loadPlatformOIDCDirectConfiguration(ctx, authority.Lookup.LoginKey)
	defer clearPlatformOIDCDirectConfigurationWire(&response)
	if err != nil || ctx.Err() != nil {
		return platformoidcauth.DirectOIDCStartGrant{}, errFederatedAuthPersistence
	}
	_, pins, err := repository.platformOIDCDirectConfigurationFromWire(response)
	if err != nil {
		return platformoidcauth.DirectOIDCStartGrant{}, errFederatedAuthPersistence
	}
	return platformoidcauth.DirectOIDCStartGrant{Authority: authority, Pins: pins}, nil
}

func (repository *FederatedAuthRepository) LoadDirectOIDCStartConfiguration(
	ctx context.Context,
	grant platformoidcauth.DirectOIDCStartGrant,
) (platformoidcauth.DirectOIDCStartConfigurationSnapshot, error) {
	if repository == nil || repository.queryer == nil || repository.oidcClient == nil ||
		ctx == nil || ctx.Err() != nil || !validPlatformOIDCDirectStartAuthority(grant.Authority) {
		return platformoidcauth.DirectOIDCStartConfigurationSnapshot{}, errFederatedAuthPersistence
	}
	response, err := repository.loadPlatformOIDCDirectConfiguration(ctx, grant.Authority.Lookup.LoginKey)
	defer clearPlatformOIDCDirectConfigurationWire(&response)
	if err != nil || ctx.Err() != nil {
		return platformoidcauth.DirectOIDCStartConfigurationSnapshot{}, errFederatedAuthPersistence
	}
	configuration, pins, err := repository.platformOIDCDirectConfigurationFromWire(response)
	if err != nil || pins != grant.Pins {
		return platformoidcauth.DirectOIDCStartConfigurationSnapshot{}, errFederatedAuthPersistence
	}
	return platformoidcauth.DirectOIDCStartConfigurationSnapshot{
		Grant: grant, Configuration: configuration,
	}, nil
}

func (repository *FederatedAuthRepository) ResolveDirectOIDCCallbackConfiguration(
	ctx context.Context,
	lookup platformoidcauth.DirectOIDCCallbackConfigurationLookup,
) (platformoidcauth.DirectOIDCCallbackConfigurationSnapshot, error) {
	if repository == nil || repository.queryer == nil || repository.oidcClient == nil ||
		ctx == nil || ctx.Err() != nil {
		return platformoidcauth.DirectOIDCCallbackConfigurationSnapshot{}, errFederatedAuthPersistence
	}
	wire, pins, err := platformOIDCDirectCallbackConfigurationLookupToWire(lookup)
	if err != nil {
		return platformoidcauth.DirectOIDCCallbackConfigurationSnapshot{}, errFederatedAuthPersistence
	}
	defer clearPlatformOIDCDirectCallbackConfigurationLookupWire(&wire)
	var response platformOIDCDirectCallbackConfigurationWire
	defer clearPlatformOIDCDirectCallbackConfigurationWire(&response)
	if err = repository.queryJSONWithResponseLimit(
		ctx, resolvePlatformOIDCDirectConfigurationSQL, wire, &response,
		maximumFederatedConfigurationResponseBytes,
	); err != nil || ctx.Err() != nil {
		return platformoidcauth.DirectOIDCCallbackConfigurationSnapshot{}, errFederatedAuthPersistence
	}
	configuration, responsePins, err := repository.platformOIDCDirectConfigurationFromWire(response.Configuration)
	outerPins, outerErr := platformOIDCDirectPinsFromWire(response.Pins)
	if err != nil || outerErr != nil || responsePins != pins || outerPins != pins ||
		!validPlatformOIDCDirectReturnPath(response.ReturnPath) ||
		response.ReturnPath != lookup.Transaction.ReturnPath {
		return platformoidcauth.DirectOIDCCallbackConfigurationSnapshot{}, errFederatedAuthPersistence
	}
	return platformoidcauth.DirectOIDCCallbackConfigurationSnapshot{
		Lookup: lookup, Pins: pins, ReturnPath: response.ReturnPath, Configuration: configuration,
	}, nil
}

func (repository *FederatedAuthRepository) loadPlatformOIDCDirectConfiguration(
	ctx context.Context,
	loginKey string,
) (platformOIDCDirectConfigurationWire, error) {
	if !platformOIDCDirectLoginKeyPattern.MatchString(loginKey) {
		return platformOIDCDirectConfigurationWire{}, errFederatedAuthPersistence
	}
	var response platformOIDCDirectConfigurationWire
	if err := repository.queryJSONWithResponseLimit(
		ctx, beginPlatformOIDCDirectConfigurationSQL,
		platformOIDCDirectBeginConfigurationWire{LoginKey: loginKey}, &response,
		maximumFederatedConfigurationResponseBytes,
	); err != nil {
		clearPlatformOIDCDirectConfigurationWire(&response)
		return platformOIDCDirectConfigurationWire{}, errFederatedAuthPersistence
	}
	return response, nil
}

func (repository *FederatedAuthRepository) platformOIDCDirectConfigurationFromWire(
	wire platformOIDCDirectConfigurationWire,
) (platformoidcauth.DirectOIDCConfiguration, platformoidcauth.DirectOIDCConfigurationPins, error) {
	discoveryDocument := append([]byte(nil), wire.DiscoveryDocument...)
	jwksDocument := append([]byte(nil), wire.JWKSDocument...)
	defer clear(discoveryDocument)
	defer clear(jwksDocument)
	pins, pinsErr := platformOIDCDirectPinsFromWire(wire.Pins)
	authorization, authorizationErr := platformOIDCDirectAuthorizationFromWire(wire.Authorization, pins)
	discoveryCache, discoveryCacheErr := cacheMetadataFromWire(wire.DiscoveryCache)
	jwksCache, jwksCacheErr := cacheMetadataFromWire(wire.JWKSCache)
	floor, floorErr := assurancePolicyFromWire(wire.PlatformFloor)
	if repository == nil || repository.oidcClient == nil || pinsErr != nil || authorizationErr != nil ||
		discoveryCacheErr != nil || jwksCacheErr != nil || floorErr != nil ||
		floor.ID != pins.PlatformFloorPolicyID || uint64(floor.Revision) != pins.PlatformFloorPolicyRevision ||
		wire.RuntimeAdmissionPolicy.AccountMode != string(platformoidcauth.AccountModeExistingIdentity) ||
		!zeroPlatformOIDCDirectClaimPolicy(wire.UserInfoClaims) ||
		wire.DiscoveryRevision != pins.DiscoveryRevision || wire.JWKSRevision != pins.JWKSRevision ||
		!validDigestWire(wire.DiscoveryDigest) || !validDigestWire(wire.JWKSDigest) ||
		len(discoveryDocument) == 0 || len(jwksDocument) == 0 {
		return platformoidcauth.DirectOIDCConfiguration{}, platformoidcauth.DirectOIDCConfigurationPins{},
			errFederatedAuthPersistence
	}
	var discoveryDigest, jwksDigest [sha256.Size]byte
	copy(discoveryDigest[:], wire.DiscoveryDigest)
	copy(jwksDigest[:], wire.JWKSDigest)
	if discoveryDigest != pins.DiscoveryDigest || jwksDigest != pins.JWKSDigest {
		return platformoidcauth.DirectOIDCConfiguration{}, platformoidcauth.DirectOIDCConfigurationPins{},
			errFederatedAuthPersistence
	}
	discovery, err := repository.oidcClient.RestoreDiscovery(federatedoidc.DiscoverySnapshotRecord{
		Request: federatedoidc.DiscoveryRequest{
			Issuer: wire.Issuer, Revision: wire.DiscoveryRevision,
			Policy: federatedoidc.TrustPolicy{
				ClientAuthentication: federatedoidc.ClientAuthenticationMode(wire.DiscoveryPolicy.ClientAuthentication),
				SigningAlgorithms:    signingAlgorithmsFromWire(wire.DiscoveryPolicy.SigningAlgorithms),
			},
		},
		Document: discoveryDocument, Digest: discoveryDigest, Cache: discoveryCache,
	})
	if err != nil {
		return platformoidcauth.DirectOIDCConfiguration{}, platformoidcauth.DirectOIDCConfigurationPins{},
			errFederatedAuthPersistence
	}
	keys, err := repository.oidcClient.RestoreJWKS(federatedoidc.JWKSSnapshotRecord{
		Revision: wire.JWKSRevision, Document: jwksDocument, Digest: jwksDigest,
		Cache: jwksCache, Discovery: discovery,
	})
	if err != nil {
		return platformoidcauth.DirectOIDCConfiguration{}, platformoidcauth.DirectOIDCConfigurationPins{},
			errFederatedAuthPersistence
	}
	authorization.Discovery = discovery
	authorization.JWKS = keys
	return platformoidcauth.DirectOIDCConfiguration{
		Authorization: authorization, IDTokenClaims: cloneOIDCClaimExtractionPolicy(wire.IDTokenClaims),
	}, pins, nil
}

func platformOIDCDirectAuthorizationFromWire(
	wire platformOIDCDirectAuthorizationWire,
	pins platformoidcauth.DirectOIDCConfigurationPins,
) (federatedoidc.AuthorizationConfiguration, error) {
	provider, binding, err := providerBindingFromWire(wire.Provider, true)
	floorID, floorErr := parseFederatedEntityIDWire(wire.PlatformFloorPolicyID, false)
	if err != nil || floorErr != nil || provider != pins.Provider || binding != (identity.EntityID{}) ||
		wire.ProviderRevision != pins.ProviderRevision ||
		wire.LoginPolicyRevision != pins.PlatformLoginRevision ||
		wire.ConfigurationRevision != pins.ConfigurationRevision ||
		wire.SecurityRevision != pins.SecurityRevision ||
		wire.AssurancePolicyRevision != pins.AssurancePolicyRevision ||
		floorID != pins.PlatformFloorPolicyID ||
		wire.PlatformFloorPolicyRevision != pins.PlatformFloorPolicyRevision ||
		wire.ClientSecretRevision != pins.ClientSecretRevision ||
		wire.UseUserInfo {
		return federatedoidc.AuthorizationConfiguration{}, errFederatedAuthPersistence
	}
	return federatedoidc.AuthorizationConfiguration{
		Authority: federatedoidc.DirectPlatformCeremonyAuthority,
		Provider:  provider, ProviderRevision: wire.ProviderRevision,
		PlatformLoginRevision: wire.LoginPolicyRevision,
		ConfigurationRevision: wire.ConfigurationRevision, SecurityRevision: wire.SecurityRevision,
		PlanRevision:            pins.PlanRevision,
		AssurancePolicyRevision: wire.AssurancePolicyRevision,
		PlatformFloorPolicyID:   floorID, PlatformFloorRevision: wire.PlatformFloorPolicyRevision,
		ClientSecretRevision: wire.ClientSecretRevision, ClientID: wire.ClientID,
		RedirectURI: wire.RedirectURI, PostLogoutRedirectURI: wire.PostLogoutRedirectURI,
		ExtraScopes:       append([]string(nil), wire.ExtraScopes...),
		AllowRefreshToken: wire.AllowRefreshToken, UseUserInfo: false,
	}, nil
}

func platformOIDCDirectCallbackConfigurationLookupToWire(
	lookup platformoidcauth.DirectOIDCCallbackConfigurationLookup,
) (platformOIDCDirectCallbackConfigurationLookupWire, platformoidcauth.DirectOIDCConfigurationPins, error) {
	pins, err := platformOIDCDirectPinsFromTransaction(lookup.Transaction.Pins)
	if err != nil || !validOpaque32(lookup.Transaction.TransactionID[:]) ||
		!validFederatedRevision(lookup.Transaction.ExpectedVersion) ||
		!validPlatformOIDCDigest(lookup.BrowserCapabilityDigest[:]) ||
		!validPlatformOIDCDirectReturnPath(lookup.Transaction.ReturnPath) {
		return platformOIDCDirectCallbackConfigurationLookupWire{},
			platformoidcauth.DirectOIDCConfigurationPins{}, errFederatedAuthPersistence
	}
	wirePins, err := platformOIDCDirectPinsToWire(pins)
	if err != nil {
		return platformOIDCDirectCallbackConfigurationLookupWire{},
			platformoidcauth.DirectOIDCConfigurationPins{}, errFederatedAuthPersistence
	}
	return platformOIDCDirectCallbackConfigurationLookupWire{
		TransactionID:   append([]byte(nil), lookup.Transaction.TransactionID[:]...),
		ExpectedVersion: lookup.Transaction.ExpectedVersion, Pins: wirePins,
		BrowserCapabilityDigest: append([]byte(nil), lookup.BrowserCapabilityDigest[:]...),
	}, pins, nil
}

func platformOIDCDirectPinsFromTransaction(
	value federatedoidc.TransactionPins,
) (platformoidcauth.DirectOIDCConfigurationPins, error) {
	if value.Authority != federatedoidc.DirectPlatformCeremonyAuthority ||
		value.Admission != (identity.TenantAdmissionContext{}) || value.BindingID != (identity.EntityID{}) ||
		value.BindingRevision != 0 || value.MappingRevision != 0 || value.AuthorizationRevision != 0 {
		return platformoidcauth.DirectOIDCConfigurationPins{}, errFederatedAuthPersistence
	}
	return platformOIDCDirectPinsValidated(platformoidcauth.DirectOIDCConfigurationPins{
		Provider: value.Provider, ProviderRevision: value.ProviderRevision,
		PlatformLoginRevision: value.PlatformLoginRevision,
		ConfigurationRevision: value.ConfigurationRevision, SecurityRevision: value.SecurityRevision,
		PlanRevision: value.PlanRevision, AssurancePolicyRevision: value.AssurancePolicyRevision,
		PlatformFloorPolicyID:       value.PlatformFloorPolicyID,
		PlatformFloorPolicyRevision: value.PlatformFloorRevision,
		ClientSecretRevision:        value.ClientSecretRevision, DiscoveryRevision: value.DiscoveryRevision,
		DiscoveryDigest: value.DiscoveryDigest, JWKSRevision: value.JWKSRevision, JWKSDigest: value.JWKSDigest,
	})
}

func platformOIDCDirectPinsToWire(
	value platformoidcauth.DirectOIDCConfigurationPins,
) (platformOIDCDirectPinsWire, error) {
	value, err := platformOIDCDirectPinsValidated(value)
	if err != nil {
		return platformOIDCDirectPinsWire{}, err
	}
	provider, err := providerBindingToWire(value.Provider, identity.EntityID{}, true)
	floorID, floorErr := requiredFederatedEntityIDWire(value.PlatformFloorPolicyID)
	if err != nil || floorErr != nil {
		return platformOIDCDirectPinsWire{}, errFederatedAuthPersistence
	}
	return platformOIDCDirectPinsWire{
		Provider: provider, ProviderRevision: value.ProviderRevision,
		LoginPolicyRevision:   value.PlatformLoginRevision,
		ConfigurationRevision: value.ConfigurationRevision, SecurityRevision: value.SecurityRevision,
		PlanRevision: value.PlanRevision, AssurancePolicyRevision: value.AssurancePolicyRevision,
		PlatformFloorPolicyID: floorID, PlatformFloorPolicyRevision: value.PlatformFloorPolicyRevision,
		ClientSecretRevision: value.ClientSecretRevision, DiscoveryRevision: value.DiscoveryRevision,
		DiscoveryDigest: append([]byte(nil), value.DiscoveryDigest[:]...),
		JWKSRevision:    value.JWKSRevision, JWKSDigest: append([]byte(nil), value.JWKSDigest[:]...),
	}, nil
}

func platformOIDCDirectPinsFromWire(
	wire platformOIDCDirectPinsWire,
) (platformoidcauth.DirectOIDCConfigurationPins, error) {
	provider, binding, err := providerBindingFromWire(wire.Provider, true)
	floorID, floorErr := parseFederatedEntityIDWire(wire.PlatformFloorPolicyID, false)
	if err != nil || floorErr != nil || binding != (identity.EntityID{}) ||
		!validDigestWire(wire.DiscoveryDigest) || !validDigestWire(wire.JWKSDigest) {
		return platformoidcauth.DirectOIDCConfigurationPins{}, errFederatedAuthPersistence
	}
	value := platformoidcauth.DirectOIDCConfigurationPins{
		Provider: provider, ProviderRevision: wire.ProviderRevision,
		PlatformLoginRevision: wire.LoginPolicyRevision,
		ConfigurationRevision: wire.ConfigurationRevision, SecurityRevision: wire.SecurityRevision,
		PlanRevision: wire.PlanRevision, AssurancePolicyRevision: wire.AssurancePolicyRevision,
		PlatformFloorPolicyID: floorID, PlatformFloorPolicyRevision: wire.PlatformFloorPolicyRevision,
		ClientSecretRevision: wire.ClientSecretRevision, DiscoveryRevision: wire.DiscoveryRevision,
		JWKSRevision: wire.JWKSRevision,
	}
	copy(value.DiscoveryDigest[:], wire.DiscoveryDigest)
	copy(value.JWKSDigest[:], wire.JWKSDigest)
	return platformOIDCDirectPinsValidated(value)
}

func platformOIDCDirectPinsValidated(
	value platformoidcauth.DirectOIDCConfigurationPins,
) (platformoidcauth.DirectOIDCConfigurationPins, error) {
	if value.Provider.Scope != identity.PlatformProviderScope ||
		value.Provider.TenantID != (identity.EntityID{}) ||
		!platformOIDCDirectUUIDv7(uuid.UUID(value.Provider.ProviderID)) ||
		!platformOIDCDirectUUIDv7(uuid.UUID(value.PlatformFloorPolicyID)) ||
		!validPlatformOIDCDirectRevision(value.ProviderRevision) ||
		!validPlatformOIDCDirectRevision(value.PlatformLoginRevision) ||
		!validPlatformOIDCDirectRevision(value.ConfigurationRevision) ||
		!validPlatformOIDCDirectRevision(value.SecurityRevision) ||
		!validPlatformOIDCDirectRevision(value.PlanRevision) ||
		!validPlatformOIDCDirectRevision(value.AssurancePolicyRevision) ||
		!validPlatformOIDCDirectRevision(value.PlatformFloorPolicyRevision) ||
		!validPlatformOIDCDirectRevision(value.ClientSecretRevision) ||
		!validPlatformOIDCDirectRevision(value.DiscoveryRevision) ||
		value.DiscoveryDigest == ([sha256.Size]byte{}) ||
		!validPlatformOIDCDirectRevision(value.JWKSRevision) || value.JWKSDigest == ([sha256.Size]byte{}) {
		return platformoidcauth.DirectOIDCConfigurationPins{}, errFederatedAuthPersistence
	}
	return value, nil
}

func validPlatformOIDCDirectStartAuthority(value platformoidcauth.DirectOIDCStartAuthority) bool {
	lookup := value.Lookup
	if !platformOIDCDirectUUIDv7(uuid.UUID(lookup.OperationRunID)) ||
		!platformOIDCDirectLoginKeyPattern.MatchString(lookup.LoginKey) ||
		!validPlatformOIDCDigest(lookup.ReceiptDigest[:]) ||
		!validPlatformOIDCDigest(lookup.NetworkDigest[:]) ||
		!validPlatformOIDCDigest(lookup.AccountDigest[:]) ||
		!validPlatformOIDCDigest(lookup.ProviderDigest[:]) ||
		!validPlatformOIDCDigest(lookup.BrowserCapabilityDigest[:]) ||
		equalAnyDigest(lookup.ReceiptDigest[:], lookup.NetworkDigest[:], lookup.AccountDigest[:],
			lookup.ProviderDigest[:], lookup.BrowserCapabilityDigest[:]) ||
		!validPlatformOIDCDirectReturnPath(value.ReturnPath) {
		return false
	}
	audit := value.Audit
	if !platformOIDCDirectUUIDv7(uuid.UUID(audit.RequestID)) ||
		!platformOIDCDirectUUIDv7(uuid.UUID(audit.CorrelationID)) ||
		!validPlatformOIDCDirectAuditAddress(audit.RemoteAddress) || audit.UserAgent == "" ||
		len(audit.UserAgent) > maximumPlatformOIDCAuditUserAgentBytes || !utf8.ValidString(audit.UserAgent) {
		return false
	}
	for _, character := range audit.UserAgent {
		if unicode.IsControl(character) || platformOIDCDirectionalControl(character) {
			return false
		}
	}
	return true
}

func validPlatformOIDCDirectReturnPath(value string) bool {
	if value == "" || len(value) > 2_048 || !utf8.ValidString(value) ||
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

func zeroPlatformOIDCDirectClaimPolicy(value federatedoidc.ClaimExtractionPolicy) bool {
	return len(value.Scalars) == 0 && len(value.Profiles) == 0 && value.Groups == nil &&
		value.ACR == nil && value.AMR == nil
}

func clearPlatformOIDCDirectConfigurationWire(value *platformOIDCDirectConfigurationWire) {
	if value == nil {
		return
	}
	clear(value.DiscoveryDocument)
	clear(value.DiscoveryDigest)
	clear(value.JWKSDocument)
	clear(value.JWKSDigest)
	clear(value.Pins.DiscoveryDigest)
	clear(value.Pins.JWKSDigest)
	*value = platformOIDCDirectConfigurationWire{}
}

func clearPlatformOIDCDirectCallbackConfigurationLookupWire(
	value *platformOIDCDirectCallbackConfigurationLookupWire,
) {
	if value == nil {
		return
	}
	clear(value.TransactionID)
	clear(value.Pins.DiscoveryDigest)
	clear(value.Pins.JWKSDigest)
	clear(value.BrowserCapabilityDigest)
	*value = platformOIDCDirectCallbackConfigurationLookupWire{}
}

func clearPlatformOIDCDirectCallbackConfigurationWire(
	value *platformOIDCDirectCallbackConfigurationWire,
) {
	if value == nil {
		return
	}
	clear(value.Pins.DiscoveryDigest)
	clear(value.Pins.JWKSDigest)
	clearPlatformOIDCDirectConfigurationWire(&value.Configuration)
	*value = platformOIDCDirectCallbackConfigurationWire{}
}
