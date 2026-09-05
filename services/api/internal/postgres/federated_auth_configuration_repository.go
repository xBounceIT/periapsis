package postgres

import (
	"context"
	"crypto/sha256"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedhttp"
	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
)

const (
	beginTenantOIDCConfigurationSQL   = `select app.begin_tenant_oidc_authentication_v1($1::jsonb)`
	resolveTenantOIDCConfigurationSQL = `select app.resolve_tenant_oidc_authentication_v1($1::jsonb)`
	beginTenantSAMLConfigurationSQL   = `select app.begin_tenant_saml_authentication_v1($1::jsonb)`
	resolveTenantSAMLConfigurationSQL = `select app.resolve_tenant_saml_authentication_v1($1::jsonb)`

	// The schema permits two independently encoded 1 MiB OIDC documents or
	// one 2 MiB SAML metadata document. The JSON wire represents []byte with
	// padded standard base64, so the generic 2 MiB ceiling cannot carry
	// a valid maximum-sized configuration. Keep a further bounded allowance
	// for the typed configuration, claim/mapping rules, and JSON structure.
	maximumFederatedConfigurationDocumentBytes        = 1024 * 1024
	maximumFederatedConfigurationDocumentCount        = 2
	maximumFederatedConfigurationEncodedDocumentBytes = maximumFederatedConfigurationDocumentCount *
		4 * ((maximumFederatedConfigurationDocumentBytes + 2) / 3)
	maximumFederatedConfigurationNonDocumentWireBytes = 2 * 1024 * 1024
	maximumFederatedConfigurationResponseBytes        = maximumFederatedConfigurationEncodedDocumentBytes +
		maximumFederatedConfigurationNonDocumentWireBytes
)

type federatedStartLookupWire struct {
	Begin      federatedBeginWire `json:"begin"`
	TenantSlug string             `json:"tenantSlug"`
	LoginKey   string             `json:"loginKey"`
}

type federatedCacheMetadataWire struct {
	RetrievedAt    time.Time `json:"retrievedAt"`
	FreshUntil     time.Time `json:"freshUntil"`
	Cacheable      bool      `json:"cacheable"`
	MustRevalidate bool      `json:"mustRevalidate"`
}

type oidcAuthorizationConfigurationWire struct {
	Provider                federatedProviderBindingWire  `json:"provider"`
	Admission               *federatedTenantAdmissionWire `json:"admission,omitempty"`
	ProviderRevision        uint64                        `json:"providerRevision"`
	BindingRevision         uint64                        `json:"bindingRevision"`
	ConfigurationRevision   uint64                        `json:"configurationRevision"`
	SecurityRevision        uint64                        `json:"securityRevision"`
	MappingRevision         uint64                        `json:"mappingRevision"`
	AuthorizationRevision   uint64                        `json:"authorizationRevision"`
	AssurancePolicyRevision uint64                        `json:"assurancePolicyRevision"`
	ClientSecretRevision    uint64                        `json:"clientSecretRevision"`
	ClientID                string                        `json:"clientId"`
	RedirectURI             string                        `json:"redirectUri"`
	PostLogoutRedirectURI   string                        `json:"postLogoutRedirectUri"`
	ExtraScopes             []string                      `json:"extraScopes"`
	AllowRefreshToken       bool                          `json:"allowRefreshToken"`
	UseUserInfo             bool                          `json:"useUserInfo"`
}

type oidcTrustPolicyWire struct {
	ClientAuthentication string   `json:"clientAuthentication"`
	SigningAlgorithms    []string `json:"signingAlgorithms"`
}

type tenantOIDCConfigurationRecordWire struct {
	Authorization     oidcAuthorizationConfigurationWire  `json:"authorization"`
	Issuer            string                              `json:"issuer"`
	DiscoveryRevision uint64                              `json:"discoveryRevision"`
	DiscoveryDocument []byte                              `json:"discoveryDocument"`
	DiscoveryDigest   []byte                              `json:"discoveryDigest"`
	DiscoveryCache    federatedCacheMetadataWire          `json:"discoveryCache"`
	DiscoveryPolicy   oidcTrustPolicyWire                 `json:"discoveryPolicy"`
	JWKSDocument      []byte                              `json:"jwksDocument"`
	JWKSDigest        []byte                              `json:"jwksDigest"`
	JWKSRevision      uint64                              `json:"jwksRevision"`
	JWKSCache         federatedCacheMetadataWire          `json:"jwksCache"`
	IDTokenClaims     federatedoidc.ClaimExtractionPolicy `json:"idTokenClaims"`
	UserInfoClaims    federatedoidc.ClaimExtractionPolicy `json:"userInfoClaims"`
}

type oidcCallbackConfigurationLookupWire struct {
	TransactionID   []byte                  `json:"transactionId"`
	ExpectedVersion uint64                  `json:"expectedVersion"`
	Pins            oidcTransactionPinsWire `json:"pins"`
}

type samlAuthenticationConfigurationWire struct {
	Provider                   federatedProviderBindingWire             `json:"provider"`
	ProviderRevision           uint64                                   `json:"providerRevision"`
	BindingRevision            uint64                                   `json:"bindingRevision"`
	ConfigurationRevision      uint64                                   `json:"configurationRevision"`
	SecurityRevision           uint64                                   `json:"securityRevision"`
	MappingRevision            uint64                                   `json:"mappingRevision"`
	AuthorizationRevision      uint64                                   `json:"authorizationRevision"`
	AssurancePolicyRevision    uint64                                   `json:"assurancePolicyRevision"`
	SPEntityID                 string                                   `json:"spEntityId"`
	ACSURL                     string                                   `json:"acsUrl"`
	SPKeyRevision              uint64                                   `json:"spKeyRevision"`
	RedirectSignatureAlgorithm federatedsaml.RedirectSignatureAlgorithm `json:"redirectSignatureAlgorithm"`
	SignaturePolicy            federatedsaml.SignaturePolicy            `json:"signaturePolicy"`
	EncryptionPolicy           federatedsaml.EncryptionPolicy           `json:"encryptionPolicy"`
	DecryptionKeyVersions      []uint32                                 `json:"decryptionKeyVersions"`
	RequestedAuthnContexts     []string                                 `json:"requestedAuthnContexts"`
	Subject                    federatedsaml.SubjectPolicy              `json:"subject"`
	Mapping                    federatedsaml.AttributeMappingPolicy     `json:"mapping"`
	TrustRules                 []federatedsaml.AuthnContextTrustRule    `json:"trustRules"`
	ClockSkew                  time.Duration                            `json:"clockSkewNanoseconds"`
	MaxAuthenticationAge       time.Duration                            `json:"maxAuthenticationAgeNanoseconds"`
}

type tenantSAMLConfigurationRecordWire struct {
	Authentication            samlAuthenticationConfigurationWire `json:"authentication"`
	ExpectedEntityID          string                              `json:"expectedEntityId"`
	MetadataRevision          uint64                              `json:"metadataRevision"`
	MetadataDocument          []byte                              `json:"metadataDocument"`
	MetadataDigest            []byte                              `json:"metadataDigest"`
	MetadataRetrievedAt       time.Time                           `json:"metadataRetrievedAt"`
	MetadataMaximumValidUntil time.Time                           `json:"metadataMaximumValidUntil"`
}

type samlCallbackConfigurationLookupWire struct {
	TransactionID   []byte                  `json:"transactionId"`
	ExpectedVersion uint64                  `json:"expectedVersion"`
	Pins            samlTransactionPinsWire `json:"pins"`
}

var _ federatedauth.TenantFederatedConfigurationRecords = (*FederatedAuthRepository)(nil)

func (repository *FederatedAuthRepository) BeginTenantOIDCConfigurationRecord(
	ctx context.Context,
	lookup federatedauth.OIDCStartLookup,
) (federatedauth.TenantOIDCConfigurationRecord, error) {
	wire, err := oidcStartLookupToWire(lookup)
	if err != nil {
		return federatedauth.TenantOIDCConfigurationRecord{}, errFederatedAuthPersistence
	}
	defer clearFederatedBeginWire(&wire.Begin)
	var response tenantOIDCConfigurationRecordWire
	defer clearTenantOIDCConfigurationRecordWire(&response)
	if err := repository.queryJSONWithResponseLimit(
		ctx, beginTenantOIDCConfigurationSQL, wire, &response, maximumFederatedConfigurationResponseBytes,
	); err != nil {
		return federatedauth.TenantOIDCConfigurationRecord{}, err
	}
	return tenantOIDCConfigurationRecordFromWire(response)
}

func (repository *FederatedAuthRepository) ResolveTenantOIDCConfigurationRecord(
	ctx context.Context,
	lookup federatedoidc.CallbackConfigurationLookup,
) (federatedauth.TenantOIDCConfigurationRecord, error) {
	wire, err := oidcCallbackLookupToWire(lookup)
	if err != nil {
		return federatedauth.TenantOIDCConfigurationRecord{}, errFederatedAuthPersistence
	}
	defer clearOIDCCallbackLookupWire(&wire)
	var response tenantOIDCConfigurationRecordWire
	defer clearTenantOIDCConfigurationRecordWire(&response)
	if err := repository.queryJSONWithResponseLimit(
		ctx, resolveTenantOIDCConfigurationSQL, wire, &response, maximumFederatedConfigurationResponseBytes,
	); err != nil {
		return federatedauth.TenantOIDCConfigurationRecord{}, err
	}
	return tenantOIDCConfigurationRecordFromWire(response)
}

func (repository *FederatedAuthRepository) BeginTenantSAMLConfigurationRecord(
	ctx context.Context,
	lookup federatedauth.SAMLStartLookup,
) (federatedauth.TenantSAMLConfigurationRecord, error) {
	wire, err := samlStartLookupToWire(lookup)
	if err != nil {
		return federatedauth.TenantSAMLConfigurationRecord{}, errFederatedAuthPersistence
	}
	defer clearFederatedBeginWire(&wire.Begin)
	var response tenantSAMLConfigurationRecordWire
	defer clearTenantSAMLConfigurationRecordWire(&response)
	if err := repository.queryJSONWithResponseLimit(
		ctx, beginTenantSAMLConfigurationSQL, wire, &response, maximumFederatedConfigurationResponseBytes,
	); err != nil {
		return federatedauth.TenantSAMLConfigurationRecord{}, err
	}
	return tenantSAMLConfigurationRecordFromWire(response)
}

func (repository *FederatedAuthRepository) ResolveTenantSAMLConfigurationRecord(
	ctx context.Context,
	lookup federatedsaml.CallbackConfigurationLookup,
) (federatedauth.TenantSAMLConfigurationRecord, error) {
	wire, err := samlCallbackLookupToWire(lookup)
	if err != nil {
		return federatedauth.TenantSAMLConfigurationRecord{}, errFederatedAuthPersistence
	}
	defer clearSAMLCallbackLookupWire(&wire)
	var response tenantSAMLConfigurationRecordWire
	defer clearTenantSAMLConfigurationRecordWire(&response)
	if err := repository.queryJSONWithResponseLimit(
		ctx, resolveTenantSAMLConfigurationSQL, wire, &response, maximumFederatedConfigurationResponseBytes,
	); err != nil {
		return federatedauth.TenantSAMLConfigurationRecord{}, err
	}
	return tenantSAMLConfigurationRecordFromWire(response)
}

func oidcStartLookupToWire(lookup federatedauth.OIDCStartLookup) (federatedStartLookupWire, error) {
	begin, err := federatedBeginToWire(
		lookup.OperationRunID, lookup.ReceiptDigest[:], lookup.NetworkDigest[:],
		lookup.AccountDigest[:], lookup.ProviderDigest[:],
	)
	if err != nil || lookup.TenantSlug == "" || lookup.LoginKey == "" {
		return federatedStartLookupWire{}, errFederatedAuthPersistence
	}
	return federatedStartLookupWire{Begin: begin, TenantSlug: lookup.TenantSlug, LoginKey: lookup.LoginKey}, nil
}

func samlStartLookupToWire(lookup federatedauth.SAMLStartLookup) (federatedStartLookupWire, error) {
	begin, err := federatedBeginToWire(
		lookup.OperationRunID, lookup.ReceiptDigest[:], lookup.NetworkDigest[:],
		lookup.AccountDigest[:], lookup.ProviderDigest[:],
	)
	if err != nil || lookup.TenantSlug == "" || lookup.LoginKey == "" {
		return federatedStartLookupWire{}, errFederatedAuthPersistence
	}
	return federatedStartLookupWire{Begin: begin, TenantSlug: lookup.TenantSlug, LoginKey: lookup.LoginKey}, nil
}

func oidcCallbackLookupToWire(
	lookup federatedoidc.CallbackConfigurationLookup,
) (oidcCallbackConfigurationLookupWire, error) {
	pins, err := oidcPinsToWire(lookup.Pins)
	if err != nil || !validOpaque32(lookup.TransactionID[:]) || !validFederatedRevision(lookup.ExpectedVersion) {
		return oidcCallbackConfigurationLookupWire{}, errFederatedAuthPersistence
	}
	return oidcCallbackConfigurationLookupWire{
		TransactionID: append([]byte(nil), lookup.TransactionID[:]...), ExpectedVersion: lookup.ExpectedVersion, Pins: pins,
	}, nil
}

func samlCallbackLookupToWire(
	lookup federatedsaml.CallbackConfigurationLookup,
) (samlCallbackConfigurationLookupWire, error) {
	pins, err := samlPinsToWire(lookup.Pins)
	if err != nil || !validOpaque32(lookup.TransactionID[:]) || !validFederatedRevision(lookup.ExpectedVersion) {
		return samlCallbackConfigurationLookupWire{}, errFederatedAuthPersistence
	}
	return samlCallbackConfigurationLookupWire{
		TransactionID: append([]byte(nil), lookup.TransactionID[:]...), ExpectedVersion: lookup.ExpectedVersion, Pins: pins,
	}, nil
}

func tenantOIDCConfigurationRecordFromWire(
	wire tenantOIDCConfigurationRecordWire,
) (federatedauth.TenantOIDCConfigurationRecord, error) {
	authorization, err := oidcAuthorizationFromWire(wire.Authorization)
	discoveryCache, discoveryCacheErr := cacheMetadataFromWire(wire.DiscoveryCache)
	jwksCache, jwksCacheErr := cacheMetadataFromWire(wire.JWKSCache)
	admission, validAdmission := authorization.TenantAdmission()
	if err != nil || !validAdmission || admission.TenantID == (identity.EntityID{}) ||
		admission.BindingID == (identity.EntityID{}) ||
		!validFederatedRevision(wire.DiscoveryRevision) || !validDigestWire(wire.DiscoveryDigest) ||
		!validFederatedRevision(wire.JWKSRevision) || !validDigestWire(wire.JWKSDigest) ||
		len(wire.DiscoveryDocument) == 0 || len(wire.JWKSDocument) == 0 ||
		discoveryCacheErr != nil || jwksCacheErr != nil {
		return federatedauth.TenantOIDCConfigurationRecord{}, errFederatedAuthPersistence
	}
	var discoveryDigest, jwksDigest [sha256.Size]byte
	copy(discoveryDigest[:], wire.DiscoveryDigest)
	copy(jwksDigest[:], wire.JWKSDigest)
	return federatedauth.TenantOIDCConfigurationRecord{
		Authorization: authorization, Issuer: wire.Issuer, DiscoveryRevision: wire.DiscoveryRevision,
		DiscoveryDocument: append([]byte(nil), wire.DiscoveryDocument...), DiscoveryDigest: discoveryDigest,
		DiscoveryCache: discoveryCache,
		DiscoveryPolicy: federatedoidc.TrustPolicy{
			ClientAuthentication: federatedoidc.ClientAuthenticationMode(wire.DiscoveryPolicy.ClientAuthentication),
			SigningAlgorithms:    signingAlgorithmsFromWire(wire.DiscoveryPolicy.SigningAlgorithms),
		},
		JWKSDocument: append([]byte(nil), wire.JWKSDocument...), JWKSDigest: jwksDigest,
		JWKSRevision: wire.JWKSRevision, JWKSCache: jwksCache,
		IDTokenClaims:  cloneOIDCClaimExtractionPolicy(wire.IDTokenClaims),
		UserInfoClaims: cloneOIDCClaimExtractionPolicy(wire.UserInfoClaims),
	}, nil
}

func oidcAuthorizationFromWire(
	wire oidcAuthorizationConfigurationWire,
) (federatedoidc.AuthorizationConfiguration, error) {
	provider, admission, binding, err := oidcProviderAdmissionFromWire(wire.Provider, wire.Admission)
	if err != nil || !validFederatedRevision(wire.ProviderRevision) || !validFederatedRevision(wire.BindingRevision) ||
		!validFederatedRevision(wire.ConfigurationRevision) || !validFederatedRevision(wire.SecurityRevision) ||
		!validFederatedRevision(wire.MappingRevision) || !validFederatedRevision(wire.AuthorizationRevision) ||
		!validFederatedRevision(wire.AssurancePolicyRevision) || !validFederatedRevision(wire.ClientSecretRevision) {
		return federatedoidc.AuthorizationConfiguration{}, errFederatedAuthPersistence
	}
	return federatedoidc.AuthorizationConfiguration{
		Provider: provider, Admission: admission, BindingID: binding, ProviderRevision: wire.ProviderRevision,
		BindingRevision: wire.BindingRevision, ConfigurationRevision: wire.ConfigurationRevision,
		SecurityRevision: wire.SecurityRevision, MappingRevision: wire.MappingRevision,
		AuthorizationRevision: wire.AuthorizationRevision, AssurancePolicyRevision: wire.AssurancePolicyRevision,
		ClientSecretRevision: wire.ClientSecretRevision, ClientID: wire.ClientID,
		RedirectURI: wire.RedirectURI, PostLogoutRedirectURI: wire.PostLogoutRedirectURI,
		ExtraScopes: append([]string(nil), wire.ExtraScopes...), AllowRefreshToken: wire.AllowRefreshToken,
		UseUserInfo: wire.UseUserInfo,
	}, nil
}

func tenantSAMLConfigurationRecordFromWire(
	wire tenantSAMLConfigurationRecordWire,
) (federatedauth.TenantSAMLConfigurationRecord, error) {
	authentication, err := samlAuthenticationFromWire(wire.Authentication)
	retrievedAt, validRetrievedAt := canonicalFederatedDatabaseTimeFromWire(wire.MetadataRetrievedAt)
	maximumValidUntil, validMaximumValidUntil := canonicalFederatedDatabaseTimeFromWire(
		wire.MetadataMaximumValidUntil,
	)
	if err != nil || authentication.Provider.Scope != identity.TenantProviderScope ||
		authentication.Provider.TenantID == (identity.EntityID{}) || authentication.BindingID == (identity.EntityID{}) ||
		!validFederatedRevision(wire.MetadataRevision) || !validDigestWire(wire.MetadataDigest) ||
		len(wire.MetadataDocument) == 0 || !validRetrievedAt || !validMaximumValidUntil ||
		!maximumValidUntil.After(retrievedAt) {
		return federatedauth.TenantSAMLConfigurationRecord{}, errFederatedAuthPersistence
	}
	var digest [sha256.Size]byte
	copy(digest[:], wire.MetadataDigest)
	return federatedauth.TenantSAMLConfigurationRecord{
		Authentication: authentication, ExpectedEntityID: wire.ExpectedEntityID,
		MetadataRevision: wire.MetadataRevision, MetadataDocument: append([]byte(nil), wire.MetadataDocument...),
		MetadataDigest: digest, MetadataRetrievedAt: retrievedAt,
		MetadataMaximumValidUntil: maximumValidUntil,
	}, nil
}

func samlAuthenticationFromWire(
	wire samlAuthenticationConfigurationWire,
) (federatedsaml.Configuration, error) {
	provider, binding, err := providerBindingFromWire(wire.Provider, false)
	if err != nil || !validFederatedRevision(wire.ProviderRevision) || !validFederatedRevision(wire.BindingRevision) ||
		!validFederatedRevision(wire.ConfigurationRevision) || !validFederatedRevision(wire.SecurityRevision) ||
		!validFederatedRevision(wire.MappingRevision) || !validFederatedRevision(wire.AuthorizationRevision) ||
		!validFederatedRevision(wire.AssurancePolicyRevision) || !validFederatedRevision(wire.SPKeyRevision) {
		return federatedsaml.Configuration{}, errFederatedAuthPersistence
	}
	return federatedsaml.Configuration{
		Provider: provider, BindingID: binding, ProviderRevision: wire.ProviderRevision,
		BindingRevision: wire.BindingRevision, ConfigurationRevision: wire.ConfigurationRevision,
		SecurityRevision: wire.SecurityRevision, MappingRevision: wire.MappingRevision,
		AuthorizationRevision: wire.AuthorizationRevision, AssurancePolicyRevision: wire.AssurancePolicyRevision,
		SPEntityID: wire.SPEntityID, ACSURL: wire.ACSURL, SPKeyRevision: wire.SPKeyRevision,
		RedirectSignatureAlgorithm: wire.RedirectSignatureAlgorithm, SignaturePolicy: wire.SignaturePolicy,
		EncryptionPolicy:       wire.EncryptionPolicy,
		DecryptionKeyVersions:  append([]uint32(nil), wire.DecryptionKeyVersions...),
		RequestedAuthnContexts: append([]string(nil), wire.RequestedAuthnContexts...),
		Subject:                wire.Subject, Mapping: cloneSAMLAttributeMappingPolicy(wire.Mapping),
		TrustRules: append([]federatedsaml.AuthnContextTrustRule(nil), wire.TrustRules...),
		ClockSkew:  wire.ClockSkew, MaxAuthenticationAge: wire.MaxAuthenticationAge,
	}, nil
}

func cacheMetadataFromWire(wire federatedCacheMetadataWire) (federatedhttp.CacheMetadata, error) {
	retrievedAt, validRetrievedAt := canonicalFederatedDatabaseTimeFromWire(wire.RetrievedAt)
	freshUntil, validFreshUntil := canonicalFederatedDatabaseTimeFromWire(wire.FreshUntil)
	if !validRetrievedAt || !validFreshUntil || freshUntil.Before(retrievedAt) ||
		freshUntil.After(retrievedAt.Add(7*24*time.Hour)) ||
		!wire.Cacheable && (!wire.MustRevalidate || !freshUntil.Equal(retrievedAt)) {
		return federatedhttp.CacheMetadata{}, errFederatedAuthPersistence
	}
	return federatedhttp.CacheMetadata{
		RetrievedAt: retrievedAt, FreshUntil: freshUntil,
		Cacheable: wire.Cacheable, MustRevalidate: wire.MustRevalidate,
	}, nil
}

func signingAlgorithmsFromWire(values []string) []federatedoidc.SigningAlgorithm {
	result := make([]federatedoidc.SigningAlgorithm, len(values))
	for index := range values {
		result[index] = federatedoidc.SigningAlgorithm(values[index])
	}
	return result
}

func cloneOIDCClaimExtractionPolicy(
	value federatedoidc.ClaimExtractionPolicy,
) federatedoidc.ClaimExtractionPolicy {
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

func cloneSAMLAttributeMappingPolicy(value federatedsaml.AttributeMappingPolicy) federatedsaml.AttributeMappingPolicy {
	value.Scalars = append([]federatedsaml.ScalarAttributeRule(nil), value.Scalars...)
	value.Profiles = append([]federatedsaml.ProfileAttributeRule(nil), value.Profiles...)
	if value.Groups != nil {
		copyValue := *value.Groups
		value.Groups = &copyValue
	}
	return value
}

func clearOIDCCallbackLookupWire(value *oidcCallbackConfigurationLookupWire) {
	if value == nil {
		return
	}
	clear(value.TransactionID)
	clearOIDCPinsWire(&value.Pins)
}

func clearSAMLCallbackLookupWire(value *samlCallbackConfigurationLookupWire) {
	if value == nil {
		return
	}
	clear(value.TransactionID)
	clearSAMLPinsWire(&value.Pins)
}

func clearTenantOIDCConfigurationRecordWire(value *tenantOIDCConfigurationRecordWire) {
	if value == nil {
		return
	}
	clear(value.DiscoveryDocument)
	clear(value.DiscoveryDigest)
	clear(value.JWKSDocument)
	clear(value.JWKSDigest)
}

func clearTenantSAMLConfigurationRecordWire(value *tenantSAMLConfigurationRecordWire) {
	if value == nil {
		return
	}
	clear(value.MetadataDocument)
	clear(value.MetadataDigest)
}
