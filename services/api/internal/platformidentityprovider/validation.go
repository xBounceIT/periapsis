package platformidentityprovider

import (
	"crypto/sha256"
	"encoding/json"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
	"github.com/periapsis-im/periapsis/modules/identity/ldapclient"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
)

const (
	defaultPageSize                         = 50
	maximumPageSize                         = 100
	maximumReasonBytes                      = 2 * 1024
	maximumOIDCIssuerBytes                  = 2 * 1024
	maximumFederationEndpointURIBytes       = 4 * 1024
	maximumOIDCClientSecretBytes            = 8 * 1024
	maximumProviderVersion            int64 = 2_147_483_647
	maximumExpectedMutationVersion    int64 = maximumProviderVersion - 1
	maximumProviderRevision           int64 = 9_007_199_254_740_991
)

var (
	providerKeyPattern       = regexp.MustCompile(`^[a-z][a-z0-9_-]{2,63}$`)
	idempotencyKeyPattern    = regexp.MustCompile(`^[A-Za-z0-9._~-]{16,128}$`)
	absoluteURISchemePattern = regexp.MustCompile(`^[a-z][a-z0-9+.-]*:`)
	canonicalDNSHostPattern  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)
	canonicalPortPattern     = regexp.MustCompile(`^[1-9][0-9]{0,4}$`)
	numericIPv4HostPattern   = regexp.MustCompile(`^[0-9.]+$`)
)

func normalizeList(input ListInput) (ListInput, error) {
	if input.Limit == 0 {
		input.Limit = defaultPageSize
	}
	if input.Limit < 1 || input.Limit > maximumPageSize ||
		input.After != nil && !validUUIDv7(*input.After) {
		return ListInput{}, authentication.ErrInvalidInput
	}
	if input.After != nil {
		value := *input.After
		input.After = &value
	}
	return input, nil
}

func normalizeCreate(
	input CreateInput,
	endpoints canonicalEndpointPolicy,
) (CreateInput, ProviderKind, [32]byte, error) {
	input.Key = strings.TrimSpace(input.Key)
	input.DisplayName = strings.TrimSpace(input.DisplayName)
	input.Description = strings.TrimSpace(input.Description)
	input.Reason = strings.TrimSpace(input.Reason)
	configuration, kind, err := normalizeCreateConfiguration(input.Key, input.Configuration, endpoints)
	if err != nil || !providerKeyPattern.MatchString(input.Key) ||
		!validText(input.DisplayName, 1, 120) || !validText(input.Description, 0, 1000) ||
		!validReason(input.Reason) || !idempotencyKeyPattern.MatchString(input.IdempotencyKey) ||
		!validEvent(input.Event) {
		return CreateInput{}, "", [32]byte{}, authentication.ErrInvalidInput
	}
	input.Configuration = configuration
	requestDigest, err := createRequestDigest(input, kind)
	if err != nil {
		return CreateInput{}, "", [32]byte{}, authentication.ErrInvalidInput
	}
	return input, kind, requestDigest, nil
}

func normalizeUpdate(providerID uuid.UUID, input UpdateInput) (UpdateInput, int64, error) {
	version, err := normalizeVersioned(providerID, input.ExpectedEntityTag, input.Event)
	if err != nil {
		return UpdateInput{}, 0, err
	}
	input.Key = strings.TrimSpace(input.Key)
	input.DisplayName = strings.TrimSpace(input.DisplayName)
	input.Description = strings.TrimSpace(input.Description)
	input.Reason = strings.TrimSpace(input.Reason)
	if !providerKeyPattern.MatchString(input.Key) || !validText(input.DisplayName, 1, 120) ||
		!validText(input.Description, 0, 1000) || !validReason(input.Reason) {
		return UpdateInput{}, 0, authentication.ErrInvalidInput
	}
	return input, version, nil
}

func normalizeArchive(providerID uuid.UUID, input ArchiveInput) (ArchiveInput, int64, error) {
	version, err := normalizeVersioned(providerID, input.ExpectedEntityTag, input.Event)
	if err != nil {
		return ArchiveInput{}, 0, err
	}
	input.Reason = strings.TrimSpace(input.Reason)
	if !validReason(input.Reason) {
		return ArchiveInput{}, 0, authentication.ErrInvalidInput
	}
	return input, version, nil
}

func normalizeReplaceOIDCClientSecret(
	providerID uuid.UUID,
	input ReplaceOIDCClientSecretInput,
) (ReplaceOIDCClientSecretInput, int64, error) {
	version, err := normalizeVersioned(providerID, input.ExpectedEntityTag, input.Event)
	if err != nil {
		return ReplaceOIDCClientSecretInput{}, 0, err
	}
	input.Reason = strings.TrimSpace(input.Reason)
	if len(input.Secret) < 1 || len(input.Secret) > maximumOIDCClientSecretBytes || !validReason(input.Reason) {
		return ReplaceOIDCClientSecretInput{}, 0, authentication.ErrInvalidInput
	}
	return input, version, nil
}

func normalizeActivate(
	providerID uuid.UUID,
	input ActivateInput,
) (ActivateInput, int64, error) {
	version, err := normalizeVersioned(providerID, input.ExpectedEntityTag, input.Event)
	if err != nil {
		return ActivateInput{}, 0, err
	}
	input.Reason = strings.TrimSpace(input.Reason)
	if !validEnabledAccountMode(input.AccountMode) || !validReason(input.Reason) {
		return ActivateInput{}, 0, authentication.ErrInvalidInput
	}
	return input, version, nil
}

func normalizeDeactivate(
	providerID uuid.UUID,
	input DeactivateInput,
) (DeactivateInput, int64, error) {
	version, err := normalizeVersioned(providerID, input.ExpectedEntityTag, input.Event)
	if err != nil {
		return DeactivateInput{}, 0, err
	}
	input.Reason = strings.TrimSpace(input.Reason)
	if !validReason(input.Reason) {
		return DeactivateInput{}, 0, authentication.ErrInvalidInput
	}
	return input, version, nil
}

func normalizeDirectLogin(
	providerID uuid.UUID,
	input DirectLoginInput,
) (DirectLoginInput, int64, error) {
	version, err := normalizeVersioned(providerID, input.ExpectedEntityTag, input.Event)
	if err != nil {
		return DirectLoginInput{}, 0, err
	}
	input.Reason = strings.TrimSpace(input.Reason)
	if !validReason(input.Reason) {
		return DirectLoginInput{}, 0, authentication.ErrInvalidInput
	}
	return input, version, nil
}

func normalizeVersioned(
	providerID uuid.UUID,
	entityTag *string,
	event authentication.EventContext,
) (int64, error) {
	if !validUUIDv7(providerID) || !validEvent(event) || entityTag == nil {
		return 0, authentication.ErrInvalidInput
	}
	version, err := parseEntityTag(*entityTag)
	if err != nil || version > maximumExpectedMutationVersion {
		return 0, authentication.ErrInvalidInput
	}
	return version, nil
}

func normalizeCreateConfiguration(
	providerKey string,
	input CreateConfiguration,
	endpoints canonicalEndpointPolicy,
) (CreateConfiguration, ProviderKind, error) {
	switch configuration := input.(type) {
	case LDAPCreateConfiguration:
		normalized, err := normalizeLDAPCreateConfiguration(configuration, false)
		return normalized, ProviderKindLDAP, err
	case OIDCCreateConfiguration:
		normalized, err := normalizeOIDCCreateConfiguration(configuration)
		if err == nil && !endpoints.acceptsOIDC(normalized) {
			err = authentication.ErrInvalidInput
		}
		return normalized, ProviderKindOIDC, err
	case SAMLCreateConfiguration:
		normalized, err := normalizeSAMLCreateConfiguration(configuration)
		if err == nil && !endpoints.acceptsSAML(providerKey, normalized) {
			err = authentication.ErrInvalidInput
		}
		return normalized, ProviderKindSAML, err
	default:
		return nil, "", authentication.ErrInvalidInput
	}
}

func normalizeLDAPCreateConfiguration(
	configuration LDAPCreateConfiguration,
	requireEndpointIDs bool,
) (LDAPCreateConfiguration, error) {
	if len(configuration.Endpoints) < 1 || len(configuration.Endpoints) > 8 {
		return LDAPCreateConfiguration{}, authentication.ErrInvalidInput
	}
	domainEndpoints := make([]identityprovider.Endpoint, len(configuration.Endpoints))
	for index, endpoint := range configuration.Endpoints {
		if requireEndpointIDs && !validUUIDv7(endpoint.ID) ||
			!requireEndpointIDs && endpoint.ID != uuid.Nil {
			return LDAPCreateConfiguration{}, authentication.ErrInvalidInput
		}
		domainEndpoints[index] = identityprovider.Endpoint{
			Priority: endpoint.Priority, Host: endpoint.Host, Port: endpoint.Port,
			Transport: ldapclient.Transport(endpoint.Transport), TLSServerName: endpoint.TLSServerName,
			ReferralAllowed: endpoint.ReferralAllowed, Enabled: endpoint.Enabled,
		}
	}
	canonical, endpoints, err := identityprovider.NormalizeLDAPConfiguration(
		configuration.Configuration,
		domainEndpoints,
	)
	if err != nil || canonical.JITMode != identityprovider.JITModeExistingIdentity ||
		canonical.NoMatchPolicy != identityprovider.NoMatchPolicyDeny {
		return LDAPCreateConfiguration{}, authentication.ErrInvalidInput
	}
	configuration.Configuration = canonical
	for index := range endpoints {
		configuration.Endpoints[index].Priority = endpoints[index].Priority
		configuration.Endpoints[index].Host = endpoints[index].Host
		configuration.Endpoints[index].Port = endpoints[index].Port
		configuration.Endpoints[index].Transport = string(endpoints[index].Transport)
		configuration.Endpoints[index].TLSServerName = endpoints[index].TLSServerName
		configuration.Endpoints[index].ReferralAllowed = endpoints[index].ReferralAllowed
		configuration.Endpoints[index].Enabled = endpoints[index].Enabled
	}
	return configuration, nil
}

func normalizeOIDCCreateConfiguration(
	configuration OIDCCreateConfiguration,
) (OIDCCreateConfiguration, error) {
	configuration.Issuer = strings.TrimSpace(configuration.Issuer)
	if !validHTTPSURL(configuration.Issuer, true, maximumOIDCIssuerBytes) ||
		!validOIDCClientID(configuration.ClientID) ||
		!validHTTPSURL(configuration.RedirectURI, false, maximumFederationEndpointURIBytes) ||
		!validHTTPSURL(configuration.TenantRedirectURI, false, maximumFederationEndpointURIBytes) ||
		!validHTTPSURL(configuration.PostLogoutRedirectURI, false, maximumFederationEndpointURIBytes) {
		return OIDCCreateConfiguration{}, authentication.ErrInvalidInput
	}
	scopes, err := normalizeScopes(configuration.ExtraScopes)
	if err != nil {
		return OIDCCreateConfiguration{}, err
	}
	configuration.ExtraScopes = scopes
	if slices.Contains(scopes, "offline_access") != configuration.AllowRefreshToken {
		return OIDCCreateConfiguration{}, authentication.ErrInvalidInput
	}
	return configuration, nil
}

func normalizeSAMLCreateConfiguration(
	configuration SAMLCreateConfiguration,
) (SAMLCreateConfiguration, error) {
	configuration.ExpectedEntityID = strings.TrimSpace(configuration.ExpectedEntityID)
	var err error
	configuration.SubjectAttributeName, err = normalizeOptionalText(configuration.SubjectAttributeName, 512)
	if err != nil {
		return SAMLCreateConfiguration{}, err
	}
	configuration.SubjectAttributeNameFormat, err = normalizeOptionalText(
		configuration.SubjectAttributeNameFormat, 512,
	)
	if err != nil {
		return SAMLCreateConfiguration{}, err
	}
	if !validAbsoluteURI(configuration.ExpectedEntityID, 2048) ||
		!validAbsoluteURI(configuration.SPEntityID, 2048) ||
		configuration.ExpectedEntityID == configuration.SPEntityID ||
		!validFederationXML10Text(configuration.ExpectedEntityID) ||
		!validHTTPSURL(configuration.ACSURL, false, maximumFederationEndpointURIBytes) ||
		!validRedirectSignatureAlgorithm(configuration.RedirectSignatureAlgorithm) ||
		!validSignaturePolicy(configuration.SignaturePolicy) ||
		!validEncryptionPolicy(configuration.EncryptionPolicy) ||
		configuration.ClockSkew < 0 || configuration.ClockSkew > 5*time.Minute ||
		configuration.MaximumAuthenticationAge < time.Minute ||
		configuration.MaximumAuthenticationAge > 24*time.Hour {
		return SAMLCreateConfiguration{}, authentication.ErrInvalidInput
	}
	keyVersions, err := normalizeKeyVersions(configuration.DecryptionKeyVersions)
	// This expand-only slice has no platform SP-key write boundary. Persisting
	// an encryption policy that cannot be satisfied would create a misleading
	// configuration, even while login remains disabled.
	if err != nil || configuration.EncryptionPolicy != federatedsaml.EncryptionDisabled || len(keyVersions) != 0 {
		return SAMLCreateConfiguration{}, authentication.ErrInvalidInput
	}
	contexts, err := normalizeAuthnContexts(configuration.RequestedAuthnContexts)
	if err != nil {
		return SAMLCreateConfiguration{}, err
	}
	if !validSAMLSubject(configuration) {
		return SAMLCreateConfiguration{}, authentication.ErrInvalidInput
	}
	configuration.DecryptionKeyVersions = keyVersions
	configuration.RequestedAuthnContexts = contexts
	return configuration, nil
}

func normalizeScopes(values []string) ([]string, error) {
	if len(values) > 31 {
		return nil, authentication.ErrInvalidInput
	}
	result := make([]string, len(values))
	seen := make(map[string]struct{}, len(values))
	for index, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "openid" || !validOAuthScope(value) {
			return nil, authentication.ErrInvalidInput
		}
		if _, duplicate := seen[value]; duplicate {
			return nil, authentication.ErrInvalidInput
		}
		seen[value] = struct{}{}
		result[index] = value
	}
	slices.Sort(result)
	return result, nil
}

func validOAuthScope(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, character := range []byte(value) {
		if character <= 0x20 || character >= 0x7f || character == '"' || character == '\\' {
			return false
		}
	}
	return true
}

func normalizeKeyVersions(values []int16) ([]int16, error) {
	if len(values) > 8 {
		return nil, authentication.ErrInvalidInput
	}
	result := make([]int16, len(values))
	copy(result, values)
	slices.Sort(result)
	for index, value := range result {
		if value < 1 || index > 0 && result[index-1] == value {
			return nil, authentication.ErrInvalidInput
		}
	}
	return result, nil
}

func normalizeAuthnContexts(values []string) ([]string, error) {
	if len(values) < 1 || len(values) > 32 {
		return nil, authentication.ErrInvalidInput
	}
	result := make([]string, len(values))
	seen := make(map[string]struct{}, len(values))
	for index, raw := range values {
		value := strings.TrimSpace(raw)
		if !validAbsoluteURI(value, 2048) || !validFederationXML10Text(value) {
			return nil, authentication.ErrInvalidInput
		}
		if _, duplicate := seen[value]; duplicate {
			return nil, authentication.ErrInvalidInput
		}
		seen[value] = struct{}{}
		result[index] = value
	}
	slices.Sort(result)
	return result, nil
}

func validSAMLSubject(configuration SAMLCreateConfiguration) bool {
	switch configuration.SubjectSource {
	case federatedsaml.SubjectPersistentNameID:
		return configuration.SubjectAttributeName == nil && configuration.SubjectAttributeNameFormat == nil
	case federatedsaml.SubjectImmutableAttribute:
		return configuration.SubjectAttributeName != nil && configuration.SubjectAttributeNameFormat != nil &&
			validFederationXML10Text(*configuration.SubjectAttributeName) &&
			validFederationXML10Text(*configuration.SubjectAttributeNameFormat) &&
			validAbsoluteURI(*configuration.SubjectAttributeNameFormat, 512)
	default:
		return false
	}
}

func createRequestDigest(input CreateInput, kind ProviderKind) ([32]byte, error) {
	document := struct {
		Schema        string              `json:"schema"`
		Kind          ProviderKind        `json:"kind"`
		Key           string              `json:"key"`
		DisplayName   string              `json:"displayName"`
		Description   string              `json:"description"`
		Configuration CreateConfiguration `json:"configuration"`
		Reason        string              `json:"reason"`
	}{
		Schema: "periapsis/platform-identity-provider-create/v1", Kind: kind,
		Key: input.Key, DisplayName: input.DisplayName, Description: input.Description,
		Configuration: input.Configuration, Reason: input.Reason,
	}
	encoded, err := json.Marshal(document)
	if err != nil || len(encoded) < 1 || len(encoded) > 64*1024 {
		clear(encoded)
		return [32]byte{}, authentication.ErrInvalidInput
	}
	digest := sha256.Sum256(encoded)
	clear(encoded)
	return digest, nil
}

func validProviderSummary(value ProviderSummary) bool {
	if !validUUIDv7(value.ID) || !providerKeyPattern.MatchString(value.Key) ||
		!validText(value.DisplayName, 1, 120) || !validText(value.Description, 0, 1000) ||
		!validProviderKind(value.Kind) || !value.Configured ||
		!validResourceVersion(value.Version) || !validInstant(value.CreatedAt) || !validInstant(value.UpdatedAt) ||
		value.UpdatedAt.Before(value.CreatedAt) {
		return false
	}
	if value.PlatformLoginEnabled && (!value.Enabled || !value.SecretPresent || value.ArchivedAt != nil) {
		return false
	}
	if value.Kind == ProviderKindLDAP {
		if value.PlatformLoginEnabled != value.Enabled || value.ActivationAvailable ||
			value.PlatformLoginActivationAvailable &&
				(value.Enabled || !value.Configured || !value.SecretPresent || value.ArchivedAt != nil) {
			return false
		}
	} else if value.PlatformLoginActivationAvailable && (!value.Enabled ||
		value.PlatformLoginEnabled || !value.Configured || !value.SecretPresent || value.ArchivedAt != nil) {
		return false
	}
	if value.ActivationAvailable && (value.Enabled || !value.SecretPresent || value.ArchivedAt != nil) {
		return false
	}
	if value.ArchivedAt != nil && (!validInstant(*value.ArchivedAt) || value.ArchivedAt.Before(value.CreatedAt) ||
		value.UpdatedAt.Before(*value.ArchivedAt) || value.Enabled || value.PlatformLoginActivationAvailable ||
		value.ActivationAvailable) {
		return false
	}
	return true
}

func validProvider(value Provider, endpoints canonicalEndpointPolicy) bool {
	if !validProviderSummary(value.ProviderSummary) || !validProviderRevision(value.ConfigurationRevision) ||
		!validProviderRevision(value.SecurityRevision) || !validProviderRevision(value.PlanRevision) ||
		!validProviderRevision(value.AssurancePolicyRevision) ||
		(value.Enabled && !validEnabledAccountMode(value.AccountMode)) ||
		(!value.Enabled && value.AccountMode != AccountModeDisabled) {
		return false
	}
	switch value.Kind {
	case ProviderKindLDAP:
		return value.LDAP != nil && value.OIDC == nil && value.SAML == nil &&
			validLDAPConfiguration(*value.LDAP) &&
			(!value.Enabled || value.AccountMode == AccountModeExistingIdentity)
	case ProviderKindOIDC:
		return value.LDAP == nil && value.OIDC != nil && value.SAML == nil && validOIDCConfiguration(*value.OIDC, endpoints) &&
			value.SecretPresent == value.OIDC.ClientSecretPresent &&
			(!value.PlatformLoginEnabled || !value.OIDC.UseUserInfo)
	case ProviderKindSAML:
		return value.LDAP == nil && value.SAML != nil && value.OIDC == nil &&
			validSAMLConfiguration(value.Key, *value.SAML, endpoints) &&
			value.SecretPresent == value.SAML.SPKeyPresent
	default:
		return false
	}
}

func initialProviderProjection(value Provider) bool {
	return value.Version == 1 && value.ArchivedAt == nil && !value.Enabled &&
		!value.PlatformLoginEnabled && !value.PlatformLoginActivationAvailable && !value.ActivationAvailable &&
		value.AccountMode == AccountModeDisabled && !value.SecretPresent &&
		value.ConfigurationRevision == 1 && value.SecurityRevision == 1 && value.PlanRevision == 1 &&
		value.AssurancePolicyRevision == 1 && value.CreatedAt.Equal(value.UpdatedAt) &&
		(value.LDAP == nil || len(value.LDAP.Mappings) == 0) &&
		(value.OIDC == nil || !value.OIDC.ClientSecretPresent && value.OIDC.ClientSecretRevision == 1 &&
			value.OIDC.DiscoveryRevision == 1 && value.OIDC.JWKSRevision == 1) &&
		(value.SAML == nil || !value.SAML.SPKeyPresent && value.SAML.SPKeyRevision == 1 &&
			value.SAML.MetadataRevision == 1)
}

func providerMatchesCreateConfiguration(value Provider, raw CreateConfiguration) bool {
	switch configuration := raw.(type) {
	case LDAPCreateConfiguration:
		return value.LDAP != nil && value.OIDC == nil && value.SAML == nil &&
			ldapConfigurationsEqual(value.LDAP.Configuration, configuration.Configuration) &&
			ldapEndpointsEqual(value.LDAP.Endpoints, configuration.Endpoints, false)
	case OIDCCreateConfiguration:
		return value.OIDC != nil && value.SAML == nil &&
			value.OIDC.Issuer == configuration.Issuer && value.OIDC.ClientID == configuration.ClientID &&
			value.OIDC.RedirectURI == configuration.RedirectURI &&
			value.OIDC.TenantRedirectURI == configuration.TenantRedirectURI &&
			value.OIDC.PostLogoutRedirectURI == configuration.PostLogoutRedirectURI &&
			slices.Equal(value.OIDC.ExtraScopes, configuration.ExtraScopes) &&
			value.OIDC.AllowRefreshToken == configuration.AllowRefreshToken &&
			value.OIDC.UseUserInfo == configuration.UseUserInfo
	case SAMLCreateConfiguration:
		return value.SAML != nil && value.OIDC == nil &&
			value.SAML.ExpectedEntityID == configuration.ExpectedEntityID &&
			value.SAML.SPEntityID == configuration.SPEntityID && value.SAML.ACSURL == configuration.ACSURL &&
			value.SAML.RedirectSignatureAlgorithm == configuration.RedirectSignatureAlgorithm &&
			value.SAML.SignaturePolicy == configuration.SignaturePolicy &&
			value.SAML.EncryptionPolicy == configuration.EncryptionPolicy &&
			slices.Equal(value.SAML.RequestedAuthnContexts, configuration.RequestedAuthnContexts) &&
			value.SAML.SubjectSource == configuration.SubjectSource &&
			optionalStringsEqual(value.SAML.SubjectAttributeName, configuration.SubjectAttributeName) &&
			optionalStringsEqual(value.SAML.SubjectAttributeNameFormat, configuration.SubjectAttributeNameFormat) &&
			value.SAML.ClockSkew == configuration.ClockSkew &&
			value.SAML.MaximumAuthenticationAge == configuration.MaximumAuthenticationAge
	default:
		return false
	}
}

func validLDAPConfiguration(value LDAPConfiguration) bool {
	create := LDAPCreateConfiguration{
		Configuration: value.Configuration,
		Endpoints:     cloneLDAPEndpoints(value.Endpoints),
	}
	if _, err := normalizeLDAPCreateConfiguration(create, true); err != nil || value.Mappings == nil {
		return false
	}
	for _, mapping := range value.Mappings {
		if !validUUIDv7(mapping.ID) || !validUUIDv7(mapping.PlatformRoleID) ||
			(mapping.MatcherType != identityprovider.MappingMatcherExactDN &&
				mapping.MatcherType != identityprovider.MappingMatcherExactCN &&
				mapping.MatcherType != identityprovider.MappingMatcherRegex) ||
			(mapping.ReconciliationMode != identityprovider.ReconciliationAdditive &&
				mapping.ReconciliationMode != identityprovider.ReconciliationAuthoritative) ||
			!validResourceVersion(mapping.Version) || !validText(mapping.MatcherValue, 1, 2048) ||
			!validText(mapping.Notes, 0, 1000) || mapping.Priority < 0 || mapping.Priority > 1_000_000 {
			return false
		}
	}
	return true
}

func ldapConfigurationsEqual(left, right identityprovider.Configuration) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	equal := leftErr == nil && rightErr == nil && slices.Equal(leftJSON, rightJSON)
	clear(leftJSON)
	clear(rightJSON)
	return equal
}

func ldapEndpointsEqual(left, right []LDAPEndpoint, compareIDs bool) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if compareIDs && left[index].ID != right[index].ID ||
			left[index].Priority != right[index].Priority || left[index].Host != right[index].Host ||
			left[index].Port != right[index].Port || left[index].Transport != right[index].Transport ||
			left[index].TLSServerName != right[index].TLSServerName ||
			left[index].ReferralAllowed != right[index].ReferralAllowed || left[index].Enabled != right[index].Enabled {
			return false
		}
	}
	return true
}

func optionalStringsEqual(left, right *string) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func validOIDCConfiguration(value OIDCConfiguration, endpoints canonicalEndpointPolicy) bool {
	normalized, err := normalizeOIDCCreateConfiguration(OIDCCreateConfiguration{
		Issuer: value.Issuer, ClientID: value.ClientID, RedirectURI: value.RedirectURI,
		TenantRedirectURI:     value.TenantRedirectURI,
		PostLogoutRedirectURI: value.PostLogoutRedirectURI, ExtraScopes: value.ExtraScopes,
		AllowRefreshToken: value.AllowRefreshToken, UseUserInfo: value.UseUserInfo,
	})
	return err == nil && value.ExtraScopes != nil && endpoints.acceptsOIDC(normalized) &&
		slices.Equal(normalized.ExtraScopes, value.ExtraScopes) &&
		validProviderRevision(value.ClientSecretRevision) &&
		validProviderRevision(value.DiscoveryRevision) && validProviderRevision(value.JWKSRevision) &&
		(!value.ClientSecretPresent || value.ClientSecretRevision >= 2)
}

func validOIDCClientID(value string) bool {
	if len(value) < 1 || len(value) > 512 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsSpace(character) || unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validFederationXML10Text(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character != '\t' && character != '\n' && character != '\r' &&
			(character < 0x20 || character > 0xd7ff && character < 0xe000 ||
				character > 0xfffd && character < 0x10000 || character > utf8.MaxRune) {
			return false
		}
	}
	return true
}

func validEnabledAccountMode(value AccountMode) bool {
	return value == AccountModeExistingIdentity || value == AccountModeCreate
}

func validSAMLConfiguration(
	providerKey string,
	value SAMLConfiguration,
	endpoints canonicalEndpointPolicy,
) bool {
	if !validAbsoluteURI(value.ExpectedEntityID, 2048) || !validAbsoluteURI(value.SPEntityID, 2048) ||
		value.ExpectedEntityID == value.SPEntityID || !validFederationXML10Text(value.ExpectedEntityID) ||
		!validHTTPSURL(value.ACSURL, false, maximumFederationEndpointURIBytes) ||
		!validProviderRevision(value.SPKeyRevision) ||
		!validProviderRevision(value.MetadataRevision) || !validRedirectSignatureAlgorithm(value.RedirectSignatureAlgorithm) ||
		!validSignaturePolicy(value.SignaturePolicy) || value.EncryptionPolicy != federatedsaml.EncryptionDisabled ||
		value.SPKeyPresent && value.SPKeyRevision < 2 ||
		value.ClockSkew < 0 || value.ClockSkew > 5*time.Minute ||
		value.MaximumAuthenticationAge < time.Minute || value.MaximumAuthenticationAge > 24*time.Hour {
		return false
	}
	if !endpoints.acceptsSAML(
		providerKey,
		SAMLCreateConfiguration{SPEntityID: value.SPEntityID, ACSURL: value.ACSURL},
	) {
		return false
	}
	contexts, err := normalizeAuthnContexts(value.RequestedAuthnContexts)
	if err != nil || !slices.Equal(contexts, value.RequestedAuthnContexts) {
		return false
	}
	subject := SAMLCreateConfiguration{
		SubjectSource: value.SubjectSource, SubjectAttributeName: value.SubjectAttributeName,
		SubjectAttributeNameFormat: value.SubjectAttributeNameFormat,
	}
	if !validSAMLSubject(subject) {
		return false
	}
	if subject.SubjectSource == federatedsaml.SubjectImmutableAttribute {
		return validCanonicalTextBytes(*subject.SubjectAttributeName, 1, 512) &&
			validFederationXML10Text(*subject.SubjectAttributeName) &&
			validFederationXML10Text(*subject.SubjectAttributeNameFormat) &&
			validAbsoluteURI(*subject.SubjectAttributeNameFormat, 512)
	}
	return true
}

func cloneProvider(value Provider) Provider {
	value.ProviderSummary = cloneProviderSummary(value.ProviderSummary)
	if value.OIDC != nil {
		configuration := *value.OIDC
		configuration.ExtraScopes = cloneSlice(value.OIDC.ExtraScopes)
		value.OIDC = &configuration
	}
	if value.LDAP != nil {
		configuration := *value.LDAP
		configuration.Configuration = cloneLDAPDomainConfiguration(value.LDAP.Configuration)
		configuration.Endpoints = cloneLDAPEndpoints(value.LDAP.Endpoints)
		configuration.Mappings = cloneLDAPMappings(value.LDAP.Mappings)
		value.LDAP = &configuration
	}
	if value.SAML != nil {
		configuration := *value.SAML
		configuration.RequestedAuthnContexts = cloneSlice(value.SAML.RequestedAuthnContexts)
		configuration.SubjectAttributeName = cloneString(value.SAML.SubjectAttributeName)
		configuration.SubjectAttributeNameFormat = cloneString(value.SAML.SubjectAttributeNameFormat)
		value.SAML = &configuration
	}
	return value
}

func cloneProviderSummary(value ProviderSummary) ProviderSummary {
	if value.ArchivedAt != nil {
		archivedAt := *value.ArchivedAt
		value.ArchivedAt = &archivedAt
	}
	return value
}

func cloneCreateConfiguration(value CreateConfiguration) CreateConfiguration {
	switch configuration := value.(type) {
	case LDAPCreateConfiguration:
		configuration.Configuration = cloneLDAPDomainConfiguration(configuration.Configuration)
		configuration.Endpoints = cloneLDAPEndpoints(configuration.Endpoints)
		return configuration
	case OIDCCreateConfiguration:
		configuration.ExtraScopes = cloneSlice(configuration.ExtraScopes)
		return configuration
	case SAMLCreateConfiguration:
		configuration.DecryptionKeyVersions = cloneSlice(configuration.DecryptionKeyVersions)
		configuration.RequestedAuthnContexts = cloneSlice(configuration.RequestedAuthnContexts)
		configuration.SubjectAttributeName = cloneString(configuration.SubjectAttributeName)
		configuration.SubjectAttributeNameFormat = cloneString(configuration.SubjectAttributeNameFormat)
		return configuration
	default:
		return nil
	}
}

func validProviderKind(value ProviderKind) bool {
	return value == ProviderKindLDAP || value == ProviderKindOIDC || value == ProviderKindSAML
}

func cloneLDAPDomainConfiguration(value identityprovider.Configuration) identityprovider.Configuration {
	value.CustomCAPEM = cloneString(value.CustomCAPEM)
	value.GroupBaseDN = cloneString(value.GroupBaseDN)
	value.GroupSearchFilter = cloneString(value.GroupSearchFilter)
	value.UserDNTemplate = cloneString(value.UserDNTemplate)
	value.AlternateUsernameAttribute = cloneString(value.AlternateUsernameAttribute)
	value.EmailAttribute = cloneString(value.EmailAttribute)
	value.GroupMembershipAttribute = cloneString(value.GroupMembershipAttribute)
	value.POSIXMemberUIDAttribute = cloneString(value.POSIXMemberUIDAttribute)
	value.POSIXGIDNumberAttribute = cloneString(value.POSIXGIDNumberAttribute)
	value.AccountStatusAttribute = cloneString(value.AccountStatusAttribute)
	value.AccountDisabledValue = cloneString(value.AccountDisabledValue)
	if value.SyncIntervalSeconds != nil {
		interval := *value.SyncIntervalSeconds
		value.SyncIntervalSeconds = &interval
	}
	return value
}

func cloneLDAPEndpoints(values []LDAPEndpoint) []LDAPEndpoint { return cloneSlice(values) }

func cloneLDAPMappings(values []LDAPMapping) []LDAPMapping {
	result := cloneSlice(values)
	for index := range result {
		if result[index].LastMatchedAt != nil {
			value := *result[index].LastMatchedAt
			result[index].LastMatchedAt = &value
		}
		if result[index].ArchivedAt != nil {
			value := *result[index].ArchivedAt
			result[index].ArchivedAt = &value
		}
	}
	return result
}

func validRedirectSignatureAlgorithm(value federatedsaml.RedirectSignatureAlgorithm) bool {
	switch value {
	case federatedsaml.RedirectRSASHA256, federatedsaml.RedirectRSASHA384, federatedsaml.RedirectRSASHA512,
		federatedsaml.RedirectECDSASHA256, federatedsaml.RedirectECDSASHA384, federatedsaml.RedirectECDSASHA512:
		return true
	default:
		return false
	}
}

func validSignaturePolicy(value federatedsaml.SignaturePolicy) bool {
	return value == federatedsaml.SignedAssertion || value == federatedsaml.SignedResponse || value == federatedsaml.SignedBoth
}

func validEncryptionPolicy(value federatedsaml.EncryptionPolicy) bool {
	return value == federatedsaml.EncryptionDisabled || value == federatedsaml.EncryptionOptional ||
		value == federatedsaml.EncryptionRequired
}

func validSession(session authentication.Session) bool {
	return validUUIDv7(session.User.ID) && validUUIDv7(session.ID) && validAuthenticationMethod(session.AuthenticationMethod)
}

func validAuthenticationMethod(value string) bool {
	switch value {
	case "bootstrap_totp", "ldap", "oidc", "passkey", "recovery_code", "saml", "totp":
		return true
	default:
		return false
	}
}

func validEvent(value authentication.EventContext) bool {
	if !validUUIDv7(value.RequestID) || !validUUIDv7(value.CorrelationID) ||
		!value.RemoteAddress.IsValid() || value.RemoteAddress.Zone() != "" ||
		len(value.UserAgent) < 1 || len(value.UserAgent) > 512 || !utf8.ValidString(value.UserAgent) {
		return false
	}
	for _, character := range value.UserAgent {
		if unicode.IsControl(character) || unicode.In(character, unicode.Cf) {
			return false
		}
	}
	return true
}

func validReason(value string) bool {
	return validCanonicalTextBytes(value, 1, maximumReasonBytes)
}

func validText(value string, minimum, maximum int) bool {
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) < minimum ||
		utf8.RuneCountInString(value) > maximum || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.In(character, unicode.Cf) {
			return false
		}
	}
	return true
}

func validCanonicalTextBytes(value string, minimum, maximum int) bool {
	return len(value) >= minimum && len(value) <= maximum && validText(value, 0, maximum)
}

func normalizeOptionalText(value *string, maximumBytes int) (*string, error) {
	if value == nil {
		return nil, nil
	}
	normalized := strings.TrimSpace(*value)
	if !validCanonicalTextBytes(normalized, 1, maximumBytes) {
		return nil, authentication.ErrInvalidInput
	}
	return &normalized, nil
}

func validHTTPSURL(value string, noQuery bool, maximumBytes int) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil &&
		parsed.Fragment == "" && (!noQuery || parsed.RawQuery == "") && parsed.String() == value &&
		validCanonicalURIText(value, maximumBytes) && validCanonicalHTTPSAuthority(parsed.Host)
}

func validAbsoluteURI(value string, maximumBytes int) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.IsAbs() && absoluteURISchemePattern.MatchString(value) &&
		parsed.String() == value && validCanonicalURIText(value, maximumBytes)
}

func validCanonicalURIText(value string, maximumBytes int) bool {
	return validCanonicalTextBytes(value, 1, maximumBytes) &&
		!strings.Contains(value, `\`) && strings.IndexFunc(value, unicode.IsSpace) < 0
}

func validCanonicalHTTPSAuthority(authority string) bool {
	var hostValue, portValue string
	if strings.HasPrefix(authority, "[") {
		closingBracket := strings.IndexByte(authority, ']')
		if closingBracket <= 1 {
			return false
		}
		hostValue = authority[1:closingBracket]
		tail := authority[closingBracket+1:]
		if tail != "" {
			if !strings.HasPrefix(tail, ":") {
				return false
			}
			portValue = tail[1:]
		}
		address, err := netip.ParseAddr(hostValue)
		if err != nil || !address.Is6() || address.String() != hostValue {
			return false
		}
	} else {
		if strings.Count(authority, ":") > 1 {
			return false
		}
		hostValue = authority
		if separator := strings.LastIndexByte(authority, ':'); separator >= 0 {
			hostValue, portValue = authority[:separator], authority[separator+1:]
		}
		if hostValue != strings.ToLower(hostValue) || len(hostValue) > 253 {
			return false
		}
		if numericIPv4HostPattern.MatchString(hostValue) {
			address, err := netip.ParseAddr(hostValue)
			if err != nil || !address.Is4() || address.String() != hostValue {
				return false
			}
		} else if !canonicalDNSHostPattern.MatchString(hostValue) {
			return false
		}
	}
	if portValue == "" {
		return !strings.HasSuffix(authority, ":")
	}
	port, err := strconv.Atoi(portValue)
	return err == nil && canonicalPortPattern.MatchString(portValue) && port <= 65_535
}

func asciiAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}

func bytesContains(values string, candidate byte) bool {
	return strings.IndexByte(values, candidate) >= 0
}

func validUUIDv7(value uuid.UUID) bool {
	return value != uuid.Nil && value.Version() == 7 && value.Variant() == uuid.RFC4122
}

func validResourceVersion(value int64) bool {
	return value > 0 && value <= maximumProviderVersion
}

func validProviderRevision(value int64) bool {
	return value > 0 && value <= maximumProviderRevision
}

func validInstant(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Year() >= 1970 && value.Year() <= 9999 &&
		value.Nanosecond()%1_000 == 0
}

func cloneString(value *string) *string {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneSlice[T any](value []T) []T {
	if value == nil {
		return nil
	}
	cloned := make([]T, len(value))
	copy(cloned, value)
	return cloned
}
