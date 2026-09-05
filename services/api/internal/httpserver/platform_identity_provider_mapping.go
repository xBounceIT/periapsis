package httpserver

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
	"github.com/periapsis-im/periapsis/services/api/internal/platformidentityprovider"
)

func platformAuthProviderCreateInput(
	value contract.PlatformAuthProviderCreateRequest,
) (platformidentityprovider.CreateInput, error) {
	discriminator, err := value.Discriminator()
	if err != nil {
		return platformidentityprovider.CreateInput{}, err
	}
	switch discriminator {
	case "ldap":
		arm, err := value.AsPlatformLDAPAuthProviderCreateRequest()
		if err != nil || !arm.Kind.Valid() {
			return platformidentityprovider.CreateInput{}, errors.New("invalid platform LDAP create request")
		}
		configuration, err := platformLDAPConfigurationInput(arm.Configuration)
		if err != nil {
			return platformidentityprovider.CreateInput{}, err
		}
		domainEndpoints, err := tenantLDAPEndpointsInput(arm.Endpoints)
		if err != nil {
			return platformidentityprovider.CreateInput{}, err
		}
		endpoints := make([]platformidentityprovider.LDAPEndpoint, len(domainEndpoints))
		for index, endpoint := range domainEndpoints {
			endpoints[index] = platformidentityprovider.LDAPEndpoint{
				Priority: endpoint.Priority, Host: endpoint.Host, Port: endpoint.Port,
				Transport: string(endpoint.Transport), TLSServerName: endpoint.TLSServerName,
				ReferralAllowed: endpoint.ReferralAllowed, Enabled: endpoint.Enabled,
			}
		}
		description := ""
		if arm.Description != nil {
			description = *arm.Description
		}
		return platformidentityprovider.CreateInput{
			Key: arm.Key, DisplayName: arm.DisplayName, Description: description,
			Configuration: platformidentityprovider.LDAPCreateConfiguration{
				Configuration: configuration, Endpoints: endpoints,
			},
		}, nil
	case "oidc":
		arm, err := value.AsPlatformOIDCAuthProviderCreateRequest()
		if err != nil || !arm.Kind.Valid() {
			return platformidentityprovider.CreateInput{}, errors.New("invalid platform OIDC create request")
		}
		description := ""
		if arm.Description != nil {
			description = *arm.Description
		}
		return platformidentityprovider.CreateInput{
			Key: arm.Key, DisplayName: arm.DisplayName, Description: description,
			Configuration: platformidentityprovider.OIDCCreateConfiguration{
				Issuer: arm.Configuration.Issuer, ClientID: arm.Configuration.ClientId,
				RedirectURI:           arm.Configuration.RedirectUri,
				TenantRedirectURI:     arm.Configuration.TenantRedirectUri,
				PostLogoutRedirectURI: arm.Configuration.PostLogoutRedirectUri,
				ExtraScopes:           append([]string(nil), arm.Configuration.ExtraScopes...),
				AllowRefreshToken:     arm.Configuration.AllowRefreshToken,
				UseUserInfo:           arm.Configuration.UseUserInfo,
			},
		}, nil
	case "saml":
		arm, err := value.AsPlatformSAMLAuthProviderCreateRequest()
		if err != nil || !arm.Kind.Valid() {
			return platformidentityprovider.CreateInput{}, errors.New("invalid platform SAML create request")
		}
		configuration, err := platformSAMLAuthProviderCreateConfiguration(arm.Configuration)
		if err != nil {
			return platformidentityprovider.CreateInput{}, err
		}
		description := ""
		if arm.Description != nil {
			description = *arm.Description
		}
		return platformidentityprovider.CreateInput{
			Key: arm.Key, DisplayName: arm.DisplayName, Description: description,
			Configuration: configuration,
		}, nil
	default:
		return platformidentityprovider.CreateInput{}, errors.New("unsupported platform provider kind")
	}
}

func platformLDAPConfigurationInput(
	value contract.PlatformLDAPAuthProviderCreateConfiguration,
) (identityprovider.Configuration, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return identityprovider.Configuration{}, errors.New("invalid platform LDAP configuration")
	}
	defer clear(encoded)
	var tenant contract.TenantLDAPAuthProviderConfiguration
	if err := json.Unmarshal(encoded, &tenant); err != nil {
		return identityprovider.Configuration{}, errors.New("invalid platform LDAP configuration")
	}
	configuration, err := tenantLDAPConfigurationInput(tenant)
	if err != nil || configuration.JITMode != identityprovider.JITModeExistingIdentity ||
		configuration.NoMatchPolicy != identityprovider.NoMatchPolicyDeny {
		return identityprovider.Configuration{}, errors.New("invalid platform LDAP policy")
	}
	return configuration, nil
}

func platformSAMLAuthProviderCreateConfiguration(
	value contract.PlatformSAMLAuthProviderCreateConfiguration,
) (platformidentityprovider.SAMLCreateConfiguration, error) {
	discriminator, err := value.Discriminator()
	if err != nil {
		return platformidentityprovider.SAMLCreateConfiguration{}, errors.New("invalid platform SAML subject source")
	}
	switch discriminator {
	case "persistent_nameid":
		configuration, err := value.AsPlatformSAMLPersistentNameIDAuthProviderCreateConfiguration()
		if err != nil || !configuration.RedirectSignatureAlgorithm.Valid() ||
			!configuration.SignaturePolicy.Valid() || !configuration.EncryptionPolicy.Valid() ||
			configuration.EncryptionPolicy !=
				contract.PlatformSAMLPersistentNameIDAuthProviderCreateConfigurationEncryptionPolicyDisabled ||
			!configuration.SubjectSource.Valid() {
			return platformidentityprovider.SAMLCreateConfiguration{}, errors.New("invalid persistent NameID SAML configuration")
		}
		return platformidentityprovider.SAMLCreateConfiguration{
			ExpectedEntityID: configuration.ExpectedEntityId,
			SPEntityID:       configuration.SpEntityId,
			ACSURL:           configuration.AcsUrl,
			RedirectSignatureAlgorithm: federatedsaml.RedirectSignatureAlgorithm(
				configuration.RedirectSignatureAlgorithm,
			),
			SignaturePolicy:          federatedsaml.SignaturePolicy(configuration.SignaturePolicy),
			EncryptionPolicy:         federatedsaml.EncryptionPolicy(configuration.EncryptionPolicy),
			DecryptionKeyVersions:    []int16{},
			RequestedAuthnContexts:   append([]string(nil), configuration.RequestedAuthnContexts...),
			SubjectSource:            federatedsaml.SubjectPersistentNameID,
			ClockSkew:                time.Duration(configuration.ClockSkewNanoseconds),
			MaximumAuthenticationAge: time.Duration(configuration.MaxAuthenticationAgeNanoseconds),
		}, nil
	case "immutable_attribute":
		configuration, err := value.AsPlatformSAMLImmutableAttributeAuthProviderCreateConfiguration()
		if err != nil || !configuration.RedirectSignatureAlgorithm.Valid() ||
			!configuration.SignaturePolicy.Valid() || !configuration.EncryptionPolicy.Valid() ||
			configuration.EncryptionPolicy !=
				contract.PlatformSAMLImmutableAttributeAuthProviderCreateConfigurationEncryptionPolicyDisabled ||
			!configuration.SubjectSource.Valid() {
			return platformidentityprovider.SAMLCreateConfiguration{}, errors.New("invalid immutable-attribute SAML configuration")
		}
		subjectAttributeName := configuration.SubjectAttributeName
		subjectAttributeNameFormat := configuration.SubjectAttributeNameFormat
		return platformidentityprovider.SAMLCreateConfiguration{
			ExpectedEntityID: configuration.ExpectedEntityId,
			SPEntityID:       configuration.SpEntityId,
			ACSURL:           configuration.AcsUrl,
			RedirectSignatureAlgorithm: federatedsaml.RedirectSignatureAlgorithm(
				configuration.RedirectSignatureAlgorithm,
			),
			SignaturePolicy:            federatedsaml.SignaturePolicy(configuration.SignaturePolicy),
			EncryptionPolicy:           federatedsaml.EncryptionPolicy(configuration.EncryptionPolicy),
			DecryptionKeyVersions:      []int16{},
			RequestedAuthnContexts:     append([]string(nil), configuration.RequestedAuthnContexts...),
			SubjectSource:              federatedsaml.SubjectImmutableAttribute,
			SubjectAttributeName:       &subjectAttributeName,
			SubjectAttributeNameFormat: &subjectAttributeNameFormat,
			ClockSkew:                  time.Duration(configuration.ClockSkewNanoseconds),
			MaximumAuthenticationAge:   time.Duration(configuration.MaxAuthenticationAgeNanoseconds),
		}, nil
	default:
		return platformidentityprovider.SAMLCreateConfiguration{}, errors.New("unsupported platform SAML subject source")
	}
}

func mapPlatformAuthProviderPage(
	value platformidentityprovider.ProviderPage,
) (contract.PlatformAuthProviderList, error) {
	items := make([]contract.PlatformAuthProviderSummary, len(value.Items))
	for index := range value.Items {
		mapped, err := mapPlatformAuthProviderSummary(value.Items[index])
		if err != nil {
			return contract.PlatformAuthProviderList{}, err
		}
		items[index] = mapped
	}
	return contract.PlatformAuthProviderList{Items: items, NextCursor: value.NextCursor}, nil
}

func mapPlatformAuthProviderSummary(
	value platformidentityprovider.ProviderSummary,
) (contract.PlatformAuthProviderSummary, error) {
	kind := contract.PlatformAuthProviderKind(value.Kind)
	if !kind.Valid() || !value.Configured ||
		value.PlatformLoginEnabled && (!value.Enabled || !value.SecretPresent || value.ArchivedAt != nil) ||
		value.PlatformLoginActivationAvailable &&
			(!value.Enabled || value.PlatformLoginEnabled || !value.SecretPresent || value.ArchivedAt != nil) ||
		value.ActivationAvailable && (value.Enabled || !value.SecretPresent || value.ArchivedAt != nil) ||
		value.ArchivedAt != nil && (value.Enabled || value.PlatformLoginEnabled ||
			value.PlatformLoginActivationAvailable || value.ActivationAvailable) {
		return contract.PlatformAuthProviderSummary{}, errors.New("invalid platform provider summary")
	}
	return contract.PlatformAuthProviderSummary{
		Id: value.ID, Key: value.Key, DisplayName: value.DisplayName, Description: value.Description,
		Kind: kind, Enabled: value.Enabled,
		PlatformLoginEnabled:             value.PlatformLoginEnabled,
		PlatformLoginActivationAvailable: value.PlatformLoginActivationAvailable,
		ActivationAvailable:              value.ActivationAvailable,
		Configured:                       value.Configured, SecretPresent: value.SecretPresent,
		ArchivedAt: utcTimePointer(value.ArchivedAt), Version: contract.ResourceVersion(value.Version),
		CreatedAt: value.CreatedAt.UTC(), UpdatedAt: value.UpdatedAt.UTC(),
	}, nil
}

func mapPlatformAuthProvider(
	value platformidentityprovider.Provider,
) (contract.PlatformAuthProvider, error) {
	summary, err := mapPlatformAuthProviderSummary(value.ProviderSummary)
	if err != nil {
		return contract.PlatformAuthProvider{}, errors.New("invalid platform provider detail")
	}
	switch value.Kind {
	case platformidentityprovider.ProviderKindLDAP:
		if value.LDAP == nil || value.OIDC != nil || value.SAML != nil {
			return contract.PlatformAuthProvider{}, errors.New("invalid platform LDAP provider detail")
		}
		configuration, err := mapPlatformLDAPConfiguration(value.LDAP.Configuration)
		if err != nil {
			return contract.PlatformAuthProvider{}, err
		}
		endpoints := make([]contract.PlatformLDAPAuthProviderEndpoint, len(value.LDAP.Endpoints))
		for index, endpoint := range value.LDAP.Endpoints {
			transport := contract.PlatformLDAPAuthProviderEndpointTransport(endpoint.Transport)
			if !transport.Valid() {
				return contract.PlatformAuthProvider{}, errors.New("invalid platform LDAP endpoint")
			}
			endpoints[index] = contract.PlatformLDAPAuthProviderEndpoint{
				Id: endpoint.ID, Priority: endpoint.Priority, Host: endpoint.Host, Port: int(endpoint.Port),
				Transport: transport, TlsServerName: endpoint.TLSServerName,
				ReferralAllowed: endpoint.ReferralAllowed, Enabled: endpoint.Enabled,
			}
		}
		mappings := make([]contract.PlatformLDAPMapping, len(value.LDAP.Mappings))
		for index, mapping := range value.LDAP.Mappings {
			matcherType := contract.PlatformLDAPMappingMatcherType(mapping.MatcherType)
			reconciliationMode := contract.PlatformLDAPMappingReconciliationMode(mapping.ReconciliationMode)
			if !matcherType.Valid() || !reconciliationMode.Valid() {
				return contract.PlatformAuthProvider{}, errors.New("invalid platform LDAP mapping")
			}
			mappings[index] = contract.PlatformLDAPMapping{
				Id: mapping.ID, MatcherType: matcherType, MatcherValue: mapping.MatcherValue,
				CaseSensitive: mapping.CaseSensitive, Priority: mapping.Priority,
				PlatformRoleId: mapping.PlatformRoleID, ReconciliationMode: reconciliationMode,
				Enabled: mapping.Enabled, Notes: mapping.Notes,
				LastMatchedAt: utcTimePointer(mapping.LastMatchedAt), Version: contract.ResourceVersion(mapping.Version),
				ArchivedAt: utcTimePointer(mapping.ArchivedAt),
			}
		}
		accountMode := contract.PlatformLDAPAuthProviderAccountMode(value.AccountMode)
		if !accountMode.Valid() {
			return contract.PlatformAuthProvider{}, errors.New("invalid platform LDAP account mode")
		}
		mapped := contract.PlatformLDAPAuthProvider{
			Id: summary.Id, Key: summary.Key, DisplayName: summary.DisplayName,
			Description: summary.Description, Kind: contract.PlatformLDAPAuthProviderKindLdap,
			Enabled: value.Enabled, PlatformLoginEnabled: value.PlatformLoginEnabled,
			PlatformLoginActivationAvailable: value.PlatformLoginActivationAvailable,
			ActivationAvailable:              contract.PlatformLDAPAuthProviderActivationAvailable(false),
			Configured:                       contract.PlatformLDAPAuthProviderConfigured(value.Configured),
			SecretPresent:                    value.SecretPresent, ArchivedAt: summary.ArchivedAt,
			Version: summary.Version, CreatedAt: summary.CreatedAt, UpdatedAt: summary.UpdatedAt,
			ConfigurationRevision: value.ConfigurationRevision, SecurityRevision: value.SecurityRevision,
			PlanRevision: value.PlanRevision, AssurancePolicyRevision: value.AssurancePolicyRevision,
			AccountMode: accountMode, Configuration: configuration,
			Endpoints: endpoints, Mappings: mappings,
		}
		var result contract.PlatformAuthProvider
		if err := result.FromPlatformLDAPAuthProvider(mapped); err != nil {
			return contract.PlatformAuthProvider{}, err
		}
		return result, nil
	case platformidentityprovider.ProviderKindOIDC:
		if value.OIDC == nil || value.SAML != nil {
			return contract.PlatformAuthProvider{}, errors.New("invalid platform OIDC provider detail")
		}
		configuration := contract.PlatformOIDCAuthProviderConfiguration{
			Issuer: value.OIDC.Issuer, ClientId: value.OIDC.ClientID,
			RedirectUri: value.OIDC.RedirectURI, TenantRedirectUri: value.OIDC.TenantRedirectURI,
			PostLogoutRedirectUri: value.OIDC.PostLogoutRedirectURI,
			ExtraScopes:           append([]string(nil), value.OIDC.ExtraScopes...),
			AllowRefreshToken:     value.OIDC.AllowRefreshToken, UseUserInfo: value.OIDC.UseUserInfo,
			ClientSecretRevision: value.OIDC.ClientSecretRevision,
			ClientSecretPresent:  value.OIDC.ClientSecretPresent,
			DiscoveryRevision:    value.OIDC.DiscoveryRevision, JwksRevision: value.OIDC.JWKSRevision,
		}
		accountMode := contract.PlatformOIDCAuthProviderAccountMode(value.AccountMode)
		if !accountMode.Valid() || value.Enabled == (value.AccountMode == platformidentityprovider.AccountModeDisabled) {
			return contract.PlatformAuthProvider{}, errors.New("invalid platform OIDC account mode")
		}
		mapped := contract.PlatformOIDCAuthProvider{
			Id: summary.Id, Key: summary.Key, DisplayName: summary.DisplayName,
			Description: summary.Description, Kind: contract.PlatformOIDCAuthProviderKindOidc,
			Enabled:                          value.Enabled,
			PlatformLoginEnabled:             value.PlatformLoginEnabled,
			PlatformLoginActivationAvailable: value.PlatformLoginActivationAvailable,
			ActivationAvailable:              value.ActivationAvailable,
			Configured:                       summary.Configured, SecretPresent: summary.SecretPresent,
			ArchivedAt: summary.ArchivedAt, Version: summary.Version,
			CreatedAt: summary.CreatedAt, UpdatedAt: summary.UpdatedAt,
			ConfigurationRevision: value.ConfigurationRevision,
			SecurityRevision:      value.SecurityRevision, PlanRevision: value.PlanRevision,
			AssurancePolicyRevision: value.AssurancePolicyRevision,
			AccountMode:             accountMode,
			Configuration:           configuration,
		}
		var result contract.PlatformAuthProvider
		if err := result.FromPlatformOIDCAuthProvider(mapped); err != nil {
			return contract.PlatformAuthProvider{}, err
		}
		return result, nil
	case platformidentityprovider.ProviderKindSAML:
		if value.SAML == nil || value.OIDC != nil {
			return contract.PlatformAuthProvider{}, errors.New("invalid platform SAML provider detail")
		}
		if value.SecretPresent != value.SAML.SPKeyPresent ||
			value.SAML.SPKeyPresent && value.SAML.SPKeyRevision < 2 {
			return contract.PlatformAuthProvider{}, errors.New("invalid platform SAML key projection")
		}
		configuration, err := mapPlatformSAMLAuthProviderConfiguration(*value.SAML)
		if err != nil {
			return contract.PlatformAuthProvider{}, err
		}
		accountMode := contract.PlatformSAMLAuthProviderAccountMode(value.AccountMode)
		if !accountMode.Valid() || value.Enabled == (value.AccountMode == platformidentityprovider.AccountModeDisabled) {
			return contract.PlatformAuthProvider{}, errors.New("invalid platform SAML account mode")
		}
		mapped := contract.PlatformSAMLAuthProvider{
			Id: summary.Id, Key: summary.Key, DisplayName: summary.DisplayName,
			Description: summary.Description, Kind: contract.PlatformSAMLAuthProviderKindSaml,
			Enabled:                          value.Enabled,
			PlatformLoginEnabled:             value.PlatformLoginEnabled,
			PlatformLoginActivationAvailable: value.PlatformLoginActivationAvailable,
			ActivationAvailable:              value.ActivationAvailable,
			Configured:                       summary.Configured,
			SecretPresent:                    summary.SecretPresent,
			ArchivedAt:                       summary.ArchivedAt, Version: summary.Version,
			CreatedAt: summary.CreatedAt, UpdatedAt: summary.UpdatedAt,
			ConfigurationRevision: value.ConfigurationRevision,
			SecurityRevision:      value.SecurityRevision, PlanRevision: value.PlanRevision,
			AssurancePolicyRevision: value.AssurancePolicyRevision,
			AccountMode:             accountMode,
			Configuration:           configuration,
		}
		var result contract.PlatformAuthProvider
		if err := result.FromPlatformSAMLAuthProvider(mapped); err != nil {
			return contract.PlatformAuthProvider{}, err
		}
		return result, nil
	default:
		return contract.PlatformAuthProvider{}, errors.New("unsupported platform provider kind")
	}
}

func mapPlatformLDAPConfiguration(
	value identityprovider.Configuration,
) (contract.PlatformLDAPAuthProviderCreateConfiguration, error) {
	tenant, err := mapTenantLDAPConfiguration(value)
	if err != nil {
		return contract.PlatformLDAPAuthProviderCreateConfiguration{}, err
	}
	encoded, err := json.Marshal(tenant)
	if err != nil {
		return contract.PlatformLDAPAuthProviderCreateConfiguration{}, err
	}
	defer clear(encoded)
	var result contract.PlatformLDAPAuthProviderCreateConfiguration
	if err := json.Unmarshal(encoded, &result); err != nil {
		return contract.PlatformLDAPAuthProviderCreateConfiguration{}, err
	}
	return result, nil
}

func mapPlatformSAMLAuthProviderConfiguration(
	value platformidentityprovider.SAMLConfiguration,
) (contract.PlatformSAMLAuthProviderConfiguration, error) {
	var result contract.PlatformSAMLAuthProviderConfiguration
	switch value.SubjectSource {
	case federatedsaml.SubjectPersistentNameID:
		configuration := contract.PlatformSAMLPersistentNameIDAuthProviderConfiguration{
			ExpectedEntityId: value.ExpectedEntityID, SpEntityId: value.SPEntityID,
			AcsUrl: value.ACSURL, SpKeyRevision: value.SPKeyRevision, SpKeyPresent: value.SPKeyPresent,
			MetadataRevision: value.MetadataRevision,
			RedirectSignatureAlgorithm: contract.PlatformSAMLPersistentNameIDAuthProviderConfigurationRedirectSignatureAlgorithm(
				value.RedirectSignatureAlgorithm,
			),
			SignaturePolicy: contract.PlatformSAMLPersistentNameIDAuthProviderConfigurationSignaturePolicy(
				value.SignaturePolicy,
			),
			EncryptionPolicy: contract.PlatformSAMLPersistentNameIDAuthProviderConfigurationEncryptionPolicy(
				value.EncryptionPolicy,
			),
			RequestedAuthnContexts:          append([]string(nil), value.RequestedAuthnContexts...),
			SubjectSource:                   contract.PlatformSAMLPersistentNameIDAuthProviderConfigurationSubjectSourcePersistentNameid,
			ClockSkewNanoseconds:            int64(value.ClockSkew),
			MaxAuthenticationAgeNanoseconds: int64(value.MaximumAuthenticationAge),
		}
		if !configuration.RedirectSignatureAlgorithm.Valid() || !configuration.SignaturePolicy.Valid() ||
			!configuration.EncryptionPolicy.Valid() || value.SubjectAttributeName != nil ||
			value.SubjectAttributeNameFormat != nil {
			return contract.PlatformSAMLAuthProviderConfiguration{}, errors.New("invalid persistent NameID SAML configuration")
		}
		if err := result.FromPlatformSAMLPersistentNameIDAuthProviderConfiguration(configuration); err != nil {
			return contract.PlatformSAMLAuthProviderConfiguration{}, err
		}
	case federatedsaml.SubjectImmutableAttribute:
		if value.SubjectAttributeName == nil || value.SubjectAttributeNameFormat == nil {
			return contract.PlatformSAMLAuthProviderConfiguration{}, errors.New("invalid immutable-attribute SAML configuration")
		}
		configuration := contract.PlatformSAMLImmutableAttributeAuthProviderConfiguration{
			ExpectedEntityId: value.ExpectedEntityID, SpEntityId: value.SPEntityID,
			AcsUrl: value.ACSURL, SpKeyRevision: value.SPKeyRevision, SpKeyPresent: value.SPKeyPresent,
			MetadataRevision: value.MetadataRevision,
			RedirectSignatureAlgorithm: contract.PlatformSAMLImmutableAttributeAuthProviderConfigurationRedirectSignatureAlgorithm(
				value.RedirectSignatureAlgorithm,
			),
			SignaturePolicy: contract.PlatformSAMLImmutableAttributeAuthProviderConfigurationSignaturePolicy(
				value.SignaturePolicy,
			),
			EncryptionPolicy: contract.PlatformSAMLImmutableAttributeAuthProviderConfigurationEncryptionPolicy(
				value.EncryptionPolicy,
			),
			RequestedAuthnContexts:          append([]string(nil), value.RequestedAuthnContexts...),
			SubjectSource:                   contract.PlatformSAMLImmutableAttributeAuthProviderConfigurationSubjectSourceImmutableAttribute,
			SubjectAttributeName:            *value.SubjectAttributeName,
			SubjectAttributeNameFormat:      *value.SubjectAttributeNameFormat,
			ClockSkewNanoseconds:            int64(value.ClockSkew),
			MaxAuthenticationAgeNanoseconds: int64(value.MaximumAuthenticationAge),
		}
		if !configuration.RedirectSignatureAlgorithm.Valid() || !configuration.SignaturePolicy.Valid() ||
			!configuration.EncryptionPolicy.Valid() {
			return contract.PlatformSAMLAuthProviderConfiguration{}, errors.New("invalid immutable-attribute SAML configuration")
		}
		if err := result.FromPlatformSAMLImmutableAttributeAuthProviderConfiguration(configuration); err != nil {
			return contract.PlatformSAMLAuthProviderConfiguration{}, err
		}
	default:
		return contract.PlatformSAMLAuthProviderConfiguration{}, errors.New("invalid platform SAML subject source")
	}
	return result, nil
}
