package httpserver

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
)

// tenantFederationOIDCConfigurationProjection preserves the complete allOf
// wire shape. The generated configuration type currently contains only the
// projection-specific fields and omits its create-configuration component.
type tenantFederationOIDCConfigurationProjection struct {
	contract.TenantFederationOIDCCreateConfiguration
	contract.TenantFederationOIDCConfiguration
}

type tenantFederationOIDCAuthProviderProjection struct {
	contract.TenantFederationOIDCAuthProvider
	Configuration tenantFederationOIDCConfigurationProjection `json:"configuration"`
}

func mapTenantFederationProviderSummary(
	value identityprovider.FederationProviderSummary,
) (contract.TenantFederationAuthProviderSummary, error) {
	if value.ID == uuid.Nil || value.TenantID == uuid.Nil || value.Binding.ID == uuid.Nil || value.Version < 1 ||
		value.Binding.Version < 1 {
		return contract.TenantFederationAuthProviderSummary{}, errors.New("invalid tenant federation provider summary")
	}
	kind := contract.TenantFederationAuthProviderSummaryKind(value.Kind)
	if !kind.Valid() {
		return contract.TenantFederationAuthProviderSummary{}, errors.New("invalid tenant federation provider kind")
	}
	return contract.TenantFederationAuthProviderSummary{
		Id: value.ID, TenantId: value.TenantID, Key: value.Key, DisplayName: value.DisplayName,
		Description: value.Description, Kind: kind, Enabled: value.Enabled, Configured: value.Configured,
		Binding: mapTenantFederationBinding(value.Binding), ArchivedAt: cloneTimePointer(value.ArchivedAt),
		Version: value.Version, CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt,
	}, nil
}

func mapTenantFederationBinding(value identityprovider.FederationBinding) contract.TenantFederationBinding {
	return contract.TenantFederationBinding{
		Id: value.ID, LoginKey: value.LoginKey, Enabled: value.Enabled,
		Version: value.Version, UpdatedAt: value.UpdatedAt,
	}
}

func mapTenantFederationProvider(
	value identityprovider.FederationProvider,
) (contract.TenantFederationAuthProvider, error) {
	base := contract.TenantFederationProviderBase{
		Id: value.ID, TenantId: value.TenantID, Key: value.Key, DisplayName: value.DisplayName,
		Description: value.Description, Enabled: value.Enabled, Configured: value.Configured,
		Binding: mapTenantFederationBinding(value.Binding), ArchivedAt: cloneTimePointer(value.ArchivedAt),
		Version: value.Version, ConfigurationRevision: value.ConfigurationRevision,
		SecurityRevision: value.SecurityRevision, PlanRevision: value.PlanRevision,
		AssurancePolicyRevision: value.AssurancePolicyRevision,
		JitMode:                 contract.TenantFederationProviderBaseJitMode(value.JITMode),
		NoMatchPolicy:           contract.TenantFederationProviderBaseNoMatchPolicy(value.NoMatchPolicy),
		CreatedAt:               value.CreatedAt, UpdatedAt: value.UpdatedAt,
	}
	if !base.JitMode.Valid() || !base.NoMatchPolicy.Valid() {
		return contract.TenantFederationAuthProvider{}, errors.New("invalid tenant federation policy")
	}
	var result contract.TenantFederationAuthProvider
	switch value.Kind {
	case identityprovider.FederationProviderOIDC:
		if value.OIDC == nil || value.SAML != nil {
			return contract.TenantFederationAuthProvider{}, errors.New("invalid tenant OIDC projection")
		}
		configuration := contract.TenantFederationOIDCConfiguration{
			RedirectUri:          value.OIDC.RedirectURI,
			ClientSecretPresent:  value.OIDC.ClientSecretPresent,
			ClientSecretRevision: value.OIDC.ClientSecretRevision,
			DiscoveryRevision:    value.OIDC.DiscoveryRevision,
			JwksRevision:         value.OIDC.JWKSRevision,
		}
		mapped := contract.TenantFederationOIDCAuthProvider{
			Id: base.Id, TenantId: base.TenantId, Key: base.Key, DisplayName: base.DisplayName,
			Description: base.Description, Enabled: base.Enabled, Configured: base.Configured,
			Binding: base.Binding, ArchivedAt: base.ArchivedAt, Version: base.Version,
			ConfigurationRevision: base.ConfigurationRevision, SecurityRevision: base.SecurityRevision,
			PlanRevision: base.PlanRevision, AssurancePolicyRevision: base.AssurancePolicyRevision,
			JitMode:       contract.TenantFederationOIDCAuthProviderJitMode(value.JITMode),
			NoMatchPolicy: contract.TenantFederationOIDCAuthProviderNoMatchPolicy(value.NoMatchPolicy),
			Kind:          contract.TenantFederationOIDCAuthProviderKindOidc,
			CreatedAt:     base.CreatedAt, UpdatedAt: base.UpdatedAt,
			Configuration: configuration,
		}
		if !mapped.JitMode.Valid() || !mapped.NoMatchPolicy.Valid() {
			return contract.TenantFederationAuthProvider{}, errors.New("could not encode tenant OIDC projection")
		}
		wire, err := json.Marshal(tenantFederationOIDCAuthProviderProjection{
			TenantFederationOIDCAuthProvider: mapped,
			Configuration: tenantFederationOIDCConfigurationProjection{
				TenantFederationOIDCCreateConfiguration: contract.TenantFederationOIDCCreateConfiguration{
					Issuer: value.OIDC.Issuer, ClientId: value.OIDC.ClientID,
					PostLogoutRedirectUri: value.OIDC.PostLogoutRedirectURI,
					ExtraScopes:           append([]string{}, value.OIDC.ExtraScopes...),
					AllowRefreshToken:     value.OIDC.AllowRefreshToken, UseUserInfo: value.OIDC.UseUserInfo,
				},
				TenantFederationOIDCConfiguration: configuration,
			},
		})
		if err != nil || result.UnmarshalJSON(wire) != nil {
			return contract.TenantFederationAuthProvider{}, errors.New("could not encode tenant OIDC projection")
		}
	case identityprovider.FederationProviderSAML:
		if value.SAML == nil || value.OIDC != nil || value.SAML.ClockSkew%time.Second != 0 ||
			value.SAML.MaximumAuthenticationAge%time.Second != 0 {
			return contract.TenantFederationAuthProvider{}, errors.New("invalid tenant SAML projection")
		}
		mapped := contract.TenantFederationSAMLAuthProvider{
			Id: base.Id, TenantId: base.TenantId, Key: base.Key, DisplayName: base.DisplayName,
			Description: base.Description, Enabled: base.Enabled, Configured: base.Configured,
			Binding: base.Binding, ArchivedAt: base.ArchivedAt, Version: base.Version,
			ConfigurationRevision: base.ConfigurationRevision, SecurityRevision: base.SecurityRevision,
			PlanRevision: base.PlanRevision, AssurancePolicyRevision: base.AssurancePolicyRevision,
			JitMode:       contract.TenantFederationSAMLAuthProviderJitMode(value.JITMode),
			NoMatchPolicy: contract.TenantFederationSAMLAuthProviderNoMatchPolicy(value.NoMatchPolicy),
			Kind:          contract.TenantFederationSAMLAuthProviderKindSaml,
			CreatedAt:     base.CreatedAt, UpdatedAt: base.UpdatedAt,
			Configuration: contract.TenantFederationSAMLConfiguration{
				ExpectedEntityId: value.SAML.ExpectedEntityID, SpEntityId: value.SAML.SPEntityID,
				AcsUrl: value.SAML.ACSURL, SpKeyPresent: value.SAML.SPKeyPresent,
				SpKeyRevision: value.SAML.SPKeyRevision, MetadataRevision: value.SAML.MetadataRevision,
				RedirectSignatureAlgorithm:  contract.TenantFederationSAMLConfigurationRedirectSignatureAlgorithm(value.SAML.RedirectSignatureAlgorithm),
				SignaturePolicy:             contract.TenantFederationSAMLConfigurationSignaturePolicy(value.SAML.SignaturePolicy),
				EncryptionPolicy:            contract.TenantFederationSAMLConfigurationEncryptionPolicy(value.SAML.EncryptionPolicy),
				RequestedAuthnContexts:      append([]string(nil), value.SAML.RequestedAuthnContexts...),
				SubjectSource:               contract.TenantFederationSAMLConfigurationSubjectSource(value.SAML.SubjectSource),
				SubjectAttributeName:        cloneStringPointer(value.SAML.SubjectAttributeName),
				SubjectAttributeNameFormat:  cloneStringPointer(value.SAML.SubjectAttributeNameFormat),
				ClockSkewSeconds:            int(value.SAML.ClockSkew / time.Second),
				MaxAuthenticationAgeSeconds: int(value.SAML.MaximumAuthenticationAge / time.Second),
				SingleLogoutConfigured:      value.SAML.SingleLogoutConfigured,
			},
		}
		if !mapped.JitMode.Valid() || !mapped.NoMatchPolicy.Valid() ||
			!mapped.Configuration.RedirectSignatureAlgorithm.Valid() || !mapped.Configuration.SignaturePolicy.Valid() ||
			!mapped.Configuration.EncryptionPolicy.Valid() || !mapped.Configuration.SubjectSource.Valid() ||
			result.FromTenantFederationSAMLAuthProvider(mapped) != nil {
			return contract.TenantFederationAuthProvider{}, errors.New("could not encode tenant SAML projection")
		}
	default:
		return contract.TenantFederationAuthProvider{}, errors.New("unknown tenant federation provider kind")
	}
	return result, nil
}

func cloneTimePointer(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func mapTenantFederationMappingPolicy(
	value identityprovider.FederationMappingPolicy,
) (contract.TenantFederationMappingPolicy, error) {
	var result contract.TenantFederationMappingPolicy
	rules, err := mapTenantFederationMappingPolicyRules(value.Rules)
	if err != nil {
		return result, err
	}
	switch value.Kind {
	case identityprovider.FederationProviderOIDC:
		claims := make([]contract.TenantFederationOIDCClaimRule, len(value.OIDCClaimRules))
		for index, rule := range value.OIDCClaimRules {
			kind := contract.TenantFederationOIDCClaimRuleKind(rule.Kind)
			source := contract.TenantFederationOIDCClaimRuleSource(rule.Source)
			if !kind.Valid() || !source.Valid() {
				return result, errors.New("invalid tenant OIDC claim projection")
			}
			claims[index] = contract.TenantFederationOIDCClaimRule{
				Source: source, Kind: kind, ClaimName: rule.ClaimName,
				ProfileField: mapTenantFederationOIDCProfileField(rule.ProfileField), Required: rule.Required,
			}
		}
		mapped := contract.TenantFederationOIDCMappingPolicy{
			TenantId: value.TenantID, ProviderId: value.ProviderID, Kind: contract.TenantFederationOIDCMappingPolicyKind("oidc"),
			ProviderVersion: value.ProviderVersion, MappingRevision: value.MappingRevision,
			OidcClaimRules: claims, Rules: rules,
		}
		if !mapped.Kind.Valid() || result.FromTenantFederationOIDCMappingPolicy(mapped) != nil {
			return result, errors.New("could not encode tenant OIDC mapping projection")
		}
	case identityprovider.FederationProviderSAML:
		attributes := make([]contract.TenantFederationSAMLAttributeRule, len(value.SAMLAttributeRules))
		for index, rule := range value.SAMLAttributeRules {
			kind := contract.TenantFederationSAMLAttributeRuleKind(rule.Kind)
			if !kind.Valid() {
				return result, errors.New("invalid tenant SAML attribute projection")
			}
			attributes[index] = contract.TenantFederationSAMLAttributeRule{
				Kind: kind, AttributeName: rule.AttributeName, AttributeNameFormat: rule.AttributeNameFormat,
				ProfileField: mapTenantFederationSAMLProfileField(rule.ProfileField), Required: rule.Required,
			}
		}
		mapped := contract.TenantFederationSAMLMappingPolicy{
			TenantId: value.TenantID, ProviderId: value.ProviderID, Kind: contract.TenantFederationSAMLMappingPolicyKind("saml"),
			ProviderVersion: value.ProviderVersion, MappingRevision: value.MappingRevision,
			SamlAttributeRules: attributes, Rules: rules,
		}
		if !mapped.Kind.Valid() || result.FromTenantFederationSAMLMappingPolicy(mapped) != nil {
			return result, errors.New("could not encode tenant SAML mapping projection")
		}
	default:
		return result, errors.New("unknown tenant federation mapping kind")
	}
	return result, nil
}

func mapTenantFederationMappingPolicyRules(
	values []identityprovider.FederationMappingRule,
) ([]contract.TenantFederationMappingRule, error) {
	result := make([]contract.TenantFederationMappingRule, len(values))
	for index, value := range values {
		matcher := contract.TenantFederationMappingRuleMatcherKind(value.MatcherKind)
		reconciliation := contract.TenantFederationMappingRuleReconciliationMode(value.ReconciliationMode)
		if !matcher.Valid() || !reconciliation.Valid() {
			return nil, errors.New("invalid tenant federation mapping rule projection")
		}
		result[index] = contract.TenantFederationMappingRule{
			RuleId: value.RuleID, Priority: value.Priority, MatcherKind: matcher,
			ClaimName: cloneStringPointer(value.ClaimName), MatcherValue: value.MatcherValue,
			ReconciliationMode: reconciliation, TenantSecurityGroupId: value.TenantSecurityGroupID,
			RoleIds:                       append([]uuid.UUID(nil), value.RoleIDs...),
			OperatorTeamId:                cloneUUIDPointer(value.OperatorTeamID),
			OperatorTeamAssignmentEpochId: cloneUUIDPointer(value.OperatorTeamAssignmentEpochID),
			Enabled:                       value.Enabled,
		}
	}
	return result, nil
}

func mapTenantFederationAssurancePolicy(
	value identityprovider.FederationAssurancePolicy,
) (contract.TenantFederationAssurancePolicy, error) {
	var result contract.TenantFederationAssurancePolicy
	switch value.Kind {
	case identityprovider.FederationProviderOIDC:
		rules := make([]contract.TenantFederationOIDCAssuranceRule, len(value.Rules))
		for index, rule := range value.Rules {
			level := contract.TenantFederationOIDCAssuranceRuleLevel(rule.Level)
			if !level.Valid() {
				return result, errors.New("invalid tenant OIDC assurance projection")
			}
			rules[index] = contract.TenantFederationOIDCAssuranceRule{
				RuleId: rule.RuleID, Enabled: rule.Enabled, Level: level,
				ExactValue:                      cloneStringPointer(rule.ExactValue),
				RequiredValues:                  append([]string(nil), rule.RequiredValues...),
				MaximumAuthenticationAgeSeconds: rule.MaximumAuthenticationAgeSeconds,
			}
		}
		mapped := contract.TenantFederationOIDCAssurancePolicy{
			TenantId: value.TenantID, ProviderId: value.ProviderID, Kind: contract.TenantFederationOIDCAssurancePolicyKind("oidc"),
			ProviderVersion:         value.ProviderVersion,
			AssurancePolicyRevision: value.AssurancePolicyRevision, Rules: rules,
		}
		if !mapped.Kind.Valid() || result.FromTenantFederationOIDCAssurancePolicy(mapped) != nil {
			return result, errors.New("could not encode tenant OIDC assurance projection")
		}
	case identityprovider.FederationProviderSAML:
		rules := make([]contract.TenantFederationSAMLAssuranceRule, len(value.Rules))
		for index, rule := range value.Rules {
			level := contract.TenantFederationSAMLAssuranceRuleLevel(rule.Level)
			if !level.Valid() || rule.ExactValue == nil {
				return result, errors.New("invalid tenant SAML assurance projection")
			}
			rules[index] = contract.TenantFederationSAMLAssuranceRule{
				RuleId: rule.RuleID, Enabled: rule.Enabled, Level: level, ExactValue: *rule.ExactValue,
				MaximumAuthenticationAgeSeconds: rule.MaximumAuthenticationAgeSeconds,
			}
		}
		mapped := contract.TenantFederationSAMLAssurancePolicy{
			TenantId: value.TenantID, ProviderId: value.ProviderID, Kind: contract.TenantFederationSAMLAssurancePolicyKind("saml"),
			ProviderVersion:         value.ProviderVersion,
			AssurancePolicyRevision: value.AssurancePolicyRevision, Rules: rules,
		}
		if !mapped.Kind.Valid() || result.FromTenantFederationSAMLAssurancePolicy(mapped) != nil {
			return result, errors.New("could not encode tenant SAML assurance projection")
		}
	default:
		return result, errors.New("unknown tenant federation assurance kind")
	}
	return result, nil
}

func mapTenantFederationOIDCProfileField(value *string) *contract.TenantFederationOIDCClaimRuleProfileField {
	if value == nil {
		return nil
	}
	mapped := contract.TenantFederationOIDCClaimRuleProfileField(*value)
	return &mapped
}

func mapTenantFederationSAMLProfileField(value *string) *contract.TenantFederationSAMLAttributeRuleProfileField {
	if value == nil {
		return nil
	}
	mapped := contract.TenantFederationSAMLAttributeRuleProfileField(*value)
	return &mapped
}
