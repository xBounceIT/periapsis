package httpserver

import (
	"errors"
	"io"
	"net/http"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
)

var (
	tenantFederationMappingRuleFields = []string{
		"ruleId", "priority", "matcherKind", "claimName", "matcherValue", "reconciliationMode",
		"tenantSecurityGroupId", "roleIds", "operatorTeamId", "operatorTeamAssignmentEpochId", "enabled",
	}
	tenantFederationMappingRuleRequiredFields = []string{
		"ruleId", "priority", "matcherKind", "matcherValue", "reconciliationMode",
		"tenantSecurityGroupId", "roleIds", "enabled",
	}
)

const maximumTenantFederationSecretBodyBytes = 64 << 10

var (
	tenantFederationCreateFields = []string{
		"kind", "key", "loginKey", "displayName", "description", "jitMode", "noMatchPolicy", "reason", "configuration",
	}
	tenantFederationUpdateFields = []string{
		"kind", "displayName", "description", "enabled", "jitMode", "noMatchPolicy", "reason", "configuration",
	}
	tenantFederationOIDCConfigurationFields = []string{
		"issuer", "clientId", "postLogoutRedirectUri", "extraScopes", "allowRefreshToken", "useUserInfo",
	}
	tenantFederationSAMLConfigurationFields = []string{
		"expectedEntityId", "redirectSignatureAlgorithm", "signaturePolicy", "encryptionPolicy",
		"requestedAuthnContexts", "subjectSource", "subjectAttributeName", "subjectAttributeNameFormat",
		"clockSkewSeconds", "maxAuthenticationAgeSeconds",
	}
)

func decodeTenantFederationCreateBody(r *http.Request) (identityprovider.FederationCreateInput, error) {
	var body contract.TenantFederationAuthProviderCreateRequest
	raw, err := decodeTenantLDAPJSONBody(r, &body)
	if err != nil {
		return identityprovider.FederationCreateInput{}, err
	}
	object, err := exactTenantLDAPJSONObject(raw, tenantFederationCreateFields, tenantFederationCreateFields)
	if err != nil {
		return identityprovider.FederationCreateInput{}, err
	}
	kind, ok := object["kind"].(string)
	if !ok || validateTenantFederationConfiguration(object["configuration"], kind) != nil {
		return identityprovider.FederationCreateInput{}, errors.New("invalid tenant federation provider document")
	}
	switch kind {
	case "oidc":
		value, decodeErr := body.AsTenantFederationOIDCProviderCreateRequest()
		if decodeErr != nil || value.Kind != contract.TenantFederationOIDCProviderCreateRequestKindOidc {
			return identityprovider.FederationCreateInput{}, errors.New("invalid tenant OIDC provider document")
		}
		configuration := mapTenantFederationOIDCInput(value.Configuration)
		return identityprovider.FederationCreateInput{
			Kind: identityprovider.FederationProviderOIDC, Key: value.Key, LoginKey: value.LoginKey,
			DisplayName: value.DisplayName, Description: value.Description,
			JITMode: identityprovider.JITMode(value.JitMode), NoMatchPolicy: identityprovider.NoMatchPolicy(value.NoMatchPolicy),
			Reason: value.Reason, OIDC: &configuration,
		}, nil
	case "saml":
		value, decodeErr := body.AsTenantFederationSAMLProviderCreateRequest()
		if decodeErr != nil || value.Kind != contract.TenantFederationSAMLProviderCreateRequestKindSaml {
			return identityprovider.FederationCreateInput{}, errors.New("invalid tenant SAML provider document")
		}
		configuration, mapErr := mapTenantFederationSAMLInput(value.Configuration)
		if mapErr != nil {
			return identityprovider.FederationCreateInput{}, mapErr
		}
		return identityprovider.FederationCreateInput{
			Kind: identityprovider.FederationProviderSAML, Key: value.Key, LoginKey: value.LoginKey,
			DisplayName: value.DisplayName, Description: value.Description,
			JITMode: identityprovider.JITMode(value.JitMode), NoMatchPolicy: identityprovider.NoMatchPolicy(value.NoMatchPolicy),
			Reason: value.Reason, SAML: &configuration,
		}, nil
	default:
		return identityprovider.FederationCreateInput{}, errors.New("unknown tenant federation provider kind")
	}
}

func decodeTenantFederationUpdateBody(r *http.Request) (identityprovider.FederationUpdateInput, error) {
	var body contract.TenantFederationAuthProviderUpdateRequest
	raw, err := decodeTenantLDAPJSONBody(r, &body)
	if err != nil {
		return identityprovider.FederationUpdateInput{}, err
	}
	object, err := exactTenantLDAPJSONObject(raw, tenantFederationUpdateFields, tenantFederationUpdateFields)
	if err != nil {
		return identityprovider.FederationUpdateInput{}, err
	}
	kind, ok := object["kind"].(string)
	if !ok || validateTenantFederationConfiguration(object["configuration"], kind) != nil {
		return identityprovider.FederationUpdateInput{}, errors.New("invalid tenant federation provider document")
	}
	switch kind {
	case "oidc":
		value, decodeErr := body.AsTenantFederationOIDCProviderUpdateRequest()
		if decodeErr != nil || value.Kind != contract.TenantFederationOIDCProviderUpdateRequestKindOidc {
			return identityprovider.FederationUpdateInput{}, errors.New("invalid tenant OIDC provider document")
		}
		configuration := mapTenantFederationOIDCInput(value.Configuration)
		return identityprovider.FederationUpdateInput{
			DisplayName: value.DisplayName, Description: value.Description, Enabled: value.Enabled,
			JITMode: identityprovider.JITMode(value.JitMode), NoMatchPolicy: identityprovider.NoMatchPolicy(value.NoMatchPolicy),
			Reason: value.Reason, OIDC: &configuration,
		}, nil
	case "saml":
		value, decodeErr := body.AsTenantFederationSAMLProviderUpdateRequest()
		if decodeErr != nil || value.Kind != contract.TenantFederationSAMLProviderUpdateRequestKindSaml {
			return identityprovider.FederationUpdateInput{}, errors.New("invalid tenant SAML provider document")
		}
		configuration, mapErr := mapTenantFederationSAMLInput(value.Configuration)
		if mapErr != nil {
			return identityprovider.FederationUpdateInput{}, mapErr
		}
		return identityprovider.FederationUpdateInput{
			DisplayName: value.DisplayName, Description: value.Description, Enabled: value.Enabled,
			JITMode: identityprovider.JITMode(value.JitMode), NoMatchPolicy: identityprovider.NoMatchPolicy(value.NoMatchPolicy),
			Reason: value.Reason, SAML: &configuration,
		}, nil
	default:
		return identityprovider.FederationUpdateInput{}, errors.New("unknown tenant federation provider kind")
	}
}

func decodeTenantFederationReasonBody(r *http.Request) (string, error) {
	var body contract.TenantFederationAuthProviderArchiveRequest
	raw, err := decodeTenantLDAPJSONBody(r, &body)
	if err != nil {
		return "", err
	}
	if _, err := exactTenantLDAPJSONObject(raw, []string{"reason"}, []string{"reason"}); err != nil {
		return "", err
	}
	return body.Reason, nil
}

func decodeTenantFederationClearSecretBody(r *http.Request) (string, error) {
	var body contract.TenantOIDCClientSecretClearRequest
	raw, err := decodeTenantLDAPJSONBody(r, &body)
	if err != nil {
		return "", err
	}
	if _, err := exactTenantLDAPJSONObject(raw, []string{"reason"}, []string{"reason"}); err != nil {
		return "", err
	}
	return body.Reason, nil
}

func validateTenantFederationConfiguration(raw any, kind string) error {
	fields := tenantFederationOIDCConfigurationFields
	if kind == "saml" {
		fields = tenantFederationSAMLConfigurationFields
	} else if kind != "oidc" {
		return errors.New("unknown tenant federation provider kind")
	}
	_, err := exactTenantLDAPJSONObject(raw, fields, fields)
	return err
}

func mapTenantFederationOIDCInput(
	value contract.TenantFederationOIDCCreateConfiguration,
) identityprovider.FederationOIDCCreateConfiguration {
	return identityprovider.FederationOIDCCreateConfiguration{
		Issuer: value.Issuer, ClientID: value.ClientId, PostLogoutRedirectURI: value.PostLogoutRedirectUri,
		ExtraScopes: append([]string(nil), value.ExtraScopes...), AllowRefreshToken: value.AllowRefreshToken,
		UseUserInfo: value.UseUserInfo,
	}
}

func mapTenantFederationSAMLInput(
	value contract.TenantFederationSAMLCreateConfiguration,
) (identityprovider.FederationSAMLCreateConfiguration, error) {
	if value.ClockSkewSeconds < 0 || value.ClockSkewSeconds > 300 ||
		value.MaxAuthenticationAgeSeconds < 60 || value.MaxAuthenticationAgeSeconds > 86_400 {
		return identityprovider.FederationSAMLCreateConfiguration{}, errors.New(
			"invalid tenant SAML duration",
		)
	}
	return identityprovider.FederationSAMLCreateConfiguration{
		ExpectedEntityID:           value.ExpectedEntityId,
		RedirectSignatureAlgorithm: federatedsaml.RedirectSignatureAlgorithm(value.RedirectSignatureAlgorithm),
		SignaturePolicy:            federatedsaml.SignaturePolicy(value.SignaturePolicy),
		EncryptionPolicy:           federatedsaml.EncryptionPolicy(value.EncryptionPolicy),
		RequestedAuthnContexts:     append([]string(nil), value.RequestedAuthnContexts...),
		SubjectSource:              federatedsaml.SubjectSource(value.SubjectSource),
		SubjectAttributeName:       cloneStringPointer(value.SubjectAttributeName),
		SubjectAttributeNameFormat: cloneStringPointer(value.SubjectAttributeNameFormat),
		ClockSkew:                  time.Duration(value.ClockSkewSeconds) * time.Second,
		MaximumAuthenticationAge:   time.Duration(value.MaxAuthenticationAgeSeconds) * time.Second,
	}, nil
}

func decodeTenantFederationOIDCTrustBody(
	r *http.Request,
) (identityprovider.FederationOIDCTrustDocumentsInput, error) {
	var body contract.TenantOIDCTrustDocumentsRefreshRequest
	raw, err := decodeTenantLDAPJSONBody(r, &body)
	if err != nil {
		return identityprovider.FederationOIDCTrustDocumentsInput{}, err
	}
	if _, err := exactTenantLDAPJSONObject(
		raw,
		[]string{"clientAuthentication", "signingAlgorithms", "reason"},
		[]string{"clientAuthentication", "signingAlgorithms", "reason"},
	); err != nil {
		return identityprovider.FederationOIDCTrustDocumentsInput{}, err
	}
	algorithms := make([]federatedoidc.SigningAlgorithm, len(body.SigningAlgorithms))
	for index, algorithm := range body.SigningAlgorithms {
		algorithms[index] = federatedoidc.SigningAlgorithm(algorithm)
	}
	return identityprovider.FederationOIDCTrustDocumentsInput{
		ClientAuthentication: federatedoidc.ClientAuthenticationMode(body.ClientAuthentication),
		SigningAlgorithms:    algorithms,
		Reason:               body.Reason,
	}, nil
}

func decodeTenantFederationMappingBody(
	r *http.Request,
) (identityprovider.FederationReplaceMappingPolicyInput, error) {
	var body contract.TenantFederationMappingPolicyReplaceRequest
	raw, err := decodeTenantLDAPJSONBody(r, &body)
	if err != nil {
		return identityprovider.FederationReplaceMappingPolicyInput{}, err
	}
	object, err := exactTenantLDAPJSONObject(
		raw,
		[]string{"kind", "oidcClaimRules", "samlAttributeRules", "rules", "reason"},
		[]string{"kind", "rules", "reason"},
	)
	if err != nil {
		return identityprovider.FederationReplaceMappingPolicyInput{}, err
	}
	kind, ok := object["kind"].(string)
	if !ok || validateTenantFederationObjectArray(
		object["rules"], tenantFederationMappingRuleFields, tenantFederationMappingRuleRequiredFields,
	) != nil {
		return identityprovider.FederationReplaceMappingPolicyInput{}, errors.New("invalid tenant federation mapping policy")
	}
	switch kind {
	case "oidc":
		if _, present := object["samlAttributeRules"]; present ||
			validateTenantFederationObjectArray(
				object["oidcClaimRules"],
				[]string{"source", "kind", "claimName", "profileField", "required"},
				[]string{"source", "kind", "claimName", "required"},
			) != nil {
			return identityprovider.FederationReplaceMappingPolicyInput{}, errors.New("invalid tenant OIDC mapping policy")
		}
		value, decodeErr := body.AsTenantFederationOIDCMappingPolicyReplaceRequest()
		if decodeErr != nil || value.Kind != contract.TenantFederationOIDCMappingPolicyReplaceRequestKindOidc {
			return identityprovider.FederationReplaceMappingPolicyInput{}, errors.New("invalid tenant OIDC mapping policy")
		}
		claims := make([]identityprovider.FederationOIDCClaimRule, len(value.OidcClaimRules))
		for index, rule := range value.OidcClaimRules {
			claims[index] = identityprovider.FederationOIDCClaimRule{
				Source: string(rule.Source), Kind: string(rule.Kind), ClaimName: rule.ClaimName,
				ProfileField: tenantFederationOIDCProfileField(rule.ProfileField), Required: rule.Required,
			}
		}
		return identityprovider.FederationReplaceMappingPolicyInput{
			Kind: identityprovider.FederationProviderOIDC, OIDCClaimRules: claims,
			Rules: mapTenantFederationMappingRules(value.Rules), Reason: value.Reason,
		}, nil
	case "saml":
		if _, present := object["oidcClaimRules"]; present ||
			validateTenantFederationObjectArray(
				object["samlAttributeRules"],
				[]string{"kind", "attributeName", "attributeNameFormat", "profileField", "required"},
				[]string{"kind", "attributeName", "attributeNameFormat", "required"},
			) != nil {
			return identityprovider.FederationReplaceMappingPolicyInput{}, errors.New("invalid tenant SAML mapping policy")
		}
		value, decodeErr := body.AsTenantFederationSAMLMappingPolicyReplaceRequest()
		if decodeErr != nil || value.Kind != contract.TenantFederationSAMLMappingPolicyReplaceRequestKindSaml {
			return identityprovider.FederationReplaceMappingPolicyInput{}, errors.New("invalid tenant SAML mapping policy")
		}
		attributes := make([]identityprovider.FederationSAMLAttributeRule, len(value.SamlAttributeRules))
		for index, rule := range value.SamlAttributeRules {
			attributes[index] = identityprovider.FederationSAMLAttributeRule{
				Kind: string(rule.Kind), AttributeName: rule.AttributeName,
				AttributeNameFormat: rule.AttributeNameFormat,
				ProfileField:        tenantFederationSAMLProfileField(rule.ProfileField),
				Required:            rule.Required,
			}
		}
		return identityprovider.FederationReplaceMappingPolicyInput{
			Kind: identityprovider.FederationProviderSAML, SAMLAttributeRules: attributes,
			Rules: mapTenantFederationMappingRules(value.Rules), Reason: value.Reason,
		}, nil
	default:
		return identityprovider.FederationReplaceMappingPolicyInput{}, errors.New("unknown tenant federation mapping kind")
	}
}

func decodeTenantFederationAssuranceBody(
	r *http.Request,
) (identityprovider.FederationReplaceAssurancePolicyInput, error) {
	var body contract.TenantFederationAssurancePolicyReplaceRequest
	raw, err := decodeTenantLDAPJSONBody(r, &body)
	if err != nil {
		return identityprovider.FederationReplaceAssurancePolicyInput{}, err
	}
	object, err := exactTenantLDAPJSONObject(raw, []string{"kind", "rules", "reason"}, []string{"kind", "rules", "reason"})
	if err != nil {
		return identityprovider.FederationReplaceAssurancePolicyInput{}, err
	}
	kind, ok := object["kind"].(string)
	if !ok {
		return identityprovider.FederationReplaceAssurancePolicyInput{}, errors.New("invalid tenant federation assurance policy")
	}
	switch kind {
	case "oidc":
		if validateTenantFederationObjectArray(
			object["rules"],
			[]string{"ruleId", "enabled", "level", "exactValue", "requiredValues", "maximumAuthenticationAgeSeconds"},
			[]string{"ruleId", "enabled", "level", "exactValue", "requiredValues", "maximumAuthenticationAgeSeconds"},
		) != nil {
			return identityprovider.FederationReplaceAssurancePolicyInput{}, errors.New("invalid tenant OIDC assurance policy")
		}
		value, decodeErr := body.AsTenantFederationOIDCAssurancePolicyReplaceRequest()
		if decodeErr != nil || value.Kind != contract.TenantFederationOIDCAssurancePolicyReplaceRequestKindOidc {
			return identityprovider.FederationReplaceAssurancePolicyInput{}, errors.New("invalid tenant OIDC assurance policy")
		}
		rules := make([]identityprovider.FederationAssuranceRule, len(value.Rules))
		for index, rule := range value.Rules {
			rules[index] = identityprovider.FederationAssuranceRule{
				RuleID: uuid.UUID(rule.RuleId), Enabled: rule.Enabled, Level: string(rule.Level),
				ExactValue: cloneStringPointer(rule.ExactValue), RequiredValues: append([]string(nil), rule.RequiredValues...),
				MaximumAuthenticationAgeSeconds: rule.MaximumAuthenticationAgeSeconds,
			}
		}
		return identityprovider.FederationReplaceAssurancePolicyInput{
			Kind: identityprovider.FederationProviderOIDC, Rules: rules, Reason: value.Reason,
		}, nil
	case "saml":
		if validateTenantFederationObjectArray(
			object["rules"],
			[]string{"ruleId", "enabled", "level", "exactValue", "maximumAuthenticationAgeSeconds"},
			[]string{"ruleId", "enabled", "level", "exactValue", "maximumAuthenticationAgeSeconds"},
		) != nil {
			return identityprovider.FederationReplaceAssurancePolicyInput{}, errors.New("invalid tenant SAML assurance policy")
		}
		value, decodeErr := body.AsTenantFederationSAMLAssurancePolicyReplaceRequest()
		if decodeErr != nil || value.Kind != contract.TenantFederationSAMLAssurancePolicyReplaceRequestKindSaml {
			return identityprovider.FederationReplaceAssurancePolicyInput{}, errors.New("invalid tenant SAML assurance policy")
		}
		rules := make([]identityprovider.FederationAssuranceRule, len(value.Rules))
		for index, rule := range value.Rules {
			exact := rule.ExactValue
			rules[index] = identityprovider.FederationAssuranceRule{
				RuleID: uuid.UUID(rule.RuleId), Enabled: rule.Enabled, Level: string(rule.Level),
				ExactValue: &exact, RequiredValues: []string{},
				MaximumAuthenticationAgeSeconds: rule.MaximumAuthenticationAgeSeconds,
			}
		}
		return identityprovider.FederationReplaceAssurancePolicyInput{
			Kind: identityprovider.FederationProviderSAML, Rules: rules, Reason: value.Reason,
		}, nil
	default:
		return identityprovider.FederationReplaceAssurancePolicyInput{}, errors.New("unknown tenant federation assurance kind")
	}
}

func validateTenantFederationObjectArray(value any, allowed, required []string) error {
	items, ok := value.([]any)
	if !ok {
		return errors.New("tenant federation request member must be an array")
	}
	for _, item := range items {
		if _, err := exactTenantLDAPJSONObject(item, allowed, required); err != nil {
			return err
		}
	}
	return nil
}

func mapTenantFederationMappingRules(values []contract.TenantFederationMappingRule) []identityprovider.FederationMappingRule {
	result := make([]identityprovider.FederationMappingRule, len(values))
	for index, value := range values {
		roleIDs := make([]uuid.UUID, len(value.RoleIds))
		for roleIndex, roleID := range value.RoleIds {
			roleIDs[roleIndex] = uuid.UUID(roleID)
		}
		result[index] = identityprovider.FederationMappingRule{
			RuleID: uuid.UUID(value.RuleId), Priority: value.Priority,
			MatcherKind: string(value.MatcherKind), ClaimName: cloneStringPointer(value.ClaimName),
			MatcherValue: value.MatcherValue, ReconciliationMode: string(value.ReconciliationMode),
			TenantSecurityGroupID: uuid.UUID(value.TenantSecurityGroupId), RoleIDs: roleIDs,
			OperatorTeamID:                tenantFederationUUID(value.OperatorTeamId),
			OperatorTeamAssignmentEpochID: tenantFederationUUID(value.OperatorTeamAssignmentEpochId),
			Enabled:                       value.Enabled,
		}
	}
	return result
}

func tenantFederationUUID(value *uuid.UUID) *uuid.UUID {
	if value == nil {
		return nil
	}
	copyValue := *value
	return &copyValue
}

func tenantFederationOIDCProfileField(
	value *contract.TenantFederationOIDCClaimRuleProfileField,
) *string {
	if value == nil {
		return nil
	}
	copyValue := string(*value)
	return &copyValue
}

func tenantFederationSAMLProfileField(
	value *contract.TenantFederationSAMLAttributeRuleProfileField,
) *string {
	if value == nil {
		return nil
	}
	copyValue := string(*value)
	return &copyValue
}

func decodeTenantFederationOIDCSecretBody(r *http.Request) (secret []byte, reason string, err error) {
	mediaType, mediaErr := requestMediaType(r)
	if mediaErr != nil || mediaType != "application/json" {
		return nil, "", errors.New("unsupported tenant federation secret content type")
	}
	defer r.Body.Close()
	buffer := make([]byte, maximumTenantFederationSecretBodyBytes+1)
	used := 0
	for used < len(buffer) {
		read, readErr := r.Body.Read(buffer[used:])
		used += read
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			clear(buffer)
			return nil, "", errors.New("tenant federation secret body could not be read")
		}
		if read == 0 {
			clear(buffer)
			return nil, "", errors.New("tenant federation secret body made no progress")
		}
	}
	if used == 0 || used > maximumTenantFederationSecretBodyBytes {
		clear(buffer)
		return nil, "", errors.New("tenant federation secret body is invalid")
	}
	return decodeTenantFederationOIDCSecretDocument(buffer[:used])
}

func decodeTenantFederationOIDCSecretDocument(document []byte) (secret []byte, reason string, err error) {
	defer clear(document[:cap(document)])
	if !utf8.Valid(document) {
		return nil, "", errors.New("tenant federation secret body is not UTF-8 JSON")
	}
	parser := tenantLDAPSecretParser{source: document}
	parser.skipWhitespace()
	if !parser.consume('{') {
		return nil, "", errors.New("tenant federation secret body must be an object")
	}
	var seenSecret, seenReason bool
	defer func() {
		if err != nil {
			clear(secret)
			secret = nil
		}
	}()
	for member := 0; member < 2; member++ {
		parser.skipWhitespace()
		key, parseErr := parser.stringBytes(32)
		if parseErr != nil {
			return nil, "", parseErr
		}
		parser.skipWhitespace()
		if !parser.consume(':') {
			clear(key)
			return nil, "", errors.New("tenant federation secret member is missing a colon")
		}
		parser.skipWhitespace()
		value, valueErr := parser.stringBytes(8192)
		if valueErr != nil {
			clear(key)
			return nil, "", valueErr
		}
		switch string(key) {
		case "clientSecret":
			if seenSecret || len(value) == 0 {
				clear(value)
				clear(key)
				return nil, "", errors.New("tenant federation client secret is duplicate or empty")
			}
			seenSecret = true
			secret = value
		case "reason":
			if seenReason {
				clear(value)
				clear(key)
				return nil, "", errors.New("tenant federation mutation reason is duplicate")
			}
			seenReason = true
			reason = string(value)
			clear(value)
		default:
			clear(value)
			clear(key)
			return nil, "", errors.New("tenant federation secret body contains an unknown field")
		}
		clear(key)
		parser.skipWhitespace()
		if member == 0 && !parser.consume(',') {
			return nil, "", errors.New("tenant federation secret body omits a required field")
		}
	}
	parser.skipWhitespace()
	if !seenSecret || !seenReason || !parser.consume('}') {
		return nil, "", errors.New("tenant federation secret body is incomplete")
	}
	parser.skipWhitespace()
	if parser.index != len(parser.source) {
		return nil, "", errors.New("tenant federation secret body contains trailing data")
	}
	return secret, reason, nil
}
