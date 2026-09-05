package identityprovider

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

const (
	maximumFederationClientSecretBytes  = 8 * 1024
	maximumFederationURIBytes           = 4096
	maximumFederationSAMLEntityIDBytes  = 2048
	maximumFederationSAMLContextBytes   = 2048
	maximumFederationSAMLAttributeBytes = 512
	maximumFederationRevision           = int64(9_007_199_254_740_991)
)

var reservedFederationOIDCSecurityClaims = map[string]struct{}{
	"iss": {}, "sub": {}, "aud": {}, "azp": {}, "exp": {}, "iat": {}, "nbf": {},
	"auth_time": {}, "nonce": {}, "at_hash": {}, "acr": {}, "amr": {},
}

func normalizeFederationList(input FederationListInput) (FederationListInput, error) {
	page, err := normalizePage(PageInput{After: input.After, Limit: input.Limit})
	if err != nil {
		return FederationListInput{}, err
	}
	input.After, input.Limit = page.After, page.Limit
	return input, nil
}

func normalizeFederationCreate(input FederationCreateInput) (FederationCreateInput, error) {
	input.Key = strings.TrimSpace(input.Key)
	input.LoginKey = strings.TrimSpace(input.LoginKey)
	input.DisplayName = strings.TrimSpace(input.DisplayName)
	input.Description = strings.TrimSpace(input.Description)
	input.Reason = strings.TrimSpace(input.Reason)
	if !providerKeyPattern.MatchString(input.Key) || !providerKeyPattern.MatchString(input.LoginKey) ||
		!validText(input.DisplayName, 1, 120) || !validText(input.Description, 0, 1000) ||
		!validFederationAuditReason(input.Reason) || !idempotencyKeyPattern.MatchString(input.IdempotencyKey) ||
		!validAudit(input.Audit, true) || !knownFederationJITMode(input.JITMode) ||
		!knownNoMatchPolicy(input.NoMatchPolicy) {
		return FederationCreateInput{}, ErrInvalidInput
	}
	switch input.Kind {
	case FederationProviderOIDC:
		if input.OIDC == nil || input.SAML != nil {
			return FederationCreateInput{}, ErrInvalidInput
		}
		configuration, err := normalizeFederationOIDC(*input.OIDC)
		if err != nil {
			return FederationCreateInput{}, err
		}
		input.OIDC = &configuration
	case FederationProviderSAML:
		if input.SAML == nil || input.OIDC != nil {
			return FederationCreateInput{}, ErrInvalidInput
		}
		configuration, err := normalizeFederationSAML(*input.SAML)
		if err != nil {
			return FederationCreateInput{}, err
		}
		input.SAML = &configuration
	default:
		return FederationCreateInput{}, ErrInvalidInput
	}
	return input, nil
}

func normalizeFederationUpdate(
	providerID uuid.UUID,
	input FederationUpdateInput,
) (FederationUpdateInput, int64, error) {
	version, err := validateIncrementableFederationVersion(providerID, input.ExpectedEntityTag, input.Audit)
	if err != nil {
		return FederationUpdateInput{}, 0, err
	}
	input.DisplayName = strings.TrimSpace(input.DisplayName)
	input.Description = strings.TrimSpace(input.Description)
	input.Reason = strings.TrimSpace(input.Reason)
	if !validText(input.DisplayName, 1, 120) || !validText(input.Description, 0, 1000) ||
		!validFederationAuditReason(input.Reason) || !knownFederationJITMode(input.JITMode) ||
		!knownNoMatchPolicy(input.NoMatchPolicy) || (input.OIDC == nil) == (input.SAML == nil) {
		return FederationUpdateInput{}, 0, ErrInvalidInput
	}
	if input.OIDC != nil {
		configuration, normalizeErr := normalizeFederationOIDC(*input.OIDC)
		if normalizeErr != nil {
			return FederationUpdateInput{}, 0, normalizeErr
		}
		input.OIDC = &configuration
	} else {
		configuration, normalizeErr := normalizeFederationSAML(*input.SAML)
		if normalizeErr != nil {
			return FederationUpdateInput{}, 0, normalizeErr
		}
		input.SAML = &configuration
	}
	return input, version, nil
}

func normalizeFederationOIDC(
	input FederationOIDCCreateConfiguration,
) (FederationOIDCCreateConfiguration, error) {
	input.Issuer = strings.TrimSpace(input.Issuer)
	input.PostLogoutRedirectURI = strings.TrimSpace(input.PostLogoutRedirectURI)
	if !validCanonicalHTTPSURL(input.Issuer, true) ||
		!validFederationOIDCClientID(input.ClientID) ||
		!validCanonicalHTTPSURL(input.PostLogoutRedirectURI, false) || len(input.ExtraScopes) > 31 {
		return FederationOIDCCreateConfiguration{}, ErrInvalidInput
	}
	seen := make(map[string]struct{}, len(input.ExtraScopes))
	for index, raw := range input.ExtraScopes {
		value := strings.TrimSpace(raw)
		if value == "openid" || !validOAuthScopeValue(value) {
			return FederationOIDCCreateConfiguration{}, ErrInvalidInput
		}
		if _, duplicate := seen[value]; duplicate {
			return FederationOIDCCreateConfiguration{}, ErrInvalidInput
		}
		seen[value] = struct{}{}
		input.ExtraScopes[index] = value
	}
	slices.Sort(input.ExtraScopes)
	_, hasOfflineAccess := seen["offline_access"]
	if hasOfflineAccess != input.AllowRefreshToken {
		return FederationOIDCCreateConfiguration{}, ErrInvalidInput
	}
	return input, nil
}

func normalizeFederationSAML(
	input FederationSAMLCreateConfiguration,
) (FederationSAMLCreateConfiguration, error) {
	input.ExpectedEntityID = strings.TrimSpace(input.ExpectedEntityID)
	if input.SubjectAttributeName != nil {
		value := strings.TrimSpace(*input.SubjectAttributeName)
		input.SubjectAttributeName = &value
	}
	if input.SubjectAttributeNameFormat != nil {
		value := strings.TrimSpace(*input.SubjectAttributeNameFormat)
		input.SubjectAttributeNameFormat = &value
	}
	if len(input.ExpectedEntityID) > maximumFederationSAMLEntityIDBytes ||
		!validFederationXML10Text(input.ExpectedEntityID) ||
		!validCanonicalAbsoluteURI(input.ExpectedEntityID) ||
		!validFederationRedirectAlgorithm(input.RedirectSignatureAlgorithm) ||
		!validFederationSignaturePolicy(input.SignaturePolicy) ||
		input.EncryptionPolicy != federatedsaml.EncryptionDisabled ||
		input.ClockSkew < 0 || input.ClockSkew > 5*time.Minute ||
		input.MaximumAuthenticationAge < time.Minute || input.MaximumAuthenticationAge > 24*time.Hour ||
		len(input.RequestedAuthnContexts) < 1 || len(input.RequestedAuthnContexts) > 32 ||
		!validFederationSubject(input) {
		return FederationSAMLCreateConfiguration{}, ErrInvalidInput
	}
	seen := make(map[string]struct{}, len(input.RequestedAuthnContexts))
	for index, raw := range input.RequestedAuthnContexts {
		value := strings.TrimSpace(raw)
		if len(value) > maximumFederationSAMLContextBytes || !validCanonicalAbsoluteURI(value) ||
			!validFederationXML10Text(value) {
			return FederationSAMLCreateConfiguration{}, ErrInvalidInput
		}
		if _, duplicate := seen[value]; duplicate {
			return FederationSAMLCreateConfiguration{}, ErrInvalidInput
		}
		seen[value] = struct{}{}
		input.RequestedAuthnContexts[index] = value
	}
	slices.Sort(input.RequestedAuthnContexts)
	return input, nil
}

func federationRequestDigest(value any) ([32]byte, error) {
	document, err := json.Marshal(value)
	if err != nil || len(document) == 0 || len(document) > 64*1024 {
		clear(document)
		return [32]byte{}, ErrInvalidInput
	}
	digest := federationSHA256(document)
	clear(document)
	return digest, nil
}

func federationSHA256(value []byte) [32]byte {
	// Kept as a small seam so callers cannot accidentally retain the canonical
	// JSON buffer while constructing the idempotency command.
	return sha256.Sum256(value)
}

func validFederationProvider(value FederationProvider, tenantID uuid.UUID) bool {
	if !validFederationProviderSummary(value.FederationProviderSummary, tenantID) ||
		!validFederationRevision(value.ConfigurationRevision) || !validFederationRevision(value.SecurityRevision) ||
		!validFederationRevision(value.PlanRevision) || !validFederationRevision(value.AssurancePolicyRevision) ||
		!knownFederationJITMode(value.JITMode) || !knownNoMatchPolicy(value.NoMatchPolicy) {
		return false
	}
	switch value.Kind {
	case FederationProviderOIDC:
		return value.OIDC != nil && value.SAML == nil && validFederationOIDCProjection(*value.OIDC)
	case FederationProviderSAML:
		return value.SAML != nil && value.OIDC == nil && validFederationSAMLProjection(*value.SAML)
	default:
		return false
	}
}

func validFederationProviderSummary(value FederationProviderSummary, tenantID uuid.UUID) bool {
	return validUUIDv7(value.ID) && value.TenantID == tenantID && providerKeyPattern.MatchString(value.Key) &&
		validText(value.DisplayName, 1, 120) && validText(value.Description, 0, 1000) &&
		(value.Kind == FederationProviderOIDC || value.Kind == FederationProviderSAML) &&
		validUUIDv7(value.Binding.ID) && providerKeyPattern.MatchString(value.Binding.LoginKey) &&
		validFederationResourceVersion(value.Binding.Version) && validInstant(value.Binding.UpdatedAt) &&
		value.Enabled == value.Binding.Enabled &&
		validFederationResourceVersion(value.Version) &&
		validInstant(value.CreatedAt) && validInstant(value.UpdatedAt) && !value.UpdatedAt.Before(value.CreatedAt) &&
		(value.ArchivedAt == nil || !value.Enabled && validInstant(*value.ArchivedAt) &&
			!value.ArchivedAt.Before(value.CreatedAt) && !value.ArchivedAt.After(value.UpdatedAt))
}

func validFederationOIDCProjection(value FederationOIDCConfiguration) bool {
	normalized, err := normalizeFederationOIDC(FederationOIDCCreateConfiguration{
		Issuer: value.Issuer, ClientID: value.ClientID,
		PostLogoutRedirectURI: value.PostLogoutRedirectURI, ExtraScopes: append([]string(nil), value.ExtraScopes...),
		AllowRefreshToken: value.AllowRefreshToken, UseUserInfo: value.UseUserInfo,
	})
	return err == nil && slices.Equal(normalized.ExtraScopes, value.ExtraScopes) &&
		validCanonicalHTTPSURL(value.RedirectURI, false) && validFederationRevision(value.ClientSecretRevision) &&
		validFederationRevision(value.DiscoveryRevision) && validFederationRevision(value.JWKSRevision) &&
		(!value.ClientSecretPresent || value.ClientSecretRevision >= 2)
}

func validFederationSAMLProjection(value FederationSAMLConfiguration) bool {
	normalized, err := normalizeFederationSAML(FederationSAMLCreateConfiguration{
		ExpectedEntityID: value.ExpectedEntityID, RedirectSignatureAlgorithm: value.RedirectSignatureAlgorithm,
		SignaturePolicy: value.SignaturePolicy, EncryptionPolicy: value.EncryptionPolicy,
		RequestedAuthnContexts: append([]string(nil), value.RequestedAuthnContexts...), SubjectSource: value.SubjectSource,
		SubjectAttributeName:       cloneFederationString(value.SubjectAttributeName),
		SubjectAttributeNameFormat: cloneFederationString(value.SubjectAttributeNameFormat), ClockSkew: value.ClockSkew,
		MaximumAuthenticationAge: value.MaximumAuthenticationAge,
	})
	return err == nil && slices.Equal(normalized.RequestedAuthnContexts, value.RequestedAuthnContexts) &&
		validCanonicalAbsoluteURI(value.SPEntityID) && validCanonicalHTTPSURL(value.ACSURL, false) &&
		value.ExpectedEntityID != value.SPEntityID &&
		validFederationRevision(value.SPKeyRevision) && validFederationRevision(value.MetadataRevision) &&
		(!value.SPKeyPresent || value.SPKeyRevision >= 2)
}

func validFederationSecretPreparation(
	value FederationSecretPreparation,
	tenantID, providerID uuid.UUID,
) bool {
	return value.TenantID == tenantID && value.ProviderID == providerID && validUUIDv7(value.BindingID) &&
		(value.CurrentSecretID == nil || validUUIDv7(*value.CurrentSecretID)) &&
		value.NextSecretRevision >= 2 && value.NextSecretRevision <= maximumFederationRevision
}

func knownFederationJITMode(value JITMode) bool {
	return value == JITModeDisabled || value == JITModeCreate
}

func validOAuthScopeValue(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, character := range []byte(value) {
		if character <= 0x20 || character >= 0x7f || bytes.ContainsRune([]byte(`"\\`), rune(character)) {
			return false
		}
	}
	return true
}

func validFederationOIDCClientID(value string) bool {
	if len(value) < 1 || len(value) > 512 || !utf8.ValidString(value) {
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

func validFederationEvidenceText(value string, minimum, maximum int) bool {
	if !utf8.ValidString(value) || strings.TrimSpace(value) != value || len(value) > 4096 {
		return false
	}
	length := utf8.RuneCountInString(value)
	if length < minimum || length > maximum {
		return false
	}
	for _, character := range value {
		if character <= 0x1f || character >= 0x7f && character <= 0x9f ||
			character == 0x200e || character == 0x200f ||
			character >= 0x202a && character <= 0x202e ||
			character >= 0x2066 && character <= 0x2069 {
			return false
		}
	}
	return true
}

func validCanonicalHTTPSURL(value string, issuer bool) bool {
	if len(value) < 1 || len(value) > maximumFederationURIBytes || strings.TrimSpace(value) != value ||
		strings.ContainsAny(value, "\\\r\n\t ") {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" ||
		issuer && (parsed.RawQuery != "" || parsed.Path == "/") || parsed.String() != value {
		return false
	}
	return parsed.Host == strings.ToLower(parsed.Host)
}

func validCanonicalAbsoluteURI(value string) bool {
	if len(value) < 1 || len(value) > maximumFederationURIBytes || strings.TrimSpace(value) != value ||
		strings.ContainsAny(value, "\\\r\n\t ") {
		return false
	}
	parsed, err := url.Parse(value)
	return err == nil && parsed.IsAbs() && parsed.Fragment == "" && parsed.String() == value
}

func validFederationRedirectAlgorithm(value federatedsaml.RedirectSignatureAlgorithm) bool {
	switch value {
	case federatedsaml.RedirectRSASHA256, federatedsaml.RedirectRSASHA384, federatedsaml.RedirectRSASHA512,
		federatedsaml.RedirectECDSASHA256, federatedsaml.RedirectECDSASHA384, federatedsaml.RedirectECDSASHA512:
		return true
	default:
		return false
	}
}

func validFederationSignaturePolicy(value federatedsaml.SignaturePolicy) bool {
	return value == federatedsaml.SignedAssertion || value == federatedsaml.SignedResponse ||
		value == federatedsaml.SignedBoth
}

func validFederationSubject(value FederationSAMLCreateConfiguration) bool {
	switch value.SubjectSource {
	case federatedsaml.SubjectPersistentNameID:
		return value.SubjectAttributeName == nil && value.SubjectAttributeNameFormat == nil
	case federatedsaml.SubjectImmutableAttribute:
		return value.SubjectAttributeName != nil &&
			len(*value.SubjectAttributeName) <= maximumFederationSAMLAttributeBytes &&
			validText(*value.SubjectAttributeName, 1, 512) &&
			validFederationXML10Text(*value.SubjectAttributeName) &&
			value.SubjectAttributeNameFormat != nil &&
			len(*value.SubjectAttributeNameFormat) <= maximumFederationSAMLAttributeBytes &&
			validCanonicalAbsoluteURI(*value.SubjectAttributeNameFormat) &&
			validFederationXML10Text(*value.SubjectAttributeNameFormat)
	default:
		return false
	}
}

func validFederationRevision(value int64) bool {
	return value >= 1 && value <= maximumFederationRevision
}

func validFederationResourceVersion(value int64) bool {
	return value >= 1 && value <= maximumResourceVersion
}

func validateIncrementableFederationVersion(
	providerID uuid.UUID,
	entityTag *string,
	audit authorization.AuditContext,
) (int64, error) {
	version, err := validateVersioned(providerID, entityTag, audit)
	if err != nil {
		return 0, err
	}
	if version >= maximumResourceVersion {
		return 0, ErrConflict
	}
	return version, nil
}

func normalizeFederationMappingPolicy(
	providerID uuid.UUID,
	input FederationReplaceMappingPolicyInput,
) (FederationReplaceMappingPolicyInput, int64, error) {
	version, err := validateIncrementableFederationVersion(providerID, input.ExpectedEntityTag, input.Audit)
	input.Reason = strings.TrimSpace(input.Reason)
	if err != nil || !validFederationAuditReason(input.Reason) || len(input.Rules) > 2000 {
		if err != nil {
			return FederationReplaceMappingPolicyInput{}, 0, err
		}
		return FederationReplaceMappingPolicyInput{}, 0, ErrInvalidInput
	}
	input = cloneFederationReplaceMappingPolicyInput(input)
	if !normalizeFederationExtractionPolicy(&input) || !normalizeFederationMappingRules(input.Rules) {
		return FederationReplaceMappingPolicyInput{}, 0, ErrInvalidInput
	}
	return input, version, nil
}

func normalizeFederationMappingRules(rules []FederationMappingRule) bool {
	if len(rules) > 2000 {
		return false
	}
	ruleIDs := make(map[uuid.UUID]struct{}, len(rules))
	for index := range rules {
		rule := &rules[index]
		rule.MatcherKind = strings.TrimSpace(rule.MatcherKind)
		rule.MatcherValue = strings.TrimSpace(rule.MatcherValue)
		rule.ReconciliationMode = strings.TrimSpace(rule.ReconciliationMode)
		if rule.ClaimName != nil {
			value := strings.TrimSpace(*rule.ClaimName)
			rule.ClaimName = &value
		}
		if !validUUIDv7(rule.RuleID) || !validUUIDv7(rule.TenantSecurityGroupID) || rule.Priority < 0 ||
			rule.Priority > 1_000_000 || !validFederationEvidenceText(rule.MatcherValue, 1, 1024) ||
			(rule.ReconciliationMode != "additive" && rule.ReconciliationMode != "authoritative") ||
			len(rule.RoleIDs) < 1 || len(rule.RoleIDs) > 32 ||
			(rule.OperatorTeamID == nil) != (rule.OperatorTeamAssignmentEpochID == nil) {
			return false
		}
		if _, duplicate := ruleIDs[rule.RuleID]; duplicate {
			return false
		}
		ruleIDs[rule.RuleID] = struct{}{}
		if rule.MatcherKind == "group_equals" {
			if rule.ClaimName != nil {
				return false
			}
		} else if rule.MatcherKind != "scalar_equals" || rule.ClaimName == nil || !validFederationClaimName(*rule.ClaimName) {
			return false
		}
		if rule.OperatorTeamID != nil && (!validUUIDv7(*rule.OperatorTeamID) ||
			!validUUIDv7(*rule.OperatorTeamAssignmentEpochID)) {
			return false
		}
		slices.SortFunc(rule.RoleIDs, bytesCompareUUID)
		for roleIndex, roleID := range rule.RoleIDs {
			if !validUUIDv7(roleID) || roleIndex > 0 && rule.RoleIDs[roleIndex-1] == roleID {
				return false
			}
		}
	}
	return true
}

func normalizeFederationExtractionPolicy(input *FederationReplaceMappingPolicyInput) bool {
	switch input.Kind {
	case FederationProviderOIDC:
		return len(input.SAMLAttributeRules) == 0 && normalizeFederationOIDCClaimRules(input.OIDCClaimRules)
	case FederationProviderSAML:
		return len(input.OIDCClaimRules) == 0 && normalizeFederationSAMLAttributeRules(input.SAMLAttributeRules)
	default:
		return false
	}
}

func normalizeFederationOIDCClaimRules(rules []FederationOIDCClaimRule) bool {
	if len(rules) < 1 || len(rules) > 64 {
		return false
	}
	claimKeys := make(map[string]struct{}, len(rules))
	profileKeys := make(map[string]struct{})
	singletonKinds := make(map[string]struct{})
	scalarCounts := map[string]int{"id_token": 0, "userinfo": 0}
	profileCounts := map[string]int{"id_token": 0, "userinfo": 0}
	hasUsername, hasAMR := false, false
	for index := range rules {
		rule := &rules[index]
		rule.Source = strings.TrimSpace(rule.Source)
		rule.Kind = strings.TrimSpace(rule.Kind)
		rule.ClaimName = strings.TrimSpace(rule.ClaimName)
		if rule.ProfileField != nil {
			value := strings.TrimSpace(*rule.ProfileField)
			rule.ProfileField = &value
		}
		if (rule.Source != "id_token" && rule.Source != "userinfo") || !validFederationClaimName(rule.ClaimName) {
			return false
		}
		key := rule.Source + "\x00" + rule.ClaimName
		if _, duplicate := claimKeys[key]; duplicate {
			return false
		}
		claimKeys[key] = struct{}{}
		if (rule.Kind == "scalar" || rule.Kind == "profile" || rule.Kind == "groups") &&
			reservedFederationOIDCClaim(rule.ClaimName) {
			return false
		}
		switch rule.Kind {
		case "profile":
			if rule.ProfileField == nil || (*rule.ProfileField != "username" && *rule.ProfileField != "email" &&
				*rule.ProfileField != "display_name") {
				return false
			}
			profileCounts[rule.Source]++
			if profileCounts[rule.Source] > 8 {
				return false
			}
			profileKey := rule.Source + "\x00" + *rule.ProfileField
			if _, duplicate := profileKeys[profileKey]; duplicate {
				return false
			}
			profileKeys[profileKey] = struct{}{}
			hasUsername = hasUsername || *rule.ProfileField == "username"
		case "scalar", "groups":
			if rule.ProfileField != nil {
				return false
			}
			if rule.Kind == "scalar" {
				scalarCounts[rule.Source]++
				if scalarCounts[rule.Source] > 16 {
					return false
				}
			} else {
				key := rule.Source + "\x00groups"
				if _, duplicate := singletonKinds[key]; duplicate {
					return false
				}
				singletonKinds[key] = struct{}{}
			}
		case "acr", "amr":
			if rule.Source != "id_token" || rule.ProfileField != nil || rule.Required || rule.ClaimName != rule.Kind {
				return false
			}
			hasAMR = hasAMR || rule.Kind == "amr"
			key := rule.Source + "\x00" + rule.Kind
			if _, duplicate := singletonKinds[key]; duplicate {
				return false
			}
			singletonKinds[key] = struct{}{}
		default:
			return false
		}
	}
	return hasUsername && hasAMR
}

func normalizeFederationSAMLAttributeRules(rules []FederationSAMLAttributeRule) bool {
	if len(rules) < 1 || len(rules) > 64 {
		return false
	}
	scalarNames := make(map[string]struct{})
	profileFields := make(map[string]struct{})
	hasUsername, hasGroups := false, false
	scalarCount, profileCount := 0, 0
	for index := range rules {
		rule := &rules[index]
		rule.Kind = strings.TrimSpace(rule.Kind)
		rule.AttributeName = strings.TrimSpace(rule.AttributeName)
		rule.AttributeNameFormat = strings.TrimSpace(rule.AttributeNameFormat)
		if rule.ProfileField != nil {
			value := strings.TrimSpace(*rule.ProfileField)
			rule.ProfileField = &value
		}
		if !validFederationSAMLAttributeIdentity(rule.AttributeName, rule.AttributeNameFormat) {
			return false
		}
		switch rule.Kind {
		case "profile":
			if rule.ProfileField == nil || (*rule.ProfileField != "username" && *rule.ProfileField != "email" &&
				*rule.ProfileField != "display_name") {
				return false
			}
			profileCount++
			if profileCount > 16 {
				return false
			}
			if _, duplicate := profileFields[*rule.ProfileField]; duplicate {
				return false
			}
			profileFields[*rule.ProfileField] = struct{}{}
			hasUsername = hasUsername || *rule.ProfileField == "username"
		case "scalar":
			if rule.ProfileField != nil {
				return false
			}
			scalarCount++
			if scalarCount > 32 {
				return false
			}
			// The runtime emits scalar observations by Name, so accepting the
			// same Name under different NameFormats would be ambiguous.
			if _, duplicate := scalarNames[rule.AttributeName]; duplicate {
				return false
			}
			scalarNames[rule.AttributeName] = struct{}{}
		case "groups":
			if rule.ProfileField != nil || hasGroups {
				return false
			}
			hasGroups = true
		default:
			return false
		}
	}
	return hasUsername
}

func validFederationSAMLAttributeIdentity(name, format string) bool {
	return len(name) <= 512 && len(format) <= 512 && validText(name, 1, 512) && validText(format, 1, 512) &&
		validFederationXML10Text(name) && validFederationXML10Text(format)
}

func normalizeFederationMappingPolicyProjection(value *FederationMappingPolicy, tenantID, providerID uuid.UUID) bool {
	if value == nil || value.TenantID != tenantID || value.ProviderID != providerID || !validUUIDv7(tenantID) ||
		!validFederationResourceVersion(value.ProviderVersion) || !validFederationRevision(value.MappingRevision) {
		return false
	}
	input := FederationReplaceMappingPolicyInput{
		Kind: value.Kind, OIDCClaimRules: value.OIDCClaimRules,
		SAMLAttributeRules: value.SAMLAttributeRules, Rules: value.Rules,
	}
	if !normalizeFederationExtractionPolicy(&input) || !normalizeFederationMappingRules(input.Rules) {
		return false
	}
	value.OIDCClaimRules, value.SAMLAttributeRules, value.Rules = input.OIDCClaimRules, input.SAMLAttributeRules, input.Rules
	return true
}

func normalizeFederationAssurancePolicyProjection(value *FederationAssurancePolicy, tenantID, providerID uuid.UUID) bool {
	return value != nil && value.TenantID == tenantID && value.ProviderID == providerID && validUUIDv7(tenantID) &&
		validFederationResourceVersion(value.ProviderVersion) && validFederationRevision(value.AssurancePolicyRevision) &&
		normalizeFederationAssuranceRules(value.Kind, value.Rules)
}

func normalizeFederationAssurancePolicy(
	providerID uuid.UUID,
	input FederationReplaceAssurancePolicyInput,
) (FederationReplaceAssurancePolicyInput, int64, error) {
	version, err := validateIncrementableFederationVersion(providerID, input.ExpectedEntityTag, input.Audit)
	input.Reason = strings.TrimSpace(input.Reason)
	if err != nil || !validFederationAuditReason(input.Reason) || !normalizeFederationAssuranceRules(input.Kind, input.Rules) {
		if err != nil {
			return FederationReplaceAssurancePolicyInput{}, 0, err
		}
		return FederationReplaceAssurancePolicyInput{}, 0, ErrInvalidInput
	}
	return input, version, nil
}

func normalizeFederationAssuranceRules(kind FederationProviderKind, rules []FederationAssuranceRule) bool {
	if len(rules) > 128 || kind == FederationProviderSAML && len(rules) > 64 {
		return false
	}
	ids := make(map[uuid.UUID]struct{}, len(rules))
	samlExactValues := make(map[string]struct{}, len(rules))
	for index := range rules {
		rule := &rules[index]
		rule.Level = strings.TrimSpace(rule.Level)
		if rule.ExactValue != nil {
			value := strings.TrimSpace(*rule.ExactValue)
			rule.ExactValue = &value
		}
		if !validUUIDv7(rule.RuleID) || (rule.Level != "mfa" && rule.Level != "phishing_resistant") ||
			rule.MaximumAuthenticationAgeSeconds < 60 || rule.MaximumAuthenticationAgeSeconds > 2_592_000 ||
			len(rule.RequiredValues) > 128 {
			return false
		}
		if _, duplicate := ids[rule.RuleID]; duplicate {
			return false
		}
		ids[rule.RuleID] = struct{}{}
		if rule.ExactValue != nil && !validFederationEvidenceText(*rule.ExactValue, 1, 4096) {
			return false
		}
		for valueIndex := range rule.RequiredValues {
			rule.RequiredValues[valueIndex] = strings.TrimSpace(rule.RequiredValues[valueIndex])
			if !validFederationEvidenceText(rule.RequiredValues[valueIndex], 1, 4096) {
				return false
			}
		}
		slices.Sort(rule.RequiredValues)
		for valueIndex := 1; valueIndex < len(rule.RequiredValues); valueIndex++ {
			if rule.RequiredValues[valueIndex-1] == rule.RequiredValues[valueIndex] {
				return false
			}
		}
	}
	switch kind {
	case FederationProviderOIDC:
		for _, rule := range rules {
			if rule.ExactValue == nil && len(rule.RequiredValues) == 0 {
				return false
			}
		}
	case FederationProviderSAML:
		for _, rule := range rules {
			if rule.ExactValue == nil || len(rule.RequiredValues) != 0 ||
				!validFederationXML10Text(*rule.ExactValue) {
				return false
			}
			if _, duplicate := samlExactValues[*rule.ExactValue]; duplicate {
				return false
			}
			samlExactValues[*rule.ExactValue] = struct{}{}
		}
	default:
		return false
	}
	return true
}

func normalizeFederationOIDCTrustDocuments(
	providerID uuid.UUID,
	input FederationOIDCTrustDocumentsInput,
) (FederationOIDCTrustDocumentsInput, int64, error) {
	version, err := validateIncrementableFederationVersion(providerID, input.ExpectedEntityTag, input.Audit)
	input.Reason = strings.TrimSpace(input.Reason)
	if err != nil || !validFederationAuditReason(input.Reason) ||
		(input.ClientAuthentication != federatedoidc.ClientSecretBasic &&
			input.ClientAuthentication != federatedoidc.ClientSecretPost) ||
		len(input.SigningAlgorithms) < 1 || len(input.SigningAlgorithms) > 10 {
		if err != nil {
			return FederationOIDCTrustDocumentsInput{}, 0, err
		}
		return FederationOIDCTrustDocumentsInput{}, 0, ErrInvalidInput
	}
	for _, algorithm := range input.SigningAlgorithms {
		switch algorithm {
		case federatedoidc.SigningRS256, federatedoidc.SigningRS384, federatedoidc.SigningRS512,
			federatedoidc.SigningPS256, federatedoidc.SigningPS384, federatedoidc.SigningPS512,
			federatedoidc.SigningES256, federatedoidc.SigningES384, federatedoidc.SigningES512,
			federatedoidc.SigningEdDSA:
		default:
			return FederationOIDCTrustDocumentsInput{}, 0, ErrInvalidInput
		}
	}
	slices.Sort(input.SigningAlgorithms)
	for index := 1; index < len(input.SigningAlgorithms); index++ {
		if input.SigningAlgorithms[index-1] == input.SigningAlgorithms[index] {
			return FederationOIDCTrustDocumentsInput{}, 0, ErrInvalidInput
		}
	}
	return input, version, nil
}

func validFederationClaimName(value string) bool {
	if len(value) < 1 || len(value) > 256 {
		return false
	}
	for _, character := range []byte(value) {
		if character < 0x21 || character > 0x7e || character == '"' || character == '\\' {
			return false
		}
	}
	return true
}

func reservedFederationOIDCClaim(value string) bool {
	_, reserved := reservedFederationOIDCSecurityClaims[value]
	return reserved
}

func federationOIDCClaimRulesUseUserInfo(rules []FederationOIDCClaimRule) bool {
	for _, rule := range rules {
		if rule.Source == "userinfo" {
			return true
		}
	}
	return false
}

func federationSAMLAssuranceMatchesContexts(rules []FederationAssuranceRule, contexts []string) bool {
	requested := make(map[string]struct{}, len(contexts))
	for _, context := range contexts {
		requested[context] = struct{}{}
	}
	for _, rule := range rules {
		if rule.ExactValue == nil {
			return false
		}
		if _, exists := requested[*rule.ExactValue]; !exists {
			return false
		}
	}
	return true
}

func cloneFederationProvider(value FederationProvider) FederationProvider {
	value.FederationProviderSummary = cloneFederationProviderSummary(value.FederationProviderSummary)
	if value.OIDC != nil {
		configuration := *value.OIDC
		configuration.ExtraScopes = append([]string(nil), value.OIDC.ExtraScopes...)
		value.OIDC = &configuration
	}
	if value.SAML != nil {
		configuration := *value.SAML
		configuration.RequestedAuthnContexts = append([]string(nil), value.SAML.RequestedAuthnContexts...)
		configuration.SubjectAttributeName = cloneFederationString(value.SAML.SubjectAttributeName)
		configuration.SubjectAttributeNameFormat = cloneFederationString(value.SAML.SubjectAttributeNameFormat)
		value.SAML = &configuration
	}
	return value
}

func cloneFederationProviderSummary(value FederationProviderSummary) FederationProviderSummary {
	if value.ArchivedAt != nil {
		archivedAt := *value.ArchivedAt
		value.ArchivedAt = &archivedAt
	}
	return value
}

func cloneFederationMappingPolicy(value FederationMappingPolicy) FederationMappingPolicy {
	value.OIDCClaimRules = slices.Clone(value.OIDCClaimRules)
	for index := range value.OIDCClaimRules {
		value.OIDCClaimRules[index].ProfileField = cloneFederationString(value.OIDCClaimRules[index].ProfileField)
	}
	value.SAMLAttributeRules = slices.Clone(value.SAMLAttributeRules)
	for index := range value.SAMLAttributeRules {
		value.SAMLAttributeRules[index].ProfileField = cloneFederationString(value.SAMLAttributeRules[index].ProfileField)
	}
	value.Rules = slices.Clone(value.Rules)
	for index := range value.Rules {
		value.Rules[index].ClaimName = cloneFederationString(value.Rules[index].ClaimName)
		value.Rules[index].RoleIDs = slices.Clone(value.Rules[index].RoleIDs)
		value.Rules[index].OperatorTeamID = cloneFederationUUID(value.Rules[index].OperatorTeamID)
		value.Rules[index].OperatorTeamAssignmentEpochID = cloneFederationUUID(
			value.Rules[index].OperatorTeamAssignmentEpochID,
		)
	}
	return value
}

func cloneFederationReplaceMappingPolicyInput(
	value FederationReplaceMappingPolicyInput,
) FederationReplaceMappingPolicyInput {
	cloned := cloneFederationMappingPolicy(FederationMappingPolicy{
		OIDCClaimRules: value.OIDCClaimRules, SAMLAttributeRules: value.SAMLAttributeRules, Rules: value.Rules,
	})
	value.OIDCClaimRules = cloned.OIDCClaimRules
	value.SAMLAttributeRules = cloned.SAMLAttributeRules
	value.Rules = cloned.Rules
	value.ExpectedEntityTag = cloneFederationString(value.ExpectedEntityTag)
	return value
}

func cloneFederationAssurancePolicy(value FederationAssurancePolicy) FederationAssurancePolicy {
	value.Rules = slices.Clone(value.Rules)
	for index := range value.Rules {
		value.Rules[index].ExactValue = cloneFederationString(value.Rules[index].ExactValue)
		value.Rules[index].RequiredValues = slices.Clone(value.Rules[index].RequiredValues)
	}
	return value
}

func cloneFederationUUID(value *uuid.UUID) *uuid.UUID {
	if value == nil {
		return nil
	}
	copyValue := *value
	return &copyValue
}

func cloneFederationString(value *string) *string {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
