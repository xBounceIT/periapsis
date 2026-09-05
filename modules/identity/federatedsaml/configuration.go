package federatedsaml

import (
	"crypto/sha256"
	"encoding/binary"
	"slices"
	"strings"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

func normalizeConfiguration(input Configuration, observedAt time.Time, limits Limits) (Configuration, [sha256.Size]byte, error) {
	configuration := input
	configuration.DecryptionKeyVersions = append([]uint32(nil), input.DecryptionKeyVersions...)
	configuration.DirectPlatformDecryptionKeyRevisions = append(
		[]uint64(nil), input.DirectPlatformDecryptionKeyRevisions...,
	)
	configuration.RequestedAuthnContexts = append([]string(nil), input.RequestedAuthnContexts...)
	configuration.Mapping.Scalars = append([]ScalarAttributeRule(nil), input.Mapping.Scalars...)
	configuration.Mapping.Profiles = append([]ProfileAttributeRule(nil), input.Mapping.Profiles...)
	if input.Mapping.Groups != nil {
		groupRule := *input.Mapping.Groups
		configuration.Mapping.Groups = &groupRule
	}
	configuration.TrustRules = append([]AuthnContextTrustRule(nil), input.TrustRules...)
	if !validCeremonyAuthority(
		configuration.Authority, configuration.Provider, configuration.BindingID,
		configuration.BindingRevision, configuration.MappingRevision, configuration.AuthorizationRevision,
		configuration.PlatformLoginRevision, configuration.PlanRevision,
	) ||
		!validPersistentRevision(configuration.ProviderRevision) ||
		!validPersistentRevision(configuration.ConfigurationRevision) ||
		!validPersistentRevision(configuration.SecurityRevision) ||
		!validPersistentRevision(configuration.AssurancePolicyRevision) ||
		!validPersistentRevision(configuration.SPKeyRevision) ||
		!validBoundedString(configuration.SPEntityID, maximumEntityIDBytes) ||
		!canonicalACSURL(configuration.ACSURL, configuration.Authority) || !configuration.Metadata.valid ||
		!validPersistentRevision(configuration.Metadata.revision) || configuration.Metadata.digest == ([sha256.Size]byte{}) ||
		configuration.Metadata.entityID == configuration.SPEntityID ||
		configuration.Metadata.ssoRedirectURL == "" || !configuration.Metadata.validUntil.After(observedAt) ||
		!validRedirectAlgorithm(configuration.RedirectSignatureAlgorithm) ||
		!validSignaturePolicy(configuration.SignaturePolicy) ||
		!validEncryptionConfiguration(
			configuration.Authority, configuration.EncryptionPolicy,
			configuration.DecryptionKeyVersions, configuration.DirectPlatformDecryptionKeyRevisions,
		) ||
		configuration.ClockSkew < 0 || configuration.ClockSkew > 5*time.Minute ||
		configuration.MaxAuthenticationAge < time.Minute || configuration.MaxAuthenticationAge > 24*time.Hour ||
		!alignedDuration(configuration.ClockSkew) || !alignedDuration(configuration.MaxAuthenticationAge) ||
		len(configuration.RequestedAuthnContexts) == 0 || len(configuration.RequestedAuthnContexts) > 32 ||
		len(configuration.Mapping.Scalars) > limits.MaxMappedScalars ||
		len(configuration.Mapping.Profiles) > limits.MaxMappedProfiles || len(configuration.TrustRules) > 64 {
		return Configuration{}, [sha256.Size]byte{}, ErrInvalidConfiguration
	}
	if !validDecryptionKeyOrder(configuration) ||
		!validUniqueStrings(configuration.RequestedAuthnContexts, maximumAuthnContextBytes) ||
		!validSubjectPolicy(configuration.Subject) ||
		!normalizeMappingPolicy(&configuration.Mapping) ||
		!validMappingAuthority(configuration.Authority, configuration.Mapping) ||
		!normalizeTrustRules(configuration.TrustRules, configuration.RequestedAuthnContexts) {
		return Configuration{}, [sha256.Size]byte{}, ErrInvalidConfiguration
	}
	slices.Sort(configuration.RequestedAuthnContexts)
	return configuration, configurationDigest(configuration), nil
}

func validRedirectAlgorithm(value RedirectSignatureAlgorithm) bool {
	switch value {
	case RedirectRSASHA256, RedirectRSASHA384, RedirectRSASHA512,
		RedirectECDSASHA256, RedirectECDSASHA384, RedirectECDSASHA512:
		return true
	default:
		return false
	}
}

func validSignaturePolicy(value SignaturePolicy) bool {
	return value == SignedAssertion || value == SignedResponse || value == SignedBoth
}

func validEncryptionConfiguration(
	authority CeremonyAuthority,
	policy EncryptionPolicy,
	tenantVersions []uint32,
	directRevisions []uint64,
) bool {
	if !validAuthorityValue(authority) || authority == TenantCeremonyAuthority && len(directRevisions) != 0 ||
		authority == DirectPlatformCeremonyAuthority && len(tenantVersions) != 0 {
		return false
	}
	count := len(tenantVersions)
	if authority == DirectPlatformCeremonyAuthority {
		count = len(directRevisions)
	}
	switch policy {
	case EncryptionDisabled:
		return count == 0
	case EncryptionOptional, EncryptionRequired:
		return count > 0 && count <= 8
	default:
		return false
	}
}

func validDecryptionKeyOrder(configuration Configuration) bool {
	if configuration.Authority == TenantCeremonyAuthority {
		return strictSortedUniqueUint32(configuration.DecryptionKeyVersions)
	}
	if configuration.Authority != DirectPlatformCeremonyAuthority {
		return false
	}
	return strictSortedUniqueUint64(configuration.DirectPlatformDecryptionKeyRevisions)
}

func strictSortedUniqueUint32(values []uint32) bool {
	for index, value := range values {
		if value == 0 || index > 0 && values[index-1] >= value {
			return false
		}
	}
	return true
}

func strictSortedUniqueUint64(values []uint64) bool {
	for index, value := range values {
		if !validPersistentRevision(value) || index > 0 && values[index-1] >= value {
			return false
		}
	}
	return true
}

func validUniqueStrings(values []string, maximum int) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validBoundedString(value, maximum) {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func validSubjectPolicy(value SubjectPolicy) bool {
	switch value.Source {
	case SubjectPersistentNameID:
		return value.AttributeName == "" && value.AttributeNameFormat == ""
	case SubjectImmutableAttribute:
		return validAttributeIdentity(value.AttributeName, value.AttributeNameFormat)
	default:
		return false
	}
}

func validAttributeIdentity(name, format string) bool {
	return validBoundedString(name, maximumAttributeNameBytes) &&
		validBoundedString(format, maximumAttributeNameBytes)
}

func normalizeMappingPolicy(policy *AttributeMappingPolicy) bool {
	if policy == nil {
		return false
	}
	seenScalar := make(map[string]struct{}, len(policy.Scalars))
	for _, rule := range policy.Scalars {
		if !validAttributeIdentity(rule.Name, rule.NameFormat) {
			return false
		}
		// Scalar observations are keyed by Name at the application mapping
		// boundary, so accepting the same Name under another NameFormat would
		// collapse two distinct SAML attributes into one ambiguous value.
		if _, duplicate := seenScalar[rule.Name]; duplicate {
			return false
		}
		seenScalar[rule.Name] = struct{}{}
	}
	seenProfile := make(map[ProfileField]struct{}, len(policy.Profiles))
	for _, rule := range policy.Profiles {
		if !validAttributeIdentity(rule.Name, rule.NameFormat) || !validProfileField(rule.Field) {
			return false
		}
		if _, duplicate := seenProfile[rule.Field]; duplicate {
			return false
		}
		seenProfile[rule.Field] = struct{}{}
	}
	if policy.Groups != nil && !validAttributeIdentity(policy.Groups.Name, policy.Groups.NameFormat) {
		return false
	}
	slices.SortFunc(policy.Scalars, func(left, right ScalarAttributeRule) int {
		if result := strings.Compare(left.NameFormat, right.NameFormat); result != 0 {
			return result
		}
		return strings.Compare(left.Name, right.Name)
	})
	slices.SortFunc(policy.Profiles, func(left, right ProfileAttributeRule) int {
		return strings.Compare(string(left.Field), string(right.Field))
	})
	return true
}

func validMappingAuthority(authority CeremonyAuthority, policy AttributeMappingPolicy) bool {
	if authority == TenantCeremonyAuthority {
		return true
	}
	return authority == DirectPlatformCeremonyAuthority && len(policy.Scalars) == 0 &&
		len(policy.Profiles) == 0 && policy.Groups == nil
}

func validProfileField(value ProfileField) bool {
	return value == ProfileUsername || value == ProfileEmail || value == ProfileDisplayName
}

func normalizeTrustRules(rules []AuthnContextTrustRule, requested []string) bool {
	seen := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		if !slices.Contains(requested, rule.ClassRef) || rule.Level <= identity.AssurancePrimary ||
			rule.Level > identity.AssurancePhishingResistant || rule.Revision < 1 ||
			rule.MaxAge < time.Minute || rule.MaxAge > 24*time.Hour || !alignedDuration(rule.MaxAge) {
			return false
		}
		if _, duplicate := seen[rule.ClassRef]; duplicate {
			return false
		}
		seen[rule.ClassRef] = struct{}{}
	}
	slices.SortFunc(rules, func(left, right AuthnContextTrustRule) int {
		return strings.Compare(left.ClassRef, right.ClassRef)
	})
	return true
}

func configurationDigest(configuration Configuration) [sha256.Size]byte {
	fields := make([][]byte, 0, 48)
	fields = append(fields,
		[]byte{byte(configuration.Provider.Scope)}, configuration.Provider.TenantID[:],
		configuration.Provider.ProviderID[:], configuration.BindingID[:],
		u64(configuration.ProviderRevision), u64(configuration.BindingRevision), u64(configuration.ConfigurationRevision),
		u64(configuration.SecurityRevision), u64(configuration.MappingRevision),
		u64(configuration.AuthorizationRevision), u64(configuration.AssurancePolicyRevision), []byte(configuration.SPEntityID),
		[]byte(configuration.ACSURL), u64(configuration.Metadata.revision),
		configuration.Metadata.digest[:], u64(configuration.SPKeyRevision),
		[]byte(configuration.RedirectSignatureAlgorithm), []byte(configuration.SignaturePolicy),
		[]byte(configuration.EncryptionPolicy), u64(uint64(configuration.ClockSkew)),
		u64(uint64(configuration.MaxAuthenticationAge)), []byte(configuration.Subject.Source),
		[]byte(configuration.Subject.AttributeName), []byte(configuration.Subject.AttributeNameFormat),
	)
	if configuration.Authority == DirectPlatformCeremonyAuthority {
		fields = append(fields,
			[]byte("direct-platform"), u64(configuration.PlatformLoginRevision), u64(configuration.PlanRevision),
		)
	}
	for _, version := range configuration.DecryptionKeyVersions {
		fields = append(fields, u64(uint64(version)))
	}
	for _, revision := range configuration.DirectPlatformDecryptionKeyRevisions {
		fields = append(fields, u64(revision))
	}
	for _, context := range configuration.RequestedAuthnContexts {
		fields = append(fields, []byte(context))
	}
	for _, rule := range configuration.Mapping.Scalars {
		fields = append(fields, []byte("scalar"), []byte(rule.Name), []byte(rule.NameFormat), boolByte(rule.Required))
	}
	for _, rule := range configuration.Mapping.Profiles {
		fields = append(fields, []byte("profile"), []byte(rule.Name), []byte(rule.NameFormat), []byte(rule.Field), boolByte(rule.Required))
	}
	if configuration.Mapping.Groups != nil {
		fields = append(fields, []byte("groups"), []byte(configuration.Mapping.Groups.Name),
			[]byte(configuration.Mapping.Groups.NameFormat), boolByte(configuration.Mapping.Groups.Required))
	}
	for _, rule := range configuration.TrustRules {
		fields = append(fields, []byte("trust"), []byte(rule.ClassRef), []byte{byte(rule.Level)}, u64(uint64(rule.Revision)), u64(uint64(rule.MaxAge)))
	}
	return digestFields(fields...)
}

func u64(value uint64) []byte {
	result := make([]byte, 8)
	binary.BigEndian.PutUint64(result, value)
	return result
}

func boolByte(value bool) []byte {
	if value {
		return []byte{1}
	}
	return []byte{0}
}

func transactionPins(configuration Configuration, digest [sha256.Size]byte) TransactionPins {
	return TransactionPins{
		Authority: configuration.Authority, Provider: configuration.Provider, BindingID: configuration.BindingID,
		ProviderRevision: configuration.ProviderRevision, BindingRevision: configuration.BindingRevision,
		PlatformLoginRevision: configuration.PlatformLoginRevision,
		ConfigurationRevision: configuration.ConfigurationRevision,
		SecurityRevision:      configuration.SecurityRevision, MappingRevision: configuration.MappingRevision,
		PlanRevision:            configuration.PlanRevision,
		AuthorizationRevision:   configuration.AuthorizationRevision,
		AssurancePolicyRevision: configuration.AssurancePolicyRevision,
		MetadataRevision:        configuration.Metadata.revision, MetadataDigest: configuration.Metadata.digest,
		SPKeyRevision: configuration.SPKeyRevision, ConfigurationDigest: digest,
	}
}

func samePins(left, right TransactionPins) bool {
	return left.Authority == right.Authority && left.Provider == right.Provider && left.BindingID == right.BindingID &&
		left.ProviderRevision == right.ProviderRevision && left.BindingRevision == right.BindingRevision &&
		left.PlatformLoginRevision == right.PlatformLoginRevision &&
		left.ConfigurationRevision == right.ConfigurationRevision &&
		left.SecurityRevision == right.SecurityRevision && left.PlanRevision == right.PlanRevision &&
		left.MappingRevision == right.MappingRevision &&
		left.AuthorizationRevision == right.AuthorizationRevision &&
		left.AssurancePolicyRevision == right.AssurancePolicyRevision &&
		left.MetadataRevision == right.MetadataRevision && compareDigest(left.MetadataDigest, right.MetadataDigest) &&
		left.SPKeyRevision == right.SPKeyRevision && compareDigest(left.ConfigurationDigest, right.ConfigurationDigest)
}
