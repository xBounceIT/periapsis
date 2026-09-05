package identityprovider

import (
	"bytes"
	"cmp"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

const (
	defaultPageSize        = 50
	maximumPageSize        = 100
	maximumResourceVersion = 2_147_483_647
	maximumBindSecretBytes = 8*1024 - 16
)

var (
	providerKeyPattern            = regexp.MustCompile(`^[a-z][a-z0-9_-]{2,63}$`)
	idempotencyKeyPattern         = regexp.MustCompile(`^[A-Za-z0-9._~-]{16,128}$`)
	attributeNamePattern          = regexp.MustCompile(`^(?:[A-Za-z][A-Za-z0-9-]{0,127}|[0-9]+(?:\.[0-9]+)+)$`)
	federationAuditSecretPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)-----BEGIN[[:space:]]+[^-]*PRIVATE[[:space:]]+KEY-----`),
		regexp.MustCompile(`(?i)(^|[^[:alnum:]_])(bearer|basic)[[:space:]]+[A-Za-z0-9+/._~=-]{12,}`),
		regexp.MustCompile(`(?i)(password|passwd|passphrase|secret|token|api[ _-]?key|assertion|recovery[ _-]?code|totp)[[:space:]]*[:=][[:space:]]*[^[:space:]]{12,}`),
		regexp.MustCompile(`(^|[^A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`),
	}
)

func normalizePage(input PageInput) (PageInput, error) {
	if input.Limit == 0 {
		input.Limit = defaultPageSize
	}
	if input.Limit < 1 || input.Limit > maximumPageSize ||
		input.After != nil && !validUUIDv7(*input.After) {
		return PageInput{}, ErrInvalidInput
	}
	if input.After != nil {
		value := *input.After
		input.After = &value
	}
	return input, nil
}

func normalizeCreate(input CreateInput) (CreateInput, error) {
	input.Key = strings.TrimSpace(input.Key)
	input.DisplayName = strings.TrimSpace(input.DisplayName)
	input.Description = strings.TrimSpace(input.Description)
	configuration, endpoints, err := normalizeConfiguration(input.Configuration, input.Endpoints)
	if err != nil || !providerKeyPattern.MatchString(input.Key) ||
		!validText(input.DisplayName, 1, 120) || !validText(input.Description, 0, 1000) ||
		!idempotencyKeyPattern.MatchString(input.IdempotencyKey) || !validAudit(input.Audit, true) {
		return CreateInput{}, ErrInvalidInput
	}
	input.Configuration, input.Endpoints = configuration, endpoints
	return input, nil
}

func normalizeUpdate(providerID uuid.UUID, input UpdateInput) (UpdateInput, int64, error) {
	version, err := validateVersioned(providerID, input.ExpectedEntityTag, input.Audit)
	if err != nil {
		return UpdateInput{}, 0, err
	}
	input.Key = strings.TrimSpace(input.Key)
	input.DisplayName = strings.TrimSpace(input.DisplayName)
	input.Description = strings.TrimSpace(input.Description)
	configuration, endpoints, err := normalizeConfiguration(input.Configuration, input.Endpoints)
	if err != nil || !providerKeyPattern.MatchString(input.Key) ||
		!validText(input.DisplayName, 1, 120) || !validText(input.Description, 0, 1000) {
		return UpdateInput{}, 0, ErrInvalidInput
	}
	input.Configuration, input.Endpoints = configuration, endpoints
	return input, version, nil
}

func normalizeArchive(providerID uuid.UUID, input ArchiveInput) (ArchiveInput, int64, error) {
	version, err := validateVersioned(providerID, input.ExpectedEntityTag, input.Audit)
	if err != nil {
		return ArchiveInput{}, 0, err
	}
	input.Reason = strings.TrimSpace(input.Reason)
	if !validText(input.Reason, 1, 500) {
		return ArchiveInput{}, 0, ErrInvalidInput
	}
	return input, version, nil
}

func normalizeRotateBindSecret(providerID uuid.UUID, input RotateBindSecretInput) (RotateBindSecretInput, int64, error) {
	version, err := validateVersioned(providerID, input.ExpectedEntityTag, input.Audit)
	if err != nil {
		return RotateBindSecretInput{}, 0, err
	}
	if len(input.Secret) < 1 || len(input.Secret) > maximumBindSecretBytes {
		return RotateBindSecretInput{}, 0, ErrInvalidInput
	}
	return input, version, nil
}

func normalizeClearBindSecret(providerID uuid.UUID, input ClearBindSecretInput) (ClearBindSecretInput, int64, error) {
	version, err := validateVersioned(providerID, input.ExpectedEntityTag, input.Audit)
	if err != nil {
		return ClearBindSecretInput{}, 0, err
	}
	input.Reason = strings.TrimSpace(input.Reason)
	if !validText(input.Reason, 1, 500) {
		return ClearBindSecretInput{}, 0, ErrInvalidInput
	}
	return input, version, nil
}

func validateVersioned(providerID uuid.UUID, entityTag *string, audit authorization.AuditContext) (int64, error) {
	if !validUUIDv7(providerID) || !validAudit(audit, true) {
		return 0, ErrInvalidInput
	}
	if entityTag == nil {
		return 0, ErrPreconditionRequired
	}
	return parseEntityTag(*entityTag)
}

func normalizeConfiguration(configuration Configuration, endpoints []Endpoint) (Configuration, []Endpoint, error) {
	configuration.BindDN = strings.TrimSpace(configuration.BindDN)
	configuration.UserBaseDN = strings.TrimSpace(configuration.UserBaseDN)
	configuration.UserSearchFilter = strings.TrimSpace(configuration.UserSearchFilter)
	configuration.FirstNameAttribute = strings.TrimSpace(configuration.FirstNameAttribute)
	configuration.LastNameAttribute = strings.TrimSpace(configuration.LastNameAttribute)
	configuration.DisplayNameAttribute = strings.TrimSpace(configuration.DisplayNameAttribute)
	configuration.UsernameAttribute = strings.TrimSpace(configuration.UsernameAttribute)
	configuration.ImmutableSubjectAttribute = strings.TrimSpace(configuration.ImmutableSubjectAttribute)

	var err error
	if configuration.CustomCAPEM, err = normalizeOptional(configuration.CustomCAPEM); err != nil {
		return Configuration{}, nil, err
	}
	for _, value := range []**string{
		&configuration.GroupBaseDN, &configuration.GroupSearchFilter,
		&configuration.UserDNTemplate, &configuration.AlternateUsernameAttribute,
		&configuration.EmailAttribute, &configuration.GroupMembershipAttribute,
		&configuration.POSIXMemberUIDAttribute, &configuration.POSIXGIDNumberAttribute,
		&configuration.AccountStatusAttribute, &configuration.AccountDisabledValue,
	} {
		*value, err = normalizeOptional(*value)
		if err != nil {
			return Configuration{}, nil, err
		}
	}

	if !knownTemplate(configuration.Template) || !configuration.VerifyCertificate ||
		!validDN(configuration.BindDN) || !validDN(configuration.UserBaseDN) ||
		configuration.GroupBaseDN != nil && !validDN(*configuration.GroupBaseDN) ||
		!validLDAPTemplates(configuration) ||
		configuration.PageSize < 1 || configuration.PageSize > 1_000 ||
		configuration.MaxPages < 1 || configuration.MaxPages > 1_000 ||
		configuration.MaxEntries < 1 || configuration.MaxEntries > 100_000 ||
		configuration.MaxResponseBytes < 1_024 || configuration.MaxResponseBytes > 52_428_800 ||
		configuration.MaxGroups < 1 || configuration.MaxGroups > 10_000 ||
		!validReferral(configuration.ReferralMode, configuration.MaxReferralHops) ||
		!validNestedGroups(configuration.NestedGroupMode, configuration.MaxNestedGroupDepth) ||
		!validRequiredAttribute(configuration.FirstNameAttribute) ||
		!validRequiredAttribute(configuration.LastNameAttribute) ||
		!validRequiredAttribute(configuration.DisplayNameAttribute) ||
		!validRequiredAttribute(configuration.UsernameAttribute) ||
		!validRequiredAttribute(configuration.ImmutableSubjectAttribute) ||
		!validOptionalAttribute(configuration.AlternateUsernameAttribute) ||
		!validOptionalAttribute(configuration.EmailAttribute) ||
		!validOptionalAttribute(configuration.GroupMembershipAttribute) ||
		!validOptionalAttribute(configuration.POSIXMemberUIDAttribute) ||
		!validOptionalAttribute(configuration.POSIXGIDNumberAttribute) ||
		!knownSubjectFormat(configuration.ImmutableSubjectFormat) ||
		!validAccountStatus(configuration) || !knownJITMode(configuration.JITMode) ||
		!knownNoMatchPolicy(configuration.NoMatchPolicy) ||
		!validDeprovisionPolicy(configuration.DeprovisionMode, configuration.DeprovisionGraceSeconds) ||
		!validSyncInterval(configuration.SyncIntervalSeconds) {
		return Configuration{}, nil, ErrInvalidInput
	}
	normalizedEndpoints, err := normalizeEndpoints(endpoints)
	if err != nil {
		return Configuration{}, nil, err
	}
	if !validReferralEndpoints(configuration.ReferralMode, normalizedEndpoints) {
		return Configuration{}, nil, ErrInvalidInput
	}
	return configuration, normalizedEndpoints, nil
}

// NormalizeLDAPConfiguration exposes the canonical tenant-neutral directory
// validation used by platform-global LDAP administration and authentication.
// The returned values are owned copies and are safe to retain.
func NormalizeLDAPConfiguration(
	configuration Configuration,
	endpoints []Endpoint,
) (Configuration, []Endpoint, error) {
	return normalizeConfiguration(configuration, endpoints)
}

func validReferralEndpoints(mode ReferralMode, endpoints []Endpoint) bool {
	allowed := 0
	for _, endpoint := range endpoints {
		if endpoint.ReferralAllowed {
			if !endpoint.Enabled {
				return false
			}
			allowed++
		}
	}
	switch mode {
	case ReferralModeDisabled:
		return allowed == 0
	case ReferralModeConfiguredEndpoints:
		return allowed > 0
	default:
		return false
	}
}

func normalizeEndpoints(values []Endpoint) ([]Endpoint, error) {
	if len(values) < 1 || len(values) > 8 {
		return nil, ErrInvalidInput
	}
	result := append([]Endpoint(nil), values...)
	slices.SortFunc(result, func(left, right Endpoint) int { return cmp.Compare(left.Priority, right.Priority) })
	priorities := make(map[int]struct{}, len(result))
	identities := make(map[string]struct{}, len(result))
	for index := range result {
		value := result[index]
		if value.Priority < 1 || value.Priority > 8 {
			return nil, ErrInvalidInput
		}
		if _, duplicate := priorities[value.Priority]; duplicate {
			return nil, ErrInvalidInput
		}
		priorities[value.Priority] = struct{}{}
		identity := string(value.Transport) + "\x00" + value.Host + "\x00" + strconv.Itoa(int(value.Port))
		if _, duplicate := identities[identity]; duplicate {
			return nil, ErrInvalidInput
		}
		identities[identity] = struct{}{}
	}
	return result, nil
}

func validDN(value string) bool {
	if !validText(value, 1, 2048) || len(value) > 2048*utf8.UTFMax {
		return false
	}
	_, err := ldap.ParseDN(value)
	return err == nil
}

func validLDAPTemplates(configuration Configuration) bool {
	if !validText(configuration.UserSearchFilter, 1, 4096) ||
		ldapTemplateIsInvalid(identity.LDAPTemplateContextUserSearchFilter, configuration.UserSearchFilter) {
		return false
	}
	if configuration.UserDNTemplate != nil &&
		(!validText(*configuration.UserDNTemplate, 1, 2048) ||
			ldapTemplateIsInvalid(identity.LDAPTemplateContextUserDN, *configuration.UserDNTemplate)) {
		return false
	}

	switch configuration.NestedGroupMode {
	case NestedGroupModeDisabled:
		return configuration.GroupSearchFilter == nil
	case NestedGroupModeActiveDirectory, NestedGroupModeReverseSearch:
		if configuration.GroupSearchFilter == nil || !validText(*configuration.GroupSearchFilter, 1, 4096) {
			return false
		}
		return !ldapTemplateIsInvalid(
			identity.LDAPTemplateContextReverseGroupSearchFilter,
			*configuration.GroupSearchFilter,
		)
	case NestedGroupModePOSIXMemberUID:
		if configuration.GroupSearchFilter == nil || !validText(*configuration.GroupSearchFilter, 1, 4096) {
			return false
		}
		return !ldapTemplateIsInvalid(
			identity.LDAPTemplateContextPOSIXGroupSearchFilter,
			*configuration.GroupSearchFilter,
		)
	default:
		return false
	}
}

func ldapTemplateIsInvalid(context identity.LDAPTemplateContext, value string) bool {
	_, err := identity.CompileLDAPTemplate(context, value)
	return err != nil
}

func validRequiredAttribute(value string) bool {
	return attributeNamePattern.MatchString(value)
}

func validOptionalAttribute(value *string) bool {
	return value == nil || validRequiredAttribute(*value)
}

func validReferral(mode ReferralMode, hops int) bool {
	return mode == ReferralModeDisabled && hops == 0 ||
		mode == ReferralModeConfiguredEndpoints && hops >= 1 && hops <= 3
}

func validNestedGroups(mode NestedGroupMode, depth int) bool {
	switch mode {
	case NestedGroupModeDisabled:
		return depth == 0
	case NestedGroupModeActiveDirectory, NestedGroupModeReverseSearch, NestedGroupModePOSIXMemberUID:
		return depth >= 1 && depth <= 20
	default:
		return false
	}
}

func validAccountStatus(configuration Configuration) bool {
	switch configuration.AccountStatusMode {
	case AccountStatusModeNone:
		return configuration.AccountStatusAttribute == nil && configuration.AccountDisabledValue == nil
	case AccountStatusModeActiveDirectoryUAC:
		return validOptionalAttribute(configuration.AccountStatusAttribute) &&
			configuration.AccountStatusAttribute != nil && configuration.AccountDisabledValue == nil
	case AccountStatusModeAttributeEquals:
		return validOptionalAttribute(configuration.AccountStatusAttribute) &&
			configuration.AccountStatusAttribute != nil && configuration.AccountDisabledValue != nil &&
			validText(*configuration.AccountDisabledValue, 1, 256)
	default:
		return false
	}
}

func normalizeOptional(value *string) (*string, error) {
	if value == nil {
		return nil, nil
	}
	normalized := strings.TrimSpace(*value)
	if normalized == "" || !utf8.ValidString(normalized) {
		return nil, ErrInvalidInput
	}
	return &normalized, nil
}

func knownTemplate(value ProviderTemplate) bool {
	switch value {
	case ProviderTemplateActiveDirectory, ProviderTemplateOpenLDAP, ProviderTemplatePOSIX, ProviderTemplateCustom:
		return true
	default:
		return false
	}
}

func knownSubjectFormat(value SubjectFormat) bool {
	switch value {
	case SubjectFormatADObjectGUID, SubjectFormatEntryUUID, SubjectFormatUTF8Exact, SubjectFormatUTF8Casefold:
		return true
	default:
		return false
	}
}

func knownJITMode(value JITMode) bool {
	switch value {
	case JITModeDisabled, JITModeExistingIdentity, JITModeCreate:
		return true
	default:
		return false
	}
}

func knownNoMatchPolicy(value NoMatchPolicy) bool {
	return value == NoMatchPolicyDeny || value == NoMatchPolicyProviderAccessOnly
}

func validDeprovisionPolicy(mode DeprovisionMode, graceSeconds int) bool {
	switch mode {
	case DeprovisionModeRetain, DeprovisionModeImmediate:
		return graceSeconds == 0
	case DeprovisionModeGrace:
		return graceSeconds >= 60 && graceSeconds <= 2_592_000
	default:
		return false
	}
}

func validSyncInterval(seconds *int) bool {
	return seconds == nil || *seconds >= 300 && *seconds <= 2_592_000
}

func validAudit(value authorization.AuditContext, requireIDs bool) bool {
	if requireIDs && (value.RequestID == uuid.Nil || value.CorrelationID == uuid.Nil) ||
		value.RequestID != uuid.Nil && value.RequestID.Variant() != uuid.RFC4122 ||
		value.CorrelationID != uuid.Nil && value.CorrelationID.Variant() != uuid.RFC4122 ||
		value.RemoteAddress.IsValid() && (value.RemoteAddress.Zone() != "" || value.RemoteAddress.Is4In6()) {
		return false
	}
	return validText(value.UserAgent, 0, 1024)
}

func validText(value string, minimum, maximum int) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	length := utf8.RuneCountInString(value)
	return length >= minimum && length <= maximum
}

func validFederationAuditReason(value string) bool {
	if !validText(value, 1, 500) {
		return false
	}
	for _, pattern := range federationAuditSecretPatterns {
		if pattern.MatchString(value) {
			return false
		}
	}
	return true
}

func validUUIDv7(value uuid.UUID) bool {
	return value != uuid.Nil && value.Version() == 7 && value.Variant() == uuid.RFC4122
}

func validInstant(value time.Time) bool {
	if value.IsZero() || value.Nanosecond()%int(time.Microsecond) != 0 {
		return false
	}
	_, err := value.UTC().MarshalJSON()
	return err == nil
}

func boundedPage(rows []ProviderSummary, after *uuid.UUID, limit int) ([]ProviderSummary, *uuid.UUID, error) {
	if len(rows) > limit+1 {
		return nil, nil, ErrUnavailable
	}
	var previous uuid.UUID
	hasPrevious := false
	if after != nil {
		previous, hasPrevious = *after, true
	}
	for _, row := range rows {
		if !validUUIDv7(row.ID) || hasPrevious && bytes.Compare(row.ID[:], previous[:]) <= 0 {
			return nil, nil, ErrUnavailable
		}
		previous, hasPrevious = row.ID, true
	}
	visible := len(rows)
	var next *uuid.UUID
	if visible > limit {
		visible = limit
		value := rows[visible-1].ID
		next = &value
	}
	return append([]ProviderSummary(nil), rows[:visible]...), next, nil
}
