package identityprovider

import (
	"bytes"
	"math"
	"slices"
	"strings"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

const (
	maximumLDAPAdministrationPriority = 1_000_000
	maximumLDAPMappingRoles           = 32
	maximumLDAPDryRunMappings         = 32
	maximumLDAPExactDNCharacters      = 2_048
	maximumLDAPExactDNBytes           = 8_192
)

func normalizeListBindings(input ListBindingsInput) (ListBindingsInput, error) {
	page, err := normalizePage(input.PageInput)
	if err != nil {
		return ListBindingsInput{}, err
	}
	input.PageInput = page
	return input, nil
}

func normalizeCreateBinding(input CreateBindingInput) (CreateBindingInput, error) {
	if !validUUIDv7(input.ProviderID) || !providerKeyPattern.MatchString(input.LoginKey) ||
		input.ProfilePriority < 0 || input.ProfilePriority > maximumLDAPAdministrationPriority ||
		!idempotencyKeyPattern.MatchString(input.IdempotencyKey) || !validAudit(input.Audit, true) {
		return CreateBindingInput{}, ErrInvalidInput
	}
	return input, nil
}

func normalizeUpdateBinding(
	bindingID uuid.UUID,
	input UpdateBindingInput,
) (UpdateBindingInput, int64, error) {
	version, err := validateVersioned(bindingID, input.ExpectedEntityTag, input.Audit)
	if err != nil {
		return UpdateBindingInput{}, 0, err
	}
	if !providerKeyPattern.MatchString(input.LoginKey) || input.ProfilePriority < 0 ||
		input.ProfilePriority > maximumLDAPAdministrationPriority {
		return UpdateBindingInput{}, 0, ErrInvalidInput
	}
	return input, version, nil
}

func normalizeArchiveBinding(
	bindingID uuid.UUID,
	input ArchiveBindingInput,
) (ArchiveBindingInput, int64, error) {
	version, err := validateVersioned(bindingID, input.ExpectedEntityTag, input.Audit)
	if err != nil {
		return ArchiveBindingInput{}, 0, err
	}
	reason, ok := normalizedLDAPAdministrationReason(input.Reason)
	if !ok {
		return ArchiveBindingInput{}, 0, ErrInvalidInput
	}
	input.Reason = reason
	return input, version, nil
}

func normalizeUserSearchTest(
	providerID uuid.UUID,
	input UserSearchTestInput,
) (UserSearchTestInput, error) {
	if !validUUIDv7(providerID) || !validLDAPAdministrationUsername(input.Username) ||
		!validAudit(input.Audit, true) {
		return UserSearchTestInput{}, ErrInvalidInput
	}
	return input, nil
}

func normalizeFilterTest(
	providerID uuid.UUID,
	input FilterTestInput,
) (FilterTestInput, error) {
	if !validUUIDv7(providerID) || !validLDAPAdministrationUsername(input.Username) ||
		!validText(input.FilterTemplate, 1, 4096) || input.MaxResults < 1 ||
		input.MaxResults > 10 || !validAudit(input.Audit, true) {
		return FilterTestInput{}, ErrInvalidInput
	}
	if _, err := identity.NewLDAPUsername(input.Username); err != nil {
		return FilterTestInput{}, ErrInvalidInput
	}

	var context identity.LDAPTemplateContext
	switch input.Kind {
	case DirectoryFilterKindUser:
		if input.UserDN != nil || input.GIDNumber != nil {
			return FilterTestInput{}, ErrInvalidInput
		}
		context = identity.LDAPTemplateContextUserSearchFilter
	case DirectoryFilterKindGroup:
		switch {
		case input.UserDN != nil && input.GIDNumber == nil:
			if _, err := identity.ParseLDAPDistinguishedName(*input.UserDN); err != nil {
				return FilterTestInput{}, ErrInvalidInput
			}
			context = identity.LDAPTemplateContextReverseGroupSearchFilter
		case input.UserDN == nil:
			if input.GIDNumber != nil && (*input.GIDNumber < 0 || uint64(*input.GIDNumber) > math.MaxUint32) {
				return FilterTestInput{}, ErrInvalidInput
			}
			context = identity.LDAPTemplateContextPOSIXGroupSearchFilter
		default:
			return FilterTestInput{}, ErrInvalidInput
		}
	default:
		return FilterTestInput{}, ErrInvalidInput
	}
	compiled, err := identity.CompileLDAPTemplate(context, input.FilterTemplate)
	if err != nil {
		return FilterTestInput{}, ErrInvalidInput
	}
	requirements, err := compiled.Requirements()
	if err != nil {
		return FilterTestInput{}, ErrInvalidInput
	}
	if requirements.UserDN != (input.UserDN != nil) || requirements.GIDNumber != (input.GIDNumber != nil) {
		return FilterTestInput{}, ErrInvalidInput
	}
	if input.UserDN != nil {
		value := *input.UserDN
		input.UserDN = &value
	}
	if input.GIDNumber != nil {
		value := *input.GIDNumber
		input.GIDNumber = &value
	}
	return input, nil
}

func normalizeListMappings(input ListMappingsInput) (ListMappingsInput, error) {
	page, err := normalizePage(PageInput{Limit: input.Limit})
	if err != nil || input.After != nil && !validMappingCursor(*input.After) ||
		input.BindingID != nil && !validUUIDv7(*input.BindingID) {
		return ListMappingsInput{}, ErrInvalidInput
	}
	input.Limit = page.Limit
	if input.After != nil {
		value := *input.After
		input.After = &value
	}
	if input.BindingID != nil {
		value := *input.BindingID
		input.BindingID = &value
	}
	return input, nil
}

func normalizeCreateMapping(input CreateMappingInput) (CreateMappingInput, error) {
	if !validUUIDv7(input.BindingID) || input.Priority < 0 ||
		input.Priority > maximumLDAPAdministrationPriority ||
		!validText(input.Notes, 0, 2000) ||
		!idempotencyKeyPattern.MatchString(input.IdempotencyKey) || !validAudit(input.Audit, true) {
		return CreateMappingInput{}, ErrInvalidInput
	}
	normalized, ok := normalizedMappingDefinition(
		input.Matcher,
		input.Target,
		input.ReconciliationMode,
	)
	if !ok {
		return CreateMappingInput{}, ErrInvalidInput
	}
	reason, ok := normalizedLDAPAdministrationReason(input.Reason)
	if !ok {
		return CreateMappingInput{}, ErrInvalidInput
	}
	input.Matcher, input.Target = normalized.Matcher, normalized.Target
	input.Reason = reason
	return input, nil
}

func normalizeUpdateMapping(
	mappingID uuid.UUID,
	input UpdateMappingInput,
) (UpdateMappingInput, int64, error) {
	version, err := validateVersioned(mappingID, input.ExpectedEntityTag, input.Audit)
	if err != nil {
		return UpdateMappingInput{}, 0, err
	}
	if input.Priority < 0 || input.Priority > maximumLDAPAdministrationPriority ||
		!validText(input.Notes, 0, 2000) {
		return UpdateMappingInput{}, 0, ErrInvalidInput
	}
	normalized, ok := normalizedMappingDefinition(
		input.Matcher,
		input.Target,
		input.ReconciliationMode,
	)
	if !ok {
		return UpdateMappingInput{}, 0, ErrInvalidInput
	}
	reason, ok := normalizedLDAPAdministrationReason(input.Reason)
	if !ok {
		return UpdateMappingInput{}, 0, ErrInvalidInput
	}
	input.Matcher, input.Target = normalized.Matcher, normalized.Target
	input.Reason = reason
	return input, version, nil
}

func normalizeArchiveMapping(
	mappingID uuid.UUID,
	input ArchiveMappingInput,
) (ArchiveMappingInput, int64, error) {
	version, err := validateVersioned(mappingID, input.ExpectedEntityTag, input.Audit)
	if err != nil {
		return ArchiveMappingInput{}, 0, err
	}
	reason, ok := normalizedLDAPAdministrationReason(input.Reason)
	if !ok {
		return ArchiveMappingInput{}, 0, ErrInvalidInput
	}
	input.Reason = reason
	return input, version, nil
}

func normalizeDryRun(input DryRunInput) (DryRunInput, error) {
	if !validUUIDv7(input.BindingID) || !validLDAPAdministrationUsername(input.Username) ||
		len(input.IncludeDisabledMappingIDs) > maximumLDAPDryRunMappings || !validAudit(input.Audit, true) {
		return DryRunInput{}, ErrInvalidInput
	}
	ids, ok := normalizedUniqueUUIDv7s(input.IncludeDisabledMappingIDs, true)
	if !ok {
		return DryRunInput{}, ErrInvalidInput
	}
	input.IncludeDisabledMappingIDs = ids
	return input, nil
}

func normalizeStartManualSync(
	bindingID uuid.UUID,
	input StartManualSyncInput,
) (StartManualSyncInput, int64, error) {
	version, err := validateVersioned(bindingID, input.ExpectedEntityTag, input.Audit)
	if err != nil {
		return StartManualSyncInput{}, 0, err
	}
	if !idempotencyKeyPattern.MatchString(input.IdempotencyKey) {
		return StartManualSyncInput{}, 0, ErrInvalidInput
	}
	reason, ok := normalizedLDAPAdministrationReason(input.Reason)
	if !ok {
		return StartManualSyncInput{}, 0, ErrInvalidInput
	}
	input.Reason = reason
	return input, version, nil
}

type normalizedLDAPMappingDefinition struct {
	Matcher MappingMatcher
	Target  MappingTarget
}

func normalizedMappingDefinition(
	matcher MappingMatcher,
	target MappingTarget,
	mode ReconciliationMode,
) (normalizedLDAPMappingDefinition, bool) {
	caseMode, ok := domainLDAPMatcherCaseMode(matcher.CaseMode)
	if !ok {
		return normalizedLDAPMappingDefinition{}, false
	}
	kind, ok := domainLDAPMatcherKind(matcher.Type)
	if !ok || mode != ReconciliationAdditive && mode != ReconciliationAuthoritative {
		return normalizedLDAPMappingDefinition{}, false
	}
	if _, err := identity.CompileLDAPGroupMatcher(identity.LDAPGroupMatcherSpec{
		Kind: kind, CaseMode: caseMode, Pattern: matcher.Value,
	}); err != nil {
		return normalizedLDAPMappingDefinition{}, false
	}
	if matcher.Type == MappingMatcherExactDN {
		parsed, err := ldap.ParseDN(matcher.Value)
		if err != nil {
			return normalizedLDAPMappingDefinition{}, false
		}
		canonical := parsed.String()
		if !validText(canonical, 1, maximumLDAPExactDNCharacters) ||
			len(canonical) > maximumLDAPExactDNBytes {
			return normalizedLDAPMappingDefinition{}, false
		}
		matcher.Value = canonical
	}
	if !validUUIDv7(target.TenantSecurityGroupID) || len(target.RoleIDs) < 1 ||
		len(target.RoleIDs) > maximumLDAPMappingRoles {
		return normalizedLDAPMappingDefinition{}, false
	}
	roleIDs, ok := normalizedUniqueUUIDv7s(target.RoleIDs, false)
	if !ok {
		return normalizedLDAPMappingDefinition{}, false
	}
	target.RoleIDs = roleIDs
	if target.OperatorTeamAssignment != nil {
		if !validUUIDv7(target.OperatorTeamAssignment.OperatorTeamID) ||
			!validUUIDv7(target.OperatorTeamAssignment.AssignmentEpochID) {
			return normalizedLDAPMappingDefinition{}, false
		}
		assignment := *target.OperatorTeamAssignment
		target.OperatorTeamAssignment = &assignment
	}
	return normalizedLDAPMappingDefinition{Matcher: matcher, Target: target}, true
}

func domainLDAPMatcherCaseMode(value MappingCaseMode) (identity.LDAPGroupCaseMode, bool) {
	switch value {
	case MappingCaseSensitive:
		return identity.LDAPGroupCaseSensitive, true
	case MappingCaseInsensitive:
		return identity.LDAPGroupCaseInsensitive, true
	default:
		return 0, false
	}
}

func domainLDAPMatcherKind(value MappingMatcherType) (identity.LDAPGroupMatcherKind, bool) {
	switch value {
	case MappingMatcherExactDN:
		return identity.LDAPGroupMatcherExactDN, true
	case MappingMatcherExactCN:
		return identity.LDAPGroupMatcherExactCN, true
	case MappingMatcherRegex:
		return identity.LDAPGroupMatcherRegex, true
	default:
		return 0, false
	}
}

func normalizedUniqueUUIDv7s(values []uuid.UUID, allowEmpty bool) ([]uuid.UUID, bool) {
	if !allowEmpty && len(values) == 0 {
		return nil, false
	}
	result := append([]uuid.UUID(nil), values...)
	slices.SortFunc(result, func(left, right uuid.UUID) int {
		return bytes.Compare(left[:], right[:])
	})
	for index, value := range result {
		if !validUUIDv7(value) || index > 0 && value == result[index-1] {
			return nil, false
		}
	}
	return result, true
}

func normalizedLDAPAdministrationReason(value string) (string, bool) {
	value = strings.TrimSpace(value)
	return value, validText(value, 1, 500)
}

func validLDAPAdministrationUsername(value string) bool {
	if !validText(value, 1, 320) || strings.TrimSpace(value) == "" {
		return false
	}
	_, err := identity.NewLDAPUsername(value)
	return err == nil
}
