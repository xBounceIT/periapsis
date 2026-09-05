package httpserver

import (
	"errors"
	"net/http"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
)

func decodeLDAPAdministrationBody(
	r *http.Request,
	destination any,
	allowed, required []string,
) (map[string]any, error) {
	raw, err := decodeTenantLDAPJSONBody(r, destination)
	if err != nil {
		return nil, err
	}
	return exactTenantLDAPJSONObject(raw, allowed, required)
}

func decodeLDAPUserSearchBody(
	r *http.Request,
) (identityprovider.UserSearchTestInput, error) {
	var body contract.TenantLDAPUserSearchTestRequest
	if _, err := decodeLDAPAdministrationBody(
		r, &body, []string{"username"}, []string{"username"},
	); err != nil || !validLDAPText(body.Username, 1, 320, false) {
		return identityprovider.UserSearchTestInput{}, errors.New("invalid LDAP user search")
	}
	return identityprovider.UserSearchTestInput{Username: body.Username}, nil
}

func decodeLDAPFilterTestBody(
	r *http.Request,
) (identityprovider.FilterTestInput, error) {
	var body contract.TenantLDAPFilterTestRequest
	if _, err := decodeLDAPAdministrationBody(
		r,
		&body,
		[]string{"kind", "filterTemplate", "username", "userDn", "gidNumber", "maxResults"},
		[]string{"kind", "filterTemplate", "username", "userDn", "gidNumber", "maxResults"},
	); err != nil {
		return identityprovider.FilterTestInput{}, err
	}
	kind := identityprovider.DirectoryFilterKind(body.Kind)
	if kind != identityprovider.DirectoryFilterKindUser && kind != identityprovider.DirectoryFilterKindGroup ||
		!validLDAPText(body.FilterTemplate, 1, 4096, false) ||
		!validLDAPText(body.Username, 1, 320, false) || body.MaxResults < 1 || body.MaxResults > 10 ||
		body.UserDn != nil && !validLDAPText(*body.UserDn, 1, 2048, false) ||
		body.GidNumber != nil && (*body.GidNumber < 0 || int64(*body.GidNumber) > 4_294_967_295) {
		return identityprovider.FilterTestInput{}, errors.New("invalid LDAP filter test")
	}
	return identityprovider.FilterTestInput{
		Kind: kind, FilterTemplate: body.FilterTemplate, Username: body.Username,
		UserDN: cloneStringPointer(body.UserDn), GIDNumber: cloneIntPointer(body.GidNumber), MaxResults: body.MaxResults,
	}, nil
}

func decodeLDAPBindingCreateBody(
	r *http.Request,
) (identityprovider.CreateBindingInput, error) {
	var body contract.TenantLDAPAuthProviderBindingCreateRequest
	if _, err := decodeLDAPAdministrationBody(
		r,
		&body,
		[]string{"providerId", "loginKey", "enabled", "profilePriority"},
		[]string{"providerId", "loginKey", "enabled", "profilePriority"},
	); err != nil || !validLDAPAdministrationID(uuid.UUID(body.ProviderId)) ||
		!validLDAPLoginKey(body.LoginKey) || body.ProfilePriority < 0 || body.ProfilePriority > 1_000_000 {
		return identityprovider.CreateBindingInput{}, errors.New("invalid LDAP binding create")
	}
	return identityprovider.CreateBindingInput{
		ProviderID: uuid.UUID(body.ProviderId), LoginKey: body.LoginKey,
		Enabled: body.Enabled, ProfilePriority: body.ProfilePriority,
	}, nil
}

func decodeLDAPBindingUpdateBody(
	r *http.Request,
) (identityprovider.UpdateBindingInput, error) {
	var body contract.TenantLDAPAuthProviderBindingUpdateRequest
	if _, err := decodeLDAPAdministrationBody(
		r,
		&body,
		[]string{"loginKey", "enabled", "profilePriority"},
		[]string{"loginKey", "enabled", "profilePriority"},
	); err != nil || !validLDAPLoginKey(body.LoginKey) ||
		body.ProfilePriority < 0 || body.ProfilePriority > 1_000_000 {
		return identityprovider.UpdateBindingInput{}, errors.New("invalid LDAP binding update")
	}
	return identityprovider.UpdateBindingInput{
		LoginKey: body.LoginKey, Enabled: body.Enabled, ProfilePriority: body.ProfilePriority,
	}, nil
}

func decodeLDAPArchiveReasonBody(r *http.Request) (string, error) {
	var body contract.TenantLDAPMappingArchiveRequest
	if _, err := decodeLDAPAdministrationBody(
		r, &body, []string{"reason"}, []string{"reason"},
	); err != nil || !validLDAPText(body.Reason, 1, 500, false) {
		return "", errors.New("invalid LDAP archive reason")
	}
	return body.Reason, nil
}

func decodeLDAPMappingCreateBody(
	r *http.Request,
) (identityprovider.CreateMappingInput, error) {
	var body contract.TenantLDAPMappingCreateRequest
	object, err := decodeLDAPAdministrationBody(
		r,
		&body,
		[]string{"bindingId", "matcher", "priority", "target", "reconciliationMode", "notes", "reason"},
		[]string{"bindingId", "matcher", "priority", "target", "reconciliationMode", "notes", "reason"},
	)
	if err != nil {
		return identityprovider.CreateMappingInput{}, err
	}
	matcher, target, err := ldapMappingDocuments(body.Matcher, body.Target, object)
	mode := identityprovider.ReconciliationMode(body.ReconciliationMode)
	if err != nil || !validLDAPAdministrationID(uuid.UUID(body.BindingId)) ||
		body.Priority < 0 || body.Priority > 1_000_000 || !validLDAPReconciliationMode(mode) ||
		!validLDAPText(body.Notes, 0, 2000, true) || !validLDAPText(body.Reason, 1, 500, false) {
		return identityprovider.CreateMappingInput{}, errors.New("invalid LDAP mapping create")
	}
	return identityprovider.CreateMappingInput{
		BindingID: uuid.UUID(body.BindingId), Matcher: matcher, Priority: body.Priority,
		Target: target, ReconciliationMode: mode, Notes: body.Notes, Reason: body.Reason,
	}, nil
}

func decodeLDAPMappingUpdateBody(
	r *http.Request,
) (identityprovider.UpdateMappingInput, error) {
	var body contract.TenantLDAPMappingUpdateRequest
	object, err := decodeLDAPAdministrationBody(
		r,
		&body,
		[]string{"matcher", "priority", "target", "reconciliationMode", "enabled", "notes", "reason"},
		[]string{"matcher", "priority", "target", "reconciliationMode", "enabled", "notes", "reason"},
	)
	if err != nil {
		return identityprovider.UpdateMappingInput{}, err
	}
	matcher, target, err := ldapMappingDocuments(body.Matcher, body.Target, object)
	mode := identityprovider.ReconciliationMode(body.ReconciliationMode)
	if err != nil || body.Priority < 0 || body.Priority > 1_000_000 ||
		!validLDAPReconciliationMode(mode) || !validLDAPText(body.Notes, 0, 2000, true) ||
		!validLDAPText(body.Reason, 1, 500, false) {
		return identityprovider.UpdateMappingInput{}, errors.New("invalid LDAP mapping update")
	}
	return identityprovider.UpdateMappingInput{
		Matcher: matcher, Priority: body.Priority, Target: target,
		ReconciliationMode: mode, Enabled: body.Enabled, Notes: body.Notes, Reason: body.Reason,
	}, nil
}

func ldapMappingDocuments(
	matcherValue contract.TenantLDAPGroupMatcher,
	targetValue contract.TenantLDAPMappingTarget,
	object map[string]any,
) (identityprovider.MappingMatcher, identityprovider.MappingTarget, error) {
	matcherObject, err := exactTenantLDAPJSONObject(
		object["matcher"], []string{"type", "dn", "cn", "pattern", "caseMode"}, []string{"type", "caseMode"},
	)
	if err != nil {
		return identityprovider.MappingMatcher{}, identityprovider.MappingTarget{}, err
	}
	discriminator, ok := matcherObject["type"].(string)
	if !ok {
		return identityprovider.MappingMatcher{}, identityprovider.MappingTarget{}, errors.New("invalid matcher discriminator")
	}
	matcher, err := ldapMappingMatcher(matcherValue, discriminator, matcherObject)
	if err != nil {
		return identityprovider.MappingMatcher{}, identityprovider.MappingTarget{}, err
	}
	targetObject, err := exactTenantLDAPJSONObject(
		object["target"],
		[]string{"tenantSecurityGroupId", "roleIds", "operatorTeamAssignment"},
		[]string{"tenantSecurityGroupId", "roleIds", "operatorTeamAssignment"},
	)
	if err != nil {
		return identityprovider.MappingMatcher{}, identityprovider.MappingTarget{}, err
	}
	if targetObject["operatorTeamAssignment"] != nil {
		if _, err := exactTenantLDAPJSONObject(
			targetObject["operatorTeamAssignment"],
			[]string{"operatorTeamId", "assignmentEpochId"},
			[]string{"operatorTeamId", "assignmentEpochId"},
		); err != nil {
			return identityprovider.MappingMatcher{}, identityprovider.MappingTarget{}, err
		}
	}
	target := identityprovider.MappingTarget{
		TenantSecurityGroupID: uuid.UUID(targetValue.TenantSecurityGroupId),
		RoleIDs:               cloneUUIDs(targetValue.RoleIds),
	}
	if targetValue.OperatorTeamAssignment != nil {
		target.OperatorTeamAssignment = &identityprovider.OperatorTeamAssignmentTarget{
			OperatorTeamID:    uuid.UUID(targetValue.OperatorTeamAssignment.OperatorTeamId),
			AssignmentEpochID: uuid.UUID(targetValue.OperatorTeamAssignment.AssignmentEpochId),
		}
	}
	if !validLDAPMappingTarget(target) {
		return identityprovider.MappingMatcher{}, identityprovider.MappingTarget{}, errors.New("invalid LDAP mapping target")
	}
	return matcher, target, nil
}

func ldapMappingMatcher(
	value contract.TenantLDAPGroupMatcher,
	discriminator string,
	object map[string]any,
) (identityprovider.MappingMatcher, error) {
	switch discriminator {
	case string(identityprovider.MappingMatcherExactDN):
		if _, err := exactTenantLDAPJSONObject(
			object, []string{"type", "dn", "caseMode"}, []string{"type", "dn", "caseMode"},
		); err != nil {
			return identityprovider.MappingMatcher{}, err
		}
		decoded, err := value.AsTenantLDAPExactDNMatcher()
		if err != nil {
			return identityprovider.MappingMatcher{}, err
		}
		return validateLDAPMappingMatcher(identityprovider.MappingMatcher{
			Type: identityprovider.MappingMatcherExactDN, Value: decoded.Dn,
			CaseMode: identityprovider.MappingCaseMode(decoded.CaseMode),
		})
	case string(identityprovider.MappingMatcherExactCN):
		if _, err := exactTenantLDAPJSONObject(
			object, []string{"type", "cn", "caseMode"}, []string{"type", "cn", "caseMode"},
		); err != nil {
			return identityprovider.MappingMatcher{}, err
		}
		decoded, err := value.AsTenantLDAPExactCNMatcher()
		if err != nil {
			return identityprovider.MappingMatcher{}, err
		}
		return validateLDAPMappingMatcher(identityprovider.MappingMatcher{
			Type: identityprovider.MappingMatcherExactCN, Value: decoded.Cn,
			CaseMode: identityprovider.MappingCaseMode(decoded.CaseMode),
		})
	case string(identityprovider.MappingMatcherRegex):
		if _, err := exactTenantLDAPJSONObject(
			object, []string{"type", "pattern", "caseMode"}, []string{"type", "pattern", "caseMode"},
		); err != nil {
			return identityprovider.MappingMatcher{}, err
		}
		decoded, err := value.AsTenantLDAPRegexMatcher()
		if err != nil {
			return identityprovider.MappingMatcher{}, err
		}
		return validateLDAPMappingMatcher(identityprovider.MappingMatcher{
			Type: identityprovider.MappingMatcherRegex, Value: decoded.Pattern,
			CaseMode: identityprovider.MappingCaseMode(decoded.CaseMode),
		})
	default:
		return identityprovider.MappingMatcher{}, errors.New("unknown matcher discriminator")
	}
}

func validateLDAPMappingMatcher(value identityprovider.MappingMatcher) (identityprovider.MappingMatcher, error) {
	if value.CaseMode != identityprovider.MappingCaseSensitive &&
		value.CaseMode != identityprovider.MappingCaseInsensitive {
		return identityprovider.MappingMatcher{}, errors.New("invalid matcher case mode")
	}
	maximum := 512
	if value.Type == identityprovider.MappingMatcherExactDN {
		maximum = 2048
	}
	if !validLDAPText(value.Value, 1, maximum, false) {
		return identityprovider.MappingMatcher{}, errors.New("invalid matcher value")
	}
	if value.Type == identityprovider.MappingMatcherRegex {
		if _, err := regexp.Compile(value.Value); err != nil {
			return identityprovider.MappingMatcher{}, errors.New("invalid RE2 matcher")
		}
	}
	return value, nil
}

func decodeLDAPDryRunBody(r *http.Request) (identityprovider.DryRunInput, error) {
	var body contract.TenantLDAPMappingDryRunRequest
	if _, err := decodeLDAPAdministrationBody(
		r,
		&body,
		[]string{"bindingId", "username", "includeDisabledMappingIds"},
		[]string{"bindingId", "username", "includeDisabledMappingIds"},
	); err != nil || !validLDAPAdministrationID(uuid.UUID(body.BindingId)) ||
		!validLDAPText(body.Username, 1, 320, false) || len(body.IncludeDisabledMappingIds) > 32 ||
		!validUniqueLDAPAdministrationIDs(body.IncludeDisabledMappingIds) {
		return identityprovider.DryRunInput{}, errors.New("invalid LDAP dry run")
	}
	return identityprovider.DryRunInput{
		BindingID: uuid.UUID(body.BindingId), Username: body.Username,
		IncludeDisabledMappingIDs: cloneUUIDs(body.IncludeDisabledMappingIds),
	}, nil
}

func decodeLDAPManualSyncBody(r *http.Request) (identityprovider.StartManualSyncInput, error) {
	var body contract.TenantLDAPManualSyncRequest
	if _, err := decodeLDAPAdministrationBody(
		r, &body, []string{"reason"}, []string{"reason"},
	); err != nil || !validLDAPText(body.Reason, 1, 500, false) {
		return identityprovider.StartManualSyncInput{}, errors.New("invalid LDAP manual sync")
	}
	return identityprovider.StartManualSyncInput{Reason: body.Reason}, nil
}

func validLDAPLoginKey(value string) bool {
	if len(value) < 3 || len(value) > 64 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value[1:] {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' ||
			character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func validLDAPText(value string, minimum, maximum int, allowEmpty bool) bool {
	if !utf8.ValidString(value) {
		return false
	}
	length := utf8.RuneCountInString(value)
	if length < minimum || length > maximum || !allowEmpty && strings.TrimSpace(value) == "" {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validLDAPAdministrationID(value uuid.UUID) bool {
	return value != uuid.Nil && value.Version() == 7 && value.Variant() == uuid.RFC4122
}

func validUniqueLDAPAdministrationIDs[T ~[16]byte](values []T) bool {
	seen := make(map[uuid.UUID]struct{}, len(values))
	for _, raw := range values {
		value := uuid.UUID(raw)
		if !validLDAPAdministrationID(value) {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func validLDAPMappingTarget(value identityprovider.MappingTarget) bool {
	if !validLDAPAdministrationID(value.TenantSecurityGroupID) || len(value.RoleIDs) < 1 ||
		len(value.RoleIDs) > 32 || !validUniqueLDAPAdministrationIDs(value.RoleIDs) {
		return false
	}
	return value.OperatorTeamAssignment == nil ||
		validLDAPAdministrationID(value.OperatorTeamAssignment.OperatorTeamID) &&
			validLDAPAdministrationID(value.OperatorTeamAssignment.AssignmentEpochID)
}

func validLDAPReconciliationMode(value identityprovider.ReconciliationMode) bool {
	return value == identityprovider.ReconciliationAdditive ||
		value == identityprovider.ReconciliationAuthoritative
}

func cloneUUIDs[T ~[16]byte](values []T) []uuid.UUID {
	result := make([]uuid.UUID, len(values))
	for index, value := range values {
		result[index] = uuid.UUID(value)
	}
	return result
}
