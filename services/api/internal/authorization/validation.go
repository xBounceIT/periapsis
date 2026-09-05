package authorization

import (
	"bytes"
	"math"
	"net/mail"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

var (
	roleKeyPattern          = regexp.MustCompile(`^[a-z][a-z0-9_]{2,63}$`)
	idempotencyKeyPattern   = regexp.MustCompile(`^[A-Za-z0-9._~-]{16,128}$`)
	lifecycleSecretPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)-----BEGIN[[:space:]]+[^-]*PRIVATE[[:space:]]+KEY-----`),
		regexp.MustCompile(`(?i)(^|[^[:alnum:]_])(bearer|basic)[[:space:]]+[A-Za-z0-9+/._~=-]{12,}`),
		regexp.MustCompile(`(?i)(password|passwd|passphrase|secret|token|api[ _-]?key|assertion|recovery[ _-]?code|totp)[[:space:]]*[:=][[:space:]]*[^[:space:]]{12,}`),
		regexp.MustCompile(`(^|[^A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`),
	}
)

const maximumResourceVersion int64 = 2_147_483_647

func validateActiveTenant(actor Actor, tenantID uuid.UUID) error {
	if !validUUIDv7(tenantID) {
		return ErrInvalidInput
	}
	if !validUUIDv7(actor.UserID) || !validUUIDv7(actor.SessionID) ||
		!validUUIDv7(actor.ActiveTenantID) || actor.ActiveTenantID != tenantID ||
		!validBoundedText(actor.AuthenticationMethod, 1, 64) {
		return ErrForbidden
	}
	return nil
}

func validUUIDv7(value uuid.UUID) bool {
	return value != uuid.Nil && value.Version() == 7 && value.Variant() == uuid.RFC4122
}

func normalizedPageInput(input PageInput) (PageInput, error) {
	if input.Limit == 0 {
		input.Limit = defaultPageSize
	}
	if input.Limit < 1 || input.Limit > maximumPageSize {
		return PageInput{}, ErrInvalidInput
	}
	if input.After != nil {
		if !validUUIDv7(*input.After) {
			return PageInput{}, ErrInvalidInput
		}
		cursor := *input.After
		input.After = &cursor
	}
	return input, nil
}

func boundedPage[T any](
	rows []T,
	after *uuid.UUID,
	limit int,
	cursor func(T) uuid.UUID,
) ([]T, *uuid.UUID, error) {
	if len(rows) > limit+1 {
		return nil, nil, ErrUnavailable
	}
	var previous uuid.UUID
	hasPrevious := false
	if after != nil {
		if !validUUIDv7(*after) {
			return nil, nil, ErrUnavailable
		}
		previous = *after
		hasPrevious = true
	}
	for _, row := range rows {
		value := cursor(row)
		if !validUUIDv7(value) || hasPrevious && bytes.Compare(value[:], previous[:]) <= 0 {
			return nil, nil, ErrUnavailable
		}
		previous = value
		hasPrevious = true
	}
	visible := len(rows)
	var next *uuid.UUID
	if visible > limit {
		visible = limit
		value := cursor(rows[visible-1])
		next = &value
	}
	items := make([]T, visible)
	copy(items, rows[:visible])
	return items, next, nil
}

func (s *Service) normalizeCreateRoleInput(input CreateTenantRoleInput) (CreateTenantRoleInput, error) {
	if !roleKeyPattern.MatchString(input.Key) || !idempotencyKeyPattern.MatchString(input.IdempotencyKey) ||
		!validAuditContext(input.Audit) {
		return CreateTenantRoleInput{}, ErrInvalidInput
	}
	name, ok := normalizedName(input.Name, 120)
	if !ok {
		return CreateTenantRoleInput{}, ErrInvalidInput
	}
	description, ok := normalizedDescription(input.Description)
	if !ok {
		return CreateTenantRoleInput{}, ErrInvalidInput
	}
	policy, err := s.normalizedRolePolicy(input.Policy)
	if err != nil {
		return CreateTenantRoleInput{}, err
	}
	input.Name = name
	input.Description = description
	input.Policy = policy
	return input, nil
}

func normalizeUpdateRoleInput(
	roleID uuid.UUID,
	input UpdateTenantRoleInput,
) (UpdateTenantRoleInput, int64, error) {
	version, err := validateVersionedMutation(roleID, input.ExpectedVersion, input.Audit)
	if err != nil {
		return UpdateTenantRoleInput{}, 0, err
	}
	if input.Name == nil && input.Description == nil {
		return UpdateTenantRoleInput{}, 0, ErrInvalidInput
	}
	if input.Name != nil {
		name, ok := normalizedName(*input.Name, 120)
		if !ok {
			return UpdateTenantRoleInput{}, 0, ErrInvalidInput
		}
		input.Name = &name
	}
	if input.Description != nil {
		description, ok := normalizedDescription(*input.Description)
		if !ok {
			return UpdateTenantRoleInput{}, 0, ErrInvalidInput
		}
		input.Description = &description
	}
	return input, version, nil
}

func normalizeGrantUserRoleInput(
	userID uuid.UUID,
	input GrantUserRoleInput,
) (GrantUserRoleInput, error) {
	if !validUUIDv7(userID) || !validUUIDv7(input.RoleID) ||
		!idempotencyKeyPattern.MatchString(input.IdempotencyKey) ||
		!validAuditContext(input.Audit) {
		return GrantUserRoleInput{}, ErrInvalidInput
	}
	reason, ok := normalizedReason(input.Reason)
	if !ok {
		return GrantUserRoleInput{}, ErrInvalidInput
	}
	input.Reason = reason
	var err error
	input.ExpiresAt, err = NormalizeWritableExpiry(input.ExpiresAt)
	if err != nil {
		return GrantUserRoleInput{}, err
	}
	return input, nil
}

func normalizeCreateSecurityGroupInput(
	input CreateTenantSecurityGroupInput,
) (CreateTenantSecurityGroupInput, error) {
	if !roleKeyPattern.MatchString(input.Key) ||
		!idempotencyKeyPattern.MatchString(input.IdempotencyKey) || !validAuditContext(input.Audit) {
		return CreateTenantSecurityGroupInput{}, ErrInvalidInput
	}
	name, ok := normalizedName(input.Name, 120)
	if !ok {
		return CreateTenantSecurityGroupInput{}, ErrInvalidInput
	}
	description, ok := normalizedDescription(input.Description)
	if !ok {
		return CreateTenantSecurityGroupInput{}, ErrInvalidInput
	}
	input.Name = name
	input.Description = description
	return input, nil
}

func normalizeUpdateSecurityGroupInput(
	groupID uuid.UUID,
	input UpdateTenantSecurityGroupInput,
) (UpdateTenantSecurityGroupInput, int64, error) {
	version, err := validateVersionedMutation(groupID, input.ExpectedVersion, input.Audit)
	if err != nil {
		return UpdateTenantSecurityGroupInput{}, 0, err
	}
	if input.Name == nil && input.Description == nil {
		return UpdateTenantSecurityGroupInput{}, 0, ErrInvalidInput
	}
	if input.Name != nil {
		name, ok := normalizedName(*input.Name, 120)
		if !ok {
			return UpdateTenantSecurityGroupInput{}, 0, ErrInvalidInput
		}
		input.Name = &name
	}
	if input.Description != nil {
		description, ok := normalizedDescription(*input.Description)
		if !ok {
			return UpdateTenantSecurityGroupInput{}, 0, ErrInvalidInput
		}
		input.Description = &description
	}
	return input, version, nil
}

func normalizeAddSecurityGroupMembershipInput(
	input AddTenantSecurityGroupMembershipInput,
) (AddTenantSecurityGroupMembershipInput, error) {
	if !validUUIDv7(input.UserID) || !idempotencyKeyPattern.MatchString(input.IdempotencyKey) ||
		!validAuditContext(input.Audit) {
		return AddTenantSecurityGroupMembershipInput{}, ErrInvalidInput
	}
	reason, ok := normalizedReason(input.Reason)
	if !ok {
		return AddTenantSecurityGroupMembershipInput{}, ErrInvalidInput
	}
	input.Reason = reason
	var err error
	input.ExpiresAt, err = NormalizeWritableExpiry(input.ExpiresAt)
	if err != nil {
		return AddTenantSecurityGroupMembershipInput{}, err
	}
	return input, nil
}

func normalizeGrantSecurityGroupRoleInput(
	input GrantTenantSecurityGroupRoleInput,
) (GrantTenantSecurityGroupRoleInput, error) {
	if !validUUIDv7(input.RoleID) || !idempotencyKeyPattern.MatchString(input.IdempotencyKey) ||
		!validAuditContext(input.Audit) {
		return GrantTenantSecurityGroupRoleInput{}, ErrInvalidInput
	}
	reason, ok := normalizedReason(input.Reason)
	if !ok {
		return GrantTenantSecurityGroupRoleInput{}, ErrInvalidInput
	}
	input.Reason = reason
	var err error
	input.ExpiresAt, err = NormalizeWritableExpiry(input.ExpiresAt)
	if err != nil {
		return GrantTenantSecurityGroupRoleInput{}, err
	}
	return input, nil
}

// NormalizeWritableExpiry returns the canonical UTC expiry accepted by every
// authorization write boundary. Accepted values must remain representable in
// the RFC 3339 JSON projections and entity tags returned by the API.
func NormalizeWritableExpiry(value *time.Time) (*time.Time, error) {
	if value == nil {
		return nil, nil
	}
	if value.IsZero() || value.Nanosecond()%int(time.Microsecond) != 0 {
		return nil, ErrInvalidInput
	}
	normalized := value.UTC()
	if _, err := normalized.MarshalJSON(); err != nil {
		return nil, ErrInvalidInput
	}
	return &normalized, nil
}

func cloneTimePointer(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func validateVersionedMutation(
	resourceID uuid.UUID,
	expectedVersion *int64,
	audit AuditContext,
) (int64, error) {
	if !validUUIDv7(resourceID) || !validAuditContext(audit) {
		return 0, ErrInvalidInput
	}
	if expectedVersion == nil {
		return 0, ErrPreconditionRequired
	}
	if *expectedVersion < 1 || *expectedVersion > maximumResourceVersion {
		return 0, ErrInvalidInput
	}
	return *expectedVersion, nil
}

func validateEdgeMutation(
	resourceID uuid.UUID,
	expectedEntityTag *string,
	audit AuditContext,
) (string, int64, error) {
	if !validUUIDv7(resourceID) || !validAuditContext(audit) {
		return "", 0, ErrInvalidInput
	}
	if expectedEntityTag == nil {
		return "", 0, ErrPreconditionRequired
	}
	version, err := ParseEdgeEntityTag(*expectedEntityTag)
	if err != nil {
		return "", 0, ErrInvalidInput
	}
	return *expectedEntityTag, version, nil
}

func (s *Service) normalizedRolePolicy(policy TenantRolePolicy) (TenantRolePolicy, error) {
	return s.normalizedRolePolicyWithLimit(policy, maximumPageSize)
}

func (s *Service) normalizedRolePolicyWithLimit(policy TenantRolePolicy, limit int) (TenantRolePolicy, error) {
	if len(policy.Permissions) > limit || len(policy.DelegationCeiling) > limit {
		return TenantRolePolicy{}, ErrInvalidInput
	}
	permissions := make([]ScopedPermission, len(policy.Permissions))
	copy(permissions, policy.Permissions)
	permissionSet := make(map[ScopedPermission]struct{}, len(permissions))
	for _, permission := range permissions {
		if !s.evaluator.validScopedPermission(permission, PrincipalKindHuman) {
			return TenantRolePolicy{}, ErrInvalidInput
		}
		if _, duplicate := permissionSet[permission]; duplicate {
			return TenantRolePolicy{}, ErrInvalidInput
		}
		permissionSet[permission] = struct{}{}
	}

	ceiling := make([]ScopedPermission, len(policy.DelegationCeiling))
	copy(ceiling, policy.DelegationCeiling)
	ceilingSet := make(map[ScopedPermission]struct{}, len(ceiling))
	for _, permission := range ceiling {
		if !s.evaluator.validScopedPermission(permission, PrincipalKindHuman) {
			return TenantRolePolicy{}, ErrInvalidInput
		}
		if _, duplicate := ceilingSet[permission]; duplicate {
			return TenantRolePolicy{}, ErrInvalidInput
		}
		if _, granted := permissionSet[permission]; !granted {
			return TenantRolePolicy{}, ErrInvalidInput
		}
		ceilingSet[permission] = struct{}{}
	}
	return TenantRolePolicy{Permissions: permissions, DelegationCeiling: ceiling}, nil
}

func validAuditContext(audit AuditContext) bool {
	if audit.RequestID != uuid.Nil && audit.RequestID.Variant() != uuid.RFC4122 {
		return false
	}
	if audit.CorrelationID != uuid.Nil && audit.CorrelationID.Variant() != uuid.RFC4122 {
		return false
	}
	return validBoundedText(audit.UserAgent, 0, 1024)
}

func normalizedName(value string, maximum int) (string, bool) {
	value = strings.TrimSpace(value)
	return value, validBoundedText(value, 1, maximum)
}

func normalizedDescription(value string) (string, bool) {
	value = strings.TrimSpace(value)
	return value, validBoundedText(value, 0, 500)
}

func normalizedReason(value string) (string, bool) {
	value = strings.TrimSpace(value)
	return value, validBoundedText(value, 1, 500)
}

func validLifecycleReason(value string) bool {
	if !utf8.ValidString(value) || len(value) < 1 || len(value) > 2048 ||
		strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.In(character, unicode.Cf) {
			return false
		}
	}
	for _, pattern := range lifecycleSecretPatterns {
		if pattern.MatchString(value) {
			return false
		}
	}
	return true
}

func validBoundedText(value string, minimum, maximum int) bool {
	if !utf8.ValidString(value) || containsControlCharacter(value) {
		return false
	}
	length := utf8.RuneCountInString(value)
	return length >= minimum && length <= maximum
}

func containsControlCharacter(value string) bool {
	for _, character := range value {
		if unicode.IsControl(character) {
			return true
		}
	}
	return false
}

func (s *Service) validResolvedAuthority(
	authority TenantAuthority,
	actor Actor,
	tenantID uuid.UUID,
) bool {
	if authority.TenantID != tenantID || authority.Principal.ID != actor.UserID ||
		authority.Principal.Kind != PrincipalKindHuman || !validUUIDv7(authority.MembershipID) ||
		authority.MembershipStatus != MembershipStatusActive ||
		!knownLegacyMembershipRole(authority.LegacyRole) || authority.EvaluatedAt.IsZero() ||
		len(authority.RoleGrants) > maximumEffectiveRolePaths ||
		len(authority.Permissions) > MaximumHydratedPermissionTuples ||
		len(authority.DelegationCeiling) > MaximumHydratedPermissionTuples ||
		len(authority.OperatorTeamRelationships) > maximumOperatorTeamRelationships ||
		!s.evaluator.validTenantAuthority(authority) {
		return false
	}
	permissions := make(map[ScopedPermission]struct{}, len(authority.Permissions))
	for _, permission := range authority.Permissions {
		if _, duplicate := permissions[permission]; duplicate {
			return false
		}
		permissions[permission] = struct{}{}
	}
	ceilings := make(map[ScopedPermission]struct{}, len(authority.DelegationCeiling))
	for _, ceiling := range authority.DelegationCeiling {
		if ceiling.ExpiresAt != nil && !ceiling.ExpiresAt.After(authority.EvaluatedAt) {
			return false
		}
		if _, duplicate := ceilings[ceiling.ScopedPermission]; duplicate {
			return false
		}
		ceilings[ceiling.ScopedPermission] = struct{}{}
	}
	for _, grant := range authority.RoleGrants {
		if (grant.EffectiveExpiresAt != nil &&
			!grant.EffectiveExpiresAt.After(authority.EvaluatedAt)) ||
			!validEffectiveRoleGrant(grant) {
			return false
		}
	}
	return true
}

func (s *Service) validPermissionDefinition(permission TenantPermissionDefinition) bool {
	metadata, known := s.evaluator.tenantPermissionMetadata(permission.Key)
	if !validUUIDv7(permission.ID) || !known ||
		!validBoundedText(strings.TrimSpace(permission.Name), 1, 120) ||
		!validBoundedText(strings.TrimSpace(permission.Description), 1, 500) ||
		len(permission.AllowedScopes) != len(metadata.scopes) ||
		len(permission.PrincipalKinds) != len(metadata.principalKinds) {
		return false
	}
	for _, scope := range permission.AllowedScopes {
		if !contains(metadata.scopes, scope) {
			return false
		}
	}
	for _, kind := range permission.PrincipalKinds {
		if !contains(metadata.principalKinds, kind) {
			return false
		}
	}
	return true
}

func validStoredRoleSummary(role TenantRoleSummary, tenantID uuid.UUID) bool {
	if !validUUIDv7(role.ID) || role.TenantID != tenantID || !roleKeyPattern.MatchString(role.Key) ||
		!knownPrincipalKind(role.PrincipalKind) ||
		!validBoundedText(strings.TrimSpace(role.Name), 1, 120) ||
		!validBoundedText(role.Description, 0, 500) ||
		role.Version < 1 || role.Version > maximumResourceVersion ||
		role.CreatedAt.IsZero() || role.UpdatedAt.IsZero() || role.UpdatedAt.Before(role.CreatedAt) {
		return false
	}
	if role.Archived {
		return role.ArchivedAt != nil && !role.ArchivedAt.Before(role.CreatedAt)
	}
	return role.ArchivedAt == nil
}

func (s *Service) validStoredRole(role TenantRole, tenantID uuid.UUID) bool {
	if !validStoredRoleSummary(role.TenantRoleSummary, tenantID) {
		return false
	}
	_, err := s.normalizedRolePolicyWithLimit(role.Policy, MaximumHydratedPermissionTuples)
	return err == nil
}

func validTenantUserSummary(user TenantUserSummary, tenantID uuid.UUID) bool {
	if user.TenantID != tenantID || !validUUIDv7(user.MembershipID) || !validUUIDv7(user.User.ID) ||
		!knownMembershipStatus(user.MembershipStatus) || !knownLegacyMembershipRole(user.LegacyMembershipRole) ||
		!validEmail(user.User.Email) || !validBoundedText(strings.TrimSpace(user.User.DisplayName), 1, 160) ||
		user.LifecycleRevision < 1 || user.LifecycleRevision > maximumResourceVersion ||
		user.CreatedAt.IsZero() || user.UpdatedAt.IsZero() || user.UpdatedAt.Before(user.CreatedAt) {
		return false
	}
	expectedTag, err := TenantMembershipLifecycleEntityTag(user.LifecycleRevision)
	return err == nil && user.EntityTag == expectedTag
}

func validTenantMembershipLifecycleReceipt(
	receipt TenantMembershipLifecycleReceipt,
	tenantID uuid.UUID,
	userID uuid.UUID,
	targetStatus MembershipStatus,
	expectedRevision int64,
) bool {
	if receipt.TenantID != tenantID || receipt.UserID != userID ||
		!validUUIDv7(receipt.MembershipID) || receipt.Status != targetStatus ||
		receipt.LifecycleRevision != expectedRevision+1 || receipt.UpdatedAt.IsZero() ||
		receipt.RevokedSessionCount < 0 || receipt.RevokedSessionCount > math.MaxInt32 ||
		receipt.RevokedContinuationCount < 0 || receipt.RevokedContinuationCount > math.MaxInt32 {
		return false
	}
	if targetStatus == MembershipStatusSuspended {
		if receipt.PreviousStatus != MembershipStatusActive {
			return false
		}
	} else if targetStatus == MembershipStatusActive {
		if receipt.PreviousStatus != MembershipStatusSuspended ||
			receipt.RevokedSessionCount != 0 || receipt.RevokedContinuationCount != 0 {
			return false
		}
	} else {
		return false
	}
	expectedTag, err := TenantMembershipLifecycleEntityTag(receipt.LifecycleRevision)
	return err == nil && receipt.EntityTag == expectedTag
}

func validDirectRoleGrant(grant DirectUserRoleGrant, tenantID, userID uuid.UUID) bool {
	if !validUUIDv7(grant.ID) || grant.TenantID != tenantID || grant.UserID != userID ||
		!validStoredRoleSummary(grant.Role, tenantID) || grant.Role.PrincipalKind != PrincipalKindHuman ||
		!validRoleGrantProvenance(grant.Provenance) ||
		!validDirectRoleGrantSource(grant.Provenance) || grant.PathType != RoleGrantPathDirect ||
		grant.Version < 1 || grant.Version > maximumResourceVersion || grant.UpdatedAt.IsZero() {
		return false
	}
	if grant.ManagedByAuthorizationAPI &&
		(grant.Provenance.SourceKind != AuthorizationSourceManual ||
			grant.Provenance.SourceType != RoleGrantSourceDirect ||
			grant.Provenance.RetiredAt != nil) {
		return false
	}
	return validAuthorizationEdgeLifecycle(
		AuthorizationEdgeState(grant.State),
		grant.Provenance.ExpiresAt,
		grant.RevokedAt,
		grant.RevokedByUserID,
		grant.RevokeReason,
	)
}

func validDirectRoleGrantSource(provenance RoleGrantProvenance) bool {
	expectedSourceType := RoleGrantSourceSystem
	switch provenance.SourceKind {
	case AuthorizationSourceManual:
		if provenance.GrantedByUserID == nil {
			return false
		}
		expectedSourceType = RoleGrantSourceDirect
	case AuthorizationSourceIdentityMapping:
		expectedSourceType = RoleGrantSourceIdentityProvider
	case AuthorizationSourceSystem,
		AuthorizationSourceTenantCreation,
		AuthorizationSourcePlatformRecovery:
	default:
		return false
	}
	return provenance.SourceType == expectedSourceType
}

func validEffectiveRoleGrant(grant EffectiveTenantRoleGrant) bool {
	if !validUUIDv7(grant.GrantID) || !validUUIDv7(grant.RoleID) ||
		!roleKeyPattern.MatchString(grant.RoleKey) ||
		!validBoundedText(strings.TrimSpace(grant.RoleName), 1, 120) ||
		!validRoleGrantProvenance(grant.Provenance) {
		return false
	}
	switch grant.Path.PathType {
	case RoleGrantPathDirect:
		if grant.Path.Direct == nil || grant.Path.Group != nil ||
			grant.Path.Direct.GrantID != grant.GrantID ||
			!equalRoleGrantProvenance(grant.Path.Direct.Provenance, grant.Provenance) ||
			!validDirectRoleGrantSource(grant.Provenance) || grant.Provenance.RetiredAt != nil {
			return false
		}
		return equalOptionalInstant(grant.EffectiveExpiresAt, grant.Provenance.ExpiresAt)
	case RoleGrantPathGroup:
		if grant.Path.Direct != nil || grant.Path.Group == nil ||
			grant.Provenance.SourceType != RoleGrantSourceGroup ||
			grant.Path.Group.RoleGrantEdge.ID != grant.GrantID ||
			!roleGrantProvenanceMatchesEdge(grant.Provenance, grant.Path.Group.RoleGrantEdge.Provenance) ||
			!validSecurityGroupAuthoritySummary(grant.Path.Group.Group) ||
			!validSecurityGroupAuthorityEdge(grant.Path.Group.MembershipEdge) ||
			!validSecurityGroupAuthorityEdge(grant.Path.Group.RoleGrantEdge) ||
			grant.Path.Group.MembershipEdge.Provenance.RetiredAt != nil ||
			grant.Path.Group.RoleGrantEdge.Provenance.RetiredAt != nil {
			return false
		}
		expected := earliestExpiry(
			grant.Path.Group.MembershipEdge.Provenance.ExpiresAt,
			grant.Path.Group.RoleGrantEdge.Provenance.ExpiresAt,
		)
		return equalOptionalInstant(grant.EffectiveExpiresAt, expected)
	default:
		return false
	}
}

func validRoleGrantProvenance(provenance RoleGrantProvenance) bool {
	if !knownRoleGrantSource(provenance.SourceType) ||
		!knownAuthorizationSourceKind(provenance.SourceKind) || provenance.GrantedAt.IsZero() ||
		provenance.SourceKind == AuthorizationSourceManual && provenance.GrantedByUserID == nil {
		return false
	}
	if provenance.SourceID == nil || !validUUIDv7(*provenance.SourceID) {
		return false
	}
	if provenance.RetiredAt != nil && provenance.RetiredAt.IsZero() {
		return false
	}
	if provenance.GrantedByUserID != nil && !validUUIDv7(*provenance.GrantedByUserID) {
		return false
	}
	if provenance.ExpiresAt != nil && !provenance.ExpiresAt.After(provenance.GrantedAt) {
		return false
	}
	_, validReason := normalizedReason(provenance.Reason)
	return validReason
}

func validEmail(value string) bool {
	if !validBoundedText(value, 1, 320) {
		return false
	}
	parsed, err := mail.ParseAddress(value)
	return err == nil && parsed.Address == value
}

func validStoredSecurityGroup(group TenantSecurityGroup, tenantID uuid.UUID) bool {
	if !validUUIDv7(group.ID) || group.TenantID != tenantID ||
		!roleKeyPattern.MatchString(group.Key) ||
		!validBoundedText(strings.TrimSpace(group.Name), 1, 120) ||
		!validBoundedText(group.Description, 0, 500) ||
		group.Version < 1 || group.Version > maximumResourceVersion ||
		group.CreatedAt.IsZero() || group.UpdatedAt.IsZero() || group.UpdatedAt.Before(group.CreatedAt) {
		return false
	}
	if group.Archived {
		return group.ArchivedAt != nil && !group.ArchivedAt.Before(group.CreatedAt)
	}
	return group.ArchivedAt == nil
}

func validSecurityGroupAuthoritySummary(group TenantSecurityGroupAuthoritySummary) bool {
	return validUUIDv7(group.ID) && roleKeyPattern.MatchString(group.Key) &&
		validBoundedText(strings.TrimSpace(group.Name), 1, 120)
}

func validAuthorizationEdgeProvenance(provenance AuthorizationEdgeProvenance) bool {
	if !knownAuthorizationSourceKind(provenance.SourceKind) || provenance.GrantedAt.IsZero() ||
		provenance.SourceKind == AuthorizationSourceManual && provenance.GrantedByUserID == nil {
		return false
	}
	if provenance.SourceID == nil || !validUUIDv7(*provenance.SourceID) {
		return false
	}
	if provenance.RetiredAt != nil && provenance.RetiredAt.IsZero() {
		return false
	}
	if provenance.GrantedByUserID != nil && !validUUIDv7(*provenance.GrantedByUserID) {
		return false
	}
	if provenance.ExpiresAt != nil && !provenance.ExpiresAt.After(provenance.GrantedAt) {
		return false
	}
	_, validReason := normalizedReason(provenance.Reason)
	return validReason
}

func validSecurityGroupAuthorityEdge(edge TenantSecurityGroupAuthorityEdge) bool {
	return validUUIDv7(edge.ID) && validAuthorizationEdgeProvenance(edge.Provenance)
}

func validSecurityGroupMembership(
	edge TenantSecurityGroupMembership,
	tenantID, groupID uuid.UUID,
) bool {
	if !validUUIDv7(edge.ID) || edge.TenantID != tenantID || edge.Group.ID != groupID ||
		!validStoredSecurityGroup(edge.Group, tenantID) ||
		!validTenantUserSummary(edge.Member, tenantID) ||
		!validAuthorizationEdgeProvenance(edge.Provenance) ||
		!validAuthorizationAPIOwnership(edge.ManagedByAuthorizationAPI, edge.Provenance) ||
		edge.Version < 1 || edge.Version > maximumResourceVersion || edge.UpdatedAt.IsZero() {
		return false
	}
	return validAuthorizationEdgeLifecycle(
		edge.State,
		edge.Provenance.ExpiresAt,
		edge.RevokedAt,
		edge.RevokedByUserID,
		edge.RevokeReason,
	)
}

func validSecurityGroupRoleGrant(
	edge TenantSecurityGroupRoleGrant,
	tenantID, groupID uuid.UUID,
) bool {
	if !validUUIDv7(edge.ID) || edge.TenantID != tenantID || edge.Group.ID != groupID ||
		!validStoredSecurityGroup(edge.Group, tenantID) ||
		!validStoredRoleSummary(edge.Role, tenantID) || edge.Role.PrincipalKind != PrincipalKindHuman ||
		!validAuthorizationEdgeProvenance(edge.Provenance) ||
		!validAuthorizationAPIOwnership(edge.ManagedByAuthorizationAPI, edge.Provenance) ||
		edge.Version < 1 || edge.Version > maximumResourceVersion || edge.UpdatedAt.IsZero() {
		return false
	}
	return validAuthorizationEdgeLifecycle(
		edge.State,
		edge.Provenance.ExpiresAt,
		edge.RevokedAt,
		edge.RevokedByUserID,
		edge.RevokeReason,
	)
}

func validAuthorizationAPIOwnership(
	managed bool,
	provenance AuthorizationEdgeProvenance,
) bool {
	return !managed ||
		(provenance.SourceKind == AuthorizationSourceManual && provenance.RetiredAt == nil)
}

func validAuthorizationEdgeLifecycle(
	state AuthorizationEdgeState,
	expiresAt, revokedAt *time.Time,
	revokedBy *uuid.UUID,
	revokeReason *string,
) bool {
	switch state {
	case AuthorizationEdgeStateActive:
		return revokedAt == nil && revokedBy == nil && revokeReason == nil
	case AuthorizationEdgeStateExpired:
		return expiresAt != nil && revokedAt == nil && revokedBy == nil && revokeReason == nil
	case AuthorizationEdgeStateRevoked:
		if revokedAt == nil || revokedBy == nil || !validUUIDv7(*revokedBy) || revokeReason == nil {
			return false
		}
		normalized, valid := normalizedReason(*revokeReason)
		return valid && normalized == *revokeReason
	default:
		return false
	}
}

func equalRoleGrantProvenance(left, right RoleGrantProvenance) bool {
	return left.SourceType == right.SourceType && left.SourceKind == right.SourceKind &&
		equalOptionalUUID(left.SourceID, right.SourceID) &&
		left.Authoritative == right.Authoritative &&
		equalOptionalInstant(left.RetiredAt, right.RetiredAt) &&
		equalOptionalUUID(left.GrantedByUserID, right.GrantedByUserID) &&
		left.GrantedAt.Equal(right.GrantedAt) && left.Reason == right.Reason &&
		equalOptionalInstant(left.ExpiresAt, right.ExpiresAt)
}

func roleGrantProvenanceMatchesEdge(
	roleGrant RoleGrantProvenance,
	edge AuthorizationEdgeProvenance,
) bool {
	return roleGrant.SourceKind == edge.SourceKind &&
		equalOptionalUUID(roleGrant.SourceID, edge.SourceID) &&
		roleGrant.Authoritative == edge.Authoritative &&
		equalOptionalInstant(roleGrant.RetiredAt, edge.RetiredAt) &&
		equalOptionalUUID(roleGrant.GrantedByUserID, edge.GrantedByUserID) &&
		roleGrant.GrantedAt.Equal(edge.GrantedAt) && roleGrant.Reason == edge.Reason &&
		equalOptionalInstant(roleGrant.ExpiresAt, edge.ExpiresAt)
}

func equalOptionalUUID(left, right *uuid.UUID) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func equalOptionalInstant(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}

func earliestExpiry(values ...*time.Time) *time.Time {
	var earliest *time.Time
	for _, value := range values {
		if value == nil {
			continue
		}
		if earliest == nil || value.Before(*earliest) {
			copy := *value
			earliest = &copy
		}
	}
	return earliest
}

func knownMembershipStatus(status MembershipStatus) bool {
	return status == MembershipStatusInvited || status == MembershipStatusActive ||
		status == MembershipStatusSuspended
}

func knownLegacyMembershipRole(role LegacyMembershipRole) bool {
	switch role {
	case LegacyMembershipRoleTenantAdmin,
		LegacyMembershipRoleSOCManager,
		LegacyMembershipRoleSeniorAnalyst,
		LegacyMembershipRoleAnalyst,
		LegacyMembershipRoleCustomerManager,
		LegacyMembershipRoleCustomerUser,
		LegacyMembershipRoleReadOnly:
		return true
	default:
		return false
	}
}

func knownRoleGrantSource(source RoleGrantSourceType) bool {
	switch source {
	case RoleGrantSourceDirect, RoleGrantSourceGroup, RoleGrantSourceIdentityProvider, RoleGrantSourceSystem:
		return true
	default:
		return false
	}
}

func knownAuthorizationSourceKind(source AuthorizationSourceKind) bool {
	switch source {
	case AuthorizationSourceSystem,
		AuthorizationSourceTenantCreation,
		AuthorizationSourceManual,
		AuthorizationSourceIdentityMapping,
		AuthorizationSourcePlatformRecovery:
		return true
	default:
		return false
	}
}
