package operatorteam

import (
	"bytes"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

const (
	defaultPageSize        = 50
	maximumPageSize        = 100
	maximumResourceVersion = int64(2_147_483_647)
)

var (
	teamKeyPattern        = regexp.MustCompile(`^[a-z][a-z0-9_]{2,63}$`)
	idempotencyKeyPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{16,128}$`)
)

func validUUIDv7(value uuid.UUID) bool {
	return value != uuid.Nil && value.Version() == 7 && value.Variant() == uuid.RFC4122
}

func validatePlatformSession(session authentication.Session) (PlatformActor, error) {
	if !validUUIDv7(session.User.ID) || !validUUIDv7(session.ID) ||
		!validBoundedText(session.AuthenticationMethod, 1, 64) {
		return PlatformActor{}, ErrForbidden
	}
	return PlatformActor{
		UserID:               session.User.ID,
		SessionID:            session.ID,
		AuthenticationMethod: session.AuthenticationMethod,
	}, nil
}

func validateTenantActor(actor authorization.Actor, tenantID uuid.UUID) error {
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

func boundedPage[T any](rows []T, after *uuid.UUID, limit int, cursor func(T) uuid.UUID) ([]T, *uuid.UUID, error) {
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

func normalizeCreateOperatorTeamInput(input CreateOperatorTeamInput) (CreateOperatorTeamInput, error) {
	if !teamKeyPattern.MatchString(input.Key) || !idempotencyKeyPattern.MatchString(input.IdempotencyKey) ||
		!validAuditContext(input.Audit) {
		return CreateOperatorTeamInput{}, ErrInvalidInput
	}
	name, ok := normalizedName(input.Name)
	if !ok {
		return CreateOperatorTeamInput{}, ErrInvalidInput
	}
	description, ok := normalizedDescription(input.Description)
	if !ok {
		return CreateOperatorTeamInput{}, ErrInvalidInput
	}
	input.Name = name
	input.Description = description
	return input, nil
}

func normalizePatchOperatorTeamInput(operatorTeamID uuid.UUID, input PatchOperatorTeamInput) (PatchOperatorTeamInput, int64, error) {
	version, err := validateVersionedMutation(operatorTeamID, input.ExpectedVersion, input.Audit)
	if err != nil {
		return PatchOperatorTeamInput{}, 0, err
	}
	if input.Name == nil && input.Description == nil {
		return PatchOperatorTeamInput{}, 0, ErrInvalidInput
	}
	if input.Name != nil {
		name, ok := normalizedName(*input.Name)
		if !ok {
			return PatchOperatorTeamInput{}, 0, ErrInvalidInput
		}
		input.Name = &name
	}
	if input.Description != nil {
		description, ok := normalizedDescription(*input.Description)
		if !ok {
			return PatchOperatorTeamInput{}, 0, ErrInvalidInput
		}
		input.Description = &description
	}
	return input, version, nil
}

func normalizeArchiveOperatorTeamInput(operatorTeamID uuid.UUID, input ArchiveOperatorTeamInput) (ArchiveOperatorTeamInput, int64, error) {
	version, err := validateVersionedMutation(operatorTeamID, input.ExpectedVersion, input.Audit)
	if err != nil {
		return ArchiveOperatorTeamInput{}, 0, err
	}
	reason, ok := normalizedReason(input.Reason)
	if !ok {
		return ArchiveOperatorTeamInput{}, 0, ErrInvalidInput
	}
	input.Reason = reason
	return input, version, nil
}

func normalizeStartAssignmentInput(operatorTeamID uuid.UUID, input StartTenantAssignmentInput) (StartTenantAssignmentInput, error) {
	if !validUUIDv7(operatorTeamID) || !idempotencyKeyPattern.MatchString(input.IdempotencyKey) ||
		!validAuditContext(input.Audit) {
		return StartTenantAssignmentInput{}, ErrInvalidInput
	}
	reason, ok := normalizedReason(input.Reason)
	if !ok {
		return StartTenantAssignmentInput{}, ErrInvalidInput
	}
	input.Reason = reason
	return input, nil
}

func normalizeEndAssignmentInput(operatorTeamID, epochID uuid.UUID, input EndTenantAssignmentInput) (EndTenantAssignmentInput, int64, error) {
	if !validUUIDv7(operatorTeamID) {
		return EndTenantAssignmentInput{}, 0, ErrInvalidInput
	}
	version, err := validateVersionedMutation(epochID, input.ExpectedVersion, input.Audit)
	if err != nil {
		return EndTenantAssignmentInput{}, 0, err
	}
	reason, ok := normalizedReason(input.Reason)
	if !ok {
		return EndTenantAssignmentInput{}, 0, ErrInvalidInput
	}
	input.Reason = reason
	return input, version, nil
}

func normalizeAddRosterEntryInput(operatorTeamID, epochID uuid.UUID, input AddRosterEntryInput) (AddRosterEntryInput, error) {
	if !validUUIDv7(operatorTeamID) || !validUUIDv7(epochID) || !validUUIDv7(input.MembershipID) ||
		!idempotencyKeyPattern.MatchString(input.IdempotencyKey) || !validAuditContext(input.Audit) {
		return AddRosterEntryInput{}, ErrInvalidInput
	}
	reason, ok := normalizedReason(input.Reason)
	if !ok {
		return AddRosterEntryInput{}, ErrInvalidInput
	}
	input.Reason = reason
	var err error
	input.ExpiresAt, err = authorization.NormalizeWritableExpiry(input.ExpiresAt)
	if err != nil {
		return AddRosterEntryInput{}, ErrInvalidInput
	}
	return input, nil
}

func normalizeRevokeRosterEntryInput(operatorTeamID, epochID, rosterEntryID uuid.UUID, input RevokeRosterEntryInput) (RevokeRosterEntryInput, string, int64, error) {
	if !validUUIDv7(operatorTeamID) || !validUUIDv7(epochID) || !validUUIDv7(rosterEntryID) ||
		!validAuditContext(input.Audit) {
		return RevokeRosterEntryInput{}, "", 0, ErrInvalidInput
	}
	if input.ExpectedEntityTag == nil {
		return RevokeRosterEntryInput{}, "", 0, ErrPreconditionRequired
	}
	version, err := authorization.ParseEdgeEntityTag(*input.ExpectedEntityTag)
	if err != nil {
		return RevokeRosterEntryInput{}, "", 0, ErrInvalidInput
	}
	reason, ok := normalizedReason(input.Reason)
	if !ok {
		return RevokeRosterEntryInput{}, "", 0, ErrInvalidInput
	}
	input.Reason = reason
	return input, *input.ExpectedEntityTag, version, nil
}

func validateVersionedMutation(resourceID uuid.UUID, expectedVersion *int64, audit authorization.AuditContext) (int64, error) {
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

func validAuditContext(audit authorization.AuditContext) bool {
	if audit.RequestID != uuid.Nil && audit.RequestID.Variant() != uuid.RFC4122 {
		return false
	}
	if audit.CorrelationID != uuid.Nil && audit.CorrelationID.Variant() != uuid.RFC4122 {
		return false
	}
	return validBoundedText(audit.UserAgent, 0, 1024)
}

func normalizedName(value string) (string, bool) {
	value = strings.TrimSpace(value)
	return value, validBoundedText(value, 1, 120)
}

func normalizedDescription(value string) (string, bool) {
	value = strings.TrimSpace(value)
	return value, validBoundedText(value, 0, 500)
}

func normalizedReason(value string) (string, bool) {
	value = strings.TrimSpace(value)
	return value, validBoundedText(value, 1, 500)
}

func validBoundedText(value string, minimum, maximum int) bool {
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

func validNonBlankText(value string, maximum int) bool {
	return validBoundedText(value, 1, maximum) && strings.TrimSpace(value) != ""
}

func validStoredInstant(value time.Time) bool {
	if value.IsZero() || value.Location() != time.UTC || value.Nanosecond()%int(time.Microsecond) != 0 {
		return false
	}
	_, err := value.MarshalJSON()
	return err == nil
}

func validOptionalStoredInstant(value *time.Time) bool {
	return value == nil || validStoredInstant(*value)
}

func validOperatorTeamSummary(team OperatorTeamSummary) bool {
	return validUUIDv7(team.ID) && teamKeyPattern.MatchString(team.Key) &&
		validNonBlankText(team.Name, 120) && knownOperatorTeamState(team.State)
}

func validOperatorTeam(team OperatorTeam) bool {
	if !validOperatorTeamSummary(team.OperatorTeamSummary) ||
		!validBoundedText(team.Description, 0, 500) || team.ActiveAssignmentCount < 0 ||
		team.Version < 1 || team.Version > maximumResourceVersion ||
		!validStoredInstant(team.CreatedAt) || !validStoredInstant(team.UpdatedAt) ||
		team.UpdatedAt.Before(team.CreatedAt) || !validOptionalStoredInstant(team.ArchivedAt) ||
		team.CreatedByUserID != nil && !validUUIDv7(*team.CreatedByUserID) {
		return false
	}
	switch team.State {
	case OperatorTeamStateActive:
		return team.ArchivedAt == nil && team.ArchivedByUserID == nil && team.ArchiveReason == nil
	case OperatorTeamStateArchived:
		return team.ArchivedAt != nil && team.ArchivedByUserID != nil && validUUIDv7(*team.ArchivedByUserID) &&
			team.ArchiveReason != nil && validNonBlankText(*team.ArchiveReason, 500) &&
			!team.ArchivedAt.Before(team.CreatedAt) &&
			!team.ArchivedAt.After(team.UpdatedAt) && team.ActiveAssignmentCount == 0
	default:
		return false
	}
}

func validAssignment(assignment TenantAssignment, tenantID, operatorTeamID, epochID uuid.UUID) bool {
	if assignment.TenantID != tenantID || assignment.OperatorTeam.ID != operatorTeamID ||
		assignment.EpochID != epochID || !validUUIDv7(tenantID) || !validUUIDv7(epochID) ||
		!validOperatorTeamSummary(assignment.OperatorTeam) || !validUUIDv7(assignment.StartedByUserID) ||
		!validNonBlankText(assignment.StartReason, 500) ||
		assignment.Version < 1 || assignment.Version > maximumResourceVersion ||
		!validStoredInstant(assignment.StartedAt) || !validStoredInstant(assignment.UpdatedAt) ||
		assignment.UpdatedAt.Before(assignment.StartedAt) || !validOptionalStoredInstant(assignment.EndedAt) {
		return false
	}
	switch assignment.State {
	case AssignmentStateActive:
		return assignment.OperatorTeam.State == OperatorTeamStateActive && assignment.EndedAt == nil &&
			assignment.EndedByUserID == nil && assignment.EndReason == nil
	case AssignmentStateEnded:
		return assignment.EndedAt != nil && assignment.EndedByUserID != nil &&
			validUUIDv7(*assignment.EndedByUserID) && assignment.EndReason != nil &&
			validNonBlankText(*assignment.EndReason, 500) &&
			!assignment.EndedAt.Before(assignment.StartedAt) && !assignment.EndedAt.After(assignment.UpdatedAt)
	default:
		return false
	}
}

func validRosterEntry(entry RosterEntry, assignment TenantAssignment, now time.Time) bool {
	if entry.TenantID != assignment.TenantID || entry.OperatorTeamID != assignment.OperatorTeam.ID ||
		entry.AssignmentEpochID != assignment.EpochID || !validUUIDv7(entry.ID) ||
		!validTenantMember(entry.Member) || !validRosterProvenance(entry.Provenance) ||
		entry.Version < 1 || entry.Version > maximumResourceVersion ||
		!validStoredInstant(entry.UpdatedAt) || !validOptionalStoredInstant(entry.RevokedAt) ||
		entry.UpdatedAt.Before(entry.Provenance.GrantedAt) || !validRosterOwnership(entry) {
		return false
	}
	hasNoRevocation := entry.RevokedAt == nil && entry.RevokedByUserID == nil && entry.RevokeReason == nil
	switch entry.State {
	case RosterEntryStateActive:
		return assignment.State == AssignmentStateActive &&
			assignment.OperatorTeam.State == OperatorTeamStateActive &&
			entry.Member.Status == authorization.MembershipStatusActive &&
			entry.Provenance.RetiredAt == nil &&
			(entry.Provenance.ExpiresAt == nil || entry.Provenance.ExpiresAt.After(now)) &&
			hasNoRevocation
	case RosterEntryStateExpired:
		return hasNoRevocation
	case RosterEntryStateRevoked:
		return entry.RevokedAt != nil && entry.RevokedByUserID != nil && validUUIDv7(*entry.RevokedByUserID) &&
			entry.RevokeReason != nil && validNonBlankText(*entry.RevokeReason, 500) &&
			!entry.RevokedAt.Before(entry.Provenance.GrantedAt) && !entry.RevokedAt.After(entry.UpdatedAt)
	default:
		return false
	}
}

func validTenantMember(member TenantMember) bool {
	return validUUIDv7(member.MembershipID) && validUUIDv7(member.UserID) &&
		validNonBlankText(member.DisplayName, 160) && knownMembershipStatus(member.Status)
}

func validRosterProvenance(provenance authorization.AuthorizationEdgeProvenance) bool {
	if !knownAuthorizationSource(provenance.SourceKind) || provenance.SourceID == nil ||
		!validUUIDv7(*provenance.SourceID) || !validStoredInstant(provenance.GrantedAt) ||
		!validNonBlankText(provenance.Reason, 500) ||
		!validOptionalStoredInstant(provenance.RetiredAt) || !validOptionalStoredInstant(provenance.ExpiresAt) {
		return false
	}
	if provenance.ExpiresAt != nil && !provenance.ExpiresAt.After(provenance.GrantedAt) ||
		provenance.RetiredAt != nil && provenance.RetiredAt.Before(provenance.GrantedAt) {
		return false
	}
	if provenance.SourceKind == authorization.AuthorizationSourceManual {
		return provenance.GrantedByUserID != nil && validUUIDv7(*provenance.GrantedByUserID)
	}
	return provenance.GrantedByUserID == nil || validUUIDv7(*provenance.GrantedByUserID)
}

func validRosterOwnership(entry RosterEntry) bool {
	return !entry.ManagedByOperatorTeamAPI ||
		(entry.Provenance.SourceKind == authorization.AuthorizationSourceManual &&
			!entry.Provenance.Authoritative && entry.Provenance.RetiredAt == nil)
}

func equalOptionalInstant(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}

func knownOperatorTeamState(state OperatorTeamState) bool {
	return state == OperatorTeamStateActive || state == OperatorTeamStateArchived
}

func knownMembershipStatus(status authorization.MembershipStatus) bool {
	switch status {
	case authorization.MembershipStatusInvited,
		authorization.MembershipStatusActive,
		authorization.MembershipStatusSuspended:
		return true
	default:
		return false
	}
}

func knownAuthorizationSource(source authorization.AuthorizationSourceKind) bool {
	switch source {
	case authorization.AuthorizationSourceSystem,
		authorization.AuthorizationSourceTenantCreation,
		authorization.AuthorizationSourceManual,
		authorization.AuthorizationSourceIdentityMapping,
		authorization.AuthorizationSourcePlatformRecovery:
		return true
	default:
		return false
	}
}
