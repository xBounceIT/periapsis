package httpserver

import (
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/operatorteam"
)

var operatorTeamTransportKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{2,63}$`)

func mapOperatorTeam(value operatorteam.OperatorTeam) (contract.OperatorTeam, error) {
	if !validOperatorTeamTransportValue(value) {
		return contract.OperatorTeam{}, errors.New("invalid operator team representation")
	}
	return contract.OperatorTeam{
		ActiveAssignmentCount: value.ActiveAssignmentCount,
		ArchivedAt:            value.ArchivedAt,
		CreatedAt:             value.CreatedAt,
		Description:           value.Description,
		Id:                    value.ID,
		Key:                   value.Key,
		Name:                  value.Name,
		State:                 contract.OperatorTeamState(value.State),
		UpdatedAt:             value.UpdatedAt,
		Version:               value.Version,
	}, nil
}

func mapOperatorTeamSummary(value operatorteam.OperatorTeamSummary) (contract.OperatorTeamSummary, error) {
	if !validOperatorTeamTransportSummary(value) {
		return contract.OperatorTeamSummary{}, errors.New("invalid operator team summary")
	}
	return contract.OperatorTeamSummary{
		Id: value.ID, Key: value.Key, Name: value.Name,
		State: contract.OperatorTeamState(value.State),
	}, nil
}

func mapOperatorTeamAssignment(
	value operatorteam.TenantAssignment,
	tenantID, operatorTeamID, epochID uuid.UUID,
) (contract.OperatorTeamAssignmentEpoch, error) {
	if !validOperatorTeamTransportAssignment(value, tenantID, operatorTeamID, epochID) {
		return contract.OperatorTeamAssignmentEpoch{}, errors.New("invalid operator team assignment representation")
	}
	summary, err := mapOperatorTeamSummary(value.OperatorTeam)
	if err != nil {
		return contract.OperatorTeamAssignmentEpoch{}, err
	}
	return contract.OperatorTeamAssignmentEpoch{
		EndReason:       value.EndReason,
		EndedAt:         value.EndedAt,
		EndedByUserId:   value.EndedByUserID,
		EpochId:         value.EpochID,
		OperatorTeam:    summary,
		StartReason:     value.StartReason,
		StartedAt:       value.StartedAt,
		StartedByUserId: value.StartedByUserID,
		State:           contract.OperatorTeamAssignmentEpochState(value.State),
		TenantId:        value.TenantID,
		UpdatedAt:       value.UpdatedAt,
		Version:         value.Version,
	}, nil
}

func mapOperatorTeamRosterEntry(
	value operatorteam.RosterEntry,
	tenantID, operatorTeamID, epochID uuid.UUID,
) (contract.OperatorTeamRosterEntry, error) {
	if !validOperatorTeamTransportRosterEntry(value, tenantID, operatorTeamID, epochID) {
		return contract.OperatorTeamRosterEntry{}, errors.New("invalid operator team roster representation")
	}
	provenance, err := mapAuthorizationEdgeProvenance(value.Provenance)
	if err != nil {
		return contract.OperatorTeamRosterEntry{}, err
	}
	entityTag, err := operatorteam.RosterEntryEntityTag(value)
	if err != nil {
		return contract.OperatorTeamRosterEntry{}, err
	}
	return contract.OperatorTeamRosterEntry{
		AssignmentEpochId:        value.AssignmentEpochID,
		Etag:                     entityTag,
		Id:                       value.ID,
		ManagedByOperatorTeamApi: value.ManagedByOperatorTeamAPI,
		Member: contract.OperatorTeamRosterMember{
			DisplayName:      value.Member.DisplayName,
			MembershipId:     value.Member.MembershipID,
			MembershipStatus: contract.OperatorTeamRosterMemberMembershipStatus(value.Member.Status),
			UserId:           value.Member.UserID,
		},
		OperatorTeamId:  value.OperatorTeamID,
		Provenance:      provenance,
		RevokeReason:    value.RevokeReason,
		RevokedAt:       value.RevokedAt,
		RevokedByUserId: value.RevokedByUserID,
		State:           contract.AuthorizationEdgeState(value.State),
		TenantId:        value.TenantID,
		UpdatedAt:       value.UpdatedAt,
		Version:         value.Version,
	}, nil
}

func validOperatorTeamTransportValue(value operatorteam.OperatorTeam) bool {
	if !validOperatorTeamTransportSummary(value.OperatorTeamSummary) ||
		!validOperatorTeamTransportText(value.Description, 0, 500) ||
		value.ActiveAssignmentCount < 0 || !validOperatorTeamTransportVersion(value.Version) ||
		!validOperatorTeamTransportInstant(value.CreatedAt) || !validOperatorTeamTransportInstant(value.UpdatedAt) ||
		value.UpdatedAt.Before(value.CreatedAt) || !validOperatorTeamOptionalTransportInstant(value.ArchivedAt) ||
		value.CreatedByUserID != nil && !validOperatorTeamTransportUUID(*value.CreatedByUserID) {
		return false
	}
	switch value.State {
	case operatorteam.OperatorTeamStateActive:
		return value.ArchivedAt == nil && value.ArchivedByUserID == nil && value.ArchiveReason == nil
	case operatorteam.OperatorTeamStateArchived:
		return value.ArchivedAt != nil && value.ArchivedByUserID != nil &&
			validOperatorTeamTransportUUID(*value.ArchivedByUserID) && value.ArchiveReason != nil &&
			validOperatorTeamTransportNonBlankText(*value.ArchiveReason, 500) &&
			!value.ArchivedAt.Before(value.CreatedAt) && !value.ArchivedAt.After(value.UpdatedAt) &&
			value.ActiveAssignmentCount == 0
	default:
		return false
	}
}

func validOperatorTeamTransportSummary(value operatorteam.OperatorTeamSummary) bool {
	state := contract.OperatorTeamState(value.State)
	return validOperatorTeamTransportUUID(value.ID) && operatorTeamTransportKeyPattern.MatchString(value.Key) &&
		validOperatorTeamTransportNonBlankText(value.Name, 120) && state.Valid()
}

func validOperatorTeamTransportAssignment(
	value operatorteam.TenantAssignment,
	tenantID, operatorTeamID, epochID uuid.UUID,
) bool {
	state := contract.OperatorTeamAssignmentEpochState(value.State)
	if value.TenantID != tenantID || value.OperatorTeam.ID != operatorTeamID || value.EpochID != epochID ||
		!validOperatorTeamTransportUUID(tenantID) || !validOperatorTeamTransportUUID(operatorTeamID) ||
		!validOperatorTeamTransportUUID(epochID) || !validOperatorTeamTransportSummary(value.OperatorTeam) ||
		!validOperatorTeamTransportUUID(value.StartedByUserID) || !validOperatorTeamTransportNonBlankText(value.StartReason, 500) ||
		!validOperatorTeamTransportVersion(value.Version) || !validOperatorTeamTransportInstant(value.StartedAt) ||
		!validOperatorTeamTransportInstant(value.UpdatedAt) || value.UpdatedAt.Before(value.StartedAt) ||
		!validOperatorTeamOptionalTransportInstant(value.EndedAt) || !state.Valid() {
		return false
	}
	switch value.State {
	case operatorteam.AssignmentStateActive:
		return value.OperatorTeam.State == operatorteam.OperatorTeamStateActive && value.EndedAt == nil &&
			value.EndedByUserID == nil && value.EndReason == nil
	case operatorteam.AssignmentStateEnded:
		return value.EndedAt != nil && value.EndedByUserID != nil && validOperatorTeamTransportUUID(*value.EndedByUserID) &&
			value.EndReason != nil && validOperatorTeamTransportNonBlankText(*value.EndReason, 500) &&
			!value.EndedAt.Before(value.StartedAt) && !value.EndedAt.After(value.UpdatedAt)
	default:
		return false
	}
}

func validOperatorTeamTransportRosterEntry(
	value operatorteam.RosterEntry,
	tenantID, operatorTeamID, epochID uuid.UUID,
) bool {
	state := contract.AuthorizationEdgeState(value.State)
	membershipStatus := contract.OperatorTeamRosterMemberMembershipStatus(value.Member.Status)
	if value.TenantID != tenantID || value.OperatorTeamID != operatorTeamID || value.AssignmentEpochID != epochID ||
		!validOperatorTeamTransportUUID(tenantID) || !validOperatorTeamTransportUUID(operatorTeamID) ||
		!validOperatorTeamTransportUUID(epochID) || !validOperatorTeamTransportUUID(value.ID) ||
		!validOperatorTeamTransportUUID(value.Member.MembershipID) || !validOperatorTeamTransportUUID(value.Member.UserID) ||
		!validOperatorTeamTransportNonBlankText(value.Member.DisplayName, 160) || !membershipStatus.Valid() ||
		!validOperatorTeamTransportProvenance(value.Provenance) || !state.Valid() ||
		!validOperatorTeamTransportVersion(value.Version) || !validOperatorTeamTransportInstant(value.UpdatedAt) ||
		!validOperatorTeamOptionalTransportInstant(value.RevokedAt) || value.UpdatedAt.Before(value.Provenance.GrantedAt) {
		return false
	}
	if value.ManagedByOperatorTeamAPI &&
		(value.Provenance.SourceKind != authorization.AuthorizationSourceManual ||
			value.Provenance.Authoritative || value.Provenance.RetiredAt != nil) {
		return false
	}
	hasNoRevocation := value.RevokedAt == nil && value.RevokedByUserID == nil && value.RevokeReason == nil
	switch value.State {
	case operatorteam.RosterEntryStateActive:
		return value.Member.Status == authorization.MembershipStatusActive &&
			value.Provenance.RetiredAt == nil && hasNoRevocation
	case operatorteam.RosterEntryStateExpired:
		return hasNoRevocation
	case operatorteam.RosterEntryStateRevoked:
		return value.RevokedAt != nil && value.RevokedByUserID != nil &&
			validOperatorTeamTransportUUID(*value.RevokedByUserID) && value.RevokeReason != nil &&
			validOperatorTeamTransportNonBlankText(*value.RevokeReason, 500) &&
			!value.RevokedAt.Before(value.Provenance.GrantedAt) && !value.RevokedAt.After(value.UpdatedAt)
	default:
		return false
	}
}

func validOperatorTeamTransportProvenance(value authorization.AuthorizationEdgeProvenance) bool {
	sourceKind := contract.AuthorizationSourceKind(value.SourceKind)
	if !sourceKind.Valid() || value.SourceID == nil || !validOperatorTeamTransportUUID(*value.SourceID) ||
		!validOperatorTeamTransportInstant(value.GrantedAt) || !validOperatorTeamTransportNonBlankText(value.Reason, 500) ||
		!validOperatorTeamOptionalTransportInstant(value.RetiredAt) || !validOperatorTeamOptionalTransportInstant(value.ExpiresAt) ||
		value.ExpiresAt != nil && !value.ExpiresAt.After(value.GrantedAt) ||
		value.RetiredAt != nil && value.RetiredAt.Before(value.GrantedAt) {
		return false
	}
	if value.SourceKind == authorization.AuthorizationSourceManual {
		return value.GrantedByUserID != nil && validOperatorTeamTransportUUID(*value.GrantedByUserID)
	}
	return value.GrantedByUserID == nil || validOperatorTeamTransportUUID(*value.GrantedByUserID)
}

func validOperatorTeamTransportUUID(value uuid.UUID) bool {
	return value != uuid.Nil && value.Version() == 7 && value.Variant() == uuid.RFC4122
}

func validOperatorTeamTransportVersion(value int64) bool {
	return value >= 1 && value <= maximumResourceVersion
}

func validOperatorTeamTransportInstant(value time.Time) bool {
	if value.IsZero() || value.Location() != time.UTC || value.Nanosecond()%int(time.Microsecond) != 0 {
		return false
	}
	_, err := value.MarshalJSON()
	return err == nil
}

func validOperatorTeamOptionalTransportInstant(value *time.Time) bool {
	return value == nil || validOperatorTeamTransportInstant(*value)
}

func validOperatorTeamTransportNonBlankText(value string, maximum int) bool {
	return validOperatorTeamTransportText(value, 1, maximum) && strings.TrimSpace(value) != ""
}

func validOperatorTeamTransportText(value string, minimum, maximum int) bool {
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
