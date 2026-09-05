package postgres

import (
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/operatorteam"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
)

func mapListedOperatorTeam(row *dbsql.ListPlatformOperatorTeamsRow) (operatorteam.OperatorTeam, error) {
	if row == nil {
		return operatorteam.OperatorTeam{}, invalidOperatorTeamProjection("null platform operator team")
	}
	return mapOperatorTeam(
		row.OperatorTeamID, row.TeamKey, row.DisplayName, row.Description, row.Version,
		row.CreatedByUserID, row.ArchivedAt, row.ArchivedByUserID, row.ArchiveReason,
		row.ActiveAssignmentCount, row.CreatedAt, row.UpdatedAt,
	)
}

func mapGotOperatorTeam(row *dbsql.GetPlatformOperatorTeamRow) (operatorteam.OperatorTeam, error) {
	if row == nil {
		return operatorteam.OperatorTeam{}, invalidOperatorTeamProjection("null platform operator team")
	}
	return mapOperatorTeam(
		row.OperatorTeamID, row.TeamKey, row.DisplayName, row.Description, row.Version,
		row.CreatedByUserID, row.ArchivedAt, row.ArchivedByUserID, row.ArchiveReason,
		row.ActiveAssignmentCount, row.CreatedAt, row.UpdatedAt,
	)
}

func mapOperatorTeam(
	idValue pgtype.UUID,
	key string,
	name string,
	description string,
	version int32,
	createdByValue pgtype.UUID,
	archivedValue pgtype.Timestamptz,
	archivedByValue pgtype.UUID,
	archiveReason string,
	activeAssignmentCount int64,
	createdValue pgtype.Timestamptz,
	updatedValue pgtype.Timestamptz,
) (operatorteam.OperatorTeam, error) {
	id, err := operatorTeamUUID(idValue)
	if err != nil {
		return operatorteam.OperatorTeam{}, err
	}
	createdBy, err := optionalOperatorTeamUUID(createdByValue)
	if err != nil {
		return operatorteam.OperatorTeam{}, err
	}
	archivedAt, err := optionalOperatorTeamTime(archivedValue)
	if err != nil {
		return operatorteam.OperatorTeam{}, err
	}
	archivedBy, err := optionalOperatorTeamUUID(archivedByValue)
	if err != nil {
		return operatorteam.OperatorTeam{}, err
	}
	createdAt, err := operatorTeamTime(createdValue)
	if err != nil {
		return operatorteam.OperatorTeam{}, err
	}
	updatedAt, err := operatorTeamTime(updatedValue)
	if err != nil {
		return operatorteam.OperatorTeam{}, err
	}
	if !validOperatorTeamKey(key) || !validOperatorTeamText(name, 1, 120, true) ||
		!validOperatorTeamText(description, 0, 500, false) || version < 1 ||
		activeAssignmentCount < 0 || updatedAt.Before(createdAt) {
		return operatorteam.OperatorTeam{}, invalidOperatorTeamProjection("invalid platform operator-team attributes")
	}

	state := operatorteam.OperatorTeamStateActive
	var reason *string
	switch {
	case archivedAt == nil && archivedBy == nil && archiveReason == "":
	case archivedAt != nil && archivedBy != nil && validOperatorTeamText(archiveReason, 1, 500, true) &&
		!archivedAt.Before(createdAt) && !archivedAt.After(updatedAt) && activeAssignmentCount == 0:
		state = operatorteam.OperatorTeamStateArchived
		reasonValue := archiveReason
		reason = &reasonValue
	default:
		return operatorteam.OperatorTeam{}, invalidOperatorTeamProjection("invalid platform operator-team archive tuple")
	}

	return operatorteam.OperatorTeam{
		OperatorTeamSummary: operatorteam.OperatorTeamSummary{ID: id, Key: key, Name: name, State: state},
		Description:         description, CreatedByUserID: createdBy, ArchivedAt: archivedAt,
		ArchivedByUserID: archivedBy, ArchiveReason: reason,
		ActiveAssignmentCount: activeAssignmentCount, Version: int64(version),
		CreatedAt: createdAt, UpdatedAt: updatedAt,
	}, nil
}

func mapListedOperatorTeamAssignment(
	tenantID uuid.UUID,
	row *dbsql.ListTenantOperatorTeamAssignmentsRow,
) (operatorteam.TenantAssignment, error) {
	if row == nil {
		return operatorteam.TenantAssignment{}, invalidOperatorTeamProjection("null operator-team assignment")
	}
	return mapOperatorTeamAssignment(
		tenantID, row.AssignmentEpochID, row.OperatorTeamID, row.TeamKey,
		row.TeamDisplayName, row.TeamArchivedAt, row.AssignedByMembershipID,
		row.AssignedByUserID, row.AssignmentReason, row.AssignedAt, row.EndedAt,
		row.EndedByMembershipID, row.EndedByUserID, row.EndReason, row.Version,
		row.UpdatedAt,
	)
}

func mapGotOperatorTeamAssignment(
	tenantID uuid.UUID,
	row *dbsql.GetTenantOperatorTeamAssignmentRow,
) (operatorteam.TenantAssignment, error) {
	if row == nil {
		return operatorteam.TenantAssignment{}, invalidOperatorTeamProjection("null operator-team assignment")
	}
	return mapOperatorTeamAssignment(
		tenantID, row.AssignmentEpochID, row.OperatorTeamID, row.TeamKey,
		row.TeamDisplayName, row.TeamArchivedAt, row.AssignedByMembershipID,
		row.AssignedByUserID, row.AssignmentReason, row.AssignedAt, row.EndedAt,
		row.EndedByMembershipID, row.EndedByUserID, row.EndReason, row.Version,
		row.UpdatedAt,
	)
}

func mapOperatorTeamAssignment(
	tenantID uuid.UUID,
	epochValue pgtype.UUID,
	operatorTeamValue pgtype.UUID,
	teamKey string,
	teamName string,
	teamArchivedValue pgtype.Timestamptz,
	assignedByMembershipValue pgtype.UUID,
	assignedByUserValue pgtype.UUID,
	reason string,
	assignedValue pgtype.Timestamptz,
	endedValue pgtype.Timestamptz,
	endedByMembershipValue pgtype.UUID,
	endedByUserValue pgtype.UUID,
	endReason string,
	version int32,
	updatedValue pgtype.Timestamptz,
) (operatorteam.TenantAssignment, error) {
	if !authorizationUUIDv7(tenantID) {
		return operatorteam.TenantAssignment{}, invalidOperatorTeamProjection("invalid assignment tenant")
	}
	epochID, err := operatorTeamUUID(epochValue)
	if err != nil {
		return operatorteam.TenantAssignment{}, err
	}
	operatorTeamID, err := operatorTeamUUID(operatorTeamValue)
	if err != nil {
		return operatorteam.TenantAssignment{}, err
	}
	teamArchivedAt, err := optionalOperatorTeamTime(teamArchivedValue)
	if err != nil {
		return operatorteam.TenantAssignment{}, err
	}
	if _, err = operatorTeamUUID(assignedByMembershipValue); err != nil {
		return operatorteam.TenantAssignment{}, invalidOperatorTeamProjection("invalid assignment grantor membership")
	}
	assignedByUserID, err := operatorTeamUUID(assignedByUserValue)
	if err != nil {
		return operatorteam.TenantAssignment{}, err
	}
	assignedAt, err := operatorTeamTime(assignedValue)
	if err != nil {
		return operatorteam.TenantAssignment{}, err
	}
	endedAt, err := optionalOperatorTeamTime(endedValue)
	if err != nil {
		return operatorteam.TenantAssignment{}, err
	}
	endedByMembershipID, err := optionalOperatorTeamUUID(endedByMembershipValue)
	if err != nil {
		return operatorteam.TenantAssignment{}, err
	}
	endedByUserID, err := optionalOperatorTeamUUID(endedByUserValue)
	if err != nil {
		return operatorteam.TenantAssignment{}, err
	}
	updatedAt, err := operatorTeamTime(updatedValue)
	if err != nil {
		return operatorteam.TenantAssignment{}, err
	}
	if !validOperatorTeamKey(teamKey) || !validOperatorTeamText(teamName, 1, 120, true) ||
		!validOperatorTeamText(reason, 1, 500, true) || version < 1 ||
		updatedAt.Before(assignedAt) {
		return operatorteam.TenantAssignment{}, invalidOperatorTeamProjection("invalid operator-team assignment attributes")
	}

	teamState := operatorteam.OperatorTeamStateActive
	if teamArchivedAt != nil {
		teamState = operatorteam.OperatorTeamStateArchived
	}
	state := operatorteam.AssignmentStateActive
	var outwardEndReason *string
	switch {
	case endedAt == nil && endedByMembershipID == nil && endedByUserID == nil && endReason == "" && teamArchivedAt == nil:
	case endedAt != nil && endedByMembershipID != nil && endedByUserID != nil &&
		validOperatorTeamText(endReason, 1, 500, true) && !endedAt.Before(assignedAt) && !endedAt.After(updatedAt):
		state = operatorteam.AssignmentStateEnded
		reasonValue := endReason
		outwardEndReason = &reasonValue
	default:
		return operatorteam.TenantAssignment{}, invalidOperatorTeamProjection("invalid operator-team assignment lifecycle tuple")
	}

	return operatorteam.TenantAssignment{
		EpochID: epochID, TenantID: tenantID,
		OperatorTeam: operatorteam.OperatorTeamSummary{
			ID: operatorTeamID, Key: teamKey, Name: teamName, State: teamState,
		},
		State: state, StartedAt: assignedAt, StartedByUserID: assignedByUserID,
		StartReason: reason, EndedAt: endedAt, EndedByUserID: endedByUserID,
		EndReason: outwardEndReason, Version: int64(version), UpdatedAt: updatedAt,
	}, nil
}

type operatorTeamRosterRecord struct {
	rosterEntryID, operatorTeamID, assignmentEpochID pgtype.UUID
	teamKey, teamName                                string
	teamArchivedAt, assignmentEndedAt                pgtype.Timestamptz
	membershipID, targetUserID                       pgtype.UUID
	email, displayName, membershipStatus             string
	compatibilityRole                                string
	userActive                                       bool
	sourceID                                         pgtype.UUID
	sourceKind, sourceKey                            string
	sourceAuthoritative                              bool
	sourceRetiredAt                                  pgtype.Timestamptz
	grantedByMembershipID, grantedByUserID           pgtype.UUID
	grantReason                                      string
	grantedAt, expiresAt, revokedAt                  pgtype.Timestamptz
	revokedByMembershipID, revokedByUserID           pgtype.UUID
	revokeReason, rosterState                        string
	version                                          int32
	updatedAt                                        pgtype.Timestamptz
}

func listedOperatorTeamRosterRecord(row *dbsql.ListTenantOperatorTeamRosterEntriesRow) (operatorTeamRosterRecord, error) {
	if row == nil {
		return operatorTeamRosterRecord{}, invalidOperatorTeamProjection("null operator-team roster entry")
	}
	return operatorTeamRosterRecord{
		rosterEntryID: row.RosterEntryID, operatorTeamID: row.OperatorTeamID,
		assignmentEpochID: row.AssignmentEpochID, teamKey: row.TeamKey, teamName: row.TeamDisplayName,
		teamArchivedAt: row.TeamArchivedAt, assignmentEndedAt: row.AssignmentEndedAt,
		membershipID: row.MembershipID, targetUserID: row.TargetUserID,
		email: row.Email, displayName: row.DisplayName, membershipStatus: row.MembershipStatus,
		compatibilityRole: row.CompatibilityRole, userActive: row.UserActive,
		sourceID: row.SourceID, sourceKind: row.SourceKind, sourceKey: row.SourceKey,
		sourceAuthoritative: row.SourceAuthoritative, sourceRetiredAt: row.SourceRetiredAt,
		grantedByMembershipID: row.GrantedByMembershipID, grantedByUserID: row.GrantedByUserID,
		grantReason: row.GrantReason, grantedAt: row.GrantedAt, expiresAt: row.ExpiresAt,
		revokedAt: row.RevokedAt, revokedByMembershipID: row.RevokedByMembershipID,
		revokedByUserID: row.RevokedByUserID, revokeReason: row.RevokeReason,
		rosterState: row.RosterState, version: row.Version, updatedAt: row.UpdatedAt,
	}, nil
}

func gotOperatorTeamRosterRecord(row *dbsql.GetTenantOperatorTeamRosterEntryRow) (operatorTeamRosterRecord, error) {
	if row == nil {
		return operatorTeamRosterRecord{}, invalidOperatorTeamProjection("null operator-team roster entry")
	}
	return operatorTeamRosterRecord{
		rosterEntryID: row.RosterEntryID, operatorTeamID: row.OperatorTeamID,
		assignmentEpochID: row.AssignmentEpochID, teamKey: row.TeamKey, teamName: row.TeamDisplayName,
		teamArchivedAt: row.TeamArchivedAt, assignmentEndedAt: row.AssignmentEndedAt,
		membershipID: row.MembershipID, targetUserID: row.TargetUserID,
		email: row.Email, displayName: row.DisplayName, membershipStatus: row.MembershipStatus,
		compatibilityRole: row.CompatibilityRole, userActive: row.UserActive,
		sourceID: row.SourceID, sourceKind: row.SourceKind, sourceKey: row.SourceKey,
		sourceAuthoritative: row.SourceAuthoritative, sourceRetiredAt: row.SourceRetiredAt,
		grantedByMembershipID: row.GrantedByMembershipID, grantedByUserID: row.GrantedByUserID,
		grantReason: row.GrantReason, grantedAt: row.GrantedAt, expiresAt: row.ExpiresAt,
		revokedAt: row.RevokedAt, revokedByMembershipID: row.RevokedByMembershipID,
		revokedByUserID: row.RevokedByUserID, revokeReason: row.RevokeReason,
		rosterState: row.RosterState, version: row.Version, updatedAt: row.UpdatedAt,
	}, nil
}

func mapOperatorTeamRosterEntry(
	tenantID, expectedTeamID, expectedEpochID uuid.UUID,
	record operatorTeamRosterRecord,
) (operatorteam.RosterEntry, error) {
	if !authorizationUUIDv7(tenantID) || !authorizationUUIDv7(expectedTeamID) ||
		!authorizationUUIDv7(expectedEpochID) {
		return operatorteam.RosterEntry{}, invalidOperatorTeamProjection("invalid roster relationship context")
	}
	rosterEntryID, err := operatorTeamUUID(record.rosterEntryID)
	if err != nil {
		return operatorteam.RosterEntry{}, err
	}
	operatorTeamID, err := operatorTeamUUID(record.operatorTeamID)
	if err != nil || operatorTeamID != expectedTeamID {
		return operatorteam.RosterEntry{}, invalidOperatorTeamProjection("unexpected roster operator team")
	}
	assignmentEpochID, err := operatorTeamUUID(record.assignmentEpochID)
	if err != nil || assignmentEpochID != expectedEpochID {
		return operatorteam.RosterEntry{}, invalidOperatorTeamProjection("unexpected roster assignment epoch")
	}
	if !validOperatorTeamKey(record.teamKey) || !validOperatorTeamText(record.teamName, 1, 120, true) {
		return operatorteam.RosterEntry{}, invalidOperatorTeamProjection("invalid roster team projection")
	}
	teamArchivedAt, err := optionalOperatorTeamTime(record.teamArchivedAt)
	if err != nil {
		return operatorteam.RosterEntry{}, err
	}
	assignmentEndedAt, err := optionalOperatorTeamTime(record.assignmentEndedAt)
	if err != nil {
		return operatorteam.RosterEntry{}, err
	}
	membershipID, err := operatorTeamUUID(record.membershipID)
	if err != nil {
		return operatorteam.RosterEntry{}, err
	}
	userID, err := operatorTeamUUID(record.targetUserID)
	if err != nil {
		return operatorteam.RosterEntry{}, err
	}
	membershipStatus, err := operatorTeamMembershipStatus(record.membershipStatus)
	if err != nil {
		return operatorteam.RosterEntry{}, err
	}
	if !validOperatorTeamText(record.email, 1, 320, true) ||
		!validOperatorTeamText(record.displayName, 1, 160, true) ||
		!knownOperatorTeamCompatibilityRole(record.compatibilityRole) {
		return operatorteam.RosterEntry{}, invalidOperatorTeamProjection("invalid roster member projection")
	}
	sourceID, err := operatorTeamUUID(record.sourceID)
	if err != nil {
		return operatorteam.RosterEntry{}, err
	}
	sourceKind, err := operatorTeamSourceKind(record.sourceKind)
	if err != nil || !validOperatorTeamSourceKey(record.sourceKey) {
		return operatorteam.RosterEntry{}, invalidOperatorTeamProjection("invalid roster source projection")
	}
	sourceRetiredAt, err := optionalOperatorTeamTime(record.sourceRetiredAt)
	if err != nil {
		return operatorteam.RosterEntry{}, err
	}
	grantedByMembershipID, err := optionalOperatorTeamUUID(record.grantedByMembershipID)
	if err != nil {
		return operatorteam.RosterEntry{}, err
	}
	grantedByUserID, err := optionalOperatorTeamUUID(record.grantedByUserID)
	if err != nil || (grantedByMembershipID == nil) != (grantedByUserID == nil) {
		return operatorteam.RosterEntry{}, invalidOperatorTeamProjection("invalid roster grantor tuple")
	}
	grantedAt, err := operatorTeamTime(record.grantedAt)
	if err != nil {
		return operatorteam.RosterEntry{}, err
	}
	expiresAt, err := optionalOperatorTeamTime(record.expiresAt)
	if err != nil {
		return operatorteam.RosterEntry{}, err
	}
	revokedAt, err := optionalOperatorTeamTime(record.revokedAt)
	if err != nil {
		return operatorteam.RosterEntry{}, err
	}
	revokedByMembershipID, err := optionalOperatorTeamUUID(record.revokedByMembershipID)
	if err != nil {
		return operatorteam.RosterEntry{}, err
	}
	revokedByUserID, err := optionalOperatorTeamUUID(record.revokedByUserID)
	if err != nil {
		return operatorteam.RosterEntry{}, err
	}
	updatedAt, err := operatorTeamTime(record.updatedAt)
	if err != nil {
		return operatorteam.RosterEntry{}, err
	}
	if !validOperatorTeamText(record.grantReason, 1, 500, true) || record.version < 1 ||
		updatedAt.Before(grantedAt) || expiresAt != nil && !expiresAt.After(grantedAt) ||
		sourceRetiredAt != nil && sourceRetiredAt.Before(grantedAt) {
		return operatorteam.RosterEntry{}, invalidOperatorTeamProjection("invalid roster provenance projection")
	}

	state, err := operatorTeamRosterState(
		record.rosterState, teamArchivedAt, assignmentEndedAt, sourceRetiredAt,
		membershipStatus, record.userActive,
	)
	if err != nil {
		return operatorteam.RosterEntry{}, err
	}
	var revokeReason *string
	switch state {
	case operatorteam.RosterEntryStateRevoked:
		if revokedAt == nil || revokedByMembershipID == nil || revokedByUserID == nil ||
			!validOperatorTeamText(record.revokeReason, 1, 500, true) ||
			revokedAt.Before(grantedAt) || revokedAt.After(updatedAt) {
			return operatorteam.RosterEntry{}, invalidOperatorTeamProjection("invalid roster revocation tuple")
		}
		reasonValue := record.revokeReason
		revokeReason = &reasonValue
	default:
		if revokedAt != nil || revokedByMembershipID != nil || revokedByUserID != nil || record.revokeReason != "" {
			return operatorteam.RosterEntry{}, invalidOperatorTeamProjection("unexpected roster revocation tuple")
		}
	}
	if sourceKind == authorization.AuthorizationSourceManual && grantedByUserID == nil {
		return operatorteam.RosterEntry{}, invalidOperatorTeamProjection("manual roster source lacks a grantor")
	}

	managed := sourceKind == authorization.AuthorizationSourceManual && record.sourceKey == "manual" &&
		!record.sourceAuthoritative && sourceRetiredAt == nil
	if record.sourceKey == "manual" && !managed {
		return operatorteam.RosterEntry{}, invalidOperatorTeamProjection("canonical manual roster source lost mutation ownership")
	}
	return operatorteam.RosterEntry{
		ID: rosterEntryID, TenantID: tenantID, AssignmentEpochID: assignmentEpochID,
		OperatorTeamID: operatorTeamID,
		Member: operatorteam.TenantMember{
			MembershipID: membershipID, UserID: userID,
			DisplayName: record.displayName, Status: membershipStatus,
		},
		Provenance: authorization.AuthorizationEdgeProvenance{
			SourceKind: sourceKind, SourceID: &sourceID, Authoritative: record.sourceAuthoritative,
			RetiredAt: sourceRetiredAt, GrantedByUserID: grantedByUserID,
			GrantedAt: grantedAt, Reason: record.grantReason, ExpiresAt: expiresAt,
		},
		State: state, RevokedAt: revokedAt, RevokedByUserID: revokedByUserID,
		RevokeReason: revokeReason, Version: int64(record.version), UpdatedAt: updatedAt,
		ManagedByOperatorTeamAPI: managed,
	}, nil
}

func operatorTeamRosterState(
	raw string,
	teamArchivedAt, assignmentEndedAt, sourceRetiredAt *time.Time,
	membershipStatus authorization.MembershipStatus,
	userActive bool,
) (operatorteam.RosterEntryState, error) {
	state := operatorteam.RosterEntryState(raw)
	switch state {
	case operatorteam.RosterEntryStateActive:
		if teamArchivedAt != nil || assignmentEndedAt != nil || sourceRetiredAt != nil ||
			membershipStatus != authorization.MembershipStatusActive || !userActive {
			return "", invalidOperatorTeamProjection("active roster state contradicts relationship lifecycle")
		}
	case operatorteam.RosterEntryStateExpired, operatorteam.RosterEntryStateRevoked:
	default:
		return "", invalidOperatorTeamProjection("unknown roster state")
	}
	return state, nil
}

func operatorTeamUUID(value pgtype.UUID) (uuid.UUID, error) {
	id, err := domainUUID(value)
	if err != nil || !authorizationUUIDv7(id) {
		return uuid.Nil, invalidOperatorTeamProjection("invalid UUIDv7")
	}
	return id, nil
}

func optionalOperatorTeamUUID(value pgtype.UUID) (*uuid.UUID, error) {
	if !value.Valid {
		return nil, nil
	}
	id, err := operatorTeamUUID(value)
	if err != nil {
		return nil, err
	}
	return &id, nil
}

func operatorTeamTime(value pgtype.Timestamptz) (time.Time, error) {
	timestamp, err := domainTime(value)
	if err != nil || timestamp.Nanosecond()%int(time.Microsecond) != 0 {
		return time.Time{}, invalidOperatorTeamProjection("invalid UTC microsecond timestamp")
	}
	if _, err = timestamp.MarshalJSON(); err != nil {
		return time.Time{}, invalidOperatorTeamProjection("timestamp outside JSON range")
	}
	return timestamp, nil
}

func optionalOperatorTeamTime(value pgtype.Timestamptz) (*time.Time, error) {
	if !value.Valid {
		return nil, nil
	}
	timestamp, err := operatorTeamTime(value)
	if err != nil {
		return nil, err
	}
	return &timestamp, nil
}

func operatorTeamMembershipStatus(value string) (authorization.MembershipStatus, error) {
	status := authorization.MembershipStatus(value)
	switch status {
	case authorization.MembershipStatusInvited,
		authorization.MembershipStatusActive,
		authorization.MembershipStatusSuspended:
		return status, nil
	default:
		return "", invalidOperatorTeamProjection("unknown membership status")
	}
}

func operatorTeamSourceKind(value string) (authorization.AuthorizationSourceKind, error) {
	kind := authorization.AuthorizationSourceKind(value)
	switch kind {
	case authorization.AuthorizationSourceSystem,
		authorization.AuthorizationSourceTenantCreation,
		authorization.AuthorizationSourceManual,
		authorization.AuthorizationSourceIdentityMapping,
		authorization.AuthorizationSourcePlatformRecovery:
		return kind, nil
	default:
		return "", invalidOperatorTeamProjection("unknown authorization source kind")
	}
}

func knownOperatorTeamCompatibilityRole(value string) bool {
	switch authorization.LegacyMembershipRole(value) {
	case authorization.LegacyMembershipRoleTenantAdmin,
		authorization.LegacyMembershipRoleSOCManager,
		authorization.LegacyMembershipRoleSeniorAnalyst,
		authorization.LegacyMembershipRoleAnalyst,
		authorization.LegacyMembershipRoleCustomerManager,
		authorization.LegacyMembershipRoleCustomerUser,
		authorization.LegacyMembershipRoleReadOnly:
		return true
	default:
		return false
	}
}

func validOperatorTeamKey(value string) bool {
	if len(value) < 3 || len(value) > 64 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value[1:] {
		if character < 'a' || character > 'z' {
			if character < '0' || character > '9' {
				if character != '_' {
					return false
				}
			}
		}
	}
	return true
}

func validOperatorTeamSourceKey(value string) bool {
	if len(value) < 2 || len(value) > 128 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	last := value[len(value)-1]
	if (last < 'a' || last > 'z') && (last < '0' || last > '9') {
		return false
	}
	for _, character := range value[1 : len(value)-1] {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' ||
			strings.ContainsRune("_.:-", character) {
			continue
		}
		return false
	}
	return true
}

func validOperatorTeamText(value string, minimum, maximum int, requireNonBlank bool) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	length := utf8.RuneCountInString(value)
	return length >= minimum && length <= maximum && (!requireNonBlank || strings.TrimSpace(value) != "")
}

func invalidOperatorTeamProjection(reason string) error {
	if reason == "" {
		reason = "invalid database projection"
	}
	return fmt.Errorf("%w: %s", operatorteam.ErrUnavailable, reason)
}
