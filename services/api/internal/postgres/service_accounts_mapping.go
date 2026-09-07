package postgres

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/periapsis-im/periapsis/services/api/internal/alert"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/serviceaccount"
)

const (
	maximumServiceAccountVersion = int64(2_147_483_647)
	maximumCredentialKeyVersion  = int32(32_767)
	maximumCredentialAge         = 90 * 24 * time.Hour
)

var (
	serviceAccountKeyPattern      = regexp.MustCompile(`^[a-z][a-z0-9_]{2,63}$`)
	authorizationSourceKeyPattern = regexp.MustCompile(
		`^[a-z][a-z0-9_.:-]{0,126}[a-z0-9]$`,
	)
)

type serviceAccountRecord struct {
	id                     pgtype.UUID
	key                    string
	displayName            string
	description            string
	createdByMembershipID  pgtype.UUID
	createdByUserID        pgtype.UUID
	archivedAt             pgtype.Timestamptz
	archivedByMembershipID pgtype.UUID
	archivedByUserID       pgtype.UUID
	archiveReason          string
	version                int32
	createdAt              pgtype.Timestamptz
	updatedAt              pgtype.Timestamptz
}

func mapServiceAccount(tenantID uuid.UUID, record serviceAccountRecord) (serviceaccount.Account, error) {
	if !serviceAccountUUIDv7(tenantID) || !serviceAccountKeyPattern.MatchString(record.key) ||
		record.displayName != strings.TrimSpace(record.displayName) ||
		record.description != strings.TrimSpace(record.description) ||
		!serviceAccountText(record.displayName, 1, 120) ||
		!serviceAccountText(record.description, 0, 500) ||
		record.version < 1 {
		return serviceaccount.Account{}, invalidServiceAccountProjection("invalid service-account attributes")
	}
	id, err := serviceAccountDatabaseUUID(record.id)
	if err != nil {
		return serviceaccount.Account{}, err
	}
	createdByMembershipID, err := serviceAccountDatabaseUUID(record.createdByMembershipID)
	if err != nil {
		return serviceaccount.Account{}, err
	}
	if _, err = serviceAccountDatabaseUUID(record.createdByUserID); err != nil {
		return serviceaccount.Account{}, invalidServiceAccountProjection("invalid service-account creator")
	}
	archivedAt, err := optionalServiceAccountTime(record.archivedAt)
	if err != nil {
		return serviceaccount.Account{}, err
	}
	archivedByMembershipID, err := optionalServiceAccountUUID(record.archivedByMembershipID)
	if err != nil {
		return serviceaccount.Account{}, err
	}
	archivedByUserID, err := optionalServiceAccountUUID(record.archivedByUserID)
	if err != nil {
		return serviceaccount.Account{}, err
	}
	createdAt, err := serviceAccountDatabaseTime(record.createdAt)
	if err != nil {
		return serviceaccount.Account{}, err
	}
	updatedAt, err := serviceAccountDatabaseTime(record.updatedAt)
	if err != nil || updatedAt.Before(createdAt) {
		return serviceaccount.Account{}, invalidServiceAccountProjection("invalid service-account timestamps")
	}

	state := serviceaccount.AccountStateActive
	var archiveReason *string
	switch {
	case archivedAt == nil && archivedByMembershipID == nil && archivedByUserID == nil && record.archiveReason == "":
	case archivedAt != nil && archivedByMembershipID != nil && archivedByUserID != nil &&
		!archivedAt.Before(createdAt) && !archivedAt.After(updatedAt) &&
		record.archiveReason == strings.TrimSpace(record.archiveReason) &&
		serviceAccountText(record.archiveReason, 1, 500):
		state = serviceaccount.AccountStateArchived
		reason := record.archiveReason
		archiveReason = &reason
	default:
		return serviceaccount.Account{}, invalidServiceAccountProjection("invalid service-account archive tuple")
	}

	return serviceaccount.Account{
		ID: id, TenantID: tenantID, Key: record.key, DisplayName: record.displayName,
		Description: record.description, State: state,
		CreatedByMembershipID: createdByMembershipID, ArchivedAt: archivedAt,
		ArchivedByMembershipID: archivedByMembershipID, ArchiveReason: archiveReason,
		Version: int64(record.version), CreatedAt: createdAt, UpdatedAt: updatedAt,
	}, nil
}

type serviceAccountRoleGrantRecord struct {
	id                    pgtype.UUID
	serviceAccountID      pgtype.UUID
	roleID                pgtype.UUID
	roleKey               string
	roleDisplayName       string
	roleSystem            bool
	sourceID              pgtype.UUID
	sourceKind            string
	sourceKey             string
	sourceAuthoritative   bool
	sourceRetiredAt       pgtype.Timestamptz
	grantedByMembershipID pgtype.UUID
	grantedByUserID       pgtype.UUID
	grantReason           string
	grantedAt             pgtype.Timestamptz
	expiresAt             pgtype.Timestamptz
	revokedAt             pgtype.Timestamptz
	revokedByMembershipID pgtype.UUID
	revokedByUserID       pgtype.UUID
	revokeReason          string
	state                 string
	version               int32
	updatedAt             pgtype.Timestamptz
}

func mapServiceAccountRoleGrant(
	tenantID, expectedServiceAccountID uuid.UUID,
	record serviceAccountRoleGrantRecord,
) (serviceaccount.RoleGrant, error) {
	if !serviceAccountUUIDv7(tenantID) || !serviceAccountUUIDv7(expectedServiceAccountID) ||
		!serviceAccountKeyPattern.MatchString(record.roleKey) ||
		record.roleDisplayName != strings.TrimSpace(record.roleDisplayName) ||
		!serviceAccountText(record.roleDisplayName, 1, 120) ||
		!authorizationSourceKeyPattern.MatchString(record.sourceKey) ||
		record.grantReason != strings.TrimSpace(record.grantReason) ||
		!serviceAccountText(record.grantReason, 1, 500) || record.version < 1 {
		return serviceaccount.RoleGrant{}, invalidServiceAccountProjection("invalid service-account role-grant attributes")
	}
	id, err := serviceAccountDatabaseUUID(record.id)
	if err != nil {
		return serviceaccount.RoleGrant{}, err
	}
	serviceAccountID, err := serviceAccountDatabaseUUID(record.serviceAccountID)
	if err != nil || serviceAccountID != expectedServiceAccountID {
		return serviceaccount.RoleGrant{}, invalidServiceAccountProjection("unexpected service-account role-grant owner")
	}
	roleID, err := serviceAccountDatabaseUUID(record.roleID)
	if err != nil {
		return serviceaccount.RoleGrant{}, err
	}
	sourceID, err := serviceAccountDatabaseUUID(record.sourceID)
	if err != nil {
		return serviceaccount.RoleGrant{}, err
	}
	sourceKind, err := serviceAccountSourceKind(record.sourceKind)
	if err != nil {
		return serviceaccount.RoleGrant{}, err
	}
	sourceRetiredAt, err := optionalServiceAccountTime(record.sourceRetiredAt)
	if err != nil {
		return serviceaccount.RoleGrant{}, err
	}
	grantedByMembershipID, err := serviceAccountDatabaseUUID(record.grantedByMembershipID)
	if err != nil {
		return serviceaccount.RoleGrant{}, err
	}
	grantedByUserID, err := serviceAccountDatabaseUUID(record.grantedByUserID)
	if err != nil {
		return serviceaccount.RoleGrant{}, err
	}
	grantedAt, err := serviceAccountDatabaseTime(record.grantedAt)
	if err != nil {
		return serviceaccount.RoleGrant{}, err
	}
	expiresAt, err := optionalServiceAccountTime(record.expiresAt)
	if err != nil || expiresAt != nil && !expiresAt.After(grantedAt) {
		return serviceaccount.RoleGrant{}, invalidServiceAccountProjection("invalid service-account role-grant expiry")
	}
	revokedAt, err := optionalServiceAccountTime(record.revokedAt)
	if err != nil {
		return serviceaccount.RoleGrant{}, err
	}
	revokedByMembershipID, err := optionalServiceAccountUUID(record.revokedByMembershipID)
	if err != nil {
		return serviceaccount.RoleGrant{}, err
	}
	revokedByUserID, err := optionalServiceAccountUUID(record.revokedByUserID)
	if err != nil {
		return serviceaccount.RoleGrant{}, err
	}
	updatedAt, err := serviceAccountDatabaseTime(record.updatedAt)
	if err != nil || updatedAt.Before(grantedAt) {
		return serviceaccount.RoleGrant{}, invalidServiceAccountProjection("invalid service-account role-grant timestamps")
	}
	state := serviceaccount.RoleGrantState(record.state)
	var revokeReason *string
	switch state {
	case serviceaccount.RoleGrantStateActive:
		if sourceRetiredAt != nil || revokedAt != nil || revokedByMembershipID != nil || revokedByUserID != nil || record.revokeReason != "" {
			return serviceaccount.RoleGrant{}, invalidServiceAccountProjection("invalid active service-account role-grant tuple")
		}
	case serviceaccount.RoleGrantStateExpired:
		if revokedAt != nil || revokedByMembershipID != nil || revokedByUserID != nil || record.revokeReason != "" {
			return serviceaccount.RoleGrant{}, invalidServiceAccountProjection("invalid expired service-account role-grant tuple")
		}
	case serviceaccount.RoleGrantStateRevoked:
		if revokedAt == nil || revokedByMembershipID == nil || revokedByUserID == nil ||
			revokedAt.Before(grantedAt) || revokedAt.After(updatedAt) ||
			record.revokeReason != strings.TrimSpace(record.revokeReason) ||
			!serviceAccountText(record.revokeReason, 1, 500) {
			return serviceaccount.RoleGrant{}, invalidServiceAccountProjection("invalid revoked service-account role-grant tuple")
		}
		reason := record.revokeReason
		revokeReason = &reason
	default:
		return serviceaccount.RoleGrant{}, invalidServiceAccountProjection("unknown service-account role-grant state")
	}
	managed := sourceKind == authorization.AuthorizationSourceManual && record.sourceKey == "manual" &&
		!record.sourceAuthoritative && sourceRetiredAt == nil
	return serviceaccount.RoleGrant{
		ID: id, TenantID: tenantID, ServiceAccountID: serviceAccountID,
		Role:     serviceaccount.RoleSummary{ID: roleID, Key: record.roleKey, DisplayName: record.roleDisplayName, System: record.roleSystem},
		SourceID: sourceID, SourceKind: sourceKind, SourceKey: record.sourceKey,
		SourceAuthoritative: record.sourceAuthoritative, SourceRetiredAt: sourceRetiredAt,
		GrantedByMembershipID: grantedByMembershipID, GrantedByUserID: grantedByUserID,
		GrantReason: record.grantReason, GrantedAt: grantedAt, ExpiresAt: expiresAt,
		State: state, RevokedAt: revokedAt, RevokedByMembershipID: revokedByMembershipID,
		RevokedByUserID: revokedByUserID, RevokeReason: revokeReason,
		Version: int64(record.version), UpdatedAt: updatedAt, ManagedByServiceAccountAPI: managed,
	}, nil
}

type serviceAccountCredentialRecord struct {
	id                      pgtype.UUID
	serviceAccountID        pgtype.UUID
	label                   string
	formatVersion           int32
	keyVersion              int32
	issuedByMembershipID    pgtype.UUID
	issuedByUserID          pgtype.UUID
	issuedAt                pgtype.Timestamptz
	expiresAt               pgtype.Timestamptz
	rotatedFromCredentialID pgtype.UUID
	revokedAt               pgtype.Timestamptz
	revokedByMembershipID   pgtype.UUID
	revokedByUserID         pgtype.UUID
	revokeReason            string
	lastUsedAt              pgtype.Timestamptz
	lastUsedIP              *netip.Addr
	state                   string
	version                 int32
	updatedAt               pgtype.Timestamptz
	permissionKeys          []string
	permissionScopes        []string
	networks                []netip.Prefix
}

func mapServiceAccountCredential(
	tenantID, expectedServiceAccountID uuid.UUID,
	record serviceAccountCredentialRecord,
) (serviceaccount.CredentialMetadata, error) {
	if !serviceAccountUUIDv7(tenantID) || !serviceAccountUUIDv7(expectedServiceAccountID) ||
		record.label != strings.TrimSpace(record.label) || !serviceAccountText(record.label, 1, 120) ||
		record.formatVersion != 1 || record.keyVersion < 1 || record.keyVersion > maximumCredentialKeyVersion ||
		record.version < 1 {
		return serviceaccount.CredentialMetadata{}, invalidServiceAccountProjection("invalid API credential attributes")
	}
	id, err := serviceAccountDatabaseUUID(record.id)
	if err != nil {
		return serviceaccount.CredentialMetadata{}, err
	}
	serviceAccountID, err := serviceAccountDatabaseUUID(record.serviceAccountID)
	if err != nil || serviceAccountID != expectedServiceAccountID {
		return serviceaccount.CredentialMetadata{}, invalidServiceAccountProjection("unexpected API credential owner")
	}
	issuedByMembershipID, err := serviceAccountDatabaseUUID(record.issuedByMembershipID)
	if err != nil {
		return serviceaccount.CredentialMetadata{}, err
	}
	if _, err = serviceAccountDatabaseUUID(record.issuedByUserID); err != nil {
		return serviceaccount.CredentialMetadata{}, invalidServiceAccountProjection("invalid API credential issuer")
	}
	issuedAt, err := serviceAccountDatabaseTime(record.issuedAt)
	if err != nil {
		return serviceaccount.CredentialMetadata{}, err
	}
	expiresAt, err := serviceAccountDatabaseTime(record.expiresAt)
	if err != nil || !expiresAt.After(issuedAt) || expiresAt.After(issuedAt.Add(maximumCredentialAge)) {
		return serviceaccount.CredentialMetadata{}, invalidServiceAccountProjection("invalid API credential expiry")
	}
	rotatedFromCredentialID, err := optionalServiceAccountUUID(record.rotatedFromCredentialID)
	if err != nil || rotatedFromCredentialID != nil && *rotatedFromCredentialID == id {
		return serviceaccount.CredentialMetadata{}, invalidServiceAccountProjection("invalid API credential rotation origin")
	}
	revokedAt, err := optionalServiceAccountTime(record.revokedAt)
	if err != nil {
		return serviceaccount.CredentialMetadata{}, err
	}
	revokedByMembershipID, err := optionalServiceAccountUUID(record.revokedByMembershipID)
	if err != nil {
		return serviceaccount.CredentialMetadata{}, err
	}
	revokedByUserID, err := optionalServiceAccountUUID(record.revokedByUserID)
	if err != nil {
		return serviceaccount.CredentialMetadata{}, err
	}
	lastUsedAt, err := optionalServiceAccountTime(record.lastUsedAt)
	if err != nil {
		return serviceaccount.CredentialMetadata{}, err
	}
	updatedAt, err := serviceAccountDatabaseTime(record.updatedAt)
	if err != nil || updatedAt.Before(issuedAt) || lastUsedAt != nil &&
		(lastUsedAt.Before(issuedAt) || lastUsedAt.After(expiresAt) || lastUsedAt.After(updatedAt)) {
		return serviceaccount.CredentialMetadata{}, invalidServiceAccountProjection("invalid API credential timestamps")
	}
	lastUsedIP, err := canonicalOptionalAddress(record.lastUsedIP)
	if err != nil || (lastUsedAt == nil) != (lastUsedIP == nil) {
		return serviceaccount.CredentialMetadata{}, invalidServiceAccountProjection("invalid API credential last-use tuple")
	}
	permissions, err := mapCredentialPermissions(record.permissionKeys, record.permissionScopes)
	if err != nil {
		return serviceaccount.CredentialMetadata{}, err
	}
	networks, err := mapCredentialNetworks(record.networks)
	if err != nil {
		return serviceaccount.CredentialMetadata{}, err
	}
	state := serviceaccount.CredentialState(record.state)
	var revokeReason *string
	switch state {
	case serviceaccount.CredentialStateActive, serviceaccount.CredentialStateExpired:
		if revokedAt != nil || revokedByMembershipID != nil || revokedByUserID != nil || record.revokeReason != "" {
			return serviceaccount.CredentialMetadata{}, invalidServiceAccountProjection("invalid live API credential tuple")
		}
	case serviceaccount.CredentialStateRevoked:
		if revokedAt == nil || revokedByMembershipID == nil || revokedByUserID == nil ||
			revokedAt.Before(issuedAt) || revokedAt.After(updatedAt) || lastUsedAt != nil && lastUsedAt.After(*revokedAt) ||
			record.revokeReason != strings.TrimSpace(record.revokeReason) ||
			!serviceAccountText(record.revokeReason, 1, 500) {
			return serviceaccount.CredentialMetadata{}, invalidServiceAccountProjection("invalid revoked API credential tuple")
		}
		reason := record.revokeReason
		revokeReason = &reason
	default:
		return serviceaccount.CredentialMetadata{}, invalidServiceAccountProjection("unknown API credential state")
	}
	return serviceaccount.CredentialMetadata{
		ID: id, TenantID: tenantID, ServiceAccountID: serviceAccountID, Label: record.label,
		FormatVersion: int16(record.formatVersion), KeyVersion: int16(record.keyVersion),
		Permissions: permissions, Networks: networks, IssuedByMembershipID: issuedByMembershipID,
		IssuedAt: issuedAt, ExpiresAt: expiresAt, RotatedFromCredentialID: rotatedFromCredentialID,
		State: state, RevokedAt: revokedAt, RevokedByMembershipID: revokedByMembershipID,
		RevokedByUserID: revokedByUserID, RevokeReason: revokeReason, LastUsedAt: lastUsedAt,
		LastUsedIP: lastUsedIP, Version: int64(record.version), UpdatedAt: updatedAt,
	}, nil
}

type alertRecord struct {
	id                        pgtype.UUID
	number                    string
	workflowID                pgtype.UUID
	workflowVersion           int32
	stateKey                  string
	customerVisible           bool
	externalID                *string
	deduplicationKey          *string
	title                     string
	description               *string
	status                    string
	severity                  string
	priority                  string
	category                  string
	classification            *string
	source                    string
	sourceType                string
	tags                      []string
	customFields              []byte
	customerCustomFields      []byte
	rawPayload                []byte
	assignedTeamID            pgtype.UUID
	assigneeUserID            pgtype.UUID
	claimedByUserID           pgtype.UUID
	createdByUserID           pgtype.UUID
	createdByMembershipID     pgtype.UUID
	createdByServiceAccountID pgtype.UUID
	detectedAt                pgtype.Timestamptz
	receivedAt                pgtype.Timestamptz
	acknowledgedAt            pgtype.Timestamptz
	closedAt                  pgtype.Timestamptz
	assignedAt                pgtype.Timestamptz
	firstResponseAt           pgtype.Timestamptz
	resolvedAt                pgtype.Timestamptz
	claimedAt                 pgtype.Timestamptz
	createdAt                 pgtype.Timestamptz
	updatedAt                 pgtype.Timestamptz
	version                   int32
	replayed                  bool
}

func mapCreatedAlert(tenantID uuid.UUID, record alertRecord) (alert.IdempotentCreateResult, error) {
	if !serviceAccountUUIDv7(tenantID) || !serviceAccountText(record.title, 1, 240) ||
		record.number == "" || record.workflowVersion < 1 || record.stateKey == "" ||
		record.externalID != nil && !serviceAccountText(*record.externalID, 1, 200) ||
		record.description != nil && !serviceAccountText(*record.description, 0, 10_000) ||
		record.version < 1 {
		return alert.IdempotentCreateResult{}, invalidAlertProjection("invalid Alert attributes")
	}
	id, err := serviceAccountDatabaseUUID(record.id)
	if err != nil {
		return alert.IdempotentCreateResult{}, invalidAlertProjection("invalid Alert identifier")
	}
	workflowID, err := serviceAccountDatabaseUUID(record.workflowID)
	if err != nil {
		return alert.IdempotentCreateResult{}, invalidAlertProjection("invalid Alert workflow")
	}
	status := alert.Status(record.status)
	if status != alert.StatusNew && status != alert.StatusInProgress && status != alert.StatusClosed {
		return alert.IdempotentCreateResult{}, invalidAlertProjection("unknown Alert status")
	}
	severity := alert.Severity(record.severity)
	switch severity {
	case alert.SeverityInformational, alert.SeverityLow, alert.SeverityMedium, alert.SeverityHigh, alert.SeverityCritical:
	default:
		return alert.IdempotentCreateResult{}, invalidAlertProjection("unknown Alert severity")
	}
	createdByUserID, err := optionalServiceAccountUUID(record.createdByUserID)
	if err != nil {
		return alert.IdempotentCreateResult{}, invalidAlertProjection("invalid Alert human creator")
	}
	createdByMembershipID, err := optionalServiceAccountUUID(record.createdByMembershipID)
	if err != nil {
		return alert.IdempotentCreateResult{}, invalidAlertProjection("invalid Alert membership creator")
	}
	createdByServiceAccountID, err := optionalServiceAccountUUID(record.createdByServiceAccountID)
	if err != nil {
		return alert.IdempotentCreateResult{}, invalidAlertProjection("invalid Alert machine creator")
	}
	assignedTeamID, err := optionalServiceAccountUUID(record.assignedTeamID)
	if err != nil {
		return alert.IdempotentCreateResult{}, invalidAlertProjection("invalid Alert team")
	}
	assigneeUserID, err := optionalServiceAccountUUID(record.assigneeUserID)
	if err != nil {
		return alert.IdempotentCreateResult{}, invalidAlertProjection("invalid Alert assignee")
	}
	claimedByUserID, err := optionalServiceAccountUUID(record.claimedByUserID)
	if err != nil {
		return alert.IdempotentCreateResult{}, invalidAlertProjection("invalid Alert claimant")
	}
	human := createdByUserID != nil && createdByMembershipID != nil && createdByServiceAccountID == nil
	machine := createdByUserID == nil && createdByMembershipID == nil && createdByServiceAccountID != nil
	if human == machine {
		return alert.IdempotentCreateResult{}, invalidAlertProjection("Alert creator attribution is not exclusive")
	}
	createdAt, err := serviceAccountDatabaseTime(record.createdAt)
	if err != nil {
		return alert.IdempotentCreateResult{}, invalidAlertProjection("invalid Alert creation time")
	}
	updatedAt, err := serviceAccountDatabaseTime(record.updatedAt)
	if err != nil || updatedAt.Before(createdAt) {
		return alert.IdempotentCreateResult{}, invalidAlertProjection("invalid Alert update time")
	}
	detectedAt, err := serviceAccountDatabaseTime(record.detectedAt)
	if err != nil {
		return alert.IdempotentCreateResult{}, invalidAlertProjection("invalid Alert detection time")
	}
	receivedAt, err := serviceAccountDatabaseTime(record.receivedAt)
	if err != nil {
		return alert.IdempotentCreateResult{}, invalidAlertProjection("invalid Alert receive time")
	}
	customFields, err := decodeAlertJSONMap(record.customFields)
	if err != nil {
		return alert.IdempotentCreateResult{}, err
	}
	customerCustomFields, err := decodeAlertJSONMap(record.customerCustomFields)
	if err != nil {
		return alert.IdempotentCreateResult{}, err
	}
	rawPayload, err := decodeAlertJSONMap(record.rawPayload)
	if err != nil {
		return alert.IdempotentCreateResult{}, err
	}
	return alert.IdempotentCreateResult{Alert: alert.Alert{
		ID: id, TenantID: tenantID, Number: record.number, WorkflowID: workflowID,
		WorkflowVersion: int64(record.workflowVersion), StateKey: record.stateKey,
		CustomerVisible: record.customerVisible, ExternalID: cloneString(record.externalID),
		DeduplicationKey: cloneString(record.deduplicationKey), Title: record.title,
		Description: cloneString(record.description), Status: status, Severity: severity,
		Priority: record.priority, Category: record.category, Classification: cloneString(record.classification),
		Source: record.source, SourceType: record.sourceType, Tags: slices.Clone(record.tags),
		CustomFields: customFields, CustomerCustomFields: customerCustomFields, RawPayload: rawPayload,
		AssignedTeamID: assignedTeamID, AssigneeUserID: assigneeUserID, ClaimedByUserID: claimedByUserID,
		CreatedByUserID: createdByUserID, CreatedByMembershipID: createdByMembershipID,
		CreatedByServiceAccountID: createdByServiceAccountID, DetectedAt: detectedAt, ReceivedAt: receivedAt,
		AcknowledgedAt: optionalDomainTime(record.acknowledgedAt), ClosedAt: optionalDomainTime(record.closedAt),
		AssignedAt: optionalDomainTime(record.assignedAt), FirstResponseAt: optionalDomainTime(record.firstResponseAt),
		ResolvedAt: optionalDomainTime(record.resolvedAt), ClaimedAt: optionalDomainTime(record.claimedAt), CreatedAt: createdAt,
		UpdatedAt: updatedAt, Version: int64(record.version),
	}, Replayed: record.replayed}, nil
}

func decodeAlertJSONMap(value []byte) (map[string]any, error) {
	result := make(map[string]any)
	if len(value) == 0 {
		return result, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.UseNumber()
	if !json.Valid(value) || decoder.Decode(&result) != nil {
		return nil, invalidAlertProjection("invalid Alert JSON projection")
	}
	return result, nil
}

func mapCredentialPermissions(keys, scopes []string) ([]authorization.ScopedPermission, error) {
	if len(keys) == 0 || len(keys) > 100 || len(keys) != len(scopes) {
		return nil, invalidServiceAccountProjection("invalid API credential permission arrays")
	}
	result := make([]authorization.ScopedPermission, len(keys))
	for index := range keys {
		if authorization.TenantPermission(keys[index]) != authorization.TenantPermissionAlertCreate ||
			authorization.Scope(scopes[index]) != authorization.ScopeTenant {
			return nil, invalidServiceAccountProjection("unknown API credential permission")
		}
		result[index] = authorization.ScopedPermission{
			Permission: authorization.TenantPermission(keys[index]), Scope: authorization.Scope(scopes[index]),
		}
	}
	slices.SortFunc(result, func(left, right authorization.ScopedPermission) int {
		if compared := strings.Compare(string(left.Permission), string(right.Permission)); compared != 0 {
			return compared
		}
		return strings.Compare(string(left.Scope), string(right.Scope))
	})
	for index := 1; index < len(result); index++ {
		if result[index-1] == result[index] {
			return nil, invalidServiceAccountProjection("duplicate API credential permission")
		}
	}
	return result, nil
}

func mapCredentialNetworks(values []netip.Prefix) ([]netip.Prefix, error) {
	if len(values) > 32 {
		return nil, invalidServiceAccountProjection("too many API credential networks")
	}
	result := make([]netip.Prefix, len(values))
	for index, value := range values {
		if !value.IsValid() || value.Addr().Is4In6() || value != value.Masked() {
			return nil, invalidServiceAccountProjection("invalid API credential network")
		}
		result[index] = value
	}
	slices.SortFunc(result, serviceaccount.CompareCredentialNetworks)
	for index := 1; index < len(result); index++ {
		if result[index-1] == result[index] {
			return nil, invalidServiceAccountProjection("duplicate API credential network")
		}
	}
	return result, nil
}

func serviceAccountSourceKind(value string) (authorization.AuthorizationSourceKind, error) {
	kind := authorization.AuthorizationSourceKind(value)
	switch kind {
	case authorization.AuthorizationSourceSystem,
		authorization.AuthorizationSourceTenantCreation,
		authorization.AuthorizationSourceManual,
		authorization.AuthorizationSourceIdentityMapping,
		authorization.AuthorizationSourcePlatformRecovery:
		return kind, nil
	default:
		return "", invalidServiceAccountProjection("unknown authorization source kind")
	}
}

func serviceAccountDatabaseUUID(value pgtype.UUID) (uuid.UUID, error) {
	identifier, err := domainUUID(value)
	if err != nil || !serviceAccountUUIDv7(identifier) {
		return uuid.Nil, invalidServiceAccountProjection("invalid UUIDv7")
	}
	return identifier, nil
}

func optionalServiceAccountUUID(value pgtype.UUID) (*uuid.UUID, error) {
	if !value.Valid {
		return nil, nil
	}
	identifier, err := serviceAccountDatabaseUUID(value)
	if err != nil {
		return nil, err
	}
	return &identifier, nil
}

func serviceAccountDatabaseTime(value pgtype.Timestamptz) (time.Time, error) {
	timestamp, err := domainTime(value)
	if err != nil || timestamp.Nanosecond()%int(time.Microsecond) != 0 {
		return time.Time{}, invalidServiceAccountProjection("invalid timestamp")
	}
	return timestamp, nil
}

func optionalServiceAccountTime(value pgtype.Timestamptz) (*time.Time, error) {
	if !value.Valid {
		return nil, nil
	}
	timestamp, err := serviceAccountDatabaseTime(value)
	if err != nil {
		return nil, err
	}
	return &timestamp, nil
}

func canonicalOptionalAddress(value *netip.Addr) (*netip.Addr, error) {
	if value == nil {
		return nil, nil
	}
	if !value.IsValid() || value.Zone() != "" || value.Is4In6() {
		return nil, errors.New("invalid database IP address")
	}
	address := *value
	return &address, nil
}

func serviceAccountUUIDv7(value uuid.UUID) bool {
	return value != uuid.Nil && value.Version() == 7 && value.Variant() == uuid.RFC4122
}

func serviceAccountText(value string, minimum, maximum int) bool {
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

func cloneString(value *string) *string {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func compareUUID(left, right uuid.UUID) int {
	return bytes.Compare(left[:], right[:])
}

func invalidServiceAccountProjection(reason string) error {
	return fmt.Errorf("%w: database returned %s", serviceaccount.ErrUnavailable, reason)
}

func invalidAlertProjection(reason string) error {
	return fmt.Errorf("%w: database returned %s", alert.ErrUnavailable, reason)
}
