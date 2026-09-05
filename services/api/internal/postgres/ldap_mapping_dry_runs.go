package postgres

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
)

const (
	maximumLDAPDryRunDisabledMappings = 32
	maximumLDAPDryRunMappings         = 1_000
	maximumLDAPSubjectAliases         = 16
)

var _ identityprovider.MappingDryRunRepository = (*IdentityProviderRepository)(nil)

func (r *IdentityProviderRepository) BeginMappingDryRun(
	ctx context.Context,
	params identityprovider.BeginMappingDryRunParams,
) (identityprovider.DirectoryOperationSnapshot, error) {
	if !validLDAPMappingDryRunBegin(params) {
		return identityprovider.DirectoryOperationSnapshot{}, identityprovider.ErrInvalidInput
	}
	audit, err := identityProviderAuditArgumentsFor(
		params.Audit,
		params.OccurredAt,
		params.Actor.AuthenticationMethod,
	)
	if err != nil {
		return identityprovider.DirectoryOperationSnapshot{}, err
	}
	disabledIDs := make([]pgtype.UUID, len(params.IncludeDisabledMappingIDs))
	for index, mappingID := range params.IncludeDisabledMappingIDs {
		disabledIDs[index] = toDatabaseUUID(mappingID)
	}
	return withLDAPDirectoryInspectionTransaction(
		ctx,
		r,
		params.HumanParams,
		func(queries ldapDirectoryInspectionQueries) (identityprovider.DirectoryOperationSnapshot, error) {
			row, queryErr := queries.BeginTenantLDAPMappingDryRun(
				ctx,
				dbsql.BeginTenantLDAPMappingDryRunParams{
					OperationRunID:            toDatabaseUUID(params.OperationRunID),
					BindingID:                 toDatabaseUUID(params.BindingID),
					IncludeDisabledMappingIds: disabledIDs,
					Reason:                    params.Reason,
					AuditEventID:              toDatabaseUUID(params.AuditEventID),
					RequestID:                 audit.requestID,
					CorrelationID:             audit.correlationID,
					IpAddress:                 audit.remoteAddress,
					UserAgent:                 audit.userAgent,
					AuthenticationMethod:      audit.authenticationMethod,
				},
			)
			if queryErr != nil {
				return identityprovider.DirectoryOperationSnapshot{}, mapIdentityProviderDatabaseError(queryErr)
			}
			return mapLDAPMappingDryRunNetworkSnapshot(
				row,
				params.TenantID,
				params.BindingID,
				params.OperationRunID,
			)
		},
	)
}

func (r *IdentityProviderRepository) GetMappingDryRunPlanningSnapshot(
	ctx context.Context,
	params identityprovider.GetMappingDryRunPlanningSnapshotParams,
) (identityprovider.MappingDryRunPlanningSnapshot, error) {
	if !validLDAPMappingDryRunPlanningRequest(params) {
		return identityprovider.MappingDryRunPlanningSnapshot{}, identityprovider.ErrInvalidInput
	}
	versions := make([]int32, len(params.SubjectAliases))
	digests := make([][]byte, len(params.SubjectAliases))
	for index, alias := range params.SubjectAliases {
		versions[index] = int32(alias.KeyVersion)
		digests[index] = append([]byte(nil), alias.Digest[:]...)
	}
	defer func() {
		for _, digest := range digests {
			clear(digest)
		}
	}()
	return withLDAPDirectoryInspectionTransaction(
		ctx,
		r,
		params.HumanParams,
		func(queries ldapDirectoryInspectionQueries) (identityprovider.MappingDryRunPlanningSnapshot, error) {
			row, queryErr := queries.GetTenantLDAPMappingDryRunPlanningSnapshot(
				ctx,
				dbsql.GetTenantLDAPMappingDryRunPlanningSnapshotParams{
					OperationRunID:    toDatabaseUUID(params.OperationRunID),
					DigestKeyVersions: versions,
					SubjectDigests:    digests,
				},
			)
			if queryErr != nil {
				return identityprovider.MappingDryRunPlanningSnapshot{}, mapIdentityProviderDatabaseError(queryErr)
			}
			return mapLDAPMappingDryRunPlanningSnapshot(
				row,
				params.TenantID,
				params.OperationRunID,
			)
		},
	)
}

func validLDAPMappingDryRunBegin(params identityprovider.BeginMappingDryRunParams) bool {
	if !validIdentityProviderHuman(params.HumanParams) ||
		!validIdentityProviderAudit(params.Audit) ||
		!validIdentityProviderOccurrence(params.OccurredAt) ||
		!identityProviderUUIDv7(params.OperationRunID) ||
		!identityProviderUUIDv7(params.AuditEventID) ||
		!identityProviderUUIDv7(params.BindingID) ||
		params.Audit.RequestID == uuid.Nil || params.Audit.CorrelationID == uuid.Nil ||
		!identityProviderText(params.Reason, 1, 500) ||
		len(params.IncludeDisabledMappingIDs) > maximumLDAPDryRunDisabledMappings {
		return false
	}
	seen := make(map[uuid.UUID]struct{}, len(params.IncludeDisabledMappingIDs))
	for _, mappingID := range params.IncludeDisabledMappingIDs {
		if !identityProviderUUIDv7(mappingID) {
			return false
		}
		if _, duplicate := seen[mappingID]; duplicate {
			return false
		}
		seen[mappingID] = struct{}{}
	}
	return true
}

func validLDAPMappingDryRunPlanningRequest(
	params identityprovider.GetMappingDryRunPlanningSnapshotParams,
) bool {
	if !validIdentityProviderHuman(params.HumanParams) ||
		!identityProviderUUIDv7(params.OperationRunID) ||
		len(params.SubjectAliases) < 1 || len(params.SubjectAliases) > maximumLDAPSubjectAliases {
		return false
	}
	var previous int16
	for index, alias := range params.SubjectAliases {
		if alias.KeyVersion < 1 || alias.KeyVersion > math.MaxInt16 ||
			index > 0 && alias.KeyVersion <= previous || allZero(alias.Digest[:]) {
			return false
		}
		previous = alias.KeyVersion
	}
	return true
}

type ldapPinnedMappingRevisionDocument struct {
	MappingID           uuid.UUID  `json:"mappingId"`
	MappingVersion      int64      `json:"mappingVersion"`
	SourceEpochID       *uuid.UUID `json:"sourceEpochId"`
	SourceEpochSequence *int       `json:"sourceEpochSequence"`
	IncludedDisabled    bool       `json:"includedDisabled"`
}

func mapLDAPMappingDryRunNetworkSnapshot(
	row *dbsql.BeginTenantLDAPMappingDryRunRow,
	tenantID, bindingID, operationRunID uuid.UUID,
) (identityprovider.DirectoryOperationSnapshot, error) {
	if row != nil {
		defer clear(row.EndpointSnapshotDigest)
		defer clear(row.BindSecretCiphertext)
		defer clear(row.BindSecretNonce)
	}
	if row == nil || row.ProviderVersion < 1 || row.ConfigurationVersion < 1 ||
		row.BindSecretVersion < 1 || row.BindSecretKeyVersion < 1 ||
		row.BindSecretKeyVersion > math.MaxInt16 || len(row.EndpointSnapshotDigest) != 32 ||
		allZero(row.EndpointSnapshotDigest) || len(row.BindSecretCiphertext) < 17 ||
		len(row.BindSecretCiphertext) > 8192 || len(row.BindSecretNonce) != 12 ||
		row.BindSecretAlgorithm != "aes-256-gcm" || row.BindingVersion < 1 ||
		row.BindingAuthRevision < 1 || row.RuleSetRevision < 1 || row.AuthorizationRevision < 1 {
		return identityprovider.DirectoryOperationSnapshot{}, invalidIdentityProviderProjection(
			"invalid LDAP mapping dry-run network snapshot",
		)
	}
	returnedRunID, err := requiredLDAPDryRunUUID(row.OperationRunID, operationRunID)
	if err != nil {
		return identityprovider.DirectoryOperationSnapshot{}, err
	}
	returnedTenantID, err := requiredLDAPDryRunUUID(row.TenantID, tenantID)
	if err != nil {
		return identityprovider.DirectoryOperationSnapshot{}, err
	}
	providerID, err := requiredLDAPDryRunUUID(row.ProviderID, uuid.Nil)
	if err != nil {
		return identityprovider.DirectoryOperationSnapshot{}, err
	}
	returnedBindingID, err := requiredLDAPDryRunUUID(row.BindingID, bindingID)
	if err != nil {
		return identityprovider.DirectoryOperationSnapshot{}, err
	}
	accessEpochID, err := requiredLDAPDryRunUUID(row.BindingAccessEpochID, uuid.Nil)
	if err != nil {
		return identityprovider.DirectoryOperationSnapshot{}, err
	}
	secretID, err := requiredLDAPDryRunUUID(row.BindSecretID, uuid.Nil)
	if err != nil {
		return identityprovider.DirectoryOperationSnapshot{}, err
	}
	configuration, err := decodeIdentityProviderJSON[identityprovider.Configuration](row.Configuration)
	if err != nil {
		return identityprovider.DirectoryOperationSnapshot{}, err
	}
	endpoints, err := decodeIdentityProviderJSON[[]identityprovider.Endpoint](row.Endpoints)
	if err != nil || len(endpoints) < 1 || len(endpoints) > 8 {
		return identityprovider.DirectoryOperationSnapshot{}, invalidIdentityProviderProjection(
			"invalid LDAP mapping dry-run endpoints",
		)
	}
	revisions, err := mapLDAPPinnedMappingRevisions(row.MappingRevisions)
	if err != nil {
		return identityprovider.DirectoryOperationSnapshot{}, err
	}
	startedAt, err := domainTime(row.StartedAt)
	if err != nil {
		return identityprovider.DirectoryOperationSnapshot{}, invalidIdentityProviderProjection(
			"invalid LDAP mapping dry-run start time",
		)
	}
	expiresAt, err := domainTime(row.ExpiresAt)
	if err != nil || !expiresAt.After(startedAt) || expiresAt.Sub(startedAt) > 2*time.Minute {
		return identityprovider.DirectoryOperationSnapshot{}, invalidIdentityProviderProjection(
			"invalid LDAP mapping dry-run expiry",
		)
	}
	var digest [32]byte
	copy(digest[:], row.EndpointSnapshotDigest)
	var nonce [12]byte
	copy(nonce[:], row.BindSecretNonce)
	bindingVersion := int64(row.BindingVersion)
	bindingAuthRevision := int(row.BindingAuthRevision)
	ruleSetRevision := row.RuleSetRevision
	authorizationRevision := row.AuthorizationRevision
	return identityprovider.DirectoryOperationSnapshot{
		OperationRunID:         returnedRunID,
		TenantID:               returnedTenantID,
		ProviderID:             providerID,
		OperationKind:          identityprovider.DirectoryOperationSearchUser,
		ProviderVersion:        int64(row.ProviderVersion),
		ConfigurationVersion:   int64(row.ConfigurationVersion),
		EndpointSnapshotDigest: digest,
		Configuration:          configuration,
		Endpoints:              endpoints,
		SecretVersion:          int64(row.BindSecretVersion),
		Secret: identityprovider.EncryptedBindSecret{
			SecretID: secretID,
			Envelope: identity.BindSecretEnvelope{
				KeyVersion: int16(row.BindSecretKeyVersion),
				Nonce:      nonce,
				Ciphertext: append([]byte(nil), row.BindSecretCiphertext...),
			},
		},
		BindingID:             &returnedBindingID,
		BindingVersion:        &bindingVersion,
		BindingAuthRevision:   &bindingAuthRevision,
		BindingAccessEpochID:  &accessEpochID,
		RuleSetRevision:       &ruleSetRevision,
		AuthorizationRevision: &authorizationRevision,
		MappingRevisions:      revisions,
		StartedAt:             startedAt,
		ExpiresAt:             expiresAt,
	}, nil
}

func mapLDAPPinnedMappingRevisions(
	document []byte,
) ([]identityprovider.PinnedMappingRevision, error) {
	rows, err := decodeIdentityProviderJSON[[]ldapPinnedMappingRevisionDocument](document)
	if err != nil || len(rows) > maximumLDAPDryRunMappings {
		return nil, invalidIdentityProviderProjection("invalid LDAP mapping dry-run revision pins")
	}
	result := make([]identityprovider.PinnedMappingRevision, 0, len(rows))
	seen := make(map[uuid.UUID]struct{}, len(rows))
	for _, row := range rows {
		if !identityProviderUUIDv7(row.MappingID) || row.MappingVersion < 1 ||
			row.MappingVersion > math.MaxInt32 ||
			(row.SourceEpochID == nil) != (row.SourceEpochSequence == nil) ||
			row.IncludedDisabled != (row.SourceEpochID == nil) ||
			row.SourceEpochID != nil && (!identityProviderUUIDv7(*row.SourceEpochID) ||
				row.SourceEpochSequence == nil || *row.SourceEpochSequence < 1 ||
				*row.SourceEpochSequence > math.MaxInt32) {
			return nil, invalidIdentityProviderProjection("invalid LDAP mapping dry-run revision pin")
		}
		if _, duplicate := seen[row.MappingID]; duplicate {
			return nil, invalidIdentityProviderProjection("duplicate LDAP mapping dry-run revision pin")
		}
		seen[row.MappingID] = struct{}{}
		var sourceEpochID *uuid.UUID
		var sourceEpochSequence *int
		if row.SourceEpochID != nil {
			id := *row.SourceEpochID
			sequence := *row.SourceEpochSequence
			sourceEpochID = &id
			sourceEpochSequence = &sequence
		}
		result = append(result, identityprovider.PinnedMappingRevision{
			MappingID: row.MappingID, MappingVersion: row.MappingVersion,
			SourceEpochID: sourceEpochID, SourceEpochSequence: sourceEpochSequence,
		})
	}
	return result, nil
}

func requiredLDAPDryRunUUID(value pgtype.UUID, expected uuid.UUID) (uuid.UUID, error) {
	identifier, err := domainUUID(value)
	if err != nil || !identityProviderUUIDv7(identifier) || expected != uuid.Nil && identifier != expected {
		return uuid.Nil, invalidIdentityProviderProjection("unexpected LDAP mapping dry-run identifier")
	}
	return identifier, nil
}

type ldapPlanningRuleDocument struct {
	RuleID                        uuid.UUID   `json:"ruleId"`
	RuleEpochID                   uuid.UUID   `json:"ruleEpochId"`
	SourceID                      uuid.UUID   `json:"sourceId"`
	Revision                      int64       `json:"revision"`
	Priority                      int32       `json:"priority"`
	Enabled                       bool        `json:"enabled"`
	MatcherType                   string      `json:"matcherType"`
	MatcherValue                  string      `json:"matcherValue"`
	CaseMode                      string      `json:"caseMode"`
	ReconciliationMode            string      `json:"reconciliationMode"`
	SecurityGroupID               uuid.UUID   `json:"securityGroupId"`
	RoleIDs                       []uuid.UUID `json:"roleIds"`
	ActiveGroupRoleIDs            []uuid.UUID `json:"activeGroupRoleIds,omitempty"`
	OperatorTeamID                *uuid.UUID  `json:"operatorTeamId"`
	OperatorTeamAssignmentEpochID *uuid.UUID  `json:"operatorTeamAssignmentEpochId"`
	OperatorTeamAssignmentLive    bool        `json:"operatorTeamAssignmentLive,omitempty"`
	AdministrativeNote            string      `json:"administrativeNote"`
}

type ldapPlanningSecurityGroupDocument struct {
	SecurityGroupID uuid.UUID   `json:"securityGroupId"`
	ActiveRoleIDs   []uuid.UUID `json:"activeRoleIds"`
}

type ldapPlanningAssignmentDocument struct {
	OperatorTeamID    uuid.UUID `json:"operatorTeamId"`
	AssignmentEpochID uuid.UUID `json:"assignmentEpochId"`
	Live              bool      `json:"live"`
}

type ldapPlanningPermissionDocument struct {
	Permission string `json:"permission"`
	Scope      string `json:"scope"`
}

type ldapPlanningRolePolicyDocument struct {
	RoleID uuid.UUID                        `json:"roleId"`
	Policy []ldapPlanningPermissionDocument `json:"policy"`
}

type ldapPlanningDelegationDocument struct {
	Permission string     `json:"permission"`
	Scope      string     `json:"scope"`
	NotAfter   *time.Time `json:"notAfter"`
}

type ldapPlanningOwnedEdgeDocument struct {
	SourceID    uuid.UUID  `json:"sourceId"`
	RuleEpochID uuid.UUID  `json:"ruleEpochId"`
	Kind        string     `json:"kind"`
	PrimaryID   uuid.UUID  `json:"primaryId"`
	SecondaryID *uuid.UUID `json:"secondaryId"`
}

func mapLDAPMappingDryRunPlanningSnapshot(
	row *dbsql.GetTenantLDAPMappingDryRunPlanningSnapshotRow,
	tenantID, operationRunID uuid.UUID,
) (identityprovider.MappingDryRunPlanningSnapshot, error) {
	if row == nil || row.ProviderVersion < 1 || row.BindingVersion < 1 ||
		row.BindingAuthRevision < 1 || row.ConfigurationRevision < 1 ||
		row.RuleSetRevision < 1 || row.AuthorizationRevision < 1 {
		return identityprovider.MappingDryRunPlanningSnapshot{}, invalidIdentityProviderProjection(
			"invalid LDAP mapping dry-run planning pins",
		)
	}
	returnedRunID, err := requiredLDAPDryRunUUID(row.OperationRunID, operationRunID)
	if err != nil {
		return identityprovider.MappingDryRunPlanningSnapshot{}, err
	}
	returnedTenantID, err := requiredLDAPDryRunUUID(row.TenantID, tenantID)
	if err != nil {
		return identityprovider.MappingDryRunPlanningSnapshot{}, err
	}
	providerID, err := requiredLDAPDryRunUUID(row.ProviderID, uuid.Nil)
	if err != nil {
		return identityprovider.MappingDryRunPlanningSnapshot{}, err
	}
	bindingID, err := requiredLDAPDryRunUUID(row.BindingID, uuid.Nil)
	if err != nil {
		return identityprovider.MappingDryRunPlanningSnapshot{}, err
	}
	accessEpochID, err := requiredLDAPDryRunUUID(row.BindingAccessEpochID, uuid.Nil)
	if err != nil {
		return identityprovider.MappingDryRunPlanningSnapshot{}, err
	}
	accessSourceID, err := requiredLDAPDryRunUUID(row.ProviderAccessSourceID, uuid.Nil)
	if err != nil {
		return identityprovider.MappingDryRunPlanningSnapshot{}, err
	}
	providerAccessEpochID, err := requiredLDAPDryRunUUID(row.ProviderAccessEpochID, accessEpochID)
	if err != nil {
		return identityprovider.MappingDryRunPlanningSnapshot{}, err
	}
	if row.ExternalIdentityID.Valid != row.ExternalIdentityExists ||
		row.UserID.Valid != row.ExternalIdentityExists ||
		row.MembershipID.Valid != row.TenantMembershipExists ||
		row.UserActive && !row.ExternalIdentityExists ||
		row.TenantMembershipExists && (!row.ExternalIdentityExists || !row.UserActive) ||
		row.TenantMembershipActive && !row.TenantMembershipExists ||
		row.AccessGrantLive && (!row.ExternalIdentityExists || !row.UserActive ||
			!row.TenantMembershipExists || !row.TenantMembershipActive) {
		return identityprovider.MappingDryRunPlanningSnapshot{}, invalidIdentityProviderProjection(
			"inconsistent LDAP mapping dry-run identity lifecycle",
		)
	}
	if row.ExternalIdentityID.Valid {
		if _, err := requiredLDAPDryRunUUID(row.ExternalIdentityID, uuid.Nil); err != nil {
			return identityprovider.MappingDryRunPlanningSnapshot{}, err
		}
		if _, err := requiredLDAPDryRunUUID(row.UserID, uuid.Nil); err != nil {
			return identityprovider.MappingDryRunPlanningSnapshot{}, err
		}
	}
	if row.MembershipID.Valid {
		if _, err := requiredLDAPDryRunUUID(row.MembershipID, uuid.Nil); err != nil {
			return identityprovider.MappingDryRunPlanningSnapshot{}, err
		}
	}

	rules, err := mapLDAPPlanningRules(row.Rules)
	if err != nil {
		return identityprovider.MappingDryRunPlanningSnapshot{}, err
	}
	securityGroups, err := mapLDAPPlanningSecurityGroups(row.SecurityGroups)
	if err != nil {
		return identityprovider.MappingDryRunPlanningSnapshot{}, err
	}
	assignments, err := mapLDAPPlanningAssignments(row.LiveAssignments)
	if err != nil {
		return identityprovider.MappingDryRunPlanningSnapshot{}, err
	}
	rolePolicies, err := mapLDAPPlanningRolePolicies(row.RolePolicies)
	if err != nil {
		return identityprovider.MappingDryRunPlanningSnapshot{}, err
	}
	existingRoles, err := mapLDAPPlanningPGUUIDs(row.ExistingEffectiveRoleIds, maximumLDAPDryRunMappings*10)
	if err != nil {
		return identityprovider.MappingDryRunPlanningSnapshot{}, err
	}
	delegation, err := mapLDAPPlanningDelegation(row.Delegation)
	if err != nil {
		return identityprovider.MappingDryRunPlanningSnapshot{}, err
	}
	edges, err := mapLDAPPlanningEdges(row.LiveOwnedEdges)
	if err != nil {
		return identityprovider.MappingDryRunPlanningSnapshot{}, err
	}
	jitMode, err := mapLDAPPlanningJITMode(row.JitMode)
	if err != nil {
		return identityprovider.MappingDryRunPlanningSnapshot{}, err
	}
	noMatchPolicy, err := mapLDAPPlanningNoMatchPolicy(row.NoMatchPolicy)
	if err != nil {
		return identityprovider.MappingDryRunPlanningSnapshot{}, err
	}
	var effectiveUntil *time.Time
	if row.EffectiveUntil.Valid {
		value, timeErr := domainTime(row.EffectiveUntil)
		if timeErr != nil {
			return identityprovider.MappingDryRunPlanningSnapshot{}, invalidIdentityProviderProjection(
				"invalid LDAP mapping dry-run effective-until timestamp",
			)
		}
		effectiveUntil = &value
	}
	tenantEntity := identity.EntityID(returnedTenantID)
	providerEntity := identity.EntityID(providerID)
	bindingEntity := identity.EntityID(bindingID)
	accessSourceEntity := identity.EntityID(accessSourceID)
	accessEpochEntity := identity.EntityID(providerAccessEpochID)
	planning := identity.LDAPPlanningSnapshot{
		TenantID: tenantEntity,
		Provider: identity.ProviderContext{
			Scope: identity.TenantProviderScope, TenantID: tenantEntity, ProviderID: providerEntity,
		},
		BindingID:             bindingEntity,
		ConfigurationRevision: int64(row.ConfigurationRevision),
		RuleSetRevision:       row.RuleSetRevision,
		AuthorizationRevision: row.AuthorizationRevision,
		JITMode:               jitMode,
		NoMatchPolicy:         noMatchPolicy,
		EffectiveUntil:        effectiveUntil,
		ProviderAccess: identity.LDAPProviderAccessState{
			SourceID:               accessSourceEntity,
			AccessEpochID:          accessEpochEntity,
			ExternalIdentityExists: row.ExternalIdentityExists,
			UserActive:             row.UserActive,
			TenantMembershipExists: row.TenantMembershipExists,
			TenantMembershipActive: row.TenantMembershipActive,
			AccessGrantLive:        row.AccessGrantLive,
		},
		Rules: rules, SecurityGroups: securityGroups, LiveAssignments: assignments,
		RolePolicies: rolePolicies, ExistingEffectiveRoleIDs: existingRoles,
		Delegation: delegation, LiveOwnedEdges: edges,
	}
	return identityprovider.MappingDryRunPlanningSnapshot{
		OperationRunID: returnedRunID, ProviderID: providerID,
		ProviderVersion: int64(row.ProviderVersion), BindingID: bindingID,
		BindingVersion: int64(row.BindingVersion), BindingAuthRevision: int(row.BindingAuthRevision),
		BindingAccessEpochID:  accessEpochID,
		ConfigurationRevision: int64(row.ConfigurationRevision),
		RuleSetRevision:       row.RuleSetRevision, AuthorizationRevision: row.AuthorizationRevision,
		Planning: planning,
	}, nil
}

func mapLDAPPlanningRules(document []byte) ([]identity.LDAPMappingRule, error) {
	rows, err := decodeIdentityProviderJSON[[]ldapPlanningRuleDocument](document)
	if err != nil || len(rows) > maximumLDAPDryRunMappings {
		return nil, invalidIdentityProviderProjection("invalid LDAP mapping dry-run rules")
	}
	result := make([]identity.LDAPMappingRule, 0, len(rows))
	for _, row := range rows {
		if !row.Enabled || row.Revision < 1 || row.Revision > math.MaxInt32 ||
			row.Priority < 0 || row.Priority > 1_000_000 || row.AdministrativeNote != "" ||
			(row.OperatorTeamID == nil) != (row.OperatorTeamAssignmentEpochID == nil) {
			return nil, invalidIdentityProviderProjection("invalid LDAP mapping dry-run rule")
		}
		matcher, compileErr := compileLDAPPlanningMatcher(row.MatcherType, row.CaseMode, row.MatcherValue)
		if compileErr != nil {
			return nil, compileErr
		}
		mode, modeErr := mapLDAPPlanningReconciliationMode(row.ReconciliationMode)
		if modeErr != nil {
			return nil, modeErr
		}
		ruleID, idErr := ldapPlanningEntityID(row.RuleID)
		if idErr != nil {
			return nil, idErr
		}
		epochID, idErr := ldapPlanningEntityID(row.RuleEpochID)
		if idErr != nil {
			return nil, idErr
		}
		sourceID, idErr := ldapPlanningEntityID(row.SourceID)
		if idErr != nil {
			return nil, idErr
		}
		groupID, idErr := ldapPlanningEntityID(row.SecurityGroupID)
		if idErr != nil {
			return nil, idErr
		}
		roles, idErr := mapLDAPPlanningUUIDs(row.RoleIDs, 100)
		if idErr != nil {
			return nil, idErr
		}
		var team *identity.LDAPOperatorTeamTarget
		if row.OperatorTeamID != nil {
			teamID, teamErr := ldapPlanningEntityID(*row.OperatorTeamID)
			if teamErr != nil {
				return nil, teamErr
			}
			assignmentID, teamErr := ldapPlanningEntityID(*row.OperatorTeamAssignmentEpochID)
			if teamErr != nil {
				return nil, teamErr
			}
			team = &identity.LDAPOperatorTeamTarget{TeamID: teamID, AssignmentEpochID: assignmentID}
		}
		result = append(result, identity.LDAPMappingRule{
			RuleID: ruleID, RuleEpochID: epochID, SourceID: sourceID,
			Revision: row.Revision, Priority: row.Priority, Enabled: true,
			Matcher: matcher, Mode: mode, SecurityGroupID: groupID,
			RoleIDs: roles, OperatorTeam: team, AdministrativeNote: "",
		})
	}
	return result, nil
}

func mapLDAPPlanningSecurityGroups(document []byte) ([]identity.LDAPSecurityGroupPolicy, error) {
	rows, err := decodeIdentityProviderJSON[[]ldapPlanningSecurityGroupDocument](document)
	if err != nil || len(rows) > maximumLDAPDryRunMappings {
		return nil, invalidIdentityProviderProjection("invalid LDAP mapping dry-run security groups")
	}
	result := make([]identity.LDAPSecurityGroupPolicy, 0, len(rows))
	for _, row := range rows {
		groupID, mapErr := ldapPlanningEntityID(row.SecurityGroupID)
		if mapErr != nil {
			return nil, mapErr
		}
		roles, mapErr := mapLDAPPlanningUUIDs(row.ActiveRoleIDs, maximumLDAPDryRunMappings*10)
		if mapErr != nil {
			return nil, mapErr
		}
		result = append(result, identity.LDAPSecurityGroupPolicy{
			SecurityGroupID: groupID, ActiveRoleIDs: roles,
		})
	}
	return result, nil
}

func mapLDAPPlanningAssignments(document []byte) ([]identity.LDAPOperatorTeamAssignment, error) {
	rows, err := decodeIdentityProviderJSON[[]ldapPlanningAssignmentDocument](document)
	if err != nil || len(rows) > maximumLDAPDryRunMappings {
		return nil, invalidIdentityProviderProjection("invalid LDAP mapping dry-run assignments")
	}
	result := make([]identity.LDAPOperatorTeamAssignment, 0, len(rows))
	for _, row := range rows {
		teamID, mapErr := ldapPlanningEntityID(row.OperatorTeamID)
		if mapErr != nil {
			return nil, mapErr
		}
		epochID, mapErr := ldapPlanningEntityID(row.AssignmentEpochID)
		if mapErr != nil {
			return nil, mapErr
		}
		result = append(result, identity.LDAPOperatorTeamAssignment{
			TeamID: teamID, AssignmentEpochID: epochID, Live: row.Live,
		})
	}
	return result, nil
}

func mapLDAPPlanningRolePolicies(document []byte) ([]identity.LDAPRolePolicy, error) {
	rows, err := decodeIdentityProviderJSON[[]ldapPlanningRolePolicyDocument](document)
	if err != nil || len(rows) > maximumLDAPDryRunMappings*10 {
		return nil, invalidIdentityProviderProjection("invalid LDAP mapping dry-run role policies")
	}
	result := make([]identity.LDAPRolePolicy, 0, len(rows))
	for _, row := range rows {
		if len(row.Policy) > maximumLDAPDryRunMappings*10 {
			return nil, invalidIdentityProviderProjection("oversized LDAP mapping dry-run role policy")
		}
		roleID, mapErr := ldapPlanningEntityID(row.RoleID)
		if mapErr != nil {
			return nil, mapErr
		}
		policy := make([]identity.LDAPPermissionTuple, 0, len(row.Policy))
		for _, tuple := range row.Policy {
			mapped, tupleErr := mapLDAPPlanningPermission(tuple.Permission, tuple.Scope)
			if tupleErr != nil {
				return nil, tupleErr
			}
			policy = append(policy, mapped)
		}
		result = append(result, identity.LDAPRolePolicy{RoleID: roleID, Policy: policy})
	}
	return result, nil
}

func mapLDAPPlanningDelegation(document []byte) ([]identity.LDAPDelegationGrant, error) {
	rows, err := decodeIdentityProviderJSON[[]ldapPlanningDelegationDocument](document)
	if err != nil || len(rows) > maximumLDAPDryRunMappings*100 {
		return nil, invalidIdentityProviderProjection("invalid LDAP mapping dry-run delegation")
	}
	result := make([]identity.LDAPDelegationGrant, 0, len(rows))
	for _, row := range rows {
		tuple, mapErr := mapLDAPPlanningPermission(row.Permission, row.Scope)
		if mapErr != nil || row.NotAfter != nil && row.NotAfter.IsZero() {
			return nil, invalidIdentityProviderProjection("invalid LDAP mapping dry-run delegation grant")
		}
		var notAfter *time.Time
		if row.NotAfter != nil {
			value := row.NotAfter.UTC()
			notAfter = &value
		}
		result = append(result, identity.LDAPDelegationGrant{Tuple: tuple, NotAfter: notAfter})
	}
	return result, nil
}

func mapLDAPPlanningEdges(document []byte) ([]identity.LDAPOwnedMappingEdge, error) {
	rows, err := decodeIdentityProviderJSON[[]ldapPlanningOwnedEdgeDocument](document)
	if err != nil || len(rows) > 100_000 {
		return nil, invalidIdentityProviderProjection("invalid LDAP mapping dry-run owned edges")
	}
	result := make([]identity.LDAPOwnedMappingEdge, 0, len(rows))
	for _, row := range rows {
		sourceID, mapErr := ldapPlanningEntityID(row.SourceID)
		if mapErr != nil {
			return nil, mapErr
		}
		epochID, mapErr := ldapPlanningEntityID(row.RuleEpochID)
		if mapErr != nil {
			return nil, mapErr
		}
		primaryID, mapErr := ldapPlanningEntityID(row.PrimaryID)
		if mapErr != nil {
			return nil, mapErr
		}
		kind, requiresSecondary, mapErr := mapLDAPPlanningEdgeKind(row.Kind)
		if mapErr != nil || requiresSecondary != (row.SecondaryID != nil) {
			return nil, invalidIdentityProviderProjection("invalid LDAP mapping dry-run owned edge")
		}
		var secondaryID identity.EntityID
		if row.SecondaryID != nil {
			secondaryID, mapErr = ldapPlanningEntityID(*row.SecondaryID)
			if mapErr != nil {
				return nil, mapErr
			}
		}
		result = append(result, identity.LDAPOwnedMappingEdge{
			SourceID: sourceID, RuleEpochID: epochID,
			Key: identity.LDAPMappingEdgeKey{
				Kind: kind, PrimaryID: primaryID, SecondaryID: secondaryID,
			},
		})
	}
	return result, nil
}

func mapLDAPPlanningPGUUIDs(values []pgtype.UUID, maximum int) ([]identity.EntityID, error) {
	if len(values) > maximum {
		return nil, invalidIdentityProviderProjection("oversized LDAP mapping dry-run ID list")
	}
	result := make([]identity.EntityID, 0, len(values))
	for _, value := range values {
		identifier, err := requiredLDAPDryRunUUID(value, uuid.Nil)
		if err != nil {
			return nil, err
		}
		result = append(result, identity.EntityID(identifier))
	}
	return result, nil
}

func mapLDAPPlanningUUIDs(values []uuid.UUID, maximum int) ([]identity.EntityID, error) {
	if len(values) > maximum {
		return nil, invalidIdentityProviderProjection("oversized LDAP mapping dry-run ID list")
	}
	result := make([]identity.EntityID, 0, len(values))
	for _, value := range values {
		identifier, err := ldapPlanningEntityID(value)
		if err != nil {
			return nil, err
		}
		result = append(result, identifier)
	}
	return result, nil
}

func ldapPlanningEntityID(value uuid.UUID) (identity.EntityID, error) {
	if !identityProviderUUIDv7(value) {
		return identity.EntityID{}, invalidIdentityProviderProjection(
			"invalid LDAP mapping dry-run entity ID",
		)
	}
	return identity.EntityID(value), nil
}

func compileLDAPPlanningMatcher(
	kindValue, caseValue, pattern string,
) (identity.CompiledLDAPGroupMatcher, error) {
	var kind identity.LDAPGroupMatcherKind
	switch kindValue {
	case string(identityprovider.MappingMatcherExactDN):
		kind = identity.LDAPGroupMatcherExactDN
	case string(identityprovider.MappingMatcherExactCN):
		kind = identity.LDAPGroupMatcherExactCN
	case string(identityprovider.MappingMatcherRegex):
		kind = identity.LDAPGroupMatcherRegex
	default:
		return identity.CompiledLDAPGroupMatcher{}, invalidIdentityProviderProjection(
			"invalid LDAP mapping dry-run matcher kind",
		)
	}
	var caseMode identity.LDAPGroupCaseMode
	switch caseValue {
	case string(identityprovider.MappingCaseSensitive):
		caseMode = identity.LDAPGroupCaseSensitive
	case string(identityprovider.MappingCaseInsensitive):
		caseMode = identity.LDAPGroupCaseInsensitive
	default:
		return identity.CompiledLDAPGroupMatcher{}, invalidIdentityProviderProjection(
			"invalid LDAP mapping dry-run matcher case mode",
		)
	}
	matcher, err := identity.CompileLDAPGroupMatcher(identity.LDAPGroupMatcherSpec{
		Kind: kind, CaseMode: caseMode, Pattern: pattern,
	})
	if err != nil {
		return identity.CompiledLDAPGroupMatcher{}, invalidIdentityProviderProjection(
			"invalid LDAP mapping dry-run matcher",
		)
	}
	return matcher, nil
}

func mapLDAPPlanningReconciliationMode(value string) (identity.LDAPReconciliationMode, error) {
	switch value {
	case string(identityprovider.ReconciliationAdditive):
		return identity.LDAPReconciliationAdditive, nil
	case string(identityprovider.ReconciliationAuthoritative):
		return identity.LDAPReconciliationAuthoritative, nil
	default:
		return 0, invalidIdentityProviderProjection("invalid LDAP mapping dry-run reconciliation mode")
	}
}

func mapLDAPPlanningJITMode(value string) (identity.LDAPJITMode, error) {
	switch value {
	case string(identityprovider.JITModeDisabled):
		return identity.LDAPJITDisabled, nil
	case string(identityprovider.JITModeExistingIdentity):
		return identity.LDAPJITExistingIdentity, nil
	case string(identityprovider.JITModeCreate):
		return identity.LDAPJITCreate, nil
	default:
		return 0, invalidIdentityProviderProjection("invalid LDAP mapping dry-run JIT mode")
	}
}

func mapLDAPPlanningNoMatchPolicy(value string) (identity.LDAPNoMatchPolicy, error) {
	switch value {
	case string(identityprovider.NoMatchPolicyDeny):
		return identity.LDAPNoMatchDeny, nil
	case string(identityprovider.NoMatchPolicyProviderAccessOnly):
		return identity.LDAPNoMatchProviderAccessOnly, nil
	default:
		return 0, invalidIdentityProviderProjection("invalid LDAP mapping dry-run no-match policy")
	}
}

func mapLDAPPlanningPermission(permission, scopeValue string) (identity.LDAPPermissionTuple, error) {
	var scope identity.LDAPPermissionScope
	switch scopeValue {
	case string(identity.LDAPScopeOwn):
		scope = identity.LDAPScopeOwn
	case string(identity.LDAPScopeAssigned):
		scope = identity.LDAPScopeAssigned
	case string(identity.LDAPScopeOperatorTeam):
		scope = identity.LDAPScopeOperatorTeam
	case string(identity.LDAPScopeTenant):
		scope = identity.LDAPScopeTenant
	default:
		return identity.LDAPPermissionTuple{}, invalidIdentityProviderProjection(
			"invalid LDAP mapping dry-run permission scope",
		)
	}
	if !identityProviderText(permission, 1, 128) {
		return identity.LDAPPermissionTuple{}, invalidIdentityProviderProjection(
			"invalid LDAP mapping dry-run permission",
		)
	}
	return identity.LDAPPermissionTuple{Permission: permission, Scope: scope}, nil
}

func mapLDAPPlanningEdgeKind(
	value string,
) (identity.LDAPMappingEdgeKind, bool, error) {
	switch value {
	case "security_group_membership":
		return identity.LDAPSecurityGroupMembershipEdge, false, nil
	case "security_group_role_grant":
		return identity.LDAPSecurityGroupRoleGrantEdge, true, nil
	case "operator_team_roster":
		return identity.LDAPOperatorTeamRosterEdge, true, nil
	default:
		return 0, false, fmt.Errorf(
			"%w: invalid LDAP mapping dry-run edge kind",
			identityprovider.ErrUnavailable,
		)
	}
}
