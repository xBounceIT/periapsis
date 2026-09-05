package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
)

type ldapDirectoryInspectionQueries interface {
	SetTenantContext(context.Context, dbsql.SetTenantContextParams) (*dbsql.SetTenantContextRow, error)
	BeginTenantLDAPAdministrativeDirectoryInspection(
		context.Context,
		dbsql.BeginTenantLDAPAdministrativeDirectoryInspectionParams,
	) (*dbsql.BeginTenantLDAPAdministrativeDirectoryInspectionRow, error)
	BeginTenantLDAPMappingDryRun(
		context.Context,
		dbsql.BeginTenantLDAPMappingDryRunParams,
	) (*dbsql.BeginTenantLDAPMappingDryRunRow, error)
	GetTenantLDAPMappingDryRunPlanningSnapshot(
		context.Context,
		dbsql.GetTenantLDAPMappingDryRunPlanningSnapshotParams,
	) (*dbsql.GetTenantLDAPMappingDryRunPlanningSnapshotRow, error)
	CompleteTenantLDAPDirectoryInspection(
		context.Context,
		dbsql.CompleteTenantLDAPDirectoryInspectionParams,
	) (*dbsql.CompleteTenantLDAPDirectoryInspectionRow, error)
}

var _ identityprovider.DirectoryInspectionRepository = (*IdentityProviderRepository)(nil)

func (r *IdentityProviderRepository) BeginAdministrativeDirectoryInspection(
	ctx context.Context,
	params identityprovider.BeginAdministrativeDirectoryInspectionParams,
) (identityprovider.DirectoryOperationSnapshot, error) {
	if !validIdentityProviderMutation(
		params.HumanParams,
		params.Audit,
		params.OccurredAt,
		params.ProviderID,
	) || !identityProviderUUIDv7(params.OperationRunID) ||
		!identityProviderUUIDv7(params.AuditEventID) ||
		!validLDAPDirectoryOperationKind(params.OperationKind) ||
		!identityProviderText(params.Reason, 1, 500) ||
		params.Audit.RequestID == uuid.Nil || params.Audit.CorrelationID == uuid.Nil {
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
	return withLDAPDirectoryInspectionTransaction(
		ctx,
		r,
		params.HumanParams,
		func(queries ldapDirectoryInspectionQueries) (identityprovider.DirectoryOperationSnapshot, error) {
			row, queryErr := queries.BeginTenantLDAPAdministrativeDirectoryInspection(
				ctx,
				dbsql.BeginTenantLDAPAdministrativeDirectoryInspectionParams{
					OperationRunID:       toDatabaseUUID(params.OperationRunID),
					ProviderID:           toDatabaseUUID(params.ProviderID),
					OperationKind:        string(params.OperationKind),
					Reason:               params.Reason,
					AuditEventID:         toDatabaseUUID(params.AuditEventID),
					RequestID:            audit.requestID,
					CorrelationID:        audit.correlationID,
					IpAddress:            audit.remoteAddress,
					UserAgent:            audit.userAgent,
					AuthenticationMethod: audit.authenticationMethod,
				},
			)
			if queryErr != nil {
				return identityprovider.DirectoryOperationSnapshot{}, mapIdentityProviderDatabaseError(queryErr)
			}
			return mapLDAPAdministrativeDirectorySnapshot(
				row,
				params.TenantID,
				params.ProviderID,
				params.OperationRunID,
				params.OperationKind,
			)
		},
	)
}

func (r *IdentityProviderRepository) CompleteDirectoryInspection(
	ctx context.Context,
	params identityprovider.CompleteDirectoryInspectionParams,
) (identityprovider.DirectoryInspectionCompletion, error) {
	if !validLDAPDirectoryInspectionCompletion(params) {
		return identityprovider.DirectoryInspectionCompletion{}, identityprovider.ErrInvalidInput
	}
	audit, err := identityProviderAuditArgumentsFor(
		params.Audit,
		params.OccurredAt,
		params.Actor.AuthenticationMethod,
	)
	if err != nil {
		return identityprovider.DirectoryInspectionCompletion{}, err
	}
	var endpointPriority *int32
	if params.EndpointPriority != nil {
		value := int32(*params.EndpointPriority)
		endpointPriority = &value
	}
	return withLDAPDirectoryInspectionTransaction(
		ctx,
		r,
		params.HumanParams,
		func(queries ldapDirectoryInspectionQueries) (identityprovider.DirectoryInspectionCompletion, error) {
			row, queryErr := queries.CompleteTenantLDAPDirectoryInspection(
				ctx,
				dbsql.CompleteTenantLDAPDirectoryInspectionParams{
					OperationRunID:       toDatabaseUUID(params.OperationRunID),
					ReportedOutcome:      string(params.ReportedOutcome),
					ReportedCategory:     string(params.ReportedCategory),
					EndpointPriority:     endpointPriority,
					DurationMs:           int32(params.Duration / time.Millisecond),
					MatchedEntryCount:    int32(params.MatchedEntryCount),
					Truncated:            params.Truncated,
					AuditEventID:         toDatabaseUUID(params.AuditEventID),
					RequestID:            audit.requestID,
					CorrelationID:        audit.correlationID,
					IpAddress:            audit.remoteAddress,
					UserAgent:            audit.userAgent,
					AuthenticationMethod: audit.authenticationMethod,
				},
			)
			if queryErr != nil {
				return identityprovider.DirectoryInspectionCompletion{}, mapIdentityProviderDatabaseError(queryErr)
			}
			return mapLDAPDirectoryInspectionCompletion(row, params.OperationRunID)
		},
	)
}

func withLDAPDirectoryInspectionTransaction[T any](
	ctx context.Context,
	repository *IdentityProviderRepository,
	human identityprovider.HumanParams,
	work func(ldapDirectoryInspectionQueries) (T, error),
) (T, error) {
	var zero T
	if !validIdentityProviderHuman(human) {
		return zero, identityprovider.ErrForbidden
	}
	if repository == nil || repository.begin == nil ||
		repository.directoryInspectionQueryFactory == nil || work == nil {
		return zero, fmt.Errorf(
			"%w: LDAP directory-inspection repository dependencies are required",
			identityprovider.ErrUnavailable,
		)
	}
	result, err := withinTransaction(
		ctx,
		repository.begin,
		func(tx databaseTransaction) (T, error) {
			queries := repository.directoryInspectionQueryFactory(tx)
			if queries == nil {
				return zero, invalidIdentityProviderProjection(
					"LDAP directory-inspection query surface is unavailable",
				)
			}
			installed, installErr := queries.SetTenantContext(
				ctx,
				dbsql.SetTenantContextParams{
					TenantID: toDatabaseUUID(human.TenantID),
					UserID:   toDatabaseUUID(human.Actor.UserID),
				},
			)
			if installErr != nil {
				return zero, mapIdentityProviderDatabaseError(installErr)
			}
			if installed == nil || installed.TenantID != human.TenantID.String() ||
				installed.UserID != human.Actor.UserID.String() {
				return zero, invalidIdentityProviderProjection(
					"database installed an unexpected LDAP directory-inspection context",
				)
			}
			return work(queries)
		},
	)
	if err != nil {
		return zero, mapIdentityProviderDatabaseError(err)
	}
	return result, nil
}

func mapLDAPAdministrativeDirectorySnapshot(
	row *dbsql.BeginTenantLDAPAdministrativeDirectoryInspectionRow,
	tenantID, providerID, operationRunID uuid.UUID,
	kind identityprovider.DirectoryOperationKind,
) (identityprovider.DirectoryOperationSnapshot, error) {
	if row != nil {
		defer clear(row.EndpointSnapshotDigest)
		defer clear(row.BindSecretCiphertext)
		defer clear(row.BindSecretNonce)
	}
	if row == nil || row.ProviderVersion < 1 || row.ConfigurationVersion < 1 ||
		row.BindSecretVersion < 1 || row.BindSecretKeyVersion < 1 ||
		row.BindSecretKeyVersion > 32767 || len(row.EndpointSnapshotDigest) != 32 ||
		allZero(row.EndpointSnapshotDigest) || len(row.BindSecretCiphertext) < 17 ||
		len(row.BindSecretCiphertext) > 8192 || len(row.BindSecretNonce) != 12 ||
		row.BindSecretAlgorithm != "aes-256-gcm" {
		return identityprovider.DirectoryOperationSnapshot{}, invalidIdentityProviderProjection(
			"invalid LDAP directory-inspection snapshot",
		)
	}
	returnedRunID, err := domainUUID(row.OperationRunID)
	if err != nil || returnedRunID != operationRunID || !identityProviderUUIDv7(returnedRunID) {
		return identityprovider.DirectoryOperationSnapshot{}, invalidIdentityProviderProjection(
			"unexpected LDAP directory-inspection run ID",
		)
	}
	returnedTenantID, err := domainUUID(row.TenantID)
	if err != nil || returnedTenantID != tenantID || !identityProviderUUIDv7(returnedTenantID) {
		return identityprovider.DirectoryOperationSnapshot{}, invalidIdentityProviderProjection(
			"unexpected LDAP directory-inspection tenant",
		)
	}
	returnedProviderID, err := domainUUID(row.ProviderID)
	if err != nil || returnedProviderID != providerID || !identityProviderUUIDv7(returnedProviderID) {
		return identityprovider.DirectoryOperationSnapshot{}, invalidIdentityProviderProjection(
			"unexpected LDAP directory-inspection provider",
		)
	}
	secretID, err := domainUUID(row.BindSecretID)
	if err != nil || !identityProviderUUIDv7(secretID) {
		return identityprovider.DirectoryOperationSnapshot{}, invalidIdentityProviderProjection(
			"invalid LDAP directory-inspection bind-secret ID",
		)
	}
	configuration, err := decodeIdentityProviderJSON[identityprovider.Configuration](row.Configuration)
	if err != nil {
		return identityprovider.DirectoryOperationSnapshot{}, err
	}
	endpoints, err := decodeIdentityProviderJSON[[]identityprovider.Endpoint](row.Endpoints)
	if err != nil || len(endpoints) < 1 || len(endpoints) > 8 {
		return identityprovider.DirectoryOperationSnapshot{}, invalidIdentityProviderProjection(
			"invalid LDAP directory-inspection endpoints",
		)
	}
	startedAt, err := domainTime(row.StartedAt)
	if err != nil {
		return identityprovider.DirectoryOperationSnapshot{}, invalidIdentityProviderProjection(
			"invalid LDAP directory-inspection start time",
		)
	}
	expiresAt, err := domainTime(row.ExpiresAt)
	if err != nil || !expiresAt.After(startedAt) || expiresAt.Sub(startedAt) > 2*time.Minute {
		return identityprovider.DirectoryOperationSnapshot{}, invalidIdentityProviderProjection(
			"invalid LDAP directory-inspection expiry",
		)
	}
	var digest [32]byte
	copy(digest[:], row.EndpointSnapshotDigest)
	var nonce [12]byte
	copy(nonce[:], row.BindSecretNonce)
	return identityprovider.DirectoryOperationSnapshot{
		OperationRunID:         returnedRunID,
		TenantID:               returnedTenantID,
		ProviderID:             returnedProviderID,
		OperationKind:          kind,
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
		StartedAt: startedAt,
		ExpiresAt: expiresAt,
	}, nil
}

func mapLDAPDirectoryInspectionCompletion(
	row *dbsql.CompleteTenantLDAPDirectoryInspectionRow,
	operationRunID uuid.UUID,
) (identityprovider.DirectoryInspectionCompletion, error) {
	if row == nil || row.EndpointPriority < 0 || row.EndpointPriority > 8 ||
		row.DurationMs < 0 || row.DurationMs > 120_000 ||
		row.MatchedEntryCount < 0 || row.MatchedEntryCount > 10 {
		return identityprovider.DirectoryInspectionCompletion{}, invalidIdentityProviderProjection(
			"invalid LDAP directory-inspection completion",
		)
	}
	returnedRunID, err := domainUUID(row.OperationRunID)
	if err != nil || returnedRunID != operationRunID || !identityProviderUUIDv7(returnedRunID) {
		return identityprovider.DirectoryInspectionCompletion{}, invalidIdentityProviderProjection(
			"unexpected LDAP directory-inspection completion ID",
		)
	}
	completedAt, err := domainTime(row.CompletedAt)
	if err != nil {
		return identityprovider.DirectoryInspectionCompletion{}, invalidIdentityProviderProjection(
			"invalid LDAP directory-inspection completion time",
		)
	}
	var endpointPriority *int
	if row.EndpointPriority != 0 {
		value := int(row.EndpointPriority)
		endpointPriority = &value
	}
	return identityprovider.DirectoryInspectionCompletion{
		Diagnostic: identityprovider.TestResult{
			TestRunID:        returnedRunID,
			Outcome:          identityprovider.TestOutcome(row.Outcome),
			Category:         identityprovider.TestCategory(row.Category),
			EndpointPriority: endpointPriority,
			Duration:         time.Duration(row.DurationMs) * time.Millisecond,
			Stale:            row.Stale,
			CompletedAt:      completedAt,
		},
		MatchedEntryCount: int(row.MatchedEntryCount),
		Truncated:         row.Truncated,
	}, nil
}

func validLDAPDirectoryOperationKind(value identityprovider.DirectoryOperationKind) bool {
	return value == identityprovider.DirectoryOperationSearchUser ||
		value == identityprovider.DirectoryOperationFilterUser ||
		value == identityprovider.DirectoryOperationFilterGroup
}

func validLDAPDirectoryInspectionCompletion(
	params identityprovider.CompleteDirectoryInspectionParams,
) bool {
	if !validIdentityProviderHuman(params.HumanParams) ||
		!validIdentityProviderAudit(params.Audit) ||
		!validIdentityProviderOccurrence(params.OccurredAt) ||
		!identityProviderUUIDv7(params.OperationRunID) ||
		!identityProviderUUIDv7(params.AuditEventID) ||
		params.Audit.RequestID == uuid.Nil || params.Audit.CorrelationID == uuid.Nil ||
		params.Duration < 0 || params.Duration > 120*time.Second ||
		params.Duration%time.Millisecond != 0 ||
		params.MatchedEntryCount < 0 || params.MatchedEntryCount > 10 ||
		(params.EndpointPriority != nil &&
			(*params.EndpointPriority < 1 || *params.EndpointPriority > 8)) {
		return false
	}
	switch params.ReportedOutcome {
	case identityprovider.TestOutcomeSuccess:
		return params.ReportedCategory == identityprovider.TestCategorySuccess &&
			params.EndpointPriority != nil
	case identityprovider.TestOutcomeFailure:
		if params.ReportedCategory == identityprovider.TestCategorySuccess ||
			params.ReportedCategory == identityprovider.TestCategoryStaleConfiguration ||
			!validLDAPDirectoryFailureCategory(params.ReportedCategory) ||
			params.MatchedEntryCount != 0 || params.Truncated {
			return false
		}
		return params.ReportedCategory == identityprovider.TestCategoryCancelled &&
			params.EndpointPriority == nil ||
			params.ReportedCategory != identityprovider.TestCategoryCancelled &&
				params.EndpointPriority != nil
	default:
		return false
	}
}

func validLDAPDirectoryFailureCategory(value identityprovider.TestCategory) bool {
	switch value {
	case identityprovider.TestCategoryDNSFailed,
		identityprovider.TestCategoryDestinationBlocked,
		identityprovider.TestCategoryConnectTimeout,
		identityprovider.TestCategoryConnectFailed,
		identityprovider.TestCategoryTLSFailed,
		identityprovider.TestCategoryCertificateRejected,
		identityprovider.TestCategoryBindRejected,
		identityprovider.TestCategoryProtocolFailed,
		identityprovider.TestCategoryCancelled:
		return true
	default:
		return false
	}
}
