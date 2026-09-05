package postgres

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/services/worker/internal/identitysync"
)

const ldapSyncUserAgent = "Periapsis LDAP sync worker"

const claimLDAPSyncQuery = `
select *
from app.claim_next_tenant_ldap_sync_run_v2(
  $1::uuid, $2::bytea, $3::integer, $4::text
)
`

type ldapSyncTransactionBeginner interface {
	Begin(context.Context) (pgx.Tx, error)
}

type LDAPSyncRepository struct {
	pool ldapSyncTransactionBeginner
}

func NewLDAPSyncRepository(pool ldapSyncTransactionBeginner) *LDAPSyncRepository {
	return &LDAPSyncRepository{pool: pool}
}

var _ identitysync.Repository = (*LDAPSyncRepository)(nil)

type stagedObservationDocument struct {
	ObservationID      uuid.UUID  `json:"observationId"`
	Ordinal            int        `json:"ordinal"`
	DigestKeyVersion   int        `json:"digestKeyVersion"`
	SubjectDigest      string     `json:"subjectDigest"`
	ObservationDigest  string     `json:"observationDigest"`
	ExternalIdentityID *uuid.UUID `json:"externalIdentityId"`
	PlanningFence      *int64     `json:"planningFence"`
	Applied            bool       `json:"applied"`
}

func (repository *LDAPSyncRepository) Claim(
	ctx context.Context,
	proof identitysync.ClaimProof,
	leaseSeconds int,
) (*identitysync.Claim, error) {
	if repository == nil || repository.pool == nil || leaseSeconds < 1 || leaseSeconds > 600 {
		return nil, identitysync.ErrInvalidSnapshot
	}
	tx, err := repository.pool.Begin(ctx)
	if err != nil {
		return nil, mapLDAPSyncDatabaseError(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	var runID, tenantID, claimID, providerID, secretID pgtype.UUID
	var bindingID, accessEpochID pgtype.UUID
	var fence, ruleSetRevision, authorizationRevision int64
	var expiresAt, queuedAt time.Time
	var enumerationStartedAt pgtype.Timestamptz
	var status string
	var runVersion, providerVersion, configurationVersion int32
	var secretVersion, secretKeyVersion int32
	var bindingVersion, bindingAuthRevision int32
	var endpointDigest, configurationJSON, endpointsJSON []byte
	var secretCiphertext, secretNonce []byte
	var secretAlgorithm string
	var mappingJSON, stagedJSON []byte
	err = tx.QueryRow(
		ctx,
		claimLDAPSyncQuery,
		pgUUID(proof.ID), proof.ReceiptDigest[:], leaseSeconds, ldapSyncUserAgent,
	).Scan(
		&runID, &tenantID, &claimID, &fence, &expiresAt, &status, &runVersion,
		&providerID, &providerVersion, &configurationVersion, &endpointDigest,
		&configurationJSON, &endpointsJSON, &secretID, &secretCiphertext,
		&secretNonce, &secretVersion, &secretKeyVersion, &secretAlgorithm,
		&bindingID, &bindingVersion, &bindingAuthRevision, &accessEpochID,
		&ruleSetRevision, &authorizationRevision, &mappingJSON, &stagedJSON,
		&queuedAt, &enumerationStartedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		clear(secretCiphertext)
		clear(secretNonce)
		return nil, mapLDAPSyncDatabaseError(err)
	}
	if _, err := tx.Exec(ctx, `select set_config('app.tenant_id', $1, true)`, uuidString(tenantID)); err != nil {
		clear(secretCiphertext)
		clear(secretNonce)
		return nil, mapLDAPSyncDatabaseError(err)
	}
	configuration, err := decodeLDAPSyncJSON[identitysync.SnapshotConfiguration](configurationJSON)
	if err != nil {
		clear(secretCiphertext)
		clear(secretNonce)
		return nil, err
	}
	endpoints, err := decodeLDAPSyncJSON[[]identitysync.SnapshotEndpoint](endpointsJSON)
	if err != nil {
		clear(secretCiphertext)
		clear(secretNonce)
		return nil, err
	}
	mappings, err := decodeLDAPSyncJSON[[]identitysync.PinnedMappingRevision](mappingJSON)
	if err != nil {
		clear(secretCiphertext)
		clear(secretNonce)
		return nil, err
	}
	staged, err := decodeStagedObservations(stagedJSON)
	if err != nil {
		clear(secretCiphertext)
		clear(secretNonce)
		return nil, err
	}
	if len(endpointDigest) != 32 || len(secretNonce) != 12 ||
		secretKeyVersion < 1 || secretKeyVersion > math.MaxInt16 {
		clear(secretCiphertext)
		clear(secretNonce)
		return nil, identitysync.ErrInvalidSnapshot
	}
	var endpointSnapshotDigest [32]byte
	copy(endpointSnapshotDigest[:], endpointDigest)
	clear(endpointDigest)
	var nonce [12]byte
	copy(nonce[:], secretNonce)
	clear(secretNonce)
	claim := &identitysync.Claim{
		Proof: proof, RunID: requiredUUID(runID), TenantID: requiredUUID(tenantID),
		Fence: fence, ExpiresAt: expiresAt.UTC(), Status: status, Version: int(runVersion),
		ProviderID: requiredUUID(providerID), ProviderVersion: int(providerVersion),
		ConfigurationVersion:   int(configurationVersion),
		EndpointSnapshotDigest: endpointSnapshotDigest,
		Configuration:          configuration, Endpoints: endpoints,
		SecretID: requiredUUID(secretID), SecretCiphertext: secretCiphertext,
		SecretNonce: nonce, SecretVersion: int(secretVersion),
		SecretKeyVersion: int16(secretKeyVersion), SecretAlgorithm: secretAlgorithm,
		BindingID: requiredUUID(bindingID), BindingVersion: int(bindingVersion),
		BindingAuthRevision:  int(bindingAuthRevision),
		BindingAccessEpochID: requiredUUID(accessEpochID),
		RuleSetRevision:      ruleSetRevision, AuthorizationRevision: authorizationRevision,
		MappingRevisions: mappings, Staged: staged, QueuedAt: queuedAt.UTC(),
	}
	if claimIDValue := requiredUUID(claimID); claimIDValue != proof.ID {
		claim.ClearSensitive()
		return nil, identitysync.ErrInvalidSnapshot
	}
	if enumerationStartedAt.Valid {
		value := enumerationStartedAt.Time.UTC()
		claim.EnumerationStartedAt = &value
	}
	if claim.RunID == uuid.Nil || claim.TenantID == uuid.Nil || claim.ProviderID == uuid.Nil ||
		claim.SecretID == uuid.Nil || claim.BindingID == uuid.Nil ||
		claim.BindingAccessEpochID == uuid.Nil {
		claim.ClearSensitive()
		return nil, identitysync.ErrInvalidSnapshot
	}
	if err := tx.Commit(ctx); err != nil {
		claim.ClearSensitive()
		return nil, mapLDAPSyncDatabaseError(err)
	}
	return claim, nil
}

func (repository *LDAPSyncRepository) Stage(
	ctx context.Context,
	claim identitysync.Claim,
	observation identitysync.StagedObservation,
) (*uuid.UUID, error) {
	var externalIdentityID pgtype.UUID
	err := repository.withTenantTransaction(ctx, claim.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
select app.stage_tenant_ldap_sync_observation_v2(
  $1::uuid, $2::uuid, $3::bytea, $4::bigint, $5::uuid,
  $6::integer, $7::integer, $8::bytea, $9::bytea
)
`, pgUUID(claim.RunID), pgUUID(claim.Proof.ID), claim.Proof.ReceiptDigest[:],
			claim.Fence, pgUUID(observation.ObservationID), observation.Ordinal,
			int32(observation.DigestKeyVersion), observation.SubjectDigest[:],
			observation.ObservationDigest[:]).Scan(&externalIdentityID)
	})
	if err != nil {
		return nil, err
	}
	return optionalUUID(externalIdentityID), nil
}

func (repository *LDAPSyncRepository) CompleteEnumeration(
	ctx context.Context,
	claim identitysync.Claim,
	expectedVersion int,
	complete bool,
	truncated bool,
	cursorDigest *[32]byte,
	failureCategory *string,
	audit identitysync.AuditIDs,
) (identitysync.EnumerationCompletion, error) {
	var cursor []byte
	if cursorDigest != nil {
		cursor = cursorDigest[:]
	}
	var result identitysync.EnumerationCompletion
	err := repository.withTenantTransaction(ctx, claim.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
select status::text, version, observed_count, absence_allowed
from app.complete_tenant_ldap_sync_enumeration_v3(
  $1::uuid, $2::uuid, $3::bytea, $4::bigint, $5::integer,
  $6::boolean, $7::boolean, $8::bytea, $9::text,
  $10::uuid, $11::uuid, $12::uuid, $13::text
)
`, pgUUID(claim.RunID), pgUUID(claim.Proof.ID), claim.Proof.ReceiptDigest[:],
			claim.Fence, expectedVersion, complete, truncated, cursor, failureCategory,
			pgUUID(audit.EventID), pgUUID(audit.RequestID), pgUUID(audit.CorrelationID),
			ldapSyncUserAgent).Scan(
			&result.Status, &result.Version, &result.ObservedCount, &result.AbsenceAllowed,
		)
	})
	return result, err
}

func (repository *LDAPSyncRepository) Planning(
	ctx context.Context,
	claim identitysync.Claim,
	observationID uuid.UUID,
	aliases []identity.SubjectAlias,
) (identitysync.PlanningProjection, error) {
	if len(aliases) < 1 || len(aliases) > 16 {
		return identitysync.PlanningProjection{}, identitysync.ErrInvalidSnapshot
	}
	versions := make([]int32, len(aliases))
	digests := make([][]byte, len(aliases))
	for index, alias := range aliases {
		versions[index] = int32(alias.KeyVersion)
		digests[index] = append([]byte(nil), alias.Digest[:]...)
	}
	defer func() {
		for _, digest := range digests {
			clear(digest)
		}
	}()
	var projection identitysync.PlanningProjection
	var runID, returnedObservationID, tenantID, providerID, bindingID pgtype.UUID
	var accessEpochID, accessSourceID pgtype.UUID
	var externalIdentityID, userID, membershipID, accessGrantID pgtype.UUID
	var existingRoleIDs []pgtype.UUID
	err := repository.withTenantTransaction(ctx, claim.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
select sync_run_id, observation_id, tenant_id, claim_fence,
       provider_id, provider_version, binding_id, binding_version,
       binding_auth_revision, binding_access_epoch_id,
       configuration_revision, rule_set_revision, authorization_revision,
       jit_mode::text, no_match_policy::text, provider_access_source_id,
       external_identity_id, user_id, membership_id, access_grant_id,
       external_identity_exists, user_active, tenant_membership_exists,
       tenant_membership_active, access_grant_live, rules, security_groups,
       live_assignments, role_policies, existing_effective_role_ids,
       delegation, live_owned_edges
from app.claim_tenant_ldap_sync_observation_planning_v3(
  $1::uuid, $2::uuid, $3::uuid, $4::bytea, $5::bigint,
  $6::integer[], $7::bytea[]
)
`, pgUUID(claim.RunID), pgUUID(observationID), pgUUID(claim.Proof.ID),
			claim.Proof.ReceiptDigest[:], claim.Fence, versions, digests).Scan(
			&runID, &returnedObservationID, &tenantID, &projection.Fence,
			&providerID, &projection.ProviderVersion, &bindingID,
			&projection.BindingVersion, &projection.BindingAuthRevision,
			&accessEpochID, &projection.ConfigurationRevision,
			&projection.RuleSetRevision, &projection.AuthorizationRevision,
			&projection.JITMode, &projection.NoMatchPolicy, &accessSourceID,
			&externalIdentityID, &userID, &membershipID, &accessGrantID,
			&projection.ExternalIdentityExists, &projection.UserActive,
			&projection.TenantMembershipExists, &projection.TenantMembershipActive,
			&projection.AccessGrantLive, &projection.Rules, &projection.SecurityGroups,
			&projection.LiveAssignments, &projection.RolePolicies, &existingRoleIDs,
			&projection.Delegation, &projection.LiveOwnedEdges,
		)
	})
	if err != nil {
		return identitysync.PlanningProjection{}, err
	}
	projection.RunID = requiredUUID(runID)
	projection.ObservationID = requiredUUID(returnedObservationID)
	projection.TenantID = requiredUUID(tenantID)
	projection.ProviderID = requiredUUID(providerID)
	projection.BindingID = requiredUUID(bindingID)
	projection.BindingAccessEpochID = requiredUUID(accessEpochID)
	projection.ProviderAccessSourceID = requiredUUID(accessSourceID)
	projection.ExternalIdentityID = optionalUUID(externalIdentityID)
	projection.UserID = optionalUUID(userID)
	projection.MembershipID = optionalUUID(membershipID)
	projection.AccessGrantID = optionalUUID(accessGrantID)
	projection.ExistingEffectiveRoleIDs = make([]uuid.UUID, 0, len(existingRoleIDs))
	for _, value := range existingRoleIDs {
		identifier := requiredUUID(value)
		if identifier == uuid.Nil {
			return identitysync.PlanningProjection{}, identitysync.ErrInvalidSnapshot
		}
		projection.ExistingEffectiveRoleIDs = append(projection.ExistingEffectiveRoleIDs, identifier)
	}
	return projection, nil
}

func (repository *LDAPSyncRepository) Apply(
	ctx context.Context,
	claim identitysync.Claim,
	request identitysync.ApplyRequest,
) (identitysync.ApplyResult, error) {
	aliasIDs := pgUUIDs(request.AliasIDs)
	aliasVersions := make([]int32, len(request.AliasKeyVersions))
	for index, version := range request.AliasKeyVersions {
		aliasVersions[index] = int32(version)
	}
	matchedEpochIDs := pgUUIDs(request.MatchedEpochIDs)
	revocationEpochIDs := pgUUIDs(request.RevocationEpochIDs)
	var subjectKeyVersion *int32
	if request.SubjectKeyVersion != nil {
		value := int32(*request.SubjectKeyVersion)
		subjectKeyVersion = &value
	}
	var result identitysync.ApplyResult
	var applicationID, externalIdentityID, userID, membershipID, accessGrantID pgtype.UUID
	err := repository.withTenantTransaction(ctx, claim.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
select application_id, decision::text, external_identity_id, user_id,
       membership_id, access_grant_id, ensured_edge_count,
       revoked_edge_count, replayed
from app.apply_tenant_ldap_sync_identity_plan_v3(
  $1::uuid, $2::uuid, $3::uuid, $4::bytea, $5::bigint,
  $6::uuid, $7::bytea, $8::uuid, $9::integer, $10::integer,
  $11::integer, $12::integer, $13::uuid, $14::bigint, $15::bigint,
  $16::public.ldap_identity_apply_decision, $17::text,
  $18::uuid, $19::uuid, $20::uuid, $21::uuid, $22::uuid[],
  $23::uuid, $24::uuid, $25::uuid, $26::uuid, $27::uuid,
  $28::public.identity_subject_format, $29::bytea, $30::bytea, $31::integer,
  $32::uuid[], $33::integer[], $34::bytea[],
  $35::text, $36::text, $37::text, $38::text, $39::text,
  $40::uuid[], $41::timestamptz, $42::uuid, $43::uuid, $44::uuid,
  null::inet, $45::text
)
`, pgUUID(claim.RunID), pgUUID(request.ObservationID), pgUUID(claim.Proof.ID),
			claim.Proof.ReceiptDigest[:], claim.Fence, pgUUID(request.ApplicationID),
			request.PlanDigest[:], pgUUID(claim.BindingID), claim.ProviderVersion,
			claim.ConfigurationVersion, claim.BindingVersion, claim.BindingAuthRevision,
			pgUUID(claim.BindingAccessEpochID), claim.RuleSetRevision,
			claim.AuthorizationRevision, request.Decision, request.DenialCategory,
			optionalPGUUID(request.ExistingExternalIdentityID), optionalPGUUID(request.ExistingUserID),
			optionalPGUUID(request.ExistingMembershipID), optionalPGUUID(request.ExistingAccessGrantID),
			revocationEpochIDs,
			optionalPGUUID(request.ExternalIdentityID), optionalPGUUID(request.UserID),
			optionalPGUUID(request.MembershipID), optionalPGUUID(request.AccessGrantID),
			optionalPGUUID(request.ProfileContributionID), request.SubjectFormat,
			request.SubjectCiphertext, request.SubjectNonce, subjectKeyVersion,
			aliasIDs, aliasVersions, request.AliasDigests, request.DisplayName,
			request.FirstName, request.LastName, request.Username, request.Email,
			matchedEpochIDs, request.ObservedAt, pgUUID(request.AuditEventID),
			pgUUID(request.RequestID), pgUUID(request.CorrelationID), ldapSyncUserAgent,
		).Scan(
			&applicationID, &result.Decision, &externalIdentityID, &userID,
			&membershipID, &accessGrantID, &result.EnsuredEdges,
			&result.RevokedEdges, &result.Replayed,
		)
	})
	if err != nil {
		return identitysync.ApplyResult{}, err
	}
	result.ApplicationID = requiredUUID(applicationID)
	result.ExternalIdentityID = optionalUUID(externalIdentityID)
	result.UserID = optionalUUID(userID)
	result.MembershipID = optionalUUID(membershipID)
	result.AccessGrantID = optionalUUID(accessGrantID)
	return result, nil
}

func (repository *LDAPSyncRepository) ApplyAbsence(
	ctx context.Context,
	claim identitysync.Claim,
	limit int,
	audit identitysync.AuditIDs,
) (identitysync.AbsenceResult, error) {
	var result identitysync.AbsenceResult
	err := repository.withTenantTransaction(ctx, claim.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
select inspected_count, revoked_count, remaining_count
from app.apply_tenant_ldap_sync_absence_chunk_v3(
  $1::uuid, $2::uuid, $3::bytea, $4::bigint, $5::integer,
  $6::uuid, $7::uuid, $8::uuid, $9::text
)
`, pgUUID(claim.RunID), pgUUID(claim.Proof.ID), claim.Proof.ReceiptDigest[:],
			claim.Fence, limit, pgUUID(audit.EventID), pgUUID(audit.RequestID),
			pgUUID(audit.CorrelationID), ldapSyncUserAgent).Scan(
			&result.Inspected, &result.Revoked, &result.Remaining,
		)
	})
	return result, err
}

func (repository *LDAPSyncRepository) Complete(
	ctx context.Context,
	claim identitysync.Claim,
	expectedVersion int,
	audit identitysync.AuditIDs,
) (int, error) {
	var version int
	err := repository.withTenantTransaction(ctx, claim.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
select app.complete_tenant_ldap_sync_run_v2(
  $1::uuid, $2::uuid, $3::bytea, $4::bigint, $5::integer,
  $6::uuid, $7::uuid, $8::uuid, $9::text
)
`, pgUUID(claim.RunID), pgUUID(claim.Proof.ID), claim.Proof.ReceiptDigest[:],
			claim.Fence, expectedVersion, pgUUID(audit.EventID), pgUUID(audit.RequestID),
			pgUUID(audit.CorrelationID), ldapSyncUserAgent).Scan(&version)
	})
	return version, err
}

func (repository *LDAPSyncRepository) Fail(
	ctx context.Context,
	claim identitysync.Claim,
	expectedVersion int,
	category string,
	audit identitysync.AuditIDs,
) (identitysync.TerminalResult, error) {
	var result identitysync.TerminalResult
	err := repository.withTenantTransaction(ctx, claim.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
select status::text, version, replayed
from app.fail_tenant_ldap_sync_run_v2(
  $1::uuid, $2::uuid, $3::bytea, $4::bigint, $5::integer,
  $6::text, $7::uuid, $8::uuid, $9::uuid, $10::text
)
`, pgUUID(claim.RunID), pgUUID(claim.Proof.ID), claim.Proof.ReceiptDigest[:],
			claim.Fence, expectedVersion, category, pgUUID(audit.EventID),
			pgUUID(audit.RequestID), pgUUID(audit.CorrelationID), ldapSyncUserAgent,
		).Scan(&result.Status, &result.Version, &result.Replayed)
	})
	return result, err
}

func (repository *LDAPSyncRepository) withTenantTransaction(
	ctx context.Context,
	tenantID uuid.UUID,
	operation func(pgx.Tx) error,
) error {
	if repository == nil || repository.pool == nil || tenantID == uuid.Nil {
		return identitysync.ErrInvalidSnapshot
	}
	tx, err := repository.pool.Begin(ctx)
	if err != nil {
		return mapLDAPSyncDatabaseError(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if _, err := tx.Exec(ctx, `select set_config('app.tenant_id', $1, true)`, tenantID.String()); err != nil {
		return mapLDAPSyncDatabaseError(err)
	}
	if err := operation(tx); err != nil {
		return mapLDAPSyncDatabaseError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return mapLDAPSyncDatabaseError(err)
	}
	return nil
}

func decodeStagedObservations(document []byte) ([]identitysync.StagedObservation, error) {
	rows, err := decodeLDAPSyncJSON[[]stagedObservationDocument](document)
	if err != nil || len(rows) > 5_000 {
		return nil, identitysync.ErrInvalidSnapshot
	}
	result := make([]identitysync.StagedObservation, 0, len(rows))
	for _, row := range rows {
		if row.DigestKeyVersion < 1 || row.DigestKeyVersion > math.MaxInt16 {
			return nil, identitysync.ErrInvalidSnapshot
		}
		subject, err := decodeDigest(row.SubjectDigest)
		if err != nil {
			return nil, err
		}
		observation, err := decodeDigest(row.ObservationDigest)
		if err != nil {
			return nil, err
		}
		result = append(result, identitysync.StagedObservation{
			ObservationID: row.ObservationID, Ordinal: row.Ordinal,
			DigestKeyVersion: int16(row.DigestKeyVersion), SubjectDigest: subject,
			ObservationDigest:  observation,
			ExternalIdentityID: row.ExternalIdentityID,
			PlanningFence:      row.PlanningFence, Applied: row.Applied,
		})
	}
	return result, nil
}

func decodeLDAPSyncJSON[T any](document []byte) (T, error) {
	var result T
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return result, identitysync.ErrInvalidSnapshot
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return result, identitysync.ErrInvalidSnapshot
	}
	return result, nil
}

func decodeDigest(value string) ([32]byte, error) {
	var result [32]byte
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(result) {
		clear(decoded)
		return result, identitysync.ErrInvalidSnapshot
	}
	copy(result[:], decoded)
	clear(decoded)
	return result, nil
}

func pgUUID(value uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: [16]byte(value), Valid: value != uuid.Nil}
}

func optionalPGUUID(value *uuid.UUID) pgtype.UUID {
	if value == nil {
		return pgtype.UUID{}
	}
	return pgUUID(*value)
}

func pgUUIDs(values []uuid.UUID) []pgtype.UUID {
	result := make([]pgtype.UUID, len(values))
	for index, value := range values {
		result[index] = pgUUID(value)
	}
	return result
}

func requiredUUID(value pgtype.UUID) uuid.UUID {
	if !value.Valid {
		return uuid.Nil
	}
	return uuid.UUID(value.Bytes)
}

func optionalUUID(value pgtype.UUID) *uuid.UUID {
	if !value.Valid {
		return nil
	}
	result := uuid.UUID(value.Bytes)
	return &result
}

func uuidString(value pgtype.UUID) string {
	return requiredUUID(value).String()
}

func mapLDAPSyncDatabaseError(err error) error {
	if err == nil {
		return nil
	}
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) && databaseError.Code == "40001" {
		return identitysync.ErrClaimLost
	}
	return fmt.Errorf("LDAP sync database operation failed: %w", err)
}
