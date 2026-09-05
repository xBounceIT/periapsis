package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
	"github.com/periapsis-im/periapsis/services/api/internal/securityaudit"
)

const tenantAuditProjection = `
id, tenant_id, sequence, occurred_at, actor_type::text, actor_user_id,
actor_service_account_id, impersonated_by_user_id, action, resource_type,
resource_id, request_id, correlation_id, ip_address, user_agent,
authentication_method, outcome::text, reason, before, after, metadata,
previous_hash::text, event_hash::text`

// SecurityAuditRepository exposes only the bounded SECURITY DEFINER audit ABI.
// Every read uses a read-write transaction because the database appends the
// corresponding access evidence before committing the returned snapshot.
type SecurityAuditRepository struct {
	begin transactionBeginner
}

func NewSecurityAuditRepository(pool *pgxpool.Pool) *SecurityAuditRepository {
	return &SecurityAuditRepository{begin: poolTransactionBeginner(pool)}
}

var _ securityaudit.Repository = (*SecurityAuditRepository)(nil)

func (repository *SecurityAuditRepository) ListTenantEvents(
	ctx context.Context,
	params securityaudit.TenantReadParams,
) ([]securityaudit.Event, error) {
	if !validTenantAuditRepositoryParams(repository, params.Actor, params.TenantID, params.Permission, params.AccessAuditID) {
		return nil, securityaudit.ErrForbidden
	}
	return withinTenantAuditTransaction(ctx, repository, params.Actor, params.TenantID, func(tx databaseTransaction) ([]securityaudit.Event, error) {
		rows, err := tx.Query(ctx, `
			SELECT `+tenantAuditProjection+`
			FROM app.list_tenant_audit_events_v1(
				$1, $2, $3, $4, $5, $6, $7::public.audit_actor_type, $8, $9,
				$10, $11, $12, $13, $14, $15::public.audit_outcome, $16,
				$17, $18, $19, $20, $21
			)`,
			params.Actor.SessionID, string(params.Permission), auditSequence(params.Query.AfterSequence), params.Query.Limit,
			params.Query.OccurredFrom, params.Query.OccurredBefore, optionalAuditActorType(params.Query.ActorType),
			params.Query.ActorUserID, params.Query.ActorServiceAccountID, nullableAuditText(params.Query.ActionPrefix),
			nullableAuditText(params.Query.ResourceType), params.Query.ResourceID, params.Query.RequestID,
			params.Query.CorrelationID, optionalAuditOutcome(params.Query.Outcome), nullableAuditText(params.Query.Search),
			params.AccessAuditID, params.Audit.RequestID, params.Audit.CorrelationID,
			params.Audit.RemoteAddress.Unmap(), params.Audit.UserAgent,
		)
		if err != nil {
			return nil, mapSecurityAuditDatabaseError(err)
		}
		return scanSecurityAuditEvents(rows)
	})
}

func (repository *SecurityAuditRepository) ListPlatformEvents(
	ctx context.Context,
	params securityaudit.PlatformReadParams,
) ([]securityaudit.Event, error) {
	if !validPlatformAuditRepositoryParams(repository, params.Session.ID, params.Session.User.ID, params.Permission, params.AccessAuditID) {
		return nil, securityaudit.ErrForbidden
	}
	return withinPlatformAuditTransaction(ctx, repository, params.Session.User.ID, func(tx databaseTransaction) ([]securityaudit.Event, error) {
		rows, err := tx.Query(ctx, `
			SELECT id, NULL::uuid AS tenant_id, sequence, occurred_at, actor_type::text,
			       actor_user_id, NULL::uuid AS actor_service_account_id,
			       NULL::uuid AS impersonated_by_user_id, action, resource_type,
			       resource_id, request_id, correlation_id, ip_address, user_agent,
			       authentication_method, outcome::text, reason, before, after, metadata,
			       previous_hash::text, event_hash::text
			FROM app.list_platform_audit_events_v1(
				$1, $2, $3, $4, $5, $6, $7::public.audit_actor_type, $8,
				$9, $10, $11, $12, $13, $14::public.audit_outcome, $15,
				$16, $17, $18, $19, $20
			)`,
			params.Session.ID, string(params.Permission), auditSequence(params.Query.AfterSequence), params.Query.Limit,
			params.Query.OccurredFrom, params.Query.OccurredBefore, optionalAuditActorType(params.Query.ActorType),
			params.Query.ActorUserID, nullableAuditText(params.Query.ActionPrefix), nullableAuditText(params.Query.ResourceType),
			params.Query.ResourceID, params.Query.RequestID, params.Query.CorrelationID,
			optionalAuditOutcome(params.Query.Outcome), nullableAuditText(params.Query.Search), params.AccessAuditID,
			params.Event.RequestID, params.Event.CorrelationID, params.Event.RemoteAddress.Unmap(), params.Event.UserAgent,
		)
		if err != nil {
			return nil, mapSecurityAuditDatabaseError(err)
		}
		return scanSecurityAuditEvents(rows)
	})
}

func (repository *SecurityAuditRepository) VerifyTenantChain(
	ctx context.Context,
	params securityaudit.TenantVerifyParams,
) (securityaudit.Verification, error) {
	if !validTenantAuditRepositoryParams(repository, params.Actor, params.TenantID, params.Permission, params.AccessAuditID) {
		return securityaudit.Verification{}, securityaudit.ErrForbidden
	}
	return withinTenantAuditTransaction(ctx, repository, params.Actor, params.TenantID, func(tx databaseTransaction) (securityaudit.Verification, error) {
		return scanSecurityAuditVerification(tx.QueryRow(ctx, `
			SELECT event_count, last_sequence, first_invalid_sequence,
			       head_valid, valid, verified_at
			FROM app.verify_tenant_audit_chain_v1($1, $2, $3, $4, $5, $6, $7, $8)
		`, params.Actor.SessionID, string(params.Permission), params.AccessAuditID,
			params.Audit.RequestID, params.Audit.CorrelationID, params.Audit.RemoteAddress.Unmap(),
			params.Audit.UserAgent, params.TenantID))
	})
}

func (repository *SecurityAuditRepository) VerifyPlatformChain(
	ctx context.Context,
	params securityaudit.PlatformVerifyParams,
) (securityaudit.Verification, error) {
	if !validPlatformAuditRepositoryParams(repository, params.Session.ID, params.Session.User.ID, params.Permission, params.AccessAuditID) {
		return securityaudit.Verification{}, securityaudit.ErrForbidden
	}
	return withinPlatformAuditTransaction(ctx, repository, params.Session.User.ID, func(tx databaseTransaction) (securityaudit.Verification, error) {
		return scanSecurityAuditVerification(tx.QueryRow(ctx, `
			SELECT event_count, last_sequence, first_invalid_sequence,
			       head_valid, valid, verified_at
			FROM app.verify_platform_audit_chain_v1($1, $2, $3, $4, $5, $6, $7)
		`, params.Session.ID, string(params.Permission), params.AccessAuditID,
			params.Event.RequestID, params.Event.CorrelationID, params.Event.RemoteAddress.Unmap(),
			params.Event.UserAgent))
	})
}

func withinTenantAuditTransaction[T any](
	ctx context.Context,
	repository *SecurityAuditRepository,
	actor authorization.Actor,
	tenantID uuid.UUID,
	work func(databaseTransaction) (T, error),
) (T, error) {
	var zero T
	if repository == nil || repository.begin == nil || work == nil || tenantID == uuid.Nil || actor.UserID == uuid.Nil || actor.ActiveTenantID != tenantID {
		return zero, securityaudit.ErrForbidden
	}
	result, err := withinTransactionWithOptions(ctx, repository.begin, pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadWrite}, func(tx databaseTransaction) (T, error) {
		installed, err := dbsql.New(tx).SetTenantContext(ctx, dbsql.SetTenantContextParams{
			TenantID: toDatabaseUUID(tenantID), UserID: toDatabaseUUID(actor.UserID),
		})
		if err != nil || installed == nil || installed.TenantID != tenantID.String() || installed.UserID != actor.UserID.String() {
			return zero, securityaudit.ErrUnavailable
		}
		if err := installPersistedTraceContext(ctx, tx); err != nil {
			return zero, securityaudit.ErrUnavailable
		}
		return work(tx)
	})
	if err != nil {
		return zero, mapSecurityAuditDatabaseError(err)
	}
	return result, nil
}

func withinPlatformAuditTransaction[T any](
	ctx context.Context,
	repository *SecurityAuditRepository,
	userID uuid.UUID,
	work func(databaseTransaction) (T, error),
) (T, error) {
	var zero T
	if repository == nil || repository.begin == nil || work == nil || userID == uuid.Nil {
		return zero, securityaudit.ErrForbidden
	}
	result, err := withinTransactionWithOptions(ctx, repository.begin, pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadWrite}, func(tx databaseTransaction) (T, error) {
		installed, err := dbsql.New(tx).SetUserContext(ctx, dbsql.SetUserContextParams{UserID: toDatabaseUUID(userID)})
		if err != nil || installed != userID.String() {
			return zero, securityaudit.ErrUnavailable
		}
		if err := installPersistedTraceContext(ctx, tx); err != nil {
			return zero, securityaudit.ErrUnavailable
		}
		return work(tx)
	})
	if err != nil {
		return zero, mapSecurityAuditDatabaseError(err)
	}
	return result, nil
}

func scanSecurityAuditEvents(rows pgx.Rows) ([]securityaudit.Event, error) {
	defer rows.Close()
	events := make([]securityaudit.Event, 0)
	for rows.Next() {
		event, err := scanSecurityAuditEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, mapSecurityAuditDatabaseError(err)
	}
	return events, nil
}

func scanSecurityAuditEvent(row pgx.Row) (securityaudit.Event, error) {
	var event securityaudit.Event
	var sequence int64
	var tenantID, actorUserID, actorServiceID, impersonatorID pgtype.UUID
	var resourceID, requestID, correlationID pgtype.UUID
	var actorType, outcome string
	var ipAddress *netip.Addr
	var userAgent, authenticationMethod, reason pgtype.Text
	var before, after, metadata []byte
	if err := row.Scan(
		&event.ID, &tenantID, &sequence, &event.OccurredAt, &actorType, &actorUserID,
		&actorServiceID, &impersonatorID, &event.Action, &event.ResourceType,
		&resourceID, &requestID, &correlationID, &ipAddress, &userAgent,
		&authenticationMethod, &outcome, &reason, &before, &after, &metadata,
		&event.PreviousHash, &event.EventHash,
	); err != nil {
		return securityaudit.Event{}, mapSecurityAuditDatabaseError(err)
	}
	if sequence <= 0 {
		return securityaudit.Event{}, securityaudit.ErrUnavailable
	}
	event.Sequence = uint64(sequence)
	event.TenantID = optionalAuditUUID(tenantID)
	event.ActorType = securityaudit.ActorType(actorType)
	event.ActorUserID = optionalAuditUUID(actorUserID)
	event.ActorServiceAccountID = optionalAuditUUID(actorServiceID)
	event.ImpersonatedByUserID = optionalAuditUUID(impersonatorID)
	event.ResourceID = optionalAuditUUID(resourceID)
	event.RequestID = optionalAuditUUID(requestID)
	event.CorrelationID = optionalAuditUUID(correlationID)
	event.IPAddress = cloneAuditAddress(ipAddress)
	event.UserAgent = optionalAuditString(userAgent)
	event.AuthenticationMethod = optionalAuditString(authenticationMethod)
	event.Outcome = securityaudit.Outcome(outcome)
	event.Reason = optionalAuditString(reason)
	event.Before = canonicalAuditObject(before)
	event.After = canonicalAuditObject(after)
	event.Metadata = json.RawMessage(slices.Clone(metadata))
	return event, nil
}

func canonicalAuditObject(document []byte) json.RawMessage {
	trimmed := bytes.TrimSpace(document)
	if document == nil || bytes.Equal(trimmed, []byte("null")) {
		return json.RawMessage{'{', '}'}
	}
	return json.RawMessage(slices.Clone(document))
}

func scanSecurityAuditVerification(row pgx.Row) (securityaudit.Verification, error) {
	var eventCount, lastSequence int64
	var firstInvalid *int64
	var result securityaudit.Verification
	if err := row.Scan(
		&eventCount, &lastSequence, &firstInvalid, &result.HeadValid, &result.Valid, &result.VerifiedAt,
	); err != nil {
		return securityaudit.Verification{}, mapSecurityAuditDatabaseError(err)
	}
	if eventCount < 0 || lastSequence < 0 || firstInvalid != nil && *firstInvalid <= 0 {
		return securityaudit.Verification{}, securityaudit.ErrUnavailable
	}
	result.EventCount = uint64(eventCount)
	result.LastSequence = uint64(lastSequence)
	if firstInvalid != nil {
		value := uint64(*firstInvalid)
		result.FirstInvalidSequence = &value
	}
	return result, nil
}

func validTenantAuditRepositoryParams(
	repository *SecurityAuditRepository,
	actor authorization.Actor,
	tenantID uuid.UUID,
	permission authorization.TenantPermission,
	accessAuditID uuid.UUID,
) bool {
	return repository != nil && repository.begin != nil && actor.UserID != uuid.Nil && actor.SessionID != uuid.Nil &&
		tenantID != uuid.Nil && actor.ActiveTenantID == tenantID && permission == authorization.TenantPermissionAuditRead && accessAuditID != uuid.Nil
}

func validPlatformAuditRepositoryParams(
	repository *SecurityAuditRepository,
	sessionID, userID uuid.UUID,
	permission authorization.Permission,
	accessAuditID uuid.UUID,
) bool {
	return repository != nil && repository.begin != nil && sessionID != uuid.Nil && userID != uuid.Nil &&
		permission == authorization.PermissionPlatformAuditRead && accessAuditID != uuid.Nil
}

func auditSequence(value uint64) int64 {
	return int64(value)
}

func optionalAuditActorType(value *securityaudit.ActorType) any {
	if value == nil {
		return nil
	}
	return string(*value)
}

func optionalAuditOutcome(value *securityaudit.Outcome) any {
	if value == nil {
		return nil
	}
	return string(*value)
}

func nullableAuditText(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func optionalAuditUUID(value pgtype.UUID) *uuid.UUID {
	if !value.Valid {
		return nil
	}
	identifier := uuid.UUID(value.Bytes)
	return &identifier
}

func optionalAuditString(value pgtype.Text) *string {
	if !value.Valid {
		return nil
	}
	text := value.String
	return &text
}

func cloneAuditAddress(value *netip.Addr) *netip.Addr {
	if value == nil {
		return nil
	}
	address := value.Unmap()
	return &address
}

func mapSecurityAuditDatabaseError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, securityaudit.ErrForbidden) || errors.Is(err, securityaudit.ErrInvalidInput) ||
		errors.Is(err, securityaudit.ErrUnavailable) {
		return err
	}
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) {
		switch databaseError.Code {
		case "42501":
			return securityaudit.ErrForbidden
		case "22023", "23514":
			return securityaudit.ErrInvalidInput
		case "57014":
			return context.DeadlineExceeded
		}
	}
	return fmt.Errorf("%w: audit database operation", securityaudit.ErrUnavailable)
}
