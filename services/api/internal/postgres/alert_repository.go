package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/periapsis-im/periapsis/services/api/internal/alert"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
)

type alertMutationQueries interface {
	SetTenantContext(context.Context, dbsql.SetTenantContextParams) (*dbsql.SetTenantContextRow, error)
	CreateTenantAlertAsHuman(context.Context, dbsql.CreateTenantAlertAsHumanParams) (*dbsql.CreateTenantAlertAsHumanRow, error)
	CreateTenantAlertAsServiceAccount(context.Context, dbsql.CreateTenantAlertAsServiceAccountParams) (*dbsql.CreateTenantAlertAsServiceAccountRow, error)
}

// AlertRepository invokes the two mutually exclusive Alert-ingest entry
// points. The bearer path deliberately begins a clean transaction and calls
// only the bounded service-account definer without installing human GUCs.
type AlertRepository struct {
	begin        transactionBeginner
	queryFactory func(databaseTransaction) alertMutationQueries
	authority    *AuthorizationRepository
}

func NewAlertRepository(pool *pgxpool.Pool) *AlertRepository {
	return &AlertRepository{
		begin: poolTransactionBeginner(pool),
		queryFactory: func(tx databaseTransaction) alertMutationQueries {
			return dbsql.New(tx)
		},
		authority: NewAuthorizationRepository(pool),
	}
}

var _ alert.Repository = (*AlertRepository)(nil)

func (r *AlertRepository) ResolveHumanAuthority(
	ctx context.Context,
	params authorization.ResolveAuthorityParams,
) (authorization.TenantAuthority, error) {
	if r == nil || r.authority == nil {
		return authorization.TenantAuthority{}, fmt.Errorf("%w: authorization repository is required", alert.ErrUnavailable)
	}
	return r.authority.ResolveAuthority(ctx, params)
}

func (r *AlertRepository) CreateAsHuman(
	ctx context.Context,
	params alert.CreateAsHumanParams,
) (alert.IdempotentCreateResult, error) {
	if !validHumanAlertCreateParams(params) {
		return alert.IdempotentCreateResult{}, alert.ErrInvalidInput
	}
	return withAlertHumanTransaction(ctx, r, params,
		func(queries alertMutationQueries) (alert.IdempotentCreateResult, error) {
			traceparent, tracestate := persistedTraceContextParameters(ctx)
			rawPayload, customFields := alertPayloadJSON(params.Payload.RawPayload), alertPayloadJSON(params.Payload.CustomFields)
			row, err := queries.CreateTenantAlertAsHuman(ctx, dbsql.CreateTenantAlertAsHumanParams{
				Title: params.Payload.Title, Description: cloneString(params.Payload.Description),
				ExternalID: cloneString(params.Payload.ExternalID), Severity: dbsql.AlertSeverity(params.Payload.Severity),
				Source: params.Payload.Source, SourceType: params.Payload.SourceType,
				DeduplicationKey: cloneString(params.Payload.DeduplicationKey), RawPayload: rawPayload,
				Priority: params.Payload.Priority, Category: params.Payload.Category,
				Classification: cloneString(params.Payload.Classification), DetectedAt: databaseTime(params.Payload.DetectedAt),
				CustomerVisible: params.Payload.CustomerVisible, Tags: append([]string{}, params.Payload.Tags...),
				CustomFields: customFields, WorkflowID: optionalDatabaseUUID(params.Payload.WorkflowID),
				AssignedTeamID: optionalDatabaseUUID(params.Payload.AssignedTeamID),
				AssigneeUserID: optionalDatabaseUUID(params.Payload.AssigneeUserID),
				KeyDigest:      append([]byte(nil), params.Payload.KeyDigest[:]...),
				RequestDigest:  append([]byte(nil), params.Payload.RequestDigest[:]...),
				RequestID:      toDatabaseUUID(params.Audit.RequestID), CorrelationID: toDatabaseUUID(params.Audit.CorrelationID),
				IpAddress: params.Audit.RemoteAddress.Unmap(), UserAgent: params.Audit.UserAgent,
				AuthenticationMethod: params.Actor.AuthenticationMethod,
				Traceparent:          traceparent, Tracestate: tracestate,
			})
			if err != nil {
				return alert.IdempotentCreateResult{}, mapAlertDatabaseError(err)
			}
			result, err := mapHumanCreatedAlert(params.TenantID, row)
			if err != nil {
				return alert.IdempotentCreateResult{}, err
			}
			if result.Alert.CreatedByUserID == nil || *result.Alert.CreatedByUserID != params.Actor.UserID ||
				result.Alert.CreatedByMembershipID == nil || *result.Alert.CreatedByMembershipID != params.MembershipID ||
				!result.Replayed && !alertProjectionMatchesPayload(result.Alert, params.Payload) {
				return alert.IdempotentCreateResult{}, invalidAlertProjection("human Alert create representation mismatch")
			}
			return result, nil
		},
	)
}

func (r *AlertRepository) CreateAsServiceAccount(
	ctx context.Context,
	params alert.CreateAsServiceAccountParams,
) (alert.IdempotentCreateResult, error) {
	defer clear(params.Credential.Digest[:])
	if !validServiceAccountAlertCreateParams(params) {
		return alert.IdempotentCreateResult{}, alert.ErrInvalidInput
	}
	if r == nil || r.begin == nil || r.queryFactory == nil {
		return alert.IdempotentCreateResult{}, fmt.Errorf("%w: Alert repository dependencies are required", alert.ErrUnavailable)
	}
	secretDigest := append([]byte(nil), params.Credential.Digest[:]...)
	defer clear(secretDigest)
	traceparent, tracestate := persistedTraceContextParameters(ctx)
	result, err := withinTransactionWithOptions(
		ctx, r.begin, pgx.TxOptions{IsoLevel: pgx.ReadCommitted},
		func(tx databaseTransaction) (alert.IdempotentCreateResult, error) {
			queries := r.queryFactory(tx)
			if queries == nil {
				return alert.IdempotentCreateResult{}, fmt.Errorf("%w: Alert query surface is required", alert.ErrUnavailable)
			}
			// Do not add context installation or any other query here. This is the
			// sole bearer authentication, authorization, and mutation boundary.
			rawPayload, customFields := alertPayloadJSON(params.Payload.RawPayload), alertPayloadJSON(params.Payload.CustomFields)
			row, queryErr := queries.CreateTenantAlertAsServiceAccount(
				ctx,
				dbsql.CreateTenantAlertAsServiceAccountParams{
					TenantID: toDatabaseUUID(params.TenantID), Locator: append([]byte(nil), params.Credential.Locator[:]...),
					EnvelopeKeyVersion: int32(params.Credential.KeyVersion),
					SecretDigest:       secretDigest,
					ClientAddress:      params.Audit.RemoteAddress.Unmap(), Title: params.Payload.Title,
					Description: cloneString(params.Payload.Description), ExternalID: cloneString(params.Payload.ExternalID),
					Severity: dbsql.AlertSeverity(params.Payload.Severity),
					Source:   params.Payload.Source, SourceType: params.Payload.SourceType,
					DeduplicationKey: cloneString(params.Payload.DeduplicationKey), RawPayload: rawPayload,
					Priority: params.Payload.Priority, Category: params.Payload.Category,
					Classification: cloneString(params.Payload.Classification), DetectedAt: databaseTime(params.Payload.DetectedAt),
					CustomerVisible: params.Payload.CustomerVisible, Tags: append([]string{}, params.Payload.Tags...),
					CustomFields: customFields, WorkflowID: optionalDatabaseUUID(params.Payload.WorkflowID),
					AssignedTeamID: optionalDatabaseUUID(params.Payload.AssignedTeamID),
					AssigneeUserID: optionalDatabaseUUID(params.Payload.AssigneeUserID),
					KeyDigest:      append([]byte(nil), params.Payload.KeyDigest[:]...),
					RequestDigest:  append([]byte(nil), params.Payload.RequestDigest[:]...),
					RequestID:      toDatabaseUUID(params.Audit.RequestID), CorrelationID: toDatabaseUUID(params.Audit.CorrelationID),
					UserAgent:   params.Audit.UserAgent,
					Traceparent: traceparent, Tracestate: tracestate,
				},
			)
			if queryErr != nil {
				return alert.IdempotentCreateResult{}, mapAlertDatabaseError(queryErr)
			}
			mapped, mapErr := mapServiceAccountCreatedAlert(params.TenantID, row)
			if mapErr != nil {
				return alert.IdempotentCreateResult{}, mapErr
			}
			if mapped.Alert.CreatedByServiceAccountID == nil ||
				!mapped.Replayed && !alertProjectionMatchesPayload(mapped.Alert, params.Payload) {
				return alert.IdempotentCreateResult{}, invalidAlertProjection("machine Alert create representation mismatch")
			}
			return mapped, nil
		},
	)
	if err != nil {
		return alert.IdempotentCreateResult{}, mapAlertDatabaseError(err)
	}
	return result, nil
}

func withAlertHumanTransaction[T any](
	ctx context.Context,
	repository *AlertRepository,
	params alert.CreateAsHumanParams,
	work func(alertMutationQueries) (T, error),
) (T, error) {
	var zero T
	if !validHumanAlertCreateParams(params) {
		return zero, alert.ErrForbidden
	}
	if repository == nil || repository.begin == nil || repository.queryFactory == nil || work == nil {
		return zero, fmt.Errorf("%w: Alert repository dependencies are required", alert.ErrUnavailable)
	}
	result, err := withinTransactionWithOptions(
		ctx, repository.begin, pgx.TxOptions{IsoLevel: pgx.ReadCommitted},
		func(tx databaseTransaction) (T, error) {
			queries := repository.queryFactory(tx)
			if queries == nil {
				return zero, fmt.Errorf("%w: Alert query surface is required", alert.ErrUnavailable)
			}
			installed, installErr := queries.SetTenantContext(ctx, dbsql.SetTenantContextParams{
				TenantID: toDatabaseUUID(params.TenantID), UserID: toDatabaseUUID(params.Actor.UserID),
			})
			if installErr != nil {
				return zero, mapAlertDatabaseError(installErr)
			}
			if installed == nil || installed.TenantID != params.TenantID.String() || installed.UserID != params.Actor.UserID.String() {
				return zero, invalidAlertProjection("database installed an unexpected human context")
			}
			return work(queries)
		},
	)
	if err != nil {
		return zero, mapAlertDatabaseError(err)
	}
	return result, nil
}

func validHumanAlertCreateParams(params alert.CreateAsHumanParams) bool {
	return serviceAccountUUIDv7(params.TenantID) && serviceAccountUUIDv7(params.MembershipID) &&
		serviceAccountUUIDv7(params.Actor.UserID) && serviceAccountUUIDv7(params.Actor.SessionID) &&
		params.Actor.ActiveTenantID == params.TenantID && serviceAccountText(params.Actor.AuthenticationMethod, 1, 64) &&
		validAlertPayload(params.Payload) && validAlertAudit(params.Audit)
}

func validServiceAccountAlertCreateParams(params alert.CreateAsServiceAccountParams) bool {
	return serviceAccountUUIDv7(params.TenantID) && params.Credential.KeyVersion >= 1 &&
		validAlertPayload(params.Payload) && validAlertAudit(params.Audit)
}

func validAlertPayload(payload alert.CreatePayload) bool {
	if payload.Title != strings.TrimSpace(payload.Title) || !serviceAccountText(payload.Title, 1, 240) {
		return false
	}
	if payload.ExternalID != nil && (*payload.ExternalID != strings.TrimSpace(*payload.ExternalID) ||
		!serviceAccountText(*payload.ExternalID, 1, 200)) {
		return false
	}
	if payload.Description != nil && (*payload.Description != strings.TrimSpace(*payload.Description) ||
		!serviceAccountText(*payload.Description, 0, 10_000)) {
		return false
	}
	if payload.Priority == "" || payload.Category == "" || payload.Source == "" || payload.SourceType == "" ||
		len(payload.Tags) > 100 || len(payload.CustomFields) > 100 || len(payload.RawPayload) > 200 ||
		payload.AssigneeUserID != nil && payload.AssignedTeamID == nil {
		return false
	}
	for _, id := range []*uuid.UUID{payload.WorkflowID, payload.AssignedTeamID, payload.AssigneeUserID} {
		if id != nil && !serviceAccountUUIDv7(*id) {
			return false
		}
	}
	switch payload.Severity {
	case alert.SeverityInformational, alert.SeverityLow, alert.SeverityMedium, alert.SeverityHigh, alert.SeverityCritical:
		return true
	default:
		return false
	}
}

func validAlertAudit(audit authorization.AuditContext) bool {
	return audit.RequestID != uuid.Nil && audit.RequestID.Variant() == uuid.RFC4122 &&
		audit.CorrelationID != uuid.Nil && audit.CorrelationID.Variant() == uuid.RFC4122 &&
		audit.RemoteAddress.IsValid() && audit.RemoteAddress.Zone() == "" && !audit.RemoteAddress.Is4In6() &&
		serviceAccountText(audit.UserAgent, 0, 512)
}

func alertProjectionMatchesPayload(value alert.Alert, payload alert.CreatePayload) bool {
	expectedVersion := int64(1)
	if payload.AssignedTeamID != nil {
		expectedVersion = 2
	}
	return value.Status == alert.StatusNew && value.Version == expectedVersion && value.UpdatedAt.Equal(value.CreatedAt) &&
		value.Title == payload.Title &&
		equalOptionalString(value.ExternalID, payload.ExternalID) &&
		equalOptionalString(value.Description, payload.Description) && value.Severity == payload.Severity &&
		value.Priority == payload.Priority && value.Category == payload.Category &&
		value.Source == payload.Source && value.SourceType == payload.SourceType &&
		equalOptionalString(value.DeduplicationKey, payload.DeduplicationKey) &&
		equalOptionalString(value.Classification, payload.Classification) && value.CustomerVisible == payload.CustomerVisible
}

func alertPayloadJSON(value map[string]any) []byte { encoded, _ := json.Marshal(value); return encoded }

func equalOptionalString(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func mapHumanCreatedAlert(
	tenantID uuid.UUID,
	row *dbsql.CreateTenantAlertAsHumanRow,
) (alert.IdempotentCreateResult, error) {
	if row == nil {
		return alert.IdempotentCreateResult{}, invalidAlertProjection("null human Alert result")
	}
	externalID, err := optionalAlertText(row.HasExternalID, row.ExternalID, false)
	if err != nil {
		return alert.IdempotentCreateResult{}, err
	}
	description, err := optionalAlertText(row.HasDescription, row.Description, true)
	if err != nil {
		return alert.IdempotentCreateResult{}, err
	}
	deduplicationKey, err := optionalAlertText(row.HasDeduplicationKey, row.DeduplicationKey, false)
	if err != nil {
		return alert.IdempotentCreateResult{}, err
	}
	classification, err := optionalAlertText(row.HasClassification, row.Classification, false)
	if err != nil {
		return alert.IdempotentCreateResult{}, err
	}
	return mapCreatedAlert(tenantID, alertRecord{
		id: row.ID, number: row.Number, workflowID: row.WorkflowID, workflowVersion: row.WorkflowVersion,
		stateKey: row.StateKey, customerVisible: row.CustomerVisible, externalID: externalID,
		deduplicationKey: deduplicationKey, title: row.Title, description: description,
		status: row.Status, severity: row.Severity, priority: row.Priority, category: row.Category,
		classification: classification, source: row.Source, sourceType: row.SourceType,
		tags: row.Tags, customFields: row.CustomFields, customerCustomFields: row.CustomerCustomFields,
		rawPayload: row.RawPayload, assignedTeamID: row.AssignedTeamID, assigneeUserID: row.AssigneeUserID,
		claimedByUserID: row.ClaimedByUserID, createdByUserID: row.CreatedByUserID,
		createdByMembershipID:     row.CreatedByMembershipID,
		createdByServiceAccountID: row.CreatedByServiceAccountID,
		detectedAt:                row.DetectedAt, receivedAt: row.ReceivedAt, acknowledgedAt: row.AcknowledgedAt,
		closedAt: row.ClosedAt, assignedAt: row.AssignedAt, firstResponseAt: row.FirstResponseAt,
		resolvedAt: row.ResolvedAt, claimedAt: row.ClaimedAt, createdAt: row.CreatedAt,
		updatedAt: row.UpdatedAt, version: row.Version, replayed: row.Replayed,
	})
}

func mapServiceAccountCreatedAlert(
	tenantID uuid.UUID,
	row *dbsql.CreateTenantAlertAsServiceAccountRow,
) (alert.IdempotentCreateResult, error) {
	if row == nil {
		return alert.IdempotentCreateResult{}, invalidAlertProjection("null machine Alert result")
	}
	externalID, err := optionalAlertText(row.HasExternalID, row.ExternalID, false)
	if err != nil {
		return alert.IdempotentCreateResult{}, err
	}
	description, err := optionalAlertText(row.HasDescription, row.Description, true)
	if err != nil {
		return alert.IdempotentCreateResult{}, err
	}
	deduplicationKey, err := optionalAlertText(row.HasDeduplicationKey, row.DeduplicationKey, false)
	if err != nil {
		return alert.IdempotentCreateResult{}, err
	}
	classification, err := optionalAlertText(row.HasClassification, row.Classification, false)
	if err != nil {
		return alert.IdempotentCreateResult{}, err
	}
	return mapCreatedAlert(tenantID, alertRecord{
		id: row.ID, number: row.Number, workflowID: row.WorkflowID, workflowVersion: row.WorkflowVersion,
		stateKey: row.StateKey, customerVisible: row.CustomerVisible, externalID: externalID,
		deduplicationKey: deduplicationKey, title: row.Title, description: description,
		status: row.Status, severity: row.Severity, priority: row.Priority, category: row.Category,
		classification: classification, source: row.Source, sourceType: row.SourceType,
		tags: row.Tags, customFields: row.CustomFields, customerCustomFields: row.CustomerCustomFields,
		rawPayload: row.RawPayload, assignedTeamID: row.AssignedTeamID, assigneeUserID: row.AssigneeUserID,
		claimedByUserID: row.ClaimedByUserID, createdByUserID: row.CreatedByUserID,
		createdByMembershipID:     row.CreatedByMembershipID,
		createdByServiceAccountID: row.CreatedByServiceAccountID,
		detectedAt:                row.DetectedAt, receivedAt: row.ReceivedAt, acknowledgedAt: row.AcknowledgedAt,
		closedAt: row.ClosedAt, assignedAt: row.AssignedAt, firstResponseAt: row.FirstResponseAt,
		resolvedAt: row.ResolvedAt, claimedAt: row.ClaimedAt, createdAt: row.CreatedAt,
		updatedAt: row.UpdatedAt, version: row.Version, replayed: row.Replayed,
	})
}

func optionalAlertText(present bool, value string, allowEmpty bool) (*string, error) {
	if !present {
		if value != "" {
			return nil, invalidAlertProjection("inconsistent optional Alert text")
		}
		return nil, nil
	}
	if value == "" && !allowEmpty {
		return nil, invalidAlertProjection("empty present Alert text")
	}
	return &value, nil
}

func mapAlertDatabaseError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, alert.ErrInvalidInput) || errors.Is(err, alert.ErrUnauthenticated) ||
		errors.Is(err, alert.ErrForbidden) || errors.Is(err, alert.ErrConflict) ||
		errors.Is(err, alert.ErrUnavailable) {
		return err
	}
	switch postgresCode(err) {
	case "22023", "22P02":
		return alert.ErrInvalidInput
	case "28000":
		return alert.ErrUnauthenticated
	case "42501":
		return alert.ErrForbidden
	case "23503", "23505", "23514", "55000":
		return alert.ErrConflict
	case "40001":
		return alert.ErrUnavailable
	default:
		return err
	}
}
