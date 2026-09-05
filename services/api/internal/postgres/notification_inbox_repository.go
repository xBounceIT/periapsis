package postgres

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/periapsis-im/periapsis/services/api/internal/notificationinbox"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
)

// NotificationInboxRepository is a JSON-ABI adapter. The database functions
// are the mutation boundary: they re-resolve live session, membership and
// audience in the same transaction as CAS, audit and idempotency persistence.
type NotificationInboxRepository struct {
	begin transactionBeginner
}

func NewNotificationInboxRepository(pool *pgxpool.Pool) *NotificationInboxRepository {
	if pool == nil {
		return nil
	}
	return &NotificationInboxRepository{begin: poolTransactionBeginner(pool)}
}

var _ notificationinbox.Repository = (*NotificationInboxRepository)(nil)

func (repository *NotificationInboxRepository) ResolveAccess(
	ctx context.Context,
	actor notificationinbox.Actor,
	tenantID uuid.UUID,
) (notificationinbox.AccessEvidence, error) {
	result, err := notificationInboxTransaction(ctx, repository, tenantID, actor.UserID, phase4ReadOptions(),
		func(tx databaseTransaction) (notificationinbox.AccessEvidence, error) {
			var raw []byte
			if queryErr := tx.QueryRow(ctx,
				"SELECT app.resolve_notification_inbox_access_v1($1)", actor.SessionID,
			).Scan(&raw); queryErr != nil {
				return notificationinbox.AccessEvidence{}, queryErr
			}
			var wire notificationInboxAccessWire
			if decodeErr := decodeNotificationInboxJSON(raw, &wire); decodeErr != nil {
				return notificationinbox.AccessEvidence{}, decodeErr
			}
			principal, principalErr := notificationInboxPrincipal(wire.Principal)
			if principalErr != nil {
				return notificationinbox.AccessEvidence{}, principalErr
			}
			return notificationinbox.AccessEvidence{
				TenantID: wire.TenantID, UserID: wire.UserID, SessionID: wire.SessionID,
				Principal: principal, Authenticated: wire.Authenticated,
				Active: wire.Active, EvaluatedAt: wire.EvaluatedAt,
			}, nil
		})
	return result, mapNotificationInboxDatabaseError(err)
}

func (repository *NotificationInboxRepository) List(
	ctx context.Context,
	params notificationinbox.ListParams,
) (notificationinbox.ListSnapshot, error) {
	result, err := notificationInboxTransaction(ctx, repository, params.TenantID, params.UserID, phase4ReadOptions(),
		func(tx databaseTransaction) (notificationinbox.ListSnapshot, error) {
			request := struct {
				SchemaVersion int        `json:"schemaVersion"`
				TenantID      uuid.UUID  `json:"tenantId"`
				UserID        uuid.UUID  `json:"userId"`
				SessionID     uuid.UUID  `json:"sessionId"`
				After         *uuid.UUID `json:"after"`
				Limit         int        `json:"limit"`
				UnreadOnly    bool       `json:"unreadOnly"`
			}{1, params.TenantID, params.UserID, params.Actor.SessionID,
				params.After, params.FetchLimit, params.UnreadOnly}
			var wire notificationInboxListWire
			if queryErr := notificationInboxJSONCall(ctx, tx,
				"app.list_notification_inbox_v1", request, &wire); queryErr != nil {
				return notificationinbox.ListSnapshot{}, queryErr
			}
			return notificationinbox.ListSnapshot{
				TenantID: wire.TenantID, UserID: wire.UserID,
				Items: wire.Items, InboxRevision: wire.InboxRevision,
			}, nil
		})
	return result, mapNotificationInboxDatabaseError(err)
}

func (repository *NotificationInboxRepository) CountUnread(
	ctx context.Context,
	params notificationinbox.CountUnreadParams,
) (notificationinbox.UnreadState, error) {
	result, err := notificationInboxTransaction(ctx, repository, params.TenantID, params.UserID, phase4ReadOptions(),
		func(tx databaseTransaction) (notificationinbox.UnreadState, error) {
			request := notificationInboxCoordinateRequest{
				SchemaVersion: 1, TenantID: params.TenantID, UserID: params.UserID,
				SessionID: params.Actor.SessionID,
			}
			var wire notificationInboxUnreadWire
			if queryErr := notificationInboxJSONCall(ctx, tx,
				"app.count_notification_inbox_unread_v1", request, &wire); queryErr != nil {
				return notificationinbox.UnreadState{}, queryErr
			}
			return notificationinbox.UnreadState{
				TenantID: wire.TenantID, UserID: wire.UserID,
				Count: wire.Count, InboxRevision: wire.InboxRevision,
			}, nil
		})
	return result, mapNotificationInboxDatabaseError(err)
}

func (repository *NotificationInboxRepository) SetReadState(
	ctx context.Context,
	params notificationinbox.SetReadStateParams,
) (notificationinbox.ReadStateResult, error) {
	result, err := notificationInboxTransaction(ctx, repository, params.TenantID, params.UserID, phase4WriteOptions(),
		func(tx databaseTransaction) (notificationinbox.ReadStateResult, error) {
			request := struct {
				SchemaVersion    int                    `json:"schemaVersion"`
				TenantID         uuid.UUID              `json:"tenantId"`
				UserID           uuid.UUID              `json:"userId"`
				SessionID        uuid.UUID              `json:"sessionId"`
				ItemID           uuid.UUID              `json:"itemId"`
				Read             bool                   `json:"read"`
				ExpectedRevision uint64                 `json:"expectedRevision"`
				Operation        string                 `json:"operation"`
				KeyDigest        string                 `json:"keyDigest"`
				RequestDigest    string                 `json:"requestDigest"`
				Audit            notificationInboxAudit `json:"audit"`
			}{
				1, params.TenantID, params.UserID, params.Actor.SessionID,
				params.ItemID, params.Read, params.ExpectedRevision,
				params.Command.Operation, hex.EncodeToString(params.Command.KeyDigest[:]),
				hex.EncodeToString(params.Command.RequestDigest[:]), notificationInboxAuditFrom(params.Audit),
			}
			var wire notificationInboxReadStateWire
			if queryErr := notificationInboxJSONCall(ctx, tx,
				"app.set_notification_inbox_read_state_v1", request, &wire); queryErr != nil {
				return notificationinbox.ReadStateResult{}, queryErr
			}
			mapped := notificationinbox.ReadStateResult{
				Item: wire.Item, InboxRevision: wire.InboxRevision,
				Changed: wire.Changed, Replayed: wire.Replayed,
			}
			if params.ValidateResult == nil {
				return notificationinbox.ReadStateResult{}, notificationinbox.ErrRepositoryInvalidInput
			}
			if validationErr := params.ValidateResult(mapped); validationErr != nil {
				return notificationinbox.ReadStateResult{}, validationErr
			}
			return mapped, nil
		})
	return result, mapNotificationInboxDatabaseError(err)
}

func (repository *NotificationInboxRepository) MarkAllRead(
	ctx context.Context,
	params notificationinbox.MarkAllReadParams,
) (notificationinbox.MarkAllReadResult, error) {
	result, err := notificationInboxTransaction(ctx, repository, params.TenantID, params.UserID, phase4WriteOptions(),
		func(tx databaseTransaction) (notificationinbox.MarkAllReadResult, error) {
			request := struct {
				SchemaVersion    int                    `json:"schemaVersion"`
				TenantID         uuid.UUID              `json:"tenantId"`
				UserID           uuid.UUID              `json:"userId"`
				SessionID        uuid.UUID              `json:"sessionId"`
				ExpectedRevision uint64                 `json:"expectedRevision"`
				Operation        string                 `json:"operation"`
				KeyDigest        string                 `json:"keyDigest"`
				RequestDigest    string                 `json:"requestDigest"`
				Audit            notificationInboxAudit `json:"audit"`
			}{
				1, params.TenantID, params.UserID, params.Actor.SessionID,
				params.ExpectedRevision, params.Command.Operation,
				hex.EncodeToString(params.Command.KeyDigest[:]),
				hex.EncodeToString(params.Command.RequestDigest[:]), notificationInboxAuditFrom(params.Audit),
			}
			var wire notificationInboxMarkAllWire
			if queryErr := notificationInboxJSONCall(ctx, tx,
				"app.mark_all_notification_inbox_read_v1", request, &wire); queryErr != nil {
				return notificationinbox.MarkAllReadResult{}, queryErr
			}
			mapped := notificationinbox.MarkAllReadResult{
				TenantID: wire.TenantID, UserID: wire.UserID, Affected: wire.Affected,
				InboxRevision: wire.InboxRevision, Changed: wire.Changed, Replayed: wire.Replayed,
			}
			if params.ValidateResult == nil {
				return notificationinbox.MarkAllReadResult{}, notificationinbox.ErrRepositoryInvalidInput
			}
			if validationErr := params.ValidateResult(mapped); validationErr != nil {
				return notificationinbox.MarkAllReadResult{}, validationErr
			}
			return mapped, nil
		})
	return result, mapNotificationInboxDatabaseError(err)
}

type notificationInboxCoordinateRequest struct {
	SchemaVersion int       `json:"schemaVersion"`
	TenantID      uuid.UUID `json:"tenantId"`
	UserID        uuid.UUID `json:"userId"`
	SessionID     uuid.UUID `json:"sessionId"`
}

type notificationInboxAudit struct {
	RequestID     uuid.UUID `json:"requestId"`
	CorrelationID uuid.UUID `json:"correlationId"`
	RemoteAddress string    `json:"remoteAddress"`
	UserAgent     string    `json:"userAgent"`
}

func notificationInboxAuditFrom(value notificationinbox.AuditMetadata) notificationInboxAudit {
	return notificationInboxAudit{
		RequestID: value.RequestID, CorrelationID: value.CorrelationID,
		RemoteAddress: value.RemoteAddress.String(), UserAgent: value.UserAgent,
	}
}

type notificationInboxAccessWire struct {
	TenantID      uuid.UUID `json:"tenantId"`
	UserID        uuid.UUID `json:"userId"`
	SessionID     uuid.UUID `json:"sessionId"`
	Principal     string    `json:"principal"`
	Authenticated bool      `json:"authenticated"`
	Active        bool      `json:"active"`
	EvaluatedAt   time.Time `json:"evaluatedAt"`
}

type notificationInboxListWire struct {
	TenantID      uuid.UUID                `json:"tenantId"`
	UserID        uuid.UUID                `json:"userId"`
	Items         []notificationinbox.Item `json:"items"`
	InboxRevision uint64                   `json:"inboxRevision"`
}

type notificationInboxUnreadWire struct {
	TenantID      uuid.UUID `json:"tenantId"`
	UserID        uuid.UUID `json:"userId"`
	Count         uint64    `json:"count"`
	InboxRevision uint64    `json:"inboxRevision"`
}

type notificationInboxReadStateWire struct {
	Item          notificationinbox.Item `json:"item"`
	InboxRevision uint64                 `json:"inboxRevision"`
	Changed       bool                   `json:"changed"`
	Replayed      bool                   `json:"replayed"`
}

type notificationInboxMarkAllWire struct {
	TenantID      uuid.UUID `json:"tenantId"`
	UserID        uuid.UUID `json:"userId"`
	Affected      uint64    `json:"affected"`
	InboxRevision uint64    `json:"inboxRevision"`
	Changed       bool      `json:"changed"`
	Replayed      bool      `json:"replayed"`
}

func notificationInboxPrincipal(value string) (notificationinbox.Principal, error) {
	switch value {
	case "operator":
		return notificationinbox.PrincipalOperator, nil
	case "customer":
		return notificationinbox.PrincipalCustomer, nil
	default:
		return 0, fmt.Errorf("invalid notification inbox principal projection")
	}
}

func notificationInboxTransaction[T any](
	ctx context.Context,
	repository *NotificationInboxRepository,
	tenantID uuid.UUID,
	userID uuid.UUID,
	options pgx.TxOptions,
	work func(databaseTransaction) (T, error),
) (T, error) {
	var zero T
	if repository == nil || repository.begin == nil || work == nil {
		return zero, notificationinbox.ErrRepositoryForbidden
	}
	return withinTransactionWithOptions(ctx, repository.begin, options,
		func(tx databaseTransaction) (T, error) {
			installed, installErr := dbsql.New(tx).SetTenantContext(ctx, dbsql.SetTenantContextParams{
				TenantID: toDatabaseUUID(tenantID), UserID: toDatabaseUUID(userID),
			})
			if installErr != nil {
				return zero, installErr
			}
			if installed == nil || installed.TenantID != tenantID.String() || installed.UserID != userID.String() {
				return zero, fmt.Errorf("notification inbox database context mismatch")
			}
			return work(tx)
		})
}

func notificationInboxJSONCall(
	ctx context.Context,
	tx databaseTransaction,
	functionName string,
	request any,
	result any,
) error {
	encoded, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("encode notification inbox request: %w", err)
	}
	var raw []byte
	query := "SELECT " + functionName + "($1::jsonb)"
	if err = tx.QueryRow(ctx, query, encoded).Scan(&raw); err != nil {
		return err
	}
	return decodeNotificationInboxJSON(raw, result)
}

func decodeNotificationInboxJSON(raw []byte, destination any) error {
	if len(raw) == 0 || destination == nil {
		return fmt.Errorf("notification inbox returned an empty projection")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode notification inbox projection: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("decode notification inbox trailing projection")
	}
	return nil
}

func mapNotificationInboxDatabaseError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, notificationinbox.ErrRepositoryInvalidInput) ||
		errors.Is(err, notificationinbox.ErrRepositoryForbidden) ||
		errors.Is(err, notificationinbox.ErrRepositoryNotFound) ||
		errors.Is(err, notificationinbox.ErrRepositoryConflict) ||
		errors.Is(err, notificationinbox.ErrRepositoryPrecondition) {
		return err
	}
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) {
		switch databaseError.Code {
		case "22023", "22P02", "23514":
			return notificationinbox.ErrRepositoryInvalidInput
		case "42501":
			return notificationinbox.ErrRepositoryForbidden
		case "P0002":
			return notificationinbox.ErrRepositoryNotFound
		case "23505":
			return notificationinbox.ErrRepositoryConflict
		case "40001":
			return notificationinbox.ErrRepositoryPrecondition
		}
	}
	return fmt.Errorf("notification inbox repository unavailable")
}
