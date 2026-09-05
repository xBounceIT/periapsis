package postgres

import (
	"context"
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

func TestLookupAlertDeleteReplayUsesClosedTenantABI(t *testing.T) {
	tenantID, actorID, alertID := mustPostgresUUIDv7(t), mustPostgresUUIDv7(t), mustPostgresUUIDv7(t)
	deletedAt := time.Date(2026, 8, 30, 19, 0, 0, 123_000, time.UTC)
	tx := &workflowReplayTransaction{rows: []pgx.Row{
		rowFunc(func(destinations ...any) error {
			*destinations[0].(*string) = tenantID.String()
			*destinations[1].(*string) = actorID.String()
			return nil
		}),
		rowFunc(func(destinations ...any) error {
			*destinations[0].(*string) = ""
			*destinations[1].(*string) = ""
			return nil
		}),
		rowFunc(func(destinations ...any) error {
			*destinations[0].(*uuid.UUID) = alertID
			*destinations[1].(*int64) = 7
			*destinations[2].(*int64) = 8
			*destinations[3].(*time.Time) = deletedAt
			return nil
		}),
	}}
	repository := &TicketingRepository{begin: func(_ context.Context, options pgx.TxOptions) (databaseTransaction, error) {
		if options.IsoLevel != pgx.ReadCommitted {
			t.Fatalf("unexpected transaction options: %+v", options)
		}
		return tx, nil
	}}
	keyHash := sha256.Sum256([]byte("delete-alert-request-0001"))
	fingerprint := sha256.Sum256([]byte("closed request"))
	receipt, found, err := repository.LookupAlertDeleteReplay(context.Background(), application.DeleteAlertReplayQuery{
		Actor:    application.Actor{UserID: actorID, ActiveTenantID: tenantID},
		TenantID: tenantID, AlertID: alertID, KeyHash: keyHash, Fingerprint: fingerprint,
	})
	if err != nil || !found || !receipt.Replayed || receipt.TenantID != tenantID || receipt.AlertID != alertID ||
		receipt.PreviousVersion != 7 || receipt.TombstoneVersion != 8 || !receipt.DeletedAt.Equal(deletedAt) {
		t.Fatalf("receipt=%+v found=%t error=%v", receipt, found, err)
	}
	if !tx.committed || len(tx.queries) != 3 || !strings.Contains(tx.queries[2], "lookup_tenant_alert_delete_replay_v1") ||
		len(tx.args[2]) != 3 || tx.args[2][0] != alertID {
		t.Fatalf("unexpected transaction/query: committed=%t queries=%#v args=%#v", tx.committed, tx.queries, tx.args)
	}
}

func TestLookupAlertDeleteReplayRejectsContradictoryReceipt(t *testing.T) {
	tenantID, actorID, alertID := mustPostgresUUIDv7(t), mustPostgresUUIDv7(t), mustPostgresUUIDv7(t)
	tx := &workflowReplayTransaction{rows: []pgx.Row{
		rowFunc(func(destinations ...any) error {
			*destinations[0].(*string) = tenantID.String()
			*destinations[1].(*string) = actorID.String()
			return nil
		}),
		rowFunc(func(destinations ...any) error {
			*destinations[0].(*string) = ""
			*destinations[1].(*string) = ""
			return nil
		}),
		rowFunc(func(destinations ...any) error {
			*destinations[0].(*uuid.UUID) = alertID
			*destinations[1].(*int64) = 7
			*destinations[2].(*int64) = 9
			*destinations[3].(*time.Time) = time.Date(2026, 8, 30, 19, 0, 0, 0, time.UTC)
			return nil
		}),
	}}
	repository := &TicketingRepository{begin: func(context.Context, pgx.TxOptions) (databaseTransaction, error) {
		return tx, nil
	}}
	_, found, err := repository.LookupAlertDeleteReplay(context.Background(), application.DeleteAlertReplayQuery{
		Actor:    application.Actor{UserID: actorID, ActiveTenantID: tenantID},
		TenantID: tenantID, AlertID: alertID,
		KeyHash:     sha256.Sum256([]byte("delete-alert-request-0002")),
		Fingerprint: sha256.Sum256([]byte("closed request")),
	})
	if err == nil || found {
		t.Fatalf("contradictory receipt was accepted: found=%t error=%v", found, err)
	}
}
