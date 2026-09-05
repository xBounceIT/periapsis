package postgres

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

func TestEscalationLocksAllDistinctSharedResourcesInStableOrder(t *testing.T) {
	t.Parallel()
	tenantID, first, second := alertTestUUID(201), alertTestUUID(202), alertTestUUID(203)
	sources := []escalationSourceJSON{
		{ItemIDs: map[string][]uuid.UUID{"iocIds": {second, first}, "assetIds": {second}, "attachmentIds": {alertTestUUID(204)}}},
		{ItemIDs: map[string][]uuid.UUID{"iocIds": {first}, "assetIds": {first, second}}},
	}
	queries := make([]string, 0)
	tx := &dfirTransactionStub{query: func(query string, args []any) (pgx.Rows, error) {
		queries = append(queries, query)
		if len(args) != 2 || args[0] != tenantID || !slices.Equal(args[1].([]uuid.UUID), []uuid.UUID{first, second}) ||
			!strings.Contains(query, "id = ANY($2::uuid[])") || !strings.Contains(query, "archived_at IS NULL") ||
			!strings.Contains(query, "ORDER BY id FOR UPDATE") {
			return nil, errors.New("escalation resource lock lost tenant, order, liveness or deduplication")
		}
		return &dfirRowsStub{rows: [][]any{{first}, {second}}}, nil
	}}
	if err := lockEscalationSharedResources(context.Background(), tx, tenantID, sources); err != nil {
		t.Fatal(err)
	}
	if len(queries) != 2 || !strings.Contains(queries[0], "public.dfir_assets") || !strings.Contains(queries[1], "public.dfir_iocs") {
		t.Fatalf("resource lock sequence = %v", queries)
	}
	queries = nil
	if err := lockEscalationSharedResources(context.Background(), tx, tenantID, []escalationSourceJSON{{ItemIDs: map[string][]uuid.UUID{"attachmentIds": {first}}}}); err != nil || len(queries) != 0 {
		t.Fatalf("attachment-only copy locked an unrelated resource: %v", err)
	}
	tx.query = func(string, []any) (pgx.Rows, error) { return &dfirRowsStub{rows: [][]any{{first}}}, nil }
	if err := lockEscalationSharedResources(context.Background(), tx, tenantID, sources); !errors.Is(err, application.ErrNotFound) {
		t.Fatalf("missing/archived shared resource = %v", err)
	}
	if err := lockEscalationSharedResources(context.Background(), tx, tenantID, []escalationSourceJSON{{ItemIDs: map[string][]uuid.UUID{"assetIds": {uuid.Nil}}}}); !errors.Is(err, application.ErrInvalidInput) {
		t.Fatalf("invalid resource UUID = %v", err)
	}
	if err := mapTicketDatabaseError(&pgconn.PgError{Code: "40P01"}); !errors.Is(err, application.ErrConflict) {
		t.Fatalf("database deadlock did not become a retryable conflict: %v", err)
	}
}
