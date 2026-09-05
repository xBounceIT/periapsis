package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestAuthStateCleanerUsesWorkerOnlyBoundedFunctions(t *testing.T) {
	querier := &cleanupQuerier{row: cleanupRow{
		rateLimits: 3, challenges: 2, sessions: 1, platformCommands: 4, tenantCommands: 5,
		tenantMembershipLifecycleCommands: 6, dfirMutationCommandResults: 7,
		dfirMutationCommands: 8,
	}}
	counts, err := NewAuthStateCleaner(querier).Prune(context.Background(), 250)
	if err != nil {
		t.Fatalf("Prune() error = %v", err)
	}
	if counts != (AuthStateCleanupCounts{
		RateLimits: 3, Challenges: 2, Sessions: 1, PlatformCommands: 4, TenantCommands: 5,
		TenantMembershipLifecycleCommands: 6,
		DFIRMutationCommandResults:        7,
		DFIRMutationCommands:              8,
	}) {
		t.Fatalf("Prune() counts = %+v", counts)
	}
	if !strings.Contains(querier.query, "app.prune_expired_auth_state($1)") {
		t.Fatalf("Prune() query = %q", querier.query)
	}
	if !strings.Contains(querier.query, "app.prune_expired_authorization_commands($1)") {
		t.Fatalf("Prune() query = %q", querier.query)
	}
	if !strings.Contains(querier.query, "app.prune_expired_tenant_membership_lifecycle_commands_v1($1)") {
		t.Fatalf("Prune() query = %q", querier.query)
	}
	if !strings.Contains(querier.query, "app.prune_expired_dfir_mutation_commands_v1($1)") {
		t.Fatalf("Prune() query = %q", querier.query)
	}
	if len(querier.arguments) != 1 || querier.arguments[0] != 250 {
		t.Fatalf("Prune() arguments = %#v", querier.arguments)
	}
}

func TestAuthStateCleanerRejectsOutOfContractBatchWithoutQuerying(t *testing.T) {
	for _, batch := range []int{0, 1001} {
		querier := &cleanupQuerier{}
		if _, err := NewAuthStateCleaner(querier).Prune(context.Background(), batch); err == nil {
			t.Fatalf("Prune() accepted batch %d", batch)
		}
		if querier.query != "" {
			t.Fatalf("Prune() queried the database for batch %d", batch)
		}
	}
}

func TestAuthStateCleanerFailsClosedOnDatabaseError(t *testing.T) {
	querier := &cleanupQuerier{row: cleanupRow{err: errors.New("database unavailable")}}
	if _, err := NewAuthStateCleaner(querier).Prune(context.Background(), 10); err == nil {
		t.Fatal("Prune() hid the database failure")
	}
}

type cleanupQuerier struct {
	query     string
	arguments []any
	row       cleanupRow
}

func (q *cleanupQuerier) QueryRow(_ context.Context, query string, arguments ...any) pgx.Row {
	q.query = query
	q.arguments = arguments
	return q.row
}

type cleanupRow struct {
	rateLimits                        int
	challenges                        int
	sessions                          int
	platformCommands                  int
	tenantCommands                    int
	tenantMembershipLifecycleCommands int
	dfirMutationCommandResults        int
	dfirMutationCommands              int
	err                               error
}

func (r cleanupRow) Scan(destinations ...any) error {
	if r.err != nil {
		return r.err
	}
	*destinations[0].(*int) = r.rateLimits
	*destinations[1].(*int) = r.challenges
	*destinations[2].(*int) = r.sessions
	*destinations[3].(*int) = r.platformCommands
	*destinations[4].(*int) = r.tenantCommands
	*destinations[5].(*int) = r.tenantMembershipLifecycleCommands
	*destinations[6].(*int) = r.dfirMutationCommandResults
	*destinations[7].(*int) = r.dfirMutationCommands
	return nil
}
