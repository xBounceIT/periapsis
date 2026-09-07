package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/periapsis-im/periapsis/services/worker/internal/customfieldimport"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRuntimeRepositoryReadinessPostgreSQL(t *testing.T) {
	databaseURL := os.Getenv("PERIAPSIS_READINESS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("PERIAPSIS_READINESS_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal("invalid readiness test database configuration")
	}
	config.MaxConns = 1
	config.ConnConfig.RuntimeParams["statement_timeout"] = "15s"
	config.AfterConnect = func(ctx context.Context, connection *pgx.Conn) error {
		_, err := connection.Exec(ctx, "SET ROLE periapsis_worker")
		return err
	}
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal("cannot create readiness test pool")
	}
	defer pool.Close()
	identity := customfieldimport.Identity{
		ServiceAccountID: uuid.MustParse("01890f00-0000-7000-8000-0000000000f1"),
		WorkerID:         uuid.Must(uuid.NewV7()),
	}
	for name, ready := range map[string]func(context.Context) error{
		"SLA events":        NewSLAEventRepository(pool).Ready,
		"SLA actions":       NewSLAActionRepository(pool).Ready,
		"ticket operations": NewTicketRuntimeRepository(pool).Ready,
		"configured import principal": func(ctx context.Context) error {
			return NewCustomFieldImportWorkerRepository(pool).Ready(ctx, identity)
		},
	} {
		t.Run(name, func(t *testing.T) {
			acquisitions := pool.Stat().AcquireCount()
			started := time.Now()
			if err := ready(ctx); err != nil {
				t.Fatalf("current repository readiness failed: %v", err)
			}
			if name == "ticket operations" {
				if pool.Stat().AcquireCount() != acquisitions+1 {
					t.Fatal("ticket readiness repeated the release attestation")
				}
				t.Logf("ticket aggregate completed in %s", time.Since(started))
			}
		})
	}
	var retiredCallable bool
	if err := pool.QueryRow(ctx, `SELECT has_function_privilege(current_user,
		'app.sla_object_event_ingress_schema_readiness_v51()', 'EXECUTE')`).Scan(&retiredCallable); err != nil {
		t.Fatal("cannot check retired readiness privileges")
	}
	if retiredCallable {
		t.Fatal("the retired readiness ABI must remain inaccessible")
	}
}
