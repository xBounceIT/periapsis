package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/periapsis-im/periapsis/services/api/internal/apiratelimit"
)

const apiRateLimitIntegrationDatabaseURL = "PERIAPSIS_API_RATE_LIMIT_TEST_DATABASE_URL"

func TestAPIRateLimitRepositoryPostgreSQL(t *testing.T) {
	databaseURL := strings.TrimSpace(os.Getenv(apiRateLimitIntegrationDatabaseURL))
	if databaseURL == "" {
		t.Skipf("%s is not set", apiRateLimitIntegrationDatabaseURL)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	adminPool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect API rate-limit admin pool: %v", err)
	}
	defer adminPool.Close()
	runtimeConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatalf("parse API rate-limit database URL: %v", err)
	}
	runtimeConfig.MaxConns = 2
	runtimeConfig.ConnConfig.RuntimeParams["statement_timeout"] = "15s"
	runtimeConfig.AfterConnect = func(connectContext context.Context, connection *pgx.Conn) error {
		_, connectErr := connection.Exec(connectContext, `SET ROLE "periapsis_api"`)
		return connectErr
	}
	runtimePool, err := pgxpool.NewWithConfig(ctx, runtimeConfig)
	if err != nil {
		t.Fatalf("create API rate-limit runtime pool: %v", err)
	}
	defer runtimePool.Close()
	if err := runtimePool.Ping(ctx); err != nil {
		t.Fatalf("connect API rate-limit runtime pool: %v", err)
	}

	unique := uuid.Must(uuid.NewV7()).String()
	networkDigest := sha256.Sum256([]byte(unique + ":network"))
	credentialDigest := sha256.Sum256([]byte(unique + ":credential"))
	tenantDigest := sha256.Sum256([]byte(unique + ":tenant-subject"))
	defer func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		if _, cleanupErr := adminPool.Exec(
			cleanupContext,
			`DELETE FROM public.auth_rate_limits
			 WHERE key_digest = $1::bytea OR key_digest = $2::bytea OR key_digest = $3::bytea`,
			networkDigest[:], credentialDigest[:], tenantDigest[:],
		); cleanupErr != nil {
			t.Errorf("clean API rate-limit integration rows: %v", cleanupErr)
		}
	}()

	rules := []apiratelimit.Rule{
		{Scope: apiratelimit.ScopeNetwork, Digest: networkDigest[:], Limit: 1},
		{Scope: apiratelimit.ScopeCredential, Digest: credentialDigest[:], Limit: 2},
		{Scope: apiratelimit.ScopeTenantSubject, Digest: tenantDigest[:], Limit: 3},
	}
	repository := NewAPIRateLimitRepository(runtimePool)
	first, err := repository.Admit(ctx, rules)
	if err != nil || !first.Admitted || first.RetryAfterSeconds != 0 {
		t.Fatalf("first Admit() = %#v, %v", first, err)
	}
	var second apiratelimit.Decision
	for attempt := 0; attempt < 10; attempt++ {
		second, err = repository.Admit(ctx, rules)
		if err != nil || !second.Admitted {
			break
		}
	}
	if err != nil || second.Admitted || second.RetryAfterSeconds != 1 {
		t.Fatalf("second Admit() = %#v, %v", second, err)
	}

	var directCount int
	err = runtimePool.QueryRow(ctx, `SELECT count(*) FROM public.auth_rate_limits`).Scan(&directCount)
	var databaseError *pgconn.PgError
	if !errors.As(err, &databaseError) || databaseError.Code != "42501" {
		t.Fatalf("direct API table read error = %v, want SQLSTATE 42501", err)
	}

	var rowCount, minimumAttempts, maximumAttempts int
	if err := adminPool.QueryRow(
		ctx,
		`SELECT count(*)::integer, min(attempt_count)::integer, max(attempt_count)::integer
		 FROM public.auth_rate_limits
		 WHERE (scope = 'api_network' AND key_digest = $1::bytea)
		    OR (scope = 'api_credential' AND key_digest = $2::bytea)
		    OR (scope = 'api_tenant_subject' AND key_digest = $3::bytea)`,
		networkDigest[:], credentialDigest[:], tenantDigest[:],
	).Scan(&rowCount, &minimumAttempts, &maximumAttempts); err != nil {
		t.Fatalf("read API rate-limit integration rows: %v", err)
	}
	if rowCount != 3 || minimumAttempts != 2 || maximumAttempts != 2 {
		t.Fatalf("rate-limit rows = %d with attempts %d..%d", rowCount, minimumAttempts, maximumAttempts)
	}
}
