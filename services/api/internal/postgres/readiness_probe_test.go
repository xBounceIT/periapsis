package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestReadinessEvidenceIsBoundToPoolAndProbeLifetime(t *testing.T) {
	pool := &pgxpool.Pool{}
	probe, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ctx := context.WithValue(probe, verifiedRuntimeKey{}, verifiedRuntime{pool: pool, probe: probe})
	if !runtimeVerifiedInProbe(ctx, pool) {
		t.Fatal("same probe and pool must reuse verified evidence")
	}
	if runtimeVerifiedInProbe(ctx, &pgxpool.Pool{}) || runtimeVerifiedInProbe(context.Background(), pool) ||
		runtimeVerifiedInProbe(nil, pool) || runtimeVerifiedInProbe(ctx, (*pgxpool.Pool)(nil)) {
		t.Fatal("evidence escaped its pool or context")
	}
	child, cancelChild := context.WithCancel(ctx)
	cancelChild()
	if runtimeVerifiedInProbe(child, pool) {
		t.Fatal("canceled child reused readiness evidence")
	}
	withoutCancellation := context.WithoutCancel(ctx)
	cancel()
	if runtimeVerifiedInProbe(ctx, pool) || runtimeVerifiedInProbe(withoutCancellation, pool) {
		t.Fatal("evidence outlived its original probe")
	}
}

func TestFailedReadinessRefreshDiscardsPriorEvidence(t *testing.T) {
	pool := &pgxpool.Pool{}
	probe, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ctx := context.WithValue(probe, verifiedRuntimeKey{}, verifiedRuntime{pool: pool, probe: probe})
	row := exactStubSchemaRow()
	row.err = errors.New("database unavailable")
	ctx, checks := NewHealthChecker(&stubSchemaQuerier{row: row}).CheckWithContext(ctx)
	if checks[0].Ready || runtimeVerifiedInProbe(ctx, pool) {
		t.Fatal("failed refresh retained earlier positive evidence")
	}
}
