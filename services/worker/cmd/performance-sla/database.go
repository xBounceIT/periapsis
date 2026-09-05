package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/periapsis-im/periapsis/services/worker/internal/postgres"
	"github.com/periapsis-im/periapsis/services/worker/internal/slaengine"
	"github.com/periapsis-im/periapsis/services/worker/internal/slaevent"
)

var errDatabase = errors.New("performance SLA database operation failed")

type databaseBackend struct {
	admin    *pgxpool.Pool
	runtime  *pgxpool.Pool
	mode     string
	workerID uuid.UUID
}

func openDatabaseBackend(ctx context.Context, cfg databaseConfig, mode string) (backend, error) {
	// pgx otherwise accepts libpq environment defaults, including service files
	// and startup options. This standalone process only accepts its pinned URL file.
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(key, "PG") {
			if err := os.Unsetenv(key); err != nil {
				return nil, errDatabase
			}
		}
	}
	store := &databaseBackend{mode: mode}
	var err error
	store.workerID, err = uuid.NewV7()
	if err != nil {
		return nil, errDatabase
	}
	store.admin, err = pinnedPool(ctx, cfg, true)
	if err != nil {
		return nil, errDatabase
	}
	store.runtime, err = pinnedPool(ctx, cfg, false)
	if err != nil {
		store.Close()
		return nil, errDatabase
	}
	if err := postgres.NewSLAEventRepository(store.runtime).Ready(ctx); err != nil {
		store.Close()
		return nil, errDatabase
	}
	return store, nil
}

func pinnedPool(ctx context.Context, cfg databaseConfig, readOnly bool) (*pgxpool.Pool, error) {
	parsed, err := parsePinnedPoolConfig(cfg.URL)
	if err != nil {
		return nil, errDatabase
	}
	parsed.MaxConns = 1
	parsed.MinConns = 0
	parsed.ConnConfig.ConnectTimeout = 10 * time.Second
	parsed.ConnConfig.Fallbacks = nil
	parsed.ConnConfig.RuntimeParams = map[string]string{
		"application_name": "periapsis-performance-sla",
		"timezone":         "UTC", "statement_timeout": "30000", "lock_timeout": "5000",
		"default_transaction_read_only": "on",
	}
	if !readOnly {
		parsed.ConnConfig.RuntimeParams["default_transaction_read_only"] = "off"
	}
	parsed.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		var directory, database, role string
		var version int
		if err := conn.QueryRow(ctx, `SELECT current_setting('data_directory'),
current_database(), current_user, current_setting('server_version_num')::integer`).Scan(
			&directory, &database, &role, &version,
		); err != nil {
			return errDatabase
		}
		normalized, err := normalizeDataDirectory(directory)
		if err != nil || normalized != cfg.ExpectedDataDirectory || database != cfg.Database || role != "postgres" || version != 180006 {
			return errDatabase
		}
		if !readOnly {
			if _, err := conn.Exec(ctx, "SET ROLE periapsis_worker"); err != nil {
				return errDatabase
			}
			if err := conn.QueryRow(ctx, "SELECT current_user").Scan(&role); err != nil || role != "periapsis_worker" {
				return errDatabase
			}
		}
		return nil
	}
	pool, err := pgxpool.NewWithConfig(ctx, parsed)
	if err != nil {
		return nil, errDatabase
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, errDatabase
	}
	return pool, nil
}

func parsePinnedPoolConfig(connectionURL string) (*pgxpool.Config, error) {
	parsed, err := url.Parse(connectionURL)
	if err != nil {
		return nil, errDatabase
	}
	// pgx reads a default passfile even when no PG environment variable exists.
	// Pin that internal option to the empty OS device: only the provided URL
	// file may supply a password. The caller cannot supply connection options.
	query := parsed.Query()
	query.Set("passfile", os.DevNull)
	parsed.RawQuery = query.Encode()
	config, err := pgxpool.ParseConfig(parsed.String())
	if err != nil {
		return nil, errDatabase
	}
	return config, nil
}

func (store *databaseBackend) Close() {
	if store.runtime != nil {
		store.runtime.Close()
	}
	if store.admin != nil {
		store.admin.Close()
	}
}

func (store *databaseBackend) Queue(ctx context.Context) (queueCounts, error) {
	query := `SELECT count(*), count(*) FILTER (WHERE status='queued'),
count(*) FILTER (WHERE status='leased'), count(*) FILTER (WHERE status='retry_scheduled'),
count(*) FILTER (WHERE status='completed'), count(*) FILTER (WHERE status='dead_lettered')
FROM public.sla_object_event_ingress`
	if store.mode == "timers" {
		query = strings.Replace(query, "public.sla_object_event_ingress", "public.sla_evaluation_jobs", 1)
	}
	var result queueCounts
	err := store.admin.QueryRow(ctx, query).Scan(&result.Total, &result.Queued, &result.Leased,
		&result.RetryScheduled, &result.Completed, &result.DeadLettered)
	if err != nil {
		return queueCounts{}, errDatabase
	}
	return result, nil
}

func (store *databaseBackend) Snapshot(ctx context.Context) (string, error) {
	// Hash each immutable payload in PostgreSQL and stream fixed-size digests:
	// do not build or transfer an unbounded aggregate of customer documents.
	rows, err := store.admin.Query(ctx, `SELECT sha256(convert_to(jsonb_build_array(
tenant_id,id,object_type,object_id,object_sequence,source_event_id,source_event_type,
source_schema_version,source_aggregate_version,source_digest,event_key,occurred_at,
assignment_snapshot,assignment_snapshot_digest)::text,'UTF8'))
FROM public.sla_object_event_ingress ORDER BY tenant_id,id`)
	if err != nil {
		return "", errDatabase
	}
	defer rows.Close()
	digest := sha256.New()
	count := 0
	for rows.Next() {
		count++
		if count > 500_000 {
			return "", errDatabase
		}
		var value []byte
		if err := rows.Scan(&value); err != nil || len(value) != sha256.Size {
			return "", errDatabase
		}
		_, _ = digest.Write(value)
	}
	if rows.Err() != nil {
		return "", errDatabase
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

type receipt struct {
	TenantID uuid.UUID
	ID       uuid.UUID
	Fence    int64
}

func (store *databaseBackend) verifyReceipts(ctx context.Context, receipts []receipt) (string, error) {
	if len(receipts) == 0 {
		return "", nil
	}
	tenants, ids, fences := make([]uuid.UUID, len(receipts)), make([]uuid.UUID, len(receipts)), make([]int64, len(receipts))
	seen := make(map[uuid.UUID]struct{}, len(receipts))
	for index, value := range receipts {
		if _, duplicate := seen[value.ID]; duplicate {
			return "", errDatabase
		}
		seen[value.ID] = struct{}{}
		tenants[index], ids[index], fences[index] = value.TenantID, value.ID, value.Fence
	}
	query := `SELECT job.tenant_id,job.id,job.fence
FROM unnest($1::uuid[],$2::uuid[],$3::bigint[]) AS expected(tenant_id,id,fence)
JOIN public.sla_object_event_ingress AS job
ON job.tenant_id=expected.tenant_id AND job.id=expected.id AND job.fence=expected.fence
WHERE job.status='completed' AND job.completed_at IS NOT NULL
AND job.worker_id IS NULL AND job.lease_expires_at IS NULL
AND job.plan_digest IS NOT NULL AND job.receipt_digest IS NOT NULL
ORDER BY job.tenant_id,job.id`
	if store.mode == "timers" {
		query = strings.Replace(query, "public.sla_object_event_ingress", "public.sla_evaluation_jobs", 1)
		query = strings.Replace(query, "AND job.plan_digest IS NOT NULL AND job.receipt_digest IS NOT NULL\n", "", 1)
	}
	rows, err := store.admin.Query(ctx, query, tenants, ids, fences)
	if err != nil {
		return "", errDatabase
	}
	defer rows.Close()
	digest := sha256.New()
	count := 0
	for rows.Next() {
		var tenant, id uuid.UUID
		var fence int64
		if err := rows.Scan(&tenant, &id, &fence); err != nil {
			return "", errDatabase
		}
		_, _ = digest.Write(tenant[:])
		_, _ = digest.Write(id[:])
		var encodedFence [8]byte
		binary.BigEndian.PutUint64(encodedFence[:], uint64(fence))
		_, _ = digest.Write(encodedFence[:])
		count++
	}
	if rows.Err() != nil || count != len(receipts) {
		return "", errDatabase
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func (store *databaseBackend) RunBatch(ctx context.Context, size int) (batchResult, error) {
	clock := func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }
	result := batchResult{Outcomes: make(map[string]int)}
	var receipts []receipt
	var workerErr error
	if store.mode == "ingress" {
		repository := &ingressRecorder{Repository: postgres.NewSLAEventRepository(store.runtime), receipts: &receipts, outcomes: result.Outcomes}
		worker, err := slaevent.New(repository, slaevent.Identity{WorkerID: store.workerID, Purpose: slaevent.WorkerPurpose}, slaevent.Config{
			BatchSize: size, LeaseDuration: 3 * time.Minute, OperationTimeout: 30 * time.Second, RunTimeout: 2 * time.Minute,
			MaximumAttempts: 100, RetryBaseDelay: time.Second, RetryMaximumDelay: time.Minute,
		}, clock)
		if err != nil {
			return result, errDatabase
		}
		summary, err := worker.RunOnce(ctx)
		workerErr = err
		result.counts = counts{Claimed: summary.Claimed, Completed: summary.Applied, Replayed: summary.Replayed,
			RetryScheduled: summary.RetryScheduled, DeadLettered: summary.DeadLettered, FenceLost: summary.FenceLost}
	} else {
		repository := &timerRecorder{Repository: postgres.NewSLARepository(store.runtime), receipts: &receipts}
		worker, err := slaengine.New(repository, slaengine.Identity{WorkerID: store.workerID, Purpose: "sla-engine"}, slaengine.Config{
			BatchSize: size, LeaseDuration: 3 * time.Minute, OperationTimeout: 30 * time.Second, RunTimeout: 2 * time.Minute,
			MaximumAttempts: 100, RetryBaseDelay: time.Second, RetryMaximumDelay: time.Minute,
		}, clock)
		if err != nil {
			return result, errDatabase
		}
		summary, err := worker.RunOnce(ctx)
		workerErr = err
		result.counts = counts{Claimed: summary.Claimed, Completed: summary.Completed,
			RetryScheduled: summary.Retryable, DeadLettered: summary.DeadLettered}
		result.Outcomes["timer_completed"] = summary.Completed
	}
	digest, err := store.verifyReceipts(ctx, receipts)
	result.ReceiptsDigest = digest
	if workerErr != nil || err != nil || len(receipts) != result.Completed+result.Replayed {
		return result, errDatabase
	}
	return result, nil
}

type ingressRecorder struct {
	slaevent.Repository
	receipts *[]receipt
	outcomes map[string]int
}

func (recorder *ingressRecorder) Commit(ctx context.Context, request slaevent.CommitRequest) (slaevent.CommitResult, error) {
	result, err := recorder.Repository.Commit(ctx, request)
	if err == nil {
		*recorder.receipts = append(*recorder.receipts, receipt{request.Job.TenantID, uuid.UUID(request.Job.ID.Bytes()), int64(request.Job.Fence)})
		recorder.outcomes[string(request.Job.ObjectType)+"/"+string(request.Job.State.Mode)+"/"+string(result.Outcome)]++
	}
	return result, err
}

type timerRecorder struct {
	slaengine.Repository
	receipts *[]receipt
}

func (recorder *timerRecorder) Finalize(ctx context.Context, request slaengine.FinalizeRequest) error {
	if err := recorder.Repository.Finalize(ctx, request); err != nil {
		return err
	}
	*recorder.receipts = append(*recorder.receipts, receipt{request.TenantID, uuid.UUID(request.JobID.Bytes()), int64(request.Fence)})
	return nil
}
