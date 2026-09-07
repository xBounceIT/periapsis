package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	"github.com/periapsis-im/periapsis/services/worker/internal/ticketbulk"
	"github.com/periapsis-im/periapsis/services/worker/internal/ticketexport"
)

type ticketRuntimeTestRow func(...any) error

func (row ticketRuntimeTestRow) Scan(destinations ...any) error { return row(destinations...) }

type ticketRuntimeTestQuerier struct {
	rows    []pgx.Row
	queries []string
	args    [][]any
}

func (querier *ticketRuntimeTestQuerier) QueryRow(
	_ context.Context,
	query string,
	arguments ...any,
) pgx.Row {
	querier.queries = append(querier.queries, query)
	querier.args = append(querier.args, append([]any(nil), arguments...))
	if len(querier.rows) == 0 {
		return ticketRuntimeTestRow(func(...any) error { return errors.New("unexpected query") })
	}
	row := querier.rows[0]
	querier.rows = querier.rows[1:]
	return row
}

func ticketRuntimeReadinessRow(value []bool) pgx.Row {
	return ticketRuntimeTestRow(func(destinations ...any) error {
		*destinations[0].(*[]bool) = value
		return nil
	})
}

func ticketRuntimeJSONRow(document string) pgx.Row {
	return ticketRuntimeTestRow(func(destinations ...any) error {
		*destinations[0].(*[]byte) = []byte(document)
		return nil
	})
}

func ticketRuntimeTestEntity(t *testing.T, suffix string) kernel.EntityID {
	t.Helper()
	id, err := ticketRuntimeEntity("01890f00-0000-7000-8000-" + suffix)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestTicketRuntimeReadinessRequiresBothABIs(t *testing.T) {
	querier := &ticketRuntimeTestQuerier{rows: []pgx.Row{ticketRuntimeReadinessRow([]bool{true, false, false, true, true})}}
	repository := NewTicketRuntimeRepository(querier)
	if err := repository.Ready(context.Background()); err != nil {
		t.Fatalf("Ready() error = %v", err)
	}
	if len(querier.queries) != 1 || querier.queries[0] != ticketRuntimeReadinessQuery {
		t.Fatalf("readiness queries = %#v", querier.queries)
	}

	for _, flags := range [][]bool{
		nil, {true}, {true, true, true, true}, {true, true, true, true, true, true},
		{false, true, true, true, true}, {true, true, true, false, true}, {true, true, true, true, false},
	} {
		querier = &ticketRuntimeTestQuerier{rows: []pgx.Row{ticketRuntimeReadinessRow(flags)}}
		if err := NewTicketRuntimeRepository(querier).Ready(context.Background()); err == nil {
			t.Fatalf("incomplete attestation or ticket ABI was accepted: %v", flags)
		}
	}
	if err := (*TicketRuntimeRepository)(nil).Ready(context.Background()); err == nil {
		t.Fatal("typed-nil repository readiness failed open")
	}
	var typedNilPool *ticketRuntimeTestQuerier
	if err := NewTicketRuntimeRepository(typedNilPool).Ready(context.Background()); err == nil {
		t.Fatal("typed-nil database dependency readiness failed open")
	}
}

func TestTicketRuntimeReadinessPreservesCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	querier := &ticketRuntimeTestQuerier{}
	if err := NewTicketRuntimeRepository(querier).Ready(ctx); !errors.Is(err, context.Canceled) || len(querier.queries) != 0 {
		t.Fatalf("canceled probe = %v, queries = %d", err, len(querier.queries))
	}
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
		querier = &ticketRuntimeTestQuerier{rows: []pgx.Row{ticketRuntimeTestRow(func(...any) error { return cause })}}
		if err := NewTicketRuntimeRepository(querier).Ready(context.Background()); !errors.Is(err, cause) {
			t.Fatalf("readiness lost context failure: %v", err)
		}
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	querier = &ticketRuntimeTestQuerier{rows: []pgx.Row{ticketRuntimeTestRow(func(destinations ...any) error {
		*destinations[0].(*[]bool) = []bool{true, true, true, true, true}
		cancel()
		return nil
	})}}
	if err := NewTicketRuntimeRepository(querier).Ready(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("probe accepted a result after cancellation")
	}
}

func TestTicketRuntimeInstantNormalizesOnlyCanonicalUTCPrecision(t *testing.T) {
	written := time.Date(2026, 8, 30, 10, 11, 12, 345000000, time.UTC)
	decoded := written.In(time.FixedZone("postgres-json", 0))
	normalized, err := ticketRuntimeInstant(decoded)
	if err != nil || !normalized.Equal(written) || normalized.Location() != time.UTC {
		t.Fatalf("ticketRuntimeInstant() = (%v, %v)", normalized, err)
	}
	for _, invalid := range []time.Time{
		written.In(time.FixedZone("non-utc", int(time.Hour/time.Second))),
		written.Add(time.Nanosecond),
	} {
		if _, err := ticketRuntimeInstant(invalid); err == nil {
			t.Fatalf("ticketRuntimeInstant() accepted %v", invalid)
		}
	}
}

func TestTicketRuntimeQueueDiscoveryUsesBoundedRedactedWire(t *testing.T) {
	tenant := ticketRuntimeTestEntity(t, "000000000001")
	service := ticketRuntimeTestEntity(t, "000000000002")
	worker := ticketRuntimeTestEntity(t, "000000000003")
	document, _ := json.Marshal(map[string]any{
		"schemaVersion": 1,
		"queues": []map[string]any{
			{"type": "bulk", "tenantId": tenant.String(), "kind": "alert", "audience": ""},
			{"type": "export", "tenantId": tenant.String(), "kind": "case", "audience": "customer"},
		},
	})
	querier := &ticketRuntimeTestQuerier{rows: []pgx.Row{ticketRuntimeJSONRow(string(document))}}
	queues, err := NewTicketRuntimeRepository(querier).ListQueues(context.Background(), service, worker, 2)
	if err != nil || len(queues) != 2 || queues[0].Export || !queues[1].Export ||
		queues[1].Audience != kernel.TicketExportAudienceCustomer {
		t.Fatalf("ListQueues() = (%#v, %v)", queues, err)
	}
	if len(querier.args) != 1 || len(querier.args[0]) != 1 {
		t.Fatalf("queue arguments = %#v", querier.args)
	}
	var request struct {
		SchemaVersion    int    `json:"schemaVersion"`
		ServiceAccountID string `json:"serviceAccountId"`
		WorkerID         string `json:"workerId"`
		Purpose          string `json:"purpose"`
		Limit            int    `json:"limit"`
	}
	if err := json.Unmarshal(querier.args[0][0].([]byte), &request); err != nil ||
		request.SchemaVersion != 1 || request.ServiceAccountID != service.String() ||
		request.WorkerID != worker.String() || request.Purpose != "ticket_runtime" || request.Limit != 2 {
		t.Fatalf("queue request = %#v, error = %v", request, err)
	}

	querier = &ticketRuntimeTestQuerier{rows: []pgx.Row{ticketRuntimeJSONRow(
		`{"schemaVersion":1,"queues":[],"unexpected":true}`,
	)}}
	if _, err := NewTicketRuntimeRepository(querier).ListQueues(context.Background(), service, worker, 2); err == nil {
		t.Fatal("queue discovery accepted an unknown response field")
	}
	querier = &ticketRuntimeTestQuerier{rows: []pgx.Row{ticketRuntimeJSONRow(
		`{"schemaVersion":1}`,
	)}}
	if _, err := NewTicketRuntimeRepository(querier).ListQueues(context.Background(), service, worker, 2); err == nil {
		t.Fatal("queue discovery accepted a missing queues field as an authoritative empty queue")
	}
}

func TestTicketRuntimeAdaptersPreserveExactFencesAndClosedOutcomes(t *testing.T) {
	tenant := ticketRuntimeTestEntity(t, "000000000001")
	job := ticketRuntimeTestEntity(t, "000000000002")
	batch := ticketRuntimeTestEntity(t, "000000000003")
	service := ticketRuntimeTestEntity(t, "000000000004")
	worker := ticketRuntimeTestEntity(t, "000000000005")
	target := ticketRuntimeTestEntity(t, "000000000006")
	fence := sha256.Sum256([]byte("fence"))
	targetSet := sha256.Sum256([]byte("target-set"))
	now := time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)
	querier := &ticketRuntimeTestQuerier{rows: []pgx.Row{
		ticketRuntimeJSONRow(`{"schemaVersion":1,"disposition":"applied","sequence":1,"result":"succeeded","controlRevision":0}`),
		ticketRuntimeJSONRow(`{"schemaVersion":1,"control":"fence_lost","controlRevision":0,"rows":[],"next":""}`),
	}}
	repository := NewTicketRuntimeRepository(querier)
	bulkBinding := ticketbulk.BatchBinding{
		TenantID: tenant, JobID: job, BatchID: batch, Kind: kernel.AggregateAlert, WorkerID: worker,
		Revision: 2, Attempt: 1, Fence: fence, TargetSetDigest: targetSet,
		ProjectionVersion: kernel.TicketBulkProjectionVersion, ClaimedAt: now,
		LeaseExpiresAt: now.Add(time.Minute), JobExpiresAt: now.Add(time.Hour),
	}
	pin, err := kernel.NewTicketBulkTargetPin(target, 4)
	if err != nil {
		t.Fatal(err)
	}
	command, err := kernel.NewTicketBulkRelease().CommandFor(tenant, pin)
	if err != nil {
		t.Fatal(err)
	}
	apply, err := repository.ApplyTarget(context.Background(), ticketbulk.ApplyTargetRequest{
		Identity: ticketbulk.Identity{ServiceAccountID: service, WorkerID: worker, Purpose: ticketbulk.WorkerPurpose},
		Binding:  bulkBinding, Sequence: 1, Pin: pin, Command: command,
	})
	if err != nil || apply.Disposition != ticketbulk.ApplyTargetApplied ||
		apply.Result != kernel.TicketBulkTargetSucceeded {
		t.Fatalf("ApplyTarget() = (%s, %v)", apply, err)
	}

	exportBinding := ticketexport.LeaseBinding{
		TenantID: tenant, JobID: job, Kind: kernel.AggregateCase,
		Audience: kernel.TicketExportAudienceOperator, WorkerID: worker,
		Revision: 2, Attempt: 1, Fence: fence, QueryDigest: sha256.Sum256([]byte("query")),
		CatalogDigest: sha256.Sum256([]byte("catalog")), ProjectionVersion: kernel.TicketExportProjectionVersion,
		LeaseClaimedAt: now, LeaseExpiresAt: now.Add(time.Minute), JobExpiresAt: now.Add(time.Hour),
	}
	page, err := repository.ReadPage(context.Background(), ticketexport.PageRequest{
		Identity: ticketexport.Identity{ServiceAccountID: service, WorkerID: worker, Purpose: ticketexport.WorkerPurpose},
		Binding:  exportBinding, Limit: 25,
	})
	if err != nil || page.Control != ticketexport.PageFenceLost || page.ControlRevision != 0 {
		t.Fatalf("ReadPage() = (%s, %v)", page, err)
	}
	for index, arguments := range querier.args {
		var envelope struct {
			Binding struct {
				Fence string `json:"fenceSha256"`
			} `json:"binding"`
		}
		if err := json.Unmarshal(arguments[0].([]byte), &envelope); err != nil ||
			envelope.Binding.Fence != hex.EncodeToString(fence[:]) {
			t.Fatalf("request %d fence = %q, error = %v", index, envelope.Binding.Fence, err)
		}
	}
	missingCursor := NewTicketRuntimeRepository(&ticketRuntimeTestQuerier{rows: []pgx.Row{
		ticketRuntimeJSONRow(`{"schemaVersion":1,"control":"fence_lost","controlRevision":0,"rows":[]}`),
	}})
	if _, err := missingCursor.ReadPage(context.Background(), ticketexport.PageRequest{
		Identity: ticketexport.Identity{ServiceAccountID: service, WorkerID: worker, Purpose: ticketexport.WorkerPurpose},
		Binding:  exportBinding, Limit: 25,
	}); !errors.Is(err, ticketexport.ErrUnavailable) {
		t.Fatalf("ReadPage() missing cursor error = %v", err)
	}
	oversizedPage := NewTicketRuntimeRepository(&ticketRuntimeTestQuerier{rows: []pgx.Row{
		ticketRuntimeJSONRow(`{"schemaVersion":1,"control":"ready","controlRevision":0,"rows":[{"kind":"ticket","snapshotKeySha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","cells":[]},{"kind":"ticket","snapshotKeySha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","cells":[]}],"next":""}`),
	}})
	if _, err := oversizedPage.ReadPage(context.Background(), ticketexport.PageRequest{
		Identity: ticketexport.Identity{ServiceAccountID: service, WorkerID: worker, Purpose: ticketexport.WorkerPurpose},
		Binding:  exportBinding, Limit: 1,
	}); !errors.Is(err, ticketexport.ErrUnavailable) {
		t.Fatalf("ReadPage() oversized page error = %v", err)
	}
}
