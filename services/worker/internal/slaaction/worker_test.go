package slaaction

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/sla"
)

type repositoryStub struct {
	claims       []Claim
	claimErr     error
	results      []ExecuteResult
	executeErrAt int
	claimCalls   []ClaimRequest
	executeCalls []ExecuteRequest
}

func (stub *repositoryStub) Claim(_ context.Context, request ClaimRequest) ([]Claim, error) {
	stub.claimCalls = append(stub.claimCalls, request)
	return append([]Claim(nil), stub.claims...), stub.claimErr
}

func (stub *repositoryStub) Execute(_ context.Context, request ExecuteRequest) (ExecuteResult, error) {
	stub.executeCalls = append(stub.executeCalls, request)
	index := len(stub.executeCalls) - 1
	if stub.executeErrAt == index+1 {
		return ExecuteResult{}, errors.New("response lost")
	}
	return stub.results[index], nil
}

func TestWorkerExecutesClosedFencedClaims(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	tenantID := testUUIDv7(1)
	stub := &repositoryStub{
		claims: []Claim{
			testClaim(tenantID, testUUIDv7(2), kernel.ActionEmail, now),
			testClaim(tenantID, testUUIDv7(6), kernel.ActionCreateSystemAlert, now),
		},
		results: []ExecuteResult{{Outcome: OutcomeApplied}, {Outcome: OutcomeReplayed}},
	}
	worker := testWorker(t, stub, now)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	summary, err := worker.RunOnce(ctx, Queue{TenantID: tenantID})
	if err != nil {
		t.Fatalf("RunOnce returned error: %v", err)
	}
	if summary != (Summary{Claimed: 2, Applied: 1, Replayed: 1}) {
		t.Fatalf("unexpected summary: %+v", summary)
	}
	if len(stub.claimCalls) != 1 || stub.claimCalls[0].Queue.TenantID != tenantID ||
		len(stub.executeCalls) != 2 || stub.executeCalls[0].Claim.ActionKind != kernel.ActionEmail {
		t.Fatalf("unexpected repository calls: claim=%+v execute=%+v", stub.claimCalls, stub.executeCalls)
	}
}

func TestWorkerLeavesUnknownCommitForFencedReplay(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	tenantID := testUUIDv7(10)
	stub := &repositoryStub{
		claims: []Claim{
			testClaim(tenantID, testUUIDv7(11), kernel.ActionAddTag, now),
			testClaim(tenantID, testUUIDv7(15), kernel.ActionWebhook, now),
		},
		results:      []ExecuteResult{{Outcome: OutcomeApplied}},
		executeErrAt: 1,
	}
	worker := testWorker(t, stub, now)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	summary, err := worker.RunOnce(ctx, Queue{TenantID: tenantID})
	if !errors.Is(err, ErrTransitionOutcomeUnknown) || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected unknown unavailable outcome, got summary=%+v err=%v", summary, err)
	}
	if summary.Claimed != 2 || len(stub.executeCalls) != 1 {
		t.Fatalf("worker continued after unknown commit: summary=%+v calls=%d", summary, len(stub.executeCalls))
	}
}

func TestWorkerRejectsCrossTenantOrDuplicateProjection(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	tenantID := testUUIDv7(20)
	claim := testClaim(tenantID, testUUIDv7(21), kernel.ActionCreateTask, now)
	claim.TenantID = testUUIDv7(30)
	stub := &repositoryStub{claims: []Claim{claim}}
	worker := testWorker(t, stub, now)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	summary, err := worker.RunOnce(ctx, Queue{TenantID: tenantID})
	if !errors.Is(err, ErrInvalidProjection) || summary.Claimed != 1 || len(stub.executeCalls) != 0 {
		t.Fatalf("cross-tenant projection was not rejected: summary=%+v err=%v", summary, err)
	}

	claim = testClaim(tenantID, testUUIDv7(31), kernel.ActionCreateTask, now)
	stub.claims = []Claim{claim, claim}
	summary, err = worker.RunOnce(ctx, Queue{TenantID: tenantID})
	if !errors.Is(err, ErrInvalidProjection) || summary.Claimed != 2 || len(stub.executeCalls) != 0 {
		t.Fatalf("duplicate projection was not rejected: summary=%+v err=%v", summary, err)
	}
}

func TestWorkerAccountsEveryTerminalDisposition(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	tenantID := testUUIDv7(40)
	kinds := []kernel.ActionKind{
		kernel.ActionEmail, kernel.ActionWebhook, kernel.ActionAddTag, kernel.ActionChangePriority,
	}
	outcomes := []Outcome{OutcomeRetryScheduled, OutcomeDeadLettered, OutcomeFenceLost, OutcomeApplied}
	stub := &repositoryStub{}
	for index, kind := range kinds {
		stub.claims = append(stub.claims, testClaim(tenantID, testUUIDv7(byte(41+index*4)), kind, now))
		stub.results = append(stub.results, ExecuteResult{Outcome: outcomes[index]})
	}
	worker := testWorker(t, stub, now)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	summary, err := worker.RunOnce(ctx, Queue{TenantID: tenantID})
	if err != nil || summary != (Summary{
		Claimed: 4, Applied: 1, RetryScheduled: 1, DeadLettered: 1, FenceLost: 1,
	}) {
		t.Fatalf("unexpected terminal accounting: summary=%+v err=%v", summary, err)
	}
}

func TestNewRejectsTypedNilRepository(t *testing.T) {
	var stub *repositoryStub
	_, err := New(Options{
		Repository: stub, Identity: Identity{WorkerID: testUUIDv7(70), Purpose: WorkerPurpose},
		BatchSize: 10, LeaseDuration: time.Minute, OperationTimeout: 5 * time.Second,
		LeaseSafety: 5 * time.Second, Clock: time.Now,
	})
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("expected typed-nil rejection, got %v", err)
	}
}

func testWorker(t *testing.T, repository Repository, now time.Time) *Worker {
	t.Helper()
	worker, err := New(Options{
		Repository: repository,
		Identity:   Identity{WorkerID: testUUIDv7(90), Purpose: WorkerPurpose},
		BatchSize:  10, LeaseDuration: time.Minute, OperationTimeout: 5 * time.Second,
		LeaseSafety: 5 * time.Second, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	return worker
}

func testClaim(tenantID, occurrenceID uuid.UUID, kind kernel.ActionKind, now time.Time) Claim {
	return Claim{
		OccurrenceID: occurrenceID, TenantID: tenantID,
		SLAInstanceID: testUUIDv7(occurrenceID[15] + 1), MetricInstanceID: testUUIDv7(occurrenceID[15] + 2),
		TriggerDefinitionID: testUUIDv7(occurrenceID[15] + 3), ActionKind: kind,
		DeduplicationDigest: [32]byte{1}, Fence: 1, Attempt: 1,
		ScheduledAt: now.Add(-time.Second), ClaimedAt: now, LeaseExpiresAt: now.Add(time.Minute),
	}
}

func testUUIDv7(suffix byte) uuid.UUID {
	value := uuid.MustParse("01999b2f-1000-7000-8000-000000000000")
	value[15] = suffix
	return value
}
