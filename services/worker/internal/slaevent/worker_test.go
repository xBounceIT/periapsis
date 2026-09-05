package slaevent

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/sla"
)

func TestWorkerPlansAndCommitsFrozenInitialAssignment(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	job := assignmentJob(t, now, true)
	repository := &eventRepositoryStub{jobs: []Job{job}}
	worker := newEventWorker(t, repository, now)
	ctx, cancel := context.WithDeadline(context.Background(), now.Add(20*time.Second))
	defer cancel()
	summary, err := worker.RunOnce(ctx)
	if err != nil || summary.Claimed != 1 || summary.Applied != 1 || repository.commitCalls != 1 ||
		repository.failureCalls != 0 {
		t.Fatalf("summary=%#v commit=%d failures=%d error=%v", summary, repository.commitCalls, repository.failureCalls, err)
	}
	assignment := repository.commit.Plan.Assignment()
	engine := repository.commit.Plan.Engine()
	if assignment == nil || !assignment.Matched() || engine == nil ||
		repository.commit.Plan.ExpectedAggregateVersion() != 0 ||
		repository.commit.Plan.NextAggregateVersion() != 1 ||
		assignment.AssignmentEventID() != job.SourceEventID {
		t.Fatalf("commit plan=%#v", repository.commit.Plan)
	}
}

func TestWorkerCommitsDurableNoPolicyDecision(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	job := assignmentJob(t, now, false)
	repository := &eventRepositoryStub{jobs: []Job{job}}
	worker := newEventWorker(t, repository, now)
	ctx, cancel := context.WithDeadline(context.Background(), now.Add(20*time.Second))
	defer cancel()
	summary, err := worker.RunOnce(ctx)
	assignment := repository.commit.Plan.Assignment()
	if err != nil || summary.Applied != 1 || assignment == nil || assignment.Matched() ||
		repository.commit.Plan.Engine() != nil || repository.commit.Plan.NextAggregateVersion() != 0 {
		t.Fatalf("summary=%#v plan=%#v error=%v", summary, repository.commit.Plan, err)
	}
}

func TestWorkerKeepsLaterEventsPinnedToNoPolicy(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	job := assignmentJob(t, now, false)
	job.Sequence = 2
	job.Event.Key = eventKey("ticket.triaged")
	job.State = kernel.ObjectEventState{Mode: kernel.ObjectEventStateNoPolicy}
	repository := &eventRepositoryStub{jobs: []Job{job}}
	worker := newEventWorker(t, repository, now)
	ctx, cancel := context.WithDeadline(context.Background(), now.Add(20*time.Second))
	defer cancel()
	summary, err := worker.RunOnce(ctx)
	if err != nil || summary.Applied != 1 || repository.commitCalls != 1 ||
		!repository.commit.Plan.PinnedNoPolicy() || repository.commit.Plan.Assignment() != nil ||
		repository.commit.Plan.Engine() != nil {
		t.Fatalf("summary=%#v plan=%#v error=%v", summary, repository.commit.Plan, err)
	}
}

func TestWorkerDeadLettersInvalidProjectionUnderFence(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	job := assignmentJob(t, now, true)
	job.InvalidProjection = true
	repository := &eventRepositoryStub{jobs: []Job{job}}
	worker := newEventWorker(t, repository, now)
	ctx, cancel := context.WithDeadline(context.Background(), now.Add(20*time.Second))
	defer cancel()
	summary, err := worker.RunOnce(ctx)
	if err != nil || summary.DeadLettered != 1 || repository.commitCalls != 0 ||
		repository.failureCalls != 1 || !repository.failure.Permanent ||
		repository.failure.Code != "invalid_projection" || repository.failure.Fence != job.Fence {
		t.Fatalf("summary=%#v failure=%#v error=%v", summary, repository.failure, err)
	}
}

func TestWorkerDoesNotWriteFailureAfterUncertainCommit(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	repository := &eventRepositoryStub{jobs: []Job{assignmentJob(t, now, true)}, commitErr: ErrUnavailable}
	worker := newEventWorker(t, repository, now)
	ctx, cancel := context.WithDeadline(context.Background(), now.Add(20*time.Second))
	defer cancel()
	if _, err := worker.RunOnce(ctx); !errors.Is(err, ErrUnavailable) || repository.failureCalls != 0 {
		t.Fatalf("error=%v failure calls=%d", err, repository.failureCalls)
	}
}

func TestWorkerRejectsConcurrentClaimsForSameObject(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	first := assignmentJob(t, now, true)
	second := first
	second.ID = eventEntity(41)
	second.SourceEventID = eventEntity(42)
	second.Event.ID = second.SourceEventID
	second.Sequence = 2
	repository := &eventRepositoryStub{jobs: []Job{first, second}}
	worker := newEventWorker(t, repository, now)
	ctx, cancel := context.WithDeadline(context.Background(), now.Add(20*time.Second))
	defer cancel()
	if _, err := worker.RunOnce(ctx); !errors.Is(err, ErrUnavailable) || repository.commitCalls != 0 {
		t.Fatalf("error=%v commits=%d", err, repository.commitCalls)
	}
}

type eventRepositoryStub struct {
	jobs         []Job
	commit       CommitRequest
	commitCalls  int
	commitErr    error
	failure      FailureRequest
	failureCalls int
	failureErr   error
}

func (repository *eventRepositoryStub) Ready(context.Context) error { return nil }

func (repository *eventRepositoryStub) Claim(context.Context, ClaimRequest) ([]Job, error) {
	return append([]Job(nil), repository.jobs...), nil
}

func (repository *eventRepositoryStub) Commit(_ context.Context, request CommitRequest) (CommitResult, error) {
	repository.commitCalls++
	repository.commit = request
	if repository.commitErr != nil {
		return CommitResult{}, repository.commitErr
	}
	assignment := request.Plan.Assignment()
	if assignment == nil {
		if request.Plan.PinnedNoPolicy() {
			return CommitResult{Outcome: OutcomeNoPolicy}, nil
		}
		return CommitResult{Outcome: OutcomeUpdated, SLAInstanceID: request.Job.SLAInstanceID,
			AggregateVersion: request.Plan.NextAggregateVersion()}, nil
	}
	if !assignment.Matched() {
		return CommitResult{Outcome: OutcomeNoPolicy}, nil
	}
	value := assignment.SLAInstanceID()
	return CommitResult{Outcome: OutcomeAssigned, SLAInstanceID: &value, AggregateVersion: 1}, nil
}

func (repository *eventRepositoryStub) Fail(_ context.Context, request FailureRequest) error {
	repository.failureCalls++
	repository.failure = request
	return repository.failureErr
}

func (repository *eventRepositoryStub) ReadQueueMetrics(context.Context) (QueueMetrics, error) {
	return QueueMetrics{}, nil
}

func newEventWorker(t *testing.T, repository Repository, now time.Time) *Worker {
	t.Helper()
	worker, err := New(repository, Identity{WorkerID: eventUUID(1), Purpose: WorkerPurpose}, Config{
		BatchSize: 10, LeaseDuration: 30 * time.Second, OperationTimeout: time.Second,
		RunTimeout: 20 * time.Second, MaximumAttempts: 3,
		RetryBaseDelay: time.Second, RetryMaximumDelay: time.Minute,
	}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	return worker
}

func assignmentJob(t *testing.T, claimedAt time.Time, matched bool) Job {
	t.Helper()
	occurredAt := claimedAt.Add(-time.Minute)
	tenantID := eventUUID(2)
	tenantEntity := eventEntityFromUUID(tenantID)
	objectID := eventEntity(3)
	snapshot, err := kernel.NewFactSnapshot(kernel.FactSnapshotInput{
		TenantID: tenantEntity, ObjectType: kernel.ObjectCase,
		EvaluatedAt: occurredAt, Timezone: "UTC",
	})
	if err != nil {
		t.Fatal(err)
	}
	policies := []kernel.Policy(nil)
	if matched {
		policies = []kernel.Policy{eventPolicy(t, tenantEntity, occurredAt)}
	}
	sourceID := eventEntity(4)
	key, _ := kernel.NewKey("ticket.created")
	return Job{
		ID: eventEntity(5), TenantID: tenantID, ObjectType: kernel.ObjectCase,
		ObjectID: objectID, Sequence: 1, SourceEventID: sourceID,
		SourceDigest: [32]byte{1}, Event: kernel.MetricEvent{
			ID: sourceID, TenantID: tenantEntity, ObjectID: objectID,
			Key: key, OccurredAt: occurredAt,
		},
		State: kernel.ObjectEventState{
			Mode: kernel.ObjectEventStateUnassigned, Snapshot: &snapshot, Policies: policies,
		},
		Fence: 7, Attempt: 1, ClaimedAt: claimedAt,
		LeaseExpiresAt: claimedAt.Add(30 * time.Second),
	}
}

func eventPolicy(t *testing.T, tenantID kernel.EntityID, effectiveAt time.Time) kernel.Policy {
	t.Helper()
	metric, err := kernel.NewMetricDefinition(kernel.MetricDefinitionInput{
		ID: eventEntity(10), Key: eventKey("resolution"), Label: "Resolution",
		Duration: 8 * time.Hour, Clock: kernel.ClockElapsed,
		StartEvent: eventKey("ticket.created"), CompletionEvent: eventKey("ticket.resolved"),
		ResetPolicy: kernel.ResetIgnore, Warning: kernel.WarningThreshold{Kind: kernel.WarningNone},
		DisplayFormat: "duration", APIVisible: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	rule, err := kernel.NewRule(&kernel.RuleInput{Kind: kernel.RuleAll})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := kernel.NewPolicy(kernel.PolicyInput{
		ID: eventEntity(11), TenantID: tenantID, Key: eventKey("default_policy"),
		Name: "Default", Version: 1, Priority: 10,
		ObjectTypes: []kernel.ObjectType{kernel.ObjectCase}, MatchRule: rule,
		Metrics: []kernel.MetricDefinition{metric}, EffectiveFrom: effectiveAt.Add(-time.Hour),
		Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func eventUUID(sequence uint16) uuid.UUID {
	value := [16]byte{0x01, 0x9d, 0, 0, 0, byte(sequence >> 8), 0x70, byte(sequence)}
	value[8] = 0x80
	return uuid.UUID(value)
}

func eventEntity(sequence uint16) kernel.EntityID { return eventEntityFromUUID(eventUUID(sequence)) }

func eventEntityFromUUID(value uuid.UUID) kernel.EntityID {
	id, err := kernel.ParseEntityID(value.String())
	if err != nil {
		panic(err)
	}
	return id
}

func eventKey(value string) kernel.Key {
	key, err := kernel.NewKey(value)
	if err != nil {
		panic(err)
	}
	return key
}
