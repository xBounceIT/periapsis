package slaengine

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/sla"
)

func TestRunOnceClaimsPlansAndFinalizesFencedMaterialization(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	job := workerJobFixture(t, now)
	repository := &workerRepositoryFake{jobs: []Job{job}}
	worker := mustWorker(t, repository, now)
	ctx := workerContext(t)
	repository.parentDeadline, _ = ctx.Deadline()
	summary, err := worker.RunOnce(ctx)
	if err != nil || summary != (RunSummary{Claimed: 1, Completed: 1}) {
		t.Fatalf("summary=%#v error=%v", summary, err)
	}
	if repository.finalizeCalls != 1 || repository.failCalls != 0 ||
		repository.finalized.Fence != job.Fence || repository.finalized.TenantID != job.TenantID ||
		repository.finalized.SLAInstanceID != job.SLAInstanceID ||
		repository.finalized.ExpectedAggregateVersion != job.AggregateVersion ||
		repository.finalized.Identity.WorkerID != worker.identity.WorkerID {
		t.Fatalf("finalize=%#v failCalls=%d", repository.finalized, repository.failCalls)
	}
	if !repository.claimDeadline.Before(repository.parentDeadline) ||
		!repository.finalizeDeadline.Before(repository.parentDeadline) {
		t.Fatalf("repository deadlines claim=%s finalize=%s parent=%s", repository.claimDeadline, repository.finalizeDeadline, repository.parentDeadline)
	}
	metrics := repository.finalized.Plan.Metrics()
	if len(metrics) != 1 || !metrics[0].Changed() || metrics[0].Instance().Consumed() != time.Hour ||
		metrics[0].Instance().Version() != job.Metrics[0].Instance.Version()+1 {
		t.Fatalf("finalized plan=%#v", repository.finalized.Plan)
	}
}

func TestRunOnceDeadLettersMalformedProjectionWithoutApplyingIt(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	job := workerJobFixture(t, now)
	job.Metrics[0].Instance = foreignWorkerInstance(t, now, job)
	repository := &workerRepositoryFake{jobs: []Job{job}}
	worker := mustWorker(t, repository, now)
	ctx := workerContext(t)
	repository.parentDeadline, _ = ctx.Deadline()
	summary, err := worker.RunOnce(ctx)
	if err != nil || summary != (RunSummary{Claimed: 1, DeadLettered: 1}) {
		t.Fatalf("summary=%#v error=%v", summary, err)
	}
	if repository.finalizeCalls != 0 || repository.failCalls != 1 ||
		!repository.failed.Permanent || repository.failed.Code != "invalid_projection" ||
		repository.failed.Fence != job.Fence {
		t.Fatalf("failure=%#v finalizeCalls=%d", repository.failed, repository.finalizeCalls)
	}
	if !repository.failDeadline.Before(repository.parentDeadline) {
		t.Fatalf("failure deadline=%s parent=%s", repository.failDeadline, repository.parentDeadline)
	}
}

func TestRunOnceDeadLettersLeaseProjectionThatIsNotExact(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	job := workerJobFixture(t, now)
	job.LeaseExpiresAt = job.LeaseExpiresAt.Add(time.Microsecond)
	repository := &workerRepositoryFake{jobs: []Job{job}}
	worker := mustWorker(t, repository, now)
	summary, err := worker.RunOnce(workerContext(t))
	if err != nil || summary != (RunSummary{Claimed: 1, DeadLettered: 1}) ||
		repository.finalizeCalls != 0 || repository.failCalls != 1 ||
		repository.failed.Code != "invalid_projection" || !repository.failed.Permanent {
		t.Fatalf("summary=%#v failure=%#v error=%v", summary, repository.failed, err)
	}
	exhausted := workerJobFixture(t, now)
	exhausted.AggregateVersion = uint64(math.MaxInt64 - 1)
	repository = &workerRepositoryFake{jobs: []Job{exhausted}}
	worker = mustWorker(t, repository, now)
	summary, err = worker.RunOnce(workerContext(t))
	if err != nil || summary != (RunSummary{Claimed: 1, DeadLettered: 1}) ||
		repository.finalizeCalls != 0 || repository.failCalls != 1 || repository.failed.Code != "invalid_projection" {
		t.Fatalf("exhausted aggregate summary=%#v failure=%#v error=%v", summary, repository.failed, err)
	}
}

func TestRunOnceLeavesAmbiguousFinalizeForFencedReclaim(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	job := workerJobFixture(t, now)
	repository := &workerRepositoryFake{jobs: []Job{job}, finalizeErr: errors.New("connection lost after commit")}
	worker := mustWorker(t, repository, now)
	summary, err := worker.RunOnce(workerContext(t))
	if !errors.Is(err, ErrUnavailable) || summary.Claimed != 1 || summary.Completed != 0 ||
		repository.finalizeCalls != 1 || repository.failCalls != 0 {
		t.Fatalf("summary=%#v finalize=%d fail=%d error=%v", summary, repository.finalizeCalls, repository.failCalls, err)
	}
}

func TestRunOnceSchedulesBoundedRetryAndNeverRetriesPermanentFailure(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	retryable := workerJobFixture(t, now)
	retryable.Attempt = 4
	repository := &workerRepositoryFake{}
	worker := mustWorker(t, repository, now)
	worker.config.RetryBaseDelay = 10 * time.Second
	worker.config.RetryMaximumDelay = 45 * time.Second

	outcome, err := worker.recordFailure(workerContext(t), retryable, now, "evaluation_timeout", false)
	if err != nil || outcome != outcomeRetryable ||
		repository.failed.Permanent || repository.failed.RetryAt == nil ||
		!repository.failed.RetryAt.Equal(now.Add(45*time.Second)) {
		t.Fatalf("retry outcome=%d failure=%#v error=%v", outcome, repository.failed, err)
	}

	permanent := workerJobFixture(t, now)
	repository = &workerRepositoryFake{}
	worker = mustWorker(t, repository, now)
	outcome, err = worker.recordFailure(workerContext(t), permanent, now, "invalid_projection", true)
	if err != nil || outcome != outcomeDeadLettered ||
		!repository.failed.Permanent || repository.failed.RetryAt != nil {
		t.Fatalf("permanent outcome=%d failure=%#v error=%v", outcome, repository.failed, err)
	}
}

func TestRunOnceRejectsClockRollbackBeforePersistence(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	job := workerJobFixture(t, now)
	repository := &workerRepositoryFake{jobs: []Job{job}}
	clockCalls := 0
	clock := func() time.Time {
		clockCalls++
		if clockCalls >= 3 {
			return now.Add(-time.Minute)
		}
		return now
	}
	worker, err := New(repository, Identity{WorkerID: workerUUID(1), Purpose: "sla-engine"}, Config{
		BatchSize: 10, LeaseDuration: 30 * time.Second, OperationTimeout: 5 * time.Second,
		RunTimeout: time.Minute, MaximumAttempts: 3, RetryBaseDelay: time.Second, RetryMaximumDelay: time.Minute,
	}, clock)
	if err != nil {
		t.Fatal(err)
	}
	summary, err := worker.RunOnce(workerContext(t))
	if !errors.Is(err, ErrUnavailable) || summary.Claimed != 1 ||
		repository.finalizeCalls != 0 || repository.failCalls != 0 {
		t.Fatalf("summary=%#v finalize=%d fail=%d error=%v", summary, repository.finalizeCalls, repository.failCalls, err)
	}
}

func TestRunOnceRejectsDuplicateClaimsAndCanceledOrUnboundedContext(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	job := workerJobFixture(t, now)
	repository := &workerRepositoryFake{jobs: []Job{job, job}}
	worker := mustWorker(t, repository, now)
	if _, err := worker.RunOnce(workerContext(t)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("duplicate claim error=%v", err)
	}
	if repository.finalizeCalls != 0 || repository.failCalls != 0 {
		t.Fatal("duplicate claims produced side effects")
	}
	distinctJob := job
	distinctJob.ID = workerEntity(24)
	repository.jobs = []Job{job, distinctJob}
	if _, err := worker.RunOnce(workerContext(t)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("duplicate aggregate claim error=%v", err)
	}
	if repository.finalizeCalls != 0 || repository.failCalls != 0 {
		t.Fatal("duplicate aggregate claims produced side effects")
	}
	if _, err := worker.RunOnce(context.Background()); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("unbounded context error=%v", err)
	}
	if _, err := worker.RunOnce(nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("nil context error=%v", err)
	}
	canceled, cancel := context.WithTimeout(context.Background(), time.Second)
	cancel()
	if _, err := worker.RunOnce(canceled); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("canceled context error=%v", err)
	}

	for _, rendered := range []string{fmt.Sprint(job), fmt.Sprintf("%#v", worker.identity), fmt.Sprint(*worker)} {
		if strings.Contains(rendered, job.ID.String()) || strings.Contains(rendered, job.ObjectID.String()) ||
			strings.Contains(rendered, worker.identity.WorkerID.String()) {
			t.Fatalf("worker formatter leaked identity: %q", rendered)
		}
	}
}

func TestUsableDeadlineAllowsOnlySubMicrosecondClockNormalization(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	maximum := time.Minute
	withinPrecision, cancelWithin := context.WithDeadline(
		context.Background(), now.Add(maximum).Add(999*time.Nanosecond),
	)
	defer cancelWithin()
	if !usableDeadline(withinPrecision, now, maximum) {
		t.Fatal("sub-microsecond normalized deadline was rejected")
	}
	outOfBounds, cancelOut := context.WithDeadline(
		context.Background(), now.Add(maximum).Add(time.Microsecond),
	)
	defer cancelOut()
	if usableDeadline(outOfBounds, now, maximum) {
		t.Fatal("full-microsecond deadline excess was accepted")
	}
}

func TestRepositoryBoundaryRequestsRedactIdentityLeaseAndPlan(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	job := workerJobFixture(t, now)
	job.Fence = 987654321012345
	identity := Identity{WorkerID: workerUUID(88), Purpose: "sla-engine"}
	finalize := FinalizeRequest{
		Identity: identity, JobID: job.ID, TenantID: job.TenantID, SLAInstanceID: job.SLAInstanceID,
		ExpectedAggregateVersion: job.AggregateVersion, Fence: job.Fence, CompletedAt: now,
	}
	failure := FailureRequest{
		Identity: identity, JobID: job.ID, TenantID: job.TenantID, Fence: job.Fence,
		Attempt: job.Attempt, Code: "repository_unavailable", FailedAt: now,
	}
	for _, value := range []any{job, finalize, failure} {
		for _, rendered := range []string{fmt.Sprintf("%+v", value), fmt.Sprintf("%#v", value)} {
			for _, secret := range []string{
				job.ID.String(), job.TenantID.String(), job.SLAInstanceID.String(), identity.WorkerID.String(),
				fmt.Sprint(job.Fence),
			} {
				if strings.Contains(rendered, secret) {
					t.Fatalf("repository request formatter leaked %q: %q", secret, rendered)
				}
			}
		}
	}
}

type workerRepositoryFake struct {
	jobs        []Job
	claimErr    error
	finalizeErr error
	failErr     error

	claimRequest     ClaimRequest
	finalized        FinalizeRequest
	failed           FailureRequest
	finalizeCalls    int
	failCalls        int
	parentDeadline   time.Time
	claimDeadline    time.Time
	finalizeDeadline time.Time
	failDeadline     time.Time
}

func (repository *workerRepositoryFake) Claim(ctx context.Context, request ClaimRequest) ([]Job, error) {
	repository.claimRequest = request
	repository.claimDeadline, _ = ctx.Deadline()
	return append([]Job(nil), repository.jobs...), repository.claimErr
}

func (repository *workerRepositoryFake) Finalize(ctx context.Context, request FinalizeRequest) error {
	repository.finalizeCalls++
	repository.finalized = request
	repository.finalizeDeadline, _ = ctx.Deadline()
	return repository.finalizeErr
}

func (repository *workerRepositoryFake) Fail(ctx context.Context, request FailureRequest) error {
	repository.failCalls++
	repository.failed = request
	repository.failDeadline, _ = ctx.Deadline()
	return repository.failErr
}

func mustWorker(t *testing.T, repository Repository, now time.Time) *Worker {
	t.Helper()
	worker, err := New(repository, Identity{WorkerID: workerUUID(1), Purpose: "sla-engine"}, Config{
		BatchSize: 10, LeaseDuration: 30 * time.Second, OperationTimeout: 5 * time.Second,
		RunTimeout: time.Minute, MaximumAttempts: 3, RetryBaseDelay: time.Second, RetryMaximumDelay: time.Minute,
	}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	return worker
}

func workerContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func workerJobFixture(t *testing.T, now time.Time) Job {
	t.Helper()
	tenantID := workerUUID(2)
	metric := workerMetric(t)
	policyID := workerEntity(3)
	instance, err := kernel.NewMetricInstance(kernel.MetricInstanceInput{
		ID: workerEntity(4), SLAInstanceID: workerEntity(8),
		TenantID: workerEntityFromUUID(tenantID), ObjectType: kernel.ObjectCase,
		ObjectID: workerEntity(5), PolicyID: policyID, PolicyVersion: 1,
		Definition: metric, CreatedAt: now.Add(-time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	started, changed, err := instance.ApplyEvent(instance.Version(), kernel.MetricEvent{
		ID: workerEntity(6), TenantID: instance.TenantID(), ObjectID: instance.ObjectID(),
		Key: metric.StartEvent(), OccurredAt: instance.CreatedAt(),
	}, nil)
	if err != nil || !changed {
		t.Fatalf("start changed=%t error=%v", changed, err)
	}
	return Job{
		ID: workerEntity(7), TenantID: tenantID, ObjectType: kernel.ObjectCase, ObjectID: instance.ObjectID(),
		SLAInstanceID: started.SLAInstanceID(), AggregateVersion: 1,
		Fence: 9, Attempt: 1, ObservedAt: now, LeaseExpiresAt: now.Add(30 * time.Second),
		Metrics: []kernel.MetricWork{{Instance: started}},
	}
}

func foreignWorkerInstance(t *testing.T, now time.Time, job Job) kernel.MetricInstance {
	t.Helper()
	metric := workerMetric(t)
	instance, err := kernel.NewMetricInstance(kernel.MetricInstanceInput{
		ID: workerEntity(20), SLAInstanceID: workerEntity(23), TenantID: workerEntity(21), ObjectType: job.ObjectType,
		ObjectID: job.ObjectID, PolicyID: workerEntity(22), PolicyVersion: 1,
		Definition: metric, CreatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return instance
}

func workerMetric(t *testing.T) kernel.MetricDefinition {
	t.Helper()
	metric, err := kernel.NewMetricDefinition(kernel.MetricDefinitionInput{
		ID: workerEntity(10), Key: workerKey("resolution"), Label: "Resolution",
		Duration: 4 * time.Hour, Clock: kernel.ClockElapsed,
		StartEvent: workerKey("ticket.created"), CompletionEvent: workerKey("ticket.resolved"),
		ResetPolicy: kernel.ResetIgnore, Warning: kernel.WarningThreshold{Kind: kernel.WarningNone},
		DisplayFormat: "duration", APIVisible: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return metric
}

func workerUUID(sequence uint16) uuid.UUID {
	value := [16]byte{0x01, 0x9d, 0, 0, 0, byte(sequence >> 8), 0x70, byte(sequence)}
	value[8] = 0x80
	return uuid.UUID(value)
}

func workerEntity(sequence uint16) kernel.EntityID {
	return workerEntityFromUUID(workerUUID(sequence))
}

func workerEntityFromUUID(value uuid.UUID) kernel.EntityID {
	id, err := kernel.ParseEntityID(value.String())
	if err != nil {
		panic(err)
	}
	return id
}

func workerKey(value string) kernel.Key {
	key, err := kernel.NewKey(value)
	if err != nil {
		panic(err)
	}
	return key
}
