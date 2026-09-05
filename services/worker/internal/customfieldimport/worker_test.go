package customfieldimport

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/customfields"
)

var workerTestNow = time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)

func TestRunOnceClaimsAndCommitsEveryZeroCellRow(t *testing.T) {
	job, queue := workerTestJob(t, 2)
	repository := &workerTestRepository{record: Record{Job: job}}
	worker := workerTestWorker(t, repository, workerTestNow.Add(time.Second))

	result, err := worker.RunOnce(context.Background(), queue)
	if err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if !result.DidWork || result.State != kernel.ImportJobCompleted || result.Rows != 2 {
		t.Fatalf("RunOnce() = %#v", result)
	}
	if repository.transitionCalls != 1 || repository.rowCalls != 2 || len(repository.decisions) != 2 {
		t.Fatalf(
			"calls transition=%d row=%d decisions=%d",
			repository.transitionCalls, repository.rowCalls, len(repository.decisions),
		)
	}
	for _, decision := range repository.decisions {
		if decision.Result.Outcome() != kernel.ImportRowNoChange ||
			decision.Result.ResultingVersion() != 7 || len(decision.Patches) != 0 {
			t.Fatalf("decision = %#v", decision)
		}
	}
	if progress := repository.record.Job.Progress(); progress.NoChange != 2 || !progress.Complete() {
		t.Fatalf("progress = %#v", progress)
	}
}

func TestRunOnceCompletesActiveAndAbandonedCancellation(t *testing.T) {
	for _, test := range []struct {
		name       string
		fence      kernel.EntityID
		lease      time.Time
		workerTime time.Time
	}{
		{
			name: "owned active lease", fence: workerTestEntity(t, 8),
			lease: workerTestNow.Add(2 * time.Minute), workerTime: workerTestNow.Add(3 * time.Second),
		},
		{
			name: "abandoned foreign lease", fence: workerTestEntity(t, 9),
			lease: workerTestNow.Add(2 * time.Second), workerTime: workerTestNow.Add(3 * time.Second),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			job, queue := workerTestJob(t, 3)
			claimed, err := kernel.ClaimImportJob(
				job, job.Revision(), test.fence, workerTestNow.Add(time.Second), test.lease,
			)
			if err != nil {
				t.Fatal(err)
			}
			cancelled, err := kernel.RequestImportCancellation(
				claimed, claimed.Revision(), workerTestNow.Add(1500*time.Millisecond),
			)
			if err != nil {
				t.Fatal(err)
			}
			repository := &workerTestRepository{record: Record{Job: cancelled}}
			worker := workerTestWorker(t, repository, test.workerTime)

			result, runErr := worker.RunOnce(context.Background(), queue)
			if runErr != nil || !result.DidWork || result.State != kernel.ImportJobCancelled || result.Rows != 0 {
				t.Fatalf("RunOnce() = (%#v, %v)", result, runErr)
			}
			if repository.transitionCalls != 1 || repository.rowCalls != 0 ||
				repository.record.Job.Progress().Cancelled != 3 {
				t.Fatalf(
					"calls transition=%d row=%d progress=%#v",
					repository.transitionCalls, repository.rowCalls, repository.record.Job.Progress(),
				)
			}
		})
	}
}

func TestRunOnceReclaimsExpiredLeaseWithANewFence(t *testing.T) {
	job, queue := workerTestJob(t, 1)
	foreignFence := workerTestEntity(t, 9)
	claimed, err := kernel.ClaimImportJob(
		job, job.Revision(), foreignFence, workerTestNow.Add(time.Second), workerTestNow.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	repository := &workerTestRepository{record: Record{Job: claimed}}
	worker := workerTestWorker(t, repository, workerTestNow.Add(2*time.Minute))

	result, err := worker.RunOnce(context.Background(), queue)
	if err != nil || !result.DidWork || result.State != kernel.ImportJobCompleted || result.Rows != 1 {
		t.Fatalf("RunOnce() = (%#v, %v)", result, err)
	}
	if repository.transitionCalls != 1 || repository.rowCalls != 1 || repository.record.Job.Attempts() != 2 {
		t.Fatalf(
			"calls transition=%d row=%d attempts=%d",
			repository.transitionCalls, repository.rowCalls, repository.record.Job.Attempts(),
		)
	}
	if fence := repository.claimFence; fence == nil || *fence == foreignFence {
		t.Fatalf("reclaim fence = %#v", fence)
	}
}

func TestRunOnceTurnsLiveAuthorityRevocationIntoTerminalEvidence(t *testing.T) {
	job, queue := workerTestJob(t, 2)
	repository := &workerTestRepository{
		record:     Record{Job: job},
		processErr: ErrAuthorizationRevoked,
	}
	worker := workerTestWorker(t, repository, workerTestNow.Add(time.Second))

	result, err := worker.RunOnce(context.Background(), queue)
	if err != nil || !result.DidWork || result.State != kernel.ImportJobAuthorizationRevoked || result.Rows != 2 {
		t.Fatalf("RunOnce() = (%#v, %v)", result, err)
	}
	if repository.transitionCalls != 2 || repository.rowCalls != 1 ||
		repository.record.Job.Progress().AuthorizationRevoked != 2 {
		t.Fatalf(
			"calls transition=%d row=%d progress=%#v",
			repository.transitionCalls, repository.rowCalls, repository.record.Job.Progress(),
		)
	}
}

func TestRunOnceDoesNotStealAnUnexpiredForeignFence(t *testing.T) {
	job, queue := workerTestJob(t, 1)
	claimed, err := kernel.ClaimImportJob(
		job, job.Revision(), workerTestEntity(t, 9),
		workerTestNow.Add(time.Second), workerTestNow.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	repository := &workerTestRepository{record: Record{Job: claimed}}
	worker := workerTestWorker(t, repository, workerTestNow.Add(2*time.Second))

	result, err := worker.RunOnce(context.Background(), queue)
	if err != nil || result.DidWork || result.State != kernel.ImportJobRunning || result.Rows != 0 {
		t.Fatalf("RunOnce() = (%#v, %v)", result, err)
	}
	if repository.transitionCalls != 0 || repository.rowCalls != 0 {
		t.Fatalf("calls transition=%d row=%d", repository.transitionCalls, repository.rowCalls)
	}
}

type workerTestRepository struct {
	record          Record
	processErr      error
	transitionCalls int
	rowCalls        int
	decisions       []RowDecision
	claimFence      *kernel.EntityID
}

func (repository *workerTestRepository) Ready(context.Context, Identity) error { return nil }

func (repository *workerTestRepository) ListQueues(
	context.Context,
	Identity,
	time.Time,
	int,
) ([]Queue, error) {
	manifest := repository.record.Job.Manifest()
	return []Queue{{
		TenantID: uuid.UUID(manifest.Tenant().Bytes()),
		JobID:    uuid.UUID(manifest.ID().Bytes()),
	}}, nil
}

func (repository *workerTestRepository) Load(
	_ context.Context,
	_ Identity,
	_ Queue,
) (Record, error) {
	return repository.record, nil
}

func (repository *workerTestRepository) CommitTransition(
	_ context.Context,
	_ Identity,
	_ Queue,
	current kernel.ImportJob,
	next kernel.ImportJob,
) (Record, error) {
	repository.transitionCalls++
	if current.Revision() != repository.record.Job.Revision() {
		return Record{}, ErrConflict
	}
	if next.State() == kernel.ImportJobRunning {
		repository.claimFence = next.Fence()
	}
	repository.record = Record{Job: next}
	return repository.record, nil
}

func (repository *workerTestRepository) ProcessRow(
	_ context.Context,
	_ Identity,
	_ Queue,
	current kernel.ImportJob,
	row kernel.ImportRow,
	_ kernel.EntityID,
	_ time.Time,
	decide RowDecider,
) (Record, error) {
	repository.rowCalls++
	if repository.processErr != nil {
		return Record{}, repository.processErr
	}
	if current.Revision() != repository.record.Job.Revision() {
		return Record{}, ErrConflict
	}
	decision, err := decide(RowSnapshot{
		FoundAndVisible: true,
		Allowed:         true,
		CurrentVersion:  row.ExpectedVersion(),
		Existing:        []kernel.FieldValue{},
	})
	if err != nil {
		return Record{}, err
	}
	repository.decisions = append(repository.decisions, decision)
	repository.record = Record{Job: decision.Next}
	return repository.record, nil
}

func workerTestWorker(t *testing.T, repository Repository, now time.Time) *Worker {
	t.Helper()
	worker, err := New(Options{
		Repository: repository,
		Identity: Identity{
			ServiceAccountID: uuid.UUID(workerTestEntity(t, 7).Bytes()),
			WorkerID:         uuid.UUID(workerTestEntity(t, 8).Bytes()),
		},
		BatchSize: 10, LeaseDuration: time.Minute, LeaseSafety: 10 * time.Second,
		Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return worker
}

func workerTestJob(t *testing.T, rowCount int) (kernel.ImportJob, Queue) {
	t.Helper()
	rows := make([]kernel.ImportRowInput, rowCount)
	for index := range rows {
		rows[index] = kernel.ImportRowInput{
			Sequence: uint32(index + 1), Target: workerTestEntity(t, byte(20+index)),
			ExpectedVersion: 7, Fields: []kernel.FieldInput{},
		}
	}
	manifest, err := kernel.NewImportManifest(kernel.ImportManifestInput{
		ID: workerTestEntity(t, 1), Tenant: workerTestEntity(t, 2),
		Requester: workerTestEntity(t, 3), OwnerMembership: workerTestEntity(t, 4),
		ObjectType: kernel.ObjectAlert, Mode: kernel.ImportCommit,
		Definitions: []kernel.Definition{}, Rows: rows,
		ProjectionVersion: kernel.ImportProjectionVersion,
		MaximumAttempts:   kernel.ImportMaximumAttempts,
	})
	if err != nil {
		t.Fatalf("NewImportManifest() error = %v", err)
	}
	job, err := kernel.NewImportJob(manifest, workerTestNow, workerTestNow.Add(time.Hour))
	if err != nil {
		t.Fatalf("NewImportJob() error = %v", err)
	}
	return job, Queue{
		TenantID: uuid.UUID(manifest.Tenant().Bytes()),
		JobID:    uuid.UUID(manifest.ID().Bytes()),
	}
}

func workerTestEntity(t *testing.T, suffix byte) kernel.EntityID {
	t.Helper()
	var raw [16]byte
	raw[0], raw[1], raw[6], raw[8], raw[15] = 1, 0xa0, 0x70, 0x80, suffix
	identifier, err := kernel.NewEntityID(raw)
	if err != nil {
		t.Fatalf("NewEntityID() error = %v", err)
	}
	return identifier
}

var _ Repository = (*workerTestRepository)(nil)
