package ticketexport

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

func TestReconcilerPurgesAndFinalizesAnExactClaim(t *testing.T) {
	fixture := newReconcileFixture(t)
	repository := &reconcileRepositoryStub{claims: []ReconcileClaim{fixture.claim}}
	repository.finalize = func(request ReconcileFinalizeRequest) (ReconcileFinalizeResult, error) {
		if request.Identity != fixture.options.Identity || request.Claim != fixture.claim ||
			!request.PurgedAt.Equal(fixture.now) {
			t.Fatalf("Finalize request = %#v", request)
		}
		return ReconcileFinalizeResult{
			Disposition:            ReconcileFinalizeApplied,
			CurrentCleanupRevision: fixture.claim.CleanupRevision + 1,
			ArtifactID:             fixture.claim.Artifact.ArtifactID,
			Reason:                 fixture.claim.Reason,
			CleanupFence:           fixture.claim.CleanupFence,
		}, nil
	}
	artifacts := &reconcileArtifactStub{}
	fixture.options.Repository = repository
	fixture.options.Artifacts = artifacts
	worker := newTestReconciler(t, fixture.options)

	summary, err := worker.RunOnce(context.Background(), fixture.queue)
	if err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if summary != (ReconcileSummary{Claimed: 1, Purged: 1}) {
		t.Fatalf("RunOnce() summary = %#v", summary)
	}
	if len(artifacts.requests) != 1 || artifacts.requests[0] != fixture.claim.Artifact ||
		len(repository.finalizeRequests) != 1 || len(repository.failureRequests) != 0 {
		t.Fatalf(
			"effects = purge:%#v finalize:%#v failure:%#v",
			artifacts.requests, repository.finalizeRequests, repository.failureRequests,
		)
	}
}

func TestReconcilerValidatesTheWholeBatchBeforeAnyDelete(t *testing.T) {
	fixture := newReconcileFixture(t)
	duplicate := fixture.claim
	duplicate.CleanupFence = sha256.Sum256([]byte("different fence"))
	repository := &reconcileRepositoryStub{claims: []ReconcileClaim{fixture.claim, duplicate}}
	artifacts := &reconcileArtifactStub{}
	fixture.options.Repository = repository
	fixture.options.Artifacts = artifacts
	worker := newTestReconciler(t, fixture.options)

	summary, err := worker.RunOnce(context.Background(), fixture.queue)
	if !errors.Is(err, ErrInvalidProjection) || summary.Claimed != 2 {
		t.Fatalf("RunOnce() = (%#v, %v)", summary, err)
	}
	if len(artifacts.requests) != 0 || len(repository.finalizeRequests) != 0 ||
		len(repository.failureRequests) != 0 {
		t.Fatal("invalid batch caused an external effect")
	}
}

func TestReconcilerSchedulesStorageRetryAndDeadLettersManifestConflict(t *testing.T) {
	for _, test := range []struct {
		name        string
		artifactErr error
		disposition ReconcileFailureDisposition
		want        ReconcileSummary
		wantCode    ReconcileFailureCode
		wantRetry   bool
	}{
		{
			name: "transient storage", artifactErr: ErrUnavailable,
			disposition: ReconcileFailureRetryScheduled,
			want:        ReconcileSummary{Claimed: 1, RetryScheduled: 1},
			wantCode:    ReconcileFailureStorageUnavailable, wantRetry: true,
		},
		{
			name: "manifest conflict", artifactErr: ErrArtifactConflict,
			disposition: ReconcileFailureDeadLettered,
			want:        ReconcileSummary{Claimed: 1, DeadLettered: 1},
			wantCode:    ReconcileFailureObjectConflict,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newReconcileFixture(t)
			repository := &reconcileRepositoryStub{claims: []ReconcileClaim{fixture.claim}}
			repository.failure = func(request ReconcileFailureRequest) (ReconcileFailureResult, error) {
				if request.Code != test.wantCode || request.RetryAt.IsZero() == test.wantRetry ||
					request.Identity != fixture.options.Identity || request.Claim != fixture.claim {
					t.Fatalf("Failure request = %#v", request)
				}
				return ReconcileFailureResult{
					Disposition:            test.disposition,
					CurrentCleanupRevision: fixture.claim.CleanupRevision + 1,
					Code:                   request.Code,
					RetryAt:                request.RetryAt,
					ArtifactID:             fixture.claim.Artifact.ArtifactID,
					Reason:                 fixture.claim.Reason,
					CleanupFence:           fixture.claim.CleanupFence,
				}, nil
			}
			fixture.options.Repository = repository
			fixture.options.Artifacts = &reconcileArtifactStub{err: test.artifactErr}
			worker := newTestReconciler(t, fixture.options)

			summary, err := worker.RunOnce(context.Background(), fixture.queue)
			if err != nil || summary != test.want {
				t.Fatalf("RunOnce() = (%#v, %v)", summary, err)
			}
			if len(repository.failureRequests) != 1 || len(repository.finalizeRequests) != 0 {
				t.Fatalf("transition calls = failure:%d finalize:%d", len(repository.failureRequests), len(repository.finalizeRequests))
			}
		})
	}
}

func TestReconcilerTreatsAmbiguousFinalizeAsPendingRatherThanDeletingAnotherObject(t *testing.T) {
	fixture := newReconcileFixture(t)
	repository := &reconcileRepositoryStub{claims: []ReconcileClaim{fixture.claim}}
	repository.finalize = func(ReconcileFinalizeRequest) (ReconcileFinalizeResult, error) {
		return ReconcileFinalizeResult{}, errors.New("customer object detail")
	}
	artifacts := &reconcileArtifactStub{}
	fixture.options.Repository = repository
	fixture.options.Artifacts = artifacts
	worker := newTestReconciler(t, fixture.options)

	summary, err := worker.RunOnce(context.Background(), fixture.queue)
	if !errors.Is(err, ErrTransitionOutcomeUnknown) || summary.Claimed != 1 || summary.Purged != 0 {
		t.Fatalf("RunOnce() = (%#v, %v)", summary, err)
	}
	if len(artifacts.requests) != 1 || len(repository.failureRequests) != 0 {
		t.Fatal("ambiguous finalization was incorrectly converted to a storage failure")
	}
}

func TestReconcilerConfigurationAndDiagnosticsFailClosed(t *testing.T) {
	fixture := newReconcileFixture(t)
	fixture.options.OperationTimeout = fixture.options.LeaseDuration
	if _, err := NewReconciler(fixture.options); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("NewReconciler() error = %v", err)
	}
	fixture = newReconcileFixture(t)
	diagnostic := fmt.Sprintf("%s %#v %s %#v", fixture.options, fixture.options, fixture.claim, fixture.claim)
	for _, secret := range []string{
		fixture.claim.Artifact.TenantID.String(), fixture.claim.Artifact.JobID.String(),
		fixture.claim.Artifact.ArtifactID.String(), fmt.Sprintf("%x", fixture.claim.CleanupFence),
	} {
		if strings.Contains(diagnostic, secret) {
			t.Fatalf("diagnostic leaked %q: %s", secret, diagnostic)
		}
	}
}

type reconcileFixture struct {
	now     time.Time
	queue   Queue
	claim   ReconcileClaim
	options ReconcileOptions
}

func newReconcileFixture(t *testing.T) reconcileFixture {
	t.Helper()
	now := time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC)
	queue := Queue{
		TenantID: testEntityID(t, 201),
		Kind:     kernel.AggregateAlert,
		Audience: kernel.TicketExportAudienceOperator,
	}
	claim := ReconcileClaim{
		Artifact: ReconcileArtifact{
			TenantID:          queue.TenantID,
			JobID:             testEntityID(t, 202),
			ArtifactID:        testEntityID(t, 203),
			Kind:              queue.Kind,
			Audience:          queue.Audience,
			ObjectRevision:    3,
			ObjectAttempt:     1,
			ProjectionVersion: kernel.TicketExportProjectionVersion,
			Digest:            sha256.Sum256([]byte("artifact")),
			Rows:              1,
			Bytes:             8,
		},
		Reason:          ReconcileExpired,
		JobRevision:     4,
		CleanupRevision: 2,
		CleanupAttempt:  1,
		CleanupFence:    sha256.Sum256([]byte("cleanup fence")),
		EligibleAt:      now.Add(-time.Minute),
		ClaimedAt:       now,
		LeaseExpiresAt:  now.Add(2 * time.Minute),
	}
	return reconcileFixture{
		now: now, queue: queue, claim: claim,
		options: ReconcileOptions{
			Repository: &reconcileRepositoryStub{}, Artifacts: &reconcileArtifactStub{},
			Identity: ReconcileIdentity{
				ServiceAccountID: testEntityID(t, 204),
				WorkerID:         testEntityID(t, 205),
				Purpose:          ReconcileWorkerPurpose,
			},
			BatchSize: 10, MaximumAttempts: 10, LeaseDuration: 2 * time.Minute,
			OperationTimeout: 5 * time.Second, LeaseSafety: 15 * time.Second,
			RetryBase: 15 * time.Second, RetryMaximum: 15 * time.Minute,
			Clock: func() time.Time { return now },
		},
	}
}

func newTestReconciler(t *testing.T, options ReconcileOptions) *Reconciler {
	t.Helper()
	worker, err := NewReconciler(options)
	if err != nil {
		t.Fatalf("NewReconciler() error = %v", err)
	}
	return worker
}

type reconcileRepositoryStub struct {
	claims           []ReconcileClaim
	claimErr         error
	finalize         func(ReconcileFinalizeRequest) (ReconcileFinalizeResult, error)
	failure          func(ReconcileFailureRequest) (ReconcileFailureResult, error)
	finalizeRequests []ReconcileFinalizeRequest
	failureRequests  []ReconcileFailureRequest
}

func (stub *reconcileRepositoryStub) ClaimArtifactReconciliation(
	_ context.Context,
	_ ReconcileClaimRequest,
) ([]ReconcileClaim, error) {
	return append([]ReconcileClaim(nil), stub.claims...), stub.claimErr
}

func (stub *reconcileRepositoryStub) FinalizeArtifactReconciliation(
	_ context.Context,
	request ReconcileFinalizeRequest,
) (ReconcileFinalizeResult, error) {
	stub.finalizeRequests = append(stub.finalizeRequests, request)
	if stub.finalize != nil {
		return stub.finalize(request)
	}
	return ReconcileFinalizeResult{}, nil
}

func (stub *reconcileRepositoryStub) ReportArtifactReconciliationFailure(
	_ context.Context,
	request ReconcileFailureRequest,
) (ReconcileFailureResult, error) {
	stub.failureRequests = append(stub.failureRequests, request)
	if stub.failure != nil {
		return stub.failure(request)
	}
	return ReconcileFailureResult{}, nil
}

type reconcileArtifactStub struct {
	requests []ReconcileArtifact
	err      error
}

func (stub *reconcileArtifactStub) PurgeArtifact(
	_ context.Context,
	artifact ReconcileArtifact,
) error {
	stub.requests = append(stub.requests, artifact)
	return stub.err
}
