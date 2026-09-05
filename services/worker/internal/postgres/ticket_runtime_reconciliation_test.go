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
	"github.com/periapsis-im/periapsis/services/worker/internal/ticketexport"
)

func TestTicketRuntimeReconciliationAdapterPreservesExactClaimAndFence(t *testing.T) {
	fixture := newTicketRuntimeReconcileFixture(t)
	document := ticketRuntimeReconcileClaimResponse(t, fixture.claim)
	querier := &ticketRuntimeTestQuerier{rows: []pgx.Row{ticketRuntimeJSONRow(string(document))}}
	repository := NewTicketRuntimeRepository(querier)

	claims, err := repository.ClaimArtifactReconciliation(context.Background(), ticketexport.ReconcileClaimRequest{
		Identity: fixture.identity,
		Queue: ticketexport.Queue{
			TenantID: fixture.claim.Artifact.TenantID, Kind: fixture.claim.Artifact.Kind,
			Audience: fixture.claim.Artifact.Audience,
		},
		Now: fixture.claim.ClaimedAt, LeaseDuration: time.Minute, Limit: 2,
	})
	if err != nil || len(claims) != 1 || claims[0] != fixture.claim {
		t.Fatalf("ClaimArtifactReconciliation() = (%#v, %v)", claims, err)
	}
	if len(querier.queries) != 1 || querier.queries[0] != ticketExportReconcileClaimQuery ||
		len(querier.args[0]) != 1 {
		t.Fatalf("claim query = %#v / %#v", querier.queries, querier.args)
	}
	var request struct {
		SchemaVersion int                         `json:"schemaVersion"`
		Identity      ticketRuntimeIdentityWireV1 `json:"identity"`
		TenantID      string                      `json:"tenantId"`
		Kind          string                      `json:"kind"`
		Audience      string                      `json:"audience"`
		Now           time.Time                   `json:"now"`
		LeaseMicros   int64                       `json:"leaseMicroseconds"`
		Limit         int                         `json:"limit"`
	}
	if err := json.Unmarshal(querier.args[0][0].([]byte), &request); err != nil ||
		request.SchemaVersion != 1 || request.Identity.Purpose != ticketexport.ReconcileWorkerPurpose ||
		request.TenantID != fixture.claim.Artifact.TenantID.String() || request.Kind != "alert" ||
		request.Audience != "operator" || request.LeaseMicros != int64(time.Minute/time.Microsecond) ||
		request.Limit != 2 {
		t.Fatalf("claim request = %#v, error = %v", request, err)
	}
}

func TestTicketRuntimeReconciliationAdapterMapsTransitionsAndGlobalMetrics(t *testing.T) {
	fixture := newTicketRuntimeReconcileFixture(t)
	nextRevision := fixture.claim.CleanupRevision + 1
	retryAt := fixture.claim.ClaimedAt.Add(15 * time.Second)
	finalizeDocument, _ := json.Marshal(map[string]any{
		"schemaVersion": 1, "disposition": "applied", "currentCleanupRevision": nextRevision,
		"artifactId": fixture.claim.Artifact.ArtifactID.String(), "reason": "expired",
		"cleanupFenceSha256": hex.EncodeToString(fixture.claim.CleanupFence[:]),
		"code":               "", "retryAt": nil,
	})
	failureDocument, _ := json.Marshal(map[string]any{
		"schemaVersion": 1, "disposition": "replay_retry", "currentCleanupRevision": nextRevision,
		"artifactId": fixture.claim.Artifact.ArtifactID.String(), "reason": "expired",
		"cleanupFenceSha256": hex.EncodeToString(fixture.claim.CleanupFence[:]),
		"code":               "storage_unavailable", "retryAt": retryAt,
	})
	metricsDocument, _ := json.Marshal(map[string]any{
		"schemaVersion": 1, "snapshotAt": fixture.claim.ClaimedAt,
		"pendingEligible": 7, "reclaimable": 2, "deadLettered": 1,
		"oldestPendingMicroseconds": 12_500_000,
	})
	querier := &ticketRuntimeTestQuerier{rows: []pgx.Row{
		ticketRuntimeJSONRow(string(finalizeDocument)), ticketRuntimeJSONRow(string(failureDocument)),
		ticketRuntimeJSONRow(string(metricsDocument)),
	}}
	repository := NewTicketRuntimeRepository(querier)
	finalized, err := repository.FinalizeArtifactReconciliation(
		context.Background(), ticketexport.ReconcileFinalizeRequest{
			Identity: fixture.identity, Claim: fixture.claim,
			PurgedAt: fixture.claim.ClaimedAt.Add(time.Second),
		},
	)
	if err != nil || finalized.Disposition != ticketexport.ReconcileFinalizeApplied ||
		finalized.CurrentCleanupRevision != nextRevision || finalized.ArtifactID != fixture.claim.Artifact.ArtifactID ||
		finalized.Reason != fixture.claim.Reason || finalized.CleanupFence != fixture.claim.CleanupFence {
		t.Fatalf("FinalizeArtifactReconciliation() = (%#v, %v)", finalized, err)
	}
	failed, err := repository.ReportArtifactReconciliationFailure(
		context.Background(), ticketexport.ReconcileFailureRequest{
			Identity: fixture.identity, Claim: fixture.claim,
			Code:     ticketexport.ReconcileFailureStorageUnavailable,
			FailedAt: fixture.claim.ClaimedAt.Add(time.Second), RetryAt: retryAt,
		},
	)
	if err != nil || failed.Disposition != ticketexport.ReconcileFailureReplayRetry ||
		failed.CurrentCleanupRevision != nextRevision || failed.Code != ticketexport.ReconcileFailureStorageUnavailable ||
		!failed.RetryAt.Equal(retryAt) || failed.ArtifactID != fixture.claim.Artifact.ArtifactID ||
		failed.Reason != fixture.claim.Reason || failed.CleanupFence != fixture.claim.CleanupFence {
		t.Fatalf("ReportArtifactReconciliationFailure() = (%#v, %v)", failed, err)
	}
	metrics, err := repository.ReadReconciliationMetrics(context.Background(), fixture.identity)
	if err != nil || !metrics.SnapshotAt.Equal(fixture.claim.ClaimedAt) ||
		metrics.PendingEligible != 7 || metrics.Reclaimable != 2 || metrics.DeadLettered != 1 ||
		metrics.OldestPendingMicros != 12_500_000 {
		t.Fatalf("ReadReconciliationMetrics() = (%#v, %v)", metrics, err)
	}
	if len(querier.queries) != 3 || querier.queries[0] != ticketExportReconcileFinalizeQuery ||
		querier.queries[1] != ticketExportReconcileFailureQuery ||
		querier.queries[2] != ticketExportReconcileMetricsQuery {
		t.Fatalf("reconciliation queries = %#v", querier.queries)
	}
	var failureRequest struct {
		Identity ticketRuntimeIdentityWireV1             `json:"identity"`
		Claim    ticketRuntimeReconcileClaimOutputWireV1 `json:"claim"`
		Code     string                                  `json:"code"`
		RetryAt  *time.Time                              `json:"retryAt"`
	}
	if err := json.Unmarshal(querier.args[1][0].([]byte), &failureRequest); err != nil ||
		failureRequest.Identity.Purpose != ticketexport.ReconcileWorkerPurpose ||
		failureRequest.Claim.CleanupFenceSHA256 != hex.EncodeToString(fixture.claim.CleanupFence[:]) ||
		failureRequest.Code != "storage_unavailable" || failureRequest.RetryAt == nil ||
		!failureRequest.RetryAt.Equal(retryAt) {
		t.Fatalf("failure request = %#v, error = %v", failureRequest, err)
	}
}

func TestTicketRuntimeReconciliationAdapterRejectsIncompleteOrContradictoryDocuments(t *testing.T) {
	fixture := newTicketRuntimeReconcileFixture(t)
	tests := []struct {
		name string
		row  string
		run  func(*TicketRuntimeRepository) error
	}{
		{
			name: "claim missing nested row count",
			row: `{"schemaVersion":1,"claims":[{"artifact":{"tenantId":"` + fixture.claim.Artifact.TenantID.String() +
				`","jobId":"` + fixture.claim.Artifact.JobID.String() + `","artifactId":"` + fixture.claim.Artifact.ArtifactID.String() +
				`","kind":"alert","audience":"operator","objectRevision":2,"objectAttempt":1,"projectionVersion":1,"sha256":"` +
				hex.EncodeToString(fixture.claim.Artifact.Digest[:]) + `","bytes":100},"reason":"expired","jobRevision":2,"cleanupRevision":2,"cleanupAttempt":1,"cleanupFenceSha256":"` +
				hex.EncodeToString(fixture.claim.CleanupFence[:]) + `","eligibleAt":"2026-08-30T10:00:00Z","claimedAt":"2026-08-30T10:00:00Z","leaseExpiresAt":"2026-08-30T10:01:00Z"}]}`,
			run: func(repository *TicketRuntimeRepository) error {
				_, err := repository.ClaimArtifactReconciliation(context.Background(), ticketexport.ReconcileClaimRequest{
					Identity: fixture.identity, Queue: ticketexport.Queue{TenantID: fixture.claim.Artifact.TenantID,
						Kind: fixture.claim.Artifact.Kind, Audience: fixture.claim.Artifact.Audience},
					Now: fixture.claim.ClaimedAt, LeaseDuration: time.Minute, Limit: 1,
				})
				return err
			},
		},
		{
			name: "finalize missing code",
			row:  `{"schemaVersion":1,"disposition":"fence_lost","currentCleanupRevision":0,"artifactId":"","reason":"","cleanupFenceSha256":"","retryAt":null}`,
			run: func(repository *TicketRuntimeRepository) error {
				_, err := repository.FinalizeArtifactReconciliation(context.Background(), ticketexport.ReconcileFinalizeRequest{
					Identity: fixture.identity, Claim: fixture.claim, PurgedAt: fixture.claim.ClaimedAt,
				})
				return err
			},
		},
		{
			name: "contradictory empty metrics",
			row:  `{"schemaVersion":1,"snapshotAt":"2026-08-30T10:00:00Z","pendingEligible":0,"reclaimable":0,"deadLettered":1,"oldestPendingMicroseconds":1}`,
			run: func(repository *TicketRuntimeRepository) error {
				_, err := repository.ReadReconciliationMetrics(context.Background(), fixture.identity)
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := NewTicketRuntimeRepository(&ticketRuntimeTestQuerier{rows: []pgx.Row{ticketRuntimeJSONRow(test.row)}})
			if err := test.run(repository); !errors.Is(err, ticketexport.ErrInvalidProjection) {
				t.Fatalf("error = %v, want invalid projection", err)
			}
		})
	}
}

type ticketRuntimeReconcileFixture struct {
	identity ticketexport.ReconcileIdentity
	claim    ticketexport.ReconcileClaim
}

func newTicketRuntimeReconcileFixture(t *testing.T) ticketRuntimeReconcileFixture {
	t.Helper()
	tenant := ticketRuntimeTestEntity(t, "000000000011")
	job := ticketRuntimeTestEntity(t, "000000000012")
	artifact := ticketRuntimeTestEntity(t, "000000000013")
	service := ticketRuntimeTestEntity(t, "000000000014")
	worker := ticketRuntimeTestEntity(t, "000000000015")
	now := time.Date(2026, time.August, 30, 10, 0, 0, 0, time.UTC)
	return ticketRuntimeReconcileFixture{
		identity: ticketexport.ReconcileIdentity{
			ServiceAccountID: service, WorkerID: worker, Purpose: ticketexport.ReconcileWorkerPurpose,
		},
		claim: ticketexport.ReconcileClaim{
			Artifact: ticketexport.ReconcileArtifact{
				TenantID: tenant, JobID: job, ArtifactID: artifact, Kind: kernel.AggregateAlert,
				Audience: kernel.TicketExportAudienceOperator, ObjectRevision: 2, ObjectAttempt: 1,
				ProjectionVersion: kernel.TicketExportProjectionVersion,
				Digest:            sha256.Sum256([]byte("artifact")), Rows: 3, Bytes: 100,
			},
			Reason: ticketexport.ReconcileExpired, JobRevision: 2, CleanupRevision: 2,
			CleanupAttempt: 1, CleanupFence: sha256.Sum256([]byte("cleanup-fence")),
			EligibleAt: now, ClaimedAt: now, LeaseExpiresAt: now.Add(time.Minute),
		},
	}
}

func ticketRuntimeReconcileClaimResponse(t *testing.T, claim ticketexport.ReconcileClaim) []byte {
	t.Helper()
	document, err := json.Marshal(map[string]any{
		"schemaVersion": 1,
		"claims":        []ticketRuntimeReconcileClaimOutputWireV1{ticketRuntimeReconcileClaimWire(claim)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return document
}
