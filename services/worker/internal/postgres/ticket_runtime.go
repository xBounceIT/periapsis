package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	"github.com/periapsis-im/periapsis/services/worker/internal/ticketbulk"
	"github.com/periapsis-im/periapsis/services/worker/internal/ticketexport"
)

const (
	ticketRuntimeWireVersion     = 1
	ticketRuntimeMaximumRequest  = 2 * 1024 * 1024
	ticketRuntimeMaximumResponse = 32 * 1024 * 1024
	ticketRuntimeMaximumTokens   = 2_000_000

	ticketWorkQueuesQuery              = `SELECT response FROM app.list_ticket_work_queues_v1($1::jsonb)`
	ticketBulkClaimQuery               = `SELECT response FROM app.claim_ticket_bulk_batch_v1($1::jsonb)`
	ticketBulkApplyTargetQuery         = `SELECT response FROM app.apply_ticket_bulk_target_v2($1::jsonb)`
	ticketBulkReleaseQuery             = `SELECT response FROM app.release_ticket_bulk_batch_v1($1::jsonb)`
	ticketBulkFailureQuery             = `SELECT response FROM app.report_ticket_bulk_batch_failure_v1($1::jsonb)`
	ticketBulkCancelQuery              = `SELECT response FROM app.finalize_ticket_bulk_cancellation_v1($1::jsonb)`
	ticketBulkRevokeQuery              = `SELECT response FROM app.finalize_ticket_bulk_authorization_revocation_v1($1::jsonb)`
	ticketExportClaimQuery             = `SELECT response FROM app.claim_ticket_export_v2($1::jsonb)`
	ticketExportPageQuery              = `SELECT response FROM app.read_ticket_export_page_v2($1::jsonb)`
	ticketExportManifestQuery          = `SELECT response FROM app.record_ticket_export_manifest_v2($1::jsonb)`
	ticketExportSuccessQuery           = `SELECT response FROM app.commit_ticket_export_success_v2($1::jsonb)`
	ticketExportFailureQuery           = `SELECT response FROM app.report_ticket_export_failure_v2($1::jsonb)`
	ticketExportCancelQuery            = `SELECT response FROM app.acknowledge_ticket_export_cancellation_v2($1::jsonb)`
	ticketExportRevokeQuery            = `SELECT response FROM app.reject_ticket_export_revocation_v2($1::jsonb)`
	ticketExportReconcileClaimQuery    = `SELECT response FROM app.claim_ticket_export_artifact_reconciliation_v2($1::jsonb)`
	ticketExportReconcileFinalizeQuery = `SELECT response FROM app.finalize_ticket_export_artifact_reconciliation_v2($1::jsonb)`
	ticketExportReconcileFailureQuery  = `SELECT response FROM app.report_ticket_export_artifact_reconciliation_failure_v2($1::jsonb)`
	ticketExportReconcileMetricsQuery  = `SELECT response FROM app.read_ticket_export_reconciliation_metrics_v2($1::jsonb)`
	ticketBulkReadinessQuery           = `SELECT app.ticket_bulk_runtime_schema_readiness_v51()`
	ticketExportReadinessQuery         = `SELECT app.ticket_export_runtime_schema_readiness_v51()`
)

type TicketRuntimeRepository struct {
	pool SchemaQuerier
}

func NewTicketRuntimeRepository(pool SchemaQuerier) *TicketRuntimeRepository {
	return &TicketRuntimeRepository{pool: pool}
}

type TicketWorkQueue struct {
	TenantID kernel.EntityID
	Kind     kernel.AggregateKind
	Audience kernel.TicketExportAudience
	Export   bool
}

func (queue TicketWorkQueue) String() string {
	if queue.Export {
		return "postgres.TicketWorkQueue{type:export,kind:" + queue.Kind.String() + ",audience:" + queue.Audience.String() + ",tenant:[REDACTED]}"
	}
	return "postgres.TicketWorkQueue{type:bulk,kind:" + queue.Kind.String() + ",tenant:[REDACTED]}"
}

func (queue TicketWorkQueue) GoString() string { return queue.String() }

type ticketRuntimeIdentityWireV1 struct {
	ServiceAccountID string `json:"serviceAccountId"`
	WorkerID         string `json:"workerId"`
	Purpose          string `json:"purpose"`
}

type ticketRuntimeTargetWireV1 struct {
	ID       string `json:"id"`
	Version  uint64 `json:"version"`
	Sequence uint32 `json:"sequence,omitempty"`
}

type ticketRuntimeSavedViewWireV1 struct {
	ID         string `json:"id"`
	OwnerID    string `json:"ownerId"`
	Revision   uint64 `json:"revision"`
	SpecSHA256 string `json:"specSha256"`
}

type ticketRuntimeBulkSelectionWireV1 struct {
	Source          string                        `json:"source"`
	ExplicitTargets []ticketRuntimeTargetWireV1   `json:"explicitTargets"`
	QuerySHA256     string                        `json:"querySha256"`
	TargetSetSHA256 string                        `json:"targetSetSha256"`
	TargetCount     uint32                        `json:"targetCount"`
	SavedView       *ticketRuntimeSavedViewWireV1 `json:"savedView"`
}

type ticketRuntimeBulkMutationWireV1 struct {
	Action     string `json:"action"`
	Transition string `json:"transition"`
	To         string `json:"to"`
	TeamID     string `json:"teamId"`
	AssigneeID string `json:"assigneeId"`
}

type ticketRuntimeBulkDefinitionWireV1 struct {
	ID                string                           `json:"id"`
	TenantID          string                           `json:"tenantId"`
	RequesterID       string                           `json:"requesterId"`
	OwnerMembershipID string                           `json:"ownerMembershipId"`
	Kind              string                           `json:"kind"`
	Selection         ticketRuntimeBulkSelectionWireV1 `json:"selection"`
	Mutation          ticketRuntimeBulkMutationWireV1  `json:"mutation"`
	ProjectionVersion uint64                           `json:"projectionVersion"`
	MaximumAttempts   uint8                            `json:"maximumAttempts"`
}

type ticketRuntimeProgressWireV1 struct {
	Total                uint32 `json:"total"`
	Succeeded            uint32 `json:"succeeded"`
	NoChange             uint32 `json:"noChange"`
	VersionConflict      uint32 `json:"versionConflict"`
	NotFoundOrHidden     uint32 `json:"notFoundOrHidden"`
	AuthorizationDenied  uint32 `json:"authorizationDenied"`
	Rejected             uint32 `json:"rejected"`
	Cancelled            uint32 `json:"cancelled"`
	AuthorizationRevoked uint32 `json:"authorizationRevoked"`
	InternalFailure      uint32 `json:"internalFailure"`
}

type ticketRuntimeBulkBindingWireV1 struct {
	TenantID          string    `json:"tenantId"`
	JobID             string    `json:"jobId"`
	BatchID           string    `json:"batchId"`
	Kind              string    `json:"kind"`
	WorkerID          string    `json:"workerId"`
	Revision          uint64    `json:"revision"`
	Attempt           uint8     `json:"attempt"`
	FenceSHA256       string    `json:"fenceSha256"`
	TargetSetSHA256   string    `json:"targetSetSha256"`
	ProjectionVersion uint64    `json:"projectionVersion"`
	ClaimedAt         time.Time `json:"claimedAt"`
	LeaseExpiresAt    time.Time `json:"leaseExpiresAt"`
	JobExpiresAt      time.Time `json:"jobExpiresAt"`
}

type ticketRuntimeExportDefinitionWireV1 struct {
	ID                string                        `json:"id"`
	TenantID          string                        `json:"tenantId"`
	RequesterID       string                        `json:"requesterId"`
	OwnerMembershipID string                        `json:"ownerMembershipId"`
	CustomerContactID string                        `json:"customerContactId"`
	Kind              string                        `json:"kind"`
	Audience          string                        `json:"audience"`
	CommentScope      string                        `json:"commentScope"`
	QuerySource       string                        `json:"querySource"`
	SavedView         *ticketRuntimeSavedViewWireV1 `json:"savedView"`
	QuerySHA256       string                        `json:"querySha256"`
	CatalogSHA256     string                        `json:"catalogSha256"`
	ProjectionVersion uint64                        `json:"projectionVersion"`
	Format            string                        `json:"format"`
	MaximumRows       uint32                        `json:"maximumRows"`
	MaximumBytes      uint64                        `json:"maximumBytes"`
	MaximumAttempts   uint8                         `json:"maximumAttempts"`
}

type ticketRuntimeExportLeaseWireV1 struct {
	WorkerID  string    `json:"workerId"`
	Fence     string    `json:"fenceSha256"`
	ClaimedAt time.Time `json:"claimedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type ticketRuntimeExportArtifactWireV1 struct {
	ID        string    `json:"id"`
	SHA256    string    `json:"sha256"`
	Rows      uint32    `json:"rows"`
	Bytes     uint64    `json:"bytes"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type ticketRuntimeExportJobWireV1 struct {
	Definition  ticketRuntimeExportDefinitionWireV1 `json:"definition"`
	State       string                              `json:"state"`
	Revision    uint64                              `json:"revision"`
	Attempts    uint8                               `json:"attempts"`
	FailureCode string                              `json:"failureCode"`
	RequestedAt time.Time                           `json:"requestedAt"`
	UpdatedAt   time.Time                           `json:"updatedAt"`
	AvailableAt time.Time                           `json:"availableAt"`
	ExpiresAt   time.Time                           `json:"expiresAt"`
	Lease       *ticketRuntimeExportLeaseWireV1     `json:"lease"`
	Artifact    *ticketRuntimeExportArtifactWireV1  `json:"artifact"`
	TerminalAt  *time.Time                          `json:"terminalAt"`
}

type ticketRuntimeExportBindingWireV1 struct {
	TenantID          string    `json:"tenantId"`
	JobID             string    `json:"jobId"`
	Kind              string    `json:"kind"`
	Audience          string    `json:"audience"`
	WorkerID          string    `json:"workerId"`
	Revision          uint64    `json:"revision"`
	Attempt           uint8     `json:"attempt"`
	FenceSHA256       string    `json:"fenceSha256"`
	QuerySHA256       string    `json:"querySha256"`
	CatalogSHA256     string    `json:"catalogSha256"`
	ProjectionVersion uint64    `json:"projectionVersion"`
	LeaseClaimedAt    time.Time `json:"leaseClaimedAt"`
	LeaseExpiresAt    time.Time `json:"leaseExpiresAt"`
	JobExpiresAt      time.Time `json:"jobExpiresAt"`
}

type ticketRuntimeReconcileArtifactWireV1 struct {
	TenantID          string `json:"tenantId"`
	JobID             string `json:"jobId"`
	ArtifactID        string `json:"artifactId"`
	Kind              string `json:"kind"`
	Audience          string `json:"audience"`
	ObjectRevision    uint64 `json:"objectRevision"`
	ObjectAttempt     uint8  `json:"objectAttempt"`
	ProjectionVersion uint64 `json:"projectionVersion"`
	SHA256            string `json:"sha256"`
	Rows              uint32 `json:"rows"`
	Bytes             uint64 `json:"bytes"`
}

type ticketRuntimeReconcileClaimWireV1 struct {
	Artifact           json.RawMessage `json:"artifact"`
	Reason             string          `json:"reason"`
	JobRevision        uint64          `json:"jobRevision"`
	CleanupRevision    uint64          `json:"cleanupRevision"`
	CleanupAttempt     uint8           `json:"cleanupAttempt"`
	CleanupFenceSHA256 string          `json:"cleanupFenceSha256"`
	EligibleAt         time.Time       `json:"eligibleAt"`
	ClaimedAt          time.Time       `json:"claimedAt"`
	LeaseExpiresAt     time.Time       `json:"leaseExpiresAt"`
}

type ticketRuntimeReconcileClaimOutputWireV1 struct {
	Artifact           ticketRuntimeReconcileArtifactWireV1 `json:"artifact"`
	Reason             string                               `json:"reason"`
	JobRevision        uint64                               `json:"jobRevision"`
	CleanupRevision    uint64                               `json:"cleanupRevision"`
	CleanupAttempt     uint8                                `json:"cleanupAttempt"`
	CleanupFenceSHA256 string                               `json:"cleanupFenceSha256"`
	EligibleAt         time.Time                            `json:"eligibleAt"`
	ClaimedAt          time.Time                            `json:"claimedAt"`
	LeaseExpiresAt     time.Time                            `json:"leaseExpiresAt"`
}

type ticketRuntimeReconcileResultWireV1 struct {
	SchemaVersion          int             `json:"schemaVersion"`
	Disposition            string          `json:"disposition"`
	CurrentCleanupRevision uint64          `json:"currentCleanupRevision"`
	ArtifactID             string          `json:"artifactId"`
	Reason                 string          `json:"reason"`
	CleanupFenceSHA256     string          `json:"cleanupFenceSha256"`
	Code                   string          `json:"code"`
	RetryAt                json.RawMessage `json:"retryAt"`
}

// TicketExportReconciliationMetrics is one global, fixed-cardinality worker
// observation. Tenant and object identities are structurally absent.
type TicketExportReconciliationMetrics struct {
	SnapshotAt          time.Time
	PendingEligible     int64
	Reclaimable         int64
	DeadLettered        int64
	OldestPendingMicros int64
}

func (repository *TicketRuntimeRepository) Ready(ctx context.Context) error {
	if repository == nil || ticketRuntimeDependencyIsNil(repository.pool) || ctx == nil || ctx.Err() != nil {
		return errors.New("ticket runtime database ABI is unavailable")
	}
	var bulkReady, exportReady bool
	if err := repository.pool.QueryRow(ctx, ticketBulkReadinessQuery).Scan(&bulkReady); err != nil || !bulkReady || ctx.Err() != nil {
		return errors.New("ticket bulk database ABI is unavailable")
	}
	if err := repository.pool.QueryRow(ctx, ticketExportReadinessQuery).Scan(&exportReady); err != nil || !exportReady || ctx.Err() != nil {
		return errors.New("ticket export database ABI is unavailable")
	}
	return nil
}

func (repository *TicketRuntimeRepository) ListQueues(
	ctx context.Context,
	serviceAccountID kernel.EntityID,
	workerID kernel.EntityID,
	limit int,
) ([]TicketWorkQueue, error) {
	if parsed, err := ticketRuntimeEntity(serviceAccountID.String()); err != nil || parsed != serviceAccountID {
		return nil, errors.New("ticket work queue identity is unavailable")
	}
	if parsed, err := ticketRuntimeEntity(workerID.String()); err != nil || parsed != workerID {
		return nil, errors.New("ticket work queue identity is unavailable")
	}
	request := struct {
		SchemaVersion    int    `json:"schemaVersion"`
		ServiceAccountID string `json:"serviceAccountId"`
		WorkerID         string `json:"workerId"`
		Purpose          string `json:"purpose"`
		Limit            int    `json:"limit"`
	}{ticketRuntimeWireVersion, serviceAccountID.String(), workerID.String(), "ticket_runtime", limit}
	var response struct {
		SchemaVersion int `json:"schemaVersion"`
		Queues        []struct {
			Type     string `json:"type"`
			TenantID string `json:"tenantId"`
			Kind     string `json:"kind"`
			Audience string `json:"audience"`
		} `json:"queues"`
	}
	if limit < 1 || limit > 1_000 || repository.query(ctx, ticketWorkQueuesQuery, request, &response, false) != nil ||
		response.SchemaVersion != ticketRuntimeWireVersion || response.Queues == nil || len(response.Queues) > limit {
		return nil, errors.New("ticket work queues are unavailable")
	}
	queues := make([]TicketWorkQueue, len(response.Queues))
	seen := make(map[string]struct{}, len(response.Queues))
	for index, item := range response.Queues {
		tenant, err := ticketRuntimeEntity(item.TenantID)
		kind, kindErr := ticketRuntimeKind(item.Kind)
		if err != nil || kindErr != nil {
			return nil, errors.New("ticket work queue projection is invalid")
		}
		queue := TicketWorkQueue{TenantID: tenant, Kind: kind}
		switch item.Type {
		case "bulk":
			if item.Audience != "" {
				return nil, errors.New("ticket work queue projection is invalid")
			}
		case "export":
			queue.Export = true
			queue.Audience, err = ticketRuntimeAudience(item.Audience)
			if err != nil {
				return nil, errors.New("ticket work queue projection is invalid")
			}
		default:
			return nil, errors.New("ticket work queue projection is invalid")
		}
		key := queue.String() + ":" + item.TenantID
		if _, duplicate := seen[key]; duplicate {
			return nil, errors.New("ticket work queue projection is invalid")
		}
		seen[key] = struct{}{}
		queues[index] = queue
	}
	return queues, nil
}

func (repository *TicketRuntimeRepository) query(
	ctx context.Context,
	query string,
	request any,
	destination any,
	allowNoRows bool,
) error {
	if repository == nil || ticketRuntimeDependencyIsNil(repository.pool) || ctx == nil || ctx.Err() != nil || destination == nil {
		return errors.New("ticket runtime dependency is unavailable")
	}
	payload, err := json.Marshal(request)
	if err != nil || len(payload) == 0 || len(payload) > ticketRuntimeMaximumRequest {
		return errors.New("ticket runtime request is unavailable")
	}
	var document []byte
	err = repository.pool.QueryRow(ctx, query, payload).Scan(&document)
	if allowNoRows && errors.Is(err, pgx.ErrNoRows) {
		return pgx.ErrNoRows
	}
	if err != nil || ctx.Err() != nil || len(document) == 0 || len(document) > ticketRuntimeMaximumResponse ||
		ticketRuntimeTokenCount(document) > ticketRuntimeMaximumTokens {
		return errors.New("ticket runtime database ABI is unavailable")
	}
	decoder := json.NewDecoder(io.LimitReader(bytes.NewReader(document), ticketRuntimeMaximumResponse+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("ticket runtime projection is invalid")
	}
	return nil
}

func ticketRuntimeTokenCount(document []byte) int {
	decoder := json.NewDecoder(bytes.NewReader(document))
	count := 0
	for {
		if _, err := decoder.Token(); err != nil {
			return count
		}
		count++
		if count > ticketRuntimeMaximumTokens {
			return count
		}
	}
}

func ticketRuntimeDependencyIsNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func ticketRuntimeEntity(value string) (kernel.EntityID, error) {
	id, err := uuid.Parse(value)
	if err != nil || id.Version() != 7 || id.String() != value {
		return kernel.EntityID{}, errors.New("invalid ticket runtime identity")
	}
	var raw [16]byte
	copy(raw[:], id[:])
	return kernel.NewEntityID(raw)
}

func ticketRuntimeInstant(value time.Time) (time.Time, error) {
	_, offset := value.Zone()
	if value.IsZero() || offset != 0 || value.Year() < 1970 || value.Year() > 9999 ||
		value.Nanosecond()%int(time.Microsecond) != 0 {
		return time.Time{}, errors.New("invalid ticket runtime instant")
	}
	return value.UTC(), nil
}

func ticketRuntimeOptionalInstant(value *time.Time) (*time.Time, error) {
	if value == nil {
		return nil, nil
	}
	normalized, err := ticketRuntimeInstant(*value)
	if err != nil {
		return nil, err
	}
	return &normalized, nil
}

func ticketRuntimeDigest(value string) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size || strings.ToLower(value) != value {
		return result, errors.New("invalid ticket runtime digest")
	}
	copy(result[:], decoded)
	if result == ([sha256.Size]byte{}) {
		return result, errors.New("invalid ticket runtime digest")
	}
	return result, nil
}

func ticketRuntimeKind(value string) (kernel.AggregateKind, error) {
	switch value {
	case kernel.AggregateAlert.String():
		return kernel.AggregateAlert, nil
	case kernel.AggregateCase.String():
		return kernel.AggregateCase, nil
	default:
		return 0, errors.New("invalid ticket runtime kind")
	}
}

func ticketRuntimeAudience(value string) (kernel.TicketExportAudience, error) {
	switch value {
	case kernel.TicketExportAudienceOperator.String():
		return kernel.TicketExportAudienceOperator, nil
	case kernel.TicketExportAudienceCustomer.String():
		return kernel.TicketExportAudienceCustomer, nil
	default:
		return 0, errors.New("invalid ticket runtime audience")
	}
}

func ticketRuntimeBulkIdentity(identity ticketbulk.Identity) ticketRuntimeIdentityWireV1 {
	return ticketRuntimeIdentityWireV1{
		ServiceAccountID: identity.ServiceAccountID.String(), WorkerID: identity.WorkerID.String(),
		Purpose: identity.Purpose,
	}
}

func ticketRuntimeExportIdentity(identity ticketexport.Identity) ticketRuntimeIdentityWireV1 {
	return ticketRuntimeIdentityWireV1{
		ServiceAccountID: identity.ServiceAccountID.String(), WorkerID: identity.WorkerID.String(),
		Purpose: identity.Purpose,
	}
}

func ticketRuntimeReconcileIdentity(identity ticketexport.ReconcileIdentity) ticketRuntimeIdentityWireV1 {
	return ticketRuntimeIdentityWireV1{
		ServiceAccountID: identity.ServiceAccountID.String(), WorkerID: identity.WorkerID.String(),
		Purpose: identity.Purpose,
	}
}

var (
	_ ticketbulk.Repository            = (*TicketRuntimeRepository)(nil)
	_ ticketexport.Repository          = (*TicketRuntimeRepository)(nil)
	_ ticketexport.ReconcileRepository = (*TicketRuntimeRepository)(nil)
)

func (repository *TicketRuntimeRepository) ClaimBatch(
	ctx context.Context,
	request ticketbulk.ClaimRequest,
) (ticketbulk.Claim, bool, error) {
	payload := struct {
		SchemaVersion int                         `json:"schemaVersion"`
		Identity      ticketRuntimeIdentityWireV1 `json:"identity"`
		TenantID      string                      `json:"tenantId"`
		Kind          string                      `json:"kind"`
		Now           time.Time                   `json:"now"`
		LeaseMicros   int64                       `json:"leaseMicroseconds"`
		Limit         int                         `json:"limit"`
	}{ticketRuntimeWireVersion, ticketRuntimeBulkIdentity(request.Identity), request.Queue.TenantID.String(), request.Queue.Kind.String(), request.Now, request.LeaseDuration.Microseconds(), request.Limit}
	var response struct {
		SchemaVersion int                               `json:"schemaVersion"`
		Definition    ticketRuntimeBulkDefinitionWireV1 `json:"definition"`
		Binding       ticketRuntimeBulkBindingWireV1    `json:"binding"`
		Targets       []ticketRuntimeTargetWireV1       `json:"targets"`
		Progress      ticketRuntimeProgressWireV1       `json:"progress"`
		ObservedAt    time.Time                         `json:"observedAt"`
	}
	if err := repository.query(ctx, ticketBulkClaimQuery, payload, &response, true); errors.Is(err, pgx.ErrNoRows) {
		return ticketbulk.Claim{}, false, nil
	} else if err != nil {
		return ticketbulk.Claim{}, false, ticketbulk.ErrUnavailable
	}
	definition, err := restoreTicketRuntimeBulkDefinition(response.Definition)
	binding, bindingErr := restoreTicketRuntimeBulkBinding(response.Binding)
	observedAt, observedErr := ticketRuntimeInstant(response.ObservedAt)
	progress := ticketRuntimeProgress(response.Progress)
	if response.SchemaVersion != ticketRuntimeWireVersion || err != nil || bindingErr != nil || observedErr != nil ||
		kernel.ValidateTicketBulkDefinition(definition) != nil {
		return ticketbulk.Claim{}, false, ticketbulk.ErrInvalidProjection
	}
	if _, err := kernel.RestoreTicketBulkProgress(progress); err != nil || len(response.Targets) == 0 || len(response.Targets) > request.Limit {
		return ticketbulk.Claim{}, false, ticketbulk.ErrInvalidProjection
	}
	targets := make([]ticketbulk.ClaimedTarget, len(response.Targets))
	for index, item := range response.Targets {
		id, err := ticketRuntimeEntity(item.ID)
		if err != nil {
			return ticketbulk.Claim{}, false, ticketbulk.ErrInvalidProjection
		}
		pin, err := kernel.NewTicketBulkTargetPin(id, item.Version)
		if err != nil || item.Sequence == 0 {
			return ticketbulk.Claim{}, false, ticketbulk.ErrInvalidProjection
		}
		targets[index] = ticketbulk.ClaimedTarget{Sequence: item.Sequence, Pin: pin}
	}
	return ticketbulk.Claim{
		Definition: definition, Binding: binding, Targets: targets,
		Progress: progress, ObservedAt: observedAt,
	}, true, nil
}

func (repository *TicketRuntimeRepository) ApplyTarget(
	ctx context.Context,
	request ticketbulk.ApplyTargetRequest,
) (ticketbulk.ApplyTargetResult, error) {
	payload := struct {
		SchemaVersion int                            `json:"schemaVersion"`
		Identity      ticketRuntimeIdentityWireV1    `json:"identity"`
		Binding       ticketRuntimeBulkBindingWireV1 `json:"binding"`
		Sequence      uint32                         `json:"sequence"`
		TargetID      string                         `json:"targetId"`
		TargetVersion uint64                         `json:"targetVersion"`
		Action        string                         `json:"action"`
	}{ticketRuntimeWireVersion, ticketRuntimeBulkIdentity(request.Identity), ticketRuntimeBulkBindingWire(request.Binding), request.Sequence, request.Pin.ID().String(), request.Pin.Version(), request.Command.Action().String()}
	var response struct {
		SchemaVersion   int    `json:"schemaVersion"`
		Disposition     string `json:"disposition"`
		Sequence        uint32 `json:"sequence"`
		Result          string `json:"result"`
		ControlRevision uint64 `json:"controlRevision"`
	}
	if repository.query(ctx, ticketBulkApplyTargetQuery, payload, &response, false) != nil || response.SchemaVersion != ticketRuntimeWireVersion {
		return ticketbulk.ApplyTargetResult{}, ticketbulk.ErrUnavailable
	}
	disposition, err := ticketRuntimeApplyDisposition(response.Disposition)
	result := kernel.TicketBulkTargetResult(0)
	if response.Result != "" {
		result, err = ticketRuntimeTargetResult(response.Result)
	}
	if err != nil {
		return ticketbulk.ApplyTargetResult{}, ticketbulk.ErrInvalidProjection
	}
	return ticketbulk.ApplyTargetResult{
		Disposition: disposition, Sequence: response.Sequence, Result: result,
		ControlRevision: response.ControlRevision,
	}, nil
}

func (repository *TicketRuntimeRepository) ReleaseBatch(
	ctx context.Context,
	request ticketbulk.ReleaseBatchRequest,
) (ticketbulk.ReleaseBatchResult, error) {
	payload := struct {
		SchemaVersion int                            `json:"schemaVersion"`
		Identity      ticketRuntimeIdentityWireV1    `json:"identity"`
		Binding       ticketRuntimeBulkBindingWireV1 `json:"binding"`
		Processed     uint32                         `json:"processed"`
		ReceiptSHA256 string                         `json:"receiptSha256"`
		ReleasedAt    time.Time                      `json:"releasedAt"`
	}{ticketRuntimeWireVersion, ticketRuntimeBulkIdentity(request.Identity), ticketRuntimeBulkBindingWire(request.Binding), request.Processed, hex.EncodeToString(request.ReceiptDigest[:]), request.ReleasedAt}
	var response struct {
		SchemaVersion   int                          `json:"schemaVersion"`
		Disposition     string                       `json:"disposition"`
		Progress        *ticketRuntimeProgressWireV1 `json:"progress"`
		ControlRevision uint64                       `json:"controlRevision"`
	}
	if repository.query(ctx, ticketBulkReleaseQuery, payload, &response, false) != nil || response.SchemaVersion != ticketRuntimeWireVersion {
		return ticketbulk.ReleaseBatchResult{}, ticketbulk.ErrUnavailable
	}
	disposition, err := ticketRuntimeReleaseDisposition(response.Disposition)
	progress, err := ticketRuntimeOptionalProgress(response.Progress, err)
	if err != nil {
		return ticketbulk.ReleaseBatchResult{}, ticketbulk.ErrInvalidProjection
	}
	return ticketbulk.ReleaseBatchResult{Disposition: disposition, Progress: progress, ControlRevision: response.ControlRevision}, nil
}

func (repository *TicketRuntimeRepository) ReportBatchFailure(
	ctx context.Context,
	request ticketbulk.BatchFailureRequest,
) (ticketbulk.BatchFailureResult, error) {
	payload := struct {
		SchemaVersion int                            `json:"schemaVersion"`
		Identity      ticketRuntimeIdentityWireV1    `json:"identity"`
		Binding       ticketRuntimeBulkBindingWireV1 `json:"binding"`
		Code          string                         `json:"code"`
		FailedAt      time.Time                      `json:"failedAt"`
		RetryAt       *time.Time                     `json:"retryAt"`
	}{ticketRuntimeWireVersion, ticketRuntimeBulkIdentity(request.Identity), ticketRuntimeBulkBindingWire(request.Binding), request.Code.String(), request.FailedAt, request.RetryAt}
	var response struct {
		SchemaVersion   int                          `json:"schemaVersion"`
		Disposition     string                       `json:"disposition"`
		Progress        *ticketRuntimeProgressWireV1 `json:"progress"`
		ControlRevision uint64                       `json:"controlRevision"`
		RetryAt         *time.Time                   `json:"retryAt"`
	}
	if repository.query(ctx, ticketBulkFailureQuery, payload, &response, false) != nil || response.SchemaVersion != ticketRuntimeWireVersion {
		return ticketbulk.BatchFailureResult{}, ticketbulk.ErrUnavailable
	}
	disposition, err := ticketRuntimeFailureDisposition(response.Disposition)
	progress, err := ticketRuntimeOptionalProgress(response.Progress, err)
	retryAt, retryErr := ticketRuntimeOptionalInstant(response.RetryAt)
	if err != nil || retryErr != nil {
		return ticketbulk.BatchFailureResult{}, ticketbulk.ErrInvalidProjection
	}
	return ticketbulk.BatchFailureResult{
		Disposition: disposition, Progress: progress, ControlRevision: response.ControlRevision,
		RetryAt: retryAt,
	}, nil
}

func (repository *TicketRuntimeRepository) FinalizeCancellation(
	ctx context.Context,
	request ticketbulk.ControlFinalizationRequest,
) (ticketbulk.ControlFinalizationResult, error) {
	return repository.finalizeBulkControl(ctx, ticketBulkCancelQuery, request)
}

func (repository *TicketRuntimeRepository) FinalizeAuthorizationRevocation(
	ctx context.Context,
	request ticketbulk.ControlFinalizationRequest,
) (ticketbulk.ControlFinalizationResult, error) {
	return repository.finalizeBulkControl(ctx, ticketBulkRevokeQuery, request)
}

func (repository *TicketRuntimeRepository) finalizeBulkControl(
	ctx context.Context,
	query string,
	request ticketbulk.ControlFinalizationRequest,
) (ticketbulk.ControlFinalizationResult, error) {
	payload := struct {
		SchemaVersion    int                            `json:"schemaVersion"`
		Identity         ticketRuntimeIdentityWireV1    `json:"identity"`
		Binding          ticketRuntimeBulkBindingWireV1 `json:"binding"`
		ExpectedRevision uint64                         `json:"expectedRevision"`
		FinalizedAt      time.Time                      `json:"finalizedAt"`
	}{ticketRuntimeWireVersion, ticketRuntimeBulkIdentity(request.Identity), ticketRuntimeBulkBindingWire(request.Binding), request.ExpectedRevision, request.FinalizedAt}
	var response struct {
		SchemaVersion   int                          `json:"schemaVersion"`
		Disposition     string                       `json:"disposition"`
		Progress        *ticketRuntimeProgressWireV1 `json:"progress"`
		ControlRevision uint64                       `json:"controlRevision"`
	}
	if repository.query(ctx, query, payload, &response, false) != nil || response.SchemaVersion != ticketRuntimeWireVersion {
		return ticketbulk.ControlFinalizationResult{}, ticketbulk.ErrUnavailable
	}
	disposition, err := ticketRuntimeControlDisposition(response.Disposition)
	progress, err := ticketRuntimeOptionalProgress(response.Progress, err)
	if err != nil {
		return ticketbulk.ControlFinalizationResult{}, ticketbulk.ErrInvalidProjection
	}
	return ticketbulk.ControlFinalizationResult{
		Disposition: disposition, Progress: progress, ControlRevision: response.ControlRevision,
	}, nil
}

func restoreTicketRuntimeBulkDefinition(
	wire ticketRuntimeBulkDefinitionWireV1,
) (kernel.TicketBulkDefinition, error) {
	id, err := ticketRuntimeEntity(wire.ID)
	if err != nil {
		return kernel.TicketBulkDefinition{}, err
	}
	tenant, err := ticketRuntimeEntity(wire.TenantID)
	if err != nil {
		return kernel.TicketBulkDefinition{}, err
	}
	requester, err := ticketRuntimeEntity(wire.RequesterID)
	if err != nil {
		return kernel.TicketBulkDefinition{}, err
	}
	owner, err := ticketRuntimeEntity(wire.OwnerMembershipID)
	if err != nil {
		return kernel.TicketBulkDefinition{}, err
	}
	kind, err := ticketRuntimeKind(wire.Kind)
	if err != nil {
		return kernel.TicketBulkDefinition{}, err
	}
	selection, err := restoreTicketRuntimeBulkSelection(wire.Selection)
	if err != nil {
		return kernel.TicketBulkDefinition{}, err
	}
	mutation, err := restoreTicketRuntimeBulkMutation(wire.Mutation)
	if err != nil {
		return kernel.TicketBulkDefinition{}, err
	}
	definition, err := kernel.NewTicketBulkDefinition(kernel.TicketBulkDefinitionInput{
		ID: id, Tenant: tenant, Requester: requester, OwnerMembership: owner, Kind: kind,
		Selection: selection, Mutation: mutation, ProjectionVersion: wire.ProjectionVersion,
		MaximumAttempts: wire.MaximumAttempts,
	})
	if err != nil {
		return kernel.TicketBulkDefinition{}, errors.New("ticket bulk definition projection is invalid")
	}
	return definition, nil
}

func restoreTicketRuntimeBulkSelection(
	wire ticketRuntimeBulkSelectionWireV1,
) (kernel.TicketBulkSelection, error) {
	switch wire.Source {
	case kernel.TicketBulkSelectionExplicit.String():
		if wire.QuerySHA256 != "" || wire.SavedView != nil ||
			wire.TargetCount != uint32(len(wire.ExplicitTargets)) {
			return kernel.TicketBulkSelection{}, errors.New("ticket bulk selection projection is invalid")
		}
		targets := make([]kernel.TicketBulkTargetPin, len(wire.ExplicitTargets))
		for index, target := range wire.ExplicitTargets {
			id, err := ticketRuntimeEntity(target.ID)
			if err != nil {
				return kernel.TicketBulkSelection{}, err
			}
			pin, err := kernel.NewTicketBulkTargetPin(id, target.Version)
			if err != nil {
				return kernel.TicketBulkSelection{}, errors.New("ticket bulk selection projection is invalid")
			}
			targets[index] = pin
		}
		selection, err := kernel.NewExplicitTicketBulkSelection(targets)
		if err != nil {
			return kernel.TicketBulkSelection{}, errors.New("ticket bulk selection projection is invalid")
		}
		digest, err := ticketRuntimeDigest(wire.TargetSetSHA256)
		if err != nil || selection.TargetSetDigest() != digest {
			return kernel.TicketBulkSelection{}, errors.New("ticket bulk selection projection is invalid")
		}
		return selection, nil
	case kernel.TicketBulkSelectionQuery.String():
		if wire.ExplicitTargets != nil {
			return kernel.TicketBulkSelection{}, errors.New("ticket bulk selection projection is invalid")
		}
		queryDigest, err := ticketRuntimeDigest(wire.QuerySHA256)
		if err != nil {
			return kernel.TicketBulkSelection{}, err
		}
		targetDigest, err := ticketRuntimeDigest(wire.TargetSetSHA256)
		if err != nil {
			return kernel.TicketBulkSelection{}, err
		}
		pin, err := restoreTicketRuntimeBulkSavedView(wire.SavedView)
		if err != nil {
			return kernel.TicketBulkSelection{}, err
		}
		selection, err := kernel.NewQueryTicketBulkSelection(
			queryDigest, targetDigest, wire.TargetCount, pin,
		)
		if err != nil {
			return kernel.TicketBulkSelection{}, errors.New("ticket bulk selection projection is invalid")
		}
		return selection, nil
	default:
		return kernel.TicketBulkSelection{}, errors.New("ticket bulk selection projection is invalid")
	}
}

func restoreTicketRuntimeBulkSavedView(
	wire *ticketRuntimeSavedViewWireV1,
) (*kernel.TicketBulkSavedViewPin, error) {
	if wire == nil {
		return nil, nil
	}
	id, err := ticketRuntimeEntity(wire.ID)
	if err != nil {
		return nil, err
	}
	owner, err := ticketRuntimeEntity(wire.OwnerID)
	if err != nil {
		return nil, err
	}
	digest, err := ticketRuntimeDigest(wire.SpecSHA256)
	if err != nil {
		return nil, err
	}
	pin, err := kernel.NewTicketBulkSavedViewPin(id, owner, wire.Revision, digest)
	if err != nil {
		return nil, errors.New("ticket bulk saved-view projection is invalid")
	}
	return &pin, nil
}

func restoreTicketRuntimeBulkMutation(
	wire ticketRuntimeBulkMutationWireV1,
) (kernel.TicketBulkMutation, error) {
	switch wire.Action {
	case kernel.ActionTransition.String():
		transition, transitionErr := kernel.NewKey(wire.Transition)
		to, toErr := kernel.NewKey(wire.To)
		if transitionErr != nil || toErr != nil || wire.TeamID != "" || wire.AssigneeID != "" {
			return kernel.TicketBulkMutation{}, errors.New("ticket bulk mutation projection is invalid")
		}
		return kernel.NewTicketBulkTransition(transition, to)
	case kernel.ActionAssign.String(), kernel.ActionTransfer.String():
		if wire.Transition != "" || wire.To != "" {
			return kernel.TicketBulkMutation{}, errors.New("ticket bulk mutation projection is invalid")
		}
		team, err := ticketRuntimeEntity(wire.TeamID)
		if err != nil {
			return kernel.TicketBulkMutation{}, err
		}
		var assignee *kernel.EntityID
		if wire.AssigneeID != "" {
			parsed, err := ticketRuntimeEntity(wire.AssigneeID)
			if err != nil {
				return kernel.TicketBulkMutation{}, err
			}
			assignee = &parsed
		}
		if wire.Action == kernel.ActionAssign.String() {
			return kernel.NewTicketBulkAssignment(team, assignee)
		}
		return kernel.NewTicketBulkTransfer(team, assignee)
	case kernel.ActionClaim.String():
		if wire.Transition != "" || wire.To != "" || wire.AssigneeID != "" {
			return kernel.TicketBulkMutation{}, errors.New("ticket bulk mutation projection is invalid")
		}
		team, err := ticketRuntimeEntity(wire.TeamID)
		if err != nil {
			return kernel.TicketBulkMutation{}, err
		}
		return kernel.NewTicketBulkClaim(team)
	case kernel.ActionRelease.String():
		if wire.Transition != "" || wire.To != "" || wire.TeamID != "" || wire.AssigneeID != "" {
			return kernel.TicketBulkMutation{}, errors.New("ticket bulk mutation projection is invalid")
		}
		return kernel.NewTicketBulkRelease(), nil
	default:
		return kernel.TicketBulkMutation{}, errors.New("ticket bulk mutation projection is invalid")
	}
}

func restoreTicketRuntimeBulkBinding(
	wire ticketRuntimeBulkBindingWireV1,
) (ticketbulk.BatchBinding, error) {
	tenant, err := ticketRuntimeEntity(wire.TenantID)
	if err != nil {
		return ticketbulk.BatchBinding{}, err
	}
	job, err := ticketRuntimeEntity(wire.JobID)
	if err != nil {
		return ticketbulk.BatchBinding{}, err
	}
	batch, err := ticketRuntimeEntity(wire.BatchID)
	if err != nil {
		return ticketbulk.BatchBinding{}, err
	}
	kind, err := ticketRuntimeKind(wire.Kind)
	if err != nil {
		return ticketbulk.BatchBinding{}, err
	}
	worker, err := ticketRuntimeEntity(wire.WorkerID)
	if err != nil {
		return ticketbulk.BatchBinding{}, err
	}
	fence, err := ticketRuntimeDigest(wire.FenceSHA256)
	if err != nil {
		return ticketbulk.BatchBinding{}, err
	}
	targetSet, err := ticketRuntimeDigest(wire.TargetSetSHA256)
	if err != nil {
		return ticketbulk.BatchBinding{}, err
	}
	claimedAt, err := ticketRuntimeInstant(wire.ClaimedAt)
	if err != nil {
		return ticketbulk.BatchBinding{}, err
	}
	leaseExpiresAt, err := ticketRuntimeInstant(wire.LeaseExpiresAt)
	if err != nil {
		return ticketbulk.BatchBinding{}, err
	}
	jobExpiresAt, err := ticketRuntimeInstant(wire.JobExpiresAt)
	if err != nil {
		return ticketbulk.BatchBinding{}, err
	}
	return ticketbulk.BatchBinding{
		TenantID: tenant, JobID: job, BatchID: batch, Kind: kind, WorkerID: worker,
		Revision: wire.Revision, Attempt: wire.Attempt, Fence: fence, TargetSetDigest: targetSet,
		ProjectionVersion: wire.ProjectionVersion, ClaimedAt: claimedAt,
		LeaseExpiresAt: leaseExpiresAt, JobExpiresAt: jobExpiresAt,
	}, nil
}

func ticketRuntimeBulkBindingWire(binding ticketbulk.BatchBinding) ticketRuntimeBulkBindingWireV1 {
	return ticketRuntimeBulkBindingWireV1{
		TenantID: binding.TenantID.String(), JobID: binding.JobID.String(),
		BatchID: binding.BatchID.String(), Kind: binding.Kind.String(),
		WorkerID: binding.WorkerID.String(), Revision: binding.Revision, Attempt: binding.Attempt,
		FenceSHA256:       hex.EncodeToString(binding.Fence[:]),
		TargetSetSHA256:   hex.EncodeToString(binding.TargetSetDigest[:]),
		ProjectionVersion: binding.ProjectionVersion, ClaimedAt: binding.ClaimedAt,
		LeaseExpiresAt: binding.LeaseExpiresAt, JobExpiresAt: binding.JobExpiresAt,
	}
}

func ticketRuntimeProgress(wire ticketRuntimeProgressWireV1) kernel.TicketBulkProgressSnapshot {
	return kernel.TicketBulkProgressSnapshot{
		Total: wire.Total, Succeeded: wire.Succeeded, NoChange: wire.NoChange,
		VersionConflict: wire.VersionConflict, NotFoundOrHidden: wire.NotFoundOrHidden,
		AuthorizationDenied: wire.AuthorizationDenied, Rejected: wire.Rejected,
		Cancelled: wire.Cancelled, AuthorizationRevoked: wire.AuthorizationRevoked,
		InternalFailure: wire.InternalFailure,
	}
}

func ticketRuntimeOptionalProgress(
	wire *ticketRuntimeProgressWireV1,
	prior error,
) (*kernel.TicketBulkProgressSnapshot, error) {
	if prior != nil || wire == nil {
		return nil, prior
	}
	progress := ticketRuntimeProgress(*wire)
	if _, err := kernel.RestoreTicketBulkProgress(progress); err != nil {
		return nil, err
	}
	return &progress, nil
}

func ticketRuntimeTargetResult(value string) (kernel.TicketBulkTargetResult, error) {
	for _, result := range []kernel.TicketBulkTargetResult{
		kernel.TicketBulkTargetSucceeded, kernel.TicketBulkTargetNoChange,
		kernel.TicketBulkTargetVersionConflict, kernel.TicketBulkTargetNotFoundOrHidden,
		kernel.TicketBulkTargetAuthorizationDenied, kernel.TicketBulkTargetRejected,
		kernel.TicketBulkTargetCancelled, kernel.TicketBulkTargetAuthorizationRevoked,
		kernel.TicketBulkTargetInternalFailure,
	} {
		if result.String() == value {
			return result, nil
		}
	}
	return 0, errors.New("ticket bulk result projection is invalid")
}

func ticketRuntimeApplyDisposition(value string) (ticketbulk.ApplyTargetDisposition, error) {
	switch value {
	case "applied":
		return ticketbulk.ApplyTargetApplied, nil
	case "replayed":
		return ticketbulk.ApplyTargetReplayed, nil
	case "cancellation_requested":
		return ticketbulk.ApplyTargetCancellationRequested, nil
	case "authorization_revoked":
		return ticketbulk.ApplyTargetAuthorizationRevoked, nil
	case "fence_lost":
		return ticketbulk.ApplyTargetFenceLost, nil
	default:
		return 0, errors.New("ticket bulk apply disposition is invalid")
	}
}

func ticketRuntimeReleaseDisposition(value string) (ticketbulk.ReleaseBatchDisposition, error) {
	switch value {
	case "batch_released":
		return ticketbulk.ReleaseBatchReleased, nil
	case "job_completed":
		return ticketbulk.ReleaseJobCompleted, nil
	case "cancellation_requested":
		return ticketbulk.ReleaseCancellationRequested, nil
	case "authorization_revoked":
		return ticketbulk.ReleaseAuthorizationRevoked, nil
	case "fence_lost":
		return ticketbulk.ReleaseFenceLost, nil
	case "job_failed":
		return ticketbulk.ReleaseJobFailed, nil
	default:
		return 0, errors.New("ticket bulk release disposition is invalid")
	}
}

func ticketRuntimeFailureDisposition(value string) (ticketbulk.BatchFailureDisposition, error) {
	switch value {
	case "retry_scheduled":
		return ticketbulk.FailureRetryScheduled, nil
	case "replay_retry":
		return ticketbulk.FailureReplayRetry, nil
	case "batch_terminalized":
		return ticketbulk.FailureBatchTerminalized, nil
	case "replay_batch_terminalized":
		return ticketbulk.FailureReplayBatchTerminalized, nil
	case "job_failed":
		return ticketbulk.FailureJobFailed, nil
	case "replay_job_failed":
		return ticketbulk.FailureReplayJobFailed, nil
	case "cancellation_requested":
		return ticketbulk.FailureCancellationRequested, nil
	case "authorization_revoked":
		return ticketbulk.FailureAuthorizationRevoked, nil
	case "fence_lost":
		return ticketbulk.FailureFenceLost, nil
	case "batch_released":
		return ticketbulk.FailureBatchReleased, nil
	case "replay_batch_released":
		return ticketbulk.FailureReplayBatchReleased, nil
	case "job_completed":
		return ticketbulk.FailureJobCompleted, nil
	case "replay_job_completed":
		return ticketbulk.FailureReplayJobCompleted, nil
	default:
		return 0, errors.New("ticket bulk failure disposition is invalid")
	}
}

func ticketRuntimeControlDisposition(value string) (ticketbulk.ControlFinalizationDisposition, error) {
	switch value {
	case "applied":
		return ticketbulk.ControlFinalizationApplied, nil
	case "replayed":
		return ticketbulk.ControlFinalizationReplayed, nil
	case "fence_lost":
		return ticketbulk.ControlFinalizationFenceLost, nil
	default:
		return 0, errors.New("ticket bulk control disposition is invalid")
	}
}

type ticketRuntimeManifestWireV1 struct {
	ArtifactID string `json:"artifactId"`
	SHA256     string `json:"sha256"`
	Rows       uint32 `json:"rows"`
	Bytes      uint64 `json:"bytes"`
}

func (repository *TicketRuntimeRepository) Claim(
	ctx context.Context,
	request ticketexport.ClaimRequest,
) (ticketexport.Claim, bool, error) {
	payload := struct {
		SchemaVersion int                         `json:"schemaVersion"`
		Identity      ticketRuntimeIdentityWireV1 `json:"identity"`
		TenantID      string                      `json:"tenantId"`
		Kind          string                      `json:"kind"`
		Audience      string                      `json:"audience"`
		ArtifactID    string                      `json:"artifactId"`
		Now           time.Time                   `json:"now"`
		LeaseMicros   int64                       `json:"leaseMicroseconds"`
	}{
		ticketRuntimeWireVersion, ticketRuntimeExportIdentity(request.Identity),
		request.Queue.TenantID.String(), request.Queue.Kind.String(), request.Queue.Audience.String(),
		request.ArtifactID.String(), request.Now, request.LeaseDuration.Microseconds(),
	}
	var response struct {
		SchemaVersion int                          `json:"schemaVersion"`
		Job           ticketRuntimeExportJobWireV1 `json:"job"`
		ArtifactID    string                       `json:"artifactId"`
		Header        []string                     `json:"header"`
		ObservedAt    time.Time                    `json:"observedAt"`
	}
	if err := repository.query(ctx, ticketExportClaimQuery, payload, &response, true); errors.Is(err, pgx.ErrNoRows) {
		return ticketexport.Claim{}, false, nil
	} else if err != nil {
		return ticketexport.Claim{}, false, ticketexport.ErrUnavailable
	}
	job, err := restoreTicketRuntimeExportJob(response.Job)
	artifactID, artifactErr := ticketRuntimeEntity(response.ArtifactID)
	observedAt, observedErr := ticketRuntimeInstant(response.ObservedAt)
	if response.SchemaVersion != ticketRuntimeWireVersion || err != nil || artifactErr != nil || observedErr != nil {
		return ticketexport.Claim{}, false, ticketexport.ErrInvalidProjection
	}
	return ticketexport.Claim{
		Job: job, ArtifactID: artifactID, Header: append([]string(nil), response.Header...),
		ObservedAt: observedAt,
	}, true, nil
}

func (repository *TicketRuntimeRepository) ReadPage(
	ctx context.Context,
	request ticketexport.PageRequest,
) (ticketexport.PageResult, error) {
	payload := struct {
		SchemaVersion int                              `json:"schemaVersion"`
		Identity      ticketRuntimeIdentityWireV1      `json:"identity"`
		Binding       ticketRuntimeExportBindingWireV1 `json:"binding"`
		After         string                           `json:"after"`
		Limit         int                              `json:"limit"`
	}{ticketRuntimeWireVersion, ticketRuntimeExportIdentity(request.Identity), ticketRuntimeExportBindingWire(request.Binding), request.After, request.Limit}
	var response struct {
		SchemaVersion   int    `json:"schemaVersion"`
		Control         string `json:"control"`
		ControlRevision uint64 `json:"controlRevision"`
		Rows            []struct {
			Kind        string   `json:"kind"`
			SnapshotKey string   `json:"snapshotKeySha256"`
			Cells       []string `json:"cells"`
		} `json:"rows"`
		Next *string `json:"next"`
	}
	if repository.query(ctx, ticketExportPageQuery, payload, &response, false) != nil ||
		response.SchemaVersion != ticketRuntimeWireVersion || response.Rows == nil || response.Next == nil ||
		len(response.Rows) > request.Limit {
		return ticketexport.PageResult{}, ticketexport.ErrUnavailable
	}
	control, err := ticketRuntimePageControl(response.Control)
	if err != nil {
		return ticketexport.PageResult{}, ticketexport.ErrInvalidProjection
	}
	rows := make([]ticketexport.Row, len(response.Rows))
	for index, item := range response.Rows {
		kind, err := ticketRuntimeRowKind(item.Kind)
		digest, digestErr := ticketRuntimeDigest(item.SnapshotKey)
		if err != nil || digestErr != nil {
			return ticketexport.PageResult{}, ticketexport.ErrInvalidProjection
		}
		rows[index] = ticketexport.Row{Kind: kind, SnapshotKey: digest, Cells: append([]string(nil), item.Cells...)}
	}
	return ticketexport.PageResult{
		Control: control, ControlRevision: response.ControlRevision,
		Page: ticketexport.Page{Rows: rows, NextCursor: *response.Next},
	}, nil
}

func (repository *TicketRuntimeRepository) RecordManifest(
	ctx context.Context,
	request ticketexport.ManifestRequest,
) (ticketexport.ManifestResult, error) {
	payload := struct {
		SchemaVersion int                              `json:"schemaVersion"`
		Identity      ticketRuntimeIdentityWireV1      `json:"identity"`
		Binding       ticketRuntimeExportBindingWireV1 `json:"binding"`
		ArtifactID    string                           `json:"artifactId"`
		SHA256        string                           `json:"sha256"`
		Rows          uint32                           `json:"rows"`
		Bytes         uint64                           `json:"bytes"`
		RecordedAt    time.Time                        `json:"recordedAt"`
	}{
		ticketRuntimeWireVersion, ticketRuntimeExportIdentity(request.Identity),
		ticketRuntimeExportBindingWire(request.Binding), request.ArtifactID.String(),
		hex.EncodeToString(request.Digest[:]), request.Rows, request.Bytes, request.RecordedAt,
	}
	var response struct {
		SchemaVersion   int                          `json:"schemaVersion"`
		Disposition     string                       `json:"disposition"`
		CurrentRevision uint64                       `json:"currentRevision"`
		Manifest        *ticketRuntimeManifestWireV1 `json:"manifest"`
	}
	if repository.query(ctx, ticketExportManifestQuery, payload, &response, false) != nil ||
		response.SchemaVersion != ticketRuntimeWireVersion {
		return ticketexport.ManifestResult{}, ticketexport.ErrUnavailable
	}
	disposition, err := ticketRuntimeManifestDisposition(response.Disposition)
	manifest, err := restoreTicketRuntimeManifest(response.Manifest, err)
	if err != nil {
		return ticketexport.ManifestResult{}, ticketexport.ErrInvalidProjection
	}
	return ticketexport.ManifestResult{
		Disposition: disposition, CurrentRevision: response.CurrentRevision, Manifest: manifest,
	}, nil
}

func (repository *TicketRuntimeRepository) CommitSuccess(
	ctx context.Context,
	request ticketexport.SuccessRequest,
) (ticketexport.CommitResult, error) {
	payload := struct {
		SchemaVersion int                              `json:"schemaVersion"`
		Identity      ticketRuntimeIdentityWireV1      `json:"identity"`
		Binding       ticketRuntimeExportBindingWireV1 `json:"binding"`
		ArtifactID    string                           `json:"artifactId"`
		SHA256        string                           `json:"sha256"`
		Rows          uint32                           `json:"rows"`
		Bytes         uint64                           `json:"bytes"`
		ExpiresAt     time.Time                        `json:"expiresAt"`
		CompletedAt   time.Time                        `json:"completedAt"`
	}{
		ticketRuntimeWireVersion, ticketRuntimeExportIdentity(request.Identity),
		ticketRuntimeExportBindingWire(request.Binding), request.ArtifactID.String(),
		hex.EncodeToString(request.Digest[:]), request.Rows, request.Bytes,
		request.ExpiresAt, request.CompletedAt,
	}
	var response struct {
		SchemaVersion   int                          `json:"schemaVersion"`
		Disposition     string                       `json:"disposition"`
		CurrentRevision uint64                       `json:"currentRevision"`
		Manifest        *ticketRuntimeManifestWireV1 `json:"manifest"`
	}
	if repository.query(ctx, ticketExportSuccessQuery, payload, &response, false) != nil ||
		response.SchemaVersion != ticketRuntimeWireVersion {
		return ticketexport.CommitResult{}, ticketexport.ErrUnavailable
	}
	disposition, err := ticketRuntimeCommitDisposition(response.Disposition)
	manifest, err := restoreTicketRuntimeManifest(response.Manifest, err)
	if err != nil {
		return ticketexport.CommitResult{}, ticketexport.ErrInvalidProjection
	}
	return ticketexport.CommitResult{
		Disposition: disposition, CurrentRevision: response.CurrentRevision, Manifest: manifest,
	}, nil
}

func (repository *TicketRuntimeRepository) ReportFailure(
	ctx context.Context,
	request ticketexport.FailureRequest,
) (ticketexport.FailureResult, error) {
	payload := struct {
		SchemaVersion int                              `json:"schemaVersion"`
		Identity      ticketRuntimeIdentityWireV1      `json:"identity"`
		Binding       ticketRuntimeExportBindingWireV1 `json:"binding"`
		Code          string                           `json:"code"`
		FailedAt      time.Time                        `json:"failedAt"`
		RetryAt       *time.Time                       `json:"retryAt"`
	}{
		ticketRuntimeWireVersion, ticketRuntimeExportIdentity(request.Identity),
		ticketRuntimeExportBindingWire(request.Binding), request.Code.String(), request.FailedAt,
		ticketRuntimeNonzeroTime(request.RetryAt),
	}
	var response struct {
		SchemaVersion   int        `json:"schemaVersion"`
		Disposition     string     `json:"disposition"`
		CurrentRevision uint64     `json:"currentRevision"`
		Code            string     `json:"code"`
		RetryAt         *time.Time `json:"retryAt"`
	}
	if repository.query(ctx, ticketExportFailureQuery, payload, &response, false) != nil ||
		response.SchemaVersion != ticketRuntimeWireVersion {
		return ticketexport.FailureResult{}, ticketexport.ErrUnavailable
	}
	disposition, err := ticketRuntimeExportFailureDisposition(response.Disposition)
	code, codeErr := ticketRuntimeExportFailure(response.Code)
	retryAt, retryErr := ticketRuntimeOptionalInstant(response.RetryAt)
	if err != nil || codeErr != nil || retryErr != nil {
		return ticketexport.FailureResult{}, ticketexport.ErrInvalidProjection
	}
	var normalizedRetryAt time.Time
	if retryAt != nil {
		normalizedRetryAt = *retryAt
	}
	return ticketexport.FailureResult{
		Disposition: disposition, CurrentRevision: response.CurrentRevision,
		Code: code, RetryAt: normalizedRetryAt,
	}, nil
}

func (repository *TicketRuntimeRepository) AcknowledgeCancellation(
	ctx context.Context,
	request ticketexport.CancellationRequest,
) (ticketexport.TransitionResult, error) {
	return repository.transitionExport(ctx, ticketExportCancelQuery, request.Identity, request.Binding,
		request.ExpectedRevision, request.AcknowledgedAt)
}

func (repository *TicketRuntimeRepository) RejectRevoked(
	ctx context.Context,
	request ticketexport.RevocationRequest,
) (ticketexport.TransitionResult, error) {
	return repository.transitionExport(ctx, ticketExportRevokeQuery, request.Identity, request.Binding,
		request.ExpectedRevision, request.RejectedAt)
}

func (repository *TicketRuntimeRepository) ClaimArtifactReconciliation(
	ctx context.Context,
	request ticketexport.ReconcileClaimRequest,
) ([]ticketexport.ReconcileClaim, error) {
	payload := struct {
		SchemaVersion int                         `json:"schemaVersion"`
		Identity      ticketRuntimeIdentityWireV1 `json:"identity"`
		TenantID      string                      `json:"tenantId"`
		Kind          string                      `json:"kind"`
		Audience      string                      `json:"audience"`
		Now           time.Time                   `json:"now"`
		LeaseMicros   int64                       `json:"leaseMicroseconds"`
		Limit         int                         `json:"limit"`
	}{
		ticketRuntimeWireVersion, ticketRuntimeReconcileIdentity(request.Identity),
		request.Queue.TenantID.String(), request.Queue.Kind.String(), request.Queue.Audience.String(),
		request.Now, request.LeaseDuration.Microseconds(), request.Limit,
	}
	var document json.RawMessage
	if repository.query(ctx, ticketExportReconcileClaimQuery, payload, &document, false) != nil {
		return nil, ticketexport.ErrUnavailable
	}
	var response struct {
		SchemaVersion int               `json:"schemaVersion"`
		Claims        []json.RawMessage `json:"claims"`
	}
	if err := decodeTicketRuntimeExactObject(document, &response, "schemaVersion", "claims"); err != nil ||
		response.SchemaVersion != ticketRuntimeWireVersion || response.Claims == nil ||
		len(response.Claims) > request.Limit {
		return nil, ticketexport.ErrInvalidProjection
	}
	claims := make([]ticketexport.ReconcileClaim, len(response.Claims))
	for index, claimDocument := range response.Claims {
		claim, err := restoreTicketRuntimeReconcileClaim(claimDocument)
		if err != nil {
			return nil, ticketexport.ErrInvalidProjection
		}
		claims[index] = claim
	}
	return claims, nil
}

func (repository *TicketRuntimeRepository) FinalizeArtifactReconciliation(
	ctx context.Context,
	request ticketexport.ReconcileFinalizeRequest,
) (ticketexport.ReconcileFinalizeResult, error) {
	payload := struct {
		SchemaVersion int                                     `json:"schemaVersion"`
		Identity      ticketRuntimeIdentityWireV1             `json:"identity"`
		Claim         ticketRuntimeReconcileClaimOutputWireV1 `json:"claim"`
		PurgedAt      time.Time                               `json:"purgedAt"`
	}{
		ticketRuntimeWireVersion, ticketRuntimeReconcileIdentity(request.Identity),
		ticketRuntimeReconcileClaimWire(request.Claim), request.PurgedAt,
	}
	wire, err := repository.ticketRuntimeReconcileResult(
		ctx, ticketExportReconcileFinalizeQuery, payload,
	)
	if err != nil {
		return ticketexport.ReconcileFinalizeResult{}, err
	}
	if wire.Code != "" || string(wire.RetryAt) != "null" {
		return ticketexport.ReconcileFinalizeResult{}, ticketexport.ErrInvalidProjection
	}
	disposition, err := ticketRuntimeReconcileFinalizeDisposition(wire.Disposition)
	if err != nil {
		return ticketexport.ReconcileFinalizeResult{}, ticketexport.ErrInvalidProjection
	}
	artifactID, reason, fence, err := restoreTicketRuntimeReconcileResultEcho(wire)
	if err != nil {
		return ticketexport.ReconcileFinalizeResult{}, ticketexport.ErrInvalidProjection
	}
	return ticketexport.ReconcileFinalizeResult{
		Disposition: disposition, CurrentCleanupRevision: wire.CurrentCleanupRevision,
		ArtifactID: artifactID, Reason: reason, CleanupFence: fence,
	}, nil
}

func (repository *TicketRuntimeRepository) ReportArtifactReconciliationFailure(
	ctx context.Context,
	request ticketexport.ReconcileFailureRequest,
) (ticketexport.ReconcileFailureResult, error) {
	payload := struct {
		SchemaVersion int                                     `json:"schemaVersion"`
		Identity      ticketRuntimeIdentityWireV1             `json:"identity"`
		Claim         ticketRuntimeReconcileClaimOutputWireV1 `json:"claim"`
		Code          string                                  `json:"code"`
		FailedAt      time.Time                               `json:"failedAt"`
		RetryAt       *time.Time                              `json:"retryAt"`
	}{
		ticketRuntimeWireVersion, ticketRuntimeReconcileIdentity(request.Identity),
		ticketRuntimeReconcileClaimWire(request.Claim), request.Code.String(), request.FailedAt,
		ticketRuntimeNonzeroTime(request.RetryAt),
	}
	wire, err := repository.ticketRuntimeReconcileResult(
		ctx, ticketExportReconcileFailureQuery, payload,
	)
	if err != nil {
		return ticketexport.ReconcileFailureResult{}, err
	}
	disposition, err := ticketRuntimeReconcileFailureDisposition(wire.Disposition)
	if err != nil {
		return ticketexport.ReconcileFailureResult{}, ticketexport.ErrInvalidProjection
	}
	artifactID, reason, fence, err := restoreTicketRuntimeReconcileResultEcho(wire)
	if err != nil {
		return ticketexport.ReconcileFailureResult{}, ticketexport.ErrInvalidProjection
	}
	code, err := ticketRuntimeReconcileFailureCode(wire.Code)
	if err != nil {
		return ticketexport.ReconcileFailureResult{}, ticketexport.ErrInvalidProjection
	}
	retryAt, err := ticketRuntimeReconcileRetryAt(wire.RetryAt)
	if err != nil {
		return ticketexport.ReconcileFailureResult{}, ticketexport.ErrInvalidProjection
	}
	return ticketexport.ReconcileFailureResult{
		Disposition: disposition, CurrentCleanupRevision: wire.CurrentCleanupRevision,
		Code: code, RetryAt: retryAt, ArtifactID: artifactID, Reason: reason,
		CleanupFence: fence,
	}, nil
}

func (repository *TicketRuntimeRepository) ReadReconciliationMetrics(
	ctx context.Context,
	identity ticketexport.ReconcileIdentity,
) (TicketExportReconciliationMetrics, error) {
	payload := struct {
		SchemaVersion int                         `json:"schemaVersion"`
		Identity      ticketRuntimeIdentityWireV1 `json:"identity"`
	}{ticketRuntimeWireVersion, ticketRuntimeReconcileIdentity(identity)}
	var document json.RawMessage
	if repository.query(ctx, ticketExportReconcileMetricsQuery, payload, &document, false) != nil {
		return TicketExportReconciliationMetrics{}, ticketexport.ErrUnavailable
	}
	var response struct {
		SchemaVersion             int       `json:"schemaVersion"`
		SnapshotAt                time.Time `json:"snapshotAt"`
		PendingEligible           int64     `json:"pendingEligible"`
		Reclaimable               int64     `json:"reclaimable"`
		DeadLettered              int64     `json:"deadLettered"`
		OldestPendingMicroseconds int64     `json:"oldestPendingMicroseconds"`
	}
	if err := decodeTicketRuntimeExactObject(
		document, &response, "schemaVersion", "snapshotAt", "pendingEligible",
		"reclaimable", "deadLettered", "oldestPendingMicroseconds",
	); err != nil || response.SchemaVersion != ticketRuntimeWireVersion ||
		response.PendingEligible < 0 || response.Reclaimable < 0 || response.DeadLettered < 0 ||
		response.OldestPendingMicroseconds < 0 ||
		response.PendingEligible == 0 && response.Reclaimable == 0 && response.OldestPendingMicroseconds != 0 {
		return TicketExportReconciliationMetrics{}, ticketexport.ErrInvalidProjection
	}
	snapshotAt, err := ticketRuntimeInstant(response.SnapshotAt)
	if err != nil {
		return TicketExportReconciliationMetrics{}, ticketexport.ErrInvalidProjection
	}
	return TicketExportReconciliationMetrics{
		SnapshotAt: snapshotAt, PendingEligible: response.PendingEligible,
		Reclaimable: response.Reclaimable, DeadLettered: response.DeadLettered,
		OldestPendingMicros: response.OldestPendingMicroseconds,
	}, nil
}

func (repository *TicketRuntimeRepository) ticketRuntimeReconcileResult(
	ctx context.Context,
	query string,
	payload any,
) (ticketRuntimeReconcileResultWireV1, error) {
	var document json.RawMessage
	if repository.query(ctx, query, payload, &document, false) != nil {
		return ticketRuntimeReconcileResultWireV1{}, ticketexport.ErrUnavailable
	}
	var wire ticketRuntimeReconcileResultWireV1
	if err := decodeTicketRuntimeExactObject(
		document, &wire, "schemaVersion", "disposition", "currentCleanupRevision",
		"artifactId", "reason", "cleanupFenceSha256", "code", "retryAt",
	); err != nil || wire.SchemaVersion != ticketRuntimeWireVersion || wire.RetryAt == nil {
		return ticketRuntimeReconcileResultWireV1{}, ticketexport.ErrInvalidProjection
	}
	return wire, nil
}

func (repository *TicketRuntimeRepository) transitionExport(
	ctx context.Context,
	query string,
	identity ticketexport.Identity,
	binding ticketexport.LeaseBinding,
	expectedRevision uint64,
	transitionedAt time.Time,
) (ticketexport.TransitionResult, error) {
	payload := struct {
		SchemaVersion    int                              `json:"schemaVersion"`
		Identity         ticketRuntimeIdentityWireV1      `json:"identity"`
		Binding          ticketRuntimeExportBindingWireV1 `json:"binding"`
		ExpectedRevision uint64                           `json:"expectedRevision"`
		TransitionedAt   time.Time                        `json:"transitionedAt"`
	}{ticketRuntimeWireVersion, ticketRuntimeExportIdentity(identity), ticketRuntimeExportBindingWire(binding), expectedRevision, transitionedAt}
	var response struct {
		SchemaVersion   int    `json:"schemaVersion"`
		Disposition     string `json:"disposition"`
		CurrentRevision uint64 `json:"currentRevision"`
	}
	if repository.query(ctx, query, payload, &response, false) != nil ||
		response.SchemaVersion != ticketRuntimeWireVersion {
		return ticketexport.TransitionResult{}, ticketexport.ErrUnavailable
	}
	disposition, err := ticketRuntimeTransitionDisposition(response.Disposition)
	if err != nil {
		return ticketexport.TransitionResult{}, ticketexport.ErrInvalidProjection
	}
	return ticketexport.TransitionResult{Disposition: disposition, CurrentRevision: response.CurrentRevision}, nil
}

func restoreTicketRuntimeExportJob(
	wire ticketRuntimeExportJobWireV1,
) (kernel.TicketExportJob, error) {
	definition, err := restoreTicketRuntimeExportDefinition(wire.Definition)
	if err != nil {
		return kernel.TicketExportJob{}, err
	}
	state, err := ticketRuntimeExportState(wire.State)
	if err != nil {
		return kernel.TicketExportJob{}, err
	}
	failure, err := ticketRuntimeExportFailure(wire.FailureCode)
	if err != nil {
		return kernel.TicketExportJob{}, err
	}
	var lease *kernel.TicketExportLease
	if wire.Lease != nil {
		worker, parseErr := ticketRuntimeEntity(wire.Lease.WorkerID)
		fence, digestErr := ticketRuntimeDigest(wire.Lease.Fence)
		claimedAt, claimedErr := ticketRuntimeInstant(wire.Lease.ClaimedAt)
		expiresAt, expiresErr := ticketRuntimeInstant(wire.Lease.ExpiresAt)
		if parseErr != nil || digestErr != nil || claimedErr != nil || expiresErr != nil {
			return kernel.TicketExportJob{}, errors.New("ticket export lease projection is invalid")
		}
		parsed, leaseErr := kernel.NewTicketExportLease(
			worker, fence, claimedAt, expiresAt,
		)
		if leaseErr != nil {
			return kernel.TicketExportJob{}, errors.New("ticket export lease projection is invalid")
		}
		lease = &parsed
	}
	var artifact *kernel.TicketExportArtifact
	if wire.Artifact != nil {
		id, parseErr := ticketRuntimeEntity(wire.Artifact.ID)
		digest, digestErr := ticketRuntimeDigest(wire.Artifact.SHA256)
		expiresAt, expiresErr := ticketRuntimeInstant(wire.Artifact.ExpiresAt)
		if parseErr != nil || digestErr != nil || expiresErr != nil {
			return kernel.TicketExportJob{}, errors.New("ticket export artifact projection is invalid")
		}
		parsed, artifactErr := kernel.NewTicketExportArtifact(
			id, digest, wire.Artifact.Rows, wire.Artifact.Bytes, expiresAt,
		)
		if artifactErr != nil {
			return kernel.TicketExportJob{}, errors.New("ticket export artifact projection is invalid")
		}
		artifact = &parsed
	}
	requestedAt, err := ticketRuntimeInstant(wire.RequestedAt)
	if err != nil {
		return kernel.TicketExportJob{}, err
	}
	updatedAt, err := ticketRuntimeInstant(wire.UpdatedAt)
	if err != nil {
		return kernel.TicketExportJob{}, err
	}
	availableAt, err := ticketRuntimeInstant(wire.AvailableAt)
	if err != nil {
		return kernel.TicketExportJob{}, err
	}
	expiresAt, err := ticketRuntimeInstant(wire.ExpiresAt)
	if err != nil {
		return kernel.TicketExportJob{}, err
	}
	terminalAt, err := ticketRuntimeOptionalInstant(wire.TerminalAt)
	if err != nil {
		return kernel.TicketExportJob{}, err
	}
	job, err := kernel.RestoreTicketExportJob(kernel.TicketExportJobSnapshot{
		Definition: definition, State: state, Revision: wire.Revision, Attempts: wire.Attempts,
		FailureCode: failure, RequestedAt: requestedAt, UpdatedAt: updatedAt,
		AvailableAt: availableAt, ExpiresAt: expiresAt, Lease: lease,
		Artifact: artifact, TerminalAt: terminalAt,
	})
	if err != nil {
		return kernel.TicketExportJob{}, errors.New("ticket export job projection is invalid")
	}
	return job, nil
}

func restoreTicketRuntimeExportDefinition(
	wire ticketRuntimeExportDefinitionWireV1,
) (kernel.TicketExportDefinition, error) {
	id, err := ticketRuntimeEntity(wire.ID)
	if err != nil {
		return kernel.TicketExportDefinition{}, err
	}
	tenant, err := ticketRuntimeEntity(wire.TenantID)
	if err != nil {
		return kernel.TicketExportDefinition{}, err
	}
	requester, err := ticketRuntimeEntity(wire.RequesterID)
	if err != nil {
		return kernel.TicketExportDefinition{}, err
	}
	owner, err := ticketRuntimeEntity(wire.OwnerMembershipID)
	if err != nil {
		return kernel.TicketExportDefinition{}, err
	}
	var contact *kernel.EntityID
	if wire.CustomerContactID != "" {
		parsed, err := ticketRuntimeEntity(wire.CustomerContactID)
		if err != nil {
			return kernel.TicketExportDefinition{}, err
		}
		contact = &parsed
	}
	kind, err := ticketRuntimeKind(wire.Kind)
	if err != nil {
		return kernel.TicketExportDefinition{}, err
	}
	audience, err := ticketRuntimeAudience(wire.Audience)
	if err != nil {
		return kernel.TicketExportDefinition{}, err
	}
	comments, err := ticketRuntimeExportComments(wire.CommentScope)
	if err != nil {
		return kernel.TicketExportDefinition{}, err
	}
	source, err := ticketRuntimeExportSource(wire.QuerySource)
	if err != nil {
		return kernel.TicketExportDefinition{}, err
	}
	savedView, err := restoreTicketRuntimeExportSavedView(wire.SavedView)
	if err != nil {
		return kernel.TicketExportDefinition{}, err
	}
	queryDigest, err := ticketRuntimeDigest(wire.QuerySHA256)
	if err != nil {
		return kernel.TicketExportDefinition{}, err
	}
	catalogDigest, err := ticketRuntimeDigest(wire.CatalogSHA256)
	if err != nil {
		return kernel.TicketExportDefinition{}, err
	}
	if wire.Format != kernel.TicketExportCSV.String() {
		return kernel.TicketExportDefinition{}, errors.New("ticket export format projection is invalid")
	}
	definition, err := kernel.NewTicketExportDefinition(kernel.TicketExportDefinitionInput{
		ID: id, Tenant: tenant, Requester: requester, OwnerMembership: owner,
		CustomerContact: contact, Kind: kind, Audience: audience, Comments: comments,
		QuerySource: source, SavedView: savedView, QueryDigest: queryDigest,
		CatalogDigest: catalogDigest, ProjectionVersion: wire.ProjectionVersion,
		Format: kernel.TicketExportCSV, MaximumRows: wire.MaximumRows,
		MaximumBytes: wire.MaximumBytes, MaximumAttempts: wire.MaximumAttempts,
	})
	if err != nil {
		return kernel.TicketExportDefinition{}, errors.New("ticket export definition projection is invalid")
	}
	return definition, nil
}

func restoreTicketRuntimeExportSavedView(
	wire *ticketRuntimeSavedViewWireV1,
) (*kernel.TicketExportSavedViewPin, error) {
	if wire == nil {
		return nil, nil
	}
	id, err := ticketRuntimeEntity(wire.ID)
	if err != nil {
		return nil, err
	}
	owner, err := ticketRuntimeEntity(wire.OwnerID)
	if err != nil {
		return nil, err
	}
	digest, err := ticketRuntimeDigest(wire.SpecSHA256)
	if err != nil {
		return nil, err
	}
	pin, err := kernel.NewTicketExportSavedViewPin(id, owner, wire.Revision, digest)
	if err != nil {
		return nil, errors.New("ticket export saved-view projection is invalid")
	}
	return &pin, nil
}

func ticketRuntimeExportBindingWire(binding ticketexport.LeaseBinding) ticketRuntimeExportBindingWireV1 {
	return ticketRuntimeExportBindingWireV1{
		TenantID: binding.TenantID.String(), JobID: binding.JobID.String(), Kind: binding.Kind.String(),
		Audience: binding.Audience.String(), WorkerID: binding.WorkerID.String(),
		Revision: binding.Revision, Attempt: binding.Attempt,
		FenceSHA256:       hex.EncodeToString(binding.Fence[:]),
		QuerySHA256:       hex.EncodeToString(binding.QueryDigest[:]),
		CatalogSHA256:     hex.EncodeToString(binding.CatalogDigest[:]),
		ProjectionVersion: binding.ProjectionVersion, LeaseClaimedAt: binding.LeaseClaimedAt,
		LeaseExpiresAt: binding.LeaseExpiresAt, JobExpiresAt: binding.JobExpiresAt,
	}
}

func restoreTicketRuntimeManifest(
	wire *ticketRuntimeManifestWireV1,
	prior error,
) (ticketexport.StreamManifest, error) {
	if prior != nil || wire == nil {
		return ticketexport.StreamManifest{}, prior
	}
	id, err := ticketRuntimeEntity(wire.ArtifactID)
	if err != nil {
		return ticketexport.StreamManifest{}, err
	}
	digest, err := ticketRuntimeDigest(wire.SHA256)
	if err != nil {
		return ticketexport.StreamManifest{}, err
	}
	return ticketexport.StreamManifest{ArtifactID: id, Digest: digest, Rows: wire.Rows, Bytes: wire.Bytes}, nil
}

func ticketRuntimePageControl(value string) (ticketexport.PageControl, error) {
	switch value {
	case "ready":
		return ticketexport.PageReady, nil
	case "cancellation_requested":
		return ticketexport.PageCancellationRequested, nil
	case "authorization_revoked":
		return ticketexport.PageAuthorizationRevoked, nil
	case "fence_lost":
		return ticketexport.PageFenceLost, nil
	case "snapshot_stale":
		return ticketexport.PageSnapshotStale, nil
	default:
		return 0, errors.New("ticket export page control is invalid")
	}
}

func ticketRuntimeRowKind(value string) (ticketexport.RowKind, error) {
	switch value {
	case ticketexport.RowTicket.String():
		return ticketexport.RowTicket, nil
	case ticketexport.RowPublicComment.String():
		return ticketexport.RowPublicComment, nil
	case ticketexport.RowPrivateComment.String():
		return ticketexport.RowPrivateComment, nil
	default:
		return 0, errors.New("ticket export row kind is invalid")
	}
}

func ticketRuntimeManifestDisposition(value string) (ticketexport.ManifestDisposition, error) {
	switch value {
	case "recorded":
		return ticketexport.ManifestRecorded, nil
	case "cancellation_requested":
		return ticketexport.ManifestCancellationRequested, nil
	case "authorization_revoked":
		return ticketexport.ManifestAuthorizationRevoked, nil
	case "fence_lost":
		return ticketexport.ManifestFenceLost, nil
	case "snapshot_stale":
		return ticketexport.ManifestSnapshotStale, nil
	default:
		return 0, errors.New("ticket export manifest disposition is invalid")
	}
}

func ticketRuntimeCommitDisposition(value string) (ticketexport.CommitDisposition, error) {
	switch value {
	case "applied":
		return ticketexport.CommitApplied, nil
	case "replayed":
		return ticketexport.CommitReplayed, nil
	case "cancellation_requested":
		return ticketexport.CommitCancellationRequested, nil
	case "authorization_revoked":
		return ticketexport.CommitAuthorizationRevoked, nil
	case "fence_lost":
		return ticketexport.CommitFenceLost, nil
	case "snapshot_stale":
		return ticketexport.CommitSnapshotStale, nil
	default:
		return 0, errors.New("ticket export commit disposition is invalid")
	}
}

func ticketRuntimeExportFailureDisposition(value string) (ticketexport.FailureDisposition, error) {
	switch value {
	case "retry_scheduled":
		return ticketexport.FailureRetryScheduled, nil
	case "terminal":
		return ticketexport.FailureTerminal, nil
	case "replay_retry":
		return ticketexport.FailureReplayRetry, nil
	case "replay_terminal":
		return ticketexport.FailureReplayTerminal, nil
	case "cancellation_requested":
		return ticketexport.FailureCancellationRequested, nil
	case "authorization_revoked":
		return ticketexport.FailureAuthorizationRevoked, nil
	case "fence_lost":
		return ticketexport.FailureFenceLost, nil
	default:
		return 0, errors.New("ticket export failure disposition is invalid")
	}
}

func ticketRuntimeTransitionDisposition(value string) (ticketexport.TransitionDisposition, error) {
	switch value {
	case "applied":
		return ticketexport.TransitionApplied, nil
	case "replayed":
		return ticketexport.TransitionReplayed, nil
	case "fence_lost":
		return ticketexport.TransitionFenceLost, nil
	default:
		return 0, errors.New("ticket export transition disposition is invalid")
	}
}

func ticketRuntimeExportComments(value string) (kernel.TicketExportCommentScope, error) {
	for _, scope := range []kernel.TicketExportCommentScope{
		kernel.TicketExportCommentsNone, kernel.TicketExportCommentsPublic,
		kernel.TicketExportCommentsPublicAndPrivate,
	} {
		if scope.String() == value {
			return scope, nil
		}
	}
	return 0, errors.New("ticket export comment scope is invalid")
}

func ticketRuntimeExportSource(value string) (kernel.TicketExportQuerySource, error) {
	switch value {
	case kernel.TicketExportQueryInline.String():
		return kernel.TicketExportQueryInline, nil
	case kernel.TicketExportQuerySavedView.String():
		return kernel.TicketExportQuerySavedView, nil
	default:
		return 0, errors.New("ticket export query source is invalid")
	}
}

func ticketRuntimeExportState(value string) (kernel.TicketExportState, error) {
	for _, state := range []kernel.TicketExportState{
		kernel.TicketExportPending, kernel.TicketExportRunning,
		kernel.TicketExportCancellationRequested, kernel.TicketExportSucceeded,
		kernel.TicketExportFailed, kernel.TicketExportCancelledState,
	} {
		if state.String() == value {
			return state, nil
		}
	}
	return 0, errors.New("ticket export state is invalid")
}

func ticketRuntimeExportFailure(value string) (kernel.TicketExportFailureCode, error) {
	for _, code := range []kernel.TicketExportFailureCode{
		kernel.TicketExportFailureNone, kernel.TicketExportFailureTransientStorage,
		kernel.TicketExportFailureTransientDatabase,
		kernel.TicketExportFailureAuthorizationRevoked, kernel.TicketExportFailureSnapshotStale,
		kernel.TicketExportFailureOutputLimit, kernel.TicketExportFailureLeaseExpired,
		kernel.TicketExportFailureExpired, kernel.TicketExportFailureInternal,
	} {
		if code.String() == value {
			return code, nil
		}
	}
	return 0, errors.New("ticket export failure code is invalid")
}

func ticketRuntimeNonzeroTime(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	return &value
}

func ticketRuntimeReconcileClaimWire(
	claim ticketexport.ReconcileClaim,
) ticketRuntimeReconcileClaimOutputWireV1 {
	artifact := claim.Artifact
	return ticketRuntimeReconcileClaimOutputWireV1{
		Artifact: ticketRuntimeReconcileArtifactWireV1{
			TenantID: artifact.TenantID.String(), JobID: artifact.JobID.String(),
			ArtifactID: artifact.ArtifactID.String(), Kind: artifact.Kind.String(),
			Audience: artifact.Audience.String(), ObjectRevision: artifact.ObjectRevision,
			ObjectAttempt: artifact.ObjectAttempt, ProjectionVersion: artifact.ProjectionVersion,
			SHA256: hex.EncodeToString(artifact.Digest[:]), Rows: artifact.Rows, Bytes: artifact.Bytes,
		},
		Reason: claim.Reason.String(), JobRevision: claim.JobRevision,
		CleanupRevision: claim.CleanupRevision, CleanupAttempt: claim.CleanupAttempt,
		CleanupFenceSHA256: hex.EncodeToString(claim.CleanupFence[:]),
		EligibleAt:         claim.EligibleAt, ClaimedAt: claim.ClaimedAt,
		LeaseExpiresAt: claim.LeaseExpiresAt,
	}
}

func restoreTicketRuntimeReconcileClaim(
	document json.RawMessage,
) (ticketexport.ReconcileClaim, error) {
	var wire ticketRuntimeReconcileClaimWireV1
	if err := decodeTicketRuntimeExactObject(
		document, &wire, "artifact", "reason", "jobRevision", "cleanupRevision",
		"cleanupAttempt", "cleanupFenceSha256", "eligibleAt", "claimedAt", "leaseExpiresAt",
	); err != nil || wire.Artifact == nil {
		return ticketexport.ReconcileClaim{}, errors.New("ticket export reconciliation claim projection is invalid")
	}
	var artifactWire ticketRuntimeReconcileArtifactWireV1
	if err := decodeTicketRuntimeExactObject(
		wire.Artifact, &artifactWire, "tenantId", "jobId", "artifactId", "kind", "audience",
		"objectRevision", "objectAttempt", "projectionVersion", "sha256", "rows", "bytes",
	); err != nil {
		return ticketexport.ReconcileClaim{}, errors.New("ticket export reconciliation artifact projection is invalid")
	}
	tenantID, err := ticketRuntimeEntity(artifactWire.TenantID)
	if err != nil {
		return ticketexport.ReconcileClaim{}, err
	}
	jobID, err := ticketRuntimeEntity(artifactWire.JobID)
	if err != nil {
		return ticketexport.ReconcileClaim{}, err
	}
	artifactID, err := ticketRuntimeEntity(artifactWire.ArtifactID)
	if err != nil {
		return ticketexport.ReconcileClaim{}, err
	}
	kind, err := ticketRuntimeKind(artifactWire.Kind)
	if err != nil {
		return ticketexport.ReconcileClaim{}, err
	}
	audience, err := ticketRuntimeAudience(artifactWire.Audience)
	if err != nil {
		return ticketexport.ReconcileClaim{}, err
	}
	digest, err := ticketRuntimeDigest(artifactWire.SHA256)
	if err != nil {
		return ticketexport.ReconcileClaim{}, err
	}
	reason, err := ticketRuntimeReconcileReason(wire.Reason)
	if err != nil {
		return ticketexport.ReconcileClaim{}, err
	}
	fence, err := ticketRuntimeDigest(wire.CleanupFenceSHA256)
	if err != nil {
		return ticketexport.ReconcileClaim{}, err
	}
	eligibleAt, err := ticketRuntimeInstant(wire.EligibleAt)
	if err != nil {
		return ticketexport.ReconcileClaim{}, err
	}
	claimedAt, err := ticketRuntimeInstant(wire.ClaimedAt)
	if err != nil {
		return ticketexport.ReconcileClaim{}, err
	}
	leaseExpiresAt, err := ticketRuntimeInstant(wire.LeaseExpiresAt)
	if err != nil {
		return ticketexport.ReconcileClaim{}, err
	}
	return ticketexport.ReconcileClaim{
		Artifact: ticketexport.ReconcileArtifact{
			TenantID: tenantID, JobID: jobID, ArtifactID: artifactID, Kind: kind,
			Audience: audience, ObjectRevision: artifactWire.ObjectRevision,
			ObjectAttempt:     artifactWire.ObjectAttempt,
			ProjectionVersion: artifactWire.ProjectionVersion,
			Digest:            digest, Rows: artifactWire.Rows, Bytes: artifactWire.Bytes,
		},
		Reason: reason, JobRevision: wire.JobRevision, CleanupRevision: wire.CleanupRevision,
		CleanupAttempt: wire.CleanupAttempt, CleanupFence: fence, EligibleAt: eligibleAt,
		ClaimedAt: claimedAt, LeaseExpiresAt: leaseExpiresAt,
	}, nil
}

func restoreTicketRuntimeReconcileResultEcho(
	wire ticketRuntimeReconcileResultWireV1,
) (kernel.EntityID, ticketexport.ReconcileReason, [sha256.Size]byte, error) {
	var artifactID kernel.EntityID
	var reason ticketexport.ReconcileReason
	var fence [sha256.Size]byte
	var err error
	if wire.ArtifactID != "" {
		artifactID, err = ticketRuntimeEntity(wire.ArtifactID)
		if err != nil {
			return kernel.EntityID{}, 0, [sha256.Size]byte{}, err
		}
	}
	if wire.Reason != "" {
		reason, err = ticketRuntimeReconcileReason(wire.Reason)
		if err != nil {
			return kernel.EntityID{}, 0, [sha256.Size]byte{}, err
		}
	}
	if wire.CleanupFenceSHA256 != "" {
		fence, err = ticketRuntimeDigest(wire.CleanupFenceSHA256)
		if err != nil {
			return kernel.EntityID{}, 0, [sha256.Size]byte{}, err
		}
	}
	return artifactID, reason, fence, nil
}

func ticketRuntimeReconcileRetryAt(document json.RawMessage) (time.Time, error) {
	if bytes.Equal(bytes.TrimSpace(document), []byte("null")) {
		return time.Time{}, nil
	}
	var value time.Time
	if err := decodeTicketRuntimeJSONValue(document, &value); err != nil {
		return time.Time{}, err
	}
	return ticketRuntimeInstant(value)
}

func ticketRuntimeReconcileReason(value string) (ticketexport.ReconcileReason, error) {
	switch value {
	case ticketexport.ReconcileExpired.String():
		return ticketexport.ReconcileExpired, nil
	case ticketexport.ReconcileOrphaned.String():
		return ticketexport.ReconcileOrphaned, nil
	default:
		return 0, errors.New("ticket export reconciliation reason is invalid")
	}
}

func ticketRuntimeReconcileFailureCode(value string) (ticketexport.ReconcileFailureCode, error) {
	switch value {
	case "":
		return 0, nil
	case ticketexport.ReconcileFailureStorageUnavailable.String():
		return ticketexport.ReconcileFailureStorageUnavailable, nil
	case ticketexport.ReconcileFailureObjectConflict.String():
		return ticketexport.ReconcileFailureObjectConflict, nil
	default:
		return 0, errors.New("ticket export reconciliation failure code is invalid")
	}
}

func ticketRuntimeReconcileFinalizeDisposition(
	value string,
) (ticketexport.ReconcileFinalizeDisposition, error) {
	switch value {
	case "applied":
		return ticketexport.ReconcileFinalizeApplied, nil
	case "replayed":
		return ticketexport.ReconcileFinalizeReplayed, nil
	case "fence_lost":
		return ticketexport.ReconcileFinalizeFenceLost, nil
	default:
		return 0, errors.New("ticket export reconciliation finalize disposition is invalid")
	}
}

func ticketRuntimeReconcileFailureDisposition(
	value string,
) (ticketexport.ReconcileFailureDisposition, error) {
	switch value {
	case "retry_scheduled":
		return ticketexport.ReconcileFailureRetryScheduled, nil
	case "dead_lettered":
		return ticketexport.ReconcileFailureDeadLettered, nil
	case "replay_retry":
		return ticketexport.ReconcileFailureReplayRetry, nil
	case "replay_dead_letter":
		return ticketexport.ReconcileFailureReplayDeadLetter, nil
	case "fence_lost":
		return ticketexport.ReconcileFailureFenceLost, nil
	default:
		return 0, errors.New("ticket export reconciliation failure disposition is invalid")
	}
}

func decodeTicketRuntimeExactObject(document json.RawMessage, target any, expected ...string) error {
	if target == nil || len(document) == 0 || len(document) > ticketRuntimeMaximumResponse {
		return errors.New("ticket runtime object is invalid")
	}
	var object map[string]json.RawMessage
	if err := decodeTicketRuntimeJSONValue(document, &object); err != nil || len(object) != len(expected) {
		return errors.New("ticket runtime object shape is invalid")
	}
	for _, key := range expected {
		if _, found := object[key]; !found {
			return errors.New("ticket runtime object shape is invalid")
		}
	}
	return decodeTicketRuntimeJSONValue(document, target)
}

func decodeTicketRuntimeJSONValue(document json.RawMessage, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("ticket runtime value has trailing data")
	}
	return nil
}
