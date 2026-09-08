package postgres

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

const (
	ticketBulkResolveAccessABIQuery = `SELECT response FROM app.resolve_ticket_bulk_access_v1($1::jsonb)`
	ticketBulkResolveQueryABIQuery  = `SELECT response FROM app.resolve_ticket_bulk_query_v1($1::jsonb)`
	ticketBulkReplayABIQuery        = `SELECT response FROM app.lookup_ticket_bulk_replay_v1($1::jsonb)`
	ticketBulkCommitRequestABIQuery = `SELECT response FROM app.commit_ticket_bulk_request_v1($1::jsonb)`
	ticketBulkGetABIQuery           = `SELECT response FROM app.get_ticket_bulk_v1($1::jsonb)`
	ticketBulkCancelABIQuery        = `SELECT response FROM app.commit_ticket_bulk_cancellation_v1($1::jsonb)`
	ticketBulkListResultsABIQuery   = `SELECT response FROM app.list_ticket_bulk_results_v1($1::jsonb)`

	ticketExportResolveAccessABIQuery    = `SELECT response FROM app.resolve_ticket_export_access_v2($1::jsonb)`
	ticketExportResolveQueryABIQuery     = `SELECT response FROM app.resolve_ticket_export_query_v2($1::jsonb)`
	ticketExportReplayABIQuery           = `SELECT response FROM app.lookup_ticket_export_replay_v2($1::jsonb)`
	ticketExportCommitRequestABIQuery    = `SELECT response FROM app.commit_ticket_export_request_v2($1::jsonb)`
	ticketExportGetABIQuery              = `SELECT response FROM app.get_ticket_export_v2($1::jsonb)`
	ticketExportOwnerTransitionQuery     = `SELECT response FROM app.commit_ticket_export_owner_transition_v2($1::jsonb)`
	ticketExportResolveWorkerAccessQuery = `SELECT response FROM app.resolve_ticket_export_worker_access_v2($1::jsonb)`
	ticketExportSelectCandidateQuery     = `SELECT response FROM app.select_ticket_export_claim_candidate_v2($1::jsonb)`
	ticketExportGetForWorkerQuery        = `SELECT response FROM app.get_ticket_export_for_worker_v2($1::jsonb)`
	ticketExportGetRevokedQuery          = `SELECT response FROM app.get_revoked_ticket_export_for_worker_v2($1::jsonb)`
	ticketExportWorkerTransitionQuery    = `SELECT response FROM app.commit_ticket_export_worker_transition_v2($1::jsonb)`
	ticketExportCommitRevocationQuery    = `SELECT response FROM app.commit_ticket_export_revocation_v2($1::jsonb)`
	ticketExportReadPageQuery            = `SELECT response FROM app.read_ticket_export_application_page_v2($1::jsonb)`

	ticketBulkReadinessABIQuery   = `SELECT app.ticket_bulk_runtime_schema_readiness_v62()`
	ticketExportReadinessABIQuery = `SELECT app.ticket_export_runtime_schema_readiness_v62()`
	ticketMetadataReadinessQuery  = `SELECT app.ticket_metadata_runtime_schema_readiness_v62()`
)

type ticketOperationsBulkAccessResponseV1 struct {
	SchemaVersion  int    `json:"schemaVersion"`
	TenantID       string `json:"tenantId"`
	ActorID        string `json:"actorId"`
	MembershipID   string `json:"membershipId"`
	Kind           string `json:"kind"`
	Capability     string `json:"capability"`
	Principal      string `json:"principal"`
	MutationAction string `json:"mutationAction"`
	Allowed        *bool  `json:"allowed"`
}

type ticketOperationsExportAccessResponseV1 struct {
	SchemaVersion     int    `json:"schemaVersion"`
	TenantID          string `json:"tenantId"`
	ActorID           string `json:"actorId"`
	MembershipID      string `json:"membershipId"`
	Kind              string `json:"kind"`
	Audience          string `json:"audience"`
	Capability        string `json:"capability"`
	Principal         string `json:"principal"`
	CustomerContactID string `json:"customerContactId"`
	PublicComments    *bool  `json:"publicComments"`
	PrivateComments   *bool  `json:"privateComments"`
	Allowed           *bool  `json:"allowed"`
}

type ticketOperationsBulkResultResponseV1 struct {
	SchemaVersion int                              `json:"schemaVersion"`
	Replayed      *bool                            `json:"replayed"`
	Fingerprint   string                           `json:"requestFingerprintSha256"`
	Record        ticketOperationsBulkRecordWireV1 `json:"record"`
}

type ticketOperationsExportResultResponseV1 struct {
	SchemaVersion int                                `json:"schemaVersion"`
	Replayed      *bool                              `json:"replayed"`
	Fingerprint   string                             `json:"requestFingerprintSha256"`
	Record        ticketOperationsExportRecordWireV1 `json:"record"`
}

type ticketOperationsBulkGetResponseV1 struct {
	SchemaVersion int                              `json:"schemaVersion"`
	Record        ticketOperationsBulkRecordWireV1 `json:"record"`
}

type ticketOperationsExportGetResponseV1 struct {
	SchemaVersion int                                `json:"schemaVersion"`
	Record        ticketOperationsExportRecordWireV1 `json:"record"`
}

type ticketOperationsBulkResultItemWireV1 struct {
	Sequence      uint32    `json:"sequence"`
	TargetID      string    `json:"targetId"`
	TargetVersion uint64    `json:"targetVersion"`
	Result        string    `json:"result"`
	RecordedAt    time.Time `json:"recordedAt"`
}

type ticketOperationsBulkResultPageWireV1 struct {
	SchemaVersion int                                    `json:"schemaVersion"`
	Items         []ticketOperationsBulkResultItemWireV1 `json:"items"`
	Next          *string                                `json:"next"`
}

var (
	_ application.TicketBulkRepository  = (*TicketingRepository)(nil)
	_ application.AsyncExportRepository = (*TicketingRepository)(nil)
)

// ReadyTicketOperations fails closed unless every independently versioned
// database surface is present and reports its complete catalog/RLS/ACL
// invariants. A missing function, NULL, cancellation, or typed-nil repository
// is never interpreted as rolling compatibility.
func (repository *TicketingRepository) ReadyTicketOperations(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || repository == nil || repository.begin == nil {
		return application.ErrUnavailable
	}
	if runtimeVerifiedInProbe(ctx, repository.pool) {
		return nil
	}
	operationContext, cancel := context.WithTimeout(ctx, savedViewDatabaseTimeout)
	defer cancel()
	ready, err := withinTransactionWithOptions(
		operationContext, repository.begin, phase4ReadOptions(),
		func(tx databaseTransaction) (bool, error) {
			var bulkReady, exportReady, metadataReady bool
			if err := tx.QueryRow(operationContext, ticketBulkReadinessABIQuery).Scan(&bulkReady); err != nil {
				return false, err
			}
			if err := tx.QueryRow(operationContext, ticketExportReadinessABIQuery).Scan(&exportReady); err != nil {
				return false, err
			}
			if err := tx.QueryRow(operationContext, ticketMetadataReadinessQuery).Scan(&metadataReady); err != nil {
				return false, err
			}
			return bulkReady && exportReady && metadataReady, nil
		},
	)
	if err != nil || !ready || operationContext.Err() != nil {
		return application.ErrUnavailable
	}
	return nil
}

func (repository *TicketingRepository) ResolveTicketBulkAccess(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	capability application.TicketBulkCapability,
	mutation kernel.Action,
) (application.TicketBulkAccess, error) {
	request := struct {
		SchemaVersion  int                         `json:"schemaVersion"`
		Actor          ticketOperationsActorWireV1 `json:"actor"`
		TenantID       string                      `json:"tenantId"`
		Kind           string                      `json:"kind"`
		Capability     string                      `json:"capability"`
		MutationAction string                      `json:"mutationAction"`
	}{ticketOperationsWireVersion, ticketOperationsActorWire(actor), tenantID.String(), kind.String(), string(capability), mutation.String()}
	document, err := repository.callTicketOperationsHuman(
		ctx, actor, tenantID, ticketOperationsReadOptions(), ticketBulkResolveAccessABIQuery, request, false,
	)
	if err != nil {
		return application.TicketBulkAccess{}, err
	}
	var response ticketOperationsBulkAccessResponseV1
	if err := decodeTicketOperations(document, &response); err != nil ||
		response.SchemaVersion != ticketOperationsWireVersion || response.Allowed == nil ||
		response.TenantID != tenantID.String() || response.ActorID != actor.UserID.String() ||
		response.Kind != kind.String() || response.Capability != string(capability) {
		return application.TicketBulkAccess{}, application.ErrUnavailable
	}
	membership, err := uuid.Parse(response.MembershipID)
	if err != nil || !authorizationUUIDv7(membership) {
		return application.TicketBulkAccess{}, application.ErrUnavailable
	}
	principal, err := ticketOperationsPrincipal(response.Principal)
	if err != nil {
		return application.TicketBulkAccess{}, err
	}
	responseMutation := kernel.Action(0)
	if response.MutationAction != "" {
		responseMutation, err = ticketOperationsAction(response.MutationAction)
		if err != nil {
			return application.TicketBulkAccess{}, err
		}
	}
	access, err := application.NewTicketBulkAccess(
		tenantID, actor.UserID, membership, kind, capability, principal, responseMutation, *response.Allowed,
	)
	if err != nil || responseMutation != mutation {
		return application.TicketBulkAccess{}, application.ErrUnavailable
	}
	return access, nil
}

func (repository *TicketingRepository) ResolveTicketBulkQuery(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	source application.TicketBulkQuerySourceInput,
	access application.TicketBulkAccess,
) (application.TicketBulkQuerySnapshot, error) {
	wireSource, err := ticketOperationsBulkSourceRequest(
		actor, tenantID, access.Membership(), kind, source,
	)
	if err != nil {
		return application.TicketBulkQuerySnapshot{}, err
	}
	request := struct {
		SchemaVersion int                         `json:"schemaVersion"`
		Actor         ticketOperationsActorWireV1 `json:"actor"`
		TenantID      string                      `json:"tenantId"`
		Kind          string                      `json:"kind"`
		MembershipID  string                      `json:"membershipId"`
		Source        any                         `json:"source"`
	}{ticketOperationsWireVersion, ticketOperationsActorWire(actor), tenantID.String(), kind.String(), access.Membership().String(), wireSource}
	document, err := repository.callTicketOperationsHuman(
		ctx, actor, tenantID, ticketOperationsReadOptions(), ticketBulkResolveQueryABIQuery, request, false,
	)
	if err != nil {
		return application.TicketBulkQuerySnapshot{}, err
	}
	var response struct {
		SchemaVersion int                         `json:"schemaVersion"`
		Query         ticketOperationsQueryWireV1 `json:"query"`
	}
	if err := decodeTicketOperations(document, &response); err != nil || response.SchemaVersion != ticketOperationsWireVersion {
		return application.TicketBulkQuerySnapshot{}, application.ErrUnavailable
	}
	query, _, err := restoreTicketOperationsQuery(response.Query, tenantID, kind, false)
	return query, err
}

func (repository *TicketingRepository) ReserveTicketBulkID(
	ctx context.Context,
	tenantID uuid.UUID,
) (kernel.EntityID, error) {
	return repository.reserveTicketOperationsID(ctx, tenantID)
}

func (repository *TicketingRepository) LookupTicketBulkReplay(
	ctx context.Context,
	query application.TicketBulkReplayQuery,
) (application.TicketBulkResult, bool, error) {
	request := struct {
		SchemaVersion int    `json:"schemaVersion"`
		TenantID      string `json:"tenantId"`
		ActorID       string `json:"actorId"`
		MembershipID  string `json:"ownerMembershipId"`
		Kind          string `json:"kind"`
		Action        string `json:"action"`
		KeySHA256     string `json:"idempotencyKeySha256"`
	}{ticketOperationsWireVersion, query.TenantID.String(), query.ActorID.String(), query.OwnerMembershipID.String(), query.Kind.String(), query.Action.String(), hex.EncodeToString(query.KeyHash[:])}
	actor := application.Actor{UserID: query.ActorID, ActiveTenantID: query.TenantID}
	document, err := repository.callTicketOperationsHuman(
		ctx, actor, query.TenantID, ticketOperationsReadOptions(), ticketBulkReplayABIQuery, request, true,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return application.TicketBulkResult{}, false, nil
	}
	if err != nil {
		return application.TicketBulkResult{}, false, err
	}
	result, err := restoreTicketOperationsBulkResult(document, query.Fingerprint)
	if err != nil {
		return application.TicketBulkResult{}, false, err
	}
	result.Replayed = true
	return result, true, nil
}

func (repository *TicketingRepository) CommitTicketBulkRequest(
	ctx context.Context,
	write application.TicketBulkRequestWrite,
) (application.TicketBulkResult, error) {
	request, err := ticketOperationsBulkCommitRequest(write)
	if err != nil {
		return application.TicketBulkResult{}, err
	}
	document, err := repository.callTicketOperationsHuman(
		ctx, write.Actor, write.Access.Tenant(), phase4WriteOptions(), ticketBulkCommitRequestABIQuery, request, false,
	)
	if err != nil {
		return application.TicketBulkResult{}, err
	}
	return restoreTicketOperationsBulkResult(document, write.Command.Fingerprint)
}

func (repository *TicketingRepository) GetTicketBulk(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	jobID uuid.UUID,
	access application.TicketBulkAccess,
) (application.TicketBulkRecord, error) {
	request := struct {
		SchemaVersion int                         `json:"schemaVersion"`
		Actor         ticketOperationsActorWireV1 `json:"actor"`
		TenantID      string                      `json:"tenantId"`
		MembershipID  string                      `json:"ownerMembershipId"`
		Kind          string                      `json:"kind"`
		Capability    string                      `json:"capability"`
		JobID         string                      `json:"jobId"`
	}{ticketOperationsWireVersion, ticketOperationsActorWire(actor), tenantID.String(), access.Membership().String(), access.Kind().String(), string(access.Capability()), jobID.String()}
	document, err := repository.callTicketOperationsHuman(
		ctx, actor, tenantID, ticketOperationsReadOptions(), ticketBulkGetABIQuery, request, true,
	)
	if err != nil {
		return application.TicketBulkRecord{}, mapSavedViewDatabaseError(err)
	}
	var response ticketOperationsBulkGetResponseV1
	if err := decodeTicketOperations(document, &response); err != nil || response.SchemaVersion != ticketOperationsWireVersion {
		return application.TicketBulkRecord{}, application.ErrUnavailable
	}
	return restoreTicketOperationsBulkRecord(response.Record)
}

func (repository *TicketingRepository) CommitTicketBulkCancellation(
	ctx context.Context,
	write application.TicketBulkCancellationWrite,
) (application.TicketBulkResult, error) {
	next, err := ticketOperationsBulkJobWire(write.Plan.Next())
	if err != nil {
		return application.TicketBulkResult{}, err
	}
	request := struct {
		SchemaVersion      int                           `json:"schemaVersion"`
		Actor              ticketOperationsActorWireV1   `json:"actor"`
		Audit              ticketOperationsAuditWireV1   `json:"audit"`
		RequiredCapability string                        `json:"requiredCapability"`
		ExpectedRevision   uint64                        `json:"expectedRevision"`
		Next               ticketOperationsBulkJobWireV1 `json:"next"`
		Action             string                        `json:"action"`
		KeySHA256          string                        `json:"idempotencyKeySha256"`
		FingerprintSHA256  string                        `json:"requestFingerprintSha256"`
	}{ticketOperationsWireVersion, ticketOperationsActorWire(write.Actor), ticketOperationsAuditWire(write.Audit), string(write.RequiredCapability), write.Plan.ExpectedRevision(), next, write.Command.Action.String(), hex.EncodeToString(write.Command.KeyHash[:]), hex.EncodeToString(write.Command.Fingerprint[:])}
	document, err := repository.callTicketOperationsHuman(
		ctx, write.Actor, write.Access.Tenant(), phase4WriteOptions(), ticketBulkCancelABIQuery, request, false,
	)
	if err != nil {
		return application.TicketBulkResult{}, err
	}
	return restoreTicketOperationsBulkResult(document, write.Command.Fingerprint)
}

func (repository *TicketingRepository) ListTicketBulkResults(
	ctx context.Context,
	query application.TicketBulkResultQuery,
) (application.TicketBulkResultPage, error) {
	request := struct {
		SchemaVersion int                         `json:"schemaVersion"`
		Actor         ticketOperationsActorWireV1 `json:"actor"`
		TenantID      string                      `json:"tenantId"`
		MembershipID  string                      `json:"ownerMembershipId"`
		Kind          string                      `json:"kind"`
		JobID         string                      `json:"jobId"`
		Limit         int                         `json:"limit"`
		After         string                      `json:"after"`
	}{ticketOperationsWireVersion, ticketOperationsActorWire(query.Actor), query.TenantID.String(), query.Access.Membership().String(), query.Access.Kind().String(), query.JobID.String(), query.Limit, query.After}
	document, err := repository.callTicketOperationsHuman(
		ctx, query.Actor, query.TenantID, ticketOperationsReadOptions(), ticketBulkListResultsABIQuery, request, false,
	)
	if err != nil {
		return application.TicketBulkResultPage{}, err
	}
	var response ticketOperationsBulkResultPageWireV1
	if err := decodeTicketOperations(document, &response); err != nil || response.SchemaVersion != ticketOperationsWireVersion ||
		response.Items == nil || response.Next == nil || len(response.Items) > query.Limit {
		return application.TicketBulkResultPage{}, application.ErrUnavailable
	}
	items := make([]application.TicketBulkTargetResultRecord, len(response.Items))
	for index, item := range response.Items {
		id, parseErr := uuid.Parse(item.TargetID)
		result, resultErr := ticketOperationsBulkTargetResult(item.Result)
		recordedAt, timeErr := ticketOperationsInstant(item.RecordedAt)
		if parseErr != nil || !authorizationUUIDv7(id) || resultErr != nil || timeErr != nil || item.Sequence == 0 {
			return application.TicketBulkResultPage{}, application.ErrUnavailable
		}
		items[index] = application.TicketBulkTargetResultRecord{
			Sequence: item.Sequence, TargetID: id, TargetVersion: item.TargetVersion,
			Result: result, RecordedAt: recordedAt,
		}
	}
	return application.TicketBulkResultPage{Items: items, Next: *response.Next}, nil
}

func (repository *TicketingRepository) ResolveAsyncExportAccess(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	audience kernel.TicketExportAudience,
	capability application.AsyncExportCapability,
) (application.AsyncExportAccess, error) {
	request := struct {
		SchemaVersion int                         `json:"schemaVersion"`
		Actor         ticketOperationsActorWireV1 `json:"actor"`
		TenantID      string                      `json:"tenantId"`
		Kind          string                      `json:"kind"`
		Audience      string                      `json:"audience"`
		Capability    string                      `json:"capability"`
	}{ticketOperationsWireVersion, ticketOperationsActorWire(actor), tenantID.String(), kind.String(), audience.String(), string(capability)}
	document, err := repository.callTicketOperationsHuman(
		ctx, actor, tenantID, ticketOperationsReadOptions(), ticketExportResolveAccessABIQuery, request, false,
	)
	if err != nil {
		return application.AsyncExportAccess{}, err
	}
	return restoreTicketOperationsExportAccess(document, actor, tenantID, kind, audience, capability)
}

func (repository *TicketingRepository) ResolveAsyncExportQuery(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	audience kernel.TicketExportAudience,
	source application.AsyncExportSourceInput,
	access application.AsyncExportAccess,
) (application.AsyncExportQuerySnapshot, error) {
	wireSource, err := ticketOperationsExportSourceRequest(
		actor, tenantID, access.Membership(), kind, source,
	)
	if err != nil {
		return application.AsyncExportQuerySnapshot{}, err
	}
	request := struct {
		SchemaVersion int                         `json:"schemaVersion"`
		Actor         ticketOperationsActorWireV1 `json:"actor"`
		TenantID      string                      `json:"tenantId"`
		MembershipID  string                      `json:"ownerMembershipId"`
		Kind          string                      `json:"kind"`
		Audience      string                      `json:"audience"`
		Source        any                         `json:"source"`
	}{ticketOperationsWireVersion, ticketOperationsActorWire(actor), tenantID.String(), access.Membership().String(), kind.String(), audience.String(), wireSource}
	document, err := repository.callTicketOperationsHuman(
		ctx, actor, tenantID, ticketOperationsReadOptions(), ticketExportResolveQueryABIQuery, request, false,
	)
	if err != nil {
		return application.AsyncExportQuerySnapshot{}, err
	}
	var response struct {
		SchemaVersion int                         `json:"schemaVersion"`
		Query         ticketOperationsQueryWireV1 `json:"query"`
	}
	if err := decodeTicketOperations(document, &response); err != nil || response.SchemaVersion != ticketOperationsWireVersion {
		return application.AsyncExportQuerySnapshot{}, application.ErrUnavailable
	}
	_, query, err := restoreTicketOperationsQuery(response.Query, tenantID, kind, true)
	return query, err
}

func (repository *TicketingRepository) ReserveAsyncExportID(
	ctx context.Context,
	tenantID uuid.UUID,
) (kernel.EntityID, error) {
	return repository.reserveTicketOperationsID(ctx, tenantID)
}

func (repository *TicketingRepository) LookupAsyncExportReplay(
	ctx context.Context,
	query application.AsyncExportReplayQuery,
) (application.AsyncExportResult, bool, error) {
	request := struct {
		SchemaVersion int    `json:"schemaVersion"`
		TenantID      string `json:"tenantId"`
		ActorID       string `json:"actorId"`
		MembershipID  string `json:"ownerMembershipId"`
		Kind          string `json:"kind"`
		Audience      string `json:"audience"`
		Action        string `json:"action"`
		KeySHA256     string `json:"idempotencyKeySha256"`
	}{ticketOperationsWireVersion, query.TenantID.String(), query.ActorID.String(), query.OwnerMembershipID.String(), query.Kind.String(), query.Audience.String(), query.Action.String(), hex.EncodeToString(query.KeyHash[:])}
	actor := application.Actor{UserID: query.ActorID, ActiveTenantID: query.TenantID}
	document, err := repository.callTicketOperationsHuman(
		ctx, actor, query.TenantID, ticketOperationsReadOptions(), ticketExportReplayABIQuery, request, true,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return application.AsyncExportResult{}, false, nil
	}
	if err != nil {
		return application.AsyncExportResult{}, false, err
	}
	result, err := restoreTicketOperationsExportResult(document, query.Fingerprint)
	if err != nil {
		return application.AsyncExportResult{}, false, err
	}
	result.Replayed = true
	return result, true, nil
}

func (repository *TicketingRepository) CommitAsyncExportRequest(
	ctx context.Context,
	write application.AsyncExportRequestWrite,
) (application.AsyncExportResult, error) {
	request, err := ticketOperationsExportTransitionRequest(
		write.Actor, write.Audit, write.Access, write.RequiredCapability,
		write.Query, write.Plan, write.Command,
	)
	if err != nil {
		return application.AsyncExportResult{}, err
	}
	document, err := repository.callTicketOperationsHuman(
		ctx, write.Actor, write.Access.Tenant(), phase4WriteOptions(), ticketExportCommitRequestABIQuery, request, false,
	)
	if err != nil {
		return application.AsyncExportResult{}, err
	}
	return restoreTicketOperationsExportResult(document, write.Command.Fingerprint)
}

func (repository *TicketingRepository) GetAsyncExport(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	jobID uuid.UUID,
	access application.AsyncExportAccess,
) (application.AsyncExportRecord, error) {
	request := struct {
		SchemaVersion int                         `json:"schemaVersion"`
		Actor         ticketOperationsActorWireV1 `json:"actor"`
		TenantID      string                      `json:"tenantId"`
		MembershipID  string                      `json:"ownerMembershipId"`
		Kind          string                      `json:"kind"`
		Audience      string                      `json:"audience"`
		Capability    string                      `json:"capability"`
		JobID         string                      `json:"jobId"`
	}{ticketOperationsWireVersion, ticketOperationsActorWire(actor), tenantID.String(), access.Membership().String(), access.Kind().String(), access.Audience().String(), string(access.Capability()), jobID.String()}
	document, err := repository.callTicketOperationsHuman(
		ctx, actor, tenantID, ticketOperationsReadOptions(), ticketExportGetABIQuery, request, true,
	)
	if err != nil {
		return application.AsyncExportRecord{}, mapSavedViewDatabaseError(err)
	}
	var response ticketOperationsExportGetResponseV1
	if err := decodeTicketOperations(document, &response); err != nil || response.SchemaVersion != ticketOperationsWireVersion {
		return application.AsyncExportRecord{}, application.ErrUnavailable
	}
	return restoreTicketOperationsExportRecord(response.Record)
}

func (repository *TicketingRepository) CommitAsyncExportOwnerTransition(
	ctx context.Context,
	write application.AsyncExportOwnerWrite,
) (application.AsyncExportResult, error) {
	request, err := ticketOperationsExportTransitionRequest(
		write.Actor, write.Audit, write.Access, write.RequiredCapability,
		write.Query, write.Plan, write.Command,
	)
	if err != nil {
		return application.AsyncExportResult{}, err
	}
	document, err := repository.callTicketOperationsHuman(
		ctx, write.Actor, write.Access.Tenant(), phase4WriteOptions(), ticketExportOwnerTransitionQuery, request, false,
	)
	if err != nil {
		return application.AsyncExportResult{}, err
	}
	return restoreTicketOperationsExportResult(document, write.Command.Fingerprint)
}

func (repository *TicketingRepository) ResolveAsyncExportWorkerAccess(
	ctx context.Context,
	worker application.AsyncExportWorker,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	audience kernel.TicketExportAudience,
	capability application.AsyncExportCapability,
) (application.AsyncExportWorkerAccess, error) {
	request := struct {
		SchemaVersion    int    `json:"schemaVersion"`
		ServiceAccountID string `json:"serviceAccountId"`
		WorkerID         string `json:"workerId"`
		Purpose          string `json:"purpose"`
		TenantID         string `json:"tenantId"`
		Kind             string `json:"kind"`
		Audience         string `json:"audience"`
		Capability       string `json:"capability"`
	}{ticketOperationsWireVersion, worker.ServiceAccountID.String(), worker.WorkerID.String(), worker.Purpose, tenantID.String(), kind.String(), audience.String(), string(capability)}
	document, err := repository.callTicketOperationsWorker(ctx, ticketExportResolveWorkerAccessQuery, request, false)
	if err != nil {
		return application.AsyncExportWorkerAccess{}, err
	}
	var response struct {
		SchemaVersion    int    `json:"schemaVersion"`
		ServiceAccountID string `json:"serviceAccountId"`
		TenantID         string `json:"tenantId"`
		Kind             string `json:"kind"`
		Audience         string `json:"audience"`
		Capability       string `json:"capability"`
		Allowed          *bool  `json:"allowed"`
	}
	if err := decodeTicketOperations(document, &response); err != nil ||
		response.SchemaVersion != ticketOperationsWireVersion || response.Allowed == nil ||
		response.ServiceAccountID != worker.ServiceAccountID.String() || response.TenantID != tenantID.String() ||
		response.Kind != kind.String() || response.Audience != audience.String() ||
		response.Capability != string(capability) {
		return application.AsyncExportWorkerAccess{}, application.ErrUnavailable
	}
	return application.NewAsyncExportWorkerAccess(
		tenantID, worker.ServiceAccountID, kind, audience, capability, *response.Allowed,
	)
}

func (repository *TicketingRepository) SelectAsyncExportClaimCandidate(
	ctx context.Context,
	worker application.AsyncExportWorker,
	access application.AsyncExportWorkerAccess,
	now time.Time,
) (application.AsyncExportRecord, bool, error) {
	request := ticketOperationsWorkerRequest(
		worker, access, "", 0, [sha256.Size]byte{}, now,
	)
	document, err := repository.callTicketOperationsWorker(ctx, ticketExportSelectCandidateQuery, request, true)
	if errors.Is(err, pgx.ErrNoRows) {
		return application.AsyncExportRecord{}, false, nil
	}
	if err != nil {
		return application.AsyncExportRecord{}, false, err
	}
	var response ticketOperationsExportGetResponseV1
	if err := decodeTicketOperations(document, &response); err != nil || response.SchemaVersion != ticketOperationsWireVersion {
		return application.AsyncExportRecord{}, false, application.ErrUnavailable
	}
	record, err := restoreTicketOperationsExportRecord(response.Record)
	return record, err == nil, err
}

func (repository *TicketingRepository) GetAsyncExportForWorker(
	ctx context.Context,
	worker application.AsyncExportWorker,
	tenantID uuid.UUID,
	jobID uuid.UUID,
	access application.AsyncExportWorkerAccess,
) (application.AsyncExportRecord, error) {
	request := ticketOperationsWorkerRequest(worker, access, jobID.String(), 0, [sha256.Size]byte{}, time.Time{})
	document, err := repository.callTicketOperationsWorker(ctx, ticketExportGetForWorkerQuery, request, true)
	if err != nil {
		return application.AsyncExportRecord{}, mapSavedViewDatabaseError(err)
	}
	var response ticketOperationsExportGetResponseV1
	if err := decodeTicketOperations(document, &response); err != nil || response.SchemaVersion != ticketOperationsWireVersion ||
		response.Record.Job.Definition.TenantID != tenantID.String() {
		return application.AsyncExportRecord{}, application.ErrUnavailable
	}
	return restoreTicketOperationsExportRecord(response.Record)
}

func (repository *TicketingRepository) GetRevokedAsyncExportForWorker(
	ctx context.Context,
	worker application.AsyncExportWorker,
	tenantID uuid.UUID,
	jobID uuid.UUID,
	access application.AsyncExportWorkerAccess,
) (kernel.TicketExportJob, error) {
	request := ticketOperationsWorkerRequest(worker, access, jobID.String(), 0, [sha256.Size]byte{}, time.Time{})
	document, err := repository.callTicketOperationsWorker(ctx, ticketExportGetRevokedQuery, request, true)
	if err != nil {
		return kernel.TicketExportJob{}, mapSavedViewDatabaseError(err)
	}
	var response struct {
		SchemaVersion int                             `json:"schemaVersion"`
		Job           ticketOperationsExportJobWireV1 `json:"job"`
	}
	if err := decodeTicketOperations(document, &response); err != nil || response.SchemaVersion != ticketOperationsWireVersion ||
		response.Job.Definition.TenantID != tenantID.String() {
		return kernel.TicketExportJob{}, application.ErrUnavailable
	}
	return restoreTicketOperationsExportJob(response.Job)
}

func (repository *TicketingRepository) CommitAsyncExportWorkerTransition(
	ctx context.Context,
	write application.AsyncExportWorkerWrite,
) (application.AsyncExportResult, error) {
	request, err := ticketOperationsExportWorkerTransitionRequest(write)
	if err != nil {
		return application.AsyncExportResult{}, err
	}
	document, err := repository.callTicketOperationsWorker(ctx, ticketExportWorkerTransitionQuery, request, false)
	if err != nil {
		return application.AsyncExportResult{}, err
	}
	var response struct {
		SchemaVersion int                                `json:"schemaVersion"`
		Record        ticketOperationsExportRecordWireV1 `json:"record"`
	}
	if err := decodeTicketOperations(document, &response); err != nil || response.SchemaVersion != ticketOperationsWireVersion {
		return application.AsyncExportResult{}, application.ErrUnavailable
	}
	record, err := restoreTicketOperationsExportRecord(response.Record)
	return application.AsyncExportResult{Record: record}, err
}

func (repository *TicketingRepository) CommitAsyncExportRevocation(
	ctx context.Context,
	write application.AsyncExportRevocationWrite,
) (kernel.TicketExportJob, error) {
	job, err := ticketOperationsExportJobWire(write.Plan.Next())
	if err != nil {
		return kernel.TicketExportJob{}, err
	}
	request := struct {
		SchemaVersion      int                             `json:"schemaVersion"`
		Worker             any                             `json:"worker"`
		TenantID           string                          `json:"tenantId"`
		Kind               string                          `json:"kind"`
		Audience           string                          `json:"audience"`
		RequiredCapability string                          `json:"requiredCapability"`
		ExpectedRevision   uint64                          `json:"expectedRevision"`
		Next               ticketOperationsExportJobWireV1 `json:"next"`
	}{ticketOperationsWireVersion, ticketOperationsWorkerIdentity(write.Worker), write.Access.Tenant().String(), write.Access.Kind().String(), write.Access.Audience().String(), string(write.RequiredCapability), write.Plan.ExpectedRevision(), job}
	document, err := repository.callTicketOperationsWorker(ctx, ticketExportCommitRevocationQuery, request, false)
	if err != nil {
		return kernel.TicketExportJob{}, err
	}
	var response struct {
		SchemaVersion int                             `json:"schemaVersion"`
		Job           ticketOperationsExportJobWireV1 `json:"job"`
	}
	if err := decodeTicketOperations(document, &response); err != nil || response.SchemaVersion != ticketOperationsWireVersion {
		return kernel.TicketExportJob{}, application.ErrUnavailable
	}
	return restoreTicketOperationsExportJob(response.Job)
}

func (repository *TicketingRepository) ReadAsyncExportPage(
	ctx context.Context,
	query application.AsyncExportPageQuery,
) (application.AsyncExportPage, error) {
	request := struct {
		SchemaVersion     int    `json:"schemaVersion"`
		Worker            any    `json:"worker"`
		TenantID          string `json:"tenantId"`
		JobID             string `json:"jobId"`
		Kind              string `json:"kind"`
		Audience          string `json:"audience"`
		ExpectedRevision  uint64 `json:"expectedRevision"`
		FenceSHA256       string `json:"fenceSha256"`
		QuerySHA256       string `json:"querySha256"`
		CatalogSHA256     string `json:"catalogSha256"`
		ProjectionVersion uint64 `json:"projectionVersion"`
		After             string `json:"after"`
		Limit             int    `json:"limit"`
	}{ticketOperationsWireVersion, ticketOperationsWorkerIdentity(query.Worker), query.TenantID.String(), query.JobID.String(), query.Access.Kind().String(), query.Access.Audience().String(), query.ExpectedRevision, hex.EncodeToString(query.Fence[:]), hex.EncodeToString(query.QueryDigest[:]), hex.EncodeToString(query.CatalogDigest[:]), query.ProjectionVersion, query.After, query.Limit}
	document, err := repository.callTicketOperationsWorker(ctx, ticketExportReadPageQuery, request, false)
	if err != nil {
		return application.AsyncExportPage{}, err
	}
	var response struct {
		SchemaVersion int `json:"schemaVersion"`
		Rows          []struct {
			Kind  string   `json:"kind"`
			Cells []string `json:"cells"`
		} `json:"rows"`
		Next *string `json:"next"`
	}
	if err := decodeTicketOperations(document, &response); err != nil || response.SchemaVersion != ticketOperationsWireVersion ||
		response.Rows == nil || response.Next == nil || len(response.Rows) > query.Limit {
		return application.AsyncExportPage{}, application.ErrUnavailable
	}
	rows := make([]application.AsyncExportRow, len(response.Rows))
	for index, row := range response.Rows {
		kind, err := ticketOperationsExportRowKind(row.Kind)
		if err != nil {
			return application.AsyncExportPage{}, err
		}
		rows[index] = application.AsyncExportRow{Kind: kind, Cells: append([]string(nil), row.Cells...)}
	}
	return application.AsyncExportPage{Rows: rows, NextCursor: *response.Next}, nil
}

func (repository *TicketingRepository) reserveTicketOperationsID(
	ctx context.Context,
	tenantID uuid.UUID,
) (kernel.EntityID, error) {
	if ctx == nil || ctx.Err() != nil || repository == nil || repository.newID == nil ||
		!authorizationUUIDv7(tenantID) {
		return kernel.EntityID{}, application.ErrUnavailable
	}
	id, err := repository.newID()
	if err != nil || !authorizationUUIDv7(id) {
		return kernel.EntityID{}, application.ErrUnavailable
	}
	return ticketOperationsEntity(id.String())
}

// Ticket operation reads lock tenant and membership authority with FOR SHARE.
// PostgreSQL requires a read-write transaction even though these calls only read.
func ticketOperationsReadOptions() pgx.TxOptions {
	return pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadWrite}
}

func (repository *TicketingRepository) callTicketOperationsHuman(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	options pgx.TxOptions,
	query string,
	request any,
	allowNoRows bool,
) ([]byte, error) {
	payload, err := marshalTicketOperations(request)
	if err != nil {
		return nil, err
	}
	missing := false
	document, err := withinSavedViewTransaction(
		ctx, repository, actor, tenantID, options,
		func(ctx context.Context, tx databaseTransaction) ([]byte, error) {
			var response []byte
			err := tx.QueryRow(ctx, query, payload).Scan(&response)
			if allowNoRows && errors.Is(err, pgx.ErrNoRows) {
				missing = true
				return nil, nil
			}
			if err != nil {
				return nil, mapSavedViewRequiredRowError(err)
			}
			if ctx.Err() != nil {
				return nil, application.ErrUnavailable
			}
			return response, nil
		},
	)
	if err == nil && missing {
		return nil, pgx.ErrNoRows
	}
	return document, err
}

func restoreTicketOperationsBulkResult(
	document []byte,
	expectedFingerprint [sha256.Size]byte,
) (application.TicketBulkResult, error) {
	var response ticketOperationsBulkResultResponseV1
	if err := decodeTicketOperations(document, &response); err != nil ||
		response.SchemaVersion != ticketOperationsWireVersion || response.Replayed == nil {
		return application.TicketBulkResult{}, application.ErrUnavailable
	}
	fingerprint, err := ticketOperationsDigest(response.Fingerprint)
	if err != nil || subtle.ConstantTimeCompare(fingerprint[:], expectedFingerprint[:]) != 1 {
		return application.TicketBulkResult{}, application.ErrConflict
	}
	record, err := restoreTicketOperationsBulkRecord(response.Record)
	if err != nil {
		return application.TicketBulkResult{}, err
	}
	return application.TicketBulkResult{Record: record, Replayed: *response.Replayed}, nil
}

func restoreTicketOperationsExportResult(
	document []byte,
	expectedFingerprint [sha256.Size]byte,
) (application.AsyncExportResult, error) {
	var response ticketOperationsExportResultResponseV1
	if err := decodeTicketOperations(document, &response); err != nil ||
		response.SchemaVersion != ticketOperationsWireVersion || response.Replayed == nil {
		return application.AsyncExportResult{}, application.ErrUnavailable
	}
	fingerprint, err := ticketOperationsDigest(response.Fingerprint)
	if err != nil || subtle.ConstantTimeCompare(fingerprint[:], expectedFingerprint[:]) != 1 {
		return application.AsyncExportResult{}, application.ErrConflict
	}
	record, err := restoreTicketOperationsExportRecord(response.Record)
	if err != nil {
		return application.AsyncExportResult{}, err
	}
	return application.AsyncExportResult{Record: record, Replayed: *response.Replayed}, nil
}

func restoreTicketOperationsExportAccess(
	document []byte,
	actor application.Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	audience kernel.TicketExportAudience,
	capability application.AsyncExportCapability,
) (application.AsyncExportAccess, error) {
	var response ticketOperationsExportAccessResponseV1
	if err := decodeTicketOperations(document, &response); err != nil ||
		response.SchemaVersion != ticketOperationsWireVersion || response.Allowed == nil ||
		response.PublicComments == nil || response.PrivateComments == nil ||
		response.TenantID != tenantID.String() || response.ActorID != actor.UserID.String() ||
		response.Kind != kind.String() || response.Audience != audience.String() ||
		response.Capability != string(capability) {
		return application.AsyncExportAccess{}, application.ErrUnavailable
	}
	membership, err := uuid.Parse(response.MembershipID)
	if err != nil || !authorizationUUIDv7(membership) {
		return application.AsyncExportAccess{}, application.ErrUnavailable
	}
	principal, err := ticketOperationsPrincipal(response.Principal)
	if err != nil {
		return application.AsyncExportAccess{}, err
	}
	var contact *uuid.UUID
	if response.CustomerContactID != "" {
		parsed, parseErr := uuid.Parse(response.CustomerContactID)
		if parseErr != nil || !authorizationUUIDv7(parsed) {
			return application.AsyncExportAccess{}, application.ErrUnavailable
		}
		contact = &parsed
	}
	access, err := application.NewAsyncExportAccess(
		tenantID, actor.UserID, membership, kind, audience, capability, principal, contact,
		*response.PublicComments, *response.PrivateComments, *response.Allowed,
	)
	if err != nil {
		return application.AsyncExportAccess{}, application.ErrUnavailable
	}
	return access, nil
}

func ticketOperationsBulkSourceRequest(
	actor application.Actor,
	tenantID uuid.UUID,
	membershipID uuid.UUID,
	kind kernel.AggregateKind,
	source application.TicketBulkQuerySourceInput,
) (any, error) {
	if source.Inline != nil && source.SavedView == nil {
		normalized, err := application.NormalizeSavedViewSpecInput(*source.Inline)
		if err != nil {
			return nil, err
		}
		request, err := newSavedViewResolveSpecRequestFromValidated(
			tenantID, actor.UserID, membershipID, kind, normalized,
		)
		if err != nil {
			return nil, err
		}
		return struct {
			Mode string                        `json:"mode"`
			Spec savedViewResolveSpecRequestV1 `json:"spec"`
		}{"inline", request}, nil
	}
	if source.Inline == nil && source.SavedView != nil {
		digest := source.SavedView.ExpectedSpecDigest
		return struct {
			Mode       string `json:"mode"`
			ID         string `json:"id"`
			Revision   uint64 `json:"revision"`
			SpecSHA256 string `json:"specSha256"`
		}{"saved_view", source.SavedView.ID.String(), source.SavedView.ExpectedRevision, hex.EncodeToString(digest[:])}, nil
	}
	return nil, application.ErrInvalidInput
}

func ticketOperationsExportSourceRequest(
	actor application.Actor,
	tenantID uuid.UUID,
	membershipID uuid.UUID,
	kind kernel.AggregateKind,
	source application.AsyncExportSourceInput,
) (any, error) {
	bulk := application.TicketBulkQuerySourceInput{Inline: source.Inline}
	if source.SavedView != nil {
		bulk.SavedView = &application.TicketBulkSavedViewSourceInput{
			ID: source.SavedView.ID, ExpectedRevision: source.SavedView.ExpectedRevision,
			ExpectedSpecDigest: source.SavedView.ExpectedSpecDigest,
		}
	}
	return ticketOperationsBulkSourceRequest(actor, tenantID, membershipID, kind, bulk)
}

func ticketOperationsBulkCommitRequest(write application.TicketBulkRequestWrite) (any, error) {
	request := struct {
		SchemaVersion      int                                `json:"schemaVersion"`
		Actor              ticketOperationsActorWireV1        `json:"actor"`
		Audit              ticketOperationsAuditWireV1        `json:"audit"`
		TenantID           string                             `json:"tenantId"`
		MembershipID       string                             `json:"ownerMembershipId"`
		Kind               string                             `json:"kind"`
		RequiredCapability string                             `json:"requiredCapability"`
		JobID              string                             `json:"jobId"`
		ExplicitTargets    []ticketOperationsTargetWireV1     `json:"explicitTargets"`
		Query              *ticketOperationsQueryWireV1       `json:"query"`
		Mutation           ticketOperationsBulkMutationWireV1 `json:"mutation"`
		RequestedAt        time.Time                          `json:"requestedAt"`
		ExpiresAt          time.Time                          `json:"expiresAt"`
		Action             string                             `json:"action"`
		KeySHA256          string                             `json:"idempotencyKeySha256"`
		FingerprintSHA256  string                             `json:"requestFingerprintSha256"`
	}{
		SchemaVersion: ticketOperationsWireVersion, Actor: ticketOperationsActorWire(write.Actor),
		Audit: ticketOperationsAuditWire(write.Audit), TenantID: write.Access.Tenant().String(),
		MembershipID: write.Access.Membership().String(), Kind: write.Access.Kind().String(),
		RequiredCapability: string(write.RequiredCapability), JobID: write.JobID.String(),
		RequestedAt: write.RequestedAt, ExpiresAt: write.ExpiresAt, Action: write.Command.Action.String(),
		KeySHA256:         hex.EncodeToString(write.Command.KeyHash[:]),
		FingerprintSHA256: hex.EncodeToString(write.Command.Fingerprint[:]),
	}
	mutation, err := ticketOperationsBulkMutationWire(write.Mutation)
	if err != nil {
		return nil, err
	}
	request.Mutation = mutation
	if write.ExplicitSelection != nil && write.Query == nil {
		targets := write.ExplicitSelection.ExplicitTargets()
		request.ExplicitTargets = make([]ticketOperationsTargetWireV1, len(targets))
		for index, target := range targets {
			request.ExplicitTargets[index] = ticketOperationsTargetWireV1{ID: target.ID().String(), Version: target.Version()}
		}
	} else if write.ExplicitSelection == nil && write.Query != nil {
		pin := ticketOperationsSavedViewWireBulk(write.Query.SavedView())
		query, err := ticketOperationsQueryWire(
			write.Query.Tenant(), write.Query.Kind(), write.Query.Source().String(), write.Query.Spec(), pin,
			write.Query.QueryDigest(), write.Query.CatalogDigest(),
		)
		if err != nil {
			return nil, err
		}
		request.Query = &query
	} else {
		return nil, application.ErrUnavailable
	}
	return request, nil
}

func ticketOperationsExportTransitionRequest(
	actor application.Actor,
	audit application.AuditContext,
	access application.AsyncExportAccess,
	required application.AsyncExportCapability,
	query application.AsyncExportQuerySnapshot,
	plan kernel.TicketExportPlan,
	command application.AsyncExportCommandBinding,
) (any, error) {
	job, err := ticketOperationsExportJobWire(plan.Next())
	if err != nil {
		return nil, err
	}
	queryWire, err := ticketOperationsQueryWire(
		query.Tenant(), query.Kind(), query.Source().String(), query.Spec(),
		ticketOperationsSavedViewWireExport(query.SavedView()), query.QueryDigest(), query.CatalogDigest(),
	)
	if err != nil {
		return nil, err
	}
	return struct {
		SchemaVersion      int                             `json:"schemaVersion"`
		Actor              ticketOperationsActorWireV1     `json:"actor"`
		Audit              ticketOperationsAuditWireV1     `json:"audit"`
		RequiredCapability string                          `json:"requiredCapability"`
		ExpectedRevision   uint64                          `json:"expectedRevision"`
		Next               ticketOperationsExportJobWireV1 `json:"next"`
		Query              ticketOperationsQueryWireV1     `json:"query"`
		Action             string                          `json:"action"`
		KeySHA256          string                          `json:"idempotencyKeySha256"`
		FingerprintSHA256  string                          `json:"requestFingerprintSha256"`
	}{
		ticketOperationsWireVersion, ticketOperationsActorWire(actor), ticketOperationsAuditWire(audit),
		string(required), plan.ExpectedRevision(), job, queryWire, command.Action.String(),
		hex.EncodeToString(command.KeyHash[:]), hex.EncodeToString(command.Fingerprint[:]),
	}, nil
}

func ticketOperationsBulkTargetResult(value string) (kernel.TicketBulkTargetResult, error) {
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
	return 0, application.ErrUnavailable
}

func (repository *TicketingRepository) callTicketOperationsWorker(
	ctx context.Context,
	query string,
	request any,
	allowNoRows bool,
) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || repository == nil || repository.begin == nil {
		return nil, application.ErrUnavailable
	}
	payload, err := marshalTicketOperations(request)
	if err != nil {
		return nil, err
	}
	operationContext, cancel := context.WithTimeout(ctx, savedViewDatabaseTimeout)
	defer cancel()
	response, err := withinTransactionWithOptions(
		operationContext, repository.begin, pgx.TxOptions{IsoLevel: pgx.ReadCommitted},
		func(tx databaseTransaction) ([]byte, error) {
			var response []byte
			err := tx.QueryRow(operationContext, query, payload).Scan(&response)
			if allowNoRows && errors.Is(err, pgx.ErrNoRows) {
				return nil, pgx.ErrNoRows
			}
			if err != nil {
				return nil, mapSavedViewRequiredRowError(err)
			}
			if operationContext.Err() != nil {
				return nil, application.ErrUnavailable
			}
			return response, nil
		},
	)
	if allowNoRows && errors.Is(err, pgx.ErrNoRows) {
		return nil, pgx.ErrNoRows
	}
	if err != nil {
		return nil, mapSavedViewDatabaseError(err)
	}
	return response, nil
}

func ticketOperationsWorkerIdentity(worker application.AsyncExportWorker) any {
	return struct {
		ServiceAccountID string `json:"serviceAccountId"`
		WorkerID         string `json:"workerId"`
		Purpose          string `json:"purpose"`
	}{worker.ServiceAccountID.String(), worker.WorkerID.String(), worker.Purpose}
}

func ticketOperationsWorkerRequest(
	worker application.AsyncExportWorker,
	access application.AsyncExportWorkerAccess,
	jobID string,
	expectedRevision uint64,
	fence [sha256.Size]byte,
	now time.Time,
) any {
	fenceText := ""
	if fence != ([sha256.Size]byte{}) {
		fenceText = hex.EncodeToString(fence[:])
	}
	var nowValue *time.Time
	if !now.IsZero() {
		nowValue = &now
	}
	return struct {
		SchemaVersion    int        `json:"schemaVersion"`
		Worker           any        `json:"worker"`
		TenantID         string     `json:"tenantId"`
		Kind             string     `json:"kind"`
		Audience         string     `json:"audience"`
		Capability       string     `json:"capability"`
		JobID            string     `json:"jobId"`
		ExpectedRevision uint64     `json:"expectedRevision"`
		FenceSHA256      string     `json:"fenceSha256"`
		Now              *time.Time `json:"now"`
	}{
		ticketOperationsWireVersion, ticketOperationsWorkerIdentity(worker), access.Tenant().String(),
		access.Kind().String(), access.Audience().String(), string(access.Capability()), jobID,
		expectedRevision, fenceText, nowValue,
	}
}

func ticketOperationsExportWorkerTransitionRequest(
	write application.AsyncExportWorkerWrite,
) (any, error) {
	job, err := ticketOperationsExportJobWire(write.Plan.Next())
	if err != nil {
		return nil, err
	}
	query, err := ticketOperationsQueryWire(
		write.Query.Tenant(), write.Query.Kind(), write.Query.Source().String(), write.Query.Spec(),
		ticketOperationsSavedViewWireExport(write.Query.SavedView()), write.Query.QueryDigest(),
		write.Query.CatalogDigest(),
	)
	if err != nil {
		return nil, err
	}
	return struct {
		SchemaVersion      int                             `json:"schemaVersion"`
		Worker             any                             `json:"worker"`
		TenantID           string                          `json:"tenantId"`
		Kind               string                          `json:"kind"`
		Audience           string                          `json:"audience"`
		RequiredCapability string                          `json:"requiredCapability"`
		ExpectedRevision   uint64                          `json:"expectedRevision"`
		Next               ticketOperationsExportJobWireV1 `json:"next"`
		Query              ticketOperationsQueryWireV1     `json:"query"`
	}{
		ticketOperationsWireVersion, ticketOperationsWorkerIdentity(write.Worker),
		write.Access.Tenant().String(), write.Access.Kind().String(), write.Access.Audience().String(),
		string(write.RequiredCapability), write.Plan.ExpectedRevision(), job, query,
	}, nil
}

func ticketOperationsExportRowKind(value string) (application.AsyncExportRowKind, error) {
	switch value {
	case application.AsyncExportTicketRow.String():
		return application.AsyncExportTicketRow, nil
	case application.AsyncExportPublicCommentRow.String():
		return application.AsyncExportPublicCommentRow, nil
	case application.AsyncExportPrivateCommentRow.String():
		return application.AsyncExportPrivateCommentRow, nil
	default:
		return 0, application.ErrUnavailable
	}
}
