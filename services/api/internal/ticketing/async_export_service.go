package ticketing

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

type AsyncExportFenceSource func() ([sha256.Size]byte, error)

type AsyncExportService struct {
	repository      AsyncExportRepository
	clock           func() time.Time
	fenceSource     AsyncExportFenceSource
	downloadStorage AsyncExportDownloadStorage
}

func NewAsyncExportService(
	repository AsyncExportRepository,
	clock func() time.Time,
	fenceSource AsyncExportFenceSource,
) (*AsyncExportService, error) {
	if nilTicketingDependency(repository) {
		return nil, errors.New("async export repository is required")
	}
	if clock == nil {
		clock = time.Now
	}
	if fenceSource == nil {
		fenceSource = randomAsyncExportFence
	}
	return &AsyncExportService{repository: repository, clock: clock, fenceSource: fenceSource}, nil
}

func NewAsyncExportServiceWithDownloadStorage(
	repository AsyncExportRepository,
	clock func() time.Time,
	fenceSource AsyncExportFenceSource,
	storage AsyncExportDownloadStorage,
) (*AsyncExportService, error) {
	if nilTicketingDependency(storage) {
		return nil, errors.New("async export download storage is required")
	}
	service, err := NewAsyncExportService(repository, clock, fenceSource)
	if err != nil {
		return nil, err
	}
	service.downloadStorage = storage
	return service, nil
}

func (service *AsyncExportService) Request(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	input AsyncExportRequestInput,
) (AsyncExportResult, error) {
	if !validMutationActor(actor, tenantID) {
		return AsyncExportResult{}, ErrForbidden
	}
	input, err := normalizeAsyncExportRequestInput(input)
	if err != nil {
		return AsyncExportResult{}, err
	}
	access, err := service.asyncExportAccess(
		ctx, actor, tenantID, kind, input.Audience, AsyncExportCapabilityRequest,
	)
	if err != nil {
		return AsyncExportResult{}, err
	}
	if input.Comments != kernel.TicketExportCommentsNone && !access.publicComments ||
		input.Comments == kernel.TicketExportCommentsPublicAndPrivate && !access.privateComments {
		return AsyncExportResult{}, ErrForbidden
	}
	query, err := service.repository.ResolveAsyncExportQuery(
		ctx, actor, tenantID, kind, input.Audience, cloneAsyncExportSourceInput(input.Source), access,
	)
	if err != nil {
		return AsyncExportResult{}, repositoryError(err)
	}
	query, err = validateResolvedAsyncExportQuery(input, access, query)
	if err != nil {
		return AsyncExportResult{}, err
	}
	command, err := bindAsyncExportRequestCommand(
		input.IdempotencyKey, access, query, input.Comments,
		input.MaximumRows, input.MaximumBytes, input.Retention,
	)
	if err != nil {
		return AsyncExportResult{}, err
	}
	replay, found, err := service.asyncExportReplay(ctx, access, command)
	if err != nil {
		return AsyncExportResult{}, err
	}
	if found {
		return validateAsyncExportRequestReplay(
			replay, access, query, input.Comments, input.MaximumRows, input.MaximumBytes,
			input.Retention,
		)
	}
	id, err := service.repository.ReserveAsyncExportID(ctx, tenantID)
	if err != nil {
		return AsyncExportResult{}, repositoryError(err)
	}
	definition, err := newAsyncExportDefinition(id, access, query, input)
	if err != nil {
		return AsyncExportResult{}, err
	}
	now, err := service.now()
	if err != nil {
		return AsyncExportResult{}, err
	}
	plan, err := kernel.PlanTicketExportCreation(definition, now, now.Add(input.Retention))
	if err != nil {
		return AsyncExportResult{}, asyncExportPlanError(err)
	}
	if err := validateAsyncExportPlanCapacity(plan); err != nil {
		return AsyncExportResult{}, err
	}
	result, err := service.repository.CommitAsyncExportRequest(ctx, AsyncExportRequestWrite{
		Actor: actor, Access: access, RequiredCapability: AsyncExportCapabilityRequest,
		Query: query, Plan: plan, Command: command, Audit: actor.Audit,
	})
	if err != nil {
		return AsyncExportResult{}, repositoryError(err)
	}
	return validateCommittedAsyncExport(result, plan, query, result.Replayed)
}

func (service *AsyncExportService) Get(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	audience kernel.TicketExportAudience,
	jobID uuid.UUID,
) (AsyncExportRecord, error) {
	if !validActor(actor, tenantID) {
		return AsyncExportRecord{}, ErrForbidden
	}
	if !validSavedViewKind(kind) || !validAsyncExportAudience(audience) || !validWorkflowUUID(jobID) {
		return AsyncExportRecord{}, ErrInvalidInput
	}
	access, err := service.asyncExportAccess(
		ctx, actor, tenantID, kind, audience, AsyncExportCapabilityRead,
	)
	if err != nil {
		return AsyncExportRecord{}, err
	}
	record, err := service.repository.GetAsyncExport(ctx, actor, tenantID, jobID, access)
	if err != nil {
		return AsyncExportRecord{}, asyncExportOwnerLookupError(err)
	}
	return normalizeAsyncExportRecord(record, &access, nil, &jobID)
}

func (service *AsyncExportService) Cancel(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	audience kernel.TicketExportAudience,
	jobID uuid.UUID,
	input AsyncExportCancelInput,
) (AsyncExportResult, error) {
	if !validMutationActor(actor, tenantID) {
		return AsyncExportResult{}, ErrForbidden
	}
	if !validSavedViewKind(kind) || !validAsyncExportAudience(audience) || !validWorkflowUUID(jobID) ||
		input.ExpectedRevision == 0 || input.ExpectedRevision >= maxResourceVersion ||
		!validIdempotencyKey(input.IdempotencyKey) {
		return AsyncExportResult{}, ErrInvalidInput
	}
	access, err := service.asyncExportAccess(
		ctx, actor, tenantID, kind, audience, AsyncExportCapabilityCancel,
	)
	if err != nil {
		return AsyncExportResult{}, err
	}
	command, err := bindAsyncExportCancelCommand(
		input.IdempotencyKey, access, jobID, input.ExpectedRevision,
	)
	if err != nil {
		return AsyncExportResult{}, err
	}
	replay, found, err := service.asyncExportReplay(ctx, access, command)
	if err != nil {
		return AsyncExportResult{}, err
	}
	if found {
		return validateAsyncExportCancelReplay(replay, access, jobID, input.ExpectedRevision)
	}
	record, err := service.repository.GetAsyncExport(ctx, actor, tenantID, jobID, access)
	if err != nil {
		return AsyncExportResult{}, asyncExportOwnerLookupError(err)
	}
	record, err = normalizeAsyncExportRecord(record, &access, nil, &jobID)
	if err != nil {
		return AsyncExportResult{}, err
	}
	now, err := service.now()
	if err != nil {
		return AsyncExportResult{}, err
	}
	plan, err := kernel.PlanTicketExportCancellation(record.Job, input.ExpectedRevision, now)
	if err != nil {
		return AsyncExportResult{}, asyncExportPlanError(err)
	}
	if err := validateAsyncExportPlanCapacity(plan); err != nil {
		return AsyncExportResult{}, err
	}
	result, err := service.repository.CommitAsyncExportOwnerTransition(ctx, AsyncExportOwnerWrite{
		Actor: actor, Access: access, RequiredCapability: AsyncExportCapabilityCancel,
		Query: record.Query, Plan: plan, Command: command, Audit: actor.Audit,
	})
	if err != nil {
		return AsyncExportResult{}, repositoryError(err)
	}
	if result.Replayed {
		return validateAsyncExportCancelReplay(result, access, jobID, input.ExpectedRevision)
	}
	return validateCommittedAsyncExport(result, plan, record.Query, false)
}

func (service *AsyncExportService) Claim(
	ctx context.Context,
	worker AsyncExportWorker,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	audience kernel.TicketExportAudience,
	input AsyncExportClaimInput,
) (AsyncExportResult, bool, error) {
	if !validAsyncExportWorker(worker) || !validWorkflowUUID(tenantID) {
		return AsyncExportResult{}, false, ErrForbidden
	}
	if !validSavedViewKind(kind) || !validAsyncExportAudience(audience) ||
		input.LeaseDuration < kernel.TicketExportMinimumLease ||
		input.LeaseDuration > kernel.TicketExportMaximumLease || input.LeaseDuration%time.Microsecond != 0 {
		return AsyncExportResult{}, false, ErrInvalidInput
	}
	access, err := service.asyncExportWorkerAccess(
		ctx, worker, tenantID, kind, audience, AsyncExportCapabilityClaim,
	)
	if err != nil {
		return AsyncExportResult{}, false, err
	}
	now, err := service.now()
	if err != nil {
		return AsyncExportResult{}, false, err
	}
	candidate, found, err := service.repository.SelectAsyncExportClaimCandidate(ctx, worker, access, now)
	if err != nil {
		return AsyncExportResult{}, false, repositoryError(err)
	}
	if !found {
		return AsyncExportResult{}, false, nil
	}
	candidate, err = normalizeAsyncExportRecord(candidate, nil, &access, nil)
	if err != nil {
		return AsyncExportResult{}, false, err
	}
	if candidate.Job.Revision() >= maxResourceVersion {
		return AsyncExportResult{}, false, ErrUnavailable
	}
	leaseUntil := now.Add(input.LeaseDuration)
	if leaseUntil.After(candidate.Job.ExpiresAt()) {
		leaseUntil = candidate.Job.ExpiresAt()
	}
	if leaseUntil.Sub(now) < kernel.TicketExportMinimumLease {
		return AsyncExportResult{}, false, ErrUnavailable
	}
	fence, err := service.fenceSource()
	if err != nil || fence == ([sha256.Size]byte{}) {
		return AsyncExportResult{}, false, ErrUnavailable
	}
	workerID, _ := entityID(worker.WorkerID)
	plan, err := kernel.PlanTicketExportClaim(candidate.Job, workerID, fence, now, leaseUntil)
	if err != nil {
		return AsyncExportResult{}, false, asyncExportPlanError(err)
	}
	if err := validateAsyncExportPlanCapacity(plan); err != nil {
		return AsyncExportResult{}, false, err
	}
	result, err := service.repository.CommitAsyncExportWorkerTransition(ctx, AsyncExportWorkerWrite{
		Worker: worker, Access: access, RequiredCapability: AsyncExportCapabilityClaim,
		Query: candidate.Query, Plan: plan,
	})
	if err != nil {
		return AsyncExportResult{}, false, repositoryError(err)
	}
	result, err = validateCommittedAsyncExport(result, plan, candidate.Query, false)
	if err != nil {
		return AsyncExportResult{}, false, err
	}
	return result, true, nil
}

func (service *AsyncExportService) Renew(
	ctx context.Context,
	worker AsyncExportWorker,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	audience kernel.TicketExportAudience,
	jobID uuid.UUID,
	input AsyncExportRenewInput,
) (AsyncExportResult, error) {
	if input.ExpectedRevision == 0 || input.ExpectedRevision >= maxResourceVersion ||
		input.Fence == ([sha256.Size]byte{}) ||
		input.LeaseDuration < kernel.TicketExportMinimumLease ||
		input.LeaseDuration > kernel.TicketExportMaximumLease || input.LeaseDuration%time.Microsecond != 0 {
		return AsyncExportResult{}, ErrInvalidInput
	}
	record, access, now, err := service.loadAsyncExportForWorker(
		ctx, worker, tenantID, kind, audience, jobID,
	)
	if err != nil {
		return AsyncExportResult{}, err
	}
	if record.Job.Revision() != input.ExpectedRevision {
		return AsyncExportResult{}, ErrPreconditionFailed
	}
	leaseUntil := now.Add(input.LeaseDuration)
	if leaseUntil.After(record.Job.ExpiresAt()) {
		leaseUntil = record.Job.ExpiresAt()
	}
	workerID, _ := entityID(worker.WorkerID)
	plan, err := kernel.PlanTicketExportLeaseRenewal(record.Job, workerID, input.Fence, now, leaseUntil)
	if err != nil {
		return AsyncExportResult{}, asyncExportPlanError(err)
	}
	return service.commitAsyncExportWorker(ctx, worker, access, record.Query, plan)
}

func (service *AsyncExportService) ReadPage(
	ctx context.Context,
	worker AsyncExportWorker,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	audience kernel.TicketExportAudience,
	jobID uuid.UUID,
	input AsyncExportPageInput,
) (AsyncExportPage, error) {
	input, err := normalizeAsyncExportPageInput(input)
	if err != nil {
		return AsyncExportPage{}, err
	}
	record, access, now, err := service.loadAsyncExportForWorker(
		ctx, worker, tenantID, kind, audience, jobID,
	)
	if err != nil {
		return AsyncExportPage{}, err
	}
	if record.Job.Revision() != input.ExpectedRevision {
		return AsyncExportPage{}, ErrPreconditionFailed
	}
	lease := record.Job.Lease()
	if record.Job.State() == kernel.TicketExportCancellationRequested {
		return AsyncExportPage{}, ErrConflict
	}
	if record.Job.State() != kernel.TicketExportRunning || lease == nil ||
		uuidFromEntity(lease.Worker()) != worker.WorkerID || lease.Fence() != input.Fence ||
		!lease.ExpiresAt().After(now) {
		return AsyncExportPage{}, ErrConflict
	}
	definition := record.Job.Definition()
	page, err := service.repository.ReadAsyncExportPage(ctx, AsyncExportPageQuery{
		Worker: worker, Access: access, TenantID: tenantID, JobID: jobID,
		ExpectedRevision: input.ExpectedRevision, Fence: input.Fence,
		QueryDigest: definition.QueryDigest(), CatalogDigest: definition.CatalogDigest(),
		ProjectionVersion: definition.ProjectionVersion(), After: input.After, Limit: input.Limit,
	})
	if err != nil {
		return AsyncExportPage{}, repositoryError(err)
	}
	return normalizeAsyncExportPage(page, record, input)
}

func (service *AsyncExportService) Finish(
	ctx context.Context,
	worker AsyncExportWorker,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	audience kernel.TicketExportAudience,
	jobID uuid.UUID,
	input AsyncExportFinishInput,
) (AsyncExportResult, error) {
	if input.ExpectedRevision == 0 || input.ExpectedRevision >= maxResourceVersion ||
		input.Fence == ([sha256.Size]byte{}) {
		return AsyncExportResult{}, ErrInvalidInput
	}
	record, access, now, err := service.loadAsyncExportForWorker(
		ctx, worker, tenantID, kind, audience, jobID,
	)
	if err != nil {
		return AsyncExportResult{}, err
	}
	if record.Job.Revision() != input.ExpectedRevision {
		return AsyncExportResult{}, ErrPreconditionFailed
	}
	workerID, _ := entityID(worker.WorkerID)
	var plan kernel.TicketExportPlan
	switch input.Action {
	case AsyncExportFinishSuccess:
		if input.Artifact == nil || input.FailureCode != kernel.TicketExportFailureNone || input.RetryAt != nil {
			return AsyncExportResult{}, ErrInvalidInput
		}
		artifactID, artifactErr := entityID(input.Artifact.ID)
		if artifactErr != nil {
			return AsyncExportResult{}, ErrInvalidInput
		}
		artifact, artifactErr := kernel.NewTicketExportArtifact(
			artifactID, input.Artifact.Digest, input.Artifact.Rows,
			input.Artifact.Bytes, input.Artifact.ExpiresAt,
		)
		if artifactErr != nil {
			return AsyncExportResult{}, ErrInvalidInput
		}
		plan, err = kernel.PlanTicketExportSuccess(record.Job, workerID, input.Fence, artifact, now)
	case AsyncExportFinishFailure:
		if input.Artifact != nil || input.FailureCode == kernel.TicketExportFailureNone {
			return AsyncExportResult{}, ErrInvalidInput
		}
		retryAt := cloneAsyncExportTime(input.RetryAt)
		plan, err = kernel.PlanTicketExportFailure(
			record.Job, workerID, input.Fence, input.FailureCode, retryAt, now,
		)
	case AsyncExportFinishCancellation:
		if input.Artifact != nil || input.FailureCode != kernel.TicketExportFailureNone || input.RetryAt != nil {
			return AsyncExportResult{}, ErrInvalidInput
		}
		plan, err = kernel.PlanTicketExportCancellationAcknowledgement(
			record.Job, workerID, input.Fence, now,
		)
	default:
		return AsyncExportResult{}, ErrInvalidInput
	}
	if err != nil {
		return AsyncExportResult{}, asyncExportPlanError(err)
	}
	return service.commitAsyncExportWorker(ctx, worker, access, record.Query, plan)
}

// RejectRevoked terminalizes a job only after the repository has proved that
// the original human/resource authorization is no longer live. It is distinct
// from normal worker reads so revocation cannot become authority to query data.
func (service *AsyncExportService) RejectRevoked(
	ctx context.Context,
	worker AsyncExportWorker,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	audience kernel.TicketExportAudience,
	jobID uuid.UUID,
	expectedRevision uint64,
) (AsyncExportRevocationResult, error) {
	if !validAsyncExportWorker(worker) || !validWorkflowUUID(tenantID) {
		return AsyncExportRevocationResult{}, ErrForbidden
	}
	if !validSavedViewKind(kind) || !validAsyncExportAudience(audience) ||
		!validWorkflowUUID(jobID) || expectedRevision == 0 || expectedRevision >= maxResourceVersion {
		return AsyncExportRevocationResult{}, ErrInvalidInput
	}
	access, err := service.asyncExportWorkerAccess(
		ctx, worker, tenantID, kind, audience, AsyncExportCapabilityExecute,
	)
	if err != nil {
		return AsyncExportRevocationResult{}, err
	}
	job, err := service.repository.GetRevokedAsyncExportForWorker(
		ctx, worker, tenantID, jobID, access,
	)
	if err != nil {
		return AsyncExportRevocationResult{}, repositoryError(err)
	}
	job, err = normalizeAsyncExportJobForWorker(job, access, jobID)
	if err != nil {
		return AsyncExportRevocationResult{}, err
	}
	if job.Revision() != expectedRevision {
		return AsyncExportRevocationResult{}, ErrPreconditionFailed
	}
	now, err := service.now()
	if err != nil {
		return AsyncExportRevocationResult{}, err
	}
	plan, err := kernel.PlanTicketExportAuthorizationRevocation(job, now)
	if err != nil {
		return AsyncExportRevocationResult{}, asyncExportPlanError(err)
	}
	if err := validateAsyncExportPlanCapacity(plan); err != nil {
		return AsyncExportRevocationResult{}, err
	}
	committed, err := service.repository.CommitAsyncExportRevocation(ctx, AsyncExportRevocationWrite{
		Worker: worker, Access: access, RequiredCapability: AsyncExportCapabilityExecute, Plan: plan,
	})
	if err != nil {
		return AsyncExportRevocationResult{}, repositoryError(err)
	}
	committed, err = normalizeAsyncExportJobForWorker(committed, access, jobID)
	if err != nil || !kernel.SameTicketExportJob(committed, plan.Next()) {
		return AsyncExportRevocationResult{}, ErrUnavailable
	}
	return AsyncExportRevocationResult{Job: committed}, nil
}

// Expire closes a cancellation whose worker disappeared or a non-terminal job
// whose retention deadline elapsed. It remains tenant-scoped and service-
// authorized; it is not a cross-tenant reaper shortcut.
func (service *AsyncExportService) Expire(
	ctx context.Context,
	worker AsyncExportWorker,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	audience kernel.TicketExportAudience,
	jobID uuid.UUID,
	expectedRevision uint64,
) (AsyncExportResult, error) {
	if expectedRevision == 0 || expectedRevision >= maxResourceVersion {
		return AsyncExportResult{}, ErrInvalidInput
	}
	record, access, now, err := service.loadAsyncExportForWorker(
		ctx, worker, tenantID, kind, audience, jobID,
	)
	if err != nil {
		return AsyncExportResult{}, err
	}
	if record.Job.Revision() != expectedRevision {
		return AsyncExportResult{}, ErrPreconditionFailed
	}
	var plan kernel.TicketExportPlan
	if !now.Before(record.Job.ExpiresAt()) {
		plan, err = kernel.PlanTicketExportExpiry(record.Job, now)
	} else if record.Job.State() == kernel.TicketExportCancellationRequested && record.Job.Lease() != nil &&
		!record.Job.Lease().ExpiresAt().After(now) {
		plan, err = kernel.PlanTicketExportCancellationExpiry(record.Job, now)
	} else if record.Job.State() == kernel.TicketExportRunning && record.Job.Lease() != nil &&
		!record.Job.Lease().ExpiresAt().After(now) {
		plan, err = kernel.PlanTicketExportLeaseExpiry(record.Job, now)
	} else {
		plan, err = kernel.PlanTicketExportExpiry(record.Job, now)
	}
	if err != nil {
		return AsyncExportResult{}, asyncExportPlanError(err)
	}
	return service.commitAsyncExportWorker(ctx, worker, access, record.Query, plan)
}

func (service *AsyncExportService) asyncExportAccess(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	audience kernel.TicketExportAudience,
	capability AsyncExportCapability,
) (AsyncExportAccess, error) {
	access, err := service.repository.ResolveAsyncExportAccess(
		ctx, actor, tenantID, kind, audience, capability,
	)
	if err != nil {
		return AsyncExportAccess{}, repositoryError(err)
	}
	if access.tenant != tenantID || access.actor != actor.UserID || access.kind != kind ||
		access.audience != audience || access.capability != capability ||
		!validWorkflowUUID(access.membership) ||
		access.principal != kernel.PrincipalOperator && access.principal != kernel.PrincipalCustomer &&
			access.principal != kernel.PrincipalServiceAccount {
		return AsyncExportAccess{}, ErrUnavailable
	}
	expectedPrincipal := kernel.PrincipalOperator
	if audience == kernel.TicketExportAudienceCustomer {
		expectedPrincipal = kernel.PrincipalCustomer
	}
	if !access.allowed || access.principal != expectedPrincipal {
		return AsyncExportAccess{}, ErrForbidden
	}
	if !validAsyncExportAccessShape(access) {
		return AsyncExportAccess{}, ErrUnavailable
	}
	return access, nil
}

func (service *AsyncExportService) asyncExportWorkerAccess(
	ctx context.Context,
	worker AsyncExportWorker,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	audience kernel.TicketExportAudience,
	capability AsyncExportCapability,
) (AsyncExportWorkerAccess, error) {
	access, err := service.repository.ResolveAsyncExportWorkerAccess(
		ctx, worker, tenantID, kind, audience, capability,
	)
	if err != nil {
		return AsyncExportWorkerAccess{}, repositoryError(err)
	}
	if access.tenant != tenantID || access.serviceAccount != worker.ServiceAccountID ||
		access.kind != kind || access.audience != audience || access.capability != capability {
		return AsyncExportWorkerAccess{}, ErrUnavailable
	}
	if !access.allowed {
		return AsyncExportWorkerAccess{}, ErrForbidden
	}
	return access, nil
}

func (service *AsyncExportService) asyncExportReplay(
	ctx context.Context,
	access AsyncExportAccess,
	command AsyncExportCommandBinding,
) (AsyncExportResult, bool, error) {
	result, found, err := service.repository.LookupAsyncExportReplay(ctx, AsyncExportReplayQuery{
		TenantID: access.tenant, ActorID: access.actor, OwnerMembershipID: access.membership,
		Kind: access.kind, Audience: access.audience, Action: command.Action,
		KeyHash: command.KeyHash, Fingerprint: command.Fingerprint,
	})
	if err != nil {
		return AsyncExportResult{}, false, repositoryError(err)
	}
	return result, found, nil
}

func (service *AsyncExportService) loadAsyncExportForWorker(
	ctx context.Context,
	worker AsyncExportWorker,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	audience kernel.TicketExportAudience,
	jobID uuid.UUID,
) (AsyncExportRecord, AsyncExportWorkerAccess, time.Time, error) {
	if !validAsyncExportWorker(worker) || !validWorkflowUUID(tenantID) {
		return AsyncExportRecord{}, AsyncExportWorkerAccess{}, time.Time{}, ErrForbidden
	}
	if !validSavedViewKind(kind) || !validAsyncExportAudience(audience) || !validWorkflowUUID(jobID) {
		return AsyncExportRecord{}, AsyncExportWorkerAccess{}, time.Time{}, ErrInvalidInput
	}
	access, err := service.asyncExportWorkerAccess(
		ctx, worker, tenantID, kind, audience, AsyncExportCapabilityExecute,
	)
	if err != nil {
		return AsyncExportRecord{}, AsyncExportWorkerAccess{}, time.Time{}, err
	}
	record, err := service.repository.GetAsyncExportForWorker(ctx, worker, tenantID, jobID, access)
	if err != nil {
		return AsyncExportRecord{}, AsyncExportWorkerAccess{}, time.Time{}, repositoryError(err)
	}
	record, err = normalizeAsyncExportRecord(record, nil, &access, &jobID)
	if err != nil {
		return AsyncExportRecord{}, AsyncExportWorkerAccess{}, time.Time{}, err
	}
	now, err := service.now()
	if err != nil {
		return AsyncExportRecord{}, AsyncExportWorkerAccess{}, time.Time{}, err
	}
	return record, access, now, nil
}

func (service *AsyncExportService) commitAsyncExportWorker(
	ctx context.Context,
	worker AsyncExportWorker,
	access AsyncExportWorkerAccess,
	query AsyncExportQuerySnapshot,
	plan kernel.TicketExportPlan,
) (AsyncExportResult, error) {
	if err := validateAsyncExportPlanCapacity(plan); err != nil {
		return AsyncExportResult{}, err
	}
	result, err := service.repository.CommitAsyncExportWorkerTransition(ctx, AsyncExportWorkerWrite{
		Worker: worker, Access: access, RequiredCapability: AsyncExportCapabilityExecute,
		Query: query, Plan: plan,
	})
	if err != nil {
		return AsyncExportResult{}, repositoryError(err)
	}
	return validateCommittedAsyncExport(result, plan, query, false)
}

func (service *AsyncExportService) now() (time.Time, error) {
	now := service.clock()
	if now.IsZero() {
		return time.Time{}, ErrUnavailable
	}
	now = now.UTC().Truncate(time.Microsecond)
	if !validStoredInstant(now) {
		return time.Time{}, ErrUnavailable
	}
	return now, nil
}

func normalizeAsyncExportRequestInput(input AsyncExportRequestInput) (AsyncExportRequestInput, error) {
	if !validAsyncExportAudience(input.Audience) ||
		input.Comments < kernel.TicketExportCommentsNone ||
		input.Comments > kernel.TicketExportCommentsPublicAndPrivate ||
		!validIdempotencyKey(input.IdempotencyKey) ||
		(input.Source.Inline == nil) == (input.Source.SavedView == nil) {
		return AsyncExportRequestInput{}, ErrInvalidInput
	}
	if input.MaximumRows == 0 {
		input.MaximumRows = AsyncExportDefaultRows
	}
	if input.MaximumBytes == 0 {
		input.MaximumBytes = AsyncExportDefaultBytes
	}
	if input.Retention == 0 {
		input.Retention = AsyncExportDefaultRetention
	}
	if input.Retention < kernel.TicketExportMinimumRetention ||
		input.Retention > kernel.TicketExportMaximumRetention || input.Retention%time.Microsecond != 0 {
		return AsyncExportRequestInput{}, ErrInvalidInput
	}
	if input.Audience == kernel.TicketExportAudienceCustomer {
		if input.Source.SavedView != nil || input.Comments == kernel.TicketExportCommentsPublicAndPrivate ||
			input.MaximumRows > kernel.TicketExportCustomerMaximumRows ||
			input.MaximumBytes > kernel.TicketExportCustomerMaximumBytes {
			return AsyncExportRequestInput{}, ErrInvalidInput
		}
	} else if input.MaximumRows > kernel.TicketExportOperatorMaximumRows ||
		input.MaximumBytes > kernel.TicketExportOperatorMaximumBytes {
		return AsyncExportRequestInput{}, ErrInvalidInput
	}
	if input.Source.Inline != nil {
		validated, err := validateSavedViewSpecInput(*input.Source.Inline)
		if err != nil {
			return AsyncExportRequestInput{}, err
		}
		input.Source = AsyncExportSourceInput{Inline: &validated}
	} else if !validWorkflowUUID(input.Source.SavedView.ID) ||
		input.Source.SavedView.ExpectedRevision == 0 ||
		input.Source.SavedView.ExpectedRevision > maxResourceVersion ||
		input.Source.SavedView.ExpectedSpecDigest == ([sha256.Size]byte{}) {
		return AsyncExportRequestInput{}, ErrInvalidInput
	} else {
		saved := *input.Source.SavedView
		input.Source = AsyncExportSourceInput{SavedView: &saved}
	}
	return input, nil
}

func validateResolvedAsyncExportQuery(
	input AsyncExportRequestInput,
	access AsyncExportAccess,
	query AsyncExportQuerySnapshot,
) (AsyncExportQuerySnapshot, error) {
	normalized, valid := normalizeAsyncExportQuerySnapshot(query)
	if !valid || normalized.tenant != access.tenant || normalized.kind != access.kind {
		return AsyncExportQuerySnapshot{}, ErrUnavailable
	}
	if input.Source.Inline != nil {
		if normalized.source != kernel.TicketExportQueryInline || normalized.savedView != nil ||
			!ticketBulkResolvedSpecMatchesInput(*input.Source.Inline, normalized.spec) {
			return AsyncExportQuerySnapshot{}, ErrUnavailable
		}
	} else {
		pin := normalized.savedView
		owner, _ := entityID(access.membership)
		if normalized.source != kernel.TicketExportQuerySavedView || pin == nil ||
			uuidFromEntity(pin.ID()) != input.Source.SavedView.ID || pin.Owner() != owner ||
			pin.Revision() != input.Source.SavedView.ExpectedRevision ||
			pin.Digest() != input.Source.SavedView.ExpectedSpecDigest {
			return AsyncExportQuerySnapshot{}, ErrUnavailable
		}
	}
	if access.audience == kernel.TicketExportAudienceCustomer &&
		!customerSafeAsyncExportSpec(normalized.spec) {
		return AsyncExportQuerySnapshot{}, ErrUnavailable
	}
	return normalized, nil
}

func customerSafeAsyncExportSpec(spec kernel.SavedViewSpec) bool {
	filters := spec.Filters()
	visible := filters.CustomerVisible()
	if visible == nil || !*visible || filters.Queue() != kernel.SavedViewQueueAll ||
		filters.AssignedTeam() != nil || filters.Assignee() != nil || filters.ClaimedBy() != nil ||
		len(filters.Custom()) != 0 {
		return false
	}
	for _, column := range spec.Columns() {
		key, core := column.CoreKey()
		if !core || !column.Visible() || !customerSafeAsyncExportColumn(key.String()) {
			return false
		}
	}
	key, core := spec.Sort().CoreKey()
	return core && customerSafeAsyncExportSort(key.String())
}

func customerSafeAsyncExportColumn(key string) bool {
	switch key {
	case "ticket", "state", "risk", "category", "created", "updated":
		return true
	default:
		return false
	}
}

func customerSafeAsyncExportSort(key string) bool {
	switch key {
	case "updated_at", "created_at", "priority":
		return true
	default:
		return false
	}
}

func newAsyncExportDefinition(
	id kernel.EntityID,
	access AsyncExportAccess,
	query AsyncExportQuerySnapshot,
	input AsyncExportRequestInput,
) (kernel.TicketExportDefinition, error) {
	tenant, tenantErr := entityID(access.tenant)
	requester, requesterErr := entityID(access.actor)
	owner, ownerErr := entityID(access.membership)
	if tenantErr != nil || requesterErr != nil || ownerErr != nil {
		return kernel.TicketExportDefinition{}, ErrUnavailable
	}
	var contact *kernel.EntityID
	if access.customerContact != nil {
		value, err := entityID(*access.customerContact)
		if err != nil {
			return kernel.TicketExportDefinition{}, ErrUnavailable
		}
		contact = &value
	}
	definition, err := kernel.NewTicketExportDefinition(kernel.TicketExportDefinitionInput{
		ID: id, Tenant: tenant, Requester: requester, OwnerMembership: owner,
		CustomerContact: contact, Kind: access.kind, Audience: access.audience,
		Comments: input.Comments, QuerySource: query.source, SavedView: query.savedView,
		QueryDigest: query.queryDigest, CatalogDigest: query.catalogDigest,
		ProjectionVersion: kernel.TicketExportProjectionVersion, Format: kernel.TicketExportCSV,
		MaximumRows: input.MaximumRows, MaximumBytes: input.MaximumBytes,
		MaximumAttempts: kernel.TicketExportMaximumAttempts,
	})
	if err != nil {
		// The request, access, and query were already normalized. At this point
		// construction can fail only because the repository supplied a malformed
		// reserved identifier or another inconsistent projection.
		return kernel.TicketExportDefinition{}, ErrUnavailable
	}
	return definition, nil
}

func normalizeAsyncExportRecord(
	record AsyncExportRecord,
	ownerAccess *AsyncExportAccess,
	workerAccess *AsyncExportWorkerAccess,
	expectedID *uuid.UUID,
) (AsyncExportRecord, error) {
	rawDefinition := record.Job.Definition()
	if ownerAccess != nil &&
		(uuidFromEntity(rawDefinition.Tenant()) != ownerAccess.tenant ||
			uuidFromEntity(rawDefinition.Requester()) != ownerAccess.actor ||
			uuidFromEntity(rawDefinition.OwnerMembership()) != ownerAccess.membership ||
			rawDefinition.Kind() != ownerAccess.kind || rawDefinition.Audience() != ownerAccess.audience ||
			!sameAsyncExportContact(rawDefinition.CustomerContact(), ownerAccess.customerContact) ||
			expectedID != nil && uuidFromEntity(rawDefinition.ID()) != *expectedID) {
		return AsyncExportRecord{}, ErrNotFound
	}
	if workerAccess != nil &&
		(uuidFromEntity(rawDefinition.Tenant()) != workerAccess.tenant ||
			rawDefinition.Kind() != workerAccess.kind || rawDefinition.Audience() != workerAccess.audience) {
		return AsyncExportRecord{}, ErrUnavailable
	}
	if ownerAccess == nil && expectedID != nil && uuidFromEntity(rawDefinition.ID()) != *expectedID {
		return AsyncExportRecord{}, ErrUnavailable
	}
	job, err := normalizeAsyncExportJob(record.Job)
	if err != nil {
		return AsyncExportRecord{}, ErrUnavailable
	}
	query, valid := normalizeAsyncExportQuerySnapshot(record.Query)
	if !valid {
		return AsyncExportRecord{}, ErrUnavailable
	}
	definition := job.Definition()
	if query.tenant != uuidFromEntity(definition.Tenant()) || query.kind != definition.Kind() ||
		query.source != definition.QuerySource() || query.queryDigest != definition.QueryDigest() ||
		query.catalogDigest != definition.CatalogDigest() ||
		!sameAsyncExportSavedViewPin(query.savedView, definition.SavedView()) {
		return AsyncExportRecord{}, ErrUnavailable
	}
	if definition.Audience() == kernel.TicketExportAudienceCustomer &&
		!customerSafeAsyncExportSpec(query.spec) {
		return AsyncExportRecord{}, ErrUnavailable
	}
	return AsyncExportRecord{Job: job, Query: query}, nil
}

func normalizeAsyncExportJobForWorker(
	job kernel.TicketExportJob,
	access AsyncExportWorkerAccess,
	expectedID uuid.UUID,
) (kernel.TicketExportJob, error) {
	definition := job.Definition()
	if uuidFromEntity(definition.Tenant()) != access.tenant ||
		definition.Kind() != access.kind || definition.Audience() != access.audience ||
		uuidFromEntity(definition.ID()) != expectedID {
		return kernel.TicketExportJob{}, ErrUnavailable
	}
	return normalizeAsyncExportJob(job)
}

func normalizeAsyncExportJob(job kernel.TicketExportJob) (kernel.TicketExportJob, error) {
	normalized, err := kernel.RestoreTicketExportJob(job.Snapshot())
	if err != nil || normalized.Revision() > maxResourceVersion ||
		normalized.Revision() == maxResourceVersion && !terminalAsyncExportState(normalized.State()) {
		return kernel.TicketExportJob{}, ErrUnavailable
	}
	return normalized, nil
}

func validateAsyncExportRequestReplay(
	replay AsyncExportResult,
	access AsyncExportAccess,
	query AsyncExportQuerySnapshot,
	comments kernel.TicketExportCommentScope,
	maximumRows uint32,
	maximumBytes uint64,
	retention time.Duration,
) (AsyncExportResult, error) {
	record, err := normalizeAsyncExportRecord(replay.Record, &access, nil, nil)
	if err != nil {
		return AsyncExportResult{}, err
	}
	definition := record.Job.Definition()
	if record.Job.State() != kernel.TicketExportPending || record.Job.Revision() != 1 ||
		record.Job.Attempts() != 0 || definition.Comments() != comments ||
		definition.MaximumRows() != maximumRows || definition.MaximumBytes() != maximumBytes ||
		definition.MaximumAttempts() != kernel.TicketExportMaximumAttempts ||
		record.Job.ExpiresAt().Sub(record.Job.RequestedAt()) != retention ||
		!sameAsyncExportQuery(record.Query, query) {
		return AsyncExportResult{}, ErrUnavailable
	}
	replay.Record, replay.Replayed = record, true
	return replay, nil
}

func validateAsyncExportCancelReplay(
	replay AsyncExportResult,
	access AsyncExportAccess,
	jobID uuid.UUID,
	expectedRevision uint64,
) (AsyncExportResult, error) {
	record, err := normalizeAsyncExportRecord(replay.Record, &access, nil, &jobID)
	if err != nil {
		return AsyncExportResult{}, err
	}
	if record.Job.Revision() != expectedRevision+1 ||
		record.Job.State() != kernel.TicketExportCancelledState &&
			record.Job.State() != kernel.TicketExportCancellationRequested {
		return AsyncExportResult{}, ErrUnavailable
	}
	replay.Record, replay.Replayed = record, true
	return replay, nil
}

func validateCommittedAsyncExport(
	result AsyncExportResult,
	plan kernel.TicketExportPlan,
	query AsyncExportQuerySnapshot,
	allowCreateWinnerID bool,
) (AsyncExportResult, error) {
	record, err := normalizeAsyncExportRecord(result.Record, nil, nil, nil)
	if err != nil || !sameAsyncExportQuery(record.Query, query) {
		return AsyncExportResult{}, ErrUnavailable
	}
	next := plan.Next()
	if allowCreateWinnerID && plan.Action() == kernel.TicketExportCreate {
		if !sameAsyncExportCreationWithoutID(record.Job, next) {
			return AsyncExportResult{}, ErrUnavailable
		}
	} else if !kernel.SameTicketExportJob(record.Job, next) {
		return AsyncExportResult{}, ErrUnavailable
	}
	result.Record = record
	return result, nil
}

func sameAsyncExportCreationWithoutID(left, right kernel.TicketExportJob) bool {
	leftSnapshot, rightSnapshot := left.Snapshot(), right.Snapshot()
	leftDefinition, rightDefinition := leftSnapshot.Definition, rightSnapshot.Definition
	leftSnapshot.Definition, rightSnapshot.Definition = kernel.TicketExportDefinition{}, kernel.TicketExportDefinition{}
	if leftDefinition.ID() == (kernel.EntityID{}) || rightDefinition.ID() == (kernel.EntityID{}) ||
		leftDefinition.Tenant() != rightDefinition.Tenant() ||
		leftDefinition.Requester() != rightDefinition.Requester() ||
		leftDefinition.OwnerMembership() != rightDefinition.OwnerMembership() ||
		leftDefinition.Kind() != rightDefinition.Kind() || leftDefinition.Audience() != rightDefinition.Audience() ||
		leftDefinition.Comments() != rightDefinition.Comments() ||
		leftDefinition.QuerySource() != rightDefinition.QuerySource() ||
		leftDefinition.QueryDigest() != rightDefinition.QueryDigest() ||
		leftDefinition.CatalogDigest() != rightDefinition.CatalogDigest() ||
		leftDefinition.ProjectionVersion() != rightDefinition.ProjectionVersion() ||
		leftDefinition.Format() != rightDefinition.Format() ||
		leftDefinition.MaximumRows() != rightDefinition.MaximumRows() ||
		leftDefinition.MaximumBytes() != rightDefinition.MaximumBytes() ||
		leftDefinition.MaximumAttempts() != rightDefinition.MaximumAttempts() ||
		!sameAsyncExportEntity(leftDefinition.CustomerContact(), rightDefinition.CustomerContact()) ||
		!sameAsyncExportSavedViewPin(leftDefinition.SavedView(), rightDefinition.SavedView()) {
		return false
	}
	return leftSnapshot.State == rightSnapshot.State && leftSnapshot.Revision == rightSnapshot.Revision &&
		leftSnapshot.Attempts == rightSnapshot.Attempts && leftSnapshot.FailureCode == rightSnapshot.FailureCode &&
		leftSnapshot.UpdatedAt.Equal(leftSnapshot.RequestedAt) &&
		leftSnapshot.AvailableAt.Equal(leftSnapshot.RequestedAt) &&
		rightSnapshot.UpdatedAt.Equal(rightSnapshot.RequestedAt) &&
		rightSnapshot.AvailableAt.Equal(rightSnapshot.RequestedAt) &&
		leftSnapshot.ExpiresAt.Sub(leftSnapshot.RequestedAt) ==
			rightSnapshot.ExpiresAt.Sub(rightSnapshot.RequestedAt)
}

func normalizeAsyncExportPage(
	page AsyncExportPage,
	record AsyncExportRecord,
	input AsyncExportPageInput,
) (AsyncExportPage, error) {
	if len(page.Rows) > input.Limit || !validOpaqueCursor(page.NextCursor) ||
		page.NextCursor != "" && page.NextCursor == input.After || len(page.Rows) == 0 && page.NextCursor != "" {
		return AsyncExportPage{}, ErrUnavailable
	}
	columns := asyncExportVisibleColumnCount(record.Query.spec)
	comments := record.Job.Definition().Comments()
	audience := record.Job.Definition().Audience()
	result := AsyncExportPage{Rows: make([]AsyncExportRow, len(page.Rows)), NextCursor: page.NextCursor}
	totalBytes := 0
	for index, row := range page.Rows {
		if len(row.Cells) != columns || row.Kind < AsyncExportTicketRow || row.Kind > AsyncExportPrivateCommentRow ||
			row.Kind != AsyncExportTicketRow && comments == kernel.TicketExportCommentsNone ||
			row.Kind == AsyncExportPrivateCommentRow &&
				(audience == kernel.TicketExportAudienceCustomer || comments != kernel.TicketExportCommentsPublicAndPrivate) {
			return AsyncExportPage{}, ErrUnavailable
		}
		result.Rows[index] = AsyncExportRow{Kind: row.Kind, Cells: make([]string, len(row.Cells))}
		for cellIndex, cell := range row.Cells {
			if !validAsyncExportCell(cell) {
				return AsyncExportPage{}, ErrUnavailable
			}
			worstCaseBytes := len(cell)*2 + 3
			if worstCaseBytes > AsyncExportMaximumPageBytes-totalBytes {
				return AsyncExportPage{}, ErrUnavailable
			}
			totalBytes += worstCaseBytes
			result.Rows[index].Cells[cellIndex] = neutralizeSpreadsheetCell(cell)
		}
		if 2 > AsyncExportMaximumPageBytes-totalBytes {
			return AsyncExportPage{}, ErrUnavailable
		}
		totalBytes += 2
	}
	return result, nil
}

func asyncExportVisibleColumnCount(spec kernel.SavedViewSpec) int {
	count := 0
	for _, column := range spec.Columns() {
		if column.Visible() {
			count++
		}
	}
	return count
}

func normalizeAsyncExportPageInput(input AsyncExportPageInput) (AsyncExportPageInput, error) {
	if input.Limit == 0 {
		input.Limit = AsyncExportDefaultPageSize
	}
	if input.ExpectedRevision == 0 || input.ExpectedRevision >= maxResourceVersion ||
		input.Fence == ([sha256.Size]byte{}) || input.Limit < 1 ||
		input.Limit > AsyncExportMaximumPageSize || !validOpaqueCursor(input.After) {
		return AsyncExportPageInput{}, ErrInvalidInput
	}
	return input, nil
}

func sameAsyncExportQuery(left, right AsyncExportQuerySnapshot) bool {
	return left.tenant == right.tenant && left.kind == right.kind && left.source == right.source &&
		left.queryDigest == right.queryDigest && left.catalogDigest == right.catalogDigest &&
		sameAsyncExportSavedViewPin(left.savedView, right.savedView)
}

func sameAsyncExportSavedViewPin(
	left *kernel.TicketExportSavedViewPin,
	right *kernel.TicketExportSavedViewPin,
) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func sameAsyncExportContact(left *kernel.EntityID, right *uuid.UUID) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return uuidFromEntity(*left) == *right
}

func sameAsyncExportEntity(left, right *kernel.EntityID) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func cloneAsyncExportTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func asyncExportOwnerLookupError(err error) error {
	if errors.Is(err, ErrForbidden) || errors.Is(err, ErrNotFound) {
		return ErrNotFound
	}
	return repositoryError(err)
}

func asyncExportPlanError(err error) error {
	switch {
	case errors.Is(err, kernel.ErrTicketExportConflict):
		return ErrPreconditionFailed
	case errors.Is(err, kernel.ErrTicketExportFenceMismatch),
		errors.Is(err, kernel.ErrTicketExportCancelled),
		errors.Is(err, kernel.ErrTicketExportTerminal),
		errors.Is(err, kernel.ErrTicketExportNotClaimable),
		errors.Is(err, kernel.ErrTicketExportNoChange):
		return ErrConflict
	case errors.Is(err, kernel.ErrInvalidTicketExport):
		return ErrInvalidInput
	default:
		return ErrUnavailable
	}
}

func validateAsyncExportPlanCapacity(plan kernel.TicketExportPlan) error {
	next := plan.Next()
	if next.Revision() > maxResourceVersion ||
		next.Revision() == maxResourceVersion && !terminalAsyncExportState(next.State()) {
		return ErrConflict
	}
	return nil
}

func terminalAsyncExportState(state kernel.TicketExportState) bool {
	return state == kernel.TicketExportSucceeded || state == kernel.TicketExportFailed ||
		state == kernel.TicketExportCancelledState
}

func randomAsyncExportFence() ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	_, err := rand.Read(result[:])
	return result, err
}
