package ticketing

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"time"

	"github.com/google/uuid"
	customkernel "github.com/periapsis-im/periapsis/modules/customfields"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

type TicketBulkService struct {
	repository TicketBulkRepository
	clock      func() time.Time
}

func NewTicketBulkService(
	repository TicketBulkRepository,
	clock func() time.Time,
) (*TicketBulkService, error) {
	if nilTicketingDependency(repository) {
		return nil, errors.New("ticket bulk repository is required")
	}
	if clock == nil {
		clock = time.Now
	}
	return &TicketBulkService{repository: repository, clock: clock}, nil
}

func (service *TicketBulkService) Request(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	input TicketBulkRequestInput,
) (TicketBulkResult, error) {
	if ctx == nil || ctx.Err() != nil {
		return TicketBulkResult{}, ErrUnavailable
	}
	if !validMutationActor(actor, tenantID) {
		return TicketBulkResult{}, ErrForbidden
	}
	normalized, explicit, mutation, err := normalizeTicketBulkRequestInput(input)
	if err != nil {
		return TicketBulkResult{}, err
	}
	access, err := service.ticketBulkAccess(
		ctx, actor, tenantID, kind, TicketBulkCapabilityRequest, mutation.Action(),
	)
	if err != nil {
		return TicketBulkResult{}, err
	}
	command, err := bindTicketBulkRequestCommand(
		normalized.IdempotencyKey, access, explicit, normalized.Selection.Query,
		mutation, normalized.Retention,
	)
	if err != nil {
		return TicketBulkResult{}, err
	}
	replay, found, err := service.ticketBulkReplay(ctx, access, command)
	if err != nil {
		return TicketBulkResult{}, err
	}
	if found {
		return validateTicketBulkRequestReplay(
			replay, access, explicit, normalized.Selection.Query, mutation, normalized.Retention,
		)
	}
	var query *TicketBulkQuerySnapshot
	if normalized.Selection.Query != nil {
		resolverInput := cloneTicketBulkQuerySourceInput(normalized.Selection.Query)
		resolved, resolveErr := service.repository.ResolveTicketBulkQuery(
			ctx, actor, tenantID, kind, *resolverInput, access,
		)
		if resolveErr != nil {
			return TicketBulkResult{}, repositoryError(resolveErr)
		}
		resolved, resolveErr = validateResolvedTicketBulkQuery(
			*normalized.Selection.Query, access, resolved,
		)
		if resolveErr != nil {
			return TicketBulkResult{}, resolveErr
		}
		query = &resolved
	}
	reservedID, err := service.repository.ReserveTicketBulkID(ctx, tenantID)
	if err != nil {
		return TicketBulkResult{}, repositoryError(err)
	}
	if _, idErr := kernel.NewEntityID(reservedID.Bytes()); idErr != nil {
		return TicketBulkResult{}, ErrUnavailable
	}
	now, err := service.now()
	if err != nil {
		return TicketBulkResult{}, err
	}
	expiresAt := now.Add(normalized.Retention)
	if !expiresAt.After(now) || !validTicketBulkStoredInstant(expiresAt) {
		return TicketBulkResult{}, ErrUnavailable
	}
	write := TicketBulkRequestWrite{
		Actor: actor, Access: access, RequiredCapability: TicketBulkCapabilityRequest,
		JobID: reservedID, Mutation: mutation, RequestedAt: now, ExpiresAt: expiresAt,
		Command: command, Audit: actor.Audit,
	}
	if explicit != nil {
		selection := *explicit
		write.ExplicitSelection = &selection
	} else {
		write.Query = cloneTicketBulkQuerySnapshot(query)
	}
	result, err := service.repository.CommitTicketBulkRequest(ctx, write)
	if err != nil {
		return TicketBulkResult{}, repositoryError(err)
	}
	return validateCommittedTicketBulkRequest(
		result, access, reservedID, explicit, normalized.Selection.Query,
		query, mutation, now, expiresAt,
	)
}

func (service *TicketBulkService) Get(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	jobID uuid.UUID,
) (TicketBulkRecord, error) {
	if ctx == nil || ctx.Err() != nil {
		return TicketBulkRecord{}, ErrUnavailable
	}
	if !validActor(actor, tenantID) {
		return TicketBulkRecord{}, ErrForbidden
	}
	if !validSavedViewKind(kind) || !validWorkflowUUID(jobID) {
		return TicketBulkRecord{}, ErrInvalidInput
	}
	access, err := service.ticketBulkAccess(
		ctx, actor, tenantID, kind, TicketBulkCapabilityRead, 0,
	)
	if err != nil {
		return TicketBulkRecord{}, err
	}
	record, err := service.repository.GetTicketBulk(ctx, actor, tenantID, jobID, access)
	if err != nil {
		return TicketBulkRecord{}, ticketBulkOwnerLookupError(err)
	}
	return normalizeTicketBulkRecord(record, &access, &jobID)
}

func (service *TicketBulkService) Cancel(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	jobID uuid.UUID,
	input TicketBulkCancelInput,
) (TicketBulkResult, error) {
	if ctx == nil || ctx.Err() != nil {
		return TicketBulkResult{}, ErrUnavailable
	}
	if !validMutationActor(actor, tenantID) {
		return TicketBulkResult{}, ErrForbidden
	}
	if !validSavedViewKind(kind) || !validWorkflowUUID(jobID) ||
		input.ExpectedRevision == 0 || input.ExpectedRevision >= maxResourceVersion ||
		!validIdempotencyKey(input.IdempotencyKey) {
		return TicketBulkResult{}, ErrInvalidInput
	}
	access, err := service.ticketBulkAccess(
		ctx, actor, tenantID, kind, TicketBulkCapabilityCancel, 0,
	)
	if err != nil {
		return TicketBulkResult{}, err
	}
	command, err := bindTicketBulkCancelCommand(
		input.IdempotencyKey, access, jobID, input.ExpectedRevision,
	)
	if err != nil {
		return TicketBulkResult{}, err
	}
	replay, found, err := service.ticketBulkReplay(ctx, access, command)
	if err != nil {
		return TicketBulkResult{}, err
	}
	if found {
		return validateTicketBulkCancelReplay(replay, access, jobID, input.ExpectedRevision)
	}
	record, err := service.repository.GetTicketBulk(ctx, actor, tenantID, jobID, access)
	if err != nil {
		return TicketBulkResult{}, ticketBulkOwnerLookupError(err)
	}
	record, err = normalizeTicketBulkRecord(record, &access, &jobID)
	if err != nil {
		return TicketBulkResult{}, err
	}
	if record.Job.Revision() != input.ExpectedRevision {
		replay, found, err = service.ticketBulkReplay(ctx, access, command)
		if err != nil {
			return TicketBulkResult{}, err
		}
		if found {
			return validateTicketBulkCancelReplay(replay, access, jobID, input.ExpectedRevision)
		}
		return TicketBulkResult{}, ErrPreconditionFailed
	}
	now, err := service.now()
	if err != nil {
		return TicketBulkResult{}, err
	}
	if now.Before(record.Job.UpdatedAt()) {
		return TicketBulkResult{}, ErrUnavailable
	}
	if !now.Before(record.Job.ExpiresAt()) {
		return TicketBulkResult{}, ErrConflict
	}
	plan, err := kernel.PlanTicketBulkCancellation(record.Job, input.ExpectedRevision, now)
	if err != nil {
		return TicketBulkResult{}, ticketBulkPlanError(err)
	}
	if err := validateTicketBulkPlanCapacity(plan); err != nil {
		return TicketBulkResult{}, err
	}
	result, err := service.repository.CommitTicketBulkCancellation(ctx, TicketBulkCancellationWrite{
		Actor: actor, Access: access, RequiredCapability: TicketBulkCapabilityCancel,
		Plan: plan, Command: command, Audit: actor.Audit,
	})
	if err != nil {
		return TicketBulkResult{}, repositoryError(err)
	}
	return validateCommittedTicketBulkCancellation(result, access, jobID, plan, record.Query)
}

func (service *TicketBulkService) ListResults(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	jobID uuid.UUID,
	input TicketBulkResultListInput,
) (TicketBulkResultPage, error) {
	if ctx == nil || ctx.Err() != nil {
		return TicketBulkResultPage{}, ErrUnavailable
	}
	if !validActor(actor, tenantID) {
		return TicketBulkResultPage{}, ErrForbidden
	}
	if !validSavedViewKind(kind) || !validWorkflowUUID(jobID) || input.Limit < 1 ||
		input.Limit > MaximumPageSize || !validTicketBulkResultCursor(input.After) {
		return TicketBulkResultPage{}, ErrInvalidInput
	}
	access, err := service.ticketBulkAccess(
		ctx, actor, tenantID, kind, TicketBulkCapabilityRead, 0,
	)
	if err != nil {
		return TicketBulkResultPage{}, err
	}
	record, err := service.repository.GetTicketBulk(ctx, actor, tenantID, jobID, access)
	if err != nil {
		return TicketBulkResultPage{}, ticketBulkOwnerLookupError(err)
	}
	record, err = normalizeTicketBulkRecord(record, &access, &jobID)
	if err != nil {
		return TicketBulkResultPage{}, err
	}
	page, err := service.repository.ListTicketBulkResults(ctx, TicketBulkResultQuery{
		Actor: actor, Access: access, TenantID: tenantID, JobID: jobID,
		Limit: input.Limit, After: input.After,
	})
	if err != nil {
		return TicketBulkResultPage{}, repositoryError(err)
	}
	return normalizeTicketBulkResultPage(page, record.Job, input)
}

func (service *TicketBulkService) ticketBulkAccess(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	capability TicketBulkCapability,
	mutation kernel.Action,
) (TicketBulkAccess, error) {
	if !validSavedViewKind(kind) || !validTicketBulkCapability(capability) ||
		capability == TicketBulkCapabilityRequest && !validTicketBulkMutationAction(mutation) ||
		capability != TicketBulkCapabilityRequest && mutation != 0 {
		return TicketBulkAccess{}, ErrInvalidInput
	}
	access, err := service.repository.ResolveTicketBulkAccess(
		ctx, actor, tenantID, kind, capability, mutation,
	)
	if err != nil {
		return TicketBulkAccess{}, repositoryError(err)
	}
	if !validTicketBulkAccessShape(access) || access.tenant != tenantID ||
		access.actor != actor.UserID || access.kind != kind || access.capability != capability ||
		access.mutation != mutation {
		return TicketBulkAccess{}, ErrUnavailable
	}
	if !access.allowed {
		return TicketBulkAccess{}, ErrForbidden
	}
	return access, nil
}

func (service *TicketBulkService) ticketBulkReplay(
	ctx context.Context,
	access TicketBulkAccess,
	command TicketBulkCommandBinding,
) (TicketBulkResult, bool, error) {
	replay, found, err := service.repository.LookupTicketBulkReplay(ctx, TicketBulkReplayQuery{
		TenantID: access.tenant, ActorID: access.actor, OwnerMembershipID: access.membership,
		Kind: access.kind, Action: command.Action, KeyHash: command.KeyHash,
		Fingerprint: command.Fingerprint,
	})
	if err != nil {
		return TicketBulkResult{}, false, repositoryError(err)
	}
	return replay, found, nil
}

func (service *TicketBulkService) now() (time.Time, error) {
	now := service.clock()
	if now.IsZero() {
		return time.Time{}, ErrUnavailable
	}
	now = now.UTC().Truncate(time.Microsecond)
	if !validTicketBulkStoredInstant(now) {
		return time.Time{}, ErrUnavailable
	}
	return now, nil
}

func normalizeTicketBulkRequestInput(
	input TicketBulkRequestInput,
) (TicketBulkRequestInput, *kernel.TicketBulkSelection, kernel.TicketBulkMutation, error) {
	hasExplicit := input.Selection.Explicit != nil
	if !validIdempotencyKey(input.IdempotencyKey) ||
		hasExplicit == (input.Selection.Query != nil) {
		return TicketBulkRequestInput{}, nil, kernel.TicketBulkMutation{}, ErrInvalidInput
	}
	if input.Retention == 0 {
		input.Retention = 24 * time.Hour
	}
	if input.Retention < kernel.TicketBulkMinimumRetention ||
		input.Retention > kernel.TicketBulkMaximumRetention || input.Retention%time.Microsecond != 0 {
		return TicketBulkRequestInput{}, nil, kernel.TicketBulkMutation{}, ErrInvalidInput
	}
	mutation, err := ticketBulkMutationFromInput(input.Mutation)
	if err != nil {
		return TicketBulkRequestInput{}, nil, kernel.TicketBulkMutation{}, err
	}
	input.Mutation = cloneTicketBulkMutationInput(input.Mutation)
	if hasExplicit {
		selection, selectionErr := ticketBulkExplicitSelection(input.Selection.Explicit)
		if selectionErr != nil {
			return TicketBulkRequestInput{}, nil, kernel.TicketBulkMutation{}, selectionErr
		}
		canonical := selection.ExplicitTargets()
		input.Selection = TicketBulkSelectionInput{Explicit: make([]TicketBulkTargetInput, len(canonical))}
		for index, pin := range canonical {
			input.Selection.Explicit[index] = TicketBulkTargetInput{
				ID: uuidFromEntity(pin.ID()), ExpectedVersion: pin.Version(),
			}
		}
		return input, &selection, mutation, nil
	}
	query, err := normalizeTicketBulkQuerySourceInput(*input.Selection.Query)
	if err != nil {
		return TicketBulkRequestInput{}, nil, kernel.TicketBulkMutation{}, err
	}
	input.Selection = TicketBulkSelectionInput{Query: &query}
	return input, nil, mutation, nil
}

func normalizeTicketBulkQuerySourceInput(
	input TicketBulkQuerySourceInput,
) (TicketBulkQuerySourceInput, error) {
	if (input.Inline == nil) == (input.SavedView == nil) {
		return TicketBulkQuerySourceInput{}, ErrInvalidInput
	}
	if input.Inline != nil {
		validated, err := canonicalTicketBulkInlineSpecInput(*input.Inline)
		if err != nil {
			return TicketBulkQuerySourceInput{}, err
		}
		return TicketBulkQuerySourceInput{Inline: cloneTicketBulkSpecInput(&validated)}, nil
	}
	if !validWorkflowUUID(input.SavedView.ID) || input.SavedView.ExpectedRevision == 0 ||
		input.SavedView.ExpectedRevision > maxResourceVersion ||
		input.SavedView.ExpectedSpecDigest == ([32]byte{}) {
		return TicketBulkQuerySourceInput{}, ErrInvalidInput
	}
	saved := *input.SavedView
	return TicketBulkQuerySourceInput{SavedView: &saved}, nil
}

func validateResolvedTicketBulkQuery(
	input TicketBulkQuerySourceInput,
	access TicketBulkAccess,
	query TicketBulkQuerySnapshot,
) (TicketBulkQuerySnapshot, error) {
	normalized, valid := normalizeTicketBulkQuerySnapshot(query)
	if !valid || normalized.tenant != access.tenant || normalized.kind != access.kind {
		return TicketBulkQuerySnapshot{}, ErrUnavailable
	}
	if input.Inline != nil {
		if normalized.source != TicketBulkQueryInline || normalized.savedView != nil ||
			!ticketBulkResolvedSpecMatchesInput(*input.Inline, normalized.spec) {
			return TicketBulkQuerySnapshot{}, ErrUnavailable
		}
		return normalized, nil
	}
	pin := normalized.savedView
	if normalized.source != TicketBulkQuerySavedView || pin == nil ||
		uuidFromEntity(pin.ID()) != input.SavedView.ID ||
		uuidFromEntity(pin.Owner()) != access.membership ||
		pin.Revision() != input.SavedView.ExpectedRevision ||
		pin.SpecDigest() != input.SavedView.ExpectedSpecDigest {
		return TicketBulkQuerySnapshot{}, ErrUnavailable
	}
	return normalized, nil
}

func normalizeTicketBulkRecord(
	record TicketBulkRecord,
	access *TicketBulkAccess,
	expectedID *uuid.UUID,
) (TicketBulkRecord, error) {
	job, err := kernel.RestoreTicketBulkJob(record.Job.Snapshot())
	if err != nil || job.Revision() > maxResourceVersion ||
		job.Revision() == maxResourceVersion && !terminalTicketBulkState(job.State()) {
		return TicketBulkRecord{}, ErrUnavailable
	}
	definition := job.Definition()
	if definition.ProjectionVersion() != kernel.TicketBulkProjectionVersion ||
		definition.MaximumAttempts() != kernel.TicketBulkMaximumAttempts {
		return TicketBulkRecord{}, ErrUnavailable
	}
	if access != nil && (uuidFromEntity(definition.Tenant()) != access.tenant ||
		uuidFromEntity(definition.Requester()) != access.actor ||
		uuidFromEntity(definition.OwnerMembership()) != access.membership ||
		definition.Kind() != access.kind) {
		return TicketBulkRecord{}, ErrUnavailable
	}
	if expectedID != nil && uuidFromEntity(definition.ID()) != *expectedID {
		return TicketBulkRecord{}, ErrUnavailable
	}
	selection := definition.Selection()
	var query *TicketBulkQuerySnapshot
	switch selection.Source() {
	case kernel.TicketBulkSelectionExplicit:
		if record.Query != nil || selection.QueryDigest() != ([32]byte{}) ||
			selection.SavedView() != nil || len(selection.ExplicitTargets()) == 0 {
			return TicketBulkRecord{}, ErrUnavailable
		}
		for _, target := range selection.ExplicitTargets() {
			if target.Version() > maxResourceVersion {
				return TicketBulkRecord{}, ErrUnavailable
			}
		}
	case kernel.TicketBulkSelectionQuery:
		if record.Query == nil {
			return TicketBulkRecord{}, ErrUnavailable
		}
		normalized, valid := normalizeTicketBulkQuerySnapshot(*record.Query)
		if !valid || normalized.tenant != uuidFromEntity(definition.Tenant()) ||
			normalized.kind != definition.Kind() || normalized.queryDigest != selection.QueryDigest() ||
			!sameTicketBulkSavedViewPin(normalized.savedView, selection.SavedView()) {
			return TicketBulkRecord{}, ErrUnavailable
		}
		query = &normalized
	default:
		return TicketBulkRecord{}, ErrUnavailable
	}
	return TicketBulkRecord{Job: job, Query: query}, nil
}

func validateTicketBulkRequestReplay(
	replay TicketBulkResult,
	access TicketBulkAccess,
	explicit *kernel.TicketBulkSelection,
	queryInput *TicketBulkQuerySourceInput,
	mutation kernel.TicketBulkMutation,
	retention time.Duration,
) (TicketBulkResult, error) {
	record, err := normalizeTicketBulkRecord(replay.Record, &access, nil)
	if err != nil {
		return TicketBulkResult{}, err
	}
	definition := record.Job.Definition()
	if record.Job.State() != kernel.TicketBulkPending || record.Job.Revision() != 1 ||
		definition.ProjectionVersion() != kernel.TicketBulkProjectionVersion ||
		definition.MaximumAttempts() != kernel.TicketBulkMaximumAttempts ||
		!sameTicketBulkMutation(definition.Mutation(), mutation) ||
		record.Job.ExpiresAt().Sub(record.Job.RequestedAt()) != retention ||
		!ticketBulkRequestSelectionMatchesInput(
			definition.Selection(), record.Query, explicit, queryInput, access.membership,
		) {
		return TicketBulkResult{}, ErrUnavailable
	}
	replay.Record, replay.Replayed = record, true
	return replay, nil
}

func validateCommittedTicketBulkRequest(
	result TicketBulkResult,
	access TicketBulkAccess,
	reservedID kernel.EntityID,
	explicit *kernel.TicketBulkSelection,
	queryInput *TicketBulkQuerySourceInput,
	query *TicketBulkQuerySnapshot,
	mutation kernel.TicketBulkMutation,
	requestedAt time.Time,
	expiresAt time.Time,
) (TicketBulkResult, error) {
	record, err := normalizeTicketBulkRecord(result.Record, &access, nil)
	if err != nil {
		return TicketBulkResult{}, err
	}
	definition := record.Job.Definition()
	if definition.ProjectionVersion() != kernel.TicketBulkProjectionVersion ||
		definition.MaximumAttempts() != kernel.TicketBulkMaximumAttempts ||
		!sameTicketBulkMutation(definition.Mutation(), mutation) {
		return TicketBulkResult{}, ErrUnavailable
	}
	if result.Replayed {
		return validateTicketBulkRequestReplay(
			TicketBulkResult{Record: record, Replayed: true}, access,
			explicit, queryInput, mutation, expiresAt.Sub(requestedAt),
		)
	}
	if !ticketBulkRequestSelectionMatches(definition.Selection(), record.Query, explicit, query) {
		return TicketBulkResult{}, ErrUnavailable
	}
	if definition.ID() != reservedID {
		return TicketBulkResult{}, ErrUnavailable
	}
	expectedDefinition, err := kernel.NewTicketBulkDefinition(kernel.TicketBulkDefinitionInput{
		ID: reservedID, Tenant: definition.Tenant(), Requester: definition.Requester(),
		OwnerMembership: definition.OwnerMembership(), Kind: definition.Kind(),
		Selection: definition.Selection(), Mutation: mutation,
		ProjectionVersion: kernel.TicketBulkProjectionVersion,
		MaximumAttempts:   kernel.TicketBulkMaximumAttempts,
	})
	if err != nil {
		return TicketBulkResult{}, ErrUnavailable
	}
	plan, err := kernel.PlanTicketBulkCreation(expectedDefinition, requestedAt, expiresAt)
	if err != nil || !kernel.SameTicketBulkJob(record.Job, plan.Next()) {
		return TicketBulkResult{}, ErrUnavailable
	}
	result.Record = record
	return result, nil
}

func validateTicketBulkCancelReplay(
	replay TicketBulkResult,
	access TicketBulkAccess,
	jobID uuid.UUID,
	expectedRevision uint64,
) (TicketBulkResult, error) {
	record, err := normalizeTicketBulkRecord(replay.Record, &access, &jobID)
	if err != nil || record.Job.Revision() != expectedRevision+1 ||
		record.Job.State() != kernel.TicketBulkCancelledState &&
			record.Job.State() != kernel.TicketBulkCancellationRequested {
		return TicketBulkResult{}, ErrUnavailable
	}
	replay.Record, replay.Replayed = record, true
	return replay, nil
}

func validateCommittedTicketBulkCancellation(
	result TicketBulkResult,
	access TicketBulkAccess,
	jobID uuid.UUID,
	plan kernel.TicketBulkPlan,
	query *TicketBulkQuerySnapshot,
) (TicketBulkResult, error) {
	record, err := normalizeTicketBulkRecord(result.Record, &access, &jobID)
	if err != nil || !sameTicketBulkQueryPointer(record.Query, query) ||
		!kernel.SameTicketBulkJob(record.Job, plan.Next()) {
		return TicketBulkResult{}, ErrUnavailable
	}
	result.Record = record
	return result, nil
}

func normalizeTicketBulkResultPage(
	page TicketBulkResultPage,
	job kernel.TicketBulkJob,
	input TicketBulkResultListInput,
) (TicketBulkResultPage, error) {
	if len(page.Items) > input.Limit || !validTicketBulkResultCursor(page.Next) ||
		page.Next != "" && (len(page.Items) == 0 || page.Next == input.After) {
		return TicketBulkResultPage{}, ErrUnavailable
	}
	items := slices.Clone(page.Items)
	var previous uint32
	pageCounts := make(map[kernel.TicketBulkTargetResult]uint32, 9)
	seenTargets := make(map[uuid.UUID]struct{}, len(items))
	explicitPins := ticketBulkExplicitTargetVersions(job.Definition().Selection())
	for _, item := range items {
		if item.Sequence == 0 || item.Sequence > job.Progress().Total() ||
			item.Sequence <= previous || !validWorkflowUUID(item.TargetID) ||
			item.TargetVersion == 0 || item.TargetVersion > maxResourceVersion ||
			!validTicketBulkTargetResult(item.Result) || !validTicketBulkStoredInstant(item.RecordedAt) ||
			item.RecordedAt.Before(job.RequestedAt()) || item.RecordedAt.After(job.UpdatedAt()) {
			return TicketBulkResultPage{}, ErrUnavailable
		}
		if _, duplicate := seenTargets[item.TargetID]; duplicate {
			return TicketBulkResultPage{}, ErrUnavailable
		}
		seenTargets[item.TargetID] = struct{}{}
		if explicitPins != nil {
			version, exists := explicitPins[item.TargetID]
			if !exists || version != item.TargetVersion {
				return TicketBulkResultPage{}, ErrUnavailable
			}
		}
		pageCounts[item.Result]++
		if pageCounts[item.Result] > job.Progress().Count(item.Result) {
			return TicketBulkResultPage{}, ErrUnavailable
		}
		previous = item.Sequence
	}
	return TicketBulkResultPage{Items: items, Next: page.Next}, nil
}

func ticketBulkRequestSelectionMatchesInput(
	selection kernel.TicketBulkSelection,
	recordQuery *TicketBulkQuerySnapshot,
	explicit *kernel.TicketBulkSelection,
	queryInput *TicketBulkQuerySourceInput,
	expectedOwner uuid.UUID,
) bool {
	if explicit != nil {
		return queryInput == nil && recordQuery == nil && sameTicketBulkSelection(selection, *explicit)
	}
	if queryInput == nil || recordQuery == nil || selection.Source() != kernel.TicketBulkSelectionQuery ||
		selection.QueryDigest() != recordQuery.queryDigest ||
		!sameTicketBulkSavedViewPin(selection.SavedView(), recordQuery.savedView) {
		return false
	}
	if queryInput.Inline != nil {
		return recordQuery.source == TicketBulkQueryInline && recordQuery.savedView == nil &&
			ticketBulkResolvedSpecMatchesInput(*queryInput.Inline, recordQuery.spec)
	}
	pin := recordQuery.savedView
	return queryInput.SavedView != nil && recordQuery.source == TicketBulkQuerySavedView && pin != nil &&
		uuidFromEntity(pin.ID()) == queryInput.SavedView.ID &&
		uuidFromEntity(pin.Owner()) == expectedOwner &&
		pin.Revision() == queryInput.SavedView.ExpectedRevision &&
		pin.SpecDigest() == queryInput.SavedView.ExpectedSpecDigest
}

func ticketBulkResolvedSpecMatchesInput(input SavedViewSpecInput, spec kernel.SavedViewSpec) bool {
	normalized, err := canonicalTicketBulkInlineSpecInput(input)
	if err != nil {
		return false
	}
	resolved, err := SavedViewSpecInputFromResolved(spec)
	if err != nil || len(normalized.Filters.Custom) != len(resolved.Filters.Custom) {
		return false
	}
	filters := spec.Filters().Custom()
	if len(filters) != len(normalized.Filters.Custom) {
		return false
	}
	for index := range normalized.Filters.Custom {
		left, right := &normalized.Filters.Custom[index], &resolved.Filters.Custom[index]
		if left.DefinitionID != right.DefinitionID ||
			left.ExpectedDefinitionVersion != right.ExpectedDefinitionVersion ||
			left.Operator != right.Operator ||
			!ticketBulkCustomFilterValueMatches(filters[index], left.Value) {
			return false
		}
		left.Value, right.Value = nil, nil
	}
	return reflect.DeepEqual(normalized, resolved)
}

func canonicalTicketBulkInlineSpecInput(input SavedViewSpecInput) (SavedViewSpecInput, error) {
	result, err := NormalizeSavedViewSpecInput(input)
	if err != nil {
		return SavedViewSpecInput{}, err
	}
	slices.Sort(result.Filters.States)
	slices.Sort(result.Filters.Severities)
	slices.Sort(result.Filters.Priorities)
	if result.Filters.States == nil {
		result.Filters.States = []string{}
	}
	if result.Filters.Severities == nil {
		result.Filters.Severities = []string{}
	}
	if result.Filters.Priorities == nil {
		result.Filters.Priorities = []string{}
	}
	slices.SortFunc(result.Filters.Custom, func(left, right SavedViewCustomFilterInput) int {
		return bytes.Compare(left.DefinitionID[:], right.DefinitionID[:])
	})
	return result, nil
}

func ticketBulkCustomFilterValueMatches(
	filter kernel.SavedViewCustomFilter,
	raw json.RawMessage,
) bool {
	pin := filter.Definition()
	definitionID, idErr := customkernel.NewEntityID(pin.ID().Bytes())
	tenantID, tenantErr := customkernel.NewEntityID(pin.Tenant().Bytes())
	key, keyErr := customkernel.NewKey(pin.Key().String())
	if idErr != nil || tenantErr != nil || keyErr != nil {
		return false
	}
	objectType := customkernel.ObjectAlert
	if pin.Kind() == kernel.AggregateCase {
		objectType = customkernel.ObjectCase
	}
	var options []customkernel.OptionInput
	if filter.DataType() == customkernel.TypeSingleSelect {
		var option string
		if json.Unmarshal(raw, &option) != nil {
			return false
		}
		optionKey, err := customkernel.NewKey(option)
		if err != nil {
			return false
		}
		options = []customkernel.OptionInput{{
			ID: definitionID, Key: optionKey, Label: "bulk option", Position: 1,
		}}
	}
	definition, err := customkernel.NewDefinition(customkernel.DefinitionInput{
		ID: definitionID, TenantID: tenantID, ObjectType: objectType, Key: key,
		Label: "bulk filter", DataType: filter.DataType(),
		Options: options, Visibility: customkernel.Visibility{Operator: true},
		Placement: customkernel.Placement{ShowInList: true}, Filterable: true,
		SchemaVersion: pin.Version(),
	})
	if err != nil {
		return false
	}
	plan, fieldErr := customkernel.PlanFilter(
		definition,
		customkernel.FilterInput{
			Key: key, Operator: customkernel.FilterEqual, Value: customkernel.JSONInputValue(raw),
		},
		tenantID, objectType, customkernel.AudienceOperator, customkernel.SurfaceList,
	)
	if fieldErr != nil {
		return false
	}
	value := plan.Value()
	return value.Presence() == customkernel.PresencePresent &&
		bytes.Equal(value.CanonicalJSON(), filter.CanonicalJSON())
}

func ticketBulkExplicitTargetVersions(selection kernel.TicketBulkSelection) map[uuid.UUID]uint64 {
	if selection.Source() != kernel.TicketBulkSelectionExplicit {
		return nil
	}
	result := make(map[uuid.UUID]uint64, selection.TargetCount())
	for _, pin := range selection.ExplicitTargets() {
		result[uuidFromEntity(pin.ID())] = pin.Version()
	}
	return result
}

func validTicketBulkResultCursor(value string) bool {
	if value == "" {
		return true
	}
	if !validOpaqueCursor(value) {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func validTicketBulkStoredInstant(value time.Time) bool {
	return validStoredInstant(value) && value.Year() >= 1 && value.Year() <= 9_999
}

func ticketBulkRequestSelectionMatches(
	selection kernel.TicketBulkSelection,
	recordQuery *TicketBulkQuerySnapshot,
	explicit *kernel.TicketBulkSelection,
	query *TicketBulkQuerySnapshot,
) bool {
	if explicit != nil {
		return query == nil && recordQuery == nil && sameTicketBulkSelection(selection, *explicit)
	}
	return query != nil && recordQuery != nil && selection.Source() == kernel.TicketBulkSelectionQuery &&
		selection.QueryDigest() == query.queryDigest && sameTicketBulkQuery(*recordQuery, *query) &&
		sameTicketBulkSavedViewPin(selection.SavedView(), query.savedView)
}

func sameTicketBulkSelection(left, right kernel.TicketBulkSelection) bool {
	if left.Source() != right.Source() || left.TargetCount() != right.TargetCount() ||
		left.QueryDigest() != right.QueryDigest() || left.TargetSetDigest() != right.TargetSetDigest() ||
		!sameTicketBulkSavedViewPin(left.SavedView(), right.SavedView()) {
		return false
	}
	return slices.Equal(left.ExplicitTargets(), right.ExplicitTargets())
}

func sameTicketBulkMutation(left, right kernel.TicketBulkMutation) bool {
	leftEnvelope, leftErr := canonicalTicketBulkMutationEnvelope(left)
	rightEnvelope, rightErr := canonicalTicketBulkMutationEnvelope(right)
	return leftErr == nil && rightErr == nil && leftEnvelope == rightEnvelope
}

func sameTicketBulkQuery(left, right TicketBulkQuerySnapshot) bool {
	return left.tenant == right.tenant && left.kind == right.kind && left.source == right.source &&
		left.queryDigest == right.queryDigest && left.catalogDigest == right.catalogDigest &&
		sameTicketBulkSavedViewPin(left.savedView, right.savedView)
}

func sameTicketBulkQueryPointer(left, right *TicketBulkQuerySnapshot) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return sameTicketBulkQuery(*left, *right)
}

func sameTicketBulkSavedViewPin(
	left *kernel.TicketBulkSavedViewPin,
	right *kernel.TicketBulkSavedViewPin,
) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.ID() == right.ID() && left.Owner() == right.Owner() &&
		left.Revision() == right.Revision() && left.SpecDigest() == right.SpecDigest()
}

func terminalTicketBulkState(state kernel.TicketBulkState) bool {
	return state == kernel.TicketBulkCompleted || state == kernel.TicketBulkFailed ||
		state == kernel.TicketBulkCancelledState || state == kernel.TicketBulkAuthorizationRevokedState
}

func validateTicketBulkPlanCapacity(plan kernel.TicketBulkPlan) error {
	next := plan.Next()
	if next.Revision() > maxResourceVersion ||
		next.Revision() == maxResourceVersion && !terminalTicketBulkState(next.State()) {
		return ErrConflict
	}
	return nil
}

func ticketBulkPlanError(err error) error {
	switch {
	case errors.Is(err, kernel.ErrTicketBulkConflict):
		return ErrConflict
	case errors.Is(err, kernel.ErrInvalidTicketBulkJob),
		errors.Is(err, kernel.ErrInvalidTicketBulkOperation),
		errors.Is(err, kernel.ErrInvalidTicketBulkProgress):
		return ErrUnavailable
	default:
		return ErrUnavailable
	}
}

func ticketBulkOwnerLookupError(err error) error {
	if errors.Is(err, ErrForbidden) || errors.Is(err, ErrNotFound) {
		return ErrNotFound
	}
	return repositoryError(err)
}
