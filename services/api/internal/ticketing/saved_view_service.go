package ticketing

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"unicode/utf8"

	"github.com/google/uuid"
	customkernel "github.com/periapsis-im/periapsis/modules/customfields"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

const (
	maximumSavedViewColumns     = 64
	maximumSavedViewFilters     = 8
	maximumSavedViewStates      = 20
	maximumSavedViewEnums       = 5
	maximumSavedViewScalarBytes = 64 * 1024
	maximumSavedViewScalarRunes = 10_000
)

type SavedViewService struct {
	repository SavedViewRepository
}

func NewSavedViewService(repository SavedViewRepository) (*SavedViewService, error) {
	if repository == nil {
		return nil, errors.New("saved-view repository is required")
	}
	return &SavedViewService{repository: repository}, nil
}

func (service *SavedViewService) ListSavedViews(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	input SavedViewListInput,
) (SavedViewPage, error) {
	if !validActor(actor, tenantID) {
		return SavedViewPage{}, ErrForbidden
	}
	if !validSavedViewKind(kind) {
		return SavedViewPage{}, ErrInvalidInput
	}
	validated, err := validateSavedViewListInput(input)
	if err != nil {
		return SavedViewPage{}, err
	}
	access, err := service.savedViewAccess(ctx, actor, tenantID, kind, SavedViewCapabilityRead)
	if err != nil {
		return SavedViewPage{}, err
	}
	page, err := service.repository.ListSavedViews(
		ctx, actor, tenantID, kind, validated, access,
	)
	if err != nil {
		return SavedViewPage{}, repositoryError(err)
	}
	if len(page.Items) > validated.Limit || !validOpaqueCursor(page.NextCursor) ||
		len(page.Items) == 0 && page.NextCursor != "" {
		return SavedViewPage{}, ErrUnavailable
	}
	owner := savedViewOwnerEntity(access)
	items := make([]SavedViewRecord, len(page.Items))
	var previous uuid.UUID
	for index, record := range page.Items {
		normalized, valid := normalizeSavedViewRecord(record, tenantID, owner, kind)
		if !valid || !validated.IncludeArchived && normalized.View.Status() == kernel.SavedViewArchived {
			return SavedViewPage{}, ErrUnavailable
		}
		current := uuidFromEntity(normalized.View.ID())
		if index > 0 && bytes.Compare(previous[:], current[:]) >= 0 {
			return SavedViewPage{}, ErrUnavailable
		}
		items[index] = normalized
		previous = current
	}
	page.Items = items
	return page, nil
}

func (service *SavedViewService) GetSavedView(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	viewID uuid.UUID,
) (SavedViewRecord, error) {
	if !validActor(actor, tenantID) {
		return SavedViewRecord{}, ErrForbidden
	}
	if !validSavedViewKind(kind) || !validWorkflowUUID(viewID) {
		return SavedViewRecord{}, ErrInvalidInput
	}
	access, err := service.savedViewAccess(ctx, actor, tenantID, kind, SavedViewCapabilityRead)
	if err != nil {
		return SavedViewRecord{}, err
	}
	return service.loadSavedView(ctx, actor, tenantID, kind, viewID, access)
}

func (service *SavedViewService) CreateSavedView(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	input SavedViewCreateInput,
) (SavedViewMutationResult, error) {
	if !validMutationActor(actor, tenantID) {
		return SavedViewMutationResult{}, ErrForbidden
	}
	if !validSavedViewKind(kind) || !validText(input.Name, 120, false) ||
		!validIdempotencyKey(input.IdempotencyKey) {
		return SavedViewMutationResult{}, ErrInvalidInput
	}
	validatedSpec, err := validateSavedViewSpecInput(input.Spec)
	if err != nil {
		return SavedViewMutationResult{}, err
	}
	access, err := service.savedViewAccess(ctx, actor, tenantID, kind, SavedViewCapabilityManage)
	if err != nil {
		return SavedViewMutationResult{}, err
	}
	spec, digest, err := service.resolveSavedViewSpec(
		ctx, actor, tenantID, kind, validatedSpec, access,
	)
	if err != nil {
		return SavedViewMutationResult{}, err
	}
	command, err := bindSavedViewCommand(
		input.IdempotencyKey, kernel.SavedViewCreate, tenantID, access.membership,
		kind, nil, 0, input.Name, &digest,
	)
	if err != nil {
		return SavedViewMutationResult{}, err
	}
	replay, found, replayErr := service.savedViewReplay(ctx, actor, access, command)
	if replayErr != nil {
		return SavedViewMutationResult{}, replayErr
	}
	if found {
		replay, valid := normalizeSavedViewReplay(
			replay, tenantID, savedViewOwnerEntity(access), kind, nil, 1,
			input.Name, kernel.SavedViewActive, digest,
		)
		if !valid {
			return SavedViewMutationResult{}, ErrUnavailable
		}
		replay.Replayed = true
		return replay, nil
	}
	id, err := service.repository.ReserveSavedViewID(ctx, tenantID)
	if err != nil {
		return SavedViewMutationResult{}, repositoryError(err)
	}
	plan, err := kernel.PlanSavedViewCreation(
		id, workflowTenantEntity(tenantID), savedViewOwnerEntity(access), kind, input.Name, spec,
	)
	if err != nil {
		return SavedViewMutationResult{}, savedViewInputError(err)
	}
	return service.commitSavedView(ctx, actor, tenantID, access, plan, command, nil)
}

func (service *SavedViewService) ReplaceSavedView(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	viewID uuid.UUID,
	input SavedViewReplaceInput,
) (SavedViewMutationResult, error) {
	if err := validateSavedViewMutationEnvelope(
		actor, tenantID, kind, viewID, input.ExpectedRevision, input.IdempotencyKey,
	); err != nil {
		return SavedViewMutationResult{}, err
	}
	if !validText(input.Name, 120, false) || !ValidSavedViewStrongETag(input.ExpectedETag) {
		return SavedViewMutationResult{}, ErrInvalidInput
	}
	validatedSpec, err := validateSavedViewSpecInput(input.Spec)
	if err != nil {
		return SavedViewMutationResult{}, err
	}
	access, err := service.savedViewAccess(ctx, actor, tenantID, kind, SavedViewCapabilityManage)
	if err != nil {
		return SavedViewMutationResult{}, err
	}
	spec, digest, err := service.resolveSavedViewSpec(
		ctx, actor, tenantID, kind, validatedSpec, access,
	)
	if err != nil {
		return SavedViewMutationResult{}, err
	}
	command, err := bindSavedViewCommand(
		input.IdempotencyKey, kernel.SavedViewReplace, tenantID, access.membership,
		kind, &viewID, input.ExpectedRevision, input.Name, &digest,
	)
	if err != nil {
		return SavedViewMutationResult{}, err
	}
	replay, found, replayErr := service.savedViewReplay(ctx, actor, access, command)
	if replayErr != nil {
		return SavedViewMutationResult{}, replayErr
	}
	if found {
		return validatedSavedViewReplay(
			replay, tenantID, savedViewOwnerEntity(access), kind,
			&viewID, input.ExpectedRevision+1, input.Name, kernel.SavedViewActive, digest,
		)
	}
	current, err := service.loadSavedView(ctx, actor, tenantID, kind, viewID, access)
	if err != nil {
		return SavedViewMutationResult{}, err
	}
	if SavedViewStrongETag(current) != input.ExpectedETag || current.View.Revision() != input.ExpectedRevision {
		return SavedViewMutationResult{}, ErrPreconditionFailed
	}
	plan, err := kernel.PlanSavedViewReplacement(
		current.View, input.ExpectedRevision, input.Name, spec,
	)
	if err != nil {
		return SavedViewMutationResult{}, savedViewPlanError(err)
	}
	return service.commitSavedView(ctx, actor, tenantID, access, plan, command, &viewID)
}

func (service *SavedViewService) ArchiveSavedView(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	viewID uuid.UUID,
	input SavedViewLifecycleInput,
) (SavedViewMutationResult, error) {
	return service.lifecycleSavedView(
		ctx, actor, tenantID, kind, viewID, input, kernel.SavedViewArchive,
		kernel.PlanSavedViewArchive,
	)
}

func (service *SavedViewService) RestoreSavedView(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	viewID uuid.UUID,
	input SavedViewLifecycleInput,
) (SavedViewMutationResult, error) {
	return service.lifecycleSavedView(
		ctx, actor, tenantID, kind, viewID, input, kernel.SavedViewRestore,
		kernel.PlanSavedViewRestore,
	)
}

func (service *SavedViewService) lifecycleSavedView(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	viewID uuid.UUID,
	input SavedViewLifecycleInput,
	action kernel.SavedViewAction,
	planner func(kernel.SavedView, uint64) (kernel.SavedViewPlan, error),
) (SavedViewMutationResult, error) {
	if err := validateSavedViewMutationEnvelope(
		actor, tenantID, kind, viewID, input.ExpectedRevision, input.IdempotencyKey,
	); err != nil {
		return SavedViewMutationResult{}, err
	}
	if !ValidSavedViewStrongETag(input.ExpectedETag) {
		return SavedViewMutationResult{}, ErrInvalidInput
	}
	access, err := service.savedViewAccess(ctx, actor, tenantID, kind, SavedViewCapabilityManage)
	if err != nil {
		return SavedViewMutationResult{}, err
	}
	command, err := bindSavedViewCommand(
		input.IdempotencyKey, action, tenantID, access.membership, kind,
		&viewID, input.ExpectedRevision, "", nil,
	)
	if err != nil {
		return SavedViewMutationResult{}, err
	}
	replay, found, replayErr := service.savedViewReplay(ctx, actor, access, command)
	if replayErr != nil {
		return SavedViewMutationResult{}, replayErr
	}
	if found {
		normalized, valid := normalizeSavedViewRecord(
			replay.Record, tenantID, savedViewOwnerEntity(access), kind,
		)
		if !valid || uuidFromEntity(normalized.View.ID()) != viewID ||
			normalized.View.Revision() != input.ExpectedRevision+1 ||
			action == kernel.SavedViewArchive && normalized.View.Status() != kernel.SavedViewArchived ||
			action == kernel.SavedViewRestore && normalized.View.Status() != kernel.SavedViewActive {
			return SavedViewMutationResult{}, ErrUnavailable
		}
		replay.Record = normalized
		replay.Replayed = true
		return replay, nil
	}
	current, err := service.loadSavedView(ctx, actor, tenantID, kind, viewID, access)
	if err != nil {
		return SavedViewMutationResult{}, err
	}
	if SavedViewStrongETag(current) != input.ExpectedETag || current.View.Revision() != input.ExpectedRevision {
		return SavedViewMutationResult{}, ErrPreconditionFailed
	}
	plan, err := planner(current.View, input.ExpectedRevision)
	if err != nil {
		return SavedViewMutationResult{}, savedViewPlanError(err)
	}
	return service.commitSavedView(ctx, actor, tenantID, access, plan, command, &viewID)
}

func (service *SavedViewService) savedViewAccess(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	capability SavedViewCapability,
) (SavedViewAccess, error) {
	access, err := service.repository.ResolveSavedViewAccess(
		ctx, actor, tenantID, kind, capability,
	)
	if err != nil {
		return SavedViewAccess{}, repositoryError(err)
	}
	if access.tenant != tenantID || access.actor != actor.UserID || access.kind != kind ||
		access.capability != capability || !validWorkflowUUID(access.membership) ||
		!validSavedViewCapability(access.capability) ||
		access.principal != kernel.PrincipalOperator && access.principal != kernel.PrincipalCustomer &&
			access.principal != kernel.PrincipalServiceAccount {
		return SavedViewAccess{}, ErrUnavailable
	}
	if !access.allowed || access.principal != kernel.PrincipalOperator {
		return SavedViewAccess{}, ErrForbidden
	}
	return access, nil
}

func (service *SavedViewService) resolveSavedViewSpec(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	input SavedViewSpecInput,
	access SavedViewAccess,
) (kernel.SavedViewSpec, [sha256.Size]byte, error) {
	spec, err := service.repository.ResolveSavedViewSpec(
		ctx, actor, tenantID, kind, input, access,
	)
	if err != nil {
		return kernel.SavedViewSpec{}, [sha256.Size]byte{}, repositoryError(err)
	}
	tenant := workflowTenantEntity(tenantID)
	if err := kernel.ValidateSavedViewSpec(tenant, kind, spec); err != nil {
		return kernel.SavedViewSpec{}, [sha256.Size]byte{}, ErrUnavailable
	}
	digest, err := SavedViewSpecDigest(tenant, kind, spec)
	if err != nil {
		return kernel.SavedViewSpec{}, [sha256.Size]byte{}, ErrUnavailable
	}
	return spec, digest, nil
}

func (service *SavedViewService) loadSavedView(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	viewID uuid.UUID,
	access SavedViewAccess,
) (SavedViewRecord, error) {
	record, err := service.repository.GetSavedView(ctx, actor, tenantID, viewID, access)
	if err != nil {
		if errors.Is(err, ErrForbidden) || errors.Is(err, ErrNotFound) {
			return SavedViewRecord{}, ErrNotFound
		}
		return SavedViewRecord{}, repositoryError(err)
	}
	owner := savedViewOwnerEntity(access)
	if !savedViewRecordIdentityMatches(record, tenantID, owner, kind, &viewID) {
		return SavedViewRecord{}, ErrNotFound
	}
	normalized, valid := normalizeSavedViewRecord(record, tenantID, owner, kind)
	if !valid {
		return SavedViewRecord{}, ErrUnavailable
	}
	return normalized, nil
}

func (service *SavedViewService) savedViewReplay(
	ctx context.Context,
	actor Actor,
	access SavedViewAccess,
	command SavedViewCommandBinding,
) (SavedViewMutationResult, bool, error) {
	result, found, err := service.repository.LookupSavedViewReplay(ctx, SavedViewReplayQuery{
		TenantID: access.tenant, ActorID: actor.UserID, OwnerMembershipID: access.membership,
		Kind: access.kind, Action: command.Action,
		KeyHash: command.KeyHash, Fingerprint: command.Fingerprint,
	})
	if err != nil {
		return SavedViewMutationResult{}, false, repositoryError(err)
	}
	return result, found, nil
}

func (service *SavedViewService) commitSavedView(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	access SavedViewAccess,
	plan kernel.SavedViewPlan,
	command SavedViewCommandBinding,
	expectedID *uuid.UUID,
) (SavedViewMutationResult, error) {
	result, err := service.repository.CommitSavedView(ctx, SavedViewWrite{
		Actor: actor, RequiredCapability: SavedViewCapabilityManage,
		OwnerMembershipID: access.membership, Plan: plan, Command: command, Audit: actor.Audit,
	})
	if err != nil {
		return SavedViewMutationResult{}, repositoryError(err)
	}
	next := plan.Next()
	normalized, valid := normalizeSavedViewRecord(
		result.Record, tenantID, savedViewOwnerEntity(access), access.kind,
	)
	if !valid || expectedID != nil && uuidFromEntity(normalized.View.ID()) != *expectedID ||
		!sameSavedViewProjection(normalized, next, result.Replayed && plan.Action() == kernel.SavedViewCreate) {
		return SavedViewMutationResult{}, ErrUnavailable
	}
	result.Record = normalized
	return result, nil
}

func validatedSavedViewReplay(
	replay SavedViewMutationResult,
	tenantID uuid.UUID,
	owner kernel.EntityID,
	kind kernel.AggregateKind,
	viewID *uuid.UUID,
	revision uint64,
	name string,
	status kernel.SavedViewStatus,
	digest [sha256.Size]byte,
) (SavedViewMutationResult, error) {
	replay, valid := normalizeSavedViewReplay(
		replay, tenantID, owner, kind, viewID, revision, name, status, digest,
	)
	if !valid {
		return SavedViewMutationResult{}, ErrUnavailable
	}
	replay.Replayed = true
	return replay, nil
}

func normalizeSavedViewReplay(
	replay SavedViewMutationResult,
	tenantID uuid.UUID,
	owner kernel.EntityID,
	kind kernel.AggregateKind,
	viewID *uuid.UUID,
	revision uint64,
	name string,
	status kernel.SavedViewStatus,
	digest [sha256.Size]byte,
) (SavedViewMutationResult, bool) {
	normalized, valid := normalizeSavedViewRecord(replay.Record, tenantID, owner, kind)
	if !valid || viewID != nil && uuidFromEntity(normalized.View.ID()) != *viewID ||
		normalized.View.Revision() != revision || normalized.View.Name() != name ||
		normalized.View.Status() != status || normalized.SpecDigest != digest {
		return SavedViewMutationResult{}, false
	}
	replay.Record = normalized
	return replay, true
}

func sameSavedViewProjection(record SavedViewRecord, next kernel.SavedView, ignoreID bool) bool {
	if !ignoreID && record.View.ID() != next.ID() || record.View.Tenant() != next.Tenant() ||
		record.View.Owner() != next.Owner() || record.View.Kind() != next.Kind() ||
		record.View.Name() != next.Name() || record.View.Status() != next.Status() ||
		record.View.Revision() != next.Revision() {
		return false
	}
	digest, err := SavedViewSpecDigest(next.Tenant(), next.Kind(), next.Spec())
	return err == nil && record.SpecDigest == digest
}

func savedViewRecordIdentityMatches(
	record SavedViewRecord,
	tenantID uuid.UUID,
	owner kernel.EntityID,
	kind kernel.AggregateKind,
	viewID *uuid.UUID,
) bool {
	return record.View.Tenant() == workflowTenantEntity(tenantID) &&
		record.View.Owner() == owner && record.View.Kind() == kind &&
		(viewID == nil || uuidFromEntity(record.View.ID()) == *viewID)
}

// normalizeSavedViewRecord validates repository output and rebuilds the
// aggregate plus optional timestamp so callers never retain repository-owned
// slices or pointers.
func normalizeSavedViewRecord(
	record SavedViewRecord,
	tenantID uuid.UUID,
	owner kernel.EntityID,
	kind kernel.AggregateKind,
) (SavedViewRecord, bool) {
	tenant := workflowTenantEntity(tenantID)
	if record.View.Tenant() != tenant || record.View.Owner() != owner || record.View.Kind() != kind ||
		!validStoredInstant(record.CreatedAt) || !validStoredInstant(record.UpdatedAt) ||
		record.UpdatedAt.Before(record.CreatedAt) || record.View.Revision() > maxResourceVersion {
		return SavedViewRecord{}, false
	}
	view, err := kernel.NewSavedView(
		record.View.ID(), record.View.Tenant(), record.View.Owner(), record.View.Kind(),
		record.View.Name(), record.View.Spec(), record.View.Status(), record.View.Revision(),
	)
	if err != nil {
		return SavedViewRecord{}, false
	}
	digest, err := SavedViewSpecDigest(view.Tenant(), view.Kind(), view.Spec())
	if err != nil || digest != record.SpecDigest {
		return SavedViewRecord{}, false
	}
	result := record
	result.View = view
	if view.Status() == kernel.SavedViewArchived {
		if record.ArchivedAt == nil || !validStoredInstant(*record.ArchivedAt) ||
			record.ArchivedAt.Before(record.CreatedAt) || !record.UpdatedAt.Equal(*record.ArchivedAt) {
			return SavedViewRecord{}, false
		}
		archivedAt := *record.ArchivedAt
		result.ArchivedAt = &archivedAt
		return result, true
	}
	if record.ArchivedAt != nil {
		return SavedViewRecord{}, false
	}
	return result, true
}

func savedViewOwnerEntity(access SavedViewAccess) kernel.EntityID {
	value, _ := entityID(access.membership)
	return value
}

func validateSavedViewListInput(input SavedViewListInput) (SavedViewListInput, error) {
	if input.Limit == 0 {
		input.Limit = DefaultPageSize
	}
	if input.Limit < 1 || input.Limit > MaximumPageSize || !validOpaqueCursor(input.After) {
		return SavedViewListInput{}, ErrInvalidInput
	}
	return input, nil
}

func validateSavedViewMutationEnvelope(
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	viewID uuid.UUID,
	expectedRevision uint64,
	idempotencyKey string,
) error {
	if !validMutationActor(actor, tenantID) {
		return ErrForbidden
	}
	if !validSavedViewKind(kind) || !validWorkflowUUID(viewID) || expectedRevision == 0 ||
		expectedRevision >= maxResourceVersion || !validIdempotencyKey(idempotencyKey) {
		return ErrInvalidInput
	}
	return nil
}

// NormalizeSavedViewSpecInput validates the complete transport shape and
// returns an ownership-safe copy for persistence adapters.
func NormalizeSavedViewSpecInput(input SavedViewSpecInput) (SavedViewSpecInput, error) {
	return validateSavedViewSpecInput(input)
}

func validateSavedViewSpecInput(input SavedViewSpecInput) (SavedViewSpecInput, error) {
	filters := input.Filters
	if len(filters.States) > maximumSavedViewStates ||
		len(filters.Severities) > maximumSavedViewEnums ||
		len(filters.Priorities) > maximumSavedViewEnums ||
		len(filters.Custom) > maximumSavedViewFilters || !validText(filters.Search, 240, false) ||
		!validSavedViewQueueInput(filters.Queue) ||
		!validOptionalSavedViewUUID(filters.AssignedTeamID) ||
		!validOptionalSavedViewUUID(filters.AssigneeUserID) ||
		!validOptionalSavedViewUUID(filters.ClaimedBy) ||
		!validUniqueEnums(filters.Severities, "informational", "low", "medium", "high", "critical") ||
		!validUniqueEnums(filters.Priorities, "low", "medium", "high", "urgent", "critical") {
		return SavedViewSpecInput{}, ErrInvalidInput
	}
	seenStates := make(map[string]struct{}, len(filters.States))
	for _, raw := range filters.States {
		key, err := kernel.NewKey(raw)
		if err != nil {
			return SavedViewSpecInput{}, ErrInvalidInput
		}
		if _, duplicate := seenStates[key.String()]; duplicate {
			return SavedViewSpecInput{}, ErrInvalidInput
		}
		seenStates[key.String()] = struct{}{}
	}
	result := input
	result.Filters.States = slices.Clone(filters.States)
	result.Filters.Severities = slices.Clone(filters.Severities)
	result.Filters.Priorities = slices.Clone(filters.Priorities)
	result.Filters.AssignedTeamID = cloneSavedViewUUID(filters.AssignedTeamID)
	result.Filters.AssigneeUserID = cloneSavedViewUUID(filters.AssigneeUserID)
	result.Filters.ClaimedBy = cloneSavedViewUUID(filters.ClaimedBy)
	result.Filters.CustomerVisible = cloneSavedViewBoolean(filters.CustomerVisible)
	result.Filters.Custom = make([]SavedViewCustomFilterInput, len(filters.Custom))
	seenDefinitions := make(map[uuid.UUID]struct{}, len(filters.Custom))
	for index, filter := range filters.Custom {
		if !validWorkflowUUID(filter.DefinitionID) || filter.ExpectedDefinitionVersion == 0 ||
			filter.ExpectedDefinitionVersion > maxResourceVersion ||
			filter.Operator != customkernel.FilterEqual || !validSavedViewScalarInputJSON(filter.Value) {
			return SavedViewSpecInput{}, ErrInvalidInput
		}
		if _, duplicate := seenDefinitions[filter.DefinitionID]; duplicate {
			return SavedViewSpecInput{}, ErrInvalidInput
		}
		seenDefinitions[filter.DefinitionID] = struct{}{}
		result.Filters.Custom[index] = filter
		result.Filters.Custom[index].Value = slices.Clone(filter.Value)
	}
	if len(input.Columns) == 0 || len(input.Columns) > maximumSavedViewColumns {
		return SavedViewSpecInput{}, ErrInvalidInput
	}
	result.Columns = slices.Clone(input.Columns)
	for index, column := range result.Columns {
		if !validSavedViewColumnInput(column) {
			return SavedViewSpecInput{}, ErrInvalidInput
		}
		result.Columns[index].DefinitionID = cloneSavedViewUUID(column.DefinitionID)
	}
	if !validSavedViewSortInput(result.Sort) {
		return SavedViewSpecInput{}, ErrInvalidInput
	}
	result.Sort.DefinitionID = cloneSavedViewUUID(input.Sort.DefinitionID)
	return result, nil
}

func validSavedViewScalarInputJSON(raw json.RawMessage) bool {
	if len(raw) == 0 || len(raw) > maximumSavedViewScalarBytes || !json.Valid(raw) {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if decoder.Decode(&value) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return false
	}
	switch typed := value.(type) {
	case string:
		return utf8.RuneCountInString(typed) <= maximumSavedViewScalarRunes
	case json.Number:
		return len(typed.String()) <= 256
	case bool:
		return true
	default:
		return false
	}
}

func validSavedViewColumnInput(input SavedViewColumnInput) bool {
	if !validSavedViewDefinitionSource(input.Source) ||
		input.Width != 0 && (input.Width < 80 || input.Width > 1_200) ||
		input.Pin != "none" && input.Pin != "start" && input.Pin != "end" {
		return false
	}
	if input.Source == SavedViewDefinitionCore {
		_, err := kernel.NewKey(input.CoreKey)
		return err == nil && input.DefinitionID == nil && input.ExpectedDefinitionVersion == 0
	}
	return input.CoreKey == "" && input.DefinitionID != nil && validWorkflowUUID(*input.DefinitionID) &&
		input.ExpectedDefinitionVersion > 0 && input.ExpectedDefinitionVersion <= maxResourceVersion
}

func validSavedViewSortInput(input SavedViewSortInput) bool {
	if !validSavedViewDefinitionSource(input.Source) ||
		input.Direction != "asc" && input.Direction != "desc" ||
		input.Nulls != "first" && input.Nulls != "last" {
		return false
	}
	if input.Source == SavedViewDefinitionCore {
		_, err := kernel.NewKey(input.CoreKey)
		return err == nil && input.Nulls == "last" && input.DefinitionID == nil &&
			input.ExpectedDefinitionVersion == 0
	}
	return input.CoreKey == "" && input.DefinitionID != nil && validWorkflowUUID(*input.DefinitionID) &&
		input.ExpectedDefinitionVersion > 0 && input.ExpectedDefinitionVersion <= maxResourceVersion
}

func validSavedViewQueueInput(value string) bool {
	return value == "all" || value == "assigned_to_me" ||
		value == "my_operator_teams" || value == "unassigned"
}

func validOptionalSavedViewUUID(value *uuid.UUID) bool {
	return value == nil || validWorkflowUUID(*value)
}

func cloneSavedViewUUID(value *uuid.UUID) *uuid.UUID {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func cloneSavedViewBoolean(value *bool) *bool {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func validSavedViewKind(kind kernel.AggregateKind) bool {
	return kind == kernel.AggregateAlert || kind == kernel.AggregateCase
}

func savedViewInputError(err error) error {
	if errors.Is(err, kernel.ErrInvalidSavedView) {
		return ErrInvalidInput
	}
	return ErrUnavailable
}

func savedViewPlanError(err error) error {
	switch {
	case errors.Is(err, kernel.ErrSavedViewConflict):
		return ErrPreconditionFailed
	case errors.Is(err, kernel.ErrSavedViewNoChange), errors.Is(err, kernel.ErrSavedViewInactive),
		errors.Is(err, kernel.ErrSavedViewAlreadyActive):
		return ErrConflict
	case errors.Is(err, kernel.ErrInvalidSavedView):
		return ErrInvalidInput
	default:
		return ErrUnavailable
	}
}
