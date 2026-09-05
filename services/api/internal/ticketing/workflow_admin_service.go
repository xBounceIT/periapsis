package ticketing

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"reflect"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

type WorkflowAdminService struct {
	repository WorkflowAdminRepository
}

func NewWorkflowAdminService(repository WorkflowAdminRepository) (*WorkflowAdminService, error) {
	if repository == nil {
		return nil, errors.New("workflow administration repository is required")
	}
	return &WorkflowAdminService{repository: repository}, nil
}

func (service *WorkflowAdminService) ListWorkflows(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	input WorkflowAdminListInput,
) (WorkflowAdminPage, error) {
	if !validActor(actor, tenantID) {
		return WorkflowAdminPage{}, ErrForbidden
	}
	validated, err := validateWorkflowAdminListInput(input)
	if err != nil {
		return WorkflowAdminPage{}, err
	}
	access, err := service.workflowAccess(ctx, actor, tenantID, WorkflowCapabilityRead)
	if err != nil {
		return WorkflowAdminPage{}, err
	}
	page, err := service.repository.ListWorkflows(ctx, actor, tenantID, validated, access)
	if err != nil {
		return WorkflowAdminPage{}, workflowAdminReadRepositoryError(err)
	}
	if !validWorkflowAdminCursor(page.NextCursor) || len(page.Items) > validated.Limit ||
		len(page.Items) == 0 && page.NextCursor != "" {
		return WorkflowAdminPage{}, ErrUnavailable
	}
	var previous uuid.UUID
	for index, record := range page.Items {
		if !validWorkflowAdminRecord(record, tenantID) ||
			validated.Kind != nil && record.Workflow.Kind() != *validated.Kind ||
			validated.Status != nil && record.Workflow.Status() != *validated.Status ||
			validated.DefaultOnly && !record.Workflow.IsDefault() {
			return WorkflowAdminPage{}, ErrUnavailable
		}
		current := uuidFromEntity(record.Workflow.ID())
		if index > 0 && bytes.Compare(previous[:], current[:]) >= 0 {
			return WorkflowAdminPage{}, ErrUnavailable
		}
		previous = current
	}
	if page.NextCursor != "" {
		cursorID, ok := workflowAdminCursorID(page.NextCursor)
		if !ok || cursorID != previous {
			return WorkflowAdminPage{}, ErrUnavailable
		}
	}
	return page, nil
}

func (service *WorkflowAdminService) GetWorkflow(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	workflowID uuid.UUID,
) (WorkflowAdminRecord, error) {
	if !validActor(actor, tenantID) {
		return WorkflowAdminRecord{}, ErrForbidden
	}
	if !validWorkflowUUID(workflowID) {
		return WorkflowAdminRecord{}, ErrInvalidInput
	}
	access, err := service.workflowAccess(ctx, actor, tenantID, WorkflowCapabilityRead)
	if err != nil {
		return WorkflowAdminRecord{}, err
	}
	return service.loadWorkflow(ctx, actor, tenantID, workflowID, access)
}

func (service *WorkflowAdminService) ListWorkflowVersions(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	workflowID uuid.UUID,
	input WorkflowVersionListInput,
) (WorkflowVersionPage, error) {
	if !validActor(actor, tenantID) {
		return WorkflowVersionPage{}, ErrForbidden
	}
	if !validWorkflowUUID(workflowID) {
		return WorkflowVersionPage{}, ErrInvalidInput
	}
	validated, err := validateWorkflowVersionListInput(input)
	if err != nil {
		return WorkflowVersionPage{}, err
	}
	access, err := service.workflowAccess(ctx, actor, tenantID, WorkflowCapabilityRead)
	if err != nil {
		return WorkflowVersionPage{}, err
	}
	current, err := service.loadWorkflow(ctx, actor, tenantID, workflowID, access)
	if err != nil {
		return WorkflowVersionPage{}, err
	}
	page, err := service.repository.ListWorkflowVersions(ctx, actor, tenantID, workflowID, validated, access)
	if err != nil {
		return WorkflowVersionPage{}, workflowAdminReadRepositoryError(err)
	}
	if len(page.Items) > validated.Limit || page.NextVersion > current.Workflow.CurrentVersion() {
		return WorkflowVersionPage{}, ErrUnavailable
	}
	previous := uint64(0)
	for index, version := range page.Items {
		if !validWorkflowVersionRecord(version, tenantID, workflowID, current.Workflow.Kind()) ||
			version.Definition.Version() > current.Workflow.CurrentVersion() ||
			validated.AfterVersion != 0 && version.Definition.Version() >= validated.AfterVersion ||
			index > 0 && version.Definition.Version() >= previous {
			return WorkflowVersionPage{}, ErrUnavailable
		}
		previous = version.Definition.Version()
	}
	if len(page.Items) == 0 && page.NextVersion != 0 ||
		len(page.Items) > 0 && page.NextVersion != 0 && page.NextVersion != previous {
		return WorkflowVersionPage{}, ErrUnavailable
	}
	return page, nil
}

func (service *WorkflowAdminService) GetWorkflowVersion(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	workflowID uuid.UUID,
	version uint64,
) (WorkflowVersionRecord, error) {
	if !validActor(actor, tenantID) {
		return WorkflowVersionRecord{}, ErrForbidden
	}
	if !validWorkflowUUID(workflowID) || version == 0 || version > maxResourceVersion {
		return WorkflowVersionRecord{}, ErrInvalidInput
	}
	access, err := service.workflowAccess(ctx, actor, tenantID, WorkflowCapabilityRead)
	if err != nil {
		return WorkflowVersionRecord{}, err
	}
	current, err := service.loadWorkflow(ctx, actor, tenantID, workflowID, access)
	if err != nil {
		return WorkflowVersionRecord{}, err
	}
	if version > current.Workflow.CurrentVersion() {
		return WorkflowVersionRecord{}, ErrNotFound
	}
	result, err := service.repository.GetWorkflowVersion(ctx, actor, tenantID, workflowID, version, access)
	if err != nil {
		return WorkflowVersionRecord{}, workflowAdminReadRepositoryError(err)
	}
	if !validWorkflowVersionRecord(result, tenantID, workflowID, current.Workflow.Kind()) ||
		result.Definition.Version() != version {
		return WorkflowVersionRecord{}, ErrUnavailable
	}
	return result, nil
}

func (service *WorkflowAdminService) SimulateWorkflow(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	workflowID uuid.UUID,
	input WorkflowSimulationInput,
) (WorkflowSimulationResult, error) {
	if !validActor(actor, tenantID) {
		return WorkflowSimulationResult{}, ErrForbidden
	}
	if !validWorkflowUUID(workflowID) || input.Version > maxResourceVersion {
		return WorkflowSimulationResult{}, ErrInvalidInput
	}
	access, err := service.workflowAccess(ctx, actor, tenantID, WorkflowCapabilityRead)
	if err != nil {
		return WorkflowSimulationResult{}, err
	}
	current, err := service.loadWorkflow(ctx, actor, tenantID, workflowID, access)
	if err != nil {
		return WorkflowSimulationResult{}, err
	}
	definition := current.Workflow.Current()
	if input.Version != 0 && input.Version != definition.Version() {
		stored, loadErr := service.repository.GetWorkflowVersion(
			ctx, actor, tenantID, workflowID, input.Version, access,
		)
		if loadErr != nil {
			return WorkflowSimulationResult{}, workflowAdminReadRepositoryError(loadErr)
		}
		if !validWorkflowVersionRecord(stored, tenantID, workflowID, current.Workflow.Kind()) ||
			stored.Definition.Version() != input.Version {
			return WorkflowSimulationResult{}, ErrUnavailable
		}
		definition = stored.Definition
	}
	scenario, err := kernel.NewWorkflowSimulationScenario(
		input.State, input.CommentPresent, input.Roles, input.Permissions,
		input.ProvidedCustomFields, input.Facts,
	)
	if err != nil {
		return WorkflowSimulationResult{}, ErrInvalidInput
	}
	results, err := kernel.SimulateWorkflow(definition, scenario)
	if err != nil {
		return WorkflowSimulationResult{}, ErrInvalidInput
	}
	return WorkflowSimulationResult{
		WorkflowID: workflowID, Kind: definition.Kind(), Version: definition.Version(), Results: results,
	}, nil
}

func (service *WorkflowAdminService) CreateWorkflow(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	input WorkflowCreateInput,
) (WorkflowAdminMutationResult, error) {
	if !validMutationActor(actor, tenantID) {
		return WorkflowAdminMutationResult{}, ErrForbidden
	}
	if input.Kind != kernel.AggregateAlert && input.Kind != kernel.AggregateCase ||
		!validIdempotencyKey(input.IdempotencyKey) {
		return WorkflowAdminMutationResult{}, ErrInvalidInput
	}
	key, err := kernel.NewKey(input.Key)
	if err != nil {
		return WorkflowAdminMutationResult{}, ErrInvalidInput
	}
	_, err = service.workflowAccess(ctx, actor, tenantID, WorkflowCapabilityManage)
	if err != nil {
		return WorkflowAdminMutationResult{}, err
	}
	id, err := service.repository.ReserveWorkflowID(ctx, tenantID)
	if err != nil {
		return WorkflowAdminMutationResult{}, ErrUnavailable
	}
	if !validWorkflowUUID(uuidFromEntity(id)) {
		return WorkflowAdminMutationResult{}, ErrUnavailable
	}
	definition, err := kernel.NewWorkflowDefinition(
		id, input.Kind, 1, input.Design.States, input.Design.Transitions,
	)
	if err != nil {
		return WorkflowAdminMutationResult{}, ErrInvalidInput
	}
	plan, err := kernel.PlanWorkflowCreation(
		workflowTenantEntity(tenantID), key, input.DisplayName, input.Description, definition,
	)
	if err != nil {
		return WorkflowAdminMutationResult{}, workflowAdministrationInputError(err)
	}
	command, err := bindWorkflowAdminCommand(
		input.IdempotencyKey, plan.Action(), tenantID, nil, 0,
		input.Key, input.DisplayName, input.Description, &definition,
	)
	if err != nil {
		return WorkflowAdminMutationResult{}, err
	}
	if replay, found, replayErr := service.workflowReplay(ctx, actor, tenantID, command); replayErr != nil || found {
		if replayErr != nil {
			return WorkflowAdminMutationResult{}, replayErr
		}
		if !validWorkflowAdminRecord(replay.Record, tenantID) || replay.Record.Workflow.Kind() != input.Kind {
			return WorkflowAdminMutationResult{}, ErrUnavailable
		}
		replay.Replayed = true
		return replay, nil
	}
	return service.commitWorkflow(ctx, actor, tenantID, plan, command, nil)
}

func (service *WorkflowAdminService) PublishWorkflow(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	workflowID uuid.UUID,
	input WorkflowPublishInput,
) (WorkflowAdminMutationResult, error) {
	if err := validateWorkflowMutationEnvelope(actor, tenantID, workflowID, input.ExpectedRevision, input.IdempotencyKey); err != nil {
		return WorkflowAdminMutationResult{}, err
	}
	access, err := service.workflowAccess(ctx, actor, tenantID, WorkflowCapabilityManage)
	if err != nil {
		return WorkflowAdminMutationResult{}, err
	}
	current, err := service.loadWorkflow(ctx, actor, tenantID, workflowID, access)
	if err != nil {
		return WorkflowAdminMutationResult{}, err
	}
	version := current.Workflow.CurrentVersion()
	if version < maxResourceVersion {
		version++
	}
	definition, err := kernel.NewWorkflowDefinition(
		current.Workflow.ID(), current.Workflow.Kind(), version,
		input.Design.States, input.Design.Transitions,
	)
	if err != nil {
		return WorkflowAdminMutationResult{}, ErrInvalidInput
	}
	command, err := bindWorkflowAdminCommand(
		input.IdempotencyKey, kernel.WorkflowAdministrationPublish, tenantID, &workflowID,
		input.ExpectedRevision, "", "", "", &definition,
	)
	if err != nil {
		return WorkflowAdminMutationResult{}, err
	}
	if replay, found, replayErr := service.workflowReplay(ctx, actor, tenantID, command); replayErr != nil || found {
		if replayErr != nil {
			return WorkflowAdminMutationResult{}, replayErr
		}
		if !validWorkflowAdminRecord(replay.Record, tenantID) || uuidFromEntity(replay.Record.Workflow.ID()) != workflowID {
			return WorkflowAdminMutationResult{}, ErrUnavailable
		}
		replay.Replayed = true
		return replay, nil
	}
	if current.Workflow.CurrentVersion() >= maxResourceVersion {
		return WorkflowAdminMutationResult{}, ErrPreconditionFailed
	}
	plan, err := kernel.PlanWorkflowPublication(current.Workflow, input.ExpectedRevision, definition)
	if err != nil {
		return WorkflowAdminMutationResult{}, workflowAdministrationPlanError(err)
	}
	return service.commitWorkflow(ctx, actor, tenantID, plan, command, &workflowID)
}

func (service *WorkflowAdminService) UpdateWorkflowMetadata(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	workflowID uuid.UUID,
	input WorkflowMetadataInput,
) (WorkflowAdminMutationResult, error) {
	if err := validateWorkflowMutationEnvelope(actor, tenantID, workflowID, input.ExpectedRevision, input.IdempotencyKey); err != nil {
		return WorkflowAdminMutationResult{}, err
	}
	command, err := bindWorkflowAdminCommand(
		input.IdempotencyKey, kernel.WorkflowAdministrationUpdateMetadata, tenantID, &workflowID,
		input.ExpectedRevision, "", input.DisplayName, input.Description, nil,
	)
	if err != nil {
		return WorkflowAdminMutationResult{}, err
	}
	return service.planAndCommitExisting(ctx, actor, tenantID, workflowID, command, func(current kernel.ManagedWorkflow) (kernel.WorkflowAdministrationPlan, error) {
		return kernel.PlanWorkflowMetadataUpdate(current, input.ExpectedRevision, input.DisplayName, input.Description)
	})
}

func (service *WorkflowAdminService) SetDefaultWorkflow(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	workflowID uuid.UUID,
	input WorkflowLifecycleInput,
) (WorkflowAdminMutationResult, error) {
	if err := validateWorkflowMutationEnvelope(actor, tenantID, workflowID, input.ExpectedRevision, input.IdempotencyKey); err != nil {
		return WorkflowAdminMutationResult{}, err
	}
	command, err := bindWorkflowAdminCommand(
		input.IdempotencyKey, kernel.WorkflowAdministrationSetDefault, tenantID, &workflowID,
		input.ExpectedRevision, "", "", "", nil,
	)
	if err != nil {
		return WorkflowAdminMutationResult{}, err
	}
	access, err := service.workflowAccess(ctx, actor, tenantID, WorkflowCapabilityManage)
	if err != nil {
		return WorkflowAdminMutationResult{}, err
	}
	if replay, found, replayErr := service.workflowReplay(ctx, actor, tenantID, command); replayErr != nil || found {
		return validatedWorkflowReplay(replay, found, replayErr, tenantID, workflowID)
	}
	current, err := service.loadWorkflow(ctx, actor, tenantID, workflowID, access)
	if err != nil {
		return WorkflowAdminMutationResult{}, err
	}
	previousRecord, found, err := service.repository.GetDefaultWorkflow(
		ctx, actor, tenantID, current.Workflow.Kind(), access,
	)
	if err != nil {
		return WorkflowAdminMutationResult{}, workflowAdminReadRepositoryError(err)
	}
	var previous *kernel.ManagedWorkflow
	if found {
		if !validWorkflowAdminRecord(previousRecord, tenantID) ||
			previousRecord.Workflow.Kind() != current.Workflow.Kind() {
			return WorkflowAdminMutationResult{}, ErrUnavailable
		}
		value := previousRecord.Workflow
		previous = &value
	}
	plan, err := kernel.PlanWorkflowSetDefault(current.Workflow, input.ExpectedRevision, previous)
	if err != nil {
		return WorkflowAdminMutationResult{}, workflowAdministrationPlanError(err)
	}
	return service.commitWorkflow(ctx, actor, tenantID, plan, command, &workflowID)
}

func (service *WorkflowAdminService) ArchiveWorkflow(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	workflowID uuid.UUID,
	input WorkflowLifecycleInput,
) (WorkflowAdminMutationResult, error) {
	return service.lifecycleWorkflow(
		ctx, actor, tenantID, workflowID, input, kernel.WorkflowAdministrationArchive,
		kernel.PlanWorkflowArchive,
	)
}

func (service *WorkflowAdminService) RestoreWorkflow(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	workflowID uuid.UUID,
	input WorkflowLifecycleInput,
) (WorkflowAdminMutationResult, error) {
	return service.lifecycleWorkflow(
		ctx, actor, tenantID, workflowID, input, kernel.WorkflowAdministrationRestore,
		kernel.PlanWorkflowRestore,
	)
}

func (service *WorkflowAdminService) lifecycleWorkflow(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	workflowID uuid.UUID,
	input WorkflowLifecycleInput,
	action kernel.WorkflowAdministrationAction,
	planner func(kernel.ManagedWorkflow, uint64) (kernel.WorkflowAdministrationPlan, error),
) (WorkflowAdminMutationResult, error) {
	if err := validateWorkflowMutationEnvelope(actor, tenantID, workflowID, input.ExpectedRevision, input.IdempotencyKey); err != nil {
		return WorkflowAdminMutationResult{}, err
	}
	command, err := bindWorkflowAdminCommand(
		input.IdempotencyKey, action, tenantID, &workflowID, input.ExpectedRevision, "", "", "", nil,
	)
	if err != nil {
		return WorkflowAdminMutationResult{}, err
	}
	return service.planAndCommitExisting(ctx, actor, tenantID, workflowID, command, func(current kernel.ManagedWorkflow) (kernel.WorkflowAdministrationPlan, error) {
		return planner(current, input.ExpectedRevision)
	})
}

func (service *WorkflowAdminService) planAndCommitExisting(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	workflowID uuid.UUID,
	command WorkflowAdminCommandBinding,
	planner func(kernel.ManagedWorkflow) (kernel.WorkflowAdministrationPlan, error),
) (WorkflowAdminMutationResult, error) {
	access, err := service.workflowAccess(ctx, actor, tenantID, WorkflowCapabilityManage)
	if err != nil {
		return WorkflowAdminMutationResult{}, err
	}
	if replay, found, replayErr := service.workflowReplay(ctx, actor, tenantID, command); replayErr != nil || found {
		return validatedWorkflowReplay(replay, found, replayErr, tenantID, workflowID)
	}
	current, err := service.loadWorkflow(ctx, actor, tenantID, workflowID, access)
	if err != nil {
		return WorkflowAdminMutationResult{}, err
	}
	plan, err := planner(current.Workflow)
	if err != nil {
		return WorkflowAdminMutationResult{}, workflowAdministrationPlanError(err)
	}
	return service.commitWorkflow(ctx, actor, tenantID, plan, command, &workflowID)
}

func (service *WorkflowAdminService) workflowAccess(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	capability WorkflowAdminCapability,
) (WorkflowAdminAccess, error) {
	access, err := service.repository.ResolveWorkflowAdminAccess(ctx, actor, tenantID, capability)
	if err != nil {
		return WorkflowAdminAccess{}, workflowAdminReadRepositoryError(err)
	}
	if access.tenant != tenantID || access.actor != actor.UserID || access.capability != capability ||
		!validWorkflowAdminCapability(access.capability) ||
		access.principal != kernel.PrincipalOperator && access.principal != kernel.PrincipalCustomer &&
			access.principal != kernel.PrincipalServiceAccount {
		return WorkflowAdminAccess{}, ErrUnavailable
	}
	if !access.allowed || access.principal != kernel.PrincipalOperator {
		return WorkflowAdminAccess{}, ErrForbidden
	}
	return access, nil
}

func (service *WorkflowAdminService) loadWorkflow(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	workflowID uuid.UUID,
	access WorkflowAdminAccess,
) (WorkflowAdminRecord, error) {
	record, err := service.repository.GetWorkflow(ctx, actor, tenantID, workflowID, access)
	if err != nil {
		return WorkflowAdminRecord{}, workflowAdminReadRepositoryError(err)
	}
	if !validWorkflowAdminRecord(record, tenantID) || uuidFromEntity(record.Workflow.ID()) != workflowID {
		return WorkflowAdminRecord{}, ErrUnavailable
	}
	return record, nil
}

func (service *WorkflowAdminService) workflowReplay(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	command WorkflowAdminCommandBinding,
) (WorkflowAdminMutationResult, bool, error) {
	result, found, err := service.repository.LookupWorkflowAdminReplay(ctx, WorkflowAdminReplayQuery{
		TenantID: tenantID, ActorID: actor.UserID, Action: command.Action,
		KeyHash: command.KeyHash, Fingerprint: command.Fingerprint,
	})
	if err != nil {
		return WorkflowAdminMutationResult{}, false, repositoryError(err)
	}
	return result, found, nil
}

func (service *WorkflowAdminService) commitWorkflow(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	plan kernel.WorkflowAdministrationPlan,
	command WorkflowAdminCommandBinding,
	expectedID *uuid.UUID,
) (WorkflowAdminMutationResult, error) {
	result, err := service.repository.CommitWorkflow(ctx, WorkflowAdminWrite{
		Actor: actor, RequiredCapability: WorkflowCapabilityManage,
		Plan: plan, Command: command, Audit: actor.Audit,
	})
	if err != nil {
		return WorkflowAdminMutationResult{}, repositoryError(err)
	}
	if !validWorkflowAdminRecord(result.Record, tenantID) ||
		expectedID != nil && uuidFromEntity(result.Record.Workflow.ID()) != *expectedID {
		return WorkflowAdminMutationResult{}, ErrUnavailable
	}
	if !result.Replayed && !sameManagedWorkflowProjection(result.Record.Workflow, plan.Next()) {
		return WorkflowAdminMutationResult{}, ErrUnavailable
	}
	return result, nil
}

func validatedWorkflowReplay(
	replay WorkflowAdminMutationResult,
	found bool,
	err error,
	tenantID uuid.UUID,
	workflowID uuid.UUID,
) (WorkflowAdminMutationResult, error) {
	if err != nil {
		return WorkflowAdminMutationResult{}, err
	}
	if !found {
		return WorkflowAdminMutationResult{}, nil
	}
	if !validWorkflowAdminRecord(replay.Record, tenantID) || uuidFromEntity(replay.Record.Workflow.ID()) != workflowID {
		return WorkflowAdminMutationResult{}, ErrUnavailable
	}
	replay.Replayed = true
	return replay, nil
}

// Read-side persistence conflicts indicate a corrupt or divergent protected
// projection, not a caller-visible business conflict. Mutation replay and
// commit paths intentionally continue to preserve real 409 semantics.
func workflowAdminReadRepositoryError(err error) error {
	switch {
	case errors.Is(err, ErrInvalidInput), errors.Is(err, ErrForbidden), errors.Is(err, ErrNotFound),
		errors.Is(err, ErrUnavailable):
		return err
	default:
		return ErrUnavailable
	}
}

func validateWorkflowAdminListInput(input WorkflowAdminListInput) (WorkflowAdminListInput, error) {
	if input.Limit == 0 {
		input.Limit = DefaultPageSize
	}
	if input.Limit < 1 || input.Limit > MaximumPageSize || !validWorkflowAdminCursor(input.After) ||
		!validText(input.Search, 200, false) {
		return WorkflowAdminListInput{}, ErrInvalidInput
	}
	if input.Kind != nil && *input.Kind != kernel.AggregateAlert && *input.Kind != kernel.AggregateCase {
		return WorkflowAdminListInput{}, ErrInvalidInput
	}
	if input.Status != nil && *input.Status != kernel.WorkflowActive && *input.Status != kernel.WorkflowArchived {
		return WorkflowAdminListInput{}, ErrInvalidInput
	}
	return input, nil
}

func validWorkflowAdminCursor(value string) bool {
	_, ok := workflowAdminCursorID(value)
	return ok
}

func workflowAdminCursorID(value string) (uuid.UUID, bool) {
	if value == "" {
		return uuid.Nil, true
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != 16 || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return uuid.Nil, false
	}
	identifier, err := uuid.FromBytes(decoded)
	return identifier, err == nil && validWorkflowUUID(identifier)
}

func validateWorkflowVersionListInput(input WorkflowVersionListInput) (WorkflowVersionListInput, error) {
	if input.Limit == 0 {
		input.Limit = DefaultPageSize
	}
	if input.Limit < 1 || input.Limit > MaximumPageSize || input.AfterVersion > maxResourceVersion {
		return WorkflowVersionListInput{}, ErrInvalidInput
	}
	return input, nil
}

func validateWorkflowMutationEnvelope(
	actor Actor,
	tenantID uuid.UUID,
	workflowID uuid.UUID,
	expectedRevision uint64,
	idempotencyKey string,
) error {
	if !validMutationActor(actor, tenantID) {
		return ErrForbidden
	}
	if !validWorkflowUUID(workflowID) || expectedRevision == 0 || expectedRevision > maxResourceVersion ||
		!validIdempotencyKey(idempotencyKey) {
		return ErrInvalidInput
	}
	return nil
}

func validWorkflowUUID(value uuid.UUID) bool {
	_, err := entityID(value)
	return err == nil
}

func workflowTenantEntity(value uuid.UUID) kernel.EntityID {
	result, _ := entityID(value)
	return result
}

func validWorkflowAdminRecord(record WorkflowAdminRecord, tenantID uuid.UUID) bool {
	tenant, err := entityID(tenantID)
	if err != nil || record.Workflow.Tenant() != tenant || !validStoredInstant(record.CreatedAt) ||
		!validStoredInstant(record.UpdatedAt) || record.UpdatedAt.Before(record.CreatedAt) ||
		record.Workflow.Revision() > maxResourceVersion || record.Workflow.CurrentVersion() > maxResourceVersion {
		return false
	}
	_, err = kernel.NewManagedWorkflow(
		record.Workflow.Tenant(), record.Workflow.Key(), record.Workflow.DisplayName(),
		record.Workflow.Description(), record.Workflow.IsDefault(), record.Workflow.Status(),
		record.Workflow.Revision(), record.Workflow.Current(),
	)
	if err != nil {
		return false
	}
	if record.Workflow.Status() == kernel.WorkflowArchived {
		return record.ArchivedAt != nil && validStoredInstant(*record.ArchivedAt) &&
			!record.ArchivedAt.Before(record.CreatedAt) && !record.UpdatedAt.Before(*record.ArchivedAt)
	}
	return record.ArchivedAt == nil
}

func validWorkflowVersionRecord(
	record WorkflowVersionRecord,
	tenantID uuid.UUID,
	workflowID uuid.UUID,
	kind kernel.AggregateKind,
) bool {
	if record.TenantID != tenantID || uuidFromEntity(record.Definition.ID()) != workflowID ||
		record.Definition.Kind() != kind || !validStoredInstant(record.PublishedAt) ||
		!validText(record.PublisherDisplayName, 200, true) ||
		record.Definition.Version() > maxResourceVersion {
		return false
	}
	if record.PublishedByMembershipID != nil && !validWorkflowUUID(*record.PublishedByMembershipID) {
		return false
	}
	_, err := kernel.NewWorkflowDefinition(
		record.Definition.ID(), record.Definition.Kind(), record.Definition.Version(),
		record.Definition.States(), record.Definition.Transitions(),
	)
	return err == nil
}

func sameManagedWorkflowProjection(left, right kernel.ManagedWorkflow) bool {
	if left.Tenant() != right.Tenant() || left.ID() != right.ID() || left.Kind() != right.Kind() ||
		left.Key() != right.Key() || left.DisplayName() != right.DisplayName() ||
		left.Description() != right.Description() || left.IsDefault() != right.IsDefault() ||
		left.Status() != right.Status() || left.Revision() != right.Revision() ||
		left.CurrentVersion() != right.CurrentVersion() {
		return false
	}
	leftDesign, leftErr := canonicalWorkflowDesign(left.Current())
	rightDesign, rightErr := canonicalWorkflowDesign(right.Current())
	return leftErr == nil && rightErr == nil && reflect.DeepEqual(leftDesign, rightDesign)
}

func workflowAdministrationInputError(err error) error {
	if errors.Is(err, kernel.ErrInvalidWorkflowAdministration) {
		return ErrInvalidInput
	}
	return ErrUnavailable
}

func workflowAdministrationPlanError(err error) error {
	switch {
	case errors.Is(err, kernel.ErrWorkflowRevisionConflict):
		return ErrPreconditionFailed
	case errors.Is(err, kernel.ErrWorkflowInactive), errors.Is(err, kernel.ErrWorkflowDefaultArchive),
		errors.Is(err, kernel.ErrWorkflowNoChange):
		return ErrConflict
	case errors.Is(err, kernel.ErrInvalidWorkflowAdministration):
		return ErrInvalidInput
	default:
		return ErrUnavailable
	}
}
