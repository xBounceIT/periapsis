package dfir

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/dfir"
)

func (service *Service) CreateTask(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	command TaskCreateCommand,
) (MutationResult[kernel.Task], error) {
	command.Input = cloneTaskDraft(command.Input)
	access, err := service.authorizeTaskMutation(ctx, actor, tenantID, command.CaseID, command.Envelope)
	if err != nil {
		return MutationResult[kernel.Task]{}, err
	}
	tenant, _, err := actorEntities(actor)
	if err != nil {
		return MutationResult[kernel.Task]{}, ErrForbidden
	}
	actorUser, err := alertActorUserEntity(actor)
	if err != nil {
		return MutationResult[kernel.Task]{}, err
	}
	now := service.now()
	checklist, err := materializeTaskChecklist(command.Input.Checklist, nil, actorUser, now)
	if err != nil {
		return MutationResult[kernel.Task]{}, ErrInvalidInput
	}
	task, err := kernel.NewTask(kernel.TaskInput{
		ID: command.Input.ID, TenantID: tenant, CaseID: command.CaseID,
		Title: command.Input.Title, Description: command.Input.Description,
		Status: kernel.TaskTodo, Priority: command.Input.Priority,
		AssigneeID: command.Input.AssigneeID, OperatorTeamID: command.Input.OperatorTeamID,
		DueAt: command.Input.DueAt, Checklist: checklist, SLAInstanceID: command.Input.SLAInstanceID,
		CreatedAt: now, UpdatedAt: now, Version: 1,
	})
	if err != nil {
		return MutationResult[kernel.Task]{}, ErrInvalidInput
	}
	contract, err := newTaskMutationContract(
		actor, command.CaseID, command.Envelope, access, operationTaskCreate,
		"Case task created", taskCreateRequestFingerprint(task),
	)
	if err != nil {
		return MutationResult[kernel.Task]{}, err
	}
	result, err := service.repository.CommitTask(ctx, TaskCreateWrite{Contract: contract, Task: task})
	if err != nil {
		return MutationResult[kernel.Task]{}, taskMutationError(err)
	}
	if !validTaskResult(result.Resource, tenant, command.CaseID, command.Input.ID, 1) ||
		!sameFingerprint(taskCreateRequestFingerprint(result.Resource), taskCreateRequestFingerprint(task)) ||
		!result.Replayed && !sameFingerprint(taskFingerprint(result.Resource, 0), taskFingerprint(task, 0)) {
		return MutationResult[kernel.Task]{}, ErrUnavailable
	}
	return result, nil
}

func (service *Service) TransitionTask(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	command TaskTransitionCommand,
) (MutationResult[kernel.Task], error) {
	command.CompletionData = slices.Clone(command.CompletionData)
	if len(command.CompletionData) == 0 {
		command.CompletionData = nil
	}
	access, err := service.authorizeTaskMutation(ctx, actor, tenantID, command.CaseID, command.Envelope)
	if err != nil {
		return MutationResult[kernel.Task]{}, err
	}
	if !validTaskMutationCoordinates(command.TaskID, command.ExpectedVersion) ||
		kernel.ValidateTaskTransitionIntent(command.Target, command.Reason, command.CompletionData) != nil {
		return MutationResult[kernel.Task]{}, ErrInvalidInput
	}
	actorUser, err := alertActorUserEntity(actor)
	if err != nil {
		return MutationResult[kernel.Task]{}, err
	}
	now := service.now()
	transition := kernel.TaskTransitionInput{
		ExpectedVersion: command.ExpectedVersion, Target: command.Target, ActorID: actorUser,
		OccurredAt: now, Reason: command.Reason, CompletionData: command.CompletionData,
	}
	return service.mutateTask(
		ctx, actor, tenantID, command.CaseID, command.TaskID, command.ExpectedVersion,
		command.Envelope, access, now, operationTaskTransition, command.Reason,
		taskTransitionRequestFingerprint(command, actorUser),
		func(current kernel.Task) (kernel.Task, error) { return current.Transition(transition) },
		func(updated kernel.Task) bool {
			if updated.Status() != command.Target {
				return false
			}
			if command.Target == kernel.TaskDone || command.Target == kernel.TaskCancelled {
				return updated.CompletedBy() != nil && *updated.CompletedBy() == actorUser &&
					sameFingerprint(canonicalRawJSON(updated.CompletionData()), canonicalRawJSON(command.CompletionData))
			}
			return updated.CompletedAt() == nil && updated.CompletedBy() == nil && len(updated.CompletionData()) == 0
		},
	)
}

func (service *Service) ReplaceTaskDetails(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	command TaskDetailsCommand,
) (MutationResult[kernel.Task], error) {
	command.SLAInstanceID = cloneKernelEntityID(command.SLAInstanceID)
	access, err := service.authorizeTaskMutation(ctx, actor, tenantID, command.CaseID, command.Envelope)
	if err != nil {
		return MutationResult[kernel.Task]{}, err
	}
	if !validTaskMutationCoordinates(command.TaskID, command.ExpectedVersion) ||
		command.SLAInstanceID != nil && *command.SLAInstanceID == (kernel.EntityID{}) {
		return MutationResult[kernel.Task]{}, ErrInvalidInput
	}
	now := service.now()
	return service.mutateTask(
		ctx, actor, tenantID, command.CaseID, command.TaskID, command.ExpectedVersion,
		command.Envelope, access, now, operationTaskReplaceDetails, "Case task details replaced",
		taskDetailsRequestFingerprint(command),
		func(current kernel.Task) (kernel.Task, error) {
			return current.ReplaceDetails(
				command.ExpectedVersion, command.Title, command.Description, command.Priority,
				command.SLAInstanceID, now,
			)
		},
		func(updated kernel.Task) bool {
			return updated.Title() == command.Title && updated.Description() == command.Description &&
				updated.Priority() == command.Priority &&
				equalKernelEntityID(updated.SLAInstanceID(), command.SLAInstanceID)
		},
	)
}

func (service *Service) AssignTask(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	command TaskAssignmentCommand,
) (MutationResult[kernel.Task], error) {
	command.OperatorTeamID = cloneKernelEntityID(command.OperatorTeamID)
	command.AssigneeID = cloneKernelEntityID(command.AssigneeID)
	access, err := service.authorizeTaskMutation(ctx, actor, tenantID, command.CaseID, command.Envelope)
	if err != nil {
		return MutationResult[kernel.Task]{}, err
	}
	if !validTaskMutationCoordinates(command.TaskID, command.ExpectedVersion) ||
		command.OperatorTeamID != nil && *command.OperatorTeamID == (kernel.EntityID{}) ||
		command.AssigneeID != nil && *command.AssigneeID == (kernel.EntityID{}) ||
		command.AssigneeID != nil && command.OperatorTeamID == nil {
		return MutationResult[kernel.Task]{}, ErrInvalidInput
	}
	now := service.now()
	return service.mutateTask(
		ctx, actor, tenantID, command.CaseID, command.TaskID, command.ExpectedVersion,
		command.Envelope, access, now, operationTaskAssign, "Case task assignment changed",
		taskAssignmentRequestFingerprint(command),
		func(current kernel.Task) (kernel.Task, error) {
			return current.Assign(command.ExpectedVersion, command.OperatorTeamID, command.AssigneeID, now)
		},
		func(updated kernel.Task) bool {
			return equalKernelEntityID(updated.OperatorTeamID(), command.OperatorTeamID) &&
				equalKernelEntityID(updated.AssigneeID(), command.AssigneeID)
		},
	)
}

func (service *Service) RescheduleTask(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	command TaskDueDateCommand,
) (MutationResult[kernel.Task], error) {
	command.DueAt = cloneTime(command.DueAt)
	access, err := service.authorizeTaskMutation(ctx, actor, tenantID, command.CaseID, command.Envelope)
	if err != nil {
		return MutationResult[kernel.Task]{}, err
	}
	if !validTaskMutationCoordinates(command.TaskID, command.ExpectedVersion) ||
		!validOptionalAlertInstant(command.DueAt) {
		return MutationResult[kernel.Task]{}, ErrInvalidInput
	}
	now := service.now()
	return service.mutateTask(
		ctx, actor, tenantID, command.CaseID, command.TaskID, command.ExpectedVersion,
		command.Envelope, access, now, operationTaskReschedule, "Case task due date changed",
		taskDueDateRequestFingerprint(command),
		func(current kernel.Task) (kernel.Task, error) {
			return current.Reschedule(command.ExpectedVersion, command.DueAt, now)
		},
		func(updated kernel.Task) bool { return equalTime(updated.DueAt(), command.DueAt) },
	)
}

func (service *Service) ReplaceTaskChecklist(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	command TaskChecklistCommand,
) (MutationResult[kernel.Task], error) {
	command.Checklist = slices.Clone(command.Checklist)
	access, err := service.authorizeTaskMutation(ctx, actor, tenantID, command.CaseID, command.Envelope)
	if err != nil {
		return MutationResult[kernel.Task]{}, err
	}
	if !validTaskMutationCoordinates(command.TaskID, command.ExpectedVersion) {
		return MutationResult[kernel.Task]{}, ErrInvalidInput
	}
	actorUser, err := alertActorUserEntity(actor)
	if err != nil {
		return MutationResult[kernel.Task]{}, err
	}
	now := service.now()
	if _, err = materializeTaskChecklist(command.Checklist, nil, actorUser, now); err != nil {
		return MutationResult[kernel.Task]{}, ErrInvalidInput
	}
	return service.mutateTask(
		ctx, actor, tenantID, command.CaseID, command.TaskID, command.ExpectedVersion,
		command.Envelope, access, now, operationTaskChecklist, "Case task checklist replaced",
		taskChecklistRequestFingerprint(command),
		func(current kernel.Task) (kernel.Task, error) {
			checklist, materializeErr := materializeTaskChecklist(command.Checklist, current.Checklist(), actorUser, now)
			if materializeErr != nil {
				return kernel.Task{}, materializeErr
			}
			return current.ReplaceChecklist(command.ExpectedVersion, checklist, now)
		},
		func(updated kernel.Task) bool {
			return sameFingerprint(
				taskChecklistProjectionIntentFingerprint(updated.Checklist()),
				taskChecklistIntentFingerprint(command.Checklist),
			)
		},
	)
}

func (service *Service) ReplaceTaskComments(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	command TaskCommentsCommand,
) (MutationResult[kernel.Task], error) {
	var err error
	command.CommentIDs, err = canonicalTaskCommentIDs(command.CommentIDs)
	if err != nil {
		return MutationResult[kernel.Task]{}, ErrInvalidInput
	}
	access, err := service.authorizeTaskMutation(ctx, actor, tenantID, command.CaseID, command.Envelope)
	if err != nil {
		return MutationResult[kernel.Task]{}, err
	}
	if !validTaskMutationCoordinates(command.TaskID, command.ExpectedVersion) {
		return MutationResult[kernel.Task]{}, ErrInvalidInput
	}
	now := service.now()
	return service.mutateTask(
		ctx, actor, tenantID, command.CaseID, command.TaskID, command.ExpectedVersion,
		command.Envelope, access, now, operationTaskComments, "Case task comments replaced",
		taskCommentsRequestFingerprint(command),
		func(current kernel.Task) (kernel.Task, error) {
			return current.ReplaceComments(command.ExpectedVersion, command.CommentIDs, now)
		},
		func(updated kernel.Task) bool {
			return slices.Equal(updated.CommentIDs(), command.CommentIDs)
		},
	)
}

func (service *Service) mutateTask(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	caseID kernel.EntityID,
	taskID kernel.EntityID,
	expectedVersion uint64,
	envelope MutationEnvelope,
	access Access,
	occurredAt time.Time,
	operation string,
	auditReason string,
	request any,
	apply func(kernel.Task) (kernel.Task, error),
	matches func(kernel.Task) bool,
) (MutationResult[kernel.Task], error) {
	if !validTaskMutationCoordinates(taskID, expectedVersion) || apply == nil || matches == nil {
		return MutationResult[kernel.Task]{}, ErrInvalidInput
	}
	contract, err := newTaskMutationContract(actor, caseID, envelope, access, operation, auditReason, request)
	if err != nil {
		return MutationResult[kernel.Task]{}, err
	}
	var applied alertCallbackCapture[kernel.Task]
	result, err := service.repository.MutateTask(ctx, TaskMutationWrite{
		Contract: contract, TaskID: taskID, ExpectedVersion: expectedVersion,
		Apply: func(current kernel.Task) (kernel.Task, error) {
			applied.begin()
			if current.TenantID().String() != tenantID.String() || current.CaseID() != caseID ||
				current.ID() != taskID || occurredAt.Before(current.UpdatedAt()) {
				return kernel.Task{}, ErrUnavailable
			}
			updated, applyErr := apply(current)
			if applyErr == nil {
				applied.complete(updated)
			}
			return updated, applyErr
		},
	})
	if err != nil {
		return MutationResult[kernel.Task]{}, taskMutationError(err)
	}
	tenant, _, conversionErr := actorEntities(actor)
	if conversionErr != nil || !validTaskResult(result.Resource, tenant, caseID, taskID, expectedVersion+1) ||
		!matches(result.Resource) {
		return MutationResult[kernel.Task]{}, ErrUnavailable
	}
	appliedTask, applyCalls := applied.snapshot()
	if result.Replayed && applyCalls != 0 || !result.Replayed &&
		(applyCalls != 1 || !sameFingerprint(taskFingerprint(result.Resource, 0), taskFingerprint(appliedTask, 0))) {
		return MutationResult[kernel.Task]{}, ErrUnavailable
	}
	return result, nil
}

func (service *Service) authorizeTaskMutation(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	caseID kernel.EntityID,
	envelope MutationEnvelope,
) (Access, error) {
	if !validActor(actor, tenantID) {
		return Access{}, ErrForbidden
	}
	if caseID == (kernel.EntityID{}) || !validEnvelope(envelope) {
		return Access{}, ErrInvalidInput
	}
	return service.resolveAccess(ctx, actor, tenantID, CapabilityTaskManage, caseID, true)
}

func validTaskMutationCoordinates(taskID kernel.EntityID, expectedVersion uint64) bool {
	return taskID != (kernel.EntityID{}) && expectedVersion > 0 &&
		expectedVersion < kernel.MaximumAlertResourceVersion
}

func validTaskResult(task kernel.Task, tenant, caseID, taskID kernel.EntityID, version uint64) bool {
	return task.TenantID() == tenant && task.CaseID() == caseID && task.ID() == taskID && task.Version() == version
}

func cloneTaskDraft(input TaskDraft) TaskDraft {
	input.AssigneeID = cloneKernelEntityID(input.AssigneeID)
	input.OperatorTeamID = cloneKernelEntityID(input.OperatorTeamID)
	input.DueAt = cloneTime(input.DueAt)
	input.Checklist = slices.Clone(input.Checklist)
	input.SLAInstanceID = cloneKernelEntityID(input.SLAInstanceID)
	return input
}

func canonicalTaskCommentIDs(values []kernel.EntityID) ([]kernel.EntityID, error) {
	if len(values) > 1_000 {
		return nil, kernel.ErrInvalidTask
	}
	result := slices.Clone(values)
	slices.SortFunc(result, func(left, right kernel.EntityID) int {
		return strings.Compare(left.String(), right.String())
	})
	for index, value := range result {
		if value == (kernel.EntityID{}) || index > 0 && result[index-1] == value {
			return nil, kernel.ErrInvalidTask
		}
	}
	return result, nil
}

func taskMutationError(err error) error {
	switch {
	case errors.Is(err, kernel.ErrTaskConflict):
		return ErrPreconditionFailed
	case errors.Is(err, kernel.ErrInvalidTask):
		return ErrInvalidInput
	default:
		return repositoryError(err)
	}
}
