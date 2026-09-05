package dfir

import (
	"context"
	"slices"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/dfir"
)

func (service *AlertInvestigationService) CreateTask(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	command AlertTaskCreateCommand,
) (MutationResult[kernel.AlertTask], error) {
	command.Input = cloneAlertTaskDraft(command.Input)
	access, _, err := service.authorizeMutation(
		ctx, actor, tenantID, command.AlertID, CapabilityTaskManage, command.Envelope,
	)
	if err != nil {
		return MutationResult[kernel.AlertTask]{}, err
	}
	tenant, _, conversionErr := actorEntities(actor)
	if conversionErr != nil {
		return MutationResult[kernel.AlertTask]{}, ErrForbidden
	}
	now, err := service.currentTime()
	if err != nil {
		return MutationResult[kernel.AlertTask]{}, err
	}
	userID, err := alertActorUserEntity(actor)
	if err != nil {
		return MutationResult[kernel.AlertTask]{}, err
	}
	checklist, err := materializeTaskChecklist(command.Input.Checklist, nil, userID, now)
	if err != nil {
		return MutationResult[kernel.AlertTask]{}, ErrInvalidInput
	}
	task, err := kernel.NewAlertTask(kernel.AlertTaskState{
		ID: command.Input.ID, TenantID: tenant, AlertID: command.AlertID,
		Title: command.Input.Title, Description: command.Input.Description,
		Status: kernel.TaskTodo, Priority: command.Input.Priority,
		AssigneeID: command.Input.AssigneeID, OperatorTeamID: command.Input.OperatorTeamID,
		DueAt: command.Input.DueAt, Checklist: checklist,
		SLAInstanceID: command.Input.SLAInstanceID, CreatedAt: now, UpdatedAt: now, Version: 1,
	})
	if err != nil {
		return MutationResult[kernel.AlertTask]{}, ErrInvalidInput
	}
	contract, err := newAlertMutationContract(
		actor, command.AlertID, command.Envelope, access, CapabilityTaskManage,
		operationAlertTaskCreate, "Alert task created", alertTaskCreateRequestFingerprint(task),
	)
	if err != nil {
		return MutationResult[kernel.AlertTask]{}, err
	}
	if err := ctx.Err(); err != nil {
		return MutationResult[kernel.AlertTask]{}, err
	}
	result, err := service.repository.CommitAlertTask(ctx, AlertTaskCreateWrite{Contract: contract, Task: task})
	if err != nil {
		return MutationResult[kernel.AlertTask]{}, alertInvestigationMutationError(err)
	}
	if err := ctx.Err(); err != nil {
		return MutationResult[kernel.AlertTask]{}, err
	}
	if !validAlertTaskResult(result.Resource, tenant, command.AlertID, command.Input.ID, 1) ||
		!sameFingerprint(alertTaskCreateRequestFingerprint(result.Resource), alertTaskCreateRequestFingerprint(task)) ||
		!result.Replayed && !sameFingerprint(alertTaskFingerprint(result.Resource, 0), alertTaskFingerprint(task, 0)) {
		return MutationResult[kernel.AlertTask]{}, ErrUnavailable
	}
	return result, nil
}

func (service *AlertInvestigationService) TransitionTask(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	command AlertTaskTransitionCommand,
) (MutationResult[kernel.AlertTask], error) {
	command.CompletionData = slices.Clone(command.CompletionData)
	if len(command.CompletionData) == 0 {
		command.CompletionData = nil
	}
	access, _, err := service.authorizeMutation(
		ctx, actor, tenantID, command.AlertID, CapabilityTaskManage, command.Envelope,
	)
	if err != nil {
		return MutationResult[kernel.AlertTask]{}, err
	}
	if !validAlertTaskMutationCoordinates(command.TaskID, command.ExpectedVersion) {
		return MutationResult[kernel.AlertTask]{}, ErrInvalidInput
	}
	userID, err := alertActorUserEntity(actor)
	if err != nil {
		return MutationResult[kernel.AlertTask]{}, err
	}
	if !validAlertSingleLineText(command.Reason, 2_000, false) {
		return MutationResult[kernel.AlertTask]{}, ErrInvalidInput
	}
	if err := kernel.ValidateAlertTaskTransitionIntent(
		command.Target, command.Reason, command.CompletionData,
	); err != nil {
		return MutationResult[kernel.AlertTask]{}, ErrInvalidInput
	}
	now, err := service.currentTime()
	if err != nil {
		return MutationResult[kernel.AlertTask]{}, err
	}
	transition := kernel.TaskTransitionInput{
		ExpectedVersion: command.ExpectedVersion, Target: command.Target, ActorID: userID,
		OccurredAt: now, Reason: command.Reason, CompletionData: command.CompletionData,
	}
	return service.mutateTask(
		ctx, actor, tenantID, command.AlertID, command.TaskID, command.ExpectedVersion,
		command.Envelope, access, now, operationAlertTaskTransition, command.Reason,
		alertTaskTransitionRequestFingerprint(command, userID),
		func(current kernel.AlertTask) (kernel.AlertTask, error) { return current.Transition(transition) },
		func(updated kernel.AlertTask) bool {
			if updated.Status() != command.Target {
				return false
			}
			if command.Target == kernel.TaskDone || command.Target == kernel.TaskCancelled {
				return updated.CompletedBy() != nil && *updated.CompletedBy() == userID &&
					sameFingerprint(
						canonicalRawJSON(updated.CompletionData()), canonicalRawJSON(command.CompletionData),
					)
			}
			return updated.CompletedBy() == nil && updated.CompletedAt() == nil && len(updated.CompletionData()) == 0
		},
	)
}

func (service *AlertInvestigationService) ReplaceTaskDetails(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	command AlertTaskDetailsCommand,
) (MutationResult[kernel.AlertTask], error) {
	command.SLAInstanceID = cloneKernelEntityID(command.SLAInstanceID)
	access, _, err := service.authorizeMutation(
		ctx, actor, tenantID, command.AlertID, CapabilityTaskManage, command.Envelope,
	)
	if err != nil {
		return MutationResult[kernel.AlertTask]{}, err
	}
	if !validAlertTaskMutationCoordinates(command.TaskID, command.ExpectedVersion) ||
		command.SLAInstanceID != nil && *command.SLAInstanceID == (kernel.EntityID{}) {
		return MutationResult[kernel.AlertTask]{}, ErrInvalidInput
	}
	now, err := service.currentTime()
	if err != nil {
		return MutationResult[kernel.AlertTask]{}, err
	}
	return service.mutateTask(
		ctx, actor, tenantID, command.AlertID, command.TaskID, command.ExpectedVersion,
		command.Envelope, access, now, operationAlertTaskReplaceDetails, "Alert task details replaced",
		alertTaskDetailsRequestFingerprint(command),
		func(current kernel.AlertTask) (kernel.AlertTask, error) {
			return current.ReplaceDetails(
				command.ExpectedVersion, command.Title, command.Description, command.Priority,
				command.SLAInstanceID, now,
			)
		},
		func(updated kernel.AlertTask) bool {
			return updated.Title() == command.Title && updated.Description() == command.Description &&
				updated.Priority() == command.Priority &&
				equalKernelEntityID(updated.SLAInstanceID(), command.SLAInstanceID)
		},
	)
}

func (service *AlertInvestigationService) AssignTask(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	command AlertTaskAssignmentCommand,
) (MutationResult[kernel.AlertTask], error) {
	command.OperatorTeamID = cloneKernelEntityID(command.OperatorTeamID)
	command.AssigneeID = cloneKernelEntityID(command.AssigneeID)
	access, _, err := service.authorizeMutation(
		ctx, actor, tenantID, command.AlertID, CapabilityTaskManage, command.Envelope,
	)
	if err != nil {
		return MutationResult[kernel.AlertTask]{}, err
	}
	if !validAlertTaskMutationCoordinates(command.TaskID, command.ExpectedVersion) ||
		command.OperatorTeamID != nil && *command.OperatorTeamID == (kernel.EntityID{}) ||
		command.AssigneeID != nil && *command.AssigneeID == (kernel.EntityID{}) ||
		command.AssigneeID != nil && command.OperatorTeamID == nil {
		return MutationResult[kernel.AlertTask]{}, ErrInvalidInput
	}
	now, err := service.currentTime()
	if err != nil {
		return MutationResult[kernel.AlertTask]{}, err
	}
	return service.mutateTask(
		ctx, actor, tenantID, command.AlertID, command.TaskID, command.ExpectedVersion,
		command.Envelope, access, now, operationAlertTaskAssign, "Alert task assignment changed",
		alertTaskAssignmentRequestFingerprint(command),
		func(current kernel.AlertTask) (kernel.AlertTask, error) {
			return current.Assign(command.ExpectedVersion, command.OperatorTeamID, command.AssigneeID, now)
		},
		func(updated kernel.AlertTask) bool {
			return equalKernelEntityID(updated.OperatorTeamID(), command.OperatorTeamID) &&
				equalKernelEntityID(updated.AssigneeID(), command.AssigneeID)
		},
	)
}

func (service *AlertInvestigationService) RescheduleTask(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	command AlertTaskDueDateCommand,
) (MutationResult[kernel.AlertTask], error) {
	command.DueAt = cloneTime(command.DueAt)
	access, _, err := service.authorizeMutation(
		ctx, actor, tenantID, command.AlertID, CapabilityTaskManage, command.Envelope,
	)
	if err != nil {
		return MutationResult[kernel.AlertTask]{}, err
	}
	if !validAlertTaskMutationCoordinates(command.TaskID, command.ExpectedVersion) ||
		!validOptionalAlertInstant(command.DueAt) {
		return MutationResult[kernel.AlertTask]{}, ErrInvalidInput
	}
	now, err := service.currentTime()
	if err != nil {
		return MutationResult[kernel.AlertTask]{}, err
	}
	return service.mutateTask(
		ctx, actor, tenantID, command.AlertID, command.TaskID, command.ExpectedVersion,
		command.Envelope, access, now, operationAlertTaskReschedule, "Alert task due date changed",
		alertTaskDueDateRequestFingerprint(command),
		func(current kernel.AlertTask) (kernel.AlertTask, error) {
			return current.Reschedule(command.ExpectedVersion, command.DueAt, now)
		},
		func(updated kernel.AlertTask) bool { return equalTime(updated.DueAt(), command.DueAt) },
	)
}

func (service *AlertInvestigationService) ReplaceTaskChecklist(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	command AlertTaskChecklistCommand,
) (MutationResult[kernel.AlertTask], error) {
	command.Checklist = slices.Clone(command.Checklist)
	access, _, err := service.authorizeMutation(
		ctx, actor, tenantID, command.AlertID, CapabilityTaskManage, command.Envelope,
	)
	if err != nil {
		return MutationResult[kernel.AlertTask]{}, err
	}
	if !validAlertTaskMutationCoordinates(command.TaskID, command.ExpectedVersion) {
		return MutationResult[kernel.AlertTask]{}, ErrInvalidInput
	}
	userID, err := alertActorUserEntity(actor)
	if err != nil {
		return MutationResult[kernel.AlertTask]{}, err
	}
	now, err := service.currentTime()
	if err != nil {
		return MutationResult[kernel.AlertTask]{}, err
	}
	if _, err := materializeTaskChecklist(command.Checklist, nil, userID, now); err != nil {
		return MutationResult[kernel.AlertTask]{}, ErrInvalidInput
	}
	return service.mutateTask(
		ctx, actor, tenantID, command.AlertID, command.TaskID, command.ExpectedVersion,
		command.Envelope, access, now, operationAlertTaskChecklistReplace,
		"Alert task checklist replaced",
		alertTaskChecklistRequestFingerprint(command),
		func(current kernel.AlertTask) (kernel.AlertTask, error) {
			checklist, err := materializeTaskChecklist(command.Checklist, current.Checklist(), userID, now)
			if err != nil {
				return kernel.AlertTask{}, err
			}
			return current.ReplaceChecklist(command.ExpectedVersion, checklist, now)
		},
		func(updated kernel.AlertTask) bool {
			return sameFingerprint(
				alertChecklistProjectionIntentFingerprint(updated.Checklist()),
				alertChecklistIntentFingerprint(command.Checklist),
			)
		},
	)
}

func (service *AlertInvestigationService) ReplaceTaskComments(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	command AlertTaskCommentsCommand,
) (MutationResult[kernel.AlertTask], error) {
	var err error
	command.CommentIDs, err = canonicalTaskCommentIDs(command.CommentIDs)
	if err != nil {
		return MutationResult[kernel.AlertTask]{}, ErrInvalidInput
	}
	access, _, err := service.authorizeMutation(
		ctx, actor, tenantID, command.AlertID, CapabilityTaskManage, command.Envelope,
	)
	if err != nil {
		return MutationResult[kernel.AlertTask]{}, err
	}
	if !validAlertTaskMutationCoordinates(command.TaskID, command.ExpectedVersion) {
		return MutationResult[kernel.AlertTask]{}, ErrInvalidInput
	}
	now, err := service.currentTime()
	if err != nil {
		return MutationResult[kernel.AlertTask]{}, err
	}
	return service.mutateTask(
		ctx, actor, tenantID, command.AlertID, command.TaskID, command.ExpectedVersion,
		command.Envelope, access, now, operationAlertTaskCommentsReplace,
		"Alert task comments replaced", alertTaskCommentsRequestFingerprint(command),
		func(current kernel.AlertTask) (kernel.AlertTask, error) {
			return current.ReplaceComments(command.ExpectedVersion, command.CommentIDs, now)
		},
		func(updated kernel.AlertTask) bool {
			return slices.Equal(updated.CommentIDs(), command.CommentIDs)
		},
	)
}

// materializeTaskChecklist treats every public task checklist as intent only. Caller
// supplied completion actors and timestamps are never trusted: a new completion
// is stamped by the service, while an unchanged completion preserves its
// existing server-owned provenance.
func materializeTaskChecklist(
	desired []TaskChecklistItemIntent,
	current []kernel.ChecklistItem,
	actorID kernel.EntityID,
	now time.Time,
) ([]kernel.ChecklistItem, error) {
	if len(desired) > 100 {
		return nil, kernel.ErrInvalidTask
	}
	existing := make(map[kernel.EntityID]kernel.ChecklistItem, len(current))
	for _, item := range current {
		existing[item.ID()] = item
	}
	seen := make(map[kernel.EntityID]struct{}, len(desired))
	result := make([]kernel.ChecklistItem, len(desired))
	for index, intent := range desired {
		if intent.ID == (kernel.EntityID{}) || !validAlertSingleLineText(intent.Title, 512, false) {
			return nil, kernel.ErrInvalidTask
		}
		if _, duplicate := seen[intent.ID]; duplicate {
			return nil, kernel.ErrInvalidTask
		}
		seen[intent.ID] = struct{}{}
		input := kernel.ChecklistItemInput{ID: intent.ID, Title: intent.Title, Completed: intent.Completed}
		if intent.Completed {
			if previous, ok := existing[intent.ID]; ok && previous.Completed() {
				input.CompletedAt = previous.CompletedAt()
				input.CompletedBy = previous.CompletedBy()
			} else {
				input.CompletedAt = cloneTime(&now)
				input.CompletedBy = cloneKernelEntityID(&actorID)
			}
		}
		item, err := kernel.NewChecklistItem(input)
		if err != nil {
			return nil, err
		}
		result[index] = item
	}
	return result, nil
}

func (service *AlertInvestigationService) mutateTask(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	alertID kernel.EntityID,
	taskID kernel.EntityID,
	expectedVersion uint64,
	envelope MutationEnvelope,
	access Access,
	occurredAt time.Time,
	operation string,
	auditReason string,
	request any,
	apply func(kernel.AlertTask) (kernel.AlertTask, error),
	matches func(kernel.AlertTask) bool,
) (MutationResult[kernel.AlertTask], error) {
	if !validAlertTaskMutationCoordinates(taskID, expectedVersion) || apply == nil || matches == nil {
		return MutationResult[kernel.AlertTask]{}, ErrInvalidInput
	}
	contract, err := newAlertMutationContract(
		actor, alertID, envelope, access, CapabilityTaskManage, operation, auditReason, request,
	)
	if err != nil {
		return MutationResult[kernel.AlertTask]{}, err
	}
	if err := ctx.Err(); err != nil {
		return MutationResult[kernel.AlertTask]{}, err
	}
	var applied alertCallbackCapture[kernel.AlertTask]
	result, err := service.repository.MutateAlertTask(ctx, AlertTaskMutationWrite{
		Contract: contract, TaskID: taskID, ExpectedVersion: expectedVersion,
		Apply: func(current kernel.AlertTask) (kernel.AlertTask, error) {
			applied.begin()
			if err := ctx.Err(); err != nil {
				return kernel.AlertTask{}, err
			}
			if current.TenantID().String() != tenantID.String() || current.AlertID() != alertID ||
				current.ID() != taskID || !validAlertTaskProjection(current) ||
				occurredAt.Before(current.UpdatedAt()) {
				return kernel.AlertTask{}, ErrUnavailable
			}
			updated, applyErr := apply(current)
			if applyErr == nil {
				applied.complete(updated)
			}
			return updated, applyErr
		},
	})
	if err != nil {
		return MutationResult[kernel.AlertTask]{}, alertInvestigationMutationError(err)
	}
	if err := ctx.Err(); err != nil {
		return MutationResult[kernel.AlertTask]{}, err
	}
	tenant, _, conversionErr := actorEntities(actor)
	if conversionErr != nil || !validAlertTaskResult(result.Resource, tenant, alertID, taskID, expectedVersion+1) ||
		!matches(result.Resource) {
		return MutationResult[kernel.AlertTask]{}, ErrUnavailable
	}
	appliedTask, applyCalls := applied.snapshot()
	if result.Replayed && applyCalls != 0 || !result.Replayed &&
		(applyCalls != 1 || !sameFingerprint(
			alertTaskFingerprint(result.Resource, 0), alertTaskFingerprint(appliedTask, 0),
		)) {
		return MutationResult[kernel.AlertTask]{}, ErrUnavailable
	}
	return result, nil
}

func validAlertTaskMutationCoordinates(taskID kernel.EntityID, expectedVersion uint64) bool {
	return taskID != (kernel.EntityID{}) && validAlertMutationVersion(expectedVersion)
}

func validAlertTaskResult(
	task kernel.AlertTask,
	tenant kernel.EntityID,
	alertID kernel.EntityID,
	taskID kernel.EntityID,
	version uint64,
) bool {
	return task.TenantID() == tenant && task.AlertID() == alertID && task.ID() == taskID &&
		task.Version() == version && validAlertTaskProjection(task)
}

func cloneAlertTaskDraft(input AlertTaskDraft) AlertTaskDraft {
	input.AssigneeID = cloneKernelEntityID(input.AssigneeID)
	input.OperatorTeamID = cloneKernelEntityID(input.OperatorTeamID)
	input.DueAt = cloneTime(input.DueAt)
	input.Checklist = slices.Clone(input.Checklist)
	input.SLAInstanceID = cloneKernelEntityID(input.SLAInstanceID)
	return input
}

func cloneKernelEntityID(value *kernel.EntityID) *kernel.EntityID {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func equalKernelEntityID(left, right *kernel.EntityID) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func equalTime(left, right *time.Time) bool {
	return left == nil && right == nil || left != nil && right != nil && left.Equal(*right)
}
