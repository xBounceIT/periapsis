package dfir

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/dfir"
)

func TestCaseTaskCreateOwnsLifecycleAndChecklistProvenance(t *testing.T) {
	t.Parallel()
	tenantID := testUUID(140)
	caseID := testEntityID(t, 141)
	taskID := testEntityID(t, 142)
	itemID := testEntityID(t, 143)
	actor := testActor(tenantID, PrincipalHuman)
	now := time.Date(2026, 9, 4, 9, 0, 0, 123_000, time.UTC)
	commits := 0
	repository := &fakeRepository{
		resolveAccess: func(_ context.Context, got Actor, gotTenant uuid.UUID, capability Capability, scope ResourceScope) (Access, error) {
			if got != actor || gotTenant != tenantID || capability != CapabilityTaskManage || scope.CaseID != caseID {
				t.Fatal("Case task authorization lost its actor, tenant, capability, or root")
			}
			return Access{Audience: kernel.AudienceOperator, Scope: ScopeTenant}, nil
		},
		commitTask: func(_ context.Context, write TaskCreateWrite) (MutationResult[kernel.Task], error) {
			commits++
			value := write.Task
			if !ValidTaskMutationContract(write.Contract, operationTaskCreate) ||
				write.Contract.Actor != actor || write.Contract.CaseID != caseID ||
				value.ID() != taskID || value.CaseID() != caseID || value.Status() != kernel.TaskTodo ||
				value.Version() != 1 || value.CompletedAt() != nil || value.CompletedBy() != nil ||
				len(value.CompletionData()) != 0 || len(value.CommentIDs()) != 0 {
				t.Fatal("Case task create accepted client-owned lifecycle state")
			}
			checklist := value.Checklist()
			actorID := testEntityIDFromUUID(t, actor.UserID)
			if len(checklist) != 1 || !checklist[0].Completed() ||
				checklist[0].CompletedAt() == nil || !checklist[0].CompletedAt().Equal(now) ||
				checklist[0].CompletedBy() == nil || *checklist[0].CompletedBy() != actorID {
				t.Fatal("Case task checklist completion provenance was not server-owned")
			}
			return MutationResult[kernel.Task]{Resource: value}, nil
		},
	}
	service := mustServiceAt(t, repository, &fakeObjectStorage{}, &fakeScanner{}, now)
	result, err := service.CreateTask(context.Background(), actor, tenantID, TaskCreateCommand{
		CaseID: caseID,
		Input: TaskDraft{
			ID: taskID, Title: "Acquire volatile memory", Description: "Before shutdown",
			Priority:  kernel.TaskPriorityUrgent,
			Checklist: []TaskChecklistItemIntent{{ID: itemID, Title: "Capture RAM", Completed: true}},
		},
		Envelope: testEnvelope(144),
	})
	if err != nil || commits != 1 || result.Replayed || result.Resource.Status() != kernel.TaskTodo {
		t.Fatalf("CreateTask() = (%v, %v), commits=%d", result, err, commits)
	}
}

func TestCaseTaskMutationsAreCallbackCASBoundAndReachDone(t *testing.T) {
	t.Parallel()
	tenantID := testUUID(150)
	caseID := testEntityID(t, 151)
	taskID := testEntityID(t, 152)
	itemID := testEntityID(t, 153)
	teamID := testEntityID(t, 154)
	assigneeID := testEntityID(t, 155)
	slaID := testEntityID(t, 156)
	actor := testActor(tenantID, PrincipalHuman)
	now := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	current, err := kernel.NewTask(kernel.TaskInput{
		ID: taskID, TenantID: testEntityIDFromUUID(t, tenantID), CaseID: caseID,
		Title: "Initial task", Status: kernel.TaskTodo, Priority: kernel.TaskPriorityMedium,
		CreatedAt: now, UpdatedAt: now, Version: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	applyCalls := 0
	repository := &fakeRepository{
		resolveAccess: func(context.Context, Actor, uuid.UUID, Capability, ResourceScope) (Access, error) {
			return Access{Audience: kernel.AudienceOperator, Scope: ScopeTenant}, nil
		},
		mutateTask: func(_ context.Context, write TaskMutationWrite) (MutationResult[kernel.Task], error) {
			if write.ExpectedVersion != current.Version() || write.TaskID != taskID ||
				!ValidTaskMutationContract(write.Contract, write.Contract.Command.Operation) {
				return MutationResult[kernel.Task]{}, ErrRepositoryPrecondition
			}
			updated, applyErr := write.Apply(current)
			if applyErr != nil {
				return MutationResult[kernel.Task]{}, applyErr
			}
			applyCalls++
			current = updated
			return MutationResult[kernel.Task]{Resource: current}, nil
		},
	}
	service := mustServiceAt(t, repository, &fakeObjectStorage{}, &fakeScanner{}, now)

	details, err := service.ReplaceTaskDetails(context.Background(), actor, tenantID, TaskDetailsCommand{
		CaseID: caseID, TaskID: taskID, ExpectedVersion: 1,
		Title: "Collect memory", Description: "Preserve acquisition order",
		Priority: kernel.TaskPriorityHigh, SLAInstanceID: &slaID, Envelope: testEnvelope(157),
	})
	if err != nil || details.Resource.SLAInstanceID() == nil || details.Resource.Version() != 2 {
		t.Fatalf("ReplaceTaskDetails() = (%v, %v)", details.Resource, err)
	}
	assigned, err := service.AssignTask(context.Background(), actor, tenantID, TaskAssignmentCommand{
		CaseID: caseID, TaskID: taskID, ExpectedVersion: 2,
		OperatorTeamID: &teamID, AssigneeID: &assigneeID, Envelope: testEnvelope(158),
	})
	if err != nil || assigned.Resource.AssigneeID() == nil || assigned.Resource.Version() != 3 {
		t.Fatalf("AssignTask() = (%v, %v)", assigned.Resource, err)
	}
	due := now.Add(4 * time.Hour)
	scheduled, err := service.RescheduleTask(context.Background(), actor, tenantID, TaskDueDateCommand{
		CaseID: caseID, TaskID: taskID, ExpectedVersion: 3, DueAt: &due, Envelope: testEnvelope(159),
	})
	if err != nil || scheduled.Resource.DueAt() == nil || scheduled.Resource.Version() != 4 {
		t.Fatalf("RescheduleTask() = (%v, %v)", scheduled.Resource, err)
	}
	checked, err := service.ReplaceTaskChecklist(context.Background(), actor, tenantID, TaskChecklistCommand{
		CaseID: caseID, TaskID: taskID, ExpectedVersion: 4,
		Checklist: []TaskChecklistItemIntent{{ID: itemID, Title: "RAM captured", Completed: true}},
		Envelope:  testEnvelope(160),
	})
	if err != nil || len(checked.Resource.Checklist()) != 1 || !checked.Resource.Checklist()[0].Completed() ||
		checked.Resource.Version() != 5 {
		t.Fatalf("ReplaceTaskChecklist() = (%v, %v)", checked.Resource, err)
	}
	commentID := testEntityID(t, 164)
	commented, err := service.ReplaceTaskComments(context.Background(), actor, tenantID, TaskCommentsCommand{
		CaseID: caseID, TaskID: taskID, ExpectedVersion: 5,
		CommentIDs: []kernel.EntityID{commentID}, Envelope: testEnvelope(165),
	})
	if err != nil || commented.Resource.Version() != 6 ||
		len(commented.Resource.CommentIDs()) != 1 || commented.Resource.CommentIDs()[0] != commentID {
		t.Fatalf("ReplaceTaskComments() = (%v, %v)", commented.Resource, err)
	}
	started, err := service.TransitionTask(context.Background(), actor, tenantID, TaskTransitionCommand{
		CaseID: caseID, TaskID: taskID, ExpectedVersion: 6, Target: kernel.TaskInProgress,
		Reason: "Begin analysis", Envelope: testEnvelope(161),
	})
	if err != nil || started.Resource.Status() != kernel.TaskInProgress || started.Resource.Version() != 7 {
		t.Fatalf("TransitionTask(in progress) = (%v, %v)", started.Resource, err)
	}
	done, err := service.TransitionTask(context.Background(), actor, tenantID, TaskTransitionCommand{
		CaseID: caseID, TaskID: taskID, ExpectedVersion: 7, Target: kernel.TaskDone,
		Reason: "Acquisition verified", Envelope: testEnvelope(162),
	})
	if err != nil || done.Resource.Status() != kernel.TaskDone || done.Resource.CompletedBy() == nil ||
		done.Resource.Version() != 8 || applyCalls != 7 {
		t.Fatalf("TransitionTask(done) = (%v, %v), applyCalls=%d", done.Resource, err, applyCalls)
	}

	if _, err = service.RescheduleTask(context.Background(), actor, tenantID, TaskDueDateCommand{
		CaseID: caseID, TaskID: taskID, ExpectedVersion: 7, Envelope: testEnvelope(163),
	}); !errors.Is(err, ErrPreconditionFailed) || applyCalls != 7 {
		t.Fatalf("stale Case task mutation = %v, applyCalls=%d", err, applyCalls)
	}
}

func TestCaseTaskReplaySkipsCallbackAndReturnsHistoricalSnapshot(t *testing.T) {
	t.Parallel()
	tenantID := testUUID(170)
	caseID := testEntityID(t, 171)
	taskID := testEntityID(t, 172)
	actor := testActor(tenantID, PrincipalHuman)
	now := time.Date(2026, 9, 4, 11, 0, 0, 0, time.UTC)
	base, err := kernel.NewTask(kernel.TaskInput{
		ID: taskID, TenantID: testEntityIDFromUUID(t, tenantID), CaseID: caseID,
		Title: "Historical task", Status: kernel.TaskTodo, Priority: kernel.TaskPriorityMedium,
		CreatedAt: now, UpdatedAt: now, Version: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	due := now.Add(time.Hour)
	historical, err := base.Reschedule(1, &due, now.Add(time.Microsecond))
	if err != nil {
		t.Fatal(err)
	}
	repository := &fakeRepository{
		resolveAccess: func(context.Context, Actor, uuid.UUID, Capability, ResourceScope) (Access, error) {
			return Access{Audience: kernel.AudienceOperator, Scope: ScopeTenant}, nil
		},
		mutateTask: func(_ context.Context, write TaskMutationWrite) (MutationResult[kernel.Task], error) {
			return MutationResult[kernel.Task]{Resource: historical, Replayed: true}, nil
		},
	}
	service := mustServiceAt(t, repository, &fakeObjectStorage{}, &fakeScanner{}, now.Add(2*time.Hour))
	result, err := service.RescheduleTask(context.Background(), actor, tenantID, TaskDueDateCommand{
		CaseID: caseID, TaskID: taskID, ExpectedVersion: 1, DueAt: &due, Envelope: testEnvelope(173),
	})
	if err != nil || !result.Replayed || !result.Resource.UpdatedAt().Equal(historical.UpdatedAt()) ||
		result.Resource.Version() != 2 {
		t.Fatalf("historical replay = (%v, %v)", result, err)
	}
}
