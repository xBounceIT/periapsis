package dfir

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestTaskLifecycleRequiresCompletedChecklistAndUsesOptimisticVersions(t *testing.T) {
	base := time.Date(2026, 8, 25, 14, 0, 0, 0, time.UTC)
	incomplete, err := NewChecklistItem(ChecklistItemInput{ID: fixtureID(101), Title: "Acquire memory image"})
	if err != nil {
		t.Fatal(err)
	}
	task := mustTask(t, []ChecklistItem{incomplete})
	inProgress, err := task.Transition(TaskTransitionInput{
		ExpectedVersion: 1, Target: TaskInProgress, ActorID: fixtureID(9),
		OccurredAt: base.Add(time.Microsecond), Reason: "investigation started",
	})
	if err != nil || inProgress.Status() != TaskInProgress || inProgress.Version() != 2 || task.Version() != 1 {
		t.Fatalf("todo -> in_progress failed: %v", err)
	}
	if _, err := inProgress.Transition(TaskTransitionInput{
		ExpectedVersion: 2, Target: TaskDone, ActorID: fixtureID(9),
		OccurredAt: base.Add(2 * time.Microsecond), Reason: "premature completion",
	}); !errors.Is(err, ErrInvalidTask) {
		t.Fatalf("incomplete checklist completion error = %v", err)
	}
	completedAt := base.Add(2 * time.Microsecond)
	completed, _ := NewChecklistItem(ChecklistItemInput{
		ID: fixtureID(101), Title: "Acquire memory image", Completed: true,
		CompletedAt: &completedAt, CompletedBy: entityIDPointer(fixtureID(9)),
	})
	ready, err := inProgress.ReplaceChecklist(2, []ChecklistItem{completed}, completedAt)
	if err != nil || ready.Version() != 3 {
		t.Fatalf("checklist completion failed: %v", err)
	}
	done, err := ready.Transition(TaskTransitionInput{
		ExpectedVersion: 3, Target: TaskDone, ActorID: fixtureID(9),
		OccurredAt: base.Add(3 * time.Microsecond), Reason: "collection verified",
		CompletionData: json.RawMessage(`{"result":"captured"}`),
	})
	if err != nil || done.Status() != TaskDone || done.CompletedAt() == nil ||
		done.CompletedBy() == nil || done.Version() != 4 {
		t.Fatalf("task completion failed: %v", err)
	}
	if _, err := done.Transition(TaskTransitionInput{
		ExpectedVersion: 3, Target: "future", OccurredAt: base,
	}); !errors.Is(err, ErrTaskConflict) {
		t.Fatalf("stale malformed transition error = %v", err)
	}
	reopened, err := done.Transition(TaskTransitionInput{
		ExpectedVersion: 4, Target: TaskInProgress, ActorID: fixtureID(9),
		OccurredAt: base.Add(4 * time.Microsecond), Reason: "authorized reopen",
	})
	if err != nil || reopened.CompletedAt() != nil || reopened.CompletedBy() != nil ||
		len(reopened.CompletionData()) != 0 {
		t.Fatalf("reopen did not clear terminal completion state: %v", err)
	}
}

func TestTaskAssignmentAndCollectionsAreDefensivelyOwned(t *testing.T) {
	team := fixtureID(110)
	assignee := fixtureID(111)
	commentIDs := []EntityID{fixtureID(113), fixtureID(112)}
	completionData := json.RawMessage(`{"private":"result"}`)
	input := validTaskInput(nil)
	input.Status = TaskCancelled
	input.CompletedAt = entityTimePointer(input.UpdatedAt)
	input.CompletedBy = entityIDPointer(fixtureID(9))
	input.CompletionData = completionData
	input.CommentIDs = commentIDs
	task, err := NewTask(input)
	if err != nil {
		t.Fatal(err)
	}
	commentIDs[0] = fixtureID(120)
	completionData[2] = 'X'
	if got := task.CommentIDs(); got[0] != fixtureID(112) || got[1] != fixtureID(113) {
		t.Fatalf("comments were not canonicalized/owned: %v", got)
	}
	if got := string(task.CompletionData()); got != `{"private":"result"}` {
		t.Fatalf("completion data = %s", got)
	}
	if _, err := task.Assign(task.Version(), &team, &assignee, task.UpdatedAt().Add(time.Microsecond)); err == nil {
		t.Fatal("terminal task assignment was accepted")
	}

	active := mustTask(t, nil)
	if _, err := active.Assign(1, nil, &assignee, active.UpdatedAt().Add(time.Microsecond)); err == nil {
		t.Fatal("assignee without an operator team was accepted")
	}
	assigned, err := active.Assign(1, &team, &assignee, active.UpdatedAt().Add(time.Microsecond))
	if err != nil || assigned.AssigneeID() == nil || assigned.OperatorTeamID() == nil {
		t.Fatalf("valid assignment failed: %v", err)
	}
	team = fixtureID(121)
	assignee = fixtureID(122)
	if *assigned.AssigneeID() != fixtureID(111) || *assigned.OperatorTeamID() != fixtureID(110) {
		t.Fatal("task retained caller-owned assignment pointers")
	}
}

func TestTaskDetailsAndScheduleReplaceAndClearWithCAS(t *testing.T) {
	t.Parallel()
	task := mustTask(t, nil)
	sla := fixtureID(130)
	detailsAt := task.UpdatedAt().Add(time.Microsecond)
	updated, err := task.ReplaceDetails(
		1, "Preserve volatile memory", "Acquire before shutdown",
		TaskPriorityUrgent, &sla, detailsAt,
	)
	if err != nil || updated.Version() != 2 || updated.Title() != "Preserve volatile memory" ||
		updated.SLAInstanceID() == nil || *updated.SLAInstanceID() != sla {
		t.Fatalf("replace details = (%v, %v)", updated, err)
	}
	cleared, err := updated.ReplaceDetails(
		2, "Preserve volatile memory", "Acquire before shutdown",
		TaskPriorityUrgent, nil, detailsAt.Add(time.Microsecond),
	)
	if err != nil || cleared.Version() != 3 || cleared.SLAInstanceID() != nil {
		t.Fatalf("clear SLA details = (%v, %v)", cleared, err)
	}
	if _, err = cleared.ReplaceDetails(
		3, cleared.Title(), cleared.Description(), cleared.Priority(), nil,
		detailsAt.Add(2*time.Microsecond),
	); !errors.Is(err, ErrInvalidTask) {
		t.Fatalf("no-op details error = %v", err)
	}

	due := detailsAt.Add(24 * time.Hour)
	scheduled, err := cleared.Reschedule(3, &due, detailsAt.Add(3*time.Microsecond))
	if err != nil || scheduled.Version() != 4 || scheduled.DueAt() == nil ||
		!scheduled.DueAt().Equal(due) {
		t.Fatalf("reschedule = (%v, %v)", scheduled, err)
	}
	unscheduled, err := scheduled.Reschedule(4, nil, detailsAt.Add(4*time.Microsecond))
	if err != nil || unscheduled.Version() != 5 || unscheduled.DueAt() != nil {
		t.Fatalf("clear due date = (%v, %v)", unscheduled, err)
	}
	if _, err = unscheduled.Reschedule(4, nil, detailsAt.Add(5*time.Microsecond)); !errors.Is(err, ErrTaskConflict) {
		t.Fatalf("stale reschedule error = %v", err)
	}
	if task.Version() != 1 || task.SLAInstanceID() != nil || task.DueAt() != nil {
		t.Fatal("details or schedule mutation modified the original task")
	}
}

func TestTaskCommentAssociationIsCanonicalCASAndBounded(t *testing.T) {
	t.Parallel()
	task := mustTask(t, nil)
	first, second := fixtureID(141), fixtureID(140)
	updatedAt := task.UpdatedAt().Add(time.Microsecond)
	comments := []EntityID{first, second}
	updated, err := task.ReplaceComments(1, comments, updatedAt)
	if err != nil || updated.Version() != 2 || !updated.UpdatedAt().Equal(updatedAt) {
		t.Fatalf("replace comments = (%v, %v)", updated, err)
	}
	comments[0] = fixtureID(142)
	if got := updated.CommentIDs(); len(got) != 2 || got[0] != second || got[1] != first {
		t.Fatalf("comment IDs were not canonicalized and owned: %v", got)
	}
	if len(task.CommentIDs()) != 0 || task.Version() != 1 {
		t.Fatal("comment replacement mutated the original task")
	}
	if _, err = updated.ReplaceComments(1, nil, updatedAt.Add(time.Microsecond)); !errors.Is(err, ErrTaskConflict) {
		t.Fatalf("stale comment replacement error = %v", err)
	}
	if _, err = updated.ReplaceComments(2, []EntityID{first, first}, updatedAt.Add(time.Microsecond)); !errors.Is(err, ErrInvalidTask) {
		t.Fatalf("duplicate comment replacement error = %v", err)
	}
	if _, err = updated.ReplaceComments(2, []EntityID{second, first}, updatedAt.Add(time.Microsecond)); !errors.Is(err, ErrInvalidTask) {
		t.Fatalf("no-op comment replacement error = %v", err)
	}
	tooMany := make([]EntityID, 1_001)
	for index := range tooMany {
		tooMany[index] = fixtureID(uint16(1_000 + index))
	}
	if _, err = updated.ReplaceComments(2, tooMany, updatedAt.Add(time.Microsecond)); !errors.Is(err, ErrInvalidTask) {
		t.Fatalf("oversized comment replacement error = %v", err)
	}
}

func TestTaskConstructorRejectsIncoherentCompletionAndChecklistTimes(t *testing.T) {
	base := validTaskInput(nil)
	tests := []func(*TaskInput){
		func(input *TaskInput) { input.AssigneeID = entityIDPointer(fixtureID(111)) },
		func(input *TaskInput) { input.Status = TaskDone },
		func(input *TaskInput) {
			at := input.UpdatedAt.Add(time.Microsecond)
			item, _ := NewChecklistItem(ChecklistItemInput{
				ID: fixtureID(101), Title: "future completion", Completed: true,
				CompletedAt: &at, CompletedBy: entityIDPointer(fixtureID(9)),
			})
			input.Checklist = []ChecklistItem{item}
		},
		func(input *TaskInput) { input.CompletionData = json.RawMessage(`{"result":"without terminal state"}`) },
		func(input *TaskInput) { input.Version = maximumAggregateVersion + 1 },
	}
	for index, mutate := range tests {
		input := base
		mutate(&input)
		if _, err := NewTask(input); err == nil {
			t.Fatalf("invalid task case %d accepted", index)
		}
	}
}

func TestTaskAndChecklistFormattingRedactContent(t *testing.T) {
	item, _ := NewChecklistItem(ChecklistItemInput{ID: fixtureID(101), Title: "private checklist title"})
	task := mustTask(t, []ChecklistItem{item})
	for _, rendered := range []string{fmt.Sprint(task), fmt.Sprintf("%#v", task)} {
		for _, secret := range []string{task.Title(), task.Description()} {
			if strings.Contains(rendered, secret) {
				t.Fatalf("task formatting leaked %q: %q", secret, rendered)
			}
		}
	}
	if rendered := fmt.Sprintf("%#v", item); strings.Contains(rendered, item.Title()) {
		t.Fatalf("checklist formatting leaked title: %q", rendered)
	}
}

func mustTask(t *testing.T, checklist []ChecklistItem) Task {
	t.Helper()
	task, err := NewTask(validTaskInput(checklist))
	if err != nil {
		t.Fatal(err)
	}
	return task
}

func validTaskInput(checklist []ChecklistItem) TaskInput {
	base := time.Date(2026, 8, 25, 14, 0, 0, 0, time.UTC)
	return TaskInput{
		ID: fixtureID(100), TenantID: fixtureID(1), CaseID: fixtureID(20),
		Title: "Collect volatile memory", Description: "Private task details",
		Status: TaskTodo, Priority: TaskPriorityHigh, Checklist: checklist,
		CreatedAt: base, UpdatedAt: base, Version: 1,
	}
}

func entityIDPointer(value EntityID) *EntityID     { return &value }
func entityTimePointer(value time.Time) *time.Time { return &value }
