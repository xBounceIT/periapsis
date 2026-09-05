package dfir

import (
	"encoding/json"
	"fmt"
	"slices"
	"time"
)

type TaskStatus string

const (
	TaskTodo       TaskStatus = "todo"
	TaskInProgress TaskStatus = "in_progress"
	TaskBlocked    TaskStatus = "blocked"
	TaskDone       TaskStatus = "done"
	TaskCancelled  TaskStatus = "cancelled"
)

func validTaskStatus(value TaskStatus) bool {
	switch value {
	case TaskTodo, TaskInProgress, TaskBlocked, TaskDone, TaskCancelled:
		return true
	default:
		return false
	}
}

func terminalTaskStatus(value TaskStatus) bool {
	return value == TaskDone || value == TaskCancelled
}

type TaskPriority string

const (
	TaskPriorityLow    TaskPriority = "low"
	TaskPriorityMedium TaskPriority = "medium"
	TaskPriorityHigh   TaskPriority = "high"
	TaskPriorityUrgent TaskPriority = "urgent"
)

func validTaskPriority(value TaskPriority) bool {
	return value == TaskPriorityLow || value == TaskPriorityMedium ||
		value == TaskPriorityHigh || value == TaskPriorityUrgent
}

type ChecklistItemInput struct {
	ID          EntityID
	Title       string
	Completed   bool
	CompletedAt *time.Time
	CompletedBy *EntityID
}

type ChecklistItem struct {
	id          EntityID
	title       string
	completed   bool
	completedAt *time.Time
	completedBy *EntityID
}

func NewChecklistItem(input ChecklistItemInput) (ChecklistItem, error) {
	completedAt, timeOK := canonicalOptionalInstant(input.CompletedAt)
	completedBy, actorOK := canonicalOptionalEntityID(input.CompletedBy)
	if !validEntityID(input.ID) || !validSingleLineText(input.Title, 512, false) ||
		!timeOK || !actorOK || input.Completed != (completedAt != nil) || input.Completed != (completedBy != nil) {
		return ChecklistItem{}, ErrInvalidTask
	}
	return ChecklistItem{
		id: input.ID, title: input.Title, completed: input.Completed,
		completedAt: completedAt, completedBy: completedBy,
	}, nil
}

func (item ChecklistItem) ID() EntityID            { return item.id }
func (item ChecklistItem) Title() string           { return item.title }
func (item ChecklistItem) Completed() bool         { return item.completed }
func (item ChecklistItem) CompletedAt() *time.Time { return cloneInstant(item.completedAt) }
func (item ChecklistItem) CompletedBy() *EntityID  { return cloneEntityID(item.completedBy) }
func (item ChecklistItem) String() string {
	return fmt.Sprintf("dfir.ChecklistItem{completed:%t,title:[REDACTED]}", item.completed)
}
func (item ChecklistItem) GoString() string { return item.String() }

type TaskInput struct {
	ID             EntityID
	TenantID       EntityID
	CaseID         EntityID
	Title          string
	Description    string
	Status         TaskStatus
	Priority       TaskPriority
	AssigneeID     *EntityID
	OperatorTeamID *EntityID
	DueAt          *time.Time
	Checklist      []ChecklistItem
	CompletedAt    *time.Time
	CompletedBy    *EntityID
	CompletionData json.RawMessage
	CommentIDs     []EntityID
	SLAInstanceID  *EntityID
	CreatedAt      time.Time
	UpdatedAt      time.Time
	Version        uint64
}

type Task struct {
	id             EntityID
	tenantID       EntityID
	caseID         EntityID
	title          string
	description    string
	status         TaskStatus
	priority       TaskPriority
	assigneeID     *EntityID
	operatorTeamID *EntityID
	dueAt          *time.Time
	checklist      []ChecklistItem
	completedAt    *time.Time
	completedBy    *EntityID
	completionData json.RawMessage
	commentIDs     []EntityID
	slaInstanceID  *EntityID
	createdAt      time.Time
	updatedAt      time.Time
	version        uint64
}

func NewTask(input TaskInput) (Task, error) {
	assignee, assigneeOK := canonicalOptionalEntityID(input.AssigneeID)
	team, teamOK := canonicalOptionalEntityID(input.OperatorTeamID)
	dueAt, dueOK := canonicalOptionalInstant(input.DueAt)
	completedAt, completedAtOK := canonicalOptionalInstant(input.CompletedAt)
	completedBy, completedByOK := canonicalOptionalEntityID(input.CompletedBy)
	sla, slaOK := canonicalOptionalEntityID(input.SLAInstanceID)
	checklist, checklistOK := canonicalChecklist(input.Checklist)
	comments, commentsOK := canonicalEntityIDs(input.CommentIDs, 1_000)
	terminal := terminalTaskStatus(input.Status)
	if !validEntityID(input.ID) || !validEntityID(input.TenantID) || !validEntityID(input.CaseID) ||
		!validSingleLineText(input.Title, 512, false) || !validOptionalText(input.Description, 16*1024) ||
		!validTaskStatus(input.Status) || !validTaskPriority(input.Priority) ||
		!assigneeOK || !teamOK || assignee != nil && team == nil || !dueOK || !completedAtOK ||
		!completedByOK || !slaOK || !checklistOK || !commentsOK || !validEnrichment(input.CompletionData) ||
		!validInstant(input.CreatedAt) || !validInstant(input.UpdatedAt) || input.UpdatedAt.Before(input.CreatedAt) ||
		input.Version == 0 || input.Version > maximumAggregateVersion || terminal != (completedAt != nil) ||
		terminal != (completedBy != nil) || !terminal && len(input.CompletionData) != 0 ||
		completedAt != nil && (completedAt.Before(input.CreatedAt) || completedAt.After(input.UpdatedAt)) ||
		input.Status == TaskDone && !allChecklistCompleted(checklist) ||
		!checklistTimesWithin(checklist, input.CreatedAt, input.UpdatedAt) {
		return Task{}, ErrInvalidTask
	}
	return Task{
		id: input.ID, tenantID: input.TenantID, caseID: input.CaseID,
		title: input.Title, description: input.Description,
		status: input.Status, priority: input.Priority,
		assigneeID: assignee, operatorTeamID: team, dueAt: dueAt,
		checklist: checklist, completedAt: completedAt, completedBy: completedBy,
		completionData: slices.Clone(input.CompletionData), commentIDs: comments,
		slaInstanceID: sla, createdAt: input.CreatedAt, updatedAt: input.UpdatedAt,
		version: input.Version,
	}, nil
}

func (task Task) ID() EntityID                    { return task.id }
func (task Task) TenantID() EntityID              { return task.tenantID }
func (task Task) CaseID() EntityID                { return task.caseID }
func (task Task) Title() string                   { return task.title }
func (task Task) Description() string             { return task.description }
func (task Task) Status() TaskStatus              { return task.status }
func (task Task) Priority() TaskPriority          { return task.priority }
func (task Task) AssigneeID() *EntityID           { return cloneEntityID(task.assigneeID) }
func (task Task) OperatorTeamID() *EntityID       { return cloneEntityID(task.operatorTeamID) }
func (task Task) DueAt() *time.Time               { return cloneInstant(task.dueAt) }
func (task Task) Checklist() []ChecklistItem      { return cloneChecklist(task.checklist) }
func (task Task) CompletedAt() *time.Time         { return cloneInstant(task.completedAt) }
func (task Task) CompletedBy() *EntityID          { return cloneEntityID(task.completedBy) }
func (task Task) CompletionData() json.RawMessage { return slices.Clone(task.completionData) }
func (task Task) CommentIDs() []EntityID          { return slices.Clone(task.commentIDs) }
func (task Task) SLAInstanceID() *EntityID        { return cloneEntityID(task.slaInstanceID) }
func (task Task) CreatedAt() time.Time            { return task.createdAt }
func (task Task) UpdatedAt() time.Time            { return task.updatedAt }
func (task Task) Version() uint64                 { return task.version }
func (task Task) String() string {
	return fmt.Sprintf(
		"dfir.Task{status:%s,priority:%s,version:%d,assigned:%t,team:%t,checklist:%d,comments:%d,sla:%t,content:[REDACTED]}",
		task.status, task.priority, task.version, task.assigneeID != nil, task.operatorTeamID != nil,
		len(task.checklist), len(task.commentIDs), task.slaInstanceID != nil,
	)
}
func (task Task) GoString() string { return task.String() }

type TaskTransitionInput struct {
	ExpectedVersion uint64
	Target          TaskStatus
	ActorID         EntityID
	OccurredAt      time.Time
	Reason          string
	CompletionData  json.RawMessage
}

// ValidateTaskTransitionIntent validates the state-independent portion of a
// transition before an idempotency receipt is consulted. State and checklist
// rules remain enforced by Task.Transition under the repository row lock.
func ValidateTaskTransitionIntent(target TaskStatus, reason string, completionData json.RawMessage) error {
	if !validTaskStatus(target) || !validSingleLineText(reason, 2_000, false) ||
		!validEnrichment(completionData) || !terminalTaskStatus(target) && len(completionData) != 0 {
		return ErrInvalidTask
	}
	return nil
}

func (task Task) Transition(input TaskTransitionInput) (Task, error) {
	if input.ExpectedVersion != task.version {
		return Task{}, ErrTaskConflict
	}
	if task.version >= maximumAggregateVersion {
		return Task{}, ErrInvalidTask
	}
	if !validTaskTransition(task.status, input.Target) || !validEntityID(input.ActorID) ||
		!validInstant(input.OccurredAt) || input.OccurredAt.Before(task.updatedAt) ||
		!validSingleLineText(input.Reason, 2_000, false) || !validEnrichment(input.CompletionData) ||
		terminalTaskStatus(input.Target) && input.OccurredAt.Before(task.createdAt) ||
		input.Target == TaskDone && !allChecklistCompleted(task.checklist) {
		return Task{}, ErrInvalidTask
	}
	updated := task.clone()
	updated.status = input.Target
	updated.updatedAt = input.OccurredAt
	updated.version++
	if terminalTaskStatus(input.Target) {
		actor := input.ActorID
		at := input.OccurredAt
		updated.completedBy = &actor
		updated.completedAt = &at
		updated.completionData = slices.Clone(input.CompletionData)
	} else {
		updated.completedBy = nil
		updated.completedAt = nil
		updated.completionData = nil
	}
	return updated, nil
}

func (task Task) ReplaceChecklist(
	expectedVersion uint64,
	items []ChecklistItem,
	updatedAt time.Time,
) (Task, error) {
	if expectedVersion != task.version {
		return Task{}, ErrTaskConflict
	}
	canonical, ok := canonicalChecklist(items)
	if !ok || task.version >= maximumAggregateVersion || terminalTaskStatus(task.status) ||
		!validInstant(updatedAt) || updatedAt.Before(task.updatedAt) ||
		!checklistTimesWithin(canonical, task.createdAt, updatedAt) {
		return Task{}, ErrInvalidTask
	}
	updated := task.clone()
	updated.checklist = canonical
	updated.updatedAt = updatedAt
	updated.version++
	return updated, nil
}

// ReplaceComments atomically replaces the complete set of ticket comments
// associated with the task. IDs are canonicalized so receipt fingerprints and
// projections remain stable regardless of caller ordering.
func (task Task) ReplaceComments(
	expectedVersion uint64,
	commentIDs []EntityID,
	updatedAt time.Time,
) (Task, error) {
	if expectedVersion != task.version {
		return Task{}, ErrTaskConflict
	}
	canonical, ok := canonicalEntityIDs(commentIDs, 1_000)
	if !ok || task.version >= maximumAggregateVersion || terminalTaskStatus(task.status) ||
		!validInstant(updatedAt) || updatedAt.Before(task.updatedAt) ||
		slices.Equal(task.commentIDs, canonical) {
		return Task{}, ErrInvalidTask
	}
	updated := task.clone()
	updated.commentIDs = canonical
	updated.updatedAt = updatedAt
	updated.version++
	return updated, nil
}

// ReplaceDetails atomically replaces the caller-editable core details and the
// optional Case-scoped SLA link. Terminal tasks cannot be rewritten and a
// semantic no-op is rejected instead of manufacturing a revision.
func (task Task) ReplaceDetails(
	expectedVersion uint64,
	title string,
	description string,
	priority TaskPriority,
	slaInstanceID *EntityID,
	updatedAt time.Time,
) (Task, error) {
	if expectedVersion != task.version {
		return Task{}, ErrTaskConflict
	}
	sla, slaOK := canonicalOptionalEntityID(slaInstanceID)
	if !validSingleLineText(title, 512, false) || !validOptionalText(description, 16*1024) ||
		!validTaskPriority(priority) || !slaOK || task.version >= maximumAggregateVersion ||
		terminalTaskStatus(task.status) || !validInstant(updatedAt) || updatedAt.Before(task.updatedAt) ||
		task.title == title && task.description == description && task.priority == priority &&
			equalOptionalEntityID(task.slaInstanceID, sla) {
		return Task{}, ErrInvalidTask
	}
	updated := task.clone()
	updated.title = title
	updated.description = description
	updated.priority = priority
	updated.slaInstanceID = sla
	updated.updatedAt = updatedAt
	updated.version++
	return updated, nil
}

func (task Task) Assign(
	expectedVersion uint64,
	teamID *EntityID,
	assigneeID *EntityID,
	updatedAt time.Time,
) (Task, error) {
	if expectedVersion != task.version {
		return Task{}, ErrTaskConflict
	}
	team, teamOK := canonicalOptionalEntityID(teamID)
	assignee, assigneeOK := canonicalOptionalEntityID(assigneeID)
	if !teamOK || !assigneeOK || task.version >= maximumAggregateVersion || terminalTaskStatus(task.status) ||
		assignee != nil && team == nil ||
		!validInstant(updatedAt) || updatedAt.Before(task.updatedAt) ||
		equalOptionalEntityID(task.operatorTeamID, team) && equalOptionalEntityID(task.assigneeID, assignee) {
		return Task{}, ErrInvalidTask
	}
	updated := task.clone()
	updated.operatorTeamID = team
	updated.assigneeID = assignee
	updated.updatedAt = updatedAt
	updated.version++
	return updated, nil
}

// Reschedule replaces or clears the due date while preserving the remaining
// task state. Terminal tasks are immutable and every update is guarded by the
// same optimistic version used by the other task mutations.
func (task Task) Reschedule(expectedVersion uint64, dueAt *time.Time, updatedAt time.Time) (Task, error) {
	if expectedVersion != task.version {
		return Task{}, ErrTaskConflict
	}
	canonical, ok := canonicalOptionalInstant(dueAt)
	if !ok || task.version >= maximumAggregateVersion || terminalTaskStatus(task.status) ||
		!validInstant(updatedAt) || updatedAt.Before(task.updatedAt) ||
		equalInstants(task.dueAt, canonical) {
		return Task{}, ErrInvalidTask
	}
	updated := task.clone()
	updated.dueAt = canonical
	updated.updatedAt = updatedAt
	updated.version++
	return updated, nil
}

func validTaskTransition(from, to TaskStatus) bool {
	switch from {
	case TaskTodo:
		return to == TaskInProgress || to == TaskCancelled
	case TaskInProgress:
		return to == TaskBlocked || to == TaskDone || to == TaskCancelled
	case TaskBlocked:
		return to == TaskInProgress || to == TaskCancelled
	case TaskDone, TaskCancelled:
		return to == TaskInProgress
	default:
		return false
	}
}

func canonicalChecklist(values []ChecklistItem) ([]ChecklistItem, bool) {
	if len(values) > 100 {
		return nil, false
	}
	result := cloneChecklist(values)
	seen := make(map[EntityID]struct{}, len(result))
	for _, item := range result {
		if !validEntityID(item.id) || !validSingleLineText(item.title, 512, false) ||
			item.completed != (item.completedAt != nil) || item.completed != (item.completedBy != nil) ||
			item.completedAt != nil && !validInstant(*item.completedAt) ||
			item.completedBy != nil && !validEntityID(*item.completedBy) {
			return nil, false
		}
		if _, duplicate := seen[item.id]; duplicate {
			return nil, false
		}
		seen[item.id] = struct{}{}
	}
	return result, true
}

func cloneChecklist(values []ChecklistItem) []ChecklistItem {
	result := slices.Clone(values)
	for index := range result {
		result[index].completedAt = cloneInstant(result[index].completedAt)
		result[index].completedBy = cloneEntityID(result[index].completedBy)
	}
	return result
}

func allChecklistCompleted(values []ChecklistItem) bool {
	for _, item := range values {
		if !item.completed {
			return false
		}
	}
	return true
}

func checklistTimesWithin(values []ChecklistItem, createdAt, updatedAt time.Time) bool {
	for _, item := range values {
		if item.completedAt != nil &&
			(item.completedAt.Before(createdAt) || item.completedAt.After(updatedAt)) {
			return false
		}
	}
	return true
}

func equalOptionalEntityID(left, right *EntityID) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func (task Task) clone() Task {
	result := task
	result.assigneeID = cloneEntityID(task.assigneeID)
	result.operatorTeamID = cloneEntityID(task.operatorTeamID)
	result.dueAt = cloneInstant(task.dueAt)
	result.checklist = cloneChecklist(task.checklist)
	result.completedAt = cloneInstant(task.completedAt)
	result.completedBy = cloneEntityID(task.completedBy)
	result.completionData = slices.Clone(task.completionData)
	result.commentIDs = slices.Clone(task.commentIDs)
	result.slaInstanceID = cloneEntityID(task.slaInstanceID)
	return result
}
