package postgres

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/dfir"
)

const caseTaskSnapshotKind = "case_task"

type caseTaskResultEnvelope struct {
	Kind string                  `json:"kind"`
	Task *caseTaskResultSnapshot `json:"task,omitempty"`
}

type caseTaskResultSnapshot struct {
	ID             uuid.UUID                      `json:"id"`
	TenantID       uuid.UUID                      `json:"tenantId"`
	CaseID         uuid.UUID                      `json:"caseId"`
	Title          string                         `json:"title"`
	Description    string                         `json:"description"`
	Status         kernel.TaskStatus              `json:"status"`
	Priority       kernel.TaskPriority            `json:"priority"`
	AssigneeID     *uuid.UUID                     `json:"assigneeId,omitempty"`
	OperatorTeamID *uuid.UUID                     `json:"operatorTeamId,omitempty"`
	DueAt          *time.Time                     `json:"dueAt,omitempty"`
	Checklist      []alertChecklistResultSnapshot `json:"checklist"`
	CompletedAt    *time.Time                     `json:"completedAt,omitempty"`
	CompletedBy    *uuid.UUID                     `json:"completedBy,omitempty"`
	CompletionData json.RawMessage                `json:"completionData,omitempty"`
	CommentIDs     []uuid.UUID                    `json:"commentIds"`
	SLAInstanceID  *uuid.UUID                     `json:"slaInstanceId,omitempty"`
	CreatedAt      time.Time                      `json:"createdAt"`
	UpdatedAt      time.Time                      `json:"updatedAt"`
	Version        uint64                         `json:"version"`
}

func encodeCaseTaskResult(value kernel.Task) ([]byte, error) {
	checklist := make([]alertChecklistResultSnapshot, len(value.Checklist()))
	for index, item := range value.Checklist() {
		checklist[index] = alertChecklistResultSnapshot{
			ID: uuid.UUID(item.ID().Bytes()), Title: item.Title(), Completed: item.Completed(),
			CompletedAt: item.CompletedAt(), CompletedBy: optionalKernelUUIDPointer(item.CompletedBy()),
		}
	}
	snapshot := caseTaskResultSnapshot{
		ID: uuid.UUID(value.ID().Bytes()), TenantID: uuid.UUID(value.TenantID().Bytes()),
		CaseID: uuid.UUID(value.CaseID().Bytes()), Title: value.Title(), Description: value.Description(),
		Status: value.Status(), Priority: value.Priority(), AssigneeID: optionalKernelUUIDPointer(value.AssigneeID()),
		OperatorTeamID: optionalKernelUUIDPointer(value.OperatorTeamID()), DueAt: value.DueAt(), Checklist: checklist,
		CompletedAt: value.CompletedAt(), CompletedBy: optionalKernelUUIDPointer(value.CompletedBy()),
		CompletionData: value.CompletionData(), CommentIDs: kernelUUIDs(value.CommentIDs()),
		SLAInstanceID: optionalKernelUUIDPointer(value.SLAInstanceID()), CreatedAt: value.CreatedAt(),
		UpdatedAt: value.UpdatedAt(), Version: value.Version(),
	}
	return json.Marshal(caseTaskResultEnvelope{Kind: caseTaskSnapshotKind, Task: &snapshot})
}

func decodeCaseTaskResult(document []byte) (kernel.Task, error) {
	var envelope caseTaskResultEnvelope
	if err := decodeAlertInvestigationSnapshot(document, &envelope); err != nil ||
		envelope.Kind != caseTaskSnapshotKind || envelope.Task == nil {
		return kernel.Task{}, unexpectedDFIRProjection("invalid Case task replay snapshot")
	}
	value := envelope.Task
	id, err := parseDFIREntityID(value.ID)
	if err != nil {
		return kernel.Task{}, err
	}
	tenant, err := parseDFIREntityID(value.TenantID)
	if err != nil {
		return kernel.Task{}, err
	}
	caseID, err := parseDFIREntityID(value.CaseID)
	if err != nil {
		return kernel.Task{}, err
	}
	assignee, err := parseOptionalDFIREntityID(value.AssigneeID)
	if err != nil {
		return kernel.Task{}, err
	}
	team, err := parseOptionalDFIREntityID(value.OperatorTeamID)
	if err != nil {
		return kernel.Task{}, err
	}
	completedBy, err := parseOptionalDFIREntityID(value.CompletedBy)
	if err != nil {
		return kernel.Task{}, err
	}
	sla, err := parseOptionalDFIREntityID(value.SLAInstanceID)
	if err != nil {
		return kernel.Task{}, err
	}
	checklist := make([]kernel.ChecklistItem, len(value.Checklist))
	for index, item := range value.Checklist {
		itemID, parseErr := parseDFIREntityID(item.ID)
		if parseErr != nil {
			return kernel.Task{}, parseErr
		}
		itemActor, parseErr := parseOptionalDFIREntityID(item.CompletedBy)
		if parseErr != nil {
			return kernel.Task{}, parseErr
		}
		checklist[index], parseErr = kernel.NewChecklistItem(kernel.ChecklistItemInput{
			ID: itemID, Title: item.Title, Completed: item.Completed,
			CompletedAt: canonicalOptionalAlertDatabaseTime(item.CompletedAt), CompletedBy: itemActor,
		})
		if parseErr != nil {
			return kernel.Task{}, unexpectedDFIRProjection("non-canonical Case checklist replay snapshot")
		}
	}
	comments := make([]kernel.EntityID, len(value.CommentIDs))
	for index, comment := range value.CommentIDs {
		comments[index], err = parseDFIREntityID(comment)
		if err != nil {
			return kernel.Task{}, err
		}
	}
	result, err := kernel.NewTask(kernel.TaskInput{
		ID: id, TenantID: tenant, CaseID: caseID, Title: value.Title, Description: value.Description,
		Status: value.Status, Priority: value.Priority, AssigneeID: assignee, OperatorTeamID: team,
		DueAt: canonicalOptionalAlertDatabaseTime(value.DueAt), Checklist: checklist,
		CompletedAt: canonicalOptionalAlertDatabaseTime(value.CompletedAt), CompletedBy: completedBy,
		CompletionData: canonicalJSONObject(value.CompletionData), CommentIDs: comments, SLAInstanceID: sla,
		CreatedAt: canonicalAlertDatabaseTime(value.CreatedAt), UpdatedAt: canonicalAlertDatabaseTime(value.UpdatedAt),
		Version: value.Version,
	})
	if err != nil {
		return kernel.Task{}, unexpectedDFIRProjection("non-canonical Case task replay snapshot")
	}
	return result, nil
}
