package dfir

import (
	"encoding/json"
	"time"

	kernel "github.com/periapsis-im/periapsis/modules/dfir"
)

// AlertInvestigationWorkspace is the bounded operator-only projection for the
// Alert resources that were previously Case-only.
type AlertInvestigationWorkspace struct {
	Evidence      []kernel.AlertEvidence
	Tasks         []kernel.AlertTask
	Relationships []kernel.AlertRelationship
}

type AlertEvidenceCollectCommand struct {
	AlertID               kernel.EntityID
	EvidenceID            kernel.EntityID
	StorageObjectID       kernel.EntityID
	InitialCustodyEventID kernel.EntityID
	Title                 string
	Description           string
	EvidenceType          string
	Classification        kernel.EvidenceClassification
	CollectedAt           time.Time
	Source                string
	RetentionUntil        *time.Time
	LegalHold             bool
	Envelope              MutationEnvelope
}

type AlertCustodyCommand struct {
	AlertID         kernel.EntityID
	EvidenceID      kernel.EntityID
	ExpectedVersion uint64
	EventID         kernel.EntityID
	Action          kernel.CustodyAction
	Reason          string
	NextScanState   kernel.ScanState
	LegalHold       *bool
	RetentionSet    bool
	RetentionUntil  *time.Time
	Envelope        MutationEnvelope
}

type AlertTaskDraft struct {
	ID             kernel.EntityID
	Title          string
	Description    string
	Priority       kernel.TaskPriority
	AssigneeID     *kernel.EntityID
	OperatorTeamID *kernel.EntityID
	DueAt          *time.Time
	Checklist      []AlertChecklistItemIntent
	SLAInstanceID  *kernel.EntityID
}

// AlertChecklistItemIntent shares the Case task intent shape so checklist
// limits and server-owned provenance cannot drift between the two roots.
type AlertChecklistItemIntent = TaskChecklistItemIntent

type AlertTaskCreateCommand struct {
	AlertID  kernel.EntityID
	Input    AlertTaskDraft
	Envelope MutationEnvelope
}

type AlertTaskTransitionCommand struct {
	AlertID         kernel.EntityID
	TaskID          kernel.EntityID
	ExpectedVersion uint64
	Target          kernel.TaskStatus
	Reason          string
	CompletionData  json.RawMessage
	Envelope        MutationEnvelope
}

type AlertTaskDetailsCommand struct {
	AlertID         kernel.EntityID
	TaskID          kernel.EntityID
	ExpectedVersion uint64
	Title           string
	Description     string
	Priority        kernel.TaskPriority
	SLAInstanceID   *kernel.EntityID
	Envelope        MutationEnvelope
}

type AlertTaskAssignmentCommand struct {
	AlertID         kernel.EntityID
	TaskID          kernel.EntityID
	ExpectedVersion uint64
	OperatorTeamID  *kernel.EntityID
	AssigneeID      *kernel.EntityID
	Envelope        MutationEnvelope
}

type AlertTaskDueDateCommand struct {
	AlertID         kernel.EntityID
	TaskID          kernel.EntityID
	ExpectedVersion uint64
	DueAt           *time.Time
	Envelope        MutationEnvelope
}

type AlertTaskChecklistCommand struct {
	AlertID         kernel.EntityID
	TaskID          kernel.EntityID
	ExpectedVersion uint64
	Checklist       []AlertChecklistItemIntent
	Envelope        MutationEnvelope
}

type AlertTaskCommentsCommand struct {
	AlertID         kernel.EntityID
	TaskID          kernel.EntityID
	ExpectedVersion uint64
	CommentIDs      []kernel.EntityID
	Envelope        MutationEnvelope
}

type AlertRelationshipDraft struct {
	ID               kernel.EntityID
	Source           kernel.EntityReference
	Target           kernel.EntityReference
	RelationshipType string
	Metadata         json.RawMessage
}

type AlertRelationshipCreateCommand struct {
	AlertID  kernel.EntityID
	Input    AlertRelationshipDraft
	Envelope MutationEnvelope
}

type AlertRelationshipRetractCommand struct {
	AlertID         kernel.EntityID
	RelationshipID  kernel.EntityID
	ExpectedVersion uint64
	RetractionID    kernel.EntityID
	Reason          string
	Envelope        MutationEnvelope
}
