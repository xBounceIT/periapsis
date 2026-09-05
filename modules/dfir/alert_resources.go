package dfir

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

// ErrRelationshipConflict reports a stale relationship revision. Alert
// relationships are immutable except for their single append-only retraction.
var ErrRelationshipConflict = errors.New("relationship version conflict")

// MaximumAlertResourceVersion remains as the Alert-facing name for the shared
// exact JSON resource revision ceiling.
const MaximumAlertResourceVersion = MaximumResourceVersion

// AlertEvidenceInput is the Alert-rooted form of EvidenceInput. The embedded
// evidence state machine remains deliberately shared with Case evidence so
// scan, retention, legal-hold, destruction, and custody rules cannot drift.
type AlertEvidenceInput struct {
	ID                    EntityID
	TenantID              EntityID
	AlertID               EntityID
	StorageObjectID       EntityID
	InitialCustodyEventID EntityID
	Title                 string
	Description           string
	EvidenceType          string
	Classification        EvidenceClassification
	ContentSHA256         string
	SizeBytes             int64
	DetectedMIME          string
	CollectedAt           time.Time
	CollectedBy           EntityID
	InitialCustodyActorID EntityID
	Source                string
	RetentionUntil        *time.Time
	LegalHold             bool
	ScanState             ScanState
}

// AlertEvidenceState is the complete persistence representation. Metadata is
// immutable; every mutable custody property is reconstructed from the
// append-only custody chain before this state is accepted.
type AlertEvidenceState struct {
	ID                    EntityID
	TenantID              EntityID
	AlertID               EntityID
	StorageObjectID       EntityID
	Title                 string
	Description           string
	EvidenceType          string
	Classification        EvidenceClassification
	ContentSHA256         string
	SizeBytes             int64
	DetectedMIME          string
	CollectedAt           time.Time
	CollectedBy           EntityID
	Source                string
	RetentionUntil        *time.Time
	LegalHold             bool
	ScanState             ScanState
	InitialRetentionUntil *time.Time
	InitialLegalHold      bool
	InitialScanState      ScanState
	Sealed                bool
	Destroyed             bool
	Version               uint64
	CustodyEvents         []CustodyEventState
}

// ValidateAlertEvidenceCollectionIntent validates every storage-independent
// field before an idempotency receipt lookup. Content hash, size, detected
// MIME, classification agreement, and initial scan state remain bound to the
// locked storage object when the fresh command is committed.
func ValidateAlertEvidenceCollectionIntent(input AlertEvidenceInput) error {
	if !validEntityID(input.ID) || !validEntityID(input.TenantID) || !validEntityID(input.AlertID) ||
		!validEntityID(input.StorageObjectID) || !validEntityID(input.InitialCustodyEventID) ||
		!validAlertResourceSingleLineText(input.Title, 512, false) ||
		!validOptionalText(input.Description, 16*1024) || !validStableKey(input.EvidenceType) ||
		!validEvidenceClassification(input.Classification) ||
		!validAlertResourceInstant(input.CollectedAt) || !validEntityID(input.CollectedBy) ||
		!validEntityID(input.InitialCustodyActorID) ||
		!validAlertResourceSingleLineText(input.Source, 512, false) ||
		!validOptionalAlertResourceInstant(input.RetentionUntil) ||
		input.RetentionUntil != nil && input.RetentionUntil.Before(input.CollectedAt) {
		return ErrInvalidEvidence
	}
	return nil
}

func (state AlertEvidenceState) String() string {
	return fmt.Sprintf(
		"dfir.AlertEvidenceState{classification:%s,scanState:%s,version:%d,custody:%d,metadata:[REDACTED],hash:[REDACTED]}",
		state.Classification, state.ScanState, state.Version, len(state.CustodyEvents),
	)
}

func (state AlertEvidenceState) GoString() string { return state.String() }

// AlertEvidence is an immutable Alert-rooted facade over the common evidence
// state machine. Internally the Alert identifier occupies the state machine's
// root slot, so it is included in the custody anchor hash; callers can only
// persist and restore it through the Alert-specific representation above.
type AlertEvidence struct {
	alertID  EntityID
	evidence Evidence
}

func NewAlertEvidence(input AlertEvidenceInput) (AlertEvidence, error) {
	if err := ValidateAlertEvidenceCollectionIntent(input); err != nil {
		return AlertEvidence{}, ErrInvalidEvidence
	}
	evidence, err := newEvidence(EvidenceInput{
		ID: input.ID, TenantID: input.TenantID, CaseID: input.AlertID,
		StorageObjectID: input.StorageObjectID, InitialCustodyEventID: input.InitialCustodyEventID,
		Title: input.Title, Description: input.Description, EvidenceType: input.EvidenceType,
		Classification: input.Classification, ContentSHA256: input.ContentSHA256,
		SizeBytes: input.SizeBytes, DetectedMIME: input.DetectedMIME,
		CollectedAt: input.CollectedAt, CollectedBy: input.CollectedBy, Source: input.Source,
		RetentionUntil: input.RetentionUntil, LegalHold: input.LegalHold, ScanState: input.ScanState,
	}, evidenceAlertRoot)
	if err != nil {
		return AlertEvidence{}, err
	}
	evidence.custody[0] = evidence.newCustodyEvent(
		input.InitialCustodyEventID,
		input.InitialCustodyActorID,
		CustodyCollected,
		"initial collection",
		"",
		input.CollectedAt,
		1,
		evidence.anchorHash(),
	)
	return AlertEvidence{alertID: input.AlertID, evidence: evidence}, nil
}

func RestoreAlertEvidence(state AlertEvidenceState) (AlertEvidence, error) {
	if !validAlertResourceSingleLineText(state.Title, 512, false) ||
		!validAlertResourceSingleLineText(state.Source, 512, false) ||
		!validAlertResourceInstant(state.CollectedAt) ||
		!validOptionalAlertResourceInstant(state.RetentionUntil) ||
		!validOptionalAlertResourceInstant(state.InitialRetentionUntil) ||
		state.Version == 0 || state.Version > MaximumAlertResourceVersion {
		return AlertEvidence{}, ErrInvalidEvidence
	}
	for _, event := range state.CustodyEvents {
		if !validAlertResourceSingleLineText(event.Reason, 2_000, false) ||
			!validAlertResourceInstant(event.OccurredAt) {
			return AlertEvidence{}, ErrInvalidEvidence
		}
	}
	evidence, err := restoreEvidence(EvidenceState{
		ID: state.ID, TenantID: state.TenantID, CaseID: state.AlertID,
		StorageObjectID: state.StorageObjectID, Title: state.Title, Description: state.Description,
		EvidenceType: state.EvidenceType, Classification: state.Classification,
		ContentSHA256: state.ContentSHA256, SizeBytes: state.SizeBytes, DetectedMIME: state.DetectedMIME,
		CollectedAt: state.CollectedAt, CollectedBy: state.CollectedBy, Source: state.Source,
		RetentionUntil: state.RetentionUntil, LegalHold: state.LegalHold, ScanState: state.ScanState,
		InitialRetentionUntil: state.InitialRetentionUntil, InitialLegalHold: state.InitialLegalHold,
		InitialScanState: state.InitialScanState, Sealed: state.Sealed, Destroyed: state.Destroyed,
		Version: state.Version, CustodyEvents: slices.Clone(state.CustodyEvents),
	}, evidenceAlertRoot)
	if err != nil {
		return AlertEvidence{}, err
	}
	return AlertEvidence{alertID: state.AlertID, evidence: evidence}, nil
}

func (evidence AlertEvidence) ID() EntityID              { return evidence.evidence.ID() }
func (evidence AlertEvidence) TenantID() EntityID        { return evidence.evidence.TenantID() }
func (evidence AlertEvidence) AlertID() EntityID         { return evidence.alertID }
func (evidence AlertEvidence) StorageObjectID() EntityID { return evidence.evidence.StorageObjectID() }
func (evidence AlertEvidence) Title() string             { return evidence.evidence.Title() }
func (evidence AlertEvidence) Description() string       { return evidence.evidence.Description() }
func (evidence AlertEvidence) EvidenceType() string      { return evidence.evidence.EvidenceType() }
func (evidence AlertEvidence) Classification() EvidenceClassification {
	return evidence.evidence.Classification()
}
func (evidence AlertEvidence) ContentSHA256() string      { return evidence.evidence.ContentSHA256() }
func (evidence AlertEvidence) SizeBytes() int64           { return evidence.evidence.SizeBytes() }
func (evidence AlertEvidence) DetectedMIME() string       { return evidence.evidence.DetectedMIME() }
func (evidence AlertEvidence) CollectedAt() time.Time     { return evidence.evidence.CollectedAt() }
func (evidence AlertEvidence) CollectedBy() EntityID      { return evidence.evidence.CollectedBy() }
func (evidence AlertEvidence) Source() string             { return evidence.evidence.Source() }
func (evidence AlertEvidence) RetentionUntil() *time.Time { return evidence.evidence.RetentionUntil() }
func (evidence AlertEvidence) LegalHold() bool            { return evidence.evidence.LegalHold() }
func (evidence AlertEvidence) ScanState() ScanState       { return evidence.evidence.ScanState() }
func (evidence AlertEvidence) Sealed() bool               { return evidence.evidence.Sealed() }
func (evidence AlertEvidence) Destroyed() bool            { return evidence.evidence.Destroyed() }
func (evidence AlertEvidence) Version() uint64            { return evidence.evidence.Version() }
func (evidence AlertEvidence) CustodyEvents() []CustodyEvent {
	return evidence.evidence.CustodyEvents()
}
func (evidence AlertEvidence) CanIssueDownload() bool {
	return validEntityID(evidence.alertID) && evidence.evidence.CaseID() == evidence.alertID &&
		evidence.evidence.canIssueDownload(evidenceAlertRoot)
}
func (evidence AlertEvidence) VerifyCustodyChain() bool {
	return validEntityID(evidence.alertID) && evidence.evidence.CaseID() == evidence.alertID &&
		evidence.evidence.verifyCustodyChain(evidenceAlertRoot)
}

func (evidence AlertEvidence) Snapshot() AlertEvidenceState {
	state := evidence.evidence.Snapshot()
	return AlertEvidenceState{
		ID: state.ID, TenantID: state.TenantID, AlertID: evidence.alertID,
		StorageObjectID: state.StorageObjectID, Title: state.Title, Description: state.Description,
		EvidenceType: state.EvidenceType, Classification: state.Classification,
		ContentSHA256: state.ContentSHA256, SizeBytes: state.SizeBytes, DetectedMIME: state.DetectedMIME,
		CollectedAt: state.CollectedAt, CollectedBy: state.CollectedBy, Source: state.Source,
		RetentionUntil: state.RetentionUntil, LegalHold: state.LegalHold, ScanState: state.ScanState,
		InitialRetentionUntil: state.InitialRetentionUntil, InitialLegalHold: state.InitialLegalHold,
		InitialScanState: state.InitialScanState, Sealed: state.Sealed, Destroyed: state.Destroyed,
		Version: state.Version, CustodyEvents: slices.Clone(state.CustodyEvents),
	}
}

func (evidence AlertEvidence) AppendCustodyEvent(expectedVersion uint64, input CustodyEventInput) (AlertEvidence, error) {
	updated, err := evidence.evidence.AppendCustodyEvent(expectedVersion, input)
	if err == nil && (!validAlertResourceSingleLineText(input.Reason, 2_000, false) ||
		!validAlertResourceInstant(input.OccurredAt)) {
		err = ErrInvalidEvidence
	}
	return evidence.withUpdatedEvidence(updated, err)
}

func (evidence AlertEvidence) ChangeScanState(expectedVersion uint64, input CustodyEventInput, next ScanState) (AlertEvidence, error) {
	updated, err := evidence.evidence.ChangeScanState(expectedVersion, input, next)
	if err == nil && (!validAlertResourceSingleLineText(input.Reason, 2_000, false) ||
		!validAlertResourceInstant(input.OccurredAt)) {
		err = ErrInvalidEvidence
	}
	return evidence.withUpdatedEvidence(updated, err)
}

func (evidence AlertEvidence) ChangeLegalHold(expectedVersion uint64, input CustodyEventInput, enabled bool) (AlertEvidence, error) {
	updated, err := evidence.evidence.ChangeLegalHold(expectedVersion, input, enabled)
	if err == nil && (!validAlertResourceSingleLineText(input.Reason, 2_000, false) ||
		!validAlertResourceInstant(input.OccurredAt)) {
		err = ErrInvalidEvidence
	}
	return evidence.withUpdatedEvidence(updated, err)
}

func (evidence AlertEvidence) ChangeRetention(expectedVersion uint64, input CustodyEventInput, until *time.Time) (AlertEvidence, error) {
	updated, err := evidence.evidence.ChangeRetention(expectedVersion, input, until)
	if err == nil && (!validAlertResourceSingleLineText(input.Reason, 2_000, false) ||
		!validAlertResourceInstant(input.OccurredAt) ||
		!validOptionalAlertResourceInstant(until)) {
		err = ErrInvalidEvidence
	}
	return evidence.withUpdatedEvidence(updated, err)
}

func (evidence AlertEvidence) Destroy(expectedVersion uint64, input CustodyEventInput) (AlertEvidence, error) {
	updated, err := evidence.evidence.Destroy(expectedVersion, input)
	if err == nil && (!validAlertResourceSingleLineText(input.Reason, 2_000, false) ||
		!validAlertResourceInstant(input.OccurredAt)) {
		err = ErrInvalidEvidence
	}
	return evidence.withUpdatedEvidence(updated, err)
}

func (evidence AlertEvidence) withUpdatedEvidence(updated Evidence, err error) (AlertEvidence, error) {
	if err != nil {
		return AlertEvidence{}, err
	}
	if updated.Version() > MaximumAlertResourceVersion {
		return AlertEvidence{}, ErrInvalidEvidence
	}
	result := AlertEvidence{alertID: evidence.alertID, evidence: updated}
	if !result.VerifyCustodyChain() {
		return AlertEvidence{}, ErrInvalidEvidence
	}
	return result, nil
}

func (evidence AlertEvidence) String() string {
	return fmt.Sprintf(
		"dfir.AlertEvidence{classification:%s,scanState:%s,sizeBytes:%d,version:%d,custody:%d,metadata:[REDACTED],contentHash:[REDACTED]}",
		evidence.Classification(), evidence.ScanState(), evidence.SizeBytes(), evidence.Version(),
		len(evidence.CustodyEvents()),
	)
}

func (evidence AlertEvidence) GoString() string { return evidence.String() }

type AlertTaskState struct {
	ID             EntityID
	TenantID       EntityID
	AlertID        EntityID
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

func (state AlertTaskState) String() string {
	return fmt.Sprintf(
		"dfir.AlertTaskState{status:%s,priority:%s,version:%d,assigned:%t,team:%t,checklist:%d,comments:%d,sla:%t,content:[REDACTED],identifiers:[REDACTED]}",
		state.Status, state.Priority, state.Version, state.AssigneeID != nil, state.OperatorTeamID != nil,
		len(state.Checklist), len(state.CommentIDs), state.SLAInstanceID != nil,
	)
}

func (state AlertTaskState) GoString() string { return state.String() }

// AlertTask keeps the existing task lifecycle invariant while binding every
// revision to one autonomous Alert rather than one Case.
type AlertTask struct {
	alertID EntityID
	task    Task
}

func NewAlertTask(state AlertTaskState) (AlertTask, error) {
	if !utf8.Valid(state.CompletionData) ||
		!validAlertResourceSingleLineText(state.Title, 512, false) ||
		!validAlertChecklistText(state.Checklist) || !validAlertTaskStateTimes(state) ||
		state.Version == 0 || state.Version > MaximumAlertResourceVersion {
		return AlertTask{}, ErrInvalidTask
	}
	task, err := NewTask(TaskInput{
		ID: state.ID, TenantID: state.TenantID, CaseID: state.AlertID,
		Title: state.Title, Description: state.Description, Status: state.Status,
		Priority: state.Priority, AssigneeID: state.AssigneeID, OperatorTeamID: state.OperatorTeamID,
		DueAt: state.DueAt, Checklist: state.Checklist, CompletedAt: state.CompletedAt,
		CompletedBy: state.CompletedBy, CompletionData: state.CompletionData,
		CommentIDs: state.CommentIDs, SLAInstanceID: state.SLAInstanceID,
		CreatedAt: state.CreatedAt, UpdatedAt: state.UpdatedAt, Version: state.Version,
	})
	if err != nil {
		return AlertTask{}, err
	}
	return AlertTask{alertID: state.AlertID, task: task}, nil
}

func (task AlertTask) ID() EntityID                    { return task.task.ID() }
func (task AlertTask) TenantID() EntityID              { return task.task.TenantID() }
func (task AlertTask) AlertID() EntityID               { return task.alertID }
func (task AlertTask) Title() string                   { return task.task.Title() }
func (task AlertTask) Description() string             { return task.task.Description() }
func (task AlertTask) Status() TaskStatus              { return task.task.Status() }
func (task AlertTask) Priority() TaskPriority          { return task.task.Priority() }
func (task AlertTask) AssigneeID() *EntityID           { return task.task.AssigneeID() }
func (task AlertTask) OperatorTeamID() *EntityID       { return task.task.OperatorTeamID() }
func (task AlertTask) DueAt() *time.Time               { return task.task.DueAt() }
func (task AlertTask) Checklist() []ChecklistItem      { return task.task.Checklist() }
func (task AlertTask) CompletedAt() *time.Time         { return task.task.CompletedAt() }
func (task AlertTask) CompletedBy() *EntityID          { return task.task.CompletedBy() }
func (task AlertTask) CompletionData() json.RawMessage { return task.task.CompletionData() }
func (task AlertTask) CommentIDs() []EntityID          { return task.task.CommentIDs() }
func (task AlertTask) SLAInstanceID() *EntityID        { return task.task.SLAInstanceID() }
func (task AlertTask) CreatedAt() time.Time            { return task.task.CreatedAt() }
func (task AlertTask) UpdatedAt() time.Time            { return task.task.UpdatedAt() }
func (task AlertTask) Version() uint64                 { return task.task.Version() }

func (task AlertTask) Snapshot() AlertTaskState {
	return AlertTaskState{
		ID: task.ID(), TenantID: task.TenantID(), AlertID: task.alertID,
		Title: task.Title(), Description: task.Description(), Status: task.Status(), Priority: task.Priority(),
		AssigneeID: task.AssigneeID(), OperatorTeamID: task.OperatorTeamID(), DueAt: task.DueAt(),
		Checklist: task.Checklist(), CompletedAt: task.CompletedAt(), CompletedBy: task.CompletedBy(),
		CompletionData: task.CompletionData(), CommentIDs: task.CommentIDs(), SLAInstanceID: task.SLAInstanceID(),
		CreatedAt: task.CreatedAt(), UpdatedAt: task.UpdatedAt(), Version: task.Version(),
	}
}

// ValidateAlertTaskTransitionIntent validates the state-independent portion of
// a transition before an idempotency receipt can be replayed. The aggregate
// still validates the transition against its current state inside the commit.
func ValidateAlertTaskTransitionIntent(
	target TaskStatus,
	reason string,
	completionData json.RawMessage,
) error {
	if ValidateTaskTransitionIntent(target, reason, completionData) != nil ||
		!validAlertResourceSingleLineText(reason, 2_000, false) || !utf8.Valid(completionData) {
		return ErrInvalidTask
	}
	return nil
}

func (task AlertTask) Transition(input TaskTransitionInput) (AlertTask, error) {
	updated, err := task.task.Transition(input)
	if err == nil && !validAlertResourceInstant(input.OccurredAt) {
		err = ErrInvalidTask
	}
	return task.withUpdatedTask(updated, err)
}

// ReplaceDetails replaces the caller-owned task details while preserving the
// Alert binding and the same CAS and terminal-state rules as a Case task.
func (task AlertTask) ReplaceDetails(
	expectedVersion uint64,
	title string,
	description string,
	priority TaskPriority,
	slaInstanceID *EntityID,
	updatedAt time.Time,
) (AlertTask, error) {
	updated, err := task.task.ReplaceDetails(
		expectedVersion, title, description, priority, slaInstanceID, updatedAt,
	)
	if err == nil && !validAlertResourceInstant(updatedAt) {
		err = ErrInvalidTask
	}
	return task.withUpdatedTask(updated, err)
}

func (task AlertTask) Assign(expectedVersion uint64, teamID, assigneeID *EntityID, updatedAt time.Time) (AlertTask, error) {
	updated, err := task.task.Assign(expectedVersion, teamID, assigneeID, updatedAt)
	if err == nil && !validAlertResourceInstant(updatedAt) {
		err = ErrInvalidTask
	}
	return task.withUpdatedTask(updated, err)
}

func (task AlertTask) ReplaceChecklist(expectedVersion uint64, items []ChecklistItem, updatedAt time.Time) (AlertTask, error) {
	updated, err := task.task.ReplaceChecklist(expectedVersion, items, updatedAt)
	if err == nil && (!validAlertResourceInstant(updatedAt) || !validAlertChecklistText(items) ||
		!validAlertChecklistTimes(items)) {
		err = ErrInvalidTask
	}
	return task.withUpdatedTask(updated, err)
}

// ReplaceComments replaces the complete comment association while preserving
// the Alert binding and the shared task CAS and terminal-state invariants.
func (task AlertTask) ReplaceComments(
	expectedVersion uint64,
	commentIDs []EntityID,
	updatedAt time.Time,
) (AlertTask, error) {
	updated, err := task.task.ReplaceComments(expectedVersion, commentIDs, updatedAt)
	if err == nil && !validAlertResourceInstant(updatedAt) {
		err = ErrInvalidTask
	}
	return task.withUpdatedTask(updated, err)
}

// Reschedule replaces the due date using the same CAS and terminal-state rules
// as the other task mutations. A nil due date explicitly clears the deadline.
func (task AlertTask) Reschedule(expectedVersion uint64, dueAt *time.Time, updatedAt time.Time) (AlertTask, error) {
	updated, err := task.task.Reschedule(expectedVersion, dueAt, updatedAt)
	if err == nil && (!validOptionalAlertResourceInstant(updated.DueAt()) ||
		!validAlertResourceInstant(updatedAt)) {
		err = ErrInvalidTask
	}
	return task.withUpdatedTask(updated, err)
}

func (task AlertTask) withUpdatedTask(updated Task, err error) (AlertTask, error) {
	if err != nil {
		return AlertTask{}, err
	}
	if updated.CaseID() != task.alertID || updated.Version() > MaximumAlertResourceVersion {
		return AlertTask{}, ErrInvalidTask
	}
	return AlertTask{alertID: task.alertID, task: updated}, nil
}

func (task AlertTask) String() string {
	return fmt.Sprintf(
		"dfir.AlertTask{status:%s,priority:%s,version:%d,assigned:%t,team:%t,checklist:%d,content:[REDACTED]}",
		task.Status(), task.Priority(), task.Version(), task.AssigneeID() != nil,
		task.OperatorTeamID() != nil, len(task.Checklist()),
	)
}

func (task AlertTask) GoString() string { return task.String() }

type AlertRelationshipRetractionInput struct {
	ID         EntityID
	ActorID    EntityID
	Reason     string
	OccurredAt time.Time
}

type AlertRelationshipRetractionState struct {
	ID             EntityID
	TenantID       EntityID
	RelationshipID EntityID
	Sequence       uint64
	ActorID        EntityID
	Reason         string
	OccurredAt     time.Time
}

func (state AlertRelationshipRetractionState) String() string {
	return fmt.Sprintf(
		"dfir.AlertRelationshipRetractionState{sequence:%d,reason:[REDACTED],identifiers:[REDACTED]}",
		state.Sequence,
	)
}

func (state AlertRelationshipRetractionState) GoString() string { return state.String() }

type AlertRelationshipState struct {
	ID               EntityID
	TenantID         EntityID
	AlertID          EntityID
	Source           EntityReference
	Target           EntityReference
	RelationshipType string
	Metadata         json.RawMessage
	CreatedBy        EntityID
	CreatedAt        time.Time
	Version          uint64
	Retractions      []AlertRelationshipRetractionState
}

func (state AlertRelationshipState) String() string {
	return fmt.Sprintf(
		"dfir.AlertRelationshipState{type:%s,source:%s,target:%s,version:%d,active:%t,retractions:%d,metadata:%t,identifiers:[REDACTED]}",
		state.RelationshipType, state.Source.Kind(), state.Target.Kind(), state.Version,
		len(state.Retractions) == 0, len(state.Retractions), len(state.Metadata) > 0,
	)
}

func (state AlertRelationshipState) GoString() string { return state.String() }

// AlertRelationship is immutable after creation. Retraction appends a single
// terminal history row; it never deletes, rewrites, reverses, or merges the
// original relationship.
type AlertRelationship struct {
	alertID      EntityID
	relationship Relationship
	version      uint64
	retractions  []AlertRelationshipRetractionState
}

// The owning Alert is an independent workspace coordinate, not an endpoint.
// Repositories authorize both endpoints against that persisted root context.
func NewAlertRelationship(input AlertRelationshipState) (AlertRelationship, error) {
	if !utf8.Valid(input.Metadata) || !validAlertResourceInstant(input.CreatedAt) {
		return AlertRelationship{}, ErrInvalidRelationship
	}
	for _, retraction := range input.Retractions {
		if !validAlertResourceInstant(retraction.OccurredAt) {
			return AlertRelationship{}, ErrInvalidRelationship
		}
	}
	relationship, err := NewRelationship(RelationshipInput{
		ID: input.ID, TenantID: input.TenantID, Source: input.Source, Target: input.Target,
		RelationshipType: input.RelationshipType, Metadata: input.Metadata,
		CreatedBy: input.CreatedBy, CreatedAt: input.CreatedAt,
	})
	if err != nil || !validAlertReferenceText(input.Source) || !validAlertReferenceText(input.Target) ||
		!validEntityID(input.AlertID) ||
		conflictsWithDedicatedAlertRelation(relationship) ||
		input.Version == 0 || input.Version > MaximumAlertResourceVersion || len(input.Retractions) > 1 ||
		input.Version != uint64(1+len(input.Retractions)) {
		return AlertRelationship{}, ErrInvalidRelationship
	}
	retractions := slices.Clone(input.Retractions)
	for index, retraction := range retractions {
		if !validEntityID(retraction.ID) || retraction.TenantID != input.TenantID ||
			retraction.RelationshipID != input.ID || retraction.Sequence != uint64(index+1) ||
			!validEntityID(retraction.ActorID) ||
			!validAlertResourceSingleLineText(retraction.Reason, 2_000, false) ||
			!validInstant(retraction.OccurredAt) || retraction.OccurredAt.Before(input.CreatedAt) {
			return AlertRelationship{}, ErrInvalidRelationship
		}
	}
	return AlertRelationship{
		alertID: input.AlertID, relationship: relationship,
		version: input.Version, retractions: retractions,
	}, nil
}

func (relationship AlertRelationship) ID() EntityID { return relationship.relationship.ID() }
func (relationship AlertRelationship) TenantID() EntityID {
	return relationship.relationship.TenantID()
}
func (relationship AlertRelationship) AlertID() EntityID { return relationship.alertID }
func (relationship AlertRelationship) Source() EntityReference {
	return relationship.relationship.Source()
}
func (relationship AlertRelationship) Target() EntityReference {
	return relationship.relationship.Target()
}
func (relationship AlertRelationship) RelationshipType() string {
	return relationship.relationship.RelationshipType()
}
func (relationship AlertRelationship) Metadata() json.RawMessage {
	return relationship.relationship.Metadata()
}
func (relationship AlertRelationship) CreatedBy() EntityID {
	return relationship.relationship.CreatedBy()
}
func (relationship AlertRelationship) CreatedAt() time.Time {
	return relationship.relationship.CreatedAt()
}
func (relationship AlertRelationship) Version() uint64 { return relationship.version }
func (relationship AlertRelationship) Active() bool    { return len(relationship.retractions) == 0 }
func (relationship AlertRelationship) Retractions() []AlertRelationshipRetractionState {
	return slices.Clone(relationship.retractions)
}

func (relationship AlertRelationship) Snapshot() AlertRelationshipState {
	return AlertRelationshipState{
		ID: relationship.ID(), TenantID: relationship.TenantID(), AlertID: relationship.alertID,
		Source: relationship.Source(), Target: relationship.Target(),
		RelationshipType: relationship.RelationshipType(), Metadata: relationship.Metadata(),
		CreatedBy: relationship.CreatedBy(), CreatedAt: relationship.CreatedAt(),
		Version: relationship.version, Retractions: relationship.Retractions(),
	}
}

func (relationship AlertRelationship) Retract(expectedVersion uint64, input AlertRelationshipRetractionInput) (AlertRelationship, error) {
	if expectedVersion != relationship.version {
		return AlertRelationship{}, ErrRelationshipConflict
	}
	if !relationship.Active() || relationship.version >= MaximumAlertResourceVersion ||
		!validEntityID(input.ID) || !validEntityID(input.ActorID) ||
		!validAlertResourceSingleLineText(input.Reason, 2_000, false) ||
		!validAlertResourceInstant(input.OccurredAt) ||
		input.OccurredAt.Before(relationship.CreatedAt()) {
		return AlertRelationship{}, ErrInvalidRelationship
	}
	updated := relationship
	updated.version++
	updated.retractions = append(slices.Clone(relationship.retractions), AlertRelationshipRetractionState{
		ID: input.ID, TenantID: relationship.TenantID(), RelationshipID: relationship.ID(),
		Sequence: uint64(len(relationship.retractions) + 1), ActorID: input.ActorID,
		Reason: input.Reason, OccurredAt: input.OccurredAt,
	})
	return updated, nil
}

func (relationship AlertRelationship) String() string {
	return fmt.Sprintf(
		"dfir.AlertRelationship{type:%s,source:%s,target:%s,version:%d,active:%t,metadata:%t,identifiers:[REDACTED]}",
		relationship.RelationshipType(), relationship.Source().Kind(), relationship.Target().Kind(),
		relationship.Version(), relationship.Active(), len(relationship.Metadata()) > 0,
	)
}

func (relationship AlertRelationship) GoString() string { return relationship.String() }

// duplicate_of and correlation between two Alerts belong exclusively to the
// dedicated, dual-CAS Alert relation aggregate. Accepting them here would
// create a second source of truth that does not advance both Alert revisions.
func conflictsWithDedicatedAlertRelation(relationship Relationship) bool {
	if relationship.Source().Kind() != EntityAlert || relationship.Target().Kind() != EntityAlert {
		return false
	}
	return relationship.RelationshipType() == "duplicate_of" ||
		relationship.RelationshipType() == "correlation"
}

// Alert resources cross JSON, PostgreSQL, and tamper-evident boundaries. The
// shared aggregates already require canonical UTC microseconds; the Alert
// facade additionally rejects years that RFC 3339 JSON cannot represent. This
// keeps projections serializable and prevents UnixMicro wraparound aliases in
// custody hashes.
func validAlertResourceInstant(value time.Time) bool {
	if !validInstant(value) {
		return false
	}
	_, err := value.MarshalJSON()
	return err == nil
}

func validOptionalAlertResourceInstant(value *time.Time) bool {
	return value == nil || validAlertResourceInstant(*value)
}

func validAlertResourceSingleLineText(value string, maximum int, optional bool) bool {
	return validSingleLineText(value, maximum, optional) && !strings.ContainsAny(value, "\u2028\u2029")
}

func validAlertReferenceText(reference EntityReference) bool {
	return reference.Kind() != EntityExternal ||
		validAlertResourceSingleLineText(reference.ExternalID(), 2_048, false)
}

func validAlertChecklistText(items []ChecklistItem) bool {
	for _, item := range items {
		if !validAlertResourceSingleLineText(item.Title(), 512, false) {
			return false
		}
	}
	return true
}

func validAlertChecklistTimes(items []ChecklistItem) bool {
	for _, item := range items {
		if !validOptionalAlertResourceInstant(item.CompletedAt()) {
			return false
		}
	}
	return true
}

func validAlertTaskStateTimes(state AlertTaskState) bool {
	return validAlertResourceInstant(state.CreatedAt) && validAlertResourceInstant(state.UpdatedAt) &&
		validOptionalAlertResourceInstant(state.DueAt) &&
		validOptionalAlertResourceInstant(state.CompletedAt) && validAlertChecklistTimes(state.Checklist)
}
