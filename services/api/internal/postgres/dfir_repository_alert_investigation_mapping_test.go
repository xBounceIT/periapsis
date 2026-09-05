package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	kernel "github.com/periapsis-im/periapsis/modules/dfir"
)

func TestAlertInvestigationResultSnapshotsRoundTripCompleteState(t *testing.T) {
	t.Parallel()

	tenantID := alertTestEntityID(1)
	alertID := alertTestEntityID(2)
	completedAt := alertTestTime(4)
	completedBy := alertTestEntityID(3)
	dueAt := alertTestTime(5)
	retention := alertTestTime(40)

	evidence, err := kernel.NewAlertEvidence(kernel.AlertEvidenceInput{
		ID: alertTestEntityID(10), TenantID: tenantID, AlertID: alertID,
		StorageObjectID: alertTestEntityID(11), InitialCustodyEventID: alertTestEntityID(12),
		Title: "Memory image", Description: "forensic detail", EvidenceType: "memory_image",
		Classification: kernel.EvidenceInternal,
		ContentSHA256:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		SizeBytes:      4096, DetectedMIME: "application/octet-stream",
		CollectedAt: alertTestTime(1), CollectedBy: alertTestEntityID(13),
		InitialCustodyActorID: alertTestEntityID(15), Source: "endpoint_sensor",
		RetentionUntil: &retention, LegalHold: true, ScanState: kernel.ScanAvailable,
	})
	if err != nil {
		t.Fatal(err)
	}
	evidence, err = evidence.AppendCustodyEvent(1, kernel.CustodyEventInput{
		ID: alertTestEntityID(14), Action: kernel.CustodySealed, ActorID: alertTestEntityID(13),
		Reason: "preserve", OccurredAt: alertTestTime(2),
	})
	if err != nil {
		t.Fatal(err)
	}

	checklist, err := kernel.NewChecklistItem(kernel.ChecklistItemInput{
		ID: alertTestEntityID(20), Title: "Acquire RAM", Completed: true,
		CompletedAt: &completedAt, CompletedBy: &completedBy,
	})
	if err != nil {
		t.Fatal(err)
	}
	task, err := kernel.NewAlertTask(kernel.AlertTaskState{
		ID: alertTestEntityID(21), TenantID: tenantID, AlertID: alertID,
		Title: "Triage endpoint", Description: "private detail", Status: kernel.TaskDone,
		Priority: kernel.TaskPriorityUrgent, AssigneeID: &completedBy,
		OperatorTeamID: &completedBy, DueAt: &dueAt, Checklist: []kernel.ChecklistItem{checklist},
		CompletedAt: &completedAt, CompletedBy: &completedBy,
		CompletionData: json.RawMessage(`{"outcome":"contained"}`),
		CommentIDs:     []kernel.EntityID{alertTestEntityID(22)}, SLAInstanceID: ptrEntityID(alertTestEntityID(23)),
		CreatedAt: alertTestTime(1), UpdatedAt: alertTestTime(4), Version: 2,
	})
	if err != nil {
		t.Fatal(err)
	}

	alertReference, err := kernel.NewEntityReference(tenantID, kernel.EntityAlert, alertID)
	if err != nil {
		t.Fatal(err)
	}
	externalReference, err := kernel.NewExternalEntityReference(tenantID, "ipv4", "203.0.113.8")
	if err != nil {
		t.Fatal(err)
	}
	relationship, err := kernel.NewAlertRelationship(kernel.AlertRelationshipState{
		ID: alertTestEntityID(30), TenantID: tenantID, AlertID: alertID,
		Source: alertReference, Target: externalReference, RelationshipType: "observed_on",
		Metadata: json.RawMessage(`{"confidence":95}`), CreatedBy: alertTestEntityID(31),
		CreatedAt: alertTestTime(1), Version: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	relationship, err = relationship.Retract(1, kernel.AlertRelationshipRetractionInput{
		ID: alertTestEntityID(32), ActorID: alertTestEntityID(31), Reason: "superseded",
		OccurredAt: alertTestTime(3),
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		encode func() ([]byte, error)
		decode func([]byte) (any, error)
		match  func(any) bool
	}{
		{
			name:   "evidence",
			encode: func() ([]byte, error) { return encodeAlertEvidenceResult(evidence) },
			decode: func(document []byte) (any, error) { return decodeAlertEvidenceResult(document) },
			match:  func(value any) bool { return sameAlertEvidence(value.(kernel.AlertEvidence), evidence) },
		},
		{
			name:   "task",
			encode: func() ([]byte, error) { return encodeAlertTaskResult(task) },
			decode: func(document []byte) (any, error) { return decodeAlertTaskResult(document) },
			match:  func(value any) bool { return sameAlertTask(value.(kernel.AlertTask), task) },
		},
		{
			name:   "relationship",
			encode: func() ([]byte, error) { return encodeAlertRelationshipResult(relationship) },
			decode: func(document []byte) (any, error) { return decodeAlertRelationshipResult(document) },
			match: func(value any) bool {
				return sameAlertRelationship(value.(kernel.AlertRelationship), relationship)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document, encodeErr := test.encode()
			if encodeErr != nil {
				t.Fatal(encodeErr)
			}
			decoded, decodeErr := test.decode(document)
			if decodeErr != nil {
				t.Fatal(decodeErr)
			}
			if !test.match(decoded) {
				t.Fatalf("snapshot round trip diverged: %s", document)
			}
		})
	}
}

func TestAlertTaskDetailsOperationAllowsOnlyCoreDetails(t *testing.T) {
	t.Parallel()
	task, err := kernel.NewAlertTask(kernel.AlertTaskState{
		ID: alertTestEntityID(90), TenantID: alertTestEntityID(91), AlertID: alertTestEntityID(92),
		Title: "Triage endpoint", Description: "Initial instructions", Status: kernel.TaskTodo,
		Priority: kernel.TaskPriorityMedium, CreatedAt: alertTestTime(1), UpdatedAt: alertTestTime(1), Version: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	sla := alertTestEntityID(93)
	updated, err := task.ReplaceDetails(
		1, "Contain endpoint", "Revised instructions", kernel.TaskPriorityUrgent, &sla, alertTestTime(2),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !validAlertTaskMutation(task, updated, "dfir.alert.task.replace_details", 1) {
		t.Fatal("canonical Alert task details mutation was rejected")
	}
	if validAlertTaskMutation(task, updated, "dfir.alert.task.transition", 1) {
		t.Fatal("details change was accepted under a lifecycle operation")
	}

	team := alertTestEntityID(94)
	reassigned, err := task.Assign(1, &team, nil, alertTestTime(2))
	if err != nil {
		t.Fatal(err)
	}
	if validAlertTaskMutation(task, reassigned, "dfir.alert.task.replace_details", 1) {
		t.Fatal("assignment change was accepted under a details operation")
	}

	operation, ok := alertInvestigationOperations["dfir.alert.task.replace_details"]
	if !ok || operation.activityType != "alert.task.details_replaced" ||
		operation.auditAction != "dfir.alert.task.replace_details" ||
		operation.outboxType != "alert.task.details_replaced.v1" || operation.resourceType != "dfir_task" {
		t.Fatalf("Alert task details operation tuple = %#v, present=%t", operation, ok)
	}
}

func TestAlertTaskCommentsOperationChangesOnlyCanonicalReferences(t *testing.T) {
	t.Parallel()
	task, err := kernel.NewAlertTask(kernel.AlertTaskState{
		ID: alertTestEntityID(95), TenantID: alertTestEntityID(96), AlertID: alertTestEntityID(97),
		Title: "Triage endpoint", Status: kernel.TaskTodo, Priority: kernel.TaskPriorityMedium,
		CreatedAt: alertTestTime(1), UpdatedAt: alertTestTime(1), Version: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	commentID := alertTestEntityID(98)
	updated, err := task.ReplaceComments(1, []kernel.EntityID{commentID}, alertTestTime(2))
	if err != nil {
		t.Fatal(err)
	}
	if !validAlertTaskMutation(task, updated, "dfir.alert.task.comments.replace", 1) {
		t.Fatal("canonical Alert task comment replacement was rejected")
	}
	if validAlertTaskMutation(task, updated, "dfir.alert.task.replace_details", 1) {
		t.Fatal("comment change was accepted under the details operation")
	}
	operation, ok := alertInvestigationOperations["dfir.alert.task.comments.replace"]
	if !ok || operation.activityType != "alert.task.comments_replaced" ||
		operation.auditAction != "dfir.alert.task.comments.replace" ||
		operation.outboxType != "alert.task.comments_replaced.v1" || operation.resourceType != "dfir_task" {
		t.Fatalf("Alert task comments operation tuple = %#v, present=%t", operation, ok)
	}
}

func TestAlertInvestigationResultSnapshotsRejectUnknownOrNonCanonicalDocuments(t *testing.T) {
	t.Parallel()

	task, err := kernel.NewAlertTask(kernel.AlertTaskState{
		ID: alertTestEntityID(40), TenantID: alertTestEntityID(41), AlertID: alertTestEntityID(42),
		Title: "Triage", Status: kernel.TaskTodo, Priority: kernel.TaskPriorityHigh,
		CreatedAt: alertTestTime(1), UpdatedAt: alertTestTime(1), Version: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	document, err := encodeAlertTaskResult(task)
	if err != nil {
		t.Fatal(err)
	}

	unknown := bytes.Replace(document, []byte(`"version":1`), []byte(`"version":1,"futureField":true`), 1)
	if _, err = decodeAlertTaskResult(unknown); err == nil {
		t.Fatal("snapshot containing an unknown field was accepted")
	}
	if _, err = decodeAlertTaskResult(append(document, []byte(` {}`)...)); err == nil {
		t.Fatal("snapshot containing trailing JSON was accepted")
	}
	wrongKind := bytes.Replace(document, []byte(`"kind":"alert_task"`), []byte(`"kind":"alert_evidence"`), 1)
	if _, err = decodeAlertTaskResult(wrongKind); err == nil {
		t.Fatal("snapshot with a mismatched aggregate kind was accepted")
	}
	oversized := make([]byte, 16*1024*1024+1)
	if _, err = decodeAlertTaskResult(oversized); err == nil {
		t.Fatal("oversized snapshot was accepted")
	}
}

func ptrEntityID(value kernel.EntityID) *kernel.EntityID { return &value }

func TestCanonicalAlertDatabaseTimeUsesPostgresPrecision(t *testing.T) {
	t.Parallel()

	value := time.Date(2026, 8, 30, 12, 0, 0, 123456789, time.FixedZone("offset", 3600))
	canonical := canonicalAlertDatabaseTime(value)
	if canonical.Location() != time.UTC || canonical.Nanosecond() != 123456000 {
		t.Fatalf("canonical time = %s", canonical.Format(time.RFC3339Nano))
	}
}

func TestCaseRelationshipLoaderCannotProjectAlertRoot(t *testing.T) {
	t.Parallel()

	tenantID, caseID, relationshipID := alertTestUUID(50), alertTestUUID(51), alertTestUUID(52)
	assetID, membershipID := alertTestUUID(53), alertTestUUID(54)
	tx := &dfirTransactionStub{row: func(query string, arguments []any, destinations []any) error {
		if !strings.Contains(query, "case_id = $2 AND alert_id IS NULL AND id = $3") ||
			len(arguments) != 3 || arguments[0] != tenantID || arguments[1] != caseID || arguments[2] != relationshipID {
			return errors.New("Case relationship query was not exact-root bound")
		}
		*(destinations[0].(*uuid.UUID)) = relationshipID
		*(destinations[1].(*uuid.UUID)) = tenantID
		*(destinations[2].(*string)) = string(kernel.EntityCase)
		*(destinations[3].(**uuid.UUID)) = &caseID
		*(destinations[4].(**string)) = nil
		*(destinations[5].(**string)) = nil
		*(destinations[6].(*string)) = string(kernel.EntityAsset)
		*(destinations[7].(**uuid.UUID)) = &assetID
		*(destinations[8].(**string)) = nil
		*(destinations[9].(**string)) = nil
		*(destinations[10].(*string)) = "contains"
		*(destinations[11].(*[]byte)) = []byte(`{}`)
		*(destinations[12].(*uuid.UUID)) = membershipID
		*(destinations[13].(*time.Time)) = alertTestTime(1)
		*(destinations[14].(*int64)) = 1
		return nil
	}, query: func(query string, arguments []any) (pgx.Rows, error) {
		if !strings.Contains(query, "FROM public.dfir_relationship_retractions") ||
			len(arguments) != 3 || arguments[0] != tenantID || arguments[1] != relationshipID || arguments[2] != caseID {
			return nil, errors.New("Case relationship history query was not exact-root bound")
		}
		return &dfirRowsStub{}, nil
	}}
	value, err := loadDFIRRelationship(context.Background(), tx, tenantID, caseID, relationshipID)
	if err != nil {
		t.Fatal(err)
	}
	if value.ID().String() != relationshipID.String() || value.Source().ID().String() != caseID.String() {
		t.Fatalf("relationship projection = %#v", value)
	}
}

func TestCaseRelationshipLoaderProjectsVersionAndImmutableRetraction(t *testing.T) {
	t.Parallel()

	tenantID, caseID, relationshipID := alertTestUUID(55), alertTestUUID(56), alertTestUUID(57)
	externalID, membershipID, retractionID := "external-asset", alertTestUUID(58), alertTestUUID(59)
	createdAt, retractedAt := alertTestTime(1), alertTestTime(2)
	tx := &dfirTransactionStub{
		row: func(query string, arguments []any, destinations []any) error {
			if !strings.Contains(query, "case_id = $2 AND alert_id IS NULL AND id = $3") ||
				len(arguments) != 3 || arguments[0] != tenantID || arguments[1] != caseID || arguments[2] != relationshipID {
				return errors.New("Case relationship query was not exact-root bound")
			}
			*(destinations[0].(*uuid.UUID)) = relationshipID
			*(destinations[1].(*uuid.UUID)) = tenantID
			*(destinations[2].(*string)) = string(kernel.EntityCase)
			*(destinations[3].(**uuid.UUID)) = &caseID
			*(destinations[4].(**string)) = nil
			*(destinations[5].(**string)) = nil
			*(destinations[6].(*string)) = string(kernel.EntityExternal)
			*(destinations[7].(**uuid.UUID)) = nil
			externalType := "host"
			*(destinations[8].(**string)) = &externalType
			*(destinations[9].(**string)) = &externalID
			*(destinations[10].(*string)) = "contains"
			*(destinations[11].(*[]byte)) = []byte(`{}`)
			*(destinations[12].(*uuid.UUID)) = membershipID
			*(destinations[13].(*time.Time)) = createdAt
			*(destinations[14].(*int64)) = 2
			return nil
		},
		query: func(query string, arguments []any) (pgx.Rows, error) {
			if !strings.Contains(query, "case_id = $3 AND alert_id IS NULL") ||
				len(arguments) != 3 || arguments[0] != tenantID || arguments[1] != relationshipID || arguments[2] != caseID {
				return nil, errors.New("Case relationship retraction query was not exact-root bound")
			}
			return &dfirRowsStub{rows: [][]any{{
				retractionID, tenantID, relationshipID, membershipID,
				"duplicate link", int64(1), int64(2), retractedAt,
			}}}, nil
		},
	}
	value, err := loadDFIRRelationship(context.Background(), tx, tenantID, caseID, relationshipID)
	if err != nil {
		t.Fatal(err)
	}
	history := value.Retractions()
	if value.Version() != 2 || value.Active() || len(history) != 1 ||
		history[0].ID.String() != retractionID.String() || history[0].Sequence != 1 ||
		!history[0].OccurredAt.Equal(retractedAt) {
		t.Fatalf("relationship projection = %#v, history = %#v", value, history)
	}
}
