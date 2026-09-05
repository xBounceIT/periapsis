package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	kernel "github.com/periapsis-im/periapsis/modules/dfir"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	application "github.com/periapsis-im/periapsis/services/api/internal/dfir"
)

func TestCaseTaskReservationUsesSnapshotVersionBeyondInt32(t *testing.T) {
	t.Parallel()
	tenantID := alertTestUUID(70)
	caseID := alertTestUUID(71)
	taskID := alertTestUUID(72)
	commandID := alertTestUUID(73)
	const taskVersion = int64(3_000_000_000)
	value, err := kernel.NewTask(kernel.TaskInput{
		ID: entityID(taskID), TenantID: entityID(tenantID), CaseID: entityID(caseID),
		Title: "High revision task", Status: kernel.TaskInProgress,
		Priority: kernel.TaskPriorityHigh, CreatedAt: alertTestTime(0),
		UpdatedAt: alertTestTime(1), Version: uint64(taskVersion),
	})
	if err != nil {
		t.Fatal(err)
	}
	document, err := encodeCaseTaskResult(value)
	if err != nil {
		t.Fatal(err)
	}
	keyDigest := sha256.Sum256([]byte("case-task-key"))
	requestDigest := sha256.Sum256([]byte("case-task-request"))
	contract := application.TaskMutationContract{BaseWrite: application.BaseWrite{
		Command: application.CommandBinding{
			Operation: "case.dfir.task.transition", KeyDigest: keyDigest,
			RequestDigest: requestDigest,
		},
	}}
	tx := &dfirTransactionStub{row: func(query string, arguments []any, destinations []any) error {
		if !strings.Contains(query, "app.reserve_case_dfir_command_v1") ||
			!strings.Contains(query, "$8::jsonb") || len(arguments) != 8 ||
			arguments[0] != commandID || arguments[1] != caseID ||
			arguments[2] != contract.Command.Operation || arguments[3] != taskID ||
			arguments[4] != taskVersion || !equalAlertTestBytes(arguments[5], keyDigest[:]) ||
			!equalAlertTestBytes(arguments[6], requestDigest[:]) || arguments[7] != string(document) {
			return errors.New("Case task reservation ABI or bigint result coordinate drifted")
		}
		*(destinations[0].(*uuid.UUID)) = commandID
		*(destinations[1].(*uuid.UUID)) = taskID
		*(destinations[2].(*int64)) = taskVersion
		*(destinations[3].(*[]byte)) = document
		*(destinations[4].(*bool)) = true
		return nil
	}}
	reservation, err := reserveCaseTaskCommand(
		context.Background(), tx, commandID, caseID, contract, taskID,
		taskVersion, document,
	)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := validateCaseTaskReservation(
		reservation, tenantID, caseID, taskID, taskVersion, true,
	)
	if err != nil || replayed.Version() != uint64(taskVersion) {
		t.Fatalf("high-version Case task replay = (%v, %v)", replayed, err)
	}
	if options := caseTaskWriteOptions(); options.IsoLevel != pgx.ReadCommitted {
		t.Fatalf("Case task write isolation = %q, want read committed", options.IsoLevel)
	}
}

func TestCaseTaskSnapshotDecodeAndMutationDeltaFailClosed(t *testing.T) {
	t.Parallel()
	current, err := kernel.NewTask(kernel.TaskInput{
		ID: alertTestEntityID(80), TenantID: alertTestEntityID(81), CaseID: alertTestEntityID(82),
		Title: "Original", Description: "Bounded", Status: kernel.TaskTodo,
		Priority: kernel.TaskPriorityMedium, CommentIDs: []kernel.EntityID{alertTestEntityID(83)},
		CreatedAt: alertTestTime(0), UpdatedAt: alertTestTime(0), Version: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := current.ReplaceDetails(
		1, "Updated", "Still bounded", kernel.TaskPriorityHigh, nil,
		alertTestTime(1),
	)
	if err != nil || !validCaseTaskMutation(
		current, updated, "case.dfir.task.replace_details", 1,
	) {
		t.Fatalf("valid details delta = (%v, %v)", updated, err)
	}
	if validCaseTaskMutation(current, updated, "case.dfir.task.assign", 1) {
		t.Fatal("details delta was accepted as an assignment operation")
	}
	document, err := encodeCaseTaskResult(updated)
	if err != nil {
		t.Fatal(err)
	}
	poisoned := append(document[:len(document)-1], []byte(`,"unknown":true}`)...)
	if _, err = decodeCaseTaskResult(poisoned); err == nil {
		t.Fatal("Case task replay snapshot accepted an unknown top-level field")
	}
}

func TestCaseAndAlertTaskCommentsAreRootBoundAndOnlyCommentOperationMayChangeThem(t *testing.T) {
	t.Parallel()
	tenantID, caseID, alertID := alertTestUUID(84), alertTestUUID(85), alertTestUUID(86)
	commentID := alertTestEntityID(87)
	caseTask, err := kernel.NewTask(kernel.TaskInput{
		ID: alertTestEntityID(88), TenantID: entityID(tenantID), CaseID: entityID(caseID),
		Title: "Associate review", Status: kernel.TaskTodo, Priority: kernel.TaskPriorityMedium,
		CreatedAt: alertTestTime(0), UpdatedAt: alertTestTime(0), Version: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	caseUpdated, err := caseTask.ReplaceComments(1, []kernel.EntityID{commentID}, alertTestTime(1))
	if err != nil || !validCaseTaskMutation(caseTask, caseUpdated, "case.dfir.task.comments.replace", 1) {
		t.Fatalf("Case comment mutation = (%v, %v)", caseUpdated, err)
	}
	if validCaseTaskMutation(caseTask, caseUpdated, "case.dfir.task.replace_details", 1) {
		t.Fatal("Case comment change was accepted under details operation")
	}
	alertTask, err := kernel.NewAlertTask(kernel.AlertTaskState{
		ID: alertTestEntityID(89), TenantID: entityID(tenantID), AlertID: entityID(alertID),
		Title: "Associate review", Status: kernel.TaskTodo, Priority: kernel.TaskPriorityMedium,
		CreatedAt: alertTestTime(0), UpdatedAt: alertTestTime(0), Version: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	alertUpdated, err := alertTask.ReplaceComments(1, []kernel.EntityID{commentID}, alertTestTime(1))
	if err != nil {
		t.Fatal(err)
	}

	wantCount := int64(1)
	tx := &dfirTransactionStub{row: func(query string, arguments []any, destinations []any) error {
		if len(arguments) != 3 || arguments[0] != tenantID ||
			(!strings.Contains(query, "case_id=$2 AND alert_id IS NULL") &&
				!strings.Contains(query, "alert_id=$2 AND case_id IS NULL")) {
			return errors.New("task comment validation was not exact-root bound")
		}
		*(destinations[0].(*int64)) = wantCount
		return nil
	}}
	if err = validateCaseTaskReferences(context.Background(), tx, tenantID, caseID, caseUpdated); err != nil {
		t.Fatalf("live Case comment validation = %v", err)
	}
	if err = validateAlertTaskReferences(context.Background(), tx, tenantID, alertID, alertUpdated); err != nil {
		t.Fatalf("live Alert comment validation = %v", err)
	}
	wantCount = 0
	if err = validateCaseTaskReferences(context.Background(), tx, tenantID, caseID, caseUpdated); !errors.Is(err, authorization.ErrForbidden) {
		t.Fatalf("unlinked Case comment error = %v", err)
	}
	if err = validateAlertTaskReferences(context.Background(), tx, tenantID, alertID, alertUpdated); !errors.Is(err, authorization.ErrForbidden) {
		t.Fatalf("unlinked Alert comment error = %v", err)
	}
}
