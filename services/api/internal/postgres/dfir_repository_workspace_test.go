package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	kernel "github.com/periapsis-im/periapsis/modules/dfir"
)

func TestCustomerCaseTaskProjectionKeepsOnlyPublicSameRootCommentIDs(t *testing.T) {
	t.Parallel()
	tenantID, caseID, taskID := alertTestUUID(171), alertTestUUID(172), alertTestUUID(173)
	publicID, privateID := alertTestUUID(174), alertTestUUID(175)
	task, err := kernel.NewTask(kernel.TaskInput{
		ID: entityID(taskID), TenantID: entityID(tenantID), CaseID: entityID(caseID),
		Title: "Customer-visible task", Status: kernel.TaskTodo, Priority: kernel.TaskPriorityHigh,
		CommentIDs: []kernel.EntityID{entityID(publicID), entityID(privateID)},
		CreatedAt:  alertTestTime(0), UpdatedAt: alertTestTime(1), Version: 7,
	})
	if err != nil {
		t.Fatal(err)
	}
	tx := &dfirTransactionStub{query: func(query string, arguments []any) (pgx.Rows, error) {
		if !strings.Contains(query, "comment.visibility = 'public'") ||
			!strings.Contains(query, "comment.case_id = $2") ||
			!strings.Contains(query, "comment.alert_id IS NULL") ||
			len(arguments) != 3 || arguments[0] != tenantID || arguments[1] != caseID {
			return nil, errors.New("customer comment filter lost tenant/root/visibility fencing")
		}
		requested, ok := arguments[2].([]uuid.UUID)
		if !ok || len(requested) != 2 || requested[0] != publicID || requested[1] != privateID {
			return nil, errors.New("customer comment filter lost exact task references")
		}
		return &dfirRowsStub{rows: [][]any{{publicID}}}, nil
	}}

	filtered, err := filterCustomerCaseTaskComments(
		context.Background(), tx, tenantID, caseID, task,
	)
	if err != nil {
		t.Fatal(err)
	}
	comments := filtered.CommentIDs()
	if len(comments) != 1 || comments[0].String() != publicID.String() ||
		filtered.ID() != task.ID() || filtered.Version() != task.Version() || filtered.Title() != task.Title() {
		t.Fatalf("customer task projection = %#v", filtered)
	}
}

func TestCustomerCaseTaskProjectionRejectsUnexpectedCommentRow(t *testing.T) {
	t.Parallel()
	tenantID, caseID, taskID := alertTestUUID(176), alertTestUUID(177), alertTestUUID(178)
	requestedID, foreignID := alertTestUUID(179), alertTestUUID(180)
	task, err := kernel.NewTask(kernel.TaskInput{
		ID: entityID(taskID), TenantID: entityID(tenantID), CaseID: entityID(caseID),
		Title: "Customer-visible task", Status: kernel.TaskTodo, Priority: kernel.TaskPriorityHigh,
		CommentIDs: []kernel.EntityID{entityID(requestedID)},
		CreatedAt:  alertTestTime(0), UpdatedAt: alertTestTime(0), Version: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	tx := &dfirTransactionStub{query: func(string, []any) (pgx.Rows, error) {
		return &dfirRowsStub{rows: [][]any{{foreignID}}}, nil
	}}
	if _, err = filterCustomerCaseTaskComments(
		context.Background(), tx, tenantID, caseID, task,
	); err == nil {
		t.Fatal("customer task projection accepted an unassociated comment")
	}
}
