package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

type workflowReplayTransaction struct {
	recordingTransaction
	rows    []pgx.Row
	queries []string
	args    [][]any
}

func (tx *workflowReplayTransaction) QueryRow(_ context.Context, query string, arguments ...any) pgx.Row {
	tx.queries = append(tx.queries, query)
	tx.args = append(tx.args, arguments)
	if len(tx.rows) == 0 {
		panic("unexpected workflow replay query")
	}
	row := tx.rows[0]
	tx.rows = tx.rows[1:]
	return row
}

func TestWorkflowAdminCursorIsCanonicalAndUUIDv7Bound(t *testing.T) {
	identifier := mustPostgresUUIDv7(t)
	encoded := encodeWorkflowAdminCursor(identifier)
	decoded, err := decodeWorkflowAdminCursor(encoded)
	if err != nil || decoded != identifier {
		t.Fatalf("decodeWorkflowAdminCursor() = (%s, %v), want %s", decoded, err, identifier)
	}
	for _, malformed := range []string{
		encoded + "=", "AQ", "not+base64", encodeWorkflowAdminCursor(uuid.Nil),
	} {
		if _, err := decodeWorkflowAdminCursor(malformed); !errors.Is(err, application.ErrInvalidInput) {
			t.Fatalf("decodeWorkflowAdminCursor(%q) error = %v, want invalid input", malformed, err)
		}
	}
}

func TestWorkflowAdminAudienceUsesRouteIntentNotLegacyRole(t *testing.T) {
	for _, legacyRole := range []authorization.LegacyMembershipRole{
		authorization.LegacyMembershipRoleTenantAdmin,
		authorization.LegacyMembershipRoleCustomerManager,
		authorization.LegacyMembershipRoleCustomerUser,
		authorization.LegacyMembershipRoleReadOnly,
	} {
		principal, err := workflowAdminPrincipal(authorization.TenantAuthority{
			Principal:  authorization.TenantPrincipal{Kind: authorization.PrincipalKindHuman},
			LegacyRole: legacyRole,
		})
		if err != nil || principal != kernel.PrincipalOperator {
			t.Fatalf("workflowAdminPrincipal(%q) = (%q, %v), want operator", legacyRole, principal, err)
		}
	}

	if _, err := workflowAdminPrincipal(authorization.TenantAuthority{
		Principal: authorization.TenantPrincipal{Kind: authorization.PrincipalKindServiceAccount},
	}); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("service-account workflow audience error = %v, want forbidden", err)
	}
}

func TestWorkflowAdminCommitIdentityAllowsConcurrentCreateReplayOnly(t *testing.T) {
	plannedID := mustPostgresUUIDv7(t)
	originalID := mustPostgresUUIDv7(t)
	for _, test := range []struct {
		name         string
		action       kernel.WorkflowAdministrationAction
		returnedID   uuid.UUID
		revision     int64
		nextRevision uint64
		replayed     bool
		want         bool
	}{
		{name: "fresh exact result", action: kernel.WorkflowAdministrationCreate, returnedID: plannedID, revision: 1, nextRevision: 1, want: true},
		{name: "fresh identity drift", action: kernel.WorkflowAdministrationCreate, returnedID: originalID, revision: 1, nextRevision: 1},
		{name: "concurrent create replay", action: kernel.WorkflowAdministrationCreate, returnedID: originalID, revision: 1, nextRevision: 1, replayed: true, want: true},
		{name: "existing resource replay drift", action: kernel.WorkflowAdministrationPublish, returnedID: originalID, revision: 2, nextRevision: 3, replayed: true},
		{name: "existing resource exact replay", action: kernel.WorkflowAdministrationPublish, returnedID: plannedID, revision: 2, nextRevision: 3, replayed: true, want: true},
		{name: "fresh revision drift", action: kernel.WorkflowAdministrationPublish, returnedID: plannedID, revision: 2, nextRevision: 3},
		{name: "malformed replay identity", action: kernel.WorkflowAdministrationCreate, returnedID: uuid.Nil, revision: 1, nextRevision: 1, replayed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := validWorkflowAdminCommitResult(
				test.action, plannedID, test.returnedID,
				test.revision, test.nextRevision, test.replayed,
			); got != test.want {
				t.Fatalf("validWorkflowAdminCommitResult() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestScanWorkflowAdminRecordBuildsClosedAggregate(t *testing.T) {
	tenantID, workflowID := mustPostgresUUIDv7(t), mustPostgresUUIDv7(t)
	createdAt := time.Date(2026, 8, 26, 8, 0, 0, 123000, time.UTC)
	updatedAt := createdAt.Add(time.Minute)
	states, transitions := workflowAdminTestDocuments()
	row := rowFunc(func(destinations ...any) error {
		*destinations[0].(*uuid.UUID) = workflowID
		*destinations[1].(*string) = "alert"
		*destinations[2].(*string) = "alert_response"
		*destinations[3].(*string) = "Alert response"
		*destinations[4].(*string) = "Governed workflow"
		*destinations[5].(*bool) = true
		*destinations[6].(*int32) = 4
		*destinations[7].(*int64) = 7
		*destinations[8].(*pgtype.Timestamptz) = pgtype.Timestamptz{}
		*destinations[9].(*time.Time) = createdAt
		*destinations[10].(*time.Time) = updatedAt
		*destinations[11].(*[]byte) = states
		*destinations[12].(*[]byte) = transitions
		return nil
	})
	record, err := scanWorkflowAdminRecord(row, tenantID)
	if err != nil {
		t.Fatalf("scanWorkflowAdminRecord() error = %v", err)
	}
	if record.Workflow.ID().String() != workflowID.String() || record.Workflow.Tenant().String() != tenantID.String() ||
		record.Workflow.Kind() != kernel.AggregateAlert || record.Workflow.Key().String() != "alert_response" ||
		record.Workflow.CurrentVersion() != 4 || record.Workflow.Revision() != 7 || !record.Workflow.IsDefault() ||
		record.Workflow.Status() != kernel.WorkflowActive || record.ArchivedAt != nil ||
		!record.CreatedAt.Equal(createdAt) || !record.UpdatedAt.Equal(updatedAt) {
		t.Fatalf("scanWorkflowAdminRecord() = %+v", record)
	}
}

func TestScanWorkflowAdminRecordRejectsArchivedDefault(t *testing.T) {
	tenantID, workflowID := mustPostgresUUIDv7(t), mustPostgresUUIDv7(t)
	now := time.Date(2026, 8, 26, 8, 0, 0, 0, time.UTC)
	states, transitions := workflowAdminTestDocuments()
	row := rowFunc(func(destinations ...any) error {
		*destinations[0].(*uuid.UUID) = workflowID
		*destinations[1].(*string) = "case"
		*destinations[2].(*string) = "case_response"
		*destinations[3].(*string) = "Case response"
		*destinations[4].(*string) = ""
		*destinations[5].(*bool) = true
		*destinations[6].(*int32) = 1
		*destinations[7].(*int64) = 1
		*destinations[8].(*pgtype.Timestamptz) = pgtype.Timestamptz{Time: now, Valid: true}
		*destinations[9].(*time.Time) = now
		*destinations[10].(*time.Time) = now
		*destinations[11].(*[]byte) = states
		*destinations[12].(*[]byte) = transitions
		return nil
	})
	if _, err := scanWorkflowAdminRecord(row, tenantID); !errors.Is(err, application.ErrConflict) {
		t.Fatalf("archived default error = %v, want conflict", err)
	}
}

func TestScanWorkflowVersionRejectsPublisherProjectionDrift(t *testing.T) {
	tenantID, workflowID, publisherID := mustPostgresUUIDv7(t), mustPostgresUUIDv7(t), mustPostgresUUIDv7(t)
	states, transitions := workflowAdminTestDocuments()
	row := rowFunc(func(destinations ...any) error {
		*destinations[0].(*uuid.UUID) = workflowID
		*destinations[1].(*string) = "alert"
		*destinations[2].(*int32) = 1
		*destinations[3].(*[]byte) = states
		*destinations[4].(*[]byte) = transitions
		*destinations[5].(*pgtype.UUID) = pgtype.UUID{Bytes: [16]byte(publisherID), Valid: true}
		*destinations[6].(*pgtype.Text) = pgtype.Text{}
		*destinations[7].(*time.Time) = time.Now().UTC()
		return nil
	})
	if _, err := scanWorkflowVersionRecord(row, tenantID); !errors.Is(err, application.ErrConflict) {
		t.Fatalf("orphan publisher error = %v, want conflict", err)
	}
}

func TestLookupWorkflowAdminReplayUsesOneRepeatableReadSnapshot(t *testing.T) {
	tenantID, actorID, workflowID := mustPostgresUUIDv7(t), mustPostgresUUIDv7(t), mustPostgresUUIDv7(t)
	fingerprint := sha256.Sum256([]byte("stable workflow command"))
	createdAt := time.Date(2026, 8, 26, 8, 0, 0, 0, time.UTC)
	snapshot := workflowAdminCommandSnapshot(
		t, workflowID, "case", "case_response", "Case response", "Governed workflow",
		"create", 1, 1, createdAt,
	)
	tx := &workflowReplayTransaction{rows: []pgx.Row{
		rowFunc(func(destinations ...any) error {
			*destinations[0].(*string) = tenantID.String()
			*destinations[1].(*string) = actorID.String()
			return nil
		}),
		rowFunc(func(destinations ...any) error {
			*destinations[0].(*string) = ""
			*destinations[1].(*string) = ""
			return nil
		}),
		rowFunc(func(destinations ...any) error {
			*destinations[0].(*uuid.UUID) = workflowID
			*destinations[1].(*[]byte) = append([]byte(nil), fingerprint[:]...)
			*destinations[2].(*int64) = 1
			*destinations[3].(*[]byte) = append([]byte(nil), snapshot...)
			return nil
		}),
	}}
	beginCalls := 0
	var options pgx.TxOptions
	repository := &TicketingRepository{begin: func(_ context.Context, requested pgx.TxOptions) (databaseTransaction, error) {
		beginCalls++
		options = requested
		return tx, nil
	}}
	result, found, err := repository.LookupWorkflowAdminReplay(context.Background(), application.WorkflowAdminReplayQuery{
		TenantID: tenantID, ActorID: actorID, Action: kernel.WorkflowAdministrationCreate,
		KeyHash: sha256.Sum256([]byte("workflow-key")), Fingerprint: fingerprint,
	})
	if err != nil {
		t.Fatalf("LookupWorkflowAdminReplay() error = %v", err)
	}
	if !found || !result.Replayed || result.Record.Workflow.ID().String() != workflowID.String() {
		t.Fatalf("LookupWorkflowAdminReplay() = (%+v, %t), want replay", result, found)
	}
	if beginCalls != 1 || options.IsoLevel != pgx.RepeatableRead || options.AccessMode != pgx.ReadOnly ||
		!tx.committed || len(tx.rows) != 0 || len(tx.queries) != 3 {
		t.Fatalf("transaction = calls:%d options:%+v committed:%t rows:%d queries:%d", beginCalls, options, tx.committed, len(tx.rows), len(tx.queries))
	}
	if !strings.Contains(tx.queries[2], "lookup_ticket_workflow_admin_replay_v1") {
		t.Fatalf("unexpected replay query order: %#v", tx.queries)
	}
}

func TestCommitWorkflowConsumesMutationOwnedSnapshot(t *testing.T) {
	tenantID, actorID, workflowID := mustPostgresUUIDv7(t), mustPostgresUUIDv7(t), mustPostgresUUIDv7(t)
	states, transitions := workflowAdminTestDocuments()
	definition, err := mapTicketWorkflow(workflowID, kernel.AggregateAlert, 1, states, transitions)
	if err != nil {
		t.Fatalf("map workflow fixture: %v", err)
	}
	tenant, err := ticketEntityID(tenantID)
	if err != nil {
		t.Fatalf("map tenant fixture: %v", err)
	}
	key, err := kernel.NewKey("alert_response")
	if err != nil {
		t.Fatalf("map workflow key: %v", err)
	}
	plan, err := kernel.PlanWorkflowCreation(
		tenant, key, "Alert response", "Original commit projection", definition,
	)
	if err != nil {
		t.Fatalf("plan workflow creation: %v", err)
	}
	createdAt := time.Date(2026, 8, 26, 10, 0, 0, 0, time.UTC)
	snapshot := workflowAdminCommandSnapshot(
		t, workflowID, "alert", "alert_response", "Alert response", "Original commit projection",
		"create", 1, 1, createdAt,
	)
	tx := &workflowReplayTransaction{rows: []pgx.Row{
		rowFunc(func(destinations ...any) error {
			*destinations[0].(*string) = tenantID.String()
			*destinations[1].(*string) = actorID.String()
			return nil
		}),
		rowFunc(func(destinations ...any) error {
			*destinations[0].(*string) = ""
			*destinations[1].(*string) = ""
			return nil
		}),
		rowFunc(func(destinations ...any) error {
			*destinations[0].(*uuid.UUID) = workflowID
			*destinations[1].(*int64) = 1
			*destinations[2].(*bool) = false
			*destinations[3].(*[]byte) = append([]byte(nil), snapshot...)
			return nil
		}),
	}}
	beginCalls := 0
	var options pgx.TxOptions
	repository := &TicketingRepository{
		begin: func(_ context.Context, requested pgx.TxOptions) (databaseTransaction, error) {
			beginCalls++
			options = requested
			return tx, nil
		},
		newID: uuid.NewV7,
	}
	audit := application.AuditContext{
		RequestID: uuid.New(), CorrelationID: uuid.New(),
		RemoteAddress: netip.MustParseAddr("192.0.2.90"), UserAgent: "workflow adapter test",
	}
	fingerprint := sha256.Sum256([]byte("workflow create request"))
	result, err := repository.CommitWorkflow(context.Background(), application.WorkflowAdminWrite{
		Actor: application.Actor{
			UserID: actorID, SessionID: mustPostgresUUIDv7(t), ActiveTenantID: tenantID,
			AuthenticationMethod: "webauthn", Audit: audit,
		},
		RequiredCapability: application.WorkflowCapabilityManage,
		Plan:               plan,
		Command: application.WorkflowAdminCommandBinding{
			Action:  kernel.WorkflowAdministrationCreate,
			KeyHash: sha256.Sum256([]byte("workflow-create-key")), Fingerprint: fingerprint,
		},
		Audit: audit,
	})
	if err != nil {
		t.Fatalf("CommitWorkflow() error = %v", err)
	}
	if result.Replayed || result.Record.Workflow.ID().String() != workflowID.String() ||
		result.Record.Workflow.Description() != "Original commit projection" {
		t.Fatalf("CommitWorkflow() = %+v", result)
	}
	if beginCalls != 1 || options.IsoLevel != pgx.ReadCommitted || !tx.committed ||
		len(tx.rows) != 0 || len(tx.queries) != 3 || len(tx.args[2]) != 30 {
		t.Fatalf("transaction = calls:%d options:%+v committed:%t rows:%d queries:%d abi_args:%d", beginCalls, options, tx.committed, len(tx.rows), len(tx.queries), len(tx.args[2]))
	}
	if !strings.Contains(tx.queries[2], "workflow_id, revision, replayed, result_snapshot") ||
		!strings.Contains(tx.queries[2], "commit_ticket_workflow_admin_v1") {
		t.Fatalf("unexpected workflow commit ABI: %s", tx.queries[2])
	}
}

func workflowAdminCommandSnapshot(
	t *testing.T,
	workflowID uuid.UUID,
	kind string,
	key string,
	displayName string,
	description string,
	action string,
	revision int,
	version int,
	createdAt time.Time,
) []byte {
	t.Helper()
	states, transitions := workflowAdminTestDocuments()
	snapshot, err := json.Marshal(map[string]any{
		"schemaVersion": 1, "action": action, "workflowId": workflowID,
		"aggregateKind": kind, "key": key, "displayName": displayName,
		"description": description, "isDefault": false, "status": "active",
		"revision": revision, "currentVersion": version, "states": json.RawMessage(states),
		"transitions": json.RawMessage(transitions), "createdAt": createdAt, "updatedAt": createdAt,
		"archivedAt": nil,
	})
	if err != nil {
		t.Fatalf("marshal workflow command snapshot: %v", err)
	}
	return snapshot
}

func workflowAdminTestDocuments() ([]byte, []byte) {
	return []byte(`[
      {"key":"new","initial":true,"terminal":false,"visibility":"customer","actions":[{"action":"create","effects":["activity","audit"]}]},
      {"key":"closed","initial":false,"terminal":true,"visibility":"customer","actions":[]}
    ]`), []byte(`[
      {"key":"close","from":"new","to":"closed","requiredComment":true,"reopen":false,
       "requiredRoles":[],"requiredPermissions":[],"requiredCustomFields":[],"effects":["activity","audit"]}
    ]`)
}
