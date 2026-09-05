package postgres

import (
	"encoding/json"
	"math"
	"testing"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

func TestMapTicketWorkflowValidatesDeclarativeConditions(t *testing.T) {
	states := []byte(`[
      {"key":"new","initial":true,"terminal":false,"visibility":"internal","actions":[{"action":"create","effects":["activity","audit"]}]},
      {"key":"closed","initial":false,"terminal":true,"visibility":"internal","actions":[]}
    ]`)
	transitions := []byte(`[
      {
        "key":"close","from":"new","to":"closed","requiredComment":false,"reopen":false,
        "requiredRoles":[],"requiredPermissions":[],"requiredCustomFields":[],
        "condition":{"kind":"all","children":[
          {"kind":"predicate","field":"severity","operator":"in","values":[
            {"type":"text","value":"critical"},{"type":"text","value":"high"}
          ]},
          {"kind":"predicate","field":"custom.risk_score","operator":"greater_than_or_equal","values":[
            {"type":"number","value":7}
          ]}
        ]},
        "effects":["activity","audit"]
      }
    ]`)
	workflow, err := mapTicketWorkflow(
		uuid.MustParse("00000000-0000-7000-8000-000000000801"),
		kernel.AggregateAlert, 1, states, transitions,
	)
	if err != nil {
		t.Fatalf("mapTicketWorkflow() error = %v", err)
	}
	condition := workflow.Transitions()[0].Condition()
	if !condition.Configured() {
		t.Fatal("stored workflow condition was discarded")
	}
	severity, _ := kernel.NewConditionField("severity")
	high, _ := kernel.NewTextConditionValue("high")
	severityFact, _ := kernel.NewConditionFact(severity, high)
	risk, _ := kernel.NewConditionField("custom.risk_score")
	score, _ := kernel.NewNumberConditionValue(9)
	riskFact, _ := kernel.NewConditionFact(risk, score)
	facts, _ := kernel.NewConditionFacts(severityFact, riskFact)
	if !condition.Evaluate(facts) {
		t.Fatal("mapped condition did not preserve its semantics")
	}

	unsafe := []byte(`[
      {
        "key":"close","from":"new","to":"closed","requiredComment":false,"reopen":false,
        "requiredRoles":[],"requiredPermissions":[],"requiredCustomFields":[],
        "condition":{"kind":"script","field":"severity","operator":"equal","values":[{"type":"text","value":"high"}]},
        "effects":["activity","audit"]
      }
    ]`)
	if _, err := mapTicketWorkflow(
		uuid.MustParse("00000000-0000-7000-8000-000000000802"),
		kernel.AggregateAlert, 1, states, unsafe,
	); err == nil {
		t.Fatal("executable workflow condition shape was accepted")
	}

	nullBoolean := []byte(`[
      {
        "key":"close","from":"new","to":"closed","requiredComment":false,"reopen":false,
        "requiredRoles":[],"requiredPermissions":[],"requiredCustomFields":[],
        "condition":{"kind":"predicate","field":"assigned","operator":"equal","values":[{"type":"boolean","value":null}]},
        "effects":["activity","audit"]
      }
    ]`)
	if _, err := mapTicketWorkflow(
		uuid.MustParse("00000000-0000-7000-8000-000000000804"),
		kernel.AggregateAlert, 1, states, nullBoolean,
	); err == nil {
		t.Fatal("null typed condition value was accepted as a zero scalar")
	}
}

func TestTicketWorkflowJSONRoundTripPreservesClosedDefinition(t *testing.T) {
	states := []byte(`[
      {"key":"new","initial":true,"terminal":false,"visibility":"customer","actions":[{"action":"create","effects":["activity","audit","sla"]}]},
      {"key":"closed","initial":false,"terminal":true,"visibility":"customer","actions":[]}
    ]`)
	transitions := []byte(`[
      {
        "key":"close","from":"new","to":"closed","requiredComment":true,"reopen":false,
        "requiredRoles":["senior_analyst"],"requiredPermissions":["alert.update"],
        "requiredCustomFields":["resolution"],
        "condition":{"kind":"not","children":[
          {"kind":"predicate","field":"detected_at","operator":"less_than","values":[
            {"type":"instant","value":"2026-08-26T08:30:00.123456Z"}
          ]}
        ]},
        "effects":["activity","audit","sla","notification"]
      }
    ]`)
	id := uuid.MustParse("00000000-0000-7000-8000-000000000805")
	want, err := mapTicketWorkflow(id, kernel.AggregateAlert, 9, states, transitions)
	if err != nil {
		t.Fatal(err)
	}
	encodedStates, encodedTransitions, err := marshalTicketWorkflow(want)
	if err != nil {
		t.Fatalf("marshalTicketWorkflow() error = %v", err)
	}
	got, err := mapTicketWorkflow(id, kernel.AggregateAlert, 9, encodedStates, encodedTransitions)
	if err != nil {
		t.Fatalf("round-trip mapTicketWorkflow() error = %v", err)
	}
	if got.ID() != want.ID() || got.Kind() != want.Kind() || got.Version() != want.Version() ||
		len(got.States()) != len(want.States()) || len(got.Transitions()) != len(want.Transitions()) {
		t.Fatalf("round-trip identity/topology = %#v, want %#v", got, want)
	}
	condition := got.Transitions()[0].Condition()
	if !condition.Configured() || got.Transitions()[0].RequiredComment() != true ||
		got.Transitions()[0].RequiredRoles()[0].String() != "senior_analyst" {
		t.Fatal("round trip lost transition gates")
	}
}

func TestMarshalTicketWorkflowRejectsDatabaseVersionOverflow(t *testing.T) {
	states := []byte(`[
      {"key":"new","initial":true,"terminal":false,"visibility":"internal","actions":[{"action":"create","effects":["activity","audit"]}]},
      {"key":"closed","initial":false,"terminal":true,"visibility":"internal","actions":[]}
    ]`)
	transitions := []byte(`[
      {"key":"close","from":"new","to":"closed","requiredComment":false,"reopen":false,
       "requiredRoles":[],"requiredPermissions":[],"requiredCustomFields":[],"effects":["activity","audit"]}
    ]`)
	id := uuid.MustParse("00000000-0000-7000-8000-000000000806")
	workflow, err := mapTicketWorkflow(id, kernel.AggregateAlert, 1, states, transitions)
	if err != nil {
		t.Fatal(err)
	}
	overflow, err := kernel.NewWorkflowDefinition(
		workflow.ID(), workflow.Kind(), uint64(math.MaxInt32)+1, workflow.States(), workflow.Transitions(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := marshalTicketWorkflow(overflow); err == nil {
		t.Fatal("database integer overflow was accepted")
	}
}

func TestMapTicketWorkflowKeepsLegacyVersionsUnconditional(t *testing.T) {
	states := []byte(`[
      {"key":"new","initial":true,"terminal":false,"visibility":"internal","actions":[{"action":"create","effects":["activity","audit"]}]},
      {"key":"closed","initial":false,"terminal":true,"visibility":"internal","actions":[]}
    ]`)
	transitions := []byte(`[
      {"key":"close","from":"new","to":"closed","requiredComment":false,"reopen":false,
       "requiredRoles":[],"requiredPermissions":[],"requiredCustomFields":[],"effects":["activity","audit"]}
    ]`)
	workflow, err := mapTicketWorkflow(
		uuid.MustParse("00000000-0000-7000-8000-000000000803"),
		kernel.AggregateAlert, 1, states, transitions,
	)
	if err != nil {
		t.Fatal(err)
	}
	condition := workflow.Transitions()[0].Condition()
	facts, _ := kernel.NewConditionFacts()
	if condition.Configured() || !condition.Evaluate(facts) {
		t.Fatal("legacy transition did not remain explicitly unconditional")
	}
}

func TestMapWorkflowAdminCommandSnapshotIsStrictAndStable(t *testing.T) {
	tenantID := uuid.MustParse("00000000-0000-7000-8000-000000000807")
	workflowID := uuid.MustParse("00000000-0000-7000-8000-000000000808")
	createdAt := time.Date(2026, 8, 26, 9, 0, 0, 0, time.UTC)
	states, transitions := workflowAdminTestDocuments()
	fixture := func() map[string]any {
		return map[string]any{
			"schemaVersion": 1, "action": "create", "workflowId": workflowID,
			"aggregateKind": "alert", "key": "alert_response", "displayName": "Alert response",
			"description": "Original replay projection", "isDefault": false, "status": "active",
			"revision": 1, "currentVersion": 1, "states": json.RawMessage(states),
			"transitions": json.RawMessage(transitions), "createdAt": createdAt, "updatedAt": createdAt,
			"archivedAt": nil,
		}
	}
	encode := func(value map[string]any) []byte {
		t.Helper()
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("marshal workflow replay fixture: %v", err)
		}
		return encoded
	}

	record, err := mapWorkflowAdminCommandSnapshot(
		encode(fixture()), tenantID, "create", workflowID, 1,
	)
	if err != nil {
		t.Fatalf("mapWorkflowAdminCommandSnapshot() error = %v", err)
	}
	if record.Workflow.Description() != "Original replay projection" ||
		record.Workflow.Revision() != 1 || !record.UpdatedAt.Equal(createdAt) {
		t.Fatalf("mapped replay snapshot = %+v", record)
	}

	unknown := fixture()
	unknown["providerToken"] = "must never pass through"
	archivedWithoutInstant := fixture()
	archivedWithoutInstant["status"] = "archived"
	for name, test := range map[string]struct {
		encoded  []byte
		action   string
		revision int64
	}{
		"unknown field": {encoded: encode(unknown), action: "create", revision: 1},
		"action drift":  {encoded: encode(fixture()), action: "publish", revision: 1},
		"revision drift": {
			encoded: encode(fixture()), action: "create", revision: 2,
		},
		"archive shape": {encoded: encode(archivedWithoutInstant), action: "create", revision: 1},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := mapWorkflowAdminCommandSnapshot(
				test.encoded, tenantID, test.action, workflowID, test.revision,
			); err == nil {
				t.Fatal("malformed immutable replay snapshot was accepted")
			}
		})
	}
}
