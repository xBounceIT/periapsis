package ticketing

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestWorkflowSimulatorExplainsEveryRequirementFailClosed(t *testing.T) {
	workflow := conditionalSimulationWorkflow(t)
	state := mustKey(t, "new")
	severityField, _ := NewConditionField("severity")
	low, _ := NewTextConditionValue("confidential-severity")
	severityFact, _ := NewConditionFact(severityField, low)
	facts, _ := NewConditionFacts(severityFact)
	scenario, err := NewWorkflowSimulationScenario(state, false, nil, nil, nil, facts)
	if err != nil {
		t.Fatal(err)
	}
	results, err := SimulateWorkflow(workflow, scenario)
	if err != nil {
		t.Fatalf("SimulateWorkflow: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("result count = %d, want 1", len(results))
	}
	result := results[0]
	if result.Eligible() || result.CommentSatisfied() || result.RoleSatisfied() ||
		result.PermissionsSatisfied() || result.CustomFieldsSatisfied() || result.ConditionSatisfied() {
		t.Fatalf("incomplete scenario was not denied: %s", result)
	}
	if got := keyStrings(result.MissingRoles()); !slices.Equal(got, []string{"senior_analyst"}) {
		t.Fatalf("missing roles = %v", got)
	}
	if got := permissionStrings(result.MissingPermissions()); !slices.Equal(got, []string{"alert.update"}) {
		t.Fatalf("missing permissions = %v", got)
	}
	if got := keyStrings(result.MissingCustomFields()); !slices.Equal(got, []string{"classification"}) {
		t.Fatalf("missing fields = %v", got)
	}
	if rendered := scenario.String(); !strings.Contains(rendered, "facts:[REDACTED]") || strings.Contains(rendered, "confidential-severity") {
		t.Fatalf("scenario formatting leaked facts: %q", rendered)
	}
}

func TestWorkflowSimulatorInjectsAuthoritativeKindAndStateFacts(t *testing.T) {
	workflow := conditionalSimulationWorkflow(t)
	severityField, _ := NewConditionField("severity")
	high, _ := NewTextConditionValue("high")
	severityFact, _ := NewConditionFact(severityField, high)
	facts, _ := NewConditionFacts(severityFact)
	scenario, err := NewWorkflowSimulationScenario(
		mustKey(t, "new"), true, []Key{mustKey(t, "senior_analyst")},
		[]Permission{PermissionAlertUpdate}, []Key{mustKey(t, "classification")}, facts,
	)
	if err != nil {
		t.Fatal(err)
	}
	results, err := SimulateWorkflow(workflow, scenario)
	if err != nil || len(results) != 1 || !results[0].Eligible() || !results[0].ConditionSatisfied() {
		t.Fatalf("complete scenario = %#v, %v", results, err)
	}

	stateField, _ := NewConditionField("state")
	wrongState, _ := NewTextConditionValue("closed")
	wrongStateFact, _ := NewConditionFact(stateField, wrongState)
	driftedFacts, _ := NewConditionFacts(severityFact, wrongStateFact)
	drifted, _ := NewWorkflowSimulationScenario(
		mustKey(t, "new"), true, []Key{mustKey(t, "senior_analyst")},
		[]Permission{PermissionAlertUpdate}, []Key{mustKey(t, "classification")}, driftedFacts,
	)
	if _, err = SimulateWorkflow(workflow, drifted); !errors.Is(err, ErrInvalidWorkflowSimulation) {
		t.Fatalf("state drift error = %v", err)
	}
}

func TestWorkflowSimulatorIsDeterministicAndDoesNotGrantAuthority(t *testing.T) {
	workflow := simulationWorkflowWithTwoOutgoingTransitions(t)
	scenario, err := NewWorkflowSimulationScenario(
		mustKey(t, "new"), true, []Key{mustKey(t, "senior_analyst")},
		[]Permission{PermissionAlertUpdate}, []Key{mustKey(t, "classification")}, ConditionFacts{},
	)
	if err != nil {
		t.Fatal(err)
	}
	first, err := SimulateWorkflow(workflow, scenario)
	if err != nil {
		t.Fatal(err)
	}
	second, err := SimulateWorkflow(workflow, scenario)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 2 || first[0].Key().String() != "direct_close" || first[1].Key().String() != "new_to_triage" {
		t.Fatalf("results are not key-sorted: %v", transitionSimulationKeys(first))
	}
	if !slices.Equal(transitionSimulationKeys(first), transitionSimulationKeys(second)) {
		t.Fatal("repeated simulation changed order")
	}
	// Simulation carries no tenant, actor, or authorization snapshot by design.
	if _, err := NewAuthorizationSnapshot(
		EntityID{}, EntityID{}, PrincipalOperator, true, scenario.Roles(), scenario.Permissions(), nil, nil, nil,
	); !errors.Is(err, ErrInvalidAuthority) {
		t.Fatalf("hypothetical scenario unexpectedly created authority: %v", err)
	}
}

func TestWorkflowSimulatorRejectsUnknownStateAndHostileDerivedFacts(t *testing.T) {
	workflow := alertWorkflowFixture(t)
	unknown, _ := NewWorkflowSimulationScenario(mustKey(t, "unknown"), false, nil, nil, nil, ConditionFacts{})
	if _, err := SimulateWorkflow(workflow, unknown); !errors.Is(err, ErrInvalidWorkflowSimulation) {
		t.Fatalf("unknown state error = %v", err)
	}

	kindField, _ := NewConditionField("aggregate_kind")
	wrongKind, _ := NewTextConditionValue("case")
	wrongKindFact, _ := NewConditionFact(kindField, wrongKind)
	facts, _ := NewConditionFacts(wrongKindFact)
	drifted, _ := NewWorkflowSimulationScenario(mustKey(t, "new"), false, nil, nil, nil, facts)
	if _, err := SimulateWorkflow(workflow, drifted); !errors.Is(err, ErrInvalidWorkflowSimulation) {
		t.Fatalf("aggregate kind drift error = %v", err)
	}

	crossKind, _ := NewWorkflowSimulationScenario(
		mustKey(t, "new"), false, nil, []Permission{PermissionCaseUpdate}, nil, ConditionFacts{},
	)
	if _, err := SimulateWorkflow(workflow, crossKind); !errors.Is(err, ErrInvalidWorkflowSimulation) {
		t.Fatalf("cross-kind hypothetical permission error = %v", err)
	}
}

func FuzzWorkflowSimulationRejectsHostileKeys(f *testing.F) {
	for _, seed := range []string{"", "new", " closed", "a/b", "\u202eadmin", "A", string([]byte{0xff})} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		workflow := alertWorkflowFixture(t)
		key, keyErr := NewKey(value)
		if keyErr != nil {
			return
		}
		scenario, scenarioErr := NewWorkflowSimulationScenario(key, false, nil, nil, nil, ConditionFacts{})
		if scenarioErr != nil {
			return
		}
		results, err := SimulateWorkflow(workflow, scenario)
		if value != "new" && value != "triage" && value != "closed" {
			if !errors.Is(err, ErrInvalidWorkflowSimulation) || results != nil {
				t.Fatalf("unknown state %q returned %#v, %v", value, results, err)
			}
		}
	})
}

func conditionalSimulationWorkflow(t testing.TB) WorkflowDefinition {
	t.Helper()
	base := alertWorkflowFixture(t)
	severity, _ := NewConditionField("severity")
	high, _ := NewTextConditionValue("high")
	severityPredicate, _ := NewConditionPredicate(severity, ConditionEqual, high)
	severityNode, _ := NewPredicateConditionNode(severityPredicate)
	state, _ := NewConditionField("state")
	newValue, _ := NewTextConditionValue("new")
	statePredicate, _ := NewConditionPredicate(state, ConditionEqual, newValue)
	stateNode, _ := NewPredicateConditionNode(statePredicate)
	kind, _ := NewConditionField("aggregate_kind")
	alertValue, _ := NewTextConditionValue("alert")
	kindPredicate, _ := NewConditionPredicate(kind, ConditionEqual, alertValue)
	kindNode, _ := NewPredicateConditionNode(kindPredicate)
	all, _ := NewAllConditionNode(severityNode, stateNode, kindNode)
	condition, _ := NewCondition(all)
	transitions := base.Transitions()
	for index, transition := range transitions {
		if transition.Key().String() != "new_to_triage" {
			continue
		}
		changed, err := NewConditionalTransitionDefinition(
			transition.Key(), transition.From(), transition.To(), transition.RequiredComment(), transition.Reopen(),
			transition.RequiredRoles(), transition.RequiredPermissions(), transition.RequiredCustomFields(),
			condition, transition.Effects(),
		)
		if err != nil {
			t.Fatal(err)
		}
		transitions[index] = changed
	}
	workflow, err := NewWorkflowDefinition(base.ID(), base.Kind(), base.Version(), base.States(), transitions)
	if err != nil {
		t.Fatal(err)
	}
	return workflow
}

func simulationWorkflowWithTwoOutgoingTransitions(t testing.TB) WorkflowDefinition {
	t.Helper()
	base := alertWorkflowFixture(t)
	direct, err := NewTransitionDefinition(
		mustKey(t, "direct_close"), mustKey(t, "new"), mustKey(t, "closed"), false, false,
		nil, nil, nil, mustEffects(t),
	)
	if err != nil {
		t.Fatal(err)
	}
	transitions := append(base.Transitions(), direct)
	workflow, err := NewWorkflowDefinition(base.ID(), base.Kind(), base.Version(), base.States(), transitions)
	if err != nil {
		t.Fatal(err)
	}
	return workflow
}

func keyStrings(keys []Key) []string {
	result := make([]string, len(keys))
	for index, key := range keys {
		result[index] = key.String()
	}
	return result
}

func permissionStrings(permissions []Permission) []string {
	result := make([]string, len(permissions))
	for index, permission := range permissions {
		result[index] = permission.String()
	}
	return result
}

func transitionSimulationKeys(results []TransitionSimulation) []string {
	keys := make([]string, len(results))
	for index, result := range results {
		keys[index] = result.Key().String()
	}
	return keys
}
