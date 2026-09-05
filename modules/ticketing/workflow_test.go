package ticketing

import (
	"reflect"
	"testing"
)

func TestWorkflowDefinitionCanonicalAndAggregateSpecific(t *testing.T) {
	alert := alertWorkflowFixture(t)
	if alert.Kind() != AggregateAlert || alert.Version() != 3 || alert.InitialState().String() != "new" {
		t.Fatalf("unexpected alert workflow: %s", alert)
	}
	states := alert.States()
	if got := []string{states[0].Key().String(), states[1].Key().String(), states[2].Key().String()}; !reflect.DeepEqual(got, []string{"closed", "new", "triage"}) {
		t.Fatalf("states are not canonical: %v", got)
	}
	transitions := alert.Transitions()
	gotTransitions := []string{transitions[0].String(), transitions[1].String(), transitions[2].String()}
	if !reflect.DeepEqual(gotTransitions, []string{"new_to_triage:new->triage", "reopen_triage:closed->triage", "triage_to_closed:triage->closed"}) {
		t.Fatalf("transitions are not canonical: %v", gotTransitions)
	}
	if caseWorkflowFixture(t).Kind() != AggregateCase {
		t.Fatal("case workflow lost aggregate kind")
	}
}

func TestWorkflowDefinitionRejectsUnsafeShapes(t *testing.T) {
	basic := mustEffects(t)
	open := mustKey(t, "open")
	closed := mustKey(t, "closed")
	create := mustStateAction(t, ActionCreate, basic)
	link := mustStateAction(t, ActionLink, basic)
	escalate := mustStateAction(t, ActionEscalate, basic)

	state := func(key Key, initial, terminal bool, actions []StateAction) StateDefinition {
		value, err := NewStateDefinition(key, initial, terminal, VisibilityInternal, actions)
		if err != nil {
			t.Fatalf("state fixture: %v", err)
		}
		return value
	}
	transition := func(from, to Key, reopen bool, permissions []Permission) TransitionDefinition {
		key := mustKey(t, from.String()+"_to_"+to.String())
		value, err := NewTransitionDefinition(key, from, to, false, reopen, nil, permissions, nil, basic)
		if err != nil {
			t.Fatalf("transition fixture: %v", err)
		}
		return value
	}

	tests := []struct {
		name        string
		kind        AggregateKind
		states      []StateDefinition
		transitions []TransitionDefinition
	}{
		{
			name:        "two initial states",
			kind:        AggregateAlert,
			states:      []StateDefinition{state(open, true, false, []StateAction{create}), state(closed, true, true, []StateAction{create})},
			transitions: []TransitionDefinition{transition(open, closed, false, nil)},
		},
		{
			name:        "no terminal state",
			kind:        AggregateAlert,
			states:      []StateDefinition{state(open, true, false, []StateAction{create}), state(closed, false, false, nil)},
			transitions: []TransitionDefinition{transition(open, closed, false, nil), transition(closed, open, false, nil)},
		},
		{
			name:        "create absent from initial",
			kind:        AggregateAlert,
			states:      []StateDefinition{state(open, true, false, nil), state(closed, false, true, nil)},
			transitions: []TransitionDefinition{transition(open, closed, false, nil)},
		},
		{
			name:        "terminal edge not marked reopen",
			kind:        AggregateAlert,
			states:      []StateDefinition{state(open, true, false, []StateAction{create}), state(closed, false, true, nil)},
			transitions: []TransitionDefinition{transition(open, closed, false, nil), transition(closed, open, false, nil)},
		},
		{
			name:        "alert contains case link action",
			kind:        AggregateAlert,
			states:      []StateDefinition{state(open, true, false, []StateAction{create, link}), state(closed, false, true, nil)},
			transitions: []TransitionDefinition{transition(open, closed, false, nil)},
		},
		{
			name:        "case contains alert escalation action",
			kind:        AggregateCase,
			states:      []StateDefinition{state(open, true, false, []StateAction{create, escalate}), state(closed, false, true, nil)},
			transitions: []TransitionDefinition{transition(open, closed, false, nil)},
		},
		{
			name:        "case transition requires alert permission",
			kind:        AggregateCase,
			states:      []StateDefinition{state(open, true, false, []StateAction{create}), state(closed, false, true, nil)},
			transitions: []TransitionDefinition{transition(open, closed, false, []Permission{PermissionAlertUpdate})},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewWorkflowDefinition(fixtureID(50), test.kind, 1, test.states, test.transitions); err == nil {
				t.Fatal("unsafe workflow accepted")
			}
		})
	}
}

func TestWorkflowDefinitionsOwnTheirSlices(t *testing.T) {
	workflow := alertWorkflowFixture(t)
	states := workflow.States()
	states[1].actions[0].action = ActionLink
	transitions := workflow.Transitions()
	transitions[0].requiredRoles[0] = mustKey(t, "different_role")
	if workflow.States()[1].Actions()[0].Action() == ActionLink {
		t.Fatal("state getter exposed internal storage")
	}
	if workflow.Transitions()[0].RequiredRoles()[0].String() != "senior_analyst" {
		t.Fatal("transition getter exposed internal storage")
	}
}

func TestWorkflowDefinitionRejectsDuplicateTransitionKeysAndEdges(t *testing.T) {
	basic := mustEffects(t)
	open := mustKey(t, "open")
	closed := mustKey(t, "closed")
	create := mustStateAction(t, ActionCreate, basic)
	openState, _ := NewStateDefinition(open, true, false, VisibilityInternal, []StateAction{create})
	closedState, _ := NewStateDefinition(closed, false, true, VisibilityInternal, nil)
	key := mustKey(t, "close")
	first, _ := NewTransitionDefinition(key, open, closed, false, false, nil, nil, nil, basic)
	duplicateKey, _ := NewTransitionDefinition(key, closed, open, false, true, nil, nil, nil, basic)
	duplicateEdge, _ := NewTransitionDefinition(mustKey(t, "close_again"), open, closed, false, false, nil, nil, nil, basic)

	for name, transitions := range map[string][]TransitionDefinition{
		"key":  {first, duplicateKey},
		"edge": {first, duplicateEdge},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewWorkflowDefinition(fixtureID(60), AggregateAlert, 1, []StateDefinition{openState, closedState}, transitions); err == nil {
				t.Fatal("ambiguous transition workflow accepted")
			}
		})
	}
}

func TestEffectPlanIsClosedAndCanonical(t *testing.T) {
	plan, err := NewEffectPlan(EffectNotification, EffectAudit, EffectActivity, EffectSLA)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := plan.Effects(), []Effect{EffectActivity, EffectAudit, EffectSLA, EffectNotification}; !reflect.DeepEqual(got, want) {
		t.Fatalf("effects = %v, want %v", got, want)
	}
	for _, effects := range [][]Effect{
		{EffectActivity},
		{EffectActivity, EffectSLA},
		{EffectActivity, EffectAudit, EffectAudit},
		{EffectActivity, EffectAudit, Effect(255)},
	} {
		if _, err := NewEffectPlan(effects...); err == nil {
			t.Fatalf("unsafe effects accepted: %v", effects)
		}
	}
}
