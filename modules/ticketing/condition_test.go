package ticketing

import (
	"math"
	"strings"
	"testing"
	"time"
)

func TestConditionEvaluatesBoundedTypedFacts(t *testing.T) {
	severity := mustConditionField(t, "severity")
	risk := mustConditionField(t, "custom.risk_score")
	assigned := mustConditionField(t, "assigned")
	classification := mustConditionField(t, "classification")

	high := mustTextConditionValue(t, "high")
	critical := mustTextConditionValue(t, "critical")
	threshold := mustNumberConditionValue(t, 7)

	severityPredicate := mustConditionPredicate(t, severity, ConditionIn, critical, high)
	riskPredicate := mustConditionPredicate(t, risk, ConditionGreaterThanOrEqual, threshold)
	assignedPredicate := mustConditionPredicate(t, assigned, ConditionEqual, NewBooleanConditionValue(true))
	classificationPredicate := mustConditionPredicate(t, classification, ConditionNotExists)

	severityNode := mustPredicateConditionNode(t, severityPredicate)
	riskNode := mustPredicateConditionNode(t, riskPredicate)
	assignedNode := mustPredicateConditionNode(t, assignedPredicate)
	classificationNode := mustPredicateConditionNode(t, classificationPredicate)
	any, err := NewAnyConditionNode(severityNode, riskNode)
	if err != nil {
		t.Fatal(err)
	}
	all, err := NewAllConditionNode(any, assignedNode, classificationNode)
	if err != nil {
		t.Fatal(err)
	}
	condition, err := NewCondition(all)
	if err != nil {
		t.Fatal(err)
	}

	facts := mustConditionFacts(t,
		mustConditionFact(t, severity, high),
		mustConditionFact(t, risk, mustNumberConditionValue(t, 2)),
		mustConditionFact(t, assigned, NewBooleanConditionValue(true)),
	)
	if !condition.Evaluate(facts) {
		t.Fatal("valid declarative condition evaluated false")
	}

	wrongType := ConditionFacts{items: []ConditionFact{{field: severity, value: threshold, hasValue: true}}}
	if condition.Evaluate(wrongType) {
		t.Fatal("forged fact type was accepted")
	}
}

func TestConditionNegativeComparisonsFailClosedWhenFactMissing(t *testing.T) {
	field := mustConditionField(t, "severity")
	value := mustTextConditionValue(t, "low")
	empty := mustConditionFacts(t)

	for _, operator := range []ConditionOperator{ConditionNotEqual, ConditionNotIn} {
		predicate := mustConditionPredicate(t, field, operator, value)
		condition := mustCondition(t, mustPredicateConditionNode(t, predicate))
		if condition.Evaluate(empty) {
			t.Fatalf("%s treated a missing fact as a match", operator)
		}
	}

	notExists := mustCondition(t, mustPredicateConditionNode(t,
		mustConditionPredicate(t, field, ConditionNotExists),
	))
	if !notExists.Evaluate(empty) {
		t.Fatal("explicit not_exists did not match an absent fact")
	}

	equal := mustPredicateConditionNode(t, mustConditionPredicate(t, field, ConditionEqual, value))
	negated, err := NewNotConditionNode(equal)
	if err != nil {
		t.Fatal(err)
	}
	if mustCondition(t, negated).Evaluate(empty) {
		t.Fatal("not converted an indeterminate missing fact into a match")
	}

	presence, err := NewPresenceConditionFact(field)
	if err != nil {
		t.Fatal(err)
	}
	opaque := mustConditionFacts(t, presence)
	if !mustCondition(t, mustPredicateConditionNode(t,
		mustConditionPredicate(t, field, ConditionExists),
	)).Evaluate(opaque) {
		t.Fatal("present non-scalar fact was treated as absent")
	}
	if notExists.Evaluate(opaque) || mustCondition(t, negated).Evaluate(opaque) {
		t.Fatal("non-scalar fact satisfied an absence or negated comparison")
	}
}

func TestConditionRejectsExecutableAndUnboundedShapes(t *testing.T) {
	for _, field := range []string{"severity;drop table", "custom.__bad", "script", "tag.x()"} {
		if _, err := NewConditionField(field); err == nil {
			t.Fatalf("unsafe condition field %q was accepted", field)
		}
	}
	if _, err := NewNumberConditionValue(math.NaN()); err == nil {
		t.Fatal("NaN condition value was accepted")
	}
	if _, err := NewTextConditionValue(strings.Repeat("a", maxConditionTextBytes+1)); err == nil {
		t.Fatal("oversized condition value was accepted")
	}
	field := mustConditionField(t, "severity")
	if _, err := NewConditionPredicate(field, ConditionGreaterThan, mustTextConditionValue(t, "high")); err == nil {
		t.Fatal("ordering a text condition was accepted")
	}

	values := make([]ConditionValue, maxConditionValues+1)
	for index := range values {
		values[index] = mustNumberConditionValue(t, float64(index))
	}
	custom := mustConditionField(t, "custom.score")
	if _, err := NewConditionPredicate(custom, ConditionIn, values...); err == nil {
		t.Fatal("oversized membership condition was accepted")
	}

	node := mustPredicateConditionNode(t, mustConditionPredicate(t, field, ConditionExists))
	for depth := 0; depth < maxConditionDepth; depth++ {
		var err error
		node, err = NewNotConditionNode(node)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := NewCondition(node); err == nil {
		t.Fatal("condition deeper than the sandbox limit was accepted")
	}

	leaf := mustPredicateConditionNode(t, mustConditionPredicate(t, field, ConditionExists))
	groups := make([]ConditionNode, 5)
	for groupIndex := range groups {
		leaves := make([]ConditionNode, maxConditionChildren)
		for index := range leaves {
			leaves[index] = leaf
		}
		groups[groupIndex], _ = NewAllConditionNode(leaves...)
	}
	overNodeLimit, err := NewAnyConditionNode(groups...)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewCondition(overNodeLimit); err == nil {
		t.Fatal("condition over the total node limit was accepted")
	}
}

func TestConditionOwnsEveryRecursiveSlice(t *testing.T) {
	field := mustConditionField(t, "severity")
	value := mustTextConditionValue(t, "high")
	predicate := mustConditionPredicate(t, field, ConditionEqual, value)
	first := mustPredicateConditionNode(t, predicate)
	second := mustPredicateConditionNode(t, mustConditionPredicate(t, field, ConditionExists))
	root, err := NewAllConditionNode(first, second)
	if err != nil {
		t.Fatal(err)
	}
	condition := mustCondition(t, root)

	children := root.Children()
	children[0].predicate.values[0].text = "critical"
	returnedRoot, ok := condition.Root()
	if !ok {
		t.Fatal("configured condition lost its root")
	}
	returnedRoot.children[0].predicate.values[0].text = "low"

	facts := mustConditionFacts(t, mustConditionFact(t, field, value))
	if !condition.Evaluate(facts) {
		t.Fatal("caller mutation changed the immutable condition")
	}
}

func TestConditionalTransitionIsEnforcedByTheCommandKernel(t *testing.T) {
	field := mustConditionField(t, "severity")
	high := mustTextConditionValue(t, "high")
	condition := mustCondition(t, mustPredicateConditionNode(t,
		mustConditionPredicate(t, field, ConditionEqual, high),
	))

	open := mustKey(t, "open")
	closed := mustKey(t, "closed")
	effects := mustEffects(t)
	openState, err := NewStateDefinition(open, true, false, VisibilityInternal, []StateAction{
		mustStateAction(t, ActionCreate, effects),
	})
	if err != nil {
		t.Fatal(err)
	}
	closedState, err := NewStateDefinition(closed, false, true, VisibilityInternal, nil)
	if err != nil {
		t.Fatal(err)
	}
	transitionKey := mustKey(t, "close")
	transition, err := NewConditionalTransitionDefinition(
		transitionKey, open, closed, false, false, nil, nil, nil, condition, effects,
	)
	if err != nil {
		t.Fatal(err)
	}
	workflow, err := NewWorkflowDefinition(
		fixtureID(700), AggregateAlert, 1,
		[]StateDefinition{openState, closedState}, []TransitionDefinition{transition},
	)
	if err != nil {
		t.Fatal(err)
	}
	returnedTransitions := workflow.Transitions()
	returnedTransitions[0].condition.root.predicate.values = []ConditionValue{mustTextConditionValue(t, "low")}
	ticket := mustTicket(t, workflow, fixtureID(701), "open", 1, false, Assignment{})
	command, err := NewTransitionCommand(
		fixtureID(1), ticket.ID(), 1, transitionKey, closed, nil, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	authority := authorityFixture(t, fixtureID(702))

	if decision := PlanTransition(workflow, ticket, command, authority); decision.Reason() != ReasonCondition {
		t.Fatalf("transition without facts = %s/%s, want condition denial", decision.Outcome(), decision.Reason())
	}
	lowFacts := mustConditionFacts(t, mustConditionFact(t, field, mustTextConditionValue(t, "low")))
	if decision := PlanTransitionWithFacts(workflow, ticket, command, authority, lowFacts); decision.Reason() != ReasonCondition {
		t.Fatalf("transition with false facts = %s/%s", decision.Outcome(), decision.Reason())
	}
	highFacts := mustConditionFacts(t, mustConditionFact(t, field, high))
	if decision := PlanTransitionWithFacts(workflow, ticket, command, authority, highFacts); !decision.Allowed() {
		t.Fatalf("transition with matching facts = %s/%s", decision.Outcome(), decision.Reason())
	}
}

func TestInstantConditionValuesAreCanonicalMicrosecondUTC(t *testing.T) {
	input := time.Date(2026, 8, 25, 20, 1, 2, 123456789, time.FixedZone("CEST", 2*60*60))
	value, err := NewInstantConditionValue(input)
	if err != nil {
		t.Fatal(err)
	}
	instant, ok := value.Instant()
	if !ok || instant.Location() != time.UTC || instant.Nanosecond() != 123456000 {
		t.Fatalf("instant = %v, want canonical UTC microseconds", instant)
	}
}

func mustConditionField(t testing.TB, value string) ConditionField {
	t.Helper()
	field, err := NewConditionField(value)
	if err != nil {
		t.Fatalf("NewConditionField(%q): %v", value, err)
	}
	return field
}

func mustTextConditionValue(t testing.TB, value string) ConditionValue {
	t.Helper()
	result, err := NewTextConditionValue(value)
	if err != nil {
		t.Fatalf("NewTextConditionValue(%q): %v", value, err)
	}
	return result
}

func mustNumberConditionValue(t testing.TB, value float64) ConditionValue {
	t.Helper()
	result, err := NewNumberConditionValue(value)
	if err != nil {
		t.Fatalf("NewNumberConditionValue(%v): %v", value, err)
	}
	return result
}

func mustConditionPredicate(
	t testing.TB,
	field ConditionField,
	operator ConditionOperator,
	values ...ConditionValue,
) ConditionPredicate {
	t.Helper()
	predicate, err := NewConditionPredicate(field, operator, values...)
	if err != nil {
		t.Fatalf("NewConditionPredicate(%s, %s): %v", field, operator, err)
	}
	return predicate
}

func mustPredicateConditionNode(t testing.TB, predicate ConditionPredicate) ConditionNode {
	t.Helper()
	node, err := NewPredicateConditionNode(predicate)
	if err != nil {
		t.Fatalf("NewPredicateConditionNode: %v", err)
	}
	return node
}

func mustCondition(t testing.TB, root ConditionNode) Condition {
	t.Helper()
	condition, err := NewCondition(root)
	if err != nil {
		t.Fatalf("NewCondition: %v", err)
	}
	return condition
}

func mustConditionFact(t testing.TB, field ConditionField, value ConditionValue) ConditionFact {
	t.Helper()
	fact, err := NewConditionFact(field, value)
	if err != nil {
		t.Fatalf("NewConditionFact(%s): %v", field, err)
	}
	return fact
}

func mustConditionFacts(t testing.TB, facts ...ConditionFact) ConditionFacts {
	t.Helper()
	result, err := NewConditionFacts(facts...)
	if err != nil {
		t.Fatalf("NewConditionFacts: %v", err)
	}
	return result
}
