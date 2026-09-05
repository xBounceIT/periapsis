package sla

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestDeclarativeRuleMatchesTypedFactsAndDerivedLocalTime(t *testing.T) {
	snapshot := mustFactSnapshot(t, FactSnapshotInput{
		TenantID: fixtureID(1), ObjectType: ObjectAlert,
		EvaluatedAt: time.Date(2026, 8, 25, 14, 0, 0, 0, time.UTC), Timezone: "Europe/Rome",
		Facts: []FactInput{
			{Path: FactPath{Kind: FactCustomerTier}, Values: []string{"gold"}},
			{Path: FactPath{Kind: FactSeverity}, Values: []string{"critical"}},
			{Path: FactPath{Kind: FactTag}, Values: []string{"ransomware", "malware"}},
			{Path: FactPath{Kind: FactSource}, Values: []string{"edr"}},
			{Path: FactPath{Kind: FactCustomField, Key: mustKey("region")}, Values: []string{"emea"}},
		},
	})
	rule := mustRule(t, &RuleInput{Kind: RuleAll, Children: []*RuleInput{
		predicateRule(FactPath{Kind: FactSeverity}, PredicateEquals, "critical"),
		{Kind: RuleAny, Children: []*RuleInput{
			predicateRule(FactPath{Kind: FactTag}, PredicateOneOf, "ransomware", "phishing"),
			predicateRule(FactPath{Kind: FactCustomerTier}, PredicateEquals, "platinum"),
		}},
		{Kind: RuleNot, Children: []*RuleInput{
			predicateRule(FactPath{Kind: FactSource}, PredicateEquals, "sla-engine"),
		}},
		predicateRule(FactPath{Kind: FactLocalHour}, PredicateEquals, "16"),
		predicateRule(FactPath{Kind: FactLocalWeekday}, PredicateEquals, "tuesday"),
		predicateRule(FactPath{Kind: FactCustomField, Key: mustKey("region")}, PredicateEquals, "emea"),
	}})
	if !rule.Matches(snapshot) {
		t.Fatal("valid declarative rule did not match")
	}
	if got := snapshot.Values(FactPath{Kind: FactTag}); len(got) != 2 || got[0] != "malware" || got[1] != "ransomware" {
		t.Fatalf("canonical tags = %#v", got)
	}

	different := mustRule(t, predicateRule(FactPath{Kind: FactPriority}, PredicateExists))
	if different.Matches(snapshot) {
		t.Fatal("missing fact satisfied exists predicate")
	}
}

func TestRuleAndFactSnapshotRejectCyclesSpoofingAndAmbiguity(t *testing.T) {
	cycle := &RuleInput{Kind: RuleNot}
	cycle.Children = []*RuleInput{cycle}
	if _, err := NewRule(cycle); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("cyclic rule error = %v", err)
	}
	if _, err := NewRule(&RuleInput{Kind: RuleAny}); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("empty any error = %v", err)
	}
	if _, err := NewRule(predicateRule(FactPath{Kind: FactSeverity}, PredicateEquals, "critical", "high")); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("multi-valued equals error = %v", err)
	}

	base := FactSnapshotInput{
		TenantID: fixtureID(1), ObjectType: ObjectCase,
		EvaluatedAt: time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC), Timezone: "UTC",
	}
	tests := []FactInput{
		{Path: FactPath{Kind: FactObjectType}, Values: []string{"alert"}},
		{Path: FactPath{Kind: FactLocalHour}, Values: []string{"23"}},
		{Path: FactPath{Kind: FactCustomField}, Values: []string{"missing-key"}},
		{Path: FactPath{Kind: FactOperatorTeam}, Values: []string{strings.ToUpper(fixtureID(9).String())}},
		{Path: FactPath{Kind: FactTag}, Values: []string{"Valid-Tag"}},
	}
	for index, fact := range tests {
		input := base
		input.Facts = []FactInput{fact}
		if _, err := NewFactSnapshot(input); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatalf("unsafe fact %d error = %v", index, err)
		}
	}
	base.Facts = []FactInput{
		{Path: FactPath{Kind: FactSeverity}, Values: []string{"critical"}},
		{Path: FactPath{Kind: FactSeverity}, Values: []string{"high"}},
	}
	if _, err := NewFactSnapshot(base); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("duplicate fact error = %v", err)
	}
}

func TestPolicySelectionIsEffectiveTenantBoundDeterministicAndLoopSafe(t *testing.T) {
	snapshot := mustFactSnapshot(t, FactSnapshotInput{
		TenantID: fixtureID(1), ObjectType: ObjectAlert,
		EvaluatedAt: time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC), Timezone: "UTC",
		Facts: []FactInput{
			{Path: FactPath{Kind: FactSeverity}, Values: []string{"critical"}},
			{Path: FactPath{Kind: FactSource}, Values: []string{"edr"}},
		},
	})
	low := mustPolicy(t, policyInput(60, "default_policy", 10, mustRule(t, &RuleInput{Kind: RuleAll})))
	high := mustPolicy(t, policyInput(61, "critical_policy", 20, mustRule(t,
		predicateRule(FactPath{Kind: FactSeverity}, PredicateEquals, "critical"),
	)))
	selected, err := SelectPolicy([]Policy{low, high}, snapshot)
	if err != nil || selected == nil || selected.ID() != high.ID() {
		t.Fatalf("selected policy = %#v, error=%v", selected, err)
	}

	tiedInput := policyInput(62, "critical_tie", 20, mustRule(t, &RuleInput{Kind: RuleAll}))
	tied := mustPolicy(t, tiedInput)
	if _, err := SelectPolicy([]Policy{high, tied}, snapshot); !errors.Is(err, ErrAmbiguousPolicy) {
		t.Fatalf("equal-priority match error = %v", err)
	}
	veryHigh := mustPolicy(t, policyInput(65, "highest_policy", 30, mustRule(t, &RuleInput{Kind: RuleAll})))
	selected, err = SelectPolicy([]Policy{high, tied, veryHigh}, snapshot)
	if err != nil || selected == nil || selected.ID() != veryHigh.ID() {
		t.Fatalf("lower-priority tie shadowed highest policy=%#v error=%v", selected, err)
	}

	foreignInput := policyInput(63, "foreign", 100, mustRule(t, &RuleInput{Kind: RuleAll}))
	foreignInput.TenantID = fixtureID(2)
	foreign := mustPolicy(t, foreignInput)
	if _, err := SelectPolicy([]Policy{foreign}, snapshot); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("cross-tenant inventory error = %v", err)
	}

	slaSnapshot := mustFactSnapshot(t, FactSnapshotInput{
		TenantID: fixtureID(1), ObjectType: ObjectAlert,
		EvaluatedAt: snapshot.EvaluatedAt(), Timezone: "UTC",
		Facts: []FactInput{{Path: FactPath{Kind: FactSource}, Values: []string{"sla-engine"}}},
	})
	selected, err = SelectPolicy([]Policy{low}, slaSnapshot)
	if err != nil || selected != nil {
		t.Fatalf("recursive source selected policy=%#v error=%v", selected, err)
	}
	loopInput := policyInput(64, "explicit_sla_engine", 30, mustRule(t, &RuleInput{Kind: RuleAll}))
	loopInput.ApplyToSLAEngineSource = true
	loopPolicy := mustPolicy(t, loopInput)
	selected, err = SelectPolicy([]Policy{loopPolicy}, slaSnapshot)
	if err != nil || selected == nil || selected.ID() != loopPolicy.ID() {
		t.Fatalf("explicit recursive policy selection=%#v error=%v", selected, err)
	}
}

func TestPolicyEffectiveWindowIsHalfOpenAndOwnsInputs(t *testing.T) {
	ruleInput := &RuleInput{Kind: RuleAll, Children: []*RuleInput{
		predicateRule(FactPath{Kind: FactSeverity}, PredicateEquals, "critical"),
	}}
	rule := mustRule(t, ruleInput)
	input := policyInput(70, "windowed", 10, rule)
	until := input.EffectiveFrom.Add(time.Hour)
	input.EffectiveUntil = &until
	policy := mustPolicy(t, input)
	ruleInput.Children[0].Predicate.Values[0] = "low"
	until = input.EffectiveFrom

	atEnd := mustFactSnapshot(t, FactSnapshotInput{
		TenantID: fixtureID(1), ObjectType: ObjectAlert,
		EvaluatedAt: input.EffectiveFrom.Add(time.Hour), Timezone: "UTC",
		Facts: []FactInput{{Path: FactPath{Kind: FactSeverity}, Values: []string{"critical"}}},
	})
	if policy.Matches(atEnd) {
		t.Fatal("policy matched at exclusive effectiveUntil boundary")
	}
	atStartInput := FactSnapshotInput{
		TenantID: fixtureID(1), ObjectType: ObjectAlert,
		EvaluatedAt: input.EffectiveFrom, Timezone: "UTC",
		Facts: []FactInput{{Path: FactPath{Kind: FactSeverity}, Values: []string{"critical"}}},
	}
	if !policy.Matches(mustFactSnapshot(t, atStartInput)) {
		t.Fatal("policy did not match at inclusive effectiveFrom boundary or retained caller rule storage")
	}
	for _, rendered := range []string{fmt.Sprint(policy), fmt.Sprintf("%#v", policy), fmt.Sprint(policy.MatchRule())} {
		for _, sensitive := range []string{policy.Key().String(), policy.Name(), "critical"} {
			if strings.Contains(rendered, sensitive) {
				t.Fatalf("policy formatting leaked %q: %q", sensitive, rendered)
			}
		}
	}
}

func predicateRule(path FactPath, operator PredicateOperator, values ...string) *RuleInput {
	return &RuleInput{Kind: RulePredicate, Predicate: PredicateInput{Path: path, Operator: operator, Values: values}}
}

func mustRule(t *testing.T, input *RuleInput) Rule {
	t.Helper()
	rule, err := NewRule(input)
	if err != nil {
		t.Fatal(err)
	}
	return rule
}

func mustFactSnapshot(t *testing.T, input FactSnapshotInput) FactSnapshot {
	t.Helper()
	snapshot, err := NewFactSnapshot(input)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func policyInput(sequence uint16, key string, priority int32, rule Rule) PolicyInput {
	return PolicyInput{
		ID: fixtureID(sequence), TenantID: fixtureID(1), Key: mustKey(key), Name: "Tenant SLA policy",
		Description: "Versioned policy", Version: 3, Priority: priority,
		ObjectTypes: []ObjectType{ObjectCase, ObjectAlert}, MatchRule: rule,
		Metrics:       []MetricDefinition{mustMetricDefinitionNoTest(elapsedMetricInput())},
		EffectiveFrom: time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC), Enabled: true,
	}
}

func mustPolicy(t *testing.T, input PolicyInput) Policy {
	t.Helper()
	policy, err := NewPolicy(input)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func mustMetricDefinitionNoTest(input MetricDefinitionInput) MetricDefinition {
	definition, err := NewMetricDefinition(input)
	if err != nil {
		panic(err)
	}
	return definition
}
