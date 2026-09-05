package sla

import (
	"errors"
	"testing"
	"time"
)

func TestPolicyOverrideChangesWholeAggregateByStableMetricKey(t *testing.T) {
	createdAt := time.Date(2026, 8, 25, 8, 0, 0, 0, time.UTC)
	first := mustMetricDefinition(t, elapsedMetricInput())
	secondInput := elapsedMetricInput()
	secondInput.ID = fixtureID(300)
	secondInput.Key = mustKey("resolution")
	secondInput.Label = "Resolution"
	secondInput.StartEvent = mustKey("ticket.created")
	secondInput.CompletionEvent = mustKey("ticket.resolved")
	second := mustMetricDefinition(t, secondInput)
	currentPolicy := policyWithMetrics(t, 301, "current_multi", 1, first, second)
	slaInstanceID := fixtureID(302)
	current := []MetricWork{
		{Instance: startedPolicyMetric(t, fixtureID(303), slaInstanceID, currentPolicy, first, createdAt)},
		{Instance: startedPolicyMetric(t, fixtureID(304), slaInstanceID, currentPolicy, second, createdAt)},
	}

	firstReplacementInput := first.Input()
	firstReplacementInput.ID = fixtureID(305)
	firstReplacementInput.Duration = 8 * time.Hour
	firstReplacement := mustMetricDefinition(t, firstReplacementInput)
	secondReplacementInput := second.Input()
	secondReplacementInput.ID = fixtureID(306)
	secondReplacementInput.Duration = 12 * time.Hour
	secondReplacement := mustMetricDefinition(t, secondReplacementInput)
	replacement := policyWithMetrics(t, 307, "replacement_multi", 2, firstReplacement, secondReplacement)
	overrideAt := createdAt.Add(time.Hour)
	command := OverrideCommand{
		ID: fixtureID(308), TenantID: fixtureID(1), ObjectID: fixtureID(309), ActorID: fixtureID(9),
		Kind: OverrideChangePolicy, Reason: "Approved aggregate policy replacement", OccurredAt: overrideAt,
		NewPolicyID: replacement.ID(), NewPolicyVersion: replacement.Version(), SimulationDigest: [32]byte{1},
	}
	authority := overrideAuthorityFixture(command)
	plan, err := PlanPolicyOverride(PolicyOverrideInput{
		Metrics: current, ReplacementPolicy: replacement, Command: command, Authority: authority,
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.SLAInstanceID() != slaInstanceID || plan.PreviousPolicyID() != currentPolicy.ID() ||
		plan.PreviousPolicyVersion() != currentPolicy.Version() || len(plan.Metrics()) != 2 ||
		len(plan.Records()) != 2 || len(plan.MaterializationPlan().Metrics()) != 2 {
		t.Fatalf("policy override=%#v", plan)
	}
	seenKeys := make(map[string]struct{})
	for _, work := range plan.Metrics() {
		instance := work.Instance
		if instance.SLAInstanceID() != slaInstanceID || instance.PolicyID() != replacement.ID() ||
			instance.PolicyVersion() != replacement.Version() || instance.Version() != 3 {
			t.Fatalf("replacement instance=%#v", instance)
		}
		seenKeys[instance.Definition().Key().String()] = struct{}{}
	}
	if len(seenKeys) != 2 {
		t.Fatalf("replacement stable keys=%v", seenKeys)
	}
}

func TestPolicyOverrideRejectsPartialMetricShapeAndMixedAggregate(t *testing.T) {
	createdAt := time.Date(2026, 8, 25, 8, 0, 0, 0, time.UTC)
	metric := mustMetricDefinition(t, elapsedMetricInput())
	currentPolicy := policyWithMetrics(t, 310, "current_single", 1, metric)
	current := []MetricWork{{Instance: startedPolicyMetric(
		t, fixtureID(311), fixtureID(312), currentPolicy, metric, createdAt,
	)}}
	replacementInput := metric.Input()
	replacementInput.ID = fixtureID(313)
	replacementInput.Key = mustKey("renamed_metric")
	replacement := policyWithMetrics(t, 314, "renamed_policy", 2, mustMetricDefinition(t, replacementInput))
	command := OverrideCommand{
		ID: fixtureID(315), TenantID: fixtureID(1), ObjectID: fixtureID(309), ActorID: fixtureID(9),
		Kind: OverrideChangePolicy, Reason: "Rejected partial policy replacement",
		OccurredAt: createdAt.Add(time.Hour), NewPolicyID: replacement.ID(),
		NewPolicyVersion: replacement.Version(), SimulationDigest: [32]byte{1},
	}
	if _, err := PlanPolicyOverride(PolicyOverrideInput{
		Metrics: current, ReplacementPolicy: replacement, Command: command,
		Authority: overrideAuthorityFixture(command),
	}); !errors.Is(err, ErrInvalidOverride) {
		t.Fatalf("renamed metric policy error=%v", err)
	}

	duplicate := current[0]
	snapshot := duplicate.Instance.Snapshot()
	snapshot.ID = fixtureID(316)
	snapshot.SLAInstanceID = fixtureID(317)
	foreign, err := RestoreMetricInstance(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	current = append(current, MetricWork{Instance: foreign})
	if _, err := PlanPolicyOverride(PolicyOverrideInput{
		Metrics: current, ReplacementPolicy: replacement, Command: command,
		Authority: overrideAuthorityFixture(command),
	}); !errors.Is(err, ErrInvalidMetric) {
		t.Fatalf("mixed aggregate policy error=%v", err)
	}
}

func policyWithMetrics(
	t *testing.T,
	sequence uint16,
	key string,
	version uint64,
	metrics ...MetricDefinition,
) Policy {
	t.Helper()
	return mustPolicy(t, PolicyInput{
		ID: fixtureID(sequence), TenantID: fixtureID(1), Key: mustKey(key), Name: "Multi metric policy",
		Version: version, Priority: 10, ObjectTypes: []ObjectType{ObjectCase},
		MatchRule: mustRule(t, &RuleInput{Kind: RuleAll}), Metrics: metrics,
		EffectiveFrom: time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC), Enabled: true,
	})
}

func startedPolicyMetric(
	t *testing.T,
	id EntityID,
	slaInstanceID EntityID,
	policy Policy,
	definition MetricDefinition,
	createdAt time.Time,
) MetricInstance {
	t.Helper()
	instance, err := NewMetricInstance(MetricInstanceInput{
		ID: id, SLAInstanceID: slaInstanceID, TenantID: policy.TenantID(), ObjectType: ObjectCase,
		ObjectID: fixtureID(309), PolicyID: policy.ID(), PolicyVersion: policy.Version(),
		Definition: definition, CreatedAt: createdAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	instance, changed, err := instance.ApplyEvent(instance.Version(), MetricEvent{
		ID: fixtureID(uint16(320) + uint16(id.Bytes()[15])), TenantID: policy.TenantID(),
		ObjectID: fixtureID(309), Key: definition.StartEvent(), OccurredAt: createdAt,
	}, nil)
	if err != nil || !changed {
		t.Fatalf("start changed=%t error=%v", changed, err)
	}
	return instance
}
