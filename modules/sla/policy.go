package sla

import (
	"context"
	"fmt"
	"slices"
	"time"
)

const maximumPolicyMetrics = 32

type PolicyInput struct {
	ID                     EntityID
	TenantID               EntityID
	Key                    Key
	Name                   string
	Description            string
	Version                uint64
	Priority               int32
	ObjectTypes            []ObjectType
	MatchRule              Rule
	Metrics                []MetricDefinition
	Triggers               []TriggerDefinition
	EffectiveFrom          time.Time
	EffectiveUntil         *time.Time
	Enabled                bool
	ApplyToSLAEngineSource bool
}

type Policy struct {
	id                     EntityID
	tenantID               EntityID
	key                    Key
	name                   string
	description            string
	version                uint64
	priority               int32
	objectTypes            []ObjectType
	matchRule              Rule
	metrics                []MetricDefinition
	triggers               []TriggerDefinition
	effectiveFrom          time.Time
	effectiveUntil         *time.Time
	enabled                bool
	applyToSLAEngineSource bool
}

func NewPolicy(input PolicyInput) (Policy, error) {
	objectTypes, ok := canonicalObjectTypes(input.ObjectTypes)
	if !ok || !validEntityID(input.ID) || !validEntityID(input.TenantID) || !validKey(input.Key.value) ||
		!validText(input.Name, maximumLabelBytes, false, false) ||
		!validText(input.Description, maximumDescription, true, true) ||
		input.Version == 0 || input.Version >= maximumVersion || !validInstant(input.EffectiveFrom) ||
		input.EffectiveUntil != nil && (!validInstant(*input.EffectiveUntil) || !input.EffectiveUntil.After(input.EffectiveFrom)) ||
		!input.MatchRule.valid() || len(input.Metrics) == 0 || len(input.Metrics) > maximumPolicyMetrics {
		return Policy{}, ErrInvalidPolicy
	}
	metrics := make([]MetricDefinition, len(input.Metrics))
	metricIDs := make(map[EntityID]struct{}, len(input.Metrics))
	metricKeys := make(map[Key]struct{}, len(input.Metrics))
	for index, metric := range input.Metrics {
		if !metric.valid() {
			return Policy{}, ErrInvalidPolicy
		}
		if _, duplicate := metricIDs[metric.id]; duplicate {
			return Policy{}, ErrInvalidPolicy
		}
		if _, duplicate := metricKeys[metric.key]; duplicate {
			return Policy{}, ErrInvalidPolicy
		}
		metricIDs[metric.id] = struct{}{}
		metricKeys[metric.key] = struct{}{}
		metrics[index] = metric.clone()
	}
	slices.SortFunc(metrics, func(left, right MetricDefinition) int {
		if left.key.value < right.key.value {
			return -1
		}
		if left.key.value > right.key.value {
			return 1
		}
		return 0
	})
	if len(input.Triggers) > maximumRuleNodes {
		return Policy{}, ErrInvalidPolicy
	}
	triggers := make([]TriggerDefinition, len(input.Triggers))
	triggerIDs := make(map[EntityID]struct{}, len(input.Triggers))
	triggerKeys := make(map[Key]struct{}, len(input.Triggers))
	for index, trigger := range input.Triggers {
		metric, exists := metricDefinitionByID(metrics, trigger.metricID)
		if !exists || !trigger.validFor(metric) {
			return Policy{}, ErrInvalidPolicy
		}
		if _, duplicate := triggerIDs[trigger.id]; duplicate {
			return Policy{}, ErrInvalidPolicy
		}
		if _, duplicate := triggerKeys[trigger.key]; duplicate {
			return Policy{}, ErrInvalidPolicy
		}
		triggerIDs[trigger.id] = struct{}{}
		triggerKeys[trigger.key] = struct{}{}
		triggers[index] = trigger.clone()
	}
	slices.SortFunc(triggers, func(left, right TriggerDefinition) int {
		if left.key.value < right.key.value {
			return -1
		}
		if left.key.value > right.key.value {
			return 1
		}
		return 0
	})
	return Policy{
		id: input.ID, tenantID: input.TenantID, key: input.Key, name: input.Name,
		description: input.Description, version: input.Version, priority: input.Priority,
		objectTypes: objectTypes, matchRule: input.MatchRule.clone(), metrics: metrics, triggers: triggers,
		effectiveFrom: input.EffectiveFrom, effectiveUntil: cloneTime(input.EffectiveUntil),
		enabled: input.Enabled, applyToSLAEngineSource: input.ApplyToSLAEngineSource,
	}, nil
}

func (policy Policy) ID() EntityID              { return policy.id }
func (policy Policy) TenantID() EntityID        { return policy.tenantID }
func (policy Policy) Key() Key                  { return policy.key }
func (policy Policy) Name() string              { return policy.name }
func (policy Policy) Description() string       { return policy.description }
func (policy Policy) Version() uint64           { return policy.version }
func (policy Policy) Priority() int32           { return policy.priority }
func (policy Policy) ObjectTypes() []ObjectType { return slices.Clone(policy.objectTypes) }
func (policy Policy) MatchRule() Rule           { return policy.matchRule.clone() }
func (policy Policy) Metrics() []MetricDefinition {
	result := make([]MetricDefinition, len(policy.metrics))
	for index, metric := range policy.metrics {
		result[index] = metric.clone()
	}
	return result
}
func (policy Policy) Triggers() []TriggerDefinition {
	result := make([]TriggerDefinition, len(policy.triggers))
	for index, trigger := range policy.triggers {
		result[index] = trigger.clone()
	}
	return result
}
func (policy Policy) EffectiveFrom() time.Time     { return policy.effectiveFrom }
func (policy Policy) EffectiveUntil() *time.Time   { return cloneTime(policy.effectiveUntil) }
func (policy Policy) Enabled() bool                { return policy.enabled }
func (policy Policy) ApplyToSLAEngineSource() bool { return policy.applyToSLAEngineSource }
func (policy Policy) String() string {
	return fmt.Sprintf(
		"sla.Policy{version:%d,priority:%d,enabled:%t,metrics:%d,identity:[REDACTED],rule:[REDACTED]}",
		policy.version, policy.priority, policy.enabled, len(policy.metrics),
	)
}
func (policy Policy) GoString() string { return policy.String() }

func (policy Policy) Matches(snapshot FactSnapshot) bool {
	if !policy.valid() || !snapshot.valid() || policy.tenantID != snapshot.tenantID ||
		!slices.Contains(policy.objectTypes, snapshot.objectType) || !policy.enabled ||
		snapshot.evaluatedAt.Before(policy.effectiveFrom) ||
		policy.effectiveUntil != nil && !snapshot.evaluatedAt.Before(*policy.effectiveUntil) {
		return false
	}
	if !policy.applyToSLAEngineSource && slices.Contains(snapshot.values[FactPath{Kind: FactSource}], "sla-engine") {
		return false
	}
	return policy.matchRule.Matches(snapshot)
}

// SelectPolicy fails on equal-precedence matches. Configuration order is never
// used as an implicit tiebreaker because it would make an SLA assignment depend
// on database query order.
func SelectPolicy(policies []Policy, snapshot FactSnapshot) (*Policy, error) {
	return selectPolicyContext(context.Background(), policies, snapshot)
}

func selectPolicyContext(ctx context.Context, policies []Policy, snapshot FactSnapshot) (*Policy, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrEngineCanceled
	}
	if !snapshot.valid() || len(policies) > 1_024 {
		return nil, ErrInvalidPolicy
	}
	var selected *Policy
	ambiguous := false
	seenIDs := make(map[EntityID]struct{}, len(policies))
	seenKeys := make(map[Key]struct{}, len(policies))
	for _, candidate := range policies {
		if ctx.Err() != nil {
			return nil, ErrEngineCanceled
		}
		if !candidate.valid() || candidate.tenantID != snapshot.tenantID {
			return nil, ErrInvalidPolicy
		}
		if _, duplicate := seenIDs[candidate.id]; duplicate {
			return nil, ErrInvalidPolicy
		}
		if _, duplicate := seenKeys[candidate.key]; duplicate {
			return nil, ErrInvalidPolicy
		}
		seenIDs[candidate.id] = struct{}{}
		seenKeys[candidate.key] = struct{}{}
		if !candidate.Matches(snapshot) {
			continue
		}
		if selected == nil || candidate.priority > selected.priority {
			copy := candidate.clone()
			selected = &copy
			ambiguous = false
			continue
		}
		if candidate.priority == selected.priority {
			ambiguous = true
		}
	}
	if ambiguous {
		return nil, ErrAmbiguousPolicy
	}
	return selected, nil
}

func (policy Policy) valid() bool {
	canonical, err := NewPolicy(PolicyInput{
		ID: policy.id, TenantID: policy.tenantID, Key: policy.key, Name: policy.name,
		Description: policy.description, Version: policy.version, Priority: policy.priority,
		ObjectTypes: policy.objectTypes, MatchRule: policy.matchRule, Metrics: policy.metrics, Triggers: policy.triggers,
		EffectiveFrom: policy.effectiveFrom, EffectiveUntil: policy.effectiveUntil,
		Enabled: policy.enabled, ApplyToSLAEngineSource: policy.applyToSLAEngineSource,
	})
	return err == nil && canonical.id == policy.id && canonical.version == policy.version
}

func (policy Policy) clone() Policy {
	result := policy
	result.objectTypes = slices.Clone(policy.objectTypes)
	result.matchRule = policy.matchRule.clone()
	result.metrics = policy.Metrics()
	result.triggers = policy.Triggers()
	result.effectiveUntil = cloneTime(policy.effectiveUntil)
	return result
}

func metricDefinitionByID(metrics []MetricDefinition, id EntityID) (MetricDefinition, bool) {
	for _, metric := range metrics {
		if metric.id == id {
			return metric, true
		}
	}
	return MetricDefinition{}, false
}

func canonicalObjectTypes(inputs []ObjectType) ([]ObjectType, bool) {
	if len(inputs) == 0 || len(inputs) > 3 {
		return nil, false
	}
	result := slices.Clone(inputs)
	for _, value := range result {
		if !validObjectType(value) {
			return nil, false
		}
	}
	slices.Sort(result)
	for index := 1; index < len(result); index++ {
		if result[index-1] == result[index] {
			return nil, false
		}
	}
	return result, true
}

func (rule Rule) valid() bool {
	nodes := rule.nodeCount()
	if nodes == 0 || nodes > maximumRuleNodes {
		return false
	}
	switch rule.kind {
	case RuleAll:
		for _, child := range rule.children {
			if !child.valid() {
				return false
			}
		}
		return true
	case RuleAny:
		if len(rule.children) == 0 {
			return false
		}
		for _, child := range rule.children {
			if !child.valid() {
				return false
			}
		}
		return true
	case RuleNot:
		return len(rule.children) == 1 && rule.children[0].valid()
	case RulePredicate:
		_, ok := canonicalPredicateValues(rule.predicate.path.Kind, rule.predicate.operator, rule.predicate.values)
		return len(rule.children) == 0 && validFactPath(rule.predicate.path) && ok
	default:
		return false
	}
}

func (rule Rule) clone() Rule {
	result := rule
	result.children = make([]Rule, len(rule.children))
	for index, child := range rule.children {
		result.children[index] = child.clone()
	}
	result.predicate.values = slices.Clone(rule.predicate.values)
	return result
}
