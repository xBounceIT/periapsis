package sla

import (
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"math"
	"time"
)

type digestBuilder struct {
	hash   hash.Hash
	buffer [8]byte
}

func newDigestBuilder(domain string) *digestBuilder {
	builder := &digestBuilder{hash: sha256.New()}
	builder.text(domain)
	return builder
}

func (builder *digestBuilder) bytes(value []byte) {
	builder.uint64(uint64(len(value)))
	_, _ = builder.hash.Write(value)
}

func (builder *digestBuilder) text(value string) { builder.bytes([]byte(value)) }
func (builder *digestBuilder) uint64(value uint64) {
	binary.BigEndian.PutUint64(builder.buffer[:], value)
	_, _ = builder.hash.Write(builder.buffer[:])
}
func (builder *digestBuilder) integer(value int64) { builder.uint64(uint64(value)) }
func (builder *digestBuilder) boolean(value bool) {
	if value {
		builder.uint64(1)
	} else {
		builder.uint64(0)
	}
}
func (builder *digestBuilder) instant(value time.Time) { builder.integer(value.UnixMicro()) }
func (builder *digestBuilder) entity(value EntityID) {
	bytes := value.Bytes()
	builder.bytes(bytes[:])
}
func (builder *digestBuilder) optionalEntity(value *EntityID) {
	builder.boolean(value != nil)
	if value != nil {
		builder.entity(*value)
	}
}
func (builder *digestBuilder) optionalInstant(value *time.Time) {
	builder.boolean(value != nil)
	if value != nil {
		builder.instant(*value)
	}
}
func (builder *digestBuilder) digest(value [32]byte) { builder.bytes(value[:]) }
func (builder *digestBuilder) sum() [32]byte {
	var result [32]byte
	copy(result[:], builder.hash.Sum(nil))
	return result
}

// Digest methods provide payload-bound, deterministic revision identities for
// idempotency ledgers and immutable version pins. They contain no secrets and
// must not be used as authentication tokens.
func (calendar BusinessCalendar) Digest() [32]byte {
	builder := newDigestBuilder("periapsis:sla-calendar:v1")
	input := calendar.Input()
	builder.entity(input.ID)
	builder.entity(input.TenantID)
	builder.text(input.Key.String())
	builder.text(input.Label)
	builder.text(input.Timezone)
	builder.uint64(input.Version)
	builder.uint64(uint64(len(input.WeeklySchedules)))
	for _, schedule := range input.WeeklySchedules {
		builder.integer(int64(schedule.Weekday))
		builder.uint64(uint64(len(schedule.Intervals)))
		for _, interval := range schedule.Intervals {
			builder.uint64(uint64(interval.StartMinute))
			builder.uint64(uint64(interval.EndMinute))
		}
	}
	builder.uint64(uint64(len(input.Exceptions)))
	for _, exception := range input.Exceptions {
		builder.text(exception.Date)
		builder.boolean(exception.Closed)
		builder.uint64(uint64(len(exception.Intervals)))
		for _, interval := range exception.Intervals {
			builder.uint64(uint64(interval.StartMinute))
			builder.uint64(uint64(interval.EndMinute))
		}
	}
	return builder.sum()
}

func (rule Rule) Digest() [32]byte {
	builder := newDigestBuilder("periapsis:sla-rule:v1")
	digestRule(builder, rule)
	return builder.sum()
}

func digestRule(builder *digestBuilder, rule Rule) {
	builder.text(string(rule.kind))
	builder.uint64(uint64(len(rule.children)))
	if rule.kind == RulePredicate {
		builder.text(string(rule.predicate.path.Kind))
		builder.text(rule.predicate.path.Key.String())
		builder.text(string(rule.predicate.operator))
		builder.uint64(uint64(len(rule.predicate.values)))
		for _, value := range rule.predicate.values {
			builder.text(value)
		}
	}
	for _, child := range rule.children {
		digestRule(builder, child)
	}
}

func (definition MetricDefinition) Digest() [32]byte { return metricDefinitionDigest(definition) }

func (definition TriggerDefinition) Digest() [32]byte {
	builder := newDigestBuilder("periapsis:sla-trigger-definition:v1")
	builder.entity(definition.id)
	builder.text(definition.key.String())
	builder.entity(definition.metricID)
	builder.text(string(definition.kind))
	builder.uint64(uint64(definition.consumedPercent))
	builder.integer(int64(definition.remaining))
	builder.integer(int64(definition.offset))
	builder.integer(int64(definition.repeatInterval))
	builder.text(string(definition.targetState))
	builder.text(string(definition.action.kind))
	builder.optionalEntity(definition.action.configurationID)
	if definition.action.kind == ActionCreateTask {
		builder.text(definition.action.text)
	} else {
		builder.text(definition.action.value.String())
	}
	builder.boolean(definition.action.allowRecursiveSLA)
	return builder.sum()
}

func (policy Policy) Digest() [32]byte {
	builder := newDigestBuilder("periapsis:sla-policy:v1")
	builder.entity(policy.id)
	builder.entity(policy.tenantID)
	builder.text(policy.key.String())
	builder.text(policy.name)
	builder.text(policy.description)
	builder.uint64(policy.version)
	builder.integer(int64(policy.priority))
	builder.uint64(uint64(len(policy.objectTypes)))
	for _, objectType := range policy.objectTypes {
		builder.text(string(objectType))
	}
	builder.digest(policy.matchRule.Digest())
	builder.uint64(uint64(len(policy.metrics)))
	for _, metric := range policy.metrics {
		builder.digest(metric.Digest())
	}
	builder.uint64(uint64(len(policy.triggers)))
	for _, trigger := range policy.triggers {
		builder.digest(trigger.Digest())
	}
	builder.instant(policy.effectiveFrom)
	builder.optionalInstant(policy.effectiveUntil)
	builder.boolean(policy.enabled)
	builder.boolean(policy.applyToSLAEngineSource)
	return builder.sum()
}

func (column ColumnDefinition) Digest() [32]byte {
	builder := newDigestBuilder("periapsis:sla-column:v1")
	builder.entity(column.id)
	builder.entity(column.tenantID)
	builder.text(column.key.String())
	builder.text(column.label)
	builder.entity(column.metricID)
	builder.text(string(column.calculation))
	builder.text(string(column.format))
	builder.boolean(column.sortable)
	builder.boolean(column.filterable)
	builder.boolean(column.customerVisible)
	builder.uint64(uint64(len(column.visibleRoleKeys)))
	for _, role := range column.visibleRoleKeys {
		builder.text(role.String())
	}
	builder.uint64(uint64(column.position))
	builder.uint64(column.version)
	builder.uint64(uint64(len(column.styleRules)))
	for _, style := range column.styleRules {
		builder.text(style.styleKey.String())
		builder.text(string(style.state))
		builder.boolean(style.minimumPercentage != nil)
		if style.minimumPercentage != nil {
			builder.uint64(math.Float64bits(*style.minimumPercentage))
		}
		builder.boolean(style.maximumRemaining != nil)
		if style.maximumRemaining != nil {
			builder.integer(int64(*style.maximumRemaining))
		}
	}
	return builder.sum()
}

func (result SimulationResult) Digest() [32]byte {
	builder := newDigestBuilder("periapsis:sla-simulation:v1")
	builder.entity(result.policyID)
	builder.uint64(result.policyVersion)
	builder.uint64(uint64(len(result.metrics)))
	for _, metric := range result.metrics {
		builder.entity(metric.metricID)
		builder.text(metric.metricKey.String())
		snapshot := metric.instance.Snapshot()
		builder.entity(snapshot.ID)
		builder.entity(snapshot.SLAInstanceID)
		builder.uint64(snapshot.Version)
		builder.text(string(snapshot.Lifecycle))
		builder.integer(int64(snapshot.Consumed))
		builder.integer(int64(snapshot.Extension))
		builder.optionalInstant(snapshot.StartedAt)
		builder.optionalInstant(snapshot.PausedAt)
		builder.optionalInstant(snapshot.CompletedAt)
		builder.optionalInstant(snapshot.DueAt)
		builder.optionalInstant(snapshot.BreachedAt)
		evaluation := metric.evaluation
		builder.text(string(evaluation.State))
		builder.integer(int64(evaluation.Remaining))
		builder.uint64(math.Float64bits(evaluation.ConsumedPercentage))
		builder.uint64(uint64(len(metric.triggers)))
		for _, trigger := range metric.triggers {
			builder.entity(trigger.triggerID)
			builder.entity(trigger.metricID)
			builder.optionalInstant(trigger.scheduledAt)
			builder.boolean(trigger.eventDriven)
			builder.text(string(trigger.action.kind))
			builder.optionalEntity(trigger.action.configurationID)
			builder.text(trigger.action.value.String())
			builder.boolean(trigger.action.allowRecursiveSLA)
		}
	}
	return builder.sum()
}
