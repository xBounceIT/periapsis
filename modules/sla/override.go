package sla

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"
)

type OverrideKind string

const (
	OverrideExtend         OverrideKind = "extend"
	OverrideSuspend        OverrideKind = "suspend"
	OverrideResume         OverrideKind = "resume"
	OverrideComplete       OverrideKind = "complete"
	OverrideChangeCalendar OverrideKind = "change_calendar"
	OverrideChangePolicy   OverrideKind = "change_policy"
	OverrideRecalculate    OverrideKind = "recalculate"
)

type OverrideAuthority struct {
	TenantID        EntityID
	ActorID         EntityID
	CanOverride     bool
	PermissionEpoch uint64
	SubjectEpoch    uint64
	EvaluatedAt     time.Time
	ValidUntil      time.Time
}

type OverrideCommand struct {
	ID               EntityID
	TenantID         EntityID
	ObjectID         EntityID
	ActorID          EntityID
	Kind             OverrideKind
	Reason           string
	OccurredAt       time.Time
	Extension        time.Duration
	NewPolicyID      EntityID
	NewPolicyVersion uint64
	NewMetric        *MetricDefinition
	SimulationDigest [32]byte
}

type OverrideSnapshot struct {
	policyID          EntityID
	policyVersion     uint64
	metricID          EntityID
	metricKey         Key
	calendarID        *EntityID
	calendarVersion   uint64
	effectiveDuration time.Duration
	extension         time.Duration
	evaluation        MetricEvaluation
}

func (snapshot OverrideSnapshot) PolicyID() EntityID               { return snapshot.policyID }
func (snapshot OverrideSnapshot) PolicyVersion() uint64            { return snapshot.policyVersion }
func (snapshot OverrideSnapshot) MetricID() EntityID               { return snapshot.metricID }
func (snapshot OverrideSnapshot) MetricKey() Key                   { return snapshot.metricKey }
func (snapshot OverrideSnapshot) CalendarID() *EntityID            { return cloneEntityID(snapshot.calendarID) }
func (snapshot OverrideSnapshot) CalendarVersion() uint64          { return snapshot.calendarVersion }
func (snapshot OverrideSnapshot) EffectiveDuration() time.Duration { return snapshot.effectiveDuration }
func (snapshot OverrideSnapshot) Extension() time.Duration         { return snapshot.extension }
func (snapshot OverrideSnapshot) Evaluation() MetricEvaluation {
	return cloneEvaluation(snapshot.evaluation)
}

type OverrideRecord struct {
	id               EntityID
	tenantID         EntityID
	objectID         EntityID
	actorID          EntityID
	kind             OverrideKind
	reason           string
	occurredAt       time.Time
	authorityEpoch   uint64
	subjectEpoch     uint64
	simulationDigest [32]byte
	previous         OverrideSnapshot
	next             OverrideSnapshot
	commandDigest    [32]byte
}

func (record OverrideRecord) ID() EntityID               { return record.id }
func (record OverrideRecord) TenantID() EntityID         { return record.tenantID }
func (record OverrideRecord) ObjectID() EntityID         { return record.objectID }
func (record OverrideRecord) ActorID() EntityID          { return record.actorID }
func (record OverrideRecord) Kind() OverrideKind         { return record.kind }
func (record OverrideRecord) Reason() string             { return record.reason }
func (record OverrideRecord) OccurredAt() time.Time      { return record.occurredAt }
func (record OverrideRecord) AuthorityEpoch() uint64     { return record.authorityEpoch }
func (record OverrideRecord) SubjectEpoch() uint64       { return record.subjectEpoch }
func (record OverrideRecord) SimulationDigest() [32]byte { return record.simulationDigest }
func (record OverrideRecord) Previous() OverrideSnapshot { return record.previous.clone() }
func (record OverrideRecord) Next() OverrideSnapshot     { return record.next.clone() }
func (record OverrideRecord) CommandDigest() [32]byte    { return record.commandDigest }
func (record OverrideRecord) String() string {
	return fmt.Sprintf(
		"sla.OverrideRecord{kind:%s,occurredAt:%s,authorityEpoch:%d,subjectEpoch:%d,reason:[REDACTED],identity:[REDACTED],snapshots:[REDACTED]}",
		record.kind, record.occurredAt.Format(time.RFC3339), record.authorityEpoch, record.subjectEpoch,
	)
}
func (record OverrideRecord) GoString() string { return record.String() }

func (instance MetricInstance) ApplyOverride(
	expectedVersion uint64,
	command OverrideCommand,
	authority OverrideAuthority,
	currentCalendar *BusinessCalendar,
	replacementCalendar *BusinessCalendar,
) (MetricInstance, *OverrideRecord, bool, error) {
	return instance.ApplyOverrideContext(
		context.Background(), expectedVersion, command, authority, currentCalendar, replacementCalendar,
	)
}

// ApplyOverrideContext applies an authorized override with cancellation
// propagated through business-time recalculation.
func (instance MetricInstance) ApplyOverrideContext(
	ctx context.Context,
	expectedVersion uint64,
	command OverrideCommand,
	authority OverrideAuthority,
	currentCalendar *BusinessCalendar,
	replacementCalendar *BusinessCalendar,
) (MetricInstance, *OverrideRecord, bool, error) {
	if ctx == nil || ctx.Err() != nil {
		return MetricInstance{}, nil, false, ErrEngineCanceled
	}
	if command.Kind == OverrideChangePolicy {
		return MetricInstance{}, nil, false, ErrInvalidOverride
	}
	return instance.applyOverrideCommandContext(
		ctx, expectedVersion, command, authority, currentCalendar, replacementCalendar,
	)
}

func (instance MetricInstance) applyOverrideCommandContext(
	ctx context.Context,
	expectedVersion uint64,
	command OverrideCommand,
	authority OverrideAuthority,
	currentCalendar *BusinessCalendar,
	replacementCalendar *BusinessCalendar,
) (MetricInstance, *OverrideRecord, bool, error) {
	if ctx == nil || ctx.Err() != nil {
		return MetricInstance{}, nil, false, ErrEngineCanceled
	}
	if expectedVersion != instance.version {
		return MetricInstance{}, nil, false, ErrMetricConflict
	}
	if !instance.valid() || !instance.matchesCalendar(currentCalendar) || !validOverrideAuthority(instance, command, authority) {
		if validEntityID(command.ID) && !authority.CanOverride {
			return MetricInstance{}, nil, false, ErrOverrideDenied
		}
		return MetricInstance{}, nil, false, ErrInvalidOverride
	}
	digest := overrideCommandDigest(command, replacementCalendar)
	if instance.lastOverrideID != nil && *instance.lastOverrideID == command.ID {
		if instance.lastOverrideDigest == digest {
			return instance.clone(), nil, false, nil
		}
		return MetricInstance{}, nil, false, ErrInvalidOverride
	}
	if !validOverrideShape(instance, command, replacementCalendar) {
		return MetricInstance{}, nil, false, ErrInvalidOverride
	}
	if instance.version >= maximumVersion-1 {
		return MetricInstance{}, nil, false, ErrMetricConflict
	}
	previousEvaluation, err := instance.EvaluateContext(ctx, command.OccurredAt, currentCalendar)
	if err != nil {
		return MetricInstance{}, nil, false, err
	}
	previous := instance.overrideSnapshot(previousEvaluation)
	updated := instance.clone()
	if updated.lifecycle == lifecycleRunning {
		elapsed, elapsedErr := updated.elapsedBetweenContext(ctx, *updated.lastResumedAt, command.OccurredAt, currentCalendar)
		if elapsedErr != nil {
			return MetricInstance{}, nil, false, elapsedErr
		}
		updated.consumed += elapsed
		updated.recordBreach(command.OccurredAt)
		updated.lastResumedAt = cloneTime(&command.OccurredAt)
	}
	nextCalendar, applyErr := updated.applyOverrideContext(ctx, command, currentCalendar, replacementCalendar)
	if applyErr != nil {
		return MetricInstance{}, nil, false, applyErr
	}
	updated.updatedAt = command.OccurredAt
	updated.lastOverrideID = cloneEntityID(&command.ID)
	updated.lastOverrideDigest = digest
	updated.version++
	nextEvaluation, err := updated.EvaluateContext(ctx, command.OccurredAt, nextCalendar)
	if err != nil {
		return MetricInstance{}, nil, false, err
	}
	record := OverrideRecord{
		id: command.ID, tenantID: command.TenantID, objectID: command.ObjectID,
		actorID: command.ActorID, kind: command.Kind, reason: command.Reason,
		occurredAt: command.OccurredAt, authorityEpoch: authority.PermissionEpoch,
		subjectEpoch: authority.SubjectEpoch, simulationDigest: command.SimulationDigest,
		previous: previous, next: updated.overrideSnapshot(nextEvaluation), commandDigest: digest,
	}
	return updated, &record, true, nil
}

func (instance *MetricInstance) applyOverrideContext(
	ctx context.Context,
	command OverrideCommand,
	currentCalendar *BusinessCalendar,
	replacementCalendar *BusinessCalendar,
) (*BusinessCalendar, error) {
	switch command.Kind {
	case OverrideExtend:
		instance.extension += command.Extension
		if instance.lifecycle == lifecycleRunning {
			return currentCalendar, instance.recalculateDeadlinesContext(ctx, command.OccurredAt, currentCalendar)
		}
		return currentCalendar, nil
	case OverrideSuspend:
		if instance.lifecycle != lifecycleRunning {
			return nil, ErrInvalidOverride
		}
		instance.lifecycle = lifecyclePaused
		instance.pausedAt = cloneTime(&command.OccurredAt)
		instance.lastResumedAt = nil
		return currentCalendar, nil
	case OverrideResume:
		if instance.lifecycle != lifecyclePaused {
			return nil, ErrInvalidOverride
		}
		instance.lifecycle = lifecycleRunning
		instance.pausedAt = nil
		instance.lastResumedAt = cloneTime(&command.OccurredAt)
		return currentCalendar, instance.recalculateDeadlinesContext(ctx, command.OccurredAt, currentCalendar)
	case OverrideComplete:
		if instance.lifecycle != lifecycleRunning && instance.lifecycle != lifecyclePaused {
			return nil, ErrInvalidOverride
		}
		instance.lifecycle = lifecycleCompleted
		instance.completedAt = cloneTime(&command.OccurredAt)
		instance.lastResumedAt = nil
		instance.pausedAt = nil
		return currentCalendar, nil
	case OverrideChangeCalendar:
		calendarID := replacementCalendar.id
		instance.definition.calendarID = &calendarID
		instance.definition.calendarVersion = replacementCalendar.version
		if instance.lifecycle == lifecycleRunning || instance.lifecycle == lifecyclePaused {
			if err := instance.recalculateDeadlinesContext(ctx, command.OccurredAt, replacementCalendar); err != nil {
				return nil, err
			}
		}
		return replacementCalendar, nil
	case OverrideChangePolicy:
		instance.policyID = command.NewPolicyID
		instance.policyVersion = command.NewPolicyVersion
		instance.definition = command.NewMetric.clone()
		instance.extension = 0
		if instance.lifecycle == lifecycleRunning || instance.lifecycle == lifecyclePaused {
			if err := instance.recalculateDeadlinesContext(ctx, command.OccurredAt, replacementCalendar); err != nil {
				return nil, err
			}
		}
		return replacementCalendar, nil
	case OverrideRecalculate:
		if instance.lifecycle != lifecycleRunning && instance.lifecycle != lifecyclePaused {
			return nil, ErrInvalidOverride
		}
		return currentCalendar, instance.recalculateDeadlinesContext(ctx, command.OccurredAt, currentCalendar)
	default:
		return nil, ErrInvalidOverride
	}
}

func validOverrideAuthority(instance MetricInstance, command OverrideCommand, authority OverrideAuthority) bool {
	return validEntityID(command.ID) && command.TenantID == instance.tenantID && command.ObjectID == instance.objectID &&
		validEntityID(command.ActorID) && authority.TenantID == instance.tenantID && authority.ActorID == command.ActorID &&
		authority.CanOverride && authority.PermissionEpoch > 0 && authority.PermissionEpoch < maximumVersion &&
		authority.SubjectEpoch > 0 && authority.SubjectEpoch < maximumVersion && validInstant(authority.EvaluatedAt) &&
		validInstant(authority.ValidUntil) && !authority.ValidUntil.Before(authority.EvaluatedAt) &&
		!command.OccurredAt.Before(authority.EvaluatedAt) && command.OccurredAt.Before(authority.ValidUntil) &&
		validInstant(command.OccurredAt) && !command.OccurredAt.Before(instance.updatedAt) &&
		validText(command.Reason, 2*1024, false, true)
}

func validOverrideShape(instance MetricInstance, command OverrideCommand, replacementCalendar *BusinessCalendar) bool {
	requiresSimulation := command.Kind == OverrideChangeCalendar || command.Kind == OverrideChangePolicy ||
		command.Kind == OverrideRecalculate
	if requiresSimulation == zeroDigest(command.SimulationDigest) ||
		command.Kind != OverrideExtend && command.Extension != 0 {
		return false
	}
	switch command.Kind {
	case OverrideExtend:
		return (instance.lifecycle == lifecycleRunning || instance.lifecycle == lifecyclePaused) &&
			command.Extension > 0 && command.Extension%time.Microsecond == 0 &&
			command.Extension <= 100*365*24*time.Hour-instance.effectiveDuration() &&
			replacementCalendar == nil && emptyReplacementPolicy(command)
	case OverrideSuspend, OverrideResume, OverrideComplete:
		return replacementCalendar == nil && emptyReplacementPolicy(command)
	case OverrideChangeCalendar:
		return instance.lifecycle != lifecycleCompleted && instance.definition.clock == ClockBusiness && replacementCalendar != nil &&
			replacementCalendar.valid() && replacementCalendar.tenantID == instance.tenantID &&
			instance.definition.calendarID != nil &&
			(replacementCalendar.id != *instance.definition.calendarID ||
				replacementCalendar.version != instance.definition.calendarVersion) &&
			emptyReplacementPolicy(command)
	case OverrideChangePolicy:
		if instance.lifecycle == lifecycleCompleted || !validEntityID(command.NewPolicyID) || command.NewPolicyVersion == 0 ||
			command.NewPolicyVersion >= maximumVersion || command.NewMetric == nil ||
			!command.NewMetric.valid() || command.NewMetric.key != instance.definition.key {
			return false
		}
		if command.NewMetric.clock == ClockElapsed {
			return replacementCalendar == nil
		}
		return replacementCalendar != nil && replacementCalendar.valid() &&
			replacementCalendar.tenantID == instance.tenantID && command.NewMetric.calendarID != nil &&
			replacementCalendar.id == *command.NewMetric.calendarID &&
			replacementCalendar.version == command.NewMetric.calendarVersion
	case OverrideRecalculate:
		return replacementCalendar == nil && emptyReplacementPolicy(command)
	default:
		return false
	}
}

func emptyReplacementPolicy(command OverrideCommand) bool {
	return command.NewPolicyID == (EntityID{}) && command.NewPolicyVersion == 0 && command.NewMetric == nil
}

func (instance MetricInstance) overrideSnapshot(evaluation MetricEvaluation) OverrideSnapshot {
	return OverrideSnapshot{
		policyID: instance.policyID, policyVersion: instance.policyVersion,
		metricID: instance.definition.id, metricKey: instance.definition.key,
		calendarID:        cloneEntityID(instance.definition.calendarID),
		calendarVersion:   instance.definition.calendarVersion,
		effectiveDuration: instance.effectiveDuration(), extension: instance.extension,
		evaluation: cloneEvaluation(evaluation),
	}
}

func (snapshot OverrideSnapshot) clone() OverrideSnapshot {
	result := snapshot
	result.calendarID = cloneEntityID(snapshot.calendarID)
	result.evaluation = cloneEvaluation(snapshot.evaluation)
	return result
}

func cloneEvaluation(value MetricEvaluation) MetricEvaluation {
	result := value
	result.StartedAt = cloneTime(value.StartedAt)
	result.DueAt = cloneTime(value.DueAt)
	result.BreachedAt = cloneTime(value.BreachedAt)
	result.CompletedAt = cloneTime(value.CompletedAt)
	return result
}

func zeroDigest(value [32]byte) bool { return value == ([32]byte{}) }

func overrideCommandDigest(command OverrideCommand, replacementCalendar *BusinessCalendar) [32]byte {
	hash := sha256.New()
	hash.Write([]byte("periapsis:sla-override:v1\x00"))
	for _, id := range []EntityID{command.ID, command.TenantID, command.ObjectID, command.ActorID, command.NewPolicyID} {
		bytes := id.Bytes()
		hash.Write(bytes[:])
	}
	hash.Write([]byte(command.Kind))
	hash.Write([]byte{0})
	hash.Write([]byte(command.Reason))
	buffer := make([]byte, 32)
	binary.BigEndian.PutUint64(buffer[:8], uint64(command.OccurredAt.UnixMicro()))
	binary.BigEndian.PutUint64(buffer[8:16], uint64(command.Extension))
	binary.BigEndian.PutUint64(buffer[16:24], command.NewPolicyVersion)
	if command.NewMetric != nil {
		metricDigest := metricDefinitionDigest(*command.NewMetric)
		hash.Write(metricDigest[:])
	}
	if replacementCalendar != nil {
		calendarID := replacementCalendar.id.Bytes()
		hash.Write(calendarID[:])
		binary.BigEndian.PutUint64(buffer[24:], replacementCalendar.version)
	}
	hash.Write(buffer)
	hash.Write(command.SimulationDigest[:])
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func metricDefinitionDigest(metric MetricDefinition) [32]byte {
	hash := sha256.New()
	hash.Write([]byte("periapsis:sla-metric-definition:v1\x00"))
	id := metric.id.Bytes()
	hash.Write(id[:])
	for _, value := range []string{
		metric.key.value, metric.label, metric.description, string(metric.clock),
		metric.startEvent.value, metric.pauseEvent.value, metric.resumeEvent.value,
		metric.completionEvent.value, metric.resetEvent.value, string(metric.resetPolicy),
		string(metric.warning.Kind), metric.displayFormat,
	} {
		hash.Write([]byte(value))
		hash.Write([]byte{0})
	}
	buffer := make([]byte, 48)
	binary.BigEndian.PutUint64(buffer[:8], uint64(metric.duration))
	binary.BigEndian.PutUint64(buffer[8:16], metric.calendarVersion)
	binary.BigEndian.PutUint64(buffer[16:24], uint64(metric.warning.ConsumedPercent))
	binary.BigEndian.PutUint64(buffer[24:32], uint64(metric.warning.RemainingDuration))
	binary.BigEndian.PutUint64(buffer[32:40], uint64(metric.breachGrace))
	if metric.customerVisible {
		buffer[40] = 1
	}
	if metric.apiVisible {
		buffer[41] = 1
	}
	hash.Write(buffer)
	if metric.calendarID != nil {
		calendarID := metric.calendarID.Bytes()
		hash.Write(calendarID[:])
	}
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result
}
