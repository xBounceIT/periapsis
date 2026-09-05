package sla

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"slices"
	"time"
)

const maximumAssignmentColumns = 256

// AssignmentInput is the immutable, transaction-local authority used when an
// alert, case, or task first enters SLA evaluation. Policies, calendars, and
// columns must all be loaded from the same database snapshot as the object
// facts. CreatedAt is the domain-event time, not the repository clock.
type AssignmentInput struct {
	Snapshot          FactSnapshot
	Policies          []Policy
	ObjectID          EntityID
	AssignmentEventID EntityID
	CreatedAt         time.Time
	Calendars         []BusinessCalendar
	Columns           []ColumnDefinition
}

// AssignmentPlan is either an explicit no-match decision or one complete SLA
// aggregate with its version-pinned metric work. IDs are deterministically
// derived from the assignment event and immutable policy revision so an exact
// event replay cannot create a second aggregate.
type AssignmentPlan struct {
	assignmentEventID EntityID
	objectID          EntityID
	createdAt         time.Time
	policy            *Policy
	slaInstanceID     EntityID
	metrics           []MetricWork
}

func (plan AssignmentPlan) Matched() bool               { return plan.policy != nil }
func (plan AssignmentPlan) AssignmentEventID() EntityID { return plan.assignmentEventID }
func (plan AssignmentPlan) ObjectID() EntityID          { return plan.objectID }
func (plan AssignmentPlan) CreatedAt() time.Time        { return plan.createdAt }
func (plan AssignmentPlan) Policy() *Policy {
	if plan.policy == nil {
		return nil
	}
	copy := plan.policy.clone()
	return &copy
}
func (plan AssignmentPlan) SLAInstanceID() EntityID { return plan.slaInstanceID }
func (plan AssignmentPlan) Metrics() []MetricWork   { return cloneMetricWork(plan.metrics) }
func (plan AssignmentPlan) String() string {
	return fmt.Sprintf(
		"sla.AssignmentPlan{matched:%t,metrics:%d,identity:[REDACTED],facts:[REDACTED]}",
		plan.Matched(), len(plan.metrics),
	)
}
func (plan AssignmentPlan) GoString() string { return plan.String() }

// PlanAssignment selects exactly one immutable policy revision and creates its
// aggregate projection. Equal-priority matches fail closed. A valid no-match
// plan is a durable decision: callers should still persist the processed event
// ledger entry so replay remains payload-bound.
func PlanAssignment(input AssignmentInput) (AssignmentPlan, error) {
	return PlanAssignmentContext(context.Background(), input)
}

// PlanAssignmentContext adds cooperative cancellation between bounded policy
// and metric projections.
func PlanAssignmentContext(ctx context.Context, input AssignmentInput) (AssignmentPlan, error) {
	if ctx == nil || ctx.Err() != nil {
		return AssignmentPlan{}, ErrEngineCanceled
	}
	if !input.Snapshot.valid() || !validEntityID(input.ObjectID) ||
		!validEntityID(input.AssignmentEventID) || !validInstant(input.CreatedAt) ||
		!input.Snapshot.evaluatedAt.Equal(input.CreatedAt) {
		return AssignmentPlan{}, ErrInvalidPolicy
	}
	selected, err := selectPolicyContext(ctx, input.Policies, input.Snapshot)
	if err != nil {
		return AssignmentPlan{}, err
	}
	plan := AssignmentPlan{
		assignmentEventID: input.AssignmentEventID,
		objectID:          input.ObjectID,
		createdAt:         input.CreatedAt,
	}
	if selected == nil {
		if len(input.Calendars) != 0 || len(input.Columns) != 0 {
			return AssignmentPlan{}, ErrInvalidPolicy
		}
		return plan, nil
	}

	policy := selected.clone()
	calendars, err := assignmentCalendars(policy, input.Calendars)
	if err != nil {
		return AssignmentPlan{}, err
	}
	columns, err := assignmentColumns(policy, input.Columns)
	if err != nil {
		return AssignmentPlan{}, err
	}
	policyDigest := policy.Digest()
	plan.policy = &policy
	plan.slaInstanceID, err = deriveAssignmentID(
		"aggregate", input.AssignmentEventID, input.Snapshot.tenantID, input.ObjectID,
		policy.id, policy.version, policyDigest, EntityID{},
	)
	if err != nil {
		return AssignmentPlan{}, err
	}

	seenInstanceIDs := map[EntityID]struct{}{plan.slaInstanceID: {}}
	for _, definition := range policy.metrics {
		if ctx.Err() != nil {
			return AssignmentPlan{}, ErrEngineCanceled
		}
		instanceID, deriveErr := deriveAssignmentID(
			"metric", input.AssignmentEventID, input.Snapshot.tenantID, input.ObjectID,
			policy.id, policy.version, policyDigest, definition.id,
		)
		if deriveErr != nil {
			return AssignmentPlan{}, deriveErr
		}
		if _, duplicate := seenInstanceIDs[instanceID]; duplicate {
			return AssignmentPlan{}, ErrInvalidMetric
		}
		seenInstanceIDs[instanceID] = struct{}{}
		instance, instanceErr := NewMetricInstance(MetricInstanceInput{
			ID: instanceID, SLAInstanceID: plan.slaInstanceID,
			TenantID: input.Snapshot.tenantID, ObjectType: input.Snapshot.objectType,
			ObjectID: input.ObjectID, PolicyID: policy.id, PolicyVersion: policy.version,
			Definition: definition, CreatedAt: input.CreatedAt,
		})
		if instanceErr != nil {
			return AssignmentPlan{}, instanceErr
		}
		work := MetricWork{Instance: instance, Calendar: cloneCalendarPointer(calendars[definition.id])}
		for _, trigger := range policy.triggers {
			if trigger.metricID != definition.id {
				continue
			}
			cursor, cursorErr := NewTriggerCursor(trigger.id)
			if cursorErr != nil {
				return AssignmentPlan{}, cursorErr
			}
			work.Triggers = append(work.Triggers, TriggerBinding{Definition: trigger.clone(), Cursor: cursor})
		}
		work.Columns = slices.Clone(columns[definition.id])
		plan.metrics = append(plan.metrics, work)
	}
	return plan, nil
}

func assignmentCalendars(policy Policy, inputs []BusinessCalendar) (map[EntityID]*BusinessCalendar, error) {
	if len(inputs) > 128 {
		return nil, ErrInvalidCalendar
	}
	required := make(map[EntityID]uint64)
	for _, metric := range policy.metrics {
		if metric.clock == ClockElapsed {
			continue
		}
		if metric.calendarID == nil || metric.calendarVersion == 0 {
			return nil, ErrInvalidCalendar
		}
		if version, exists := required[*metric.calendarID]; exists && version != metric.calendarVersion {
			return nil, ErrInvalidCalendar
		}
		required[*metric.calendarID] = metric.calendarVersion
	}
	if len(inputs) != len(required) {
		return nil, ErrInvalidCalendar
	}
	byMetric := make(map[EntityID]*BusinessCalendar, len(policy.metrics))
	provided := make(map[EntityID]BusinessCalendar, len(inputs))
	for _, calendar := range inputs {
		version, expected := required[calendar.id]
		if !expected || !calendar.valid() || calendar.tenantID != policy.tenantID || calendar.version != version {
			return nil, ErrInvalidCalendar
		}
		if _, duplicate := provided[calendar.id]; duplicate {
			return nil, ErrInvalidCalendar
		}
		provided[calendar.id] = calendar
	}
	for _, metric := range policy.metrics {
		if metric.clock == ClockElapsed {
			byMetric[metric.id] = nil
			continue
		}
		calendar, exists := provided[*metric.calendarID]
		if !exists {
			return nil, ErrInvalidCalendar
		}
		copy := calendar
		byMetric[metric.id] = &copy
	}
	return byMetric, nil
}

func assignmentColumns(policy Policy, inputs []ColumnDefinition) (map[EntityID][]ColumnDefinition, error) {
	if len(inputs) > maximumAssignmentColumns {
		return nil, ErrInvalidMetric
	}
	metrics := make(map[EntityID]MetricDefinition, len(policy.metrics))
	for _, metric := range policy.metrics {
		metrics[metric.id] = metric
	}
	result := make(map[EntityID][]ColumnDefinition, len(metrics))
	seenIDs := make(map[EntityID]struct{}, len(inputs))
	seenKeys := make(map[Key]struct{}, len(inputs))
	for _, column := range inputs {
		metric, exists := metrics[column.metricID]
		canonical, canonicalErr := NewColumnDefinition(metric, column.Input())
		if !exists || canonicalErr != nil || canonical.tenantID != policy.tenantID {
			return nil, ErrInvalidMetric
		}
		if _, duplicate := seenIDs[column.id]; duplicate {
			return nil, ErrInvalidMetric
		}
		if _, duplicate := seenKeys[column.key]; duplicate {
			return nil, ErrInvalidMetric
		}
		seenIDs[column.id] = struct{}{}
		seenKeys[column.key] = struct{}{}
		result[column.metricID] = append(result[column.metricID], canonical)
	}
	return result, nil
}

func deriveAssignmentID(
	domain string,
	eventID EntityID,
	tenantID EntityID,
	objectID EntityID,
	policyID EntityID,
	policyVersion uint64,
	policyDigest [32]byte,
	metricID EntityID,
) (EntityID, error) {
	if (domain != "aggregate" && domain != "metric") || !validEntityID(eventID) ||
		!validEntityID(tenantID) || !validEntityID(objectID) || !validEntityID(policyID) ||
		policyVersion == 0 || policyVersion >= maximumVersion || policyDigest == ([32]byte{}) ||
		domain == "metric" != validEntityID(metricID) {
		return EntityID{}, ErrInvalidMetric
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("periapsis:sla-assignment-id:v1\x00"))
	_, _ = hash.Write([]byte(domain))
	for _, value := range []EntityID{eventID, tenantID, objectID, policyID, metricID} {
		bytes := value.Bytes()
		_, _ = hash.Write(bytes[:])
	}
	var version [8]byte
	binary.BigEndian.PutUint64(version[:], policyVersion)
	_, _ = hash.Write(version[:])
	_, _ = hash.Write(policyDigest[:])
	sum := hash.Sum(nil)
	eventBytes := eventID.Bytes()
	var value [16]byte
	copy(value[:6], eventBytes[:6])
	value[6] = 0x70 | sum[0]&0x0f
	value[7] = sum[1]
	value[8] = 0x80 | sum[2]&0x3f
	copy(value[9:], sum[3:10])
	return NewEntityID(value)
}

func cloneMetricWork(values []MetricWork) []MetricWork {
	result := make([]MetricWork, len(values))
	for index, value := range values {
		result[index] = MetricWork{
			Instance: value.Instance.clone(), Calendar: cloneCalendarPointer(value.Calendar),
			Columns: slices.Clone(value.Columns),
		}
		result[index].Triggers = make([]TriggerBinding, len(value.Triggers))
		for triggerIndex, trigger := range value.Triggers {
			result[index].Triggers[triggerIndex] = TriggerBinding{
				Definition: trigger.Definition.clone(), Cursor: trigger.Cursor.clone(),
			}
		}
	}
	return result
}
