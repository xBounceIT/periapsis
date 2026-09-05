package postgres

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/sla"
)

type slaEventFactDocument struct {
	Kind   kernel.FactKind `json:"kind"`
	Key    *string         `json:"key"`
	Values []string        `json:"values"`
}

type slaEventFactSnapshotDocument struct {
	TenantID    uuid.UUID              `json:"tenant_id"`
	ObjectType  kernel.ObjectType      `json:"object_type"`
	ObjectID    uuid.UUID              `json:"object_id"`
	EvaluatedAt time.Time              `json:"evaluated_at"`
	Timezone    string                 `json:"timezone"`
	Facts       []slaEventFactDocument `json:"facts"`
}

type slaEventRuleDocument struct {
	Kind      kernel.RuleKind            `json:"kind"`
	Children  []slaEventRuleDocument     `json:"children,omitempty"`
	Predicate *slaEventPredicateDocument `json:"predicate,omitempty"`
}

type slaEventPredicateDocument struct {
	Kind     kernel.FactKind          `json:"kind"`
	Key      string                   `json:"key,omitempty"`
	Operator kernel.PredicateOperator `json:"operator"`
	Values   []string                 `json:"values"`
}

type slaEventPolicyDocument struct {
	ID                     uuid.UUID             `json:"id"`
	TenantID               uuid.UUID             `json:"tenant_id"`
	Key                    string                `json:"key"`
	Version                uint64                `json:"version"`
	Name                   string                `json:"name"`
	Description            string                `json:"description"`
	Priority               int32                 `json:"priority"`
	ObjectTypes            []kernel.ObjectType   `json:"object_types"`
	MatchRule              slaEventRuleDocument  `json:"match_rule"`
	EffectiveFrom          time.Time             `json:"effective_from"`
	EffectiveUntil         *time.Time            `json:"effective_until"`
	Enabled                bool                  `json:"enabled"`
	ApplyToSLAEngineSource bool                  `json:"apply_to_sla_engine_source"`
	Metrics                []slaWorkerDefinition `json:"metrics"`
	Triggers               []slaWorkerTrigger    `json:"triggers"`
	RevisionDigest         string                `json:"revision_digest"`
}

type slaEventColumnDocument struct {
	ID                 uuid.UUID                `json:"id"`
	TenantID           uuid.UUID                `json:"tenant_id"`
	Key                string                   `json:"key"`
	Label              string                   `json:"label"`
	MetricDefinitionID uuid.UUID                `json:"metric_definition_id"`
	Metric             slaWorkerDefinition      `json:"metric"`
	Calculation        kernel.ColumnCalculation `json:"calculation"`
	Format             kernel.ColumnFormat      `json:"format"`
	Sortable           bool                     `json:"sortable"`
	Filterable         bool                     `json:"filterable"`
	CustomerVisible    bool                     `json:"customer_visible"`
	VisibleRoleKeys    []string                 `json:"visible_role_keys"`
	Position           uint16                   `json:"position"`
	StyleRules         []slaWorkerColumnStyle   `json:"style_rules"`
	Version            uint64                   `json:"version"`
	RevisionDigest     string                   `json:"revision_digest"`
}

type slaEventAssignmentSnapshotDocument struct {
	Facts     slaEventFactSnapshotDocument `json:"facts"`
	Policies  []slaEventPolicyDocument     `json:"policies"`
	Calendars []slaWorkerCalendar          `json:"calendars"`
	Columns   []slaEventColumnDocument     `json:"columns"`
}

func decodeSLAEventAssignmentSnapshot(
	tenantID uuid.UUID,
	objectType kernel.ObjectType,
	objectID kernel.EntityID,
	eventAt time.Time,
	raw []byte,
) (kernel.ObjectEventState, error) {
	var document slaEventAssignmentSnapshotDocument
	if err := decodeStrictSLAWorkerJSON(raw, &document); err != nil {
		return kernel.ObjectEventState{}, err
	}
	if document.Facts.TenantID != tenantID || document.Facts.ObjectType != objectType ||
		document.Facts.ObjectID != uuid.UUID(objectID.Bytes()) ||
		!normalizeSLAWorkerInstant(&document.Facts.EvaluatedAt) ||
		!document.Facts.EvaluatedAt.Equal(eventAt) || len(document.Facts.Facts) > 256 ||
		len(document.Policies) > 512 || len(document.Calendars) > 512 || len(document.Columns) > 256 {
		return kernel.ObjectEventState{}, errors.New("database returned an invalid SLA event assignment snapshot")
	}
	tenantEntity, err := kernel.ParseEntityID(tenantID.String())
	if err != nil {
		return kernel.ObjectEventState{}, err
	}
	facts := make([]kernel.FactInput, len(document.Facts.Facts))
	for index, fact := range document.Facts.Facts {
		key := kernel.Key{}
		if fact.Key != nil {
			key, err = kernel.NewKey(*fact.Key)
			if err != nil {
				return kernel.ObjectEventState{}, errors.New("database returned an invalid SLA event fact key")
			}
		}
		facts[index] = kernel.FactInput{
			Path:   kernel.FactPath{Kind: fact.Kind, Key: key},
			Values: append([]string(nil), fact.Values...),
		}
	}
	snapshot, err := kernel.NewFactSnapshot(kernel.FactSnapshotInput{
		TenantID: tenantEntity, ObjectType: objectType, EvaluatedAt: document.Facts.EvaluatedAt,
		Timezone: document.Facts.Timezone, Facts: facts,
	})
	if err != nil {
		return kernel.ObjectEventState{}, errors.New("database returned non-restorable SLA event facts")
	}
	calendars := make([]kernel.BusinessCalendar, len(document.Calendars))
	calendarIDs := make(map[kernel.EntityID]struct{}, len(document.Calendars))
	for index, value := range document.Calendars {
		calendar, decodeErr := decodeSLAWorkerCalendar(value, tenantID, tenantEntity)
		if decodeErr != nil {
			return kernel.ObjectEventState{}, decodeErr
		}
		if _, duplicate := calendarIDs[calendar.ID()]; duplicate {
			return kernel.ObjectEventState{}, errors.New("database returned duplicate SLA event calendars")
		}
		calendarIDs[calendar.ID()] = struct{}{}
		calendars[index] = calendar
	}
	policies := make([]kernel.Policy, len(document.Policies))
	policyIDs := make(map[kernel.EntityID]struct{}, len(document.Policies))
	for index, value := range document.Policies {
		policy, decodeErr := decodeSLAEventPolicy(tenantID, tenantEntity, value)
		if decodeErr != nil {
			return kernel.ObjectEventState{}, decodeErr
		}
		if _, duplicate := policyIDs[policy.ID()]; duplicate {
			return kernel.ObjectEventState{}, errors.New("database returned duplicate SLA event policies")
		}
		policyIDs[policy.ID()] = struct{}{}
		policies[index] = policy
	}
	columns := make([]kernel.ColumnDefinition, len(document.Columns))
	columnIDs := make(map[kernel.EntityID]struct{}, len(document.Columns))
	for index, value := range document.Columns {
		metric, decodeErr := decodeSLAWorkerDefinition(value.Metric)
		if decodeErr != nil || value.MetricDefinitionID != value.Metric.ID {
			return kernel.ObjectEventState{}, errors.New("database returned an invalid SLA event column metric")
		}
		converted := slaWorkerColumn{
			ID: value.ID, TenantID: value.TenantID, Key: value.Key, Label: value.Label,
			MetricDefinitionID: value.MetricDefinitionID, Calculation: value.Calculation,
			Format: value.Format, Sortable: value.Sortable, Filterable: value.Filterable,
			CustomerVisible: value.CustomerVisible, VisibleRoleKeys: value.VisibleRoleKeys,
			Position: value.Position, StyleRules: value.StyleRules, Version: value.Version,
			RevisionDigest: value.RevisionDigest,
		}
		decoded, decodeErr := decodeSLAWorkerColumns(metric, tenantID, tenantEntity, []slaWorkerColumn{converted})
		if decodeErr != nil {
			return kernel.ObjectEventState{}, decodeErr
		}
		if _, duplicate := columnIDs[decoded[0].ID()]; duplicate {
			return kernel.ObjectEventState{}, errors.New("database returned duplicate SLA event columns")
		}
		columnIDs[decoded[0].ID()] = struct{}{}
		columns[index] = decoded[0]
	}
	return kernel.ObjectEventState{
		Mode: kernel.ObjectEventStateUnassigned, Snapshot: &snapshot,
		Policies: policies, Calendars: calendars, Columns: columns,
	}, nil
}

func decodeSLAEventPolicy(
	tenantID uuid.UUID,
	tenantEntity kernel.EntityID,
	document slaEventPolicyDocument,
) (kernel.Policy, error) {
	if document.TenantID != tenantID || !slaWorkerUUIDv7(document.ID) || document.Version == 0 ||
		!normalizeSLAWorkerInstant(&document.EffectiveFrom) ||
		!normalizeSLAWorkerInstantPointer(document.EffectiveUntil) ||
		len(document.Metrics) == 0 || len(document.Metrics) > 32 || len(document.Triggers) > 256 {
		return kernel.Policy{}, errors.New("database returned an invalid SLA event policy")
	}
	id, _ := kernel.ParseEntityID(document.ID.String())
	key, err := kernel.NewKey(document.Key)
	if err != nil {
		return kernel.Policy{}, err
	}
	ruleInput, err := decodeSLAEventRule(document.MatchRule)
	if err != nil {
		return kernel.Policy{}, errors.New("database returned an invalid SLA event rule key")
	}
	rule, err := kernel.NewRule(ruleInput)
	if err != nil {
		return kernel.Policy{}, errors.New("database returned a non-restorable SLA event rule")
	}
	metrics := make([]kernel.MetricDefinition, len(document.Metrics))
	metricsByID := make(map[kernel.EntityID]kernel.MetricDefinition, len(document.Metrics))
	for index, value := range document.Metrics {
		if value.Position != uint16(index) {
			return kernel.Policy{}, errors.New("database returned unordered SLA event metrics")
		}
		metric, decodeErr := decodeSLAWorkerDefinition(value)
		if decodeErr != nil {
			return kernel.Policy{}, decodeErr
		}
		if _, duplicate := metricsByID[metric.ID()]; duplicate {
			return kernel.Policy{}, errors.New("database returned duplicate SLA event metrics")
		}
		metrics[index], metricsByID[metric.ID()] = metric, metric
	}
	triggers := make([]kernel.TriggerDefinition, len(document.Triggers))
	for index, value := range document.Triggers {
		if value.Position != uint16(index) {
			return kernel.Policy{}, errors.New("database returned unordered SLA event triggers")
		}
		metricID, parseErr := kernel.ParseEntityID(value.MetricDefinitionID.String())
		metric, exists := metricsByID[metricID]
		if parseErr != nil || !exists {
			return kernel.Policy{}, errors.New("database returned an orphan SLA event trigger")
		}
		trigger, decodeErr := decodeSLAWorkerTrigger(value, metric)
		if decodeErr != nil {
			return kernel.Policy{}, decodeErr
		}
		triggers[index] = trigger
	}
	policy, err := kernel.NewPolicy(kernel.PolicyInput{
		ID: id, TenantID: tenantEntity, Key: key, Name: document.Name,
		Description: document.Description, Version: document.Version, Priority: document.Priority,
		ObjectTypes: append([]kernel.ObjectType(nil), document.ObjectTypes...), MatchRule: rule,
		Metrics: metrics, Triggers: triggers, EffectiveFrom: document.EffectiveFrom,
		EffectiveUntil: document.EffectiveUntil, Enabled: document.Enabled,
		ApplyToSLAEngineSource: document.ApplyToSLAEngineSource,
	})
	if err != nil || !matchesSLAWorkerDigest(document.RevisionDigest, policy.Digest()) {
		return kernel.Policy{}, errors.New("database returned a non-restorable SLA event policy")
	}
	return policy, nil
}

func decodeSLAEventRule(document slaEventRuleDocument) (*kernel.RuleInput, error) {
	result := &kernel.RuleInput{Kind: document.Kind}
	if document.Predicate != nil {
		result.Predicate = kernel.PredicateInput{
			Path:     kernel.FactPath{Kind: document.Predicate.Kind},
			Operator: document.Predicate.Operator,
			Values:   append([]string(nil), document.Predicate.Values...),
		}
		if document.Predicate.Key != "" {
			key, err := kernel.NewKey(document.Predicate.Key)
			if err != nil {
				return nil, err
			}
			result.Predicate.Path.Key = key
		}
	}
	result.Children = make([]*kernel.RuleInput, len(document.Children))
	for index, child := range document.Children {
		decoded, err := decodeSLAEventRule(child)
		if err != nil {
			return nil, err
		}
		result.Children[index] = decoded
	}
	return result, nil
}

type slaEventPlanDocument struct {
	Metrics              []slaWorkerMetricWrite     `json:"metrics"`
	Cursors              []slaWorkerCursorWrite     `json:"cursors"`
	Occurrences          []slaWorkerOccurrenceWrite `json:"occurrences"`
	Columns              []slaWorkerColumnWrite     `json:"columns"`
	NextEvaluationAt     *time.Time                 `json:"next_evaluation_at"`
	AggregateCompletedAt *time.Time                 `json:"aggregate_completed_at"`
}

func encodeSLAEventPlan(plan kernel.ObjectEventPlan) ([]byte, error) {
	engine := plan.Engine()
	if engine == nil {
		assignment := plan.Assignment()
		if (!plan.PinnedNoPolicy() && (assignment == nil || assignment.Matched())) ||
			(plan.PinnedNoPolicy() && assignment != nil) ||
			plan.ExpectedAggregateVersion() != 0 || plan.NextAggregateVersion() != 0 {
			return nil, errors.New("invalid empty SLA event plan")
		}
		return marshalSLAEventDocument(slaEventPlanDocument{
			Metrics: []slaWorkerMetricWrite{}, Cursors: []slaWorkerCursorWrite{},
			Occurrences: []slaWorkerOccurrenceWrite{}, Columns: []slaWorkerColumnWrite{},
		})
	}
	if assignment := plan.Assignment(); assignment != nil && assignment.Matched() {
		return encodeSLAEventAssignmentPlan(*engine)
	}
	return encodeSLAEventEnginePlan(*engine)
}

func marshalSLAEventDocument(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(true)
	if err := encoder.Encode(value); err != nil || buffer.Len() > maximumSLAWorkerDocumentBytes {
		return nil, errors.New("cannot encode SLA event document")
	}
	result := bytes.TrimSuffix(buffer.Bytes(), []byte{'\n'})
	return append([]byte(nil), result...), nil
}

func decodeSLAEventDigest(value []byte) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	if len(value) != sha256.Size {
		return result, errors.New("database returned an invalid SLA event digest")
	}
	copy(result[:], value)
	return result, nil
}

func encodeSLAEventDigest(value [sha256.Size]byte) string { return hex.EncodeToString(value[:]) }

func decodeStrictSLAEventResult(raw []byte, target any) error {
	if len(raw) == 0 || len(raw) > maximumSLAWorkerDocumentBytes || target == nil {
		return errors.New("database returned an invalid SLA event result")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errors.New("database returned a malformed SLA event result")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("database returned trailing SLA event result data")
	}
	return nil
}
