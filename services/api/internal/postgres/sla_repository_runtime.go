package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	kernel "github.com/periapsis-im/periapsis/modules/sla"
	application "github.com/periapsis-im/periapsis/services/api/internal/sla"
)

func (repository *SLARepository) LoadObjectProjection(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	resource application.Resource,
	claimed application.Authority,
) (application.ObjectProjectionState, error) {
	state, err := withinTransactionWithOptions(
		ctx, repository.begin, phase4ReadOptions(),
		func(tx databaseTransaction) (application.ObjectProjectionState, error) {
			if err := recheckSLAAuthority(ctx, tx, actor, tenantID, claimed.Capability, resource, claimed); err != nil {
				return application.ObjectProjectionState{}, err
			}
			var runtime decodedSLARuntimeState
			var err error
			switch actor.Kind {
			case application.PrincipalOperator:
				runtime, err = readSLARuntimeState(
					ctx, tx, tenantID, resource, claimed.Capability, claimed.EvaluatedAt,
				)
			case application.PrincipalCustomer:
				runtime, err = readSLACustomerRuntimeState(
					ctx, tx, tenantID, resource, claimed.Capability, claimed.EvaluatedAt,
				)
			default:
				return application.ObjectProjectionState{}, application.ErrRepositoryForbidden
			}
			if err != nil {
				return application.ObjectProjectionState{}, err
			}
			if runtime.PermissionEpoch != claimed.PermissionEpoch || runtime.SubjectEpoch != claimed.SubjectEpoch {
				return application.ObjectProjectionState{}, application.ErrRepositoryForbidden
			}
			if runtime.Aggregate == nil {
				return application.ObjectProjectionState{}, pgx.ErrNoRows
			}
			slaInstanceID, parseErr := kernel.ParseEntityID(runtime.Aggregate.ID.String())
			if parseErr != nil {
				return application.ObjectProjectionState{}, parseErr
			}
			policyID, parseErr := kernel.ParseEntityID(runtime.Aggregate.PolicyID.String())
			if parseErr != nil {
				return application.ObjectProjectionState{}, parseErr
			}
			return application.ObjectProjectionState{
				SLAInstanceID: slaInstanceID, AggregateVersion: runtime.Aggregate.AggregateVersion,
				PolicyID: policyID, PolicyVersion: runtime.Aggregate.PolicyVersion, Metrics: runtime.Metrics,
			}, nil
		},
	)
	return state, mapSLADatabaseError(err)
}

func (repository *SLARepository) TransactEvent(
	ctx context.Context,
	transaction application.EventTransaction,
) (application.EventResult, error) {
	if repository == nil || repository.begin == nil || transaction.Plan == nil {
		return application.EventResult{}, application.ErrRepositoryForbidden
	}
	result, err := withinTransactionWithOptions(
		ctx, repository.begin, phase4WriteOptions(),
		func(tx databaseTransaction) (application.EventResult, error) {
			command := transaction.Command
			capability, ok := slaObjectReadCapability(command.ObjectType)
			if !ok || command.Envelope.Audit.AuthMethod != command.Actor.AuthenticationMethod {
				return application.EventResult{}, application.ErrRepositoryForbidden
			}
			resource := application.Resource{ObjectType: command.ObjectType, ObjectID: command.Event.ObjectID}
			if _, err := resolveSLAAuthorityInTransaction(
				ctx, tx, command.Actor, transaction.TenantID, capability, resource,
			); err != nil {
				return application.EventResult{}, err
			}
			if err := installPersistedTraceContext(ctx, tx); err != nil {
				return application.EventResult{}, err
			}
			begin, err := beginSLAEvent(ctx, tx, transaction)
			if err != nil {
				return application.EventResult{}, err
			}
			if !begin.fresh {
				return application.EventResult{Receipt: begin.receipt, Replayed: true}, nil
			}
			runtime, err := decodeSLARuntimeState(transaction.TenantID, resource, begin.stateDocument)
			if err != nil {
				return application.EventResult{}, err
			}
			state := application.EventState{
				Mode: application.EventStateUnassigned, Snapshot: &runtime.Facts,
				Policies: runtime.ActivePolicies, Calendars: runtime.ActiveCalendars, Columns: runtime.ActiveColumns,
			}
			if runtime.Aggregate != nil {
				state = application.EventState{
					Mode: application.EventStateExisting, AggregateVersion: runtime.Aggregate.AggregateVersion,
					Metrics: runtime.Metrics,
				}
			}
			plan, err := transaction.Plan(state)
			if err != nil {
				return application.EventResult{}, err
			}
			planDocument, err := encodeSLAEventPlan(plan)
			if err != nil {
				return application.EventResult{}, err
			}
			receipt, err := commitSLAEvent(ctx, tx, transaction, plan, planDocument)
			if err != nil {
				return application.EventResult{}, err
			}
			return application.EventResult{Receipt: receipt}, nil
		},
	)
	return result, mapSLADatabaseError(err)
}

func (repository *SLARepository) TransactOverride(
	ctx context.Context,
	transaction application.OverrideTransaction,
) (application.OverrideResult, error) {
	if repository == nil || repository.begin == nil || transaction.Plan == nil {
		return application.OverrideResult{}, application.ErrRepositoryForbidden
	}
	result, err := withinTransactionWithOptions(
		ctx, repository.begin, phase4WriteOptions(),
		func(tx databaseTransaction) (application.OverrideResult, error) {
			request := transaction.Request
			resource := application.Resource{ObjectType: request.ObjectType, ObjectID: request.ObjectID}
			if request.Envelope.Audit.AuthMethod != transaction.Actor.AuthenticationMethod {
				return application.OverrideResult{}, application.ErrRepositoryForbidden
			}
			if err := recheckSLAAuthority(
				ctx, tx, transaction.Actor, transaction.TenantID,
				transaction.Authority.Capability, resource, transaction.Authority,
			); err != nil {
				return application.OverrideResult{}, err
			}
			if err := installPersistedTraceContext(ctx, tx); err != nil {
				return application.OverrideResult{}, err
			}
			begin, err := beginSLAOverride(ctx, tx, transaction)
			if err != nil {
				return application.OverrideResult{}, err
			}
			if !begin.fresh {
				return application.OverrideResult{Receipt: begin.receipt, Replayed: true}, nil
			}
			runtime, err := decodeSLARuntimeState(transaction.TenantID, resource, begin.stateDocument)
			if err != nil {
				return application.OverrideResult{}, err
			}
			if runtime.Aggregate == nil || runtime.PermissionEpoch != transaction.Authority.PermissionEpoch ||
				runtime.SubjectEpoch != transaction.Authority.SubjectEpoch {
				return application.OverrideResult{}, application.ErrRepositoryForbidden
			}
			state, err := overrideStateFromRuntime(request, runtime)
			if err != nil {
				return application.OverrideResult{}, err
			}
			plan, err := transaction.Plan(state)
			if err != nil {
				return application.OverrideResult{}, err
			}
			planDocument, commandDigest, err := encodeSLAOverridePlan(plan, state)
			if err != nil {
				return application.OverrideResult{}, err
			}
			receipt, err := commitSLAOverride(ctx, tx, transaction, plan, planDocument, commandDigest)
			if err != nil {
				return application.OverrideResult{}, err
			}
			return application.OverrideResult{Receipt: receipt}, nil
		},
	)
	return result, mapSLADatabaseError(err)
}

func readSLARuntimeState(
	ctx context.Context,
	tx databaseTransaction,
	tenantID uuid.UUID,
	resource application.Resource,
	capability application.Capability,
	at time.Time,
) (decodedSLARuntimeState, error) {
	var raw []byte
	if err := tx.QueryRow(ctx, `
		SELECT app.read_sla_runtime_state_v2($1, $2, $3, $4, $5)`,
		tenantID, string(resource.ObjectType), slaUUID(resource.ObjectID), string(capability), at,
	).Scan(&raw); err != nil {
		return decodedSLARuntimeState{}, err
	}
	return decodeSLARuntimeState(tenantID, resource, raw)
}

const readSLACustomerRuntimeStateQuery = `
	WITH runtime AS MATERIALIZED (
		SELECT app.read_sla_runtime_state_v2($1, $2, $3, $4, $5) AS document
	), customer_metrics AS (
		SELECT metric_ordinal,
		       jsonb_build_object(
		         'id', metric_document -> 'id',
		         'sla_instance_id', metric_document -> 'sla_instance_id',
		         'tenant_id', metric_document -> 'tenant_id',
		         'definition_id', metric_document -> 'definition_id',
		         'policy_id', metric_document -> 'policy_id',
		         'policy_version', metric_document -> 'policy_version',
		         'version', metric_document -> 'version',
		         'lifecycle', metric_document -> 'lifecycle',
		         'created_at', metric_document -> 'created_at',
		         'updated_at', metric_document -> 'updated_at',
		         'extension_micros', metric_document -> 'extension_micros',
		         'consumed_micros', metric_document -> 'consumed_micros',
		         'started_at', metric_document -> 'started_at',
		         'last_resumed_at', metric_document -> 'last_resumed_at',
		         'paused_at', metric_document -> 'paused_at',
		         'completed_at', metric_document -> 'completed_at',
		         'due_at', metric_document -> 'due_at',
		         'breach_threshold_at', metric_document -> 'breach_threshold_at',
		         'breached_at', metric_document -> 'breached_at',
		         'definition', metric_document -> 'definition',
		         'calendar', metric_document -> 'calendar',
		         'triggers', '[]'::jsonb,
		         'cursors', '[]'::jsonb,
		         'columns', coalesce((
		           SELECT jsonb_agg(column_document ORDER BY column_ordinal)
		           FROM jsonb_array_elements(metric_document -> 'columns')
		             WITH ORDINALITY AS visible_column(column_document, column_ordinal)
		           WHERE coalesce((column_document ->> 'customer_visible')::boolean, false)
		         ), '[]'::jsonb)
		       ) AS document
		FROM runtime
		CROSS JOIN LATERAL jsonb_array_elements(runtime.document -> 'metrics')
		  WITH ORDINALITY AS visible_metric(metric_document, metric_ordinal)
		WHERE coalesce((metric_document #>> '{definition,api_visible}')::boolean, false)
		  AND coalesce((metric_document #>> '{definition,customer_visible}')::boolean, false)
	)
	SELECT jsonb_build_object(
	  'facts', jsonb_build_object(
	    'tenant_id', $1::uuid,
	    'object_type', $2::public.sla_object_type,
	    'object_id', $3::uuid,
	    'evaluated_at', $5::timestamp with time zone,
	    'timezone', 'UTC',
	    'facts', '[]'::jsonb
	  ),
	  'permission_epoch', runtime.document -> 'permission_epoch',
	  'subject_epoch', runtime.document -> 'subject_epoch',
	  'aggregate', runtime.document -> 'aggregate',
	  'metrics', coalesce((
	    SELECT jsonb_agg(customer_metrics.document ORDER BY customer_metrics.metric_ordinal)
	    FROM customer_metrics
	  ), '[]'::jsonb),
	  'active_policies', '[]'::jsonb,
	  'active_calendars', '[]'::jsonb,
	  'active_columns', '[]'::jsonb,
	  'replacement_calendar', NULL,
	  'replacement_policy', NULL,
	  'replacement_calendars', '[]'::jsonb,
	  'replacement_columns', '[]'::jsonb,
	  'simulation_digest', NULL,
	  'occurred_at', $5::timestamp with time zone
	)
	FROM runtime`

func readSLACustomerRuntimeState(
	ctx context.Context,
	tx databaseTransaction,
	tenantID uuid.UUID,
	resource application.Resource,
	capability application.Capability,
	at time.Time,
) (decodedSLARuntimeState, error) {
	if !slaPrincipalMayUseCapability(application.PrincipalCustomer, capability) {
		return decodedSLARuntimeState{}, application.ErrRepositoryForbidden
	}
	var raw []byte
	if err := tx.QueryRow(
		ctx, readSLACustomerRuntimeStateQuery,
		tenantID, string(resource.ObjectType), slaUUID(resource.ObjectID), string(capability), at,
	).Scan(&raw); err != nil {
		return decodedSLARuntimeState{}, err
	}
	return decodeSLACustomerRuntimeState(tenantID, resource, raw)
}

type slaEventBeginResult struct {
	fresh         bool
	receipt       application.EventReceipt
	stateDocument []byte
}

func beginSLAEvent(
	ctx context.Context,
	tx databaseTransaction,
	transaction application.EventTransaction,
) (slaEventBeginResult, error) {
	command := transaction.Command
	var result slaEventBeginResult
	var eventID uuid.UUID
	var outcome *string
	var slaInstanceID, policyID *uuid.UUID
	var aggregateVersion, policyVersion *int64
	if err := tx.QueryRow(ctx, `
		SELECT fresh, event_id, outcome::text, sla_instance_id,
		       aggregate_version, policy_id, policy_version, state_document
		FROM app.begin_sla_object_event_v2(
		  $1,$2,$3,$4,$5,$6,$7,$8,$9,$10
		)`, transaction.TenantID, slaUUID(command.Event.ID), string(command.ObjectType),
		slaUUID(command.Event.ObjectID), command.Origin, slaUUID(command.OriginID),
		command.Event.OccurredAt, transaction.Binding.KeyDigest[:], transaction.Binding.RequestDigest[:],
		command.Actor.MembershipID,
	).Scan(&result.fresh, &eventID, &outcome, &slaInstanceID, &aggregateVersion, &policyID, &policyVersion, &result.stateDocument); err != nil {
		return slaEventBeginResult{}, err
	}
	if result.fresh {
		if eventID != slaUUID(command.Event.ID) || outcome != nil || slaInstanceID != nil ||
			aggregateVersion != nil || policyID != nil || policyVersion != nil || len(result.stateDocument) == 0 {
			return slaEventBeginResult{}, errors.New("database returned an invalid fresh SLA event boundary")
		}
		return result, nil
	}
	receipt, err := eventReceiptFromDatabase(
		transaction, eventID, outcome, slaInstanceID, aggregateVersion, policyID, policyVersion,
	)
	if err != nil || len(result.stateDocument) != 0 {
		return slaEventBeginResult{}, errors.New("database returned an invalid SLA event replay")
	}
	result.receipt = receipt
	return result, nil
}

func encodeSLAEventPlan(plan application.EventPlan) ([]byte, error) {
	if plan.Engine == nil {
		return marshalSLADocument(slaRuntimePlanWrite{
			Metrics: []slaMetricRuntimeWrite{}, Cursors: []slaTriggerCursorWrite{},
			Occurrences: []slaTriggerOccurrenceWrite{}, Columns: []slaMaterializedColumnWrite{},
		})
	}
	return encodeSLAEnginePlan(*plan.Engine, true, plan.Assignment != nil)
}

func commitSLAEvent(
	ctx context.Context,
	tx databaseTransaction,
	transaction application.EventTransaction,
	plan application.EventPlan,
	planDocument []byte,
) (application.EventReceipt, error) {
	command := transaction.Command
	outcome := application.EventOutcomeUpdated
	var slaInstanceID, policyID any
	var policyVersion uint64
	if plan.Assignment != nil && !plan.Assignment.Matched() {
		outcome = application.EventOutcomeNoPolicy
	} else if plan.Assignment != nil {
		outcome = application.EventOutcomeAssigned
		policy := plan.Assignment.Policy()
		slaInstanceID, policyID, policyVersion = slaUUID(plan.Assignment.SLAInstanceID()), slaUUID(policy.ID()), policy.Version()
	} else {
		instance := plan.Engine.Metrics()[0].Instance()
		slaInstanceID, policyID, policyVersion = slaUUID(instance.SLAInstanceID()), slaUUID(instance.PolicyID()), instance.PolicyVersion()
	}
	var eventID uuid.UUID
	var storedOutcome string
	var storedSLAInstanceID, storedPolicyID *uuid.UUID
	var aggregateVersion, storedPolicyVersion int64
	var replayed bool
	audit := command.Envelope.Audit
	err := tx.QueryRow(ctx, `
		SELECT event_id, outcome::text, sla_instance_id, aggregate_version,
		       policy_id, policy_version, replayed
		FROM app.commit_sla_object_event_v1(
		  $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb,
		  $15,$16,$17,$18,$19::inet,$20,$21
		)`, transaction.TenantID, slaUUID(command.Event.ID), string(command.ObjectType),
		slaUUID(command.Event.ObjectID), command.Origin, slaUUID(command.OriginID), string(outcome),
		slaInstanceID, plan.ExpectedAggregateVersion, plan.NextAggregateVersion, policyID, policyVersion,
		command.Event.OccurredAt, planDocument, transaction.Binding.KeyDigest[:], transaction.Binding.RequestDigest[:],
		audit.RequestID, audit.CorrelationID, audit.IPAddress, audit.UserAgent, audit.AuthMethod,
	).Scan(&eventID, &storedOutcome, &storedSLAInstanceID, &aggregateVersion, &storedPolicyID, &storedPolicyVersion, &replayed)
	if err != nil {
		return application.EventReceipt{}, err
	}
	if replayed {
		return application.EventReceipt{}, errors.New("fresh SLA event commit unexpectedly replayed")
	}
	return eventReceiptFromDatabase(
		transaction, eventID, &storedOutcome, storedSLAInstanceID, &aggregateVersion, storedPolicyID, &storedPolicyVersion,
	)
}

func eventReceiptFromDatabase(
	transaction application.EventTransaction,
	eventID uuid.UUID,
	outcome *string,
	slaInstanceID *uuid.UUID,
	aggregateVersion *int64,
	policyID *uuid.UUID,
	policyVersion *int64,
) (application.EventReceipt, error) {
	if eventID != slaUUID(transaction.Command.Event.ID) || outcome == nil || aggregateVersion == nil || policyVersion == nil ||
		*aggregateVersion < 0 || *policyVersion < 0 {
		return application.EventReceipt{}, errors.New("database returned an invalid SLA event receipt")
	}
	receipt := application.EventReceipt{
		Command: transaction.Binding, EventID: transaction.Command.Event.ID, TenantID: transaction.TenantID,
		ObjectType: transaction.Command.ObjectType, ObjectID: transaction.Command.Event.ObjectID,
		Outcome: application.EventOutcome(*outcome), AggregateVersion: uint64(*aggregateVersion),
		PolicyVersion: uint64(*policyVersion),
	}
	var err error
	if slaInstanceID != nil {
		value, parseErr := kernel.ParseEntityID(slaInstanceID.String())
		err, receipt.SLAInstanceID = parseErr, &value
	}
	if policyID != nil {
		value, parseErr := kernel.ParseEntityID(policyID.String())
		if err == nil {
			err = parseErr
		}
		receipt.PolicyID = &value
	}
	return receipt, err
}

type slaOverrideBeginResult struct {
	fresh         bool
	receipt       application.OverrideReceipt
	stateDocument []byte
}

func beginSLAOverride(
	ctx context.Context,
	tx databaseTransaction,
	transaction application.OverrideTransaction,
) (slaOverrideBeginResult, error) {
	request := transaction.Request
	var result slaOverrideBeginResult
	var overrideID uuid.UUID
	var outcome *string
	var metricID *uuid.UUID
	var currentVersion, aggregateVersion, policyVersion, permissionEpoch, subjectEpoch *int64
	var policyID *uuid.UUID
	var occurredAt *time.Time
	var metricArgument any
	if request.MetricInstanceID != (kernel.EntityID{}) {
		metricArgument = slaUUID(request.MetricInstanceID)
	}
	var simulationDigest any
	if request.Intent.SimulationDigest != ([32]byte{}) {
		simulationDigest = request.Intent.SimulationDigest[:]
	}
	var replacementCalendarArgument any
	if request.Intent.ReplacementCalendarID != (kernel.EntityID{}) {
		replacementCalendarArgument = slaUUID(request.Intent.ReplacementCalendarID)
	}
	var newPolicyArgument any
	if request.Intent.NewPolicyID != (kernel.EntityID{}) {
		newPolicyArgument = slaUUID(request.Intent.NewPolicyID)
	}
	if err := tx.QueryRow(ctx, `
		SELECT fresh, override_id, outcome::text, metric_instance_id,
		       current_version, aggregate_version, policy_id, policy_version,
		       permission_epoch, subject_epoch, occurred_at, state_document
		FROM app.begin_sla_override_v2(
		  $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18
		)`, transaction.TenantID, slaUUID(request.Intent.ID), string(request.ObjectType),
		slaUUID(request.ObjectID), slaUUID(request.SLAInstanceID), metricArgument, string(request.Intent.Kind),
		request.ExpectedMetricVersion, request.ExpectedAggregateVersion,
		replacementCalendarArgument, request.Intent.ReplacementCalendarVersion,
		newPolicyArgument, request.Intent.NewPolicyVersion, simulationDigest,
		transaction.Binding.KeyDigest[:], transaction.Binding.RequestDigest[:],
		transaction.Actor.MembershipID, transaction.Authority.Capability,
	).Scan(&result.fresh, &overrideID, &outcome, &metricID, &currentVersion, &aggregateVersion,
		&policyID, &policyVersion, &permissionEpoch, &subjectEpoch, &occurredAt, &result.stateDocument); err != nil {
		return slaOverrideBeginResult{}, err
	}
	if result.fresh {
		if overrideID != slaUUID(request.Intent.ID) || outcome != nil || metricID != nil || currentVersion != nil ||
			aggregateVersion != nil || policyID != nil || policyVersion != nil || permissionEpoch != nil ||
			subjectEpoch != nil || occurredAt != nil || len(result.stateDocument) == 0 {
			return slaOverrideBeginResult{}, errors.New("database returned an invalid fresh SLA override boundary")
		}
		return result, nil
	}
	receipt, err := overrideReceiptFromDatabase(
		transaction, overrideID, outcome, metricID, currentVersion, aggregateVersion,
		policyID, policyVersion, permissionEpoch, subjectEpoch, occurredAt,
	)
	if err != nil || len(result.stateDocument) != 0 {
		return slaOverrideBeginResult{}, errors.New("database returned an invalid SLA override replay")
	}
	result.receipt = receipt
	return result, nil
}

func overrideStateFromRuntime(
	request application.OverrideRequest,
	runtime decodedSLARuntimeState,
) (application.OverrideState, error) {
	state := application.OverrideState{
		Metrics: runtime.Metrics, AggregateVersion: runtime.Aggregate.AggregateVersion,
		ReplacementCalendar: runtime.ReplacementCalendar, ReplacementPolicy: runtime.ReplacementPolicy,
		ReplacementCalendars: runtime.ReplacementCalendars, ReplacementColumns: runtime.ReplacementColumns,
		SimulationDigest: runtime.SimulationDigest, OccurredAt: runtime.OccurredAt,
	}
	if request.Intent.Kind != kernel.OverrideChangePolicy {
		for index := range state.Metrics {
			if state.Metrics[index].Instance.ID() == request.MetricInstanceID {
				value := state.Metrics[index]
				state.Metric = &value
				break
			}
		}
		if state.Metric == nil {
			return application.OverrideState{}, errors.New("database omitted the targeted SLA metric")
		}
	}
	return state, nil
}

func encodeSLAOverridePlan(
	plan application.OverridePlan,
	state application.OverrideState,
) ([]byte, [32]byte, error) {
	engine := plan.Materialization
	records := []kernel.OverrideRecord(nil)
	if plan.Policy != nil {
		value := plan.Policy.MaterializationPlan()
		engine = &value
		records = plan.Policy.Records()
	} else if plan.Record != nil {
		records = []kernel.OverrideRecord{*plan.Record}
	}
	if engine == nil || len(records) == 0 {
		return nil, [32]byte{}, errors.New("SLA override plan is incomplete")
	}
	allOtherComplete := true
	for _, work := range state.Metrics {
		if plan.Record != nil && work.Instance.ID() == plan.Instance.ID() {
			continue
		}
		allOtherComplete = allOtherComplete && work.Instance.Snapshot().Lifecycle == kernel.LifecycleCompleted
	}
	raw, err := encodeSLAEnginePlan(*engine, allOtherComplete, true)
	if err != nil {
		return nil, [32]byte{}, err
	}
	var document slaRuntimePlanWrite
	if err := unmarshalSLADocument(raw, &document); err != nil {
		return nil, [32]byte{}, err
	}
	type forensicSnapshot struct {
		PolicyID      uuid.UUID `json:"policy_id"`
		PolicyVersion uint64    `json:"policy_version"`
		MetricID      uuid.UUID `json:"metric_id"`
	}
	previous := make([]forensicSnapshot, len(records))
	current := make([]forensicSnapshot, len(records))
	commandDigest := records[0].CommandDigest()
	for index, record := range records {
		if record.CommandDigest() != commandDigest {
			return nil, [32]byte{}, errors.New("SLA policy override records have different command digests")
		}
		before, after := record.Previous(), record.Next()
		previous[index] = forensicSnapshot{
			PolicyID: slaUUID(before.PolicyID()), PolicyVersion: before.PolicyVersion(),
			MetricID: slaUUID(before.MetricID()),
		}
		current[index] = forensicSnapshot{
			PolicyID: slaUUID(after.PolicyID()), PolicyVersion: after.PolicyVersion(),
			MetricID: slaUUID(after.MetricID()),
		}
	}
	document.PreviousSnapshot, document.CurrentSnapshot = previous, current
	encoded, err := marshalSLADocument(document)
	return encoded, commandDigest, err
}

func commitSLAOverride(
	ctx context.Context,
	tx databaseTransaction,
	transaction application.OverrideTransaction,
	plan application.OverridePlan,
	planDocument []byte,
	commandDigest [32]byte,
) (application.OverrideReceipt, error) {
	request := transaction.Request
	outcome := application.OverrideOutcomeMetricUpdated
	var metricID any
	policyID, policyVersion := plan.Instance.PolicyID(), plan.Instance.PolicyVersion()
	currentVersion := plan.Instance.Version()
	if plan.Policy != nil {
		outcome = application.OverrideOutcomePolicyChanged
		policy := plan.Policy.ReplacementPolicy()
		policyID, policyVersion, currentVersion = policy.ID(), policy.Version(), plan.NextAggregateVersion
	} else {
		metricID = slaUUID(request.MetricInstanceID)
	}
	var simulationDigest any
	if request.Intent.SimulationDigest != ([32]byte{}) {
		simulationDigest = request.Intent.SimulationDigest[:]
	}
	var overrideID uuid.UUID
	var storedOutcome string
	var storedMetricID *uuid.UUID
	var storedCurrentVersion, aggregateVersion, storedPolicyVersion, permissionEpoch, subjectEpoch int64
	var storedPolicyID uuid.UUID
	var occurredAt time.Time
	var replayed bool
	audit := request.Envelope.Audit
	err := tx.QueryRow(ctx, `
		SELECT override_id, outcome::text, metric_instance_id, current_version,
		       aggregate_version, policy_id, policy_version, permission_epoch,
		       subject_epoch, occurred_at, replayed
		FROM app.commit_sla_override_v1(
		  $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,
		  $19,$20,$21::jsonb,$22,$23,$24,$25,$26::inet,$27,$28
		)`, transaction.TenantID, slaUUID(request.Intent.ID), string(request.ObjectType),
		slaUUID(request.ObjectID), slaUUID(request.SLAInstanceID), metricID, string(request.Intent.Kind),
		request.Intent.Reason, string(outcome), plan.ExpectedAggregateVersion, plan.NextAggregateVersion,
		overridePreviousVersion(request), currentVersion, slaUUID(policyID), policyVersion,
		transaction.Authority.PermissionEpoch, transaction.Authority.SubjectEpoch, stateOccurredAt(plan),
		commandDigest[:], simulationDigest, planDocument, transaction.Binding.KeyDigest[:], transaction.Binding.RequestDigest[:],
		audit.RequestID, audit.CorrelationID, audit.IPAddress, audit.UserAgent, audit.AuthMethod,
	).Scan(&overrideID, &storedOutcome, &storedMetricID, &storedCurrentVersion, &aggregateVersion,
		&storedPolicyID, &storedPolicyVersion, &permissionEpoch, &subjectEpoch, &occurredAt, &replayed)
	if err != nil {
		return application.OverrideReceipt{}, err
	}
	if replayed {
		return application.OverrideReceipt{}, errors.New("fresh SLA override commit unexpectedly replayed")
	}
	return overrideReceiptFromDatabase(
		transaction, overrideID, &storedOutcome, storedMetricID, &storedCurrentVersion, &aggregateVersion,
		&storedPolicyID, &storedPolicyVersion, &permissionEpoch, &subjectEpoch, &occurredAt,
	)
}

func stateOccurredAt(plan application.OverridePlan) time.Time {
	if plan.Record != nil {
		return plan.Record.OccurredAt()
	}
	if plan.Policy != nil && len(plan.Policy.Records()) != 0 {
		return plan.Policy.Records()[0].OccurredAt()
	}
	return time.Time{}
}

func overridePreviousVersion(request application.OverrideRequest) uint64 {
	if request.Intent.Kind == kernel.OverrideChangePolicy {
		return request.ExpectedAggregateVersion
	}
	return request.ExpectedMetricVersion
}

func overrideReceiptFromDatabase(
	transaction application.OverrideTransaction,
	overrideID uuid.UUID,
	outcome *string,
	metricID *uuid.UUID,
	currentVersion, aggregateVersion *int64,
	policyID *uuid.UUID,
	policyVersion, permissionEpoch, subjectEpoch *int64,
	occurredAt *time.Time,
) (application.OverrideReceipt, error) {
	request := transaction.Request
	if overrideID != slaUUID(request.Intent.ID) || outcome == nil || currentVersion == nil || aggregateVersion == nil ||
		policyID == nil || policyVersion == nil || permissionEpoch == nil || subjectEpoch == nil || occurredAt == nil ||
		*currentVersion < 1 || *aggregateVersion < 1 || *policyVersion < 1 || *permissionEpoch < 1 || *subjectEpoch < 1 {
		return application.OverrideReceipt{}, errors.New("database returned an invalid SLA override receipt")
	}
	parsedPolicyID, err := kernel.ParseEntityID(policyID.String())
	if err != nil || !normalizeSLAInstant(occurredAt) {
		return application.OverrideReceipt{}, errors.New("database returned an invalid SLA override receipt identity")
	}
	actorID, err := kernel.ParseEntityID(transaction.Actor.MembershipID.String())
	if err != nil {
		return application.OverrideReceipt{}, err
	}
	receipt := application.OverrideReceipt{
		Command: transaction.Binding, OverrideID: request.Intent.ID, TenantID: transaction.TenantID,
		ObjectType: request.ObjectType, ObjectID: request.ObjectID, Outcome: application.OverrideOutcome(*outcome),
		Kind: request.Intent.Kind, SLAInstanceID: request.SLAInstanceID,
		PreviousVersion: overridePreviousVersion(request), CurrentVersion: uint64(*currentVersion),
		AggregateVersion: uint64(*aggregateVersion), PolicyID: parsedPolicyID, PolicyVersion: uint64(*policyVersion),
		ActorID: actorID, PermissionEpoch: uint64(*permissionEpoch), SubjectEpoch: uint64(*subjectEpoch),
		OccurredAt: *occurredAt, SimulationDigest: request.Intent.SimulationDigest,
	}
	if metricID != nil {
		parsed, parseErr := kernel.ParseEntityID(metricID.String())
		if parseErr != nil {
			return application.OverrideReceipt{}, parseErr
		}
		receipt.MetricInstanceID = &parsed
	}
	return receipt, nil
}

func slaObjectReadCapability(objectType kernel.ObjectType) (application.Capability, bool) {
	switch objectType {
	case kernel.ObjectAlert:
		return application.CapabilityAlertRead, true
	case kernel.ObjectCase:
		return application.CapabilityCaseRead, true
	default:
		return "", false
	}
}
