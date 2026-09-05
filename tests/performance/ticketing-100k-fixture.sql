\set ON_ERROR_STOP on

SET ROLE periapsis_migrator;
SET TIME ZONE 'UTC';
SET statement_timeout = '15min';
SET lock_timeout = '30s';

DO $fixture_guard$
DECLARE
  target_tenant uuid;
  administrator_user uuid;
  existing_alerts bigint;
  existing_cases bigint;
BEGIN
  IF current_setting('server_version_num') <> '180006' THEN
    RAISE EXCEPTION 'performance fixture requires PostgreSQL 18.6';
  END IF;
  IF current_database() !~ '^periapsis_performance_[0-9]{13}_[0-9a-f]{12}$' THEN
    RAISE EXCEPTION 'performance fixture requires an explicitly disposable database';
  END IF;
  SELECT id INTO STRICT target_tenant
  FROM public.tenants
  WHERE slug = 'acme';
  SELECT count(*) INTO existing_alerts
  FROM public.alerts
  WHERE tenant_id = target_tenant;
  IF existing_alerts <> 1 OR NOT EXISTS (
    SELECT 1 FROM public.alerts
    WHERE tenant_id = target_tenant
      AND id = '01993ea0-0000-7000-8000-000000000301'::uuid
  ) THEN
    RAISE EXCEPTION 'performance fixture requires the fresh canonical seed';
  END IF;
  SELECT count(*) INTO existing_cases
  FROM public.cases
  WHERE tenant_id = target_tenant;
  IF existing_cases <> 1 OR NOT EXISTS (
    SELECT 1 FROM public.cases
    WHERE tenant_id = target_tenant
      AND id = '01993ea0-0000-7000-8000-000000001101'::uuid
  ) THEN
    RAISE EXCEPTION 'performance fixture requires the exact canonical demo Case';
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.custom_field_definitions
    WHERE tenant_id = target_tenant AND key = 'performance_score'
  ) OR EXISTS (
    SELECT 1 FROM public.sla_columns
    WHERE tenant_id = target_tenant AND key = 'performance-due-at'
  ) THEN
    RAISE EXCEPTION 'performance fixture must not be reused';
  END IF;
  SELECT user_id INTO STRICT administrator_user
  FROM public.tenant_memberships
  WHERE tenant_id = target_tenant AND role = 'tenant_admin' AND status = 'active';
  -- This psql file uses autocommit. Keep context for the whole disposable session;
  -- even migrator-owned fixture inserts must satisfy the numbering tenant fence.
  PERFORM set_config('app.tenant_id', target_tenant::text, false);
  PERFORM set_config('app.user_id', administrator_user::text, false);
  PERFORM set_config('app.service_account_id', '', false);
END;
$fixture_guard$;

-- The runner supplies the generated kernel document as one psql variable.
-- Publish before ticket creation: ingress captures immutable assignment snapshots.
SET app.performance_sla_fixture = :'sla_fixture';
BEGIN;
SET LOCAL ROLE periapsis_api;
DO $publish_performance_sla$
DECLARE
  fixture jsonb := current_setting('app.performance_sla_fixture')::jsonb;
  target_tenant uuid := current_setting('app.tenant_id')::uuid;
BEGIN
  IF fixture->'identity' IS DISTINCT FROM '{
    "tenant_id":"01993ea0-0000-7000-8000-000000000001",
    "calendar_id":"01b00000-0000-7000-8000-000000000023",
    "policy_id":"01b00000-0000-7000-8000-000000000020",
    "metric_id":"01b00000-0000-7000-8000-000000000021",
    "trigger_id":"01b00000-0000-7000-8000-000000000024",
    "column_id":"01b00000-0000-7000-8000-000000000022",
    "object_type":"alert","key_prefix":"performance",
    "effective_from":"2026-01-02T12:00:00Z","duration_micros":1000000,
    "completion_event":"ticket.in_progress"
  }'::jsonb OR (fixture->'identity'->>'tenant_id')::uuid <> target_tenant THEN
    RAISE EXCEPTION 'performance SLA fixture identity drifted';
  END IF;
  PERFORM app.publish_sla_calendar_v2(
    target_tenant, (fixture->'identity'->>'calendar_id')::uuid, 0, fixture->'calendar',
    sha256(convert_to('performance:sla-calendar:key', 'UTF8')),
    sha256(convert_to((fixture->'calendar')::text, 'UTF8')),
    uuidv7(), uuidv7(), '127.0.0.1'::inet, 'performance_harness', 'bootstrap_totp'
  );
  PERFORM app.publish_sla_policy_v2(
    target_tenant, (fixture->'identity'->>'policy_id')::uuid, 0, fixture->'policy',
    sha256(convert_to('performance:sla-policy:key', 'UTF8')),
    sha256(convert_to((fixture->'policy')::text, 'UTF8')),
    uuidv7(), uuidv7(), '127.0.0.1'::inet, 'performance_harness', 'bootstrap_totp'
  );
  PERFORM app.publish_sla_column_v2(
    target_tenant, (fixture->'identity'->>'column_id')::uuid, 0, fixture->'column',
    sha256(convert_to('performance:sla-column:key', 'UTF8')),
    sha256(convert_to((fixture->'column')::text, 'UTF8')),
    uuidv7(), uuidv7(), '127.0.0.1'::inet, 'performance_harness', 'bootstrap_totp'
  );
END;
$publish_performance_sla$;
COMMIT;

INSERT INTO public.operator_team_assignment_epochs (
  id, tenant_id, operator_team_id, assigned_by_membership_id,
  assignment_reason, assigned_at, version, updated_at
)
SELECT
  '01b00000-0000-7000-8000-000000000001'::uuid,
  tenant.id,
  team.id,
  administrator.id,
  'Synthetic 100k-ticket performance fixture.',
  '2026-08-01 00:00:00+00'::timestamptz,
  1,
  '2026-08-01 00:00:00+00'::timestamptz
FROM public.tenants AS tenant
JOIN public.tenant_memberships AS administrator
  ON administrator.tenant_id = tenant.id
 AND administrator.role = 'tenant_admin'
 AND administrator.status = 'active'
JOIN public.operator_teams AS team
  ON team.key = 'soc_l1' AND team.archived_at IS NULL
WHERE tenant.slug = 'acme';

INSERT INTO public.operator_team_roster_entries (
  id, tenant_id, assignment_epoch_id, membership_id, source_id,
  granted_by_membership_id, grant_reason, granted_at, version, updated_at
)
SELECT
  uuidv7(), tenant.id,
  '01b00000-0000-7000-8000-000000000001'::uuid,
  member.id, source.id, administrator.id,
  'Synthetic performance roster membership.',
  '2026-08-01 00:00:00+00'::timestamptz, 1,
  '2026-08-01 00:00:00+00'::timestamptz
FROM public.tenants AS tenant
JOIN public.tenant_memberships AS administrator
  ON administrator.tenant_id = tenant.id
 AND administrator.role = 'tenant_admin'
 AND administrator.status = 'active'
JOIN public.tenant_memberships AS member
  ON member.tenant_id = tenant.id
 AND member.role IN ('tenant_admin', 'analyst')
 AND member.status = 'active'
JOIN public.tenant_authorization_sources AS source
  ON source.tenant_id = tenant.id
 AND source.key = 'manual'
 AND source.retired_at IS NULL
WHERE tenant.slug = 'acme';

INSERT INTO public.custom_field_definitions (
  id, tenant_id, object_type, key, label, description, data_type,
  required, nullable, has_default, show_in_create, show_in_detail,
  show_in_list, show_in_export, searchable, filterable, sortable,
  allow_structured_json, schema_version, created_by_membership_id,
  updated_by_membership_id, created_at, updated_at
)
SELECT
  '01b00000-0000-7000-8000-000000000010'::uuid,
  tenant.id, 'alert', 'performance_score', 'Performance score',
  'Synthetic bounded integer used only by the disposable performance gate.',
  'integer', false, false, false, false, true, true, true,
  false, true, true, false, 1, administrator.id, administrator.id,
  '2026-08-01 00:00:00+00'::timestamptz,
  '2026-08-01 00:00:00+00'::timestamptz
FROM public.tenants AS tenant
JOIN public.tenant_memberships AS administrator
  ON administrator.tenant_id = tenant.id
 AND administrator.role = 'tenant_admin'
 AND administrator.status = 'active'
WHERE tenant.slug = 'acme';

INSERT INTO public.custom_field_definition_revisions (
  id, tenant_id, definition_id, object_type, schema_version, snapshot,
  created_by_membership_id, created_at
)
SELECT
  '01b00000-0000-7000-8000-000000000011'::uuid,
  definition.tenant_id, definition.id, definition.object_type,
  definition.schema_version,
  jsonb_build_object(
    'id', definition.id, 'tenantId', definition.tenant_id,
    'objectType', definition.object_type, 'key', definition.key,
    'label', definition.label, 'description', definition.description,
    'dataType', definition.data_type, 'required', definition.required,
    'nullable', definition.nullable, 'default', NULL,
    'defaultPresence', 'missing',
    'constraints', jsonb_build_object(
      'minimumLength', NULL, 'maximumLength', NULL,
      'minimum', NULL, 'maximum', NULL, 'pattern', NULL
    ),
    'options', '[]'::jsonb,
    'permissions', jsonb_build_array(
      jsonb_build_object(
        'audience', 'operator', 'read', true, 'create', false, 'update', false
      ),
      jsonb_build_object(
        'audience', 'customer', 'read', false, 'create', false, 'update', false
      )
    ),
    'visibility', jsonb_build_object(
      'operator', jsonb_build_object('read', true, 'create', false, 'update', false),
      'customer', jsonb_build_object('read', false, 'create', false, 'update', false)
    ),
    'editPolicy', jsonb_build_object('mode', 'always'),
    'placement', jsonb_build_object(
      'create', false, 'detail', true, 'list', true, 'export', true
    ),
    'requiredOnTransitions', '[]'::jsonb,
    'capabilities', jsonb_build_object(
      'searchable', false, 'filterable', true, 'sortable', true,
      'allowStructuredJson', false
    ),
    'searchable', false, 'filterable', true, 'sortable', true,
    'allowStructuredJson', false, 'archived', false,
    'schemaVersion', definition.schema_version
  ),
  definition.created_by_membership_id,
  '2026-08-01 00:00:00+00'::timestamptz
FROM public.custom_field_definitions AS definition
WHERE definition.id = '01b00000-0000-7000-8000-000000000010'::uuid;

INSERT INTO public.custom_field_permissions (
  tenant_id, definition_id, audience, can_read, can_create,
  can_update, schema_version
)
SELECT definition.tenant_id, definition.id, audience.value,
       audience.value = 'operator', false, false, definition.schema_version
FROM public.custom_field_definitions AS definition
CROSS JOIN (VALUES
  ('operator'::public.custom_field_audience),
  ('customer'::public.custom_field_audience)
) AS audience(value)
WHERE definition.id = '01b00000-0000-7000-8000-000000000010'::uuid;

DO $load_alert_batches$
DECLARE
  batch_start integer;
  transition_key text;
  transition_from text;
  transition_to text;
  transitioned_rows integer;
BEGIN
  SELECT transition.value ->> 'key', transition.value ->> 'from', transition.value ->> 'to'
  INTO STRICT transition_key, transition_from, transition_to
  FROM public.ticket_workflows AS workflow
  JOIN public.ticket_workflow_versions AS version
    ON version.tenant_id = workflow.tenant_id AND version.workflow_id = workflow.id
   AND version.version = workflow.current_version AND version.aggregate_kind = 'alert'
  CROSS JOIN LATERAL jsonb_array_elements(version.transitions) AS transition(value)
  WHERE workflow.tenant_id = current_setting('app.tenant_id')::uuid
    AND workflow.key = 'default_alert' AND workflow.aggregate_kind = 'alert'
    AND transition.value ->> 'key' = 'start_investigation';
  -- Canonical numbering holds one transaction-level advisory lock per ticket.
  FOR batch_start IN 1..99999 BY 1000 LOOP
    WITH fixture AS MATERIALIZED (
      SELECT tenant.id AS tenant_id,
             workflow.id AS workflow_id,
             workflow.current_version AS workflow_version,
             administrator.user_id AS administrator_user_id,
             administrator.id AS administrator_membership_id,
             analyst.user_id AS analyst_user_id,
             analyst.id AS analyst_membership_id,
             '01b00000-0000-7000-8000-000000000001'::uuid AS assignment_epoch_id,
             team.id AS team_id,
             coalesce((
               SELECT state.value ->> 'key'
               FROM public.ticket_workflow_versions AS version,
                    LATERAL jsonb_array_elements(version.states) AS state(value)
               WHERE version.tenant_id = tenant.id
                 AND version.workflow_id = workflow.id
                 AND version.version = workflow.current_version
                 AND (state.value ->> 'initial')::boolean
               LIMIT 1
             ), 'new') AS initial_state
      FROM public.tenants AS tenant
      JOIN public.ticket_workflows AS workflow
        ON workflow.tenant_id = tenant.id
       AND workflow.aggregate_kind = 'alert'
       AND workflow.key = 'default_alert'
       AND workflow.archived_at IS NULL
      JOIN public.tenant_memberships AS administrator
        ON administrator.tenant_id = tenant.id
       AND administrator.role = 'tenant_admin'
       AND administrator.status = 'active'
      JOIN public.tenant_memberships AS analyst
        ON analyst.tenant_id = tenant.id
       AND analyst.role = 'analyst'
       AND analyst.status = 'active'
      JOIN public.operator_teams AS team
        ON team.key = 'soc_l1' AND team.archived_at IS NULL
      WHERE tenant.slug = 'acme'
    ), generated AS MATERIALIZED (
      SELECT series AS ordinal,
             transaction_timestamp() AS occurred_at
      FROM generate_series(batch_start, least(batch_start + 999, 99999)) AS series
    )
    INSERT INTO public.alerts (
      id, tenant_id, number, workflow_id, workflow_version, state_key,
      customer_visible, external_id, title, description, status, severity,
      priority, category, source, source_type, tags, custom_fields,
      customer_custom_fields, raw_payload, assigned_team_id,
      assigned_team_epoch_id, assignee_user_id, claimed_by_user_id,
      created_by, created_by_membership_id, detected_at, received_at,
      created_at, updated_at, version
    )
    SELECT
      uuidv7(), fixture.tenant_id,
      NULL, -- The canonical insert trigger allocates the immutable policy-bound number.
      fixture.workflow_id, fixture.workflow_version, fixture.initial_state,
      false,
      'performance-alert-' || lpad(generated.ordinal::text, 6, '0'),
      'Synthetic performance Alert ' || generated.ordinal,
      'Non-sensitive deterministic fixture payload.',
      'new'::public.alert_status,
      (ARRAY['informational','low','medium','high','critical']::public.alert_severity[])
        [1 + generated.ordinal % 5],
      (ARRAY['low','medium','high','urgent','critical']::text[])
        [1 + generated.ordinal % 5],
      'performance', 'performance', 'synthetic', ARRAY['performance'],
      '{}'::jsonb, '{}'::jsonb, '{}'::jsonb,
      CASE WHEN generated.ordinal % 10 = 0 THEN fixture.team_id END,
      CASE WHEN generated.ordinal % 10 = 0 THEN fixture.assignment_epoch_id END,
      CASE WHEN generated.ordinal % 10 = 0 THEN fixture.analyst_user_id END,
      NULL,
      fixture.analyst_user_id, fixture.analyst_membership_id,
      generated.occurred_at, generated.occurred_at,
      generated.occurred_at, generated.occurred_at, 1
    FROM generated
    CROSS JOIN fixture;
    COMMIT;
    SET LOCAL ROLE periapsis_api;
    -- Ten real transitions per creation batch give a selective state population.
    -- Keep assigned tickets at version 1 for the independent claim workload.
    WITH candidates AS MATERIALIZED (
      SELECT ticket.* FROM public.alerts AS ticket
      WHERE ticket.tenant_id = current_setting('app.tenant_id')::uuid
        AND ticket.external_id BETWEEN
          'performance-alert-' || lpad(batch_start::text, 6, '0') AND
          'performance-alert-' || lpad(least(batch_start + 999, 99999)::text, 6, '0')
        AND ticket.assigned_team_id IS NULL
        AND ticket.version = 1 AND ticket.state_key = transition_from
      ORDER BY ticket.external_id
      LIMIT 10
    )
    SELECT count(*) INTO transitioned_rows
    FROM candidates AS ticket
    CROSS JOIN LATERAL app.apply_tenant_ticket_mutation_v2(
      'alert', ticket.id, 'transition', 1, 2,
      ticket.workflow_id, ticket.workflow_version, transition_from, transition_to,
      transition_key, ticket.customer_visible, NULL, NULL, NULL,
      'Synthetic selective-state performance fixture.', NULL, NULL, '{}'::jsonb,
      sha256(convert_to('performance-transition-key:' || ticket.id::text, 'UTF8')),
      sha256(convert_to('performance-transition-request:' || ticket.id::text, 'UTF8')),
      uuidv7(), uuidv7(), '192.0.2.10'::inet, 'Periapsis performance harness', 'totp'
    ) AS transitioned;
    IF transitioned_rows <> 10 THEN
      RAISE EXCEPTION 'performance fixture transition batch cardinality drifted';
    END IF;
    COMMIT;
    -- Creation triggers grow this queue too. Refresh its statistics before the
    -- next batch so cached trigger plans do not retain empty-table estimates.
    ANALYZE public.sla_object_event_ingress;
  END LOOP;
END;
$load_alert_batches$;

DO $load_case_batches$
DECLARE
  batch_start integer;
BEGIN
  -- Canonical numbering holds one transaction-level advisory lock per ticket.
  FOR batch_start IN 1..99999 BY 1000 LOOP
    WITH fixture AS MATERIALIZED (
      SELECT tenant.id AS tenant_id,
             workflow.id AS workflow_id,
             workflow.current_version AS workflow_version,
             administrator.id AS administrator_membership_id,
             administrator.user_id AS administrator_user_id,
             (
               SELECT state.value ->> 'key'
               FROM public.ticket_workflow_versions AS version,
                    LATERAL jsonb_array_elements(version.states) AS state(value)
               WHERE version.tenant_id = tenant.id
                 AND version.workflow_id = workflow.id
                 AND version.version = workflow.current_version
                 AND (state.value ->> 'initial')::boolean
             ) AS initial_state
      FROM public.tenants AS tenant
      JOIN public.ticket_workflows AS workflow
        ON workflow.tenant_id = tenant.id
       AND workflow.aggregate_kind = 'case'
       AND workflow.key = 'default_case'
       AND workflow.archived_at IS NULL
      JOIN public.tenant_memberships AS administrator
        ON administrator.tenant_id = tenant.id
       AND administrator.role = 'tenant_admin'
       AND administrator.status = 'active'
      WHERE tenant.slug = 'acme'
    ), generated AS MATERIALIZED (
      SELECT series AS ordinal,
             transaction_timestamp() AS occurred_at
      FROM generate_series(batch_start, least(batch_start + 999, 99999)) AS series
    )
    INSERT INTO public.cases (
      id, tenant_id, number, workflow_id, workflow_version, state_key,
      customer_visible, title, description, summary, severity, priority,
      category, classification, tags, custom_fields, customer_custom_fields,
      created_by_membership_id, created_by_user_id, detection_time, opened_at,
      created_at, updated_at, version
    )
    SELECT
      uuidv7(), fixture.tenant_id,
      NULL, -- The canonical insert trigger allocates the immutable policy-bound number.
      fixture.workflow_id, fixture.workflow_version, fixture.initial_state,
      false,
      'Synthetic performance Case ' || generated.ordinal,
      'Non-sensitive deterministic fixture payload.',
      'Synthetic 100k-Case performance fixture.',
      (ARRAY['informational','low','medium','high','critical']::public.alert_severity[])
        [1 + generated.ordinal % 5],
      (ARRAY['low','medium','high','urgent','critical']::text[])
        [1 + generated.ordinal % 5],
      'performance', NULL, ARRAY['performance'], '{}'::jsonb, '{}'::jsonb,
      fixture.administrator_membership_id, fixture.administrator_user_id,
      generated.occurred_at, generated.occurred_at,
      generated.occurred_at, generated.occurred_at, 1
    FROM generated
    CROSS JOIN fixture;
    COMMIT;
  END LOOP;
END;
$load_case_batches$;

WITH target AS MATERIALIZED (
  SELECT alert.id AS alert_id, alert.tenant_id,
         row_number() OVER (ORDER BY alert.id) AS ordinal,
         administrator.id AS administrator_membership_id
  FROM public.alerts AS alert
  JOIN public.tenants AS tenant ON tenant.id = alert.tenant_id
  JOIN public.tenant_memberships AS administrator
    ON administrator.tenant_id = tenant.id
   AND administrator.role = 'tenant_admin'
   AND administrator.status = 'active'
  WHERE tenant.slug = 'acme'
)
INSERT INTO public.custom_field_values (
  id, tenant_id, object_type, alert_id, definition_id,
  definition_schema_version, data_type, presence, canonical_value,
  integer_value, created_by_membership_id, updated_by_membership_id,
  version, created_at, updated_at
)
SELECT
  uuidv7(), target.tenant_id, 'alert', target.alert_id,
  '01b00000-0000-7000-8000-000000000010'::uuid,
  1, 'integer', 'present', to_jsonb((target.ordinal % 100)::bigint),
  target.ordinal % 100, target.administrator_membership_id,
  target.administrator_membership_id, 1,
  '2026-08-01 00:10:00+00'::timestamptz,
  '2026-08-01 00:10:00+00'::timestamptz
FROM target;

-- SLA instances, metrics, projections and timers are created only by the real
-- worker after this setup. Never manufacture assignment snapshots or queue state.

WITH target AS MATERIALIZED (
  SELECT alert.tenant_id, alert.id,
         row_number() OVER (ORDER BY alert.id) AS ordinal
  FROM public.alerts AS alert
  JOIN public.tenants AS tenant ON tenant.id = alert.tenant_id
  WHERE tenant.slug = 'acme'
  ORDER BY alert.id
  LIMIT 10000
)
INSERT INTO public.outbox_events (
  id, tenant_id, aggregate_type, aggregate_id, aggregate_version,
  event_type, schema_version, payload, deduplication_key, actor_kind,
  actor_id, producer, maximum_audience, occurred_at, available_at,
  attempts, max_attempts, created_at
)
SELECT uuidv7(), target.tenant_id, 'alert', target.id, 1,
       'notification.alert.created', 2,
       jsonb_build_object(
         'operatorContext', jsonb_build_object(
           'alert', jsonb_build_object('id', target.id, 'version', 1)
         )
       ),
       'performance-notification:' || target.ordinal,
       'system', NULL, 'performance_harness', 'operator',
       '2026-08-01 00:40:00+00'::timestamptz
         + target.ordinal * interval '1 microsecond',
       '2026-08-01 00:40:00+00'::timestamptz
         + target.ordinal * interval '1 microsecond',
       0, 12,
       '2026-08-01 00:40:00+00'::timestamptz
         + target.ordinal * interval '1 microsecond'
FROM target;

ANALYZE public.alerts;
ANALYZE public.cases;
ANALYZE public.custom_field_values;
ANALYZE public.sla_instances;
ANALYZE public.sla_metric_instances;
ANALYZE public.sla_materialized_column_values;
ANALYZE public.sla_evaluation_jobs;
ANALYZE public.outbox_events;

DO $fixture_assertions$
DECLARE
  target_tenant uuid;
  initial_alert_state text;
  active_alert_state text;
  transitioned_count integer;
  transitioned_critical_count integer;
  batch_count integer;
BEGIN
  SELECT id INTO STRICT target_tenant FROM public.tenants WHERE slug = 'acme';
  SELECT state.value->>'key' INTO STRICT initial_alert_state
  FROM public.ticket_workflows AS workflow
  JOIN public.ticket_workflow_versions AS version
    ON version.tenant_id = workflow.tenant_id
   AND version.workflow_id = workflow.id
   AND version.aggregate_kind = workflow.aggregate_kind
   AND version.version = workflow.current_version
  CROSS JOIN LATERAL jsonb_array_elements(version.states) AS state(value)
  WHERE workflow.tenant_id = target_tenant AND workflow.aggregate_kind = 'alert'
    AND workflow.key = 'default_alert' AND (state.value->>'initial')::boolean;
  SELECT transition.value ->> 'to' INTO STRICT active_alert_state
  FROM public.ticket_workflows AS workflow
  JOIN public.ticket_workflow_versions AS version
    ON version.tenant_id = workflow.tenant_id AND version.workflow_id = workflow.id
   AND version.version = workflow.current_version AND version.aggregate_kind = 'alert'
  CROSS JOIN LATERAL jsonb_array_elements(version.transitions) AS transition(value)
  WHERE workflow.tenant_id = target_tenant AND workflow.key = 'default_alert'
    AND workflow.aggregate_kind = 'alert'
    AND transition.value ->> 'key' = 'start_investigation'
    AND transition.value ->> 'from' = initial_alert_state;
  SELECT count(*) FILTER (WHERE version = 2),
         count(*) FILTER (WHERE version = 2 AND severity = 'critical'),
         count(DISTINCT created_at)
  INTO transitioned_count, transitioned_critical_count, batch_count
  FROM public.alerts
  WHERE tenant_id = target_tenant AND external_id LIKE 'performance-alert-%';
  IF active_alert_state = initial_alert_state OR transitioned_count <> 1000
     OR transitioned_critical_count <> 200 OR batch_count <> 100 OR EXISTS (
    SELECT 1 FROM public.alerts
    WHERE tenant_id = target_tenant AND external_id LIKE 'performance-alert-%'
      AND NOT (
        version = 1 AND state_key = initial_alert_state AND status = 'new'
        OR version = 2 AND state_key = active_alert_state AND status = 'in_progress'
          AND assigned_team_id IS NULL AND acknowledged_at IS NOT NULL
          AND updated_at > created_at
      )
  ) THEN
    RAISE EXCEPTION 'performance fixture state distribution drifted';
  END IF;
  IF EXISTS (
    WITH batches AS (
      SELECT created_at, count(*) AS population,
             count(*) FILTER (WHERE version = 2) AS transitioned,
             count(*) FILTER (WHERE version = 2 AND severity = 'critical') AS critical,
             max(updated_at) AS last_update,
             lead(created_at) OVER (ORDER BY created_at) AS next_created_at
      FROM public.alerts
      WHERE tenant_id = target_tenant AND external_id LIKE 'performance-alert-%'
      GROUP BY created_at
    )
    SELECT 1 FROM batches
    WHERE population NOT IN (999, 1000) OR transitioned <> 10 OR critical <> 2
      OR last_update >= next_created_at
  ) THEN
    RAISE EXCEPTION 'performance fixture transition chronology drifted';
  END IF;
  IF (SELECT count(*) FROM public.alerts WHERE tenant_id = target_tenant) <> 100000 THEN
    RAISE EXCEPTION 'performance fixture did not create exactly 100000 Alerts';
  END IF;
  IF (SELECT count(*) FROM public.cases WHERE tenant_id = target_tenant) <> 100000 THEN
    RAISE EXCEPTION 'performance fixture did not create exactly 100000 Cases';
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.alerts AS ticket
    WHERE ticket.tenant_id = target_tenant AND NOT EXISTS (
      SELECT 1 FROM public.tenant_ticket_numbering_receipts AS receipt
      WHERE receipt.tenant_id = ticket.tenant_id AND receipt.aggregate_kind = 'alert'
        AND receipt.aggregate_id = ticket.id AND receipt.number = ticket.number
    )
  ) OR EXISTS (
    SELECT 1 FROM public.cases AS ticket
    WHERE ticket.tenant_id = target_tenant AND NOT EXISTS (
      SELECT 1 FROM public.tenant_ticket_numbering_receipts AS receipt
      WHERE receipt.tenant_id = ticket.tenant_id AND receipt.aggregate_kind = 'case'
        AND receipt.aggregate_id = ticket.id AND receipt.number = ticket.number
    )
  ) THEN
    RAISE EXCEPTION 'performance fixture ticket numbering receipt drifted';
  END IF;
  IF (SELECT count(*) FROM public.custom_field_values
      WHERE tenant_id = target_tenant
        AND definition_id = '01b00000-0000-7000-8000-000000000010'::uuid) <> 100000 THEN
    RAISE EXCEPTION 'performance fixture custom-field cardinality drifted';
  END IF;
  IF EXISTS (SELECT 1 FROM public.sla_instances
      WHERE tenant_id = target_tenant
        AND policy_id = '01b00000-0000-7000-8000-000000000020'::uuid) THEN
    RAISE EXCEPTION 'performance SLA state must be produced by the worker after setup';
  END IF;
  IF (SELECT count(*) FROM public.outbox_events
      WHERE tenant_id = target_tenant
        AND event_type = 'notification.alert.created'
        AND schema_version = 2) <> 10000 THEN
    RAISE EXCEPTION 'performance fixture notification queue cardinality drifted';
  END IF;
END;
$fixture_assertions$;
