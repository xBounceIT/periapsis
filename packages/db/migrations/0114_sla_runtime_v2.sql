-- Phase 5 runtime ABI v2. Replay lookup happens after a live resource
-- authorization check but before any planner-shaped document is assembled.
-- Runtime documents are version-pinned and closed by the Go decoders.

CREATE FUNCTION app.private_sla_runtime_metric_document_v2(
  p_tenant_id uuid,
  p_metric_instance_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE document jsonb;
BEGIN
  SELECT to_jsonb(metric) - 'state' - 'last_override_digest'
      || jsonb_build_object(
        'last_override_digest', CASE
          WHEN metric.last_override_digest IS NULL THEN NULL
          ELSE encode(metric.last_override_digest, 'hex')
        END,
        'definition', app.private_sla_metric_document_v2(
          metric.tenant_id, metric.definition_id
        ),
        'calendar', CASE WHEN definition.calendar_id IS NULL THEN NULL
          ELSE app.private_sla_configuration_document_v2(
            metric.tenant_id, 'calendar', definition.calendar_id,
            definition.calendar_version
          ) END,
        'triggers', coalesce((
          SELECT jsonb_agg(
            to_jsonb(trigger_row) - 'tenant_id' - 'policy_id'
              - 'policy_version' - 'created_at' - 'definition_digest'
              || jsonb_build_object(
                'definition_digest', encode(trigger_row.definition_digest, 'hex')
              )
            ORDER BY trigger_row.position, trigger_row.id
          )
          FROM public.sla_trigger_definitions AS trigger_row
          WHERE trigger_row.tenant_id = metric.tenant_id
            AND trigger_row.policy_id = metric.policy_id
            AND trigger_row.policy_version = metric.policy_version
            AND trigger_row.metric_definition_id = metric.definition_id
        ), '[]'::jsonb),
        'cursors', coalesce((
          SELECT jsonb_agg(
            to_jsonb(cursor_row) - 'tenant_id' - 'metric_instance_id'
              - 'updated_at'
            ORDER BY cursor_row.trigger_definition_id
          )
          FROM public.sla_trigger_cursors AS cursor_row
          WHERE cursor_row.tenant_id = metric.tenant_id
            AND cursor_row.metric_instance_id = metric.id
        ), '[]'::jsonb),
        'columns', coalesce((
          SELECT jsonb_agg(
            app.private_sla_configuration_document_v2(
              value_row.tenant_id, 'column', value_row.column_id,
              value_row.column_version
            ) ORDER BY value_row.column_id
          )
          FROM public.sla_materialized_column_values AS value_row
          WHERE value_row.tenant_id = metric.tenant_id
            AND value_row.metric_instance_id = metric.id
        ), '[]'::jsonb)
      )
  INTO document
  FROM public.sla_metric_instances AS metric
  JOIN public.sla_metric_definitions AS definition
    ON definition.tenant_id = metric.tenant_id
   AND definition.id = metric.definition_id
   AND definition.policy_id = metric.policy_id
   AND definition.policy_version = metric.policy_version
  WHERE metric.tenant_id = p_tenant_id
    AND metric.id = p_metric_instance_id;
  IF document IS NULL OR pg_column_size(document) > 16777216 THEN
    RAISE EXCEPTION 'SLA runtime metric is unavailable'
      USING ERRCODE = 'P0002';
  END IF;
  RETURN document;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_sla_runtime_metric_document_v2(uuid, uuid)
  OWNER TO periapsis_sla_api_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_sla_runtime_metric_document_v2(uuid, uuid)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
--> statement-breakpoint

CREATE FUNCTION app.read_sla_runtime_state_v2(
  p_tenant_id uuid,
  p_object_type public.sla_object_type,
  p_object_id uuid,
  p_capability text,
  p_at timestamp with time zone
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  base jsonb;
  aggregate_id uuid;
  fact_values jsonb := '[]'::jsonb;
  custom_field record;
  custom_values jsonb;
  result jsonb;
BEGIN
  -- v1 remains the single resource-scope authorization oracle.
  base := app.read_sla_runtime_state_v1(
    p_tenant_id, p_object_type, p_object_id, p_capability, p_at
  );
  fact_values := fact_values
    || jsonb_build_array(jsonb_build_object(
      'kind', 'severity', 'key', NULL,
      'values', jsonb_build_array(base -> 'facts' ->> 'severity')
    ))
    || jsonb_build_array(jsonb_build_object(
      'kind', 'priority', 'key', NULL,
      'values', jsonb_build_array(base -> 'facts' ->> 'priority')
    ))
    || jsonb_build_array(jsonb_build_object(
      'kind', 'category', 'key', NULL,
      'values', jsonb_build_array(base -> 'facts' ->> 'category')
    ))
    || jsonb_build_array(jsonb_build_object(
      'kind', 'source', 'key', NULL,
      'values', jsonb_build_array(base -> 'facts' ->> 'source')
    ));
  IF jsonb_array_length(coalesce(base -> 'facts' -> 'tags', '[]'::jsonb)) > 0 THEN
    fact_values := fact_values || jsonb_build_array(jsonb_build_object(
      'kind', 'tag', 'key', NULL, 'values', base -> 'facts' -> 'tags'
    ));
  END IF;
  IF base -> 'facts' ->> 'assigned_team_id' IS NOT NULL THEN
    fact_values := fact_values || jsonb_build_array(jsonb_build_object(
      'kind', 'operator_team', 'key', NULL,
      'values', jsonb_build_array(base -> 'facts' ->> 'assigned_team_id')
    ));
  END IF;
  FOR custom_field IN
    SELECT field.key, field.value
    FROM jsonb_each(
      coalesce(base -> 'facts' -> 'customer_custom_fields', '{}'::jsonb)
        || coalesce(base -> 'facts' -> 'custom_fields', '{}'::jsonb)
    ) AS field(key, value)
    ORDER BY field.key
  LOOP
    IF jsonb_typeof(custom_field.value) = 'array' THEN
      SELECT coalesce(jsonb_agg(element #>> '{}' ORDER BY ordinal), '[]'::jsonb)
      INTO custom_values
      FROM jsonb_array_elements(custom_field.value)
        WITH ORDINALITY AS item(element, ordinal);
    ELSE
      custom_values := jsonb_build_array(custom_field.value #>> '{}');
    END IF;
    IF jsonb_array_length(custom_values) > 0 THEN
      fact_values := fact_values || jsonb_build_array(jsonb_build_object(
        'kind', 'custom_field', 'key', custom_field.key,
        'values', custom_values
      ));
    END IF;
  END LOOP;

  aggregate_id := (base -> 'aggregate' ->> 'id')::uuid;
  result := jsonb_build_object(
    'facts', jsonb_build_object(
      'tenant_id', p_tenant_id, 'object_type', p_object_type,
      'object_id', p_object_id, 'evaluated_at', p_at,
      'timezone', 'UTC', 'facts', fact_values
    ),
    'permission_epoch', (base ->> 'permission_epoch')::bigint,
    'subject_epoch', (base ->> 'subject_epoch')::bigint,
    'aggregate', CASE WHEN aggregate_id IS NULL THEN NULL ELSE (
      SELECT jsonb_build_object(
        'id', aggregate_row.id, 'tenant_id', aggregate_row.tenant_id,
        'object_type', aggregate_row.object_type,
        'object_id', aggregate_row.object_id,
        'policy_id', aggregate_row.policy_id,
        'policy_version', aggregate_row.policy_version,
        'aggregate_version', aggregate_row.aggregate_version,
        'created_at', aggregate_row.created_at,
        'updated_at', aggregate_row.updated_at,
        'completed_at', aggregate_row.completed_at
      ) FROM public.sla_instances AS aggregate_row
      WHERE aggregate_row.tenant_id = p_tenant_id
        AND aggregate_row.id = aggregate_id
    ) END,
    'metrics', CASE WHEN aggregate_id IS NULL THEN '[]'::jsonb ELSE coalesce((
      SELECT jsonb_agg(
        app.private_sla_runtime_metric_document_v2(metric.tenant_id, metric.id)
        ORDER BY definition.position, metric.id
      )
      FROM public.sla_metric_instances AS metric
      JOIN public.sla_metric_definitions AS definition
        ON definition.tenant_id = metric.tenant_id
       AND definition.id = metric.definition_id
       AND definition.policy_id = metric.policy_id
       AND definition.policy_version = metric.policy_version
      WHERE metric.tenant_id = p_tenant_id
        AND metric.sla_instance_id = aggregate_id
    ), '[]'::jsonb) END,
    'active_policies', coalesce((
      SELECT jsonb_agg(
        app.private_sla_configuration_document_v2(
          shell.tenant_id, 'policy', shell.id, shell.active_version
        ) ORDER BY version.priority DESC, shell.key, shell.id
      )
      FROM public.sla_policies AS shell
      JOIN public.sla_policy_versions AS version
        ON version.tenant_id = shell.tenant_id
       AND version.policy_id = shell.id
       AND version.version = shell.active_version
      WHERE shell.tenant_id = p_tenant_id AND shell.archived_at IS NULL
        AND version.enabled AND p_object_type = ANY(version.object_types)
        AND version.effective_from <= p_at
        AND (version.effective_until IS NULL OR p_at < version.effective_until)
    ), '[]'::jsonb),
    'active_calendars', coalesce((
      SELECT jsonb_agg(
        app.private_sla_configuration_document_v2(
          shell.tenant_id, 'calendar', shell.id, shell.active_version
        ) ORDER BY shell.key, shell.id
      )
      FROM public.sla_business_calendars AS shell
      WHERE shell.tenant_id = p_tenant_id AND shell.archived_at IS NULL
    ), '[]'::jsonb),
    'active_columns', coalesce((
      SELECT jsonb_agg(
        app.private_sla_configuration_document_v2(
          shell.tenant_id, 'column', shell.id, shell.active_version
        ) ORDER BY version.position, shell.key, shell.id
      )
      FROM public.sla_columns AS shell
      JOIN public.sla_column_versions AS version
        ON version.tenant_id = shell.tenant_id
       AND version.column_id = shell.id
       AND version.version = shell.active_version
      WHERE shell.tenant_id = p_tenant_id AND shell.archived_at IS NULL
    ), '[]'::jsonb),
    'replacement_calendar', NULL,
    'replacement_policy', NULL,
    'replacement_calendars', '[]'::jsonb,
    'replacement_columns', '[]'::jsonb,
    'simulation_digest', NULL,
    'occurred_at', p_at
  );
  IF pg_column_size(result) > 16777216 THEN
    RAISE EXCEPTION 'SLA runtime document is oversized'
      USING ERRCODE = '54000';
  END IF;
  RETURN result;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.read_sla_runtime_state_v2(
  uuid, public.sla_object_type, uuid, text, timestamp with time zone
) OWNER TO periapsis_sla_api_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.read_sla_runtime_state_v2(
  uuid, public.sla_object_type, uuid, text, timestamp with time zone
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor,
  periapsis_audit_reader_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.read_sla_runtime_state_v2(
  uuid, public.sla_object_type, uuid, text, timestamp with time zone
) TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.begin_sla_override_v2(
  p_tenant_id uuid,
  p_override_id uuid,
  p_object_type public.sla_object_type,
  p_object_id uuid,
  p_sla_instance_id uuid,
  p_metric_instance_id uuid,
  p_kind public.sla_override_kind,
  p_expected_metric_version integer,
  p_expected_aggregate_version integer,
  p_replacement_calendar_id uuid,
  p_replacement_calendar_version integer,
  p_new_policy_id uuid,
  p_new_policy_version integer,
  p_simulation_digest bytea,
  p_key_digest bytea,
  p_request_digest bytea,
  p_actor_membership_id uuid,
  p_capability text
)
RETURNS TABLE(
  fresh boolean,
  override_id uuid,
  outcome public.sla_override_outcome,
  metric_instance_id uuid,
  current_version integer,
  aggregate_version integer,
  policy_id uuid,
  policy_version integer,
  permission_epoch bigint,
  subject_epoch bigint,
  occurred_at timestamp with time zone,
  state_document jsonb
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  required_capability text;
  existing public.sla_overrides%ROWTYPE;
  aggregate public.sla_instances%ROWTYPE;
  observed_at timestamp with time zone := transaction_timestamp();
  state jsonb;
  replacement_calendar jsonb;
  replacement_policy jsonb;
  replacement_calendars jsonb := '[]'::jsonb;
  replacement_columns jsonb := '[]'::jsonb;
BEGIN
  required_capability := CASE p_object_type
    WHEN 'alert' THEN 'alert.sla.override'
    WHEN 'case' THEN 'case.sla.override'
    ELSE NULL
  END;
  IF p_tenant_id IS NULL OR required_capability IS NULL
     OR p_capability IS DISTINCT FROM required_capability
     OR p_override_id IS NULL OR p_object_id IS NULL
     OR p_sla_instance_id IS NULL OR p_kind IS NULL
     OR p_expected_aggregate_version NOT BETWEEN 1 AND 2147483645
     OR p_key_digest IS NULL OR octet_length(p_key_digest) <> 32
     OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32
     OR p_actor_membership_id IS DISTINCT FROM app.current_tenant_membership_id()
     OR NOT app.private_sla_context_allows_v1(
       required_capability, p_tenant_id, p_object_type, p_object_id
     )
     OR NOT coalesce((
       p_kind = 'change_policy'
         AND p_metric_instance_id IS NULL
         AND p_expected_metric_version = 0
         AND p_replacement_calendar_id IS NULL
         AND p_replacement_calendar_version = 0
         AND p_new_policy_id IS NOT NULL
         AND p_new_policy_version BETWEEN 1 AND 2147483646
         AND p_simulation_digest IS NOT NULL
         AND octet_length(p_simulation_digest) = 32
       OR p_kind = 'change_calendar'
         AND p_metric_instance_id IS NOT NULL
         AND p_expected_metric_version BETWEEN 1 AND 2147483645
         AND p_replacement_calendar_id IS NOT NULL
         AND p_replacement_calendar_version BETWEEN 1 AND 2147483646
         AND p_new_policy_id IS NULL
         AND p_new_policy_version = 0
         AND p_simulation_digest IS NOT NULL
         AND octet_length(p_simulation_digest) = 32
       OR p_kind = 'recalculate'
         AND p_metric_instance_id IS NOT NULL
         AND p_expected_metric_version BETWEEN 1 AND 2147483645
         AND p_replacement_calendar_id IS NULL
         AND p_replacement_calendar_version = 0
         AND p_new_policy_id IS NULL
         AND p_new_policy_version = 0
         AND p_simulation_digest IS NOT NULL
         AND octet_length(p_simulation_digest) = 32
       OR p_kind IN ('extend', 'suspend', 'resume', 'complete')
         AND p_metric_instance_id IS NOT NULL
         AND p_expected_metric_version BETWEEN 1 AND 2147483645
         AND p_replacement_calendar_id IS NULL
         AND p_replacement_calendar_version = 0
         AND p_new_policy_id IS NULL
         AND p_new_policy_version = 0
         AND p_simulation_digest IS NULL
     ), false) THEN
    RAISE EXCEPTION 'SLA override begin is forbidden or invalid'
      USING ERRCODE = '42501';
  END IF;

  -- A live resource-scope authorization check always precedes replay. The
  -- payload-bound receipt is then read before any mutable planner projection.
  PERFORM pg_advisory_xact_lock(
    hashtextextended(encode(p_key_digest, 'hex'), 0)
  );
  SELECT override_row.* INTO existing
  FROM public.sla_overrides AS override_row
  WHERE override_row.tenant_id = p_tenant_id
    AND (
      override_row.id = p_override_id
      OR override_row.actor_membership_id = p_actor_membership_id
        AND override_row.key_digest = p_key_digest
    )
  ORDER BY (override_row.id = p_override_id) DESC
  LIMIT 1;
  IF FOUND THEN
    IF existing.id IS DISTINCT FROM p_override_id
       OR existing.actor_membership_id IS DISTINCT FROM p_actor_membership_id
       OR existing.object_type IS DISTINCT FROM p_object_type
       OR existing.object_id IS DISTINCT FROM p_object_id
       OR existing.sla_instance_id IS DISTINCT FROM p_sla_instance_id
       OR existing.metric_instance_id IS DISTINCT FROM p_metric_instance_id
       OR existing.kind IS DISTINCT FROM p_kind
       OR existing.key_digest IS DISTINCT FROM p_key_digest
       OR existing.request_digest IS DISTINCT FROM p_request_digest THEN
      RAISE EXCEPTION 'SLA override replay conflict'
        USING ERRCODE = '23505';
    END IF;
    RETURN QUERY SELECT false, existing.id, existing.outcome,
      existing.metric_instance_id, existing.current_version,
      existing.aggregate_version, existing.policy_id,
      existing.policy_version, existing.permission_epoch,
      existing.subject_epoch, existing.occurred_at, NULL::jsonb;
    RETURN;
  END IF;

  SELECT instance.* INTO aggregate
  FROM public.sla_instances AS instance
  WHERE instance.tenant_id = p_tenant_id
    AND instance.id = p_sla_instance_id
  FOR UPDATE;
  IF NOT FOUND OR aggregate.object_type IS DISTINCT FROM p_object_type
     OR aggregate.object_id IS DISTINCT FROM p_object_id
     OR aggregate.aggregate_version IS DISTINCT FROM p_expected_aggregate_version
     OR aggregate.completed_at IS NOT NULL THEN
    RAISE EXCEPTION 'SLA override aggregate precondition failed'
      USING ERRCODE = '40001';
  END IF;
  IF p_kind <> 'change_policy' AND NOT EXISTS (
    SELECT 1
    FROM public.sla_metric_instances AS metric
    WHERE metric.tenant_id = p_tenant_id
      AND metric.sla_instance_id = p_sla_instance_id
      AND metric.id = p_metric_instance_id
      AND metric.version = p_expected_metric_version
    FOR UPDATE
  ) THEN
    RAISE EXCEPTION 'SLA override metric precondition failed'
      USING ERRCODE = '40001';
  END IF;

  state := app.read_sla_runtime_state_v2(
    p_tenant_id, p_object_type, p_object_id, required_capability, observed_at
  );
  IF p_kind = 'change_calendar' THEN
    replacement_calendar := app.private_sla_configuration_document_v2(
      p_tenant_id, 'calendar', p_replacement_calendar_id,
      p_replacement_calendar_version
    );
  ELSIF p_kind = 'change_policy' THEN
    replacement_policy := app.private_sla_configuration_document_v2(
      p_tenant_id, 'policy', p_new_policy_id, p_new_policy_version
    );
    SELECT coalesce(jsonb_agg(
      app.private_sla_configuration_document_v2(
        calendar_ref.tenant_id, 'calendar', calendar_ref.calendar_id,
        calendar_ref.calendar_version
      ) ORDER BY calendar_ref.calendar_id, calendar_ref.calendar_version
    ), '[]'::jsonb)
    INTO replacement_calendars
    FROM (
      SELECT DISTINCT metric.tenant_id, metric.calendar_id,
        metric.calendar_version
      FROM public.sla_metric_definitions AS metric
      WHERE metric.tenant_id = p_tenant_id
        AND metric.policy_id = p_new_policy_id
        AND metric.policy_version = p_new_policy_version
        AND metric.calendar_id IS NOT NULL
    ) AS calendar_ref;
    SELECT coalesce(jsonb_agg(
      app.private_sla_configuration_document_v2(
        column_ref.tenant_id, 'column', column_ref.column_id,
        column_ref.column_version
      ) ORDER BY column_ref.position, column_ref.column_id
    ), '[]'::jsonb)
    INTO replacement_columns
    FROM (
      SELECT shell.tenant_id, shell.id AS column_id,
        shell.active_version AS column_version, version.position
      FROM public.sla_columns AS shell
      JOIN public.sla_column_versions AS version
        ON version.tenant_id = shell.tenant_id
       AND version.column_id = shell.id
       AND version.version = shell.active_version
      JOIN public.sla_metric_definitions AS metric
        ON metric.tenant_id = version.tenant_id
       AND metric.id = version.metric_definition_id
      WHERE shell.tenant_id = p_tenant_id
        AND shell.archived_at IS NULL
        AND metric.policy_id = p_new_policy_id
        AND metric.policy_version = p_new_policy_version
    ) AS column_ref;
  END IF;
  state := state || jsonb_build_object(
    'replacement_calendar', replacement_calendar,
    'replacement_policy', replacement_policy,
    'replacement_calendars', replacement_calendars,
    'replacement_columns', replacement_columns,
    'simulation_digest', CASE WHEN p_simulation_digest IS NULL THEN NULL
      ELSE encode(p_simulation_digest, 'hex') END,
    'occurred_at', observed_at
  );
  IF pg_column_size(state) > 16777216 THEN
    RAISE EXCEPTION 'SLA override state is oversized' USING ERRCODE = '54000';
  END IF;
  RETURN QUERY SELECT true, p_override_id,
    NULL::public.sla_override_outcome, NULL::uuid, NULL::integer,
    NULL::integer, NULL::uuid, NULL::integer, NULL::bigint,
    NULL::bigint, NULL::timestamp with time zone, state;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.begin_sla_override_v2(
  uuid, uuid, public.sla_object_type, uuid, uuid, uuid,
  public.sla_override_kind, integer, integer, uuid, integer,
  uuid, integer, bytea, bytea, bytea, uuid, text
) OWNER TO periapsis_sla_api_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.begin_sla_override_v2(
  uuid, uuid, public.sla_object_type, uuid, uuid, uuid,
  public.sla_override_kind, integer, integer, uuid, integer,
  uuid, integer, bytea, bytea, bytea, uuid, text
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor,
  periapsis_audit_reader_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.begin_sla_override_v2(
  uuid, uuid, public.sla_object_type, uuid, uuid, uuid,
  public.sla_override_kind, integer, integer, uuid, integer,
  uuid, integer, bytea, bytea, bytea, uuid, text
) TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.begin_sla_object_event_v2(
  p_tenant_id uuid, p_event_id uuid,
  p_object_type public.sla_object_type, p_object_id uuid,
  p_origin text, p_origin_id uuid, p_occurred_at timestamp with time zone,
  p_key_digest bytea, p_request_digest bytea, p_actor_membership_id uuid
)
RETURNS TABLE(
  fresh boolean, event_id uuid, outcome public.sla_event_outcome,
  sla_instance_id uuid, aggregate_version integer,
  policy_id uuid, policy_version integer, state_document jsonb
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  read_capability text;
  existing public.sla_object_event_ledger%ROWTYPE;
BEGIN
  read_capability := CASE p_object_type
    WHEN 'alert' THEN 'alert.read' WHEN 'case' THEN 'case.read' ELSE NULL END;
  IF p_tenant_id IS NULL OR read_capability IS NULL
     OR p_event_id IS NULL OR p_object_id IS NULL
     OR p_origin IS NULL OR p_origin_id IS NULL OR p_occurred_at IS NULL
     OR p_origin !~ '^[a-z][a-z0-9_.-]{0,127}$'
     OR p_key_digest IS NULL OR octet_length(p_key_digest) <> 32
     OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32
     OR p_actor_membership_id IS DISTINCT FROM app.current_tenant_membership_id()
     OR NOT app.private_sla_context_allows_v1(
       read_capability, p_tenant_id, p_object_type, p_object_id
     ) THEN
    RAISE EXCEPTION 'SLA event begin is forbidden or invalid'
      USING ERRCODE = '42501';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(encode(p_key_digest, 'hex'), 0));
  SELECT ledger.* INTO existing
  FROM public.sla_object_event_ledger AS ledger
  WHERE ledger.tenant_id = p_tenant_id
    AND (ledger.event_id = p_event_id OR ledger.key_digest = p_key_digest)
  ORDER BY (ledger.event_id = p_event_id) DESC LIMIT 1;
  IF FOUND THEN
    IF existing.event_id IS DISTINCT FROM p_event_id
       OR existing.object_type IS DISTINCT FROM p_object_type
       OR existing.object_id IS DISTINCT FROM p_object_id
       OR existing.origin IS DISTINCT FROM p_origin
       OR existing.origin_id IS DISTINCT FROM p_origin_id
       OR existing.occurred_at IS DISTINCT FROM p_occurred_at
       OR existing.key_digest IS DISTINCT FROM p_key_digest
       OR existing.request_digest IS DISTINCT FROM p_request_digest THEN
      RAISE EXCEPTION 'SLA event replay conflict' USING ERRCODE = '23505';
    END IF;
    RETURN QUERY SELECT false, existing.event_id, existing.outcome,
      existing.sla_instance_id, existing.aggregate_version,
      existing.policy_id, existing.policy_version, NULL::jsonb;
    RETURN;
  END IF;
  RETURN QUERY SELECT true, p_event_id, NULL::public.sla_event_outcome,
    NULL::uuid, NULL::integer, NULL::uuid, NULL::integer,
    app.read_sla_runtime_state_v2(
      p_tenant_id, p_object_type, p_object_id, read_capability, p_occurred_at
    );
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.begin_sla_object_event_v2(
  uuid, uuid, public.sla_object_type, uuid, text, uuid,
  timestamp with time zone, bytea, bytea, uuid
) OWNER TO periapsis_sla_api_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.begin_sla_object_event_v2(
  uuid, uuid, public.sla_object_type, uuid, text, uuid,
  timestamp with time zone, bytea, bytea, uuid
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor,
  periapsis_audit_reader_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.begin_sla_object_event_v2(
  uuid, uuid, public.sla_object_type, uuid, text, uuid,
  timestamp with time zone, bytea, bytea, uuid
) TO periapsis_api;
--> statement-breakpoint

-- The worker projection is deliberately separate from the API projection:
-- it contains only immutable definitions selected by the versions already
-- pinned on the aggregate/runtime rows and never consults active revisions.
GRANT SELECT ON TABLE public.sla_business_calendars
TO periapsis_sla_worker_owner;
--> statement-breakpoint
CREATE POLICY sla_business_calendars_sla_worker_owner_read_v2
ON public.sla_business_calendars AS PERMISSIVE FOR SELECT
TO periapsis_sla_worker_owner USING (true);
--> statement-breakpoint

CREATE FUNCTION app.private_sla_worker_metric_document_v2(
  p_tenant_id uuid,
  p_metric_instance_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE document jsonb;
BEGIN
  SELECT to_jsonb(metric) - 'state' - 'last_override_digest'
      || jsonb_build_object(
        'last_override_digest', CASE
          WHEN metric.last_override_digest IS NULL THEN NULL
          ELSE encode(metric.last_override_digest, 'hex')
        END,
        'definition', to_jsonb(definition) - 'tenant_id' - 'policy_id'
          - 'policy_version' - 'created_at' - 'definition_digest'
          || jsonb_build_object(
            'definition_digest', encode(definition.definition_digest, 'hex')
          ),
        'calendar', CASE WHEN definition.calendar_id IS NULL THEN NULL ELSE (
          SELECT jsonb_build_object(
            'id', calendar_shell.id,
            'tenant_id', calendar_shell.tenant_id,
            'key', calendar_shell.key,
            'label', calendar_version.label,
            'timezone', calendar_version.timezone,
            'version', calendar_version.version,
            'weekly_schedule', calendar_version.weekly_schedule,
            'exceptions', calendar_version.exceptions,
            'revision_digest', encode(calendar_version.revision_digest, 'hex')
          )
          FROM public.sla_business_calendars AS calendar_shell
          JOIN public.sla_business_calendar_versions AS calendar_version
            ON calendar_version.tenant_id = calendar_shell.tenant_id
           AND calendar_version.calendar_id = calendar_shell.id
           AND calendar_version.version = definition.calendar_version
          WHERE calendar_shell.tenant_id = definition.tenant_id
            AND calendar_shell.id = definition.calendar_id
        ) END,
        'triggers', coalesce((
          SELECT jsonb_agg(
            to_jsonb(trigger_row) - 'tenant_id' - 'policy_id'
              - 'policy_version' - 'created_at' - 'definition_digest'
              || jsonb_build_object(
                'definition_digest', encode(trigger_row.definition_digest, 'hex')
              )
            ORDER BY trigger_row.position, trigger_row.id
          )
          FROM public.sla_trigger_definitions AS trigger_row
          WHERE trigger_row.tenant_id = metric.tenant_id
            AND trigger_row.policy_id = metric.policy_id
            AND trigger_row.policy_version = metric.policy_version
            AND trigger_row.metric_definition_id = metric.definition_id
        ), '[]'::jsonb),
        'cursors', coalesce((
          SELECT jsonb_agg(
            to_jsonb(cursor_row) - 'tenant_id' - 'metric_instance_id'
              - 'updated_at'
            ORDER BY cursor_row.trigger_definition_id
          )
          FROM public.sla_trigger_cursors AS cursor_row
          WHERE cursor_row.tenant_id = metric.tenant_id
            AND cursor_row.metric_instance_id = metric.id
        ), '[]'::jsonb),
        'columns', coalesce((
          SELECT jsonb_agg(jsonb_build_object(
            'id', column_shell.id,
            'tenant_id', column_shell.tenant_id,
            'key', column_shell.key,
            'label', column_version.label,
            'metric_definition_id', column_version.metric_definition_id,
            'calculation', column_version.calculation,
            'format', column_version.format,
            'sortable', column_version.sortable,
            'filterable', column_version.filterable,
            'customer_visible', column_version.customer_visible,
            'visible_role_keys', column_version.visible_role_keys,
            'position', column_version.position,
            'style_rules', column_version.style_rules,
            'version', column_version.version,
            'revision_digest', encode(column_version.revision_digest, 'hex')
          ) ORDER BY column_version.position, column_shell.id)
          FROM public.sla_materialized_column_values AS materialized
          JOIN public.sla_columns AS column_shell
            ON column_shell.tenant_id = materialized.tenant_id
           AND column_shell.id = materialized.column_id
          JOIN public.sla_column_versions AS column_version
            ON column_version.tenant_id = materialized.tenant_id
           AND column_version.column_id = materialized.column_id
           AND column_version.version = materialized.column_version
          WHERE materialized.tenant_id = metric.tenant_id
            AND materialized.metric_instance_id = metric.id
            AND column_version.metric_definition_id = metric.definition_id
        ), '[]'::jsonb)
      )
  INTO document
  FROM public.sla_metric_instances AS metric
  JOIN public.sla_metric_definitions AS definition
    ON definition.tenant_id = metric.tenant_id
   AND definition.id = metric.definition_id
   AND definition.policy_id = metric.policy_id
   AND definition.policy_version = metric.policy_version
  WHERE metric.tenant_id = p_tenant_id
    AND metric.id = p_metric_instance_id;
  IF document IS NULL
     OR document -> 'definition' IS NULL
     OR document -> 'calendar' = 'null'::jsonb
       AND (document -> 'definition' ->> 'clock') = 'business'
     OR pg_column_size(document) > 8388608 THEN
    RAISE EXCEPTION 'SLA worker metric projection is unavailable'
      USING ERRCODE = 'P0002';
  END IF;
  RETURN document;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_sla_worker_metric_document_v2(uuid, uuid)
  OWNER TO periapsis_sla_worker_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_sla_worker_metric_document_v2(uuid, uuid)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_sla_api_owner, periapsis_sla_readiness_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_sla_worker_job_document_v2(
  p_tenant_id uuid,
  p_sla_instance_id uuid,
  p_expected_aggregate_version integer
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE document jsonb;
BEGIN
  SELECT jsonb_build_object(
    'aggregate', jsonb_build_object(
      'id', aggregate_row.id,
      'tenant_id', aggregate_row.tenant_id,
      'object_type', aggregate_row.object_type,
      'object_id', aggregate_row.object_id,
      'policy_id', aggregate_row.policy_id,
      'policy_version', aggregate_row.policy_version,
      'aggregate_version', aggregate_row.aggregate_version,
      'created_at', aggregate_row.created_at,
      'updated_at', aggregate_row.updated_at,
      'completed_at', aggregate_row.completed_at
    ),
    'metrics', coalesce((
      SELECT jsonb_agg(
        app.private_sla_worker_metric_document_v2(metric.tenant_id, metric.id)
        ORDER BY definition.position, metric.id
      )
      FROM public.sla_metric_instances AS metric
      JOIN public.sla_metric_definitions AS definition
        ON definition.tenant_id = metric.tenant_id
       AND definition.id = metric.definition_id
       AND definition.policy_id = metric.policy_id
       AND definition.policy_version = metric.policy_version
      WHERE metric.tenant_id = aggregate_row.tenant_id
        AND metric.sla_instance_id = aggregate_row.id
    ), '[]'::jsonb)
  )
  INTO document
  FROM public.sla_instances AS aggregate_row
  WHERE aggregate_row.tenant_id = p_tenant_id
    AND aggregate_row.id = p_sla_instance_id
    AND aggregate_row.aggregate_version = p_expected_aggregate_version
    AND aggregate_row.completed_at IS NULL;
  IF document IS NULL
     OR jsonb_array_length(document -> 'metrics') NOT BETWEEN 1 AND 32
     OR pg_column_size(document) > 16777216 THEN
    RAISE EXCEPTION 'SLA worker job projection is unavailable or stale'
      USING ERRCODE = '40001';
  END IF;
  RETURN document;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_sla_worker_job_document_v2(uuid, uuid, integer)
  OWNER TO periapsis_sla_worker_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_sla_worker_job_document_v2(
  uuid, uuid, integer
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_sla_api_owner, periapsis_sla_readiness_owner;
--> statement-breakpoint

CREATE FUNCTION app.claim_sla_evaluation_jobs_v2(
  p_worker_id uuid,
  p_observed_at timestamp with time zone,
  p_batch_size integer,
  p_lease_micros bigint
)
RETURNS TABLE(
  job_id uuid,
  tenant_id uuid,
  sla_instance_id uuid,
  expected_aggregate_version integer,
  fence bigint,
  attempt integer,
  observed_at timestamp with time zone,
  lease_expires_at timestamp with time zone,
  state_document jsonb
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE claimed record;
BEGIN
  FOR claimed IN
    SELECT source.*
    FROM app.claim_sla_evaluation_jobs_v1(
      p_worker_id, p_observed_at, p_batch_size, p_lease_micros
    ) AS source
  LOOP
    job_id := claimed.job_id;
    tenant_id := claimed.tenant_id;
    sla_instance_id := claimed.sla_instance_id;
    expected_aggregate_version := claimed.expected_aggregate_version;
    fence := claimed.fence;
    attempt := claimed.attempt;
    observed_at := claimed.observed_at;
    lease_expires_at := claimed.lease_expires_at;
    state_document := app.private_sla_worker_job_document_v2(
      claimed.tenant_id, claimed.sla_instance_id,
      claimed.expected_aggregate_version
    );
    RETURN NEXT;
  END LOOP;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.claim_sla_evaluation_jobs_v2(
  uuid, timestamp with time zone, integer, bigint
) OWNER TO periapsis_sla_worker_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.claim_sla_evaluation_jobs_v2(
  uuid, timestamp with time zone, integer, bigint
) FROM PUBLIC, periapsis_api, periapsis_notifier, periapsis_auditor,
  periapsis_audit_reader_owner, periapsis_sla_api_owner,
  periapsis_sla_readiness_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.claim_sla_evaluation_jobs_v2(
  uuid, timestamp with time zone, integer, bigint
) TO periapsis_worker;
--> statement-breakpoint
REVOKE EXECUTE ON FUNCTION app.claim_sla_evaluation_jobs_v1(
  uuid, timestamp with time zone, integer, bigint
) FROM periapsis_worker;
--> statement-breakpoint
REVOKE EXECUTE ON FUNCTION app.read_sla_runtime_state_v1(
  uuid, public.sla_object_type, uuid, text, timestamp with time zone
) FROM periapsis_api;
