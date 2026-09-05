-- Phase 5 SLA transaction ABI. Public runtime roles receive EXECUTE only;
-- every entry point rechecks live tenant context, binds idempotency to the
-- canonical request digest, and keeps audit/outbox effects in the mutation.

CREATE FUNCTION app.private_append_sla_mutation_effects_v1(
  p_action text,
  p_resource_type text,
  p_resource_id uuid,
  p_resource_version integer,
  p_before jsonb,
  p_after jsonb,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  tenant_id uuid := app.context_tenant_id();
  actor_user_id uuid := app.context_user_id();
BEGIN
  IF tenant_id IS NULL OR app.current_tenant_membership_id() IS NULL
     OR p_action IS NULL OR p_action !~ '^sla\.[a-z0-9_.-]{1,96}$'
     OR p_resource_type NOT IN (
       'sla_business_calendar', 'sla_policy', 'sla_column',
       'sla_object', 'sla_instance', 'sla_metric_instance'
     )
     OR p_resource_id IS NULL
     OR p_resource_version NOT BETWEEN 0 AND 2147483646
     OR (p_resource_version = 0 AND p_resource_type <> 'sla_object')
     OR p_request_id IS NULL OR p_correlation_id IS NULL
     OR coalesce(jsonb_typeof(p_before), 'object') <> 'object'
     OR coalesce(jsonb_typeof(p_after), 'object') <> 'object'
     OR pg_column_size(coalesce(p_before, '{}'::jsonb)) > 32768
     OR pg_column_size(coalesce(p_after, '{}'::jsonb)) > 32768 THEN
    RAISE EXCEPTION 'SLA mutation effects are invalid'
      USING ERRCODE = '22023';
  END IF;

  PERFORM app.append_tenant_authorization_audit(
    uuidv7(), p_action, p_resource_type, p_resource_id,
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method, p_before, p_after,
    jsonb_build_object(
      'phase', 5,
      'resourceVersion', p_resource_version
    )
  );

  INSERT INTO public.outbox_events (
    id, tenant_id, aggregate_type, aggregate_id, aggregate_version,
    event_type, schema_version, payload, deduplication_key,
    correlation_id, causation_id, actor_kind, actor_id, producer,
    maximum_audience, traceparent, tracestate, occurred_at
  ) VALUES (
    uuidv7(), tenant_id, p_resource_type, p_resource_id,
    p_resource_version, p_action, 1,
    jsonb_build_object(
      'tenantId', tenant_id,
      'resourceId', p_resource_id,
      'resourceVersion', p_resource_version
    ),
    concat('sla:', p_request_id::text, ':', p_action, ':', p_resource_id::text),
    p_correlation_id, p_request_id, 'human', actor_user_id, 'sla-api',
    'operator', nullif(current_setting('app.traceparent', true), ''),
    nullif(current_setting('app.tracestate', true), ''),
    transaction_timestamp()
  );
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_append_sla_mutation_effects_v1(
  text, text, uuid, integer, jsonb, jsonb, uuid, uuid, inet, text, text
) OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_append_sla_mutation_effects_v1(
  text, text, uuid, integer, jsonb, jsonb, uuid, uuid, inet, text, text
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_sla_worker_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.private_append_sla_mutation_effects_v1(
  text, text, uuid, integer, jsonb, jsonb, uuid, uuid, inet, text, text
) TO periapsis_sla_api_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_lock_sla_authority_epochs_v1(
  p_tenant_id uuid,
  p_membership_id uuid
)
RETURNS TABLE(permission_epoch bigint, subject_epoch bigint)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_tenant_id IS NULL OR p_membership_id IS NULL
     OR p_tenant_id IS DISTINCT FROM app.context_tenant_id()
     OR p_membership_id IS DISTINCT FROM app.current_tenant_membership_id()
  THEN
    RAISE EXCEPTION 'SLA authority epoch context is invalid'
      USING ERRCODE = '42501';
  END IF;
  RETURN QUERY
  SELECT state.revision, profile.version::bigint
  FROM public.tenant_authorization_states AS state
  JOIN public.tenant_user_profiles AS profile
    ON profile.tenant_id = state.tenant_id
   AND profile.membership_id = p_membership_id
  WHERE state.tenant_id = p_tenant_id
  -- Freeze both mutable epoch values until the override transaction commits.
  -- FOR KEY SHARE would still permit non-key updates to revision/version and
  -- could therefore authorize a write against authority that drifted in-flight.
  FOR SHARE OF state, profile;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_lock_sla_authority_epochs_v1(uuid, uuid)
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_lock_sla_authority_epochs_v1(uuid, uuid)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_sla_worker_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.private_lock_sla_authority_epochs_v1(uuid, uuid)
TO periapsis_sla_api_owner;
--> statement-breakpoint

CREATE FUNCTION app.publish_sla_calendar_v1(
  p_tenant_id uuid,
  p_calendar_id uuid,
  p_expected_resource_version integer,
  p_document jsonb,
  p_key_digest bytea,
  p_request_digest bytea,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE(
  resource_id uuid,
  resource_version integer,
  active_version integer,
  replayed boolean
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor_membership uuid := app.current_tenant_membership_id();
  command_row public.sla_configuration_commands%ROWTYPE;
  shell public.sla_business_calendars%ROWTYPE;
  next_active_version integer;
  next_resource_version integer;
  key_value text;
BEGIN
  IF NOT app.private_sla_context_allows_v1(
       'sla.manage', p_tenant_id, NULL, NULL
     ) OR p_calendar_id IS NULL
     OR p_expected_resource_version NOT BETWEEN 0 AND 2147483646
     OR jsonb_typeof(p_document) <> 'object'
     OR pg_column_size(p_document) > 8388608
     OR octet_length(p_key_digest) <> 32
     OR octet_length(p_request_digest) <> 32
     OR p_request_id IS NULL OR p_correlation_id IS NULL THEN
    RAISE EXCEPTION 'SLA calendar publication is invalid'
      USING ERRCODE = '22023';
  END IF;
  key_value := p_document ->> 'key';
  IF key_value IS NULL
     OR p_document ->> 'revision_digest' !~ '^[0-9a-f]{64}$'
     OR jsonb_typeof(p_document -> 'weekly_schedule') <> 'array'
     OR jsonb_typeof(p_document -> 'exceptions') <> 'array' THEN
    RAISE EXCEPTION 'SLA calendar document is invalid'
      USING ERRCODE = '22023';
  END IF;

  PERFORM pg_advisory_xact_lock(
    hashtextextended(encode(p_key_digest, 'hex'), 0)
  );
  SELECT command.* INTO command_row
  FROM public.sla_configuration_commands AS command
  WHERE command.tenant_id = p_tenant_id
    AND command.actor_membership_id = actor_membership
    AND command.operation = 'sla.calendar.publish'
    AND command.key_digest = p_key_digest;
  IF FOUND THEN
    IF command_row.request_digest IS DISTINCT FROM p_request_digest
       OR command_row.resource_id IS DISTINCT FROM p_calendar_id THEN
      RAISE EXCEPTION 'SLA calendar idempotency conflict'
        USING ERRCODE = '23505';
    END IF;
    RETURN QUERY SELECT command_row.resource_id,
      command_row.resource_version, command_row.active_version, true;
    RETURN;
  END IF;

  IF p_expected_resource_version = 0 THEN
    next_active_version := 1;
    next_resource_version := 1;
    INSERT INTO public.sla_business_calendars (
      id, tenant_id, key, active_version, resource_version,
      created_by_membership_id, updated_by_membership_id
    ) VALUES (
      p_calendar_id, p_tenant_id, key_value, 1, 1,
      actor_membership, actor_membership
    );
  ELSE
    SELECT calendar.* INTO shell
    FROM public.sla_business_calendars AS calendar
    WHERE calendar.tenant_id = p_tenant_id
      AND calendar.id = p_calendar_id
    FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'SLA calendar not found' USING ERRCODE = 'P0002';
    END IF;
    IF shell.archived_at IS NOT NULL
       OR shell.resource_version <> p_expected_resource_version
       OR shell.key <> key_value
       OR shell.resource_version >= 2147483646
       OR shell.active_version >= 2147483646 THEN
      RAISE EXCEPTION 'SLA calendar precondition failed'
        USING ERRCODE = '40001';
    END IF;
    next_active_version := shell.active_version + 1;
    next_resource_version := shell.resource_version + 1;
    UPDATE public.sla_business_calendars
    SET active_version = next_active_version,
        resource_version = next_resource_version,
        updated_by_membership_id = actor_membership,
        updated_at = transaction_timestamp()
    WHERE tenant_id = p_tenant_id AND id = p_calendar_id;
  END IF;

  INSERT INTO public.sla_business_calendar_versions (
    tenant_id, calendar_id, version, label, timezone,
    weekly_schedule, exceptions, revision_digest,
    created_by_membership_id, created_at
  ) VALUES (
    p_tenant_id, p_calendar_id, next_active_version,
    p_document ->> 'label', p_document ->> 'timezone',
    p_document -> 'weekly_schedule', p_document -> 'exceptions',
    decode(p_document ->> 'revision_digest', 'hex'),
    actor_membership, transaction_timestamp()
  );
  INSERT INTO public.sla_configuration_commands (
    tenant_id, actor_membership_id, operation, key_digest,
    request_digest, resource_id, resource_version, active_version,
    archived
  ) VALUES (
    p_tenant_id, actor_membership, 'sla.calendar.publish',
    p_key_digest, p_request_digest, p_calendar_id,
    next_resource_version, next_active_version, false
  );
  PERFORM app.private_append_sla_mutation_effects_v1(
    'sla.calendar.published', 'sla_business_calendar', p_calendar_id,
    next_resource_version,
    CASE WHEN p_expected_resource_version = 0 THEN NULL
         ELSE jsonb_build_object('resourceVersion', p_expected_resource_version)
    END,
    jsonb_build_object(
      'resourceVersion', next_resource_version,
      'activeVersion', next_active_version
    ),
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method
  );
  RETURN QUERY SELECT p_calendar_id, next_resource_version,
    next_active_version, false;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.publish_sla_calendar_v1(
  uuid, uuid, integer, jsonb, bytea, bytea, uuid, uuid, inet, text, text
) OWNER TO periapsis_sla_api_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.publish_sla_calendar_v1(
  uuid, uuid, integer, jsonb, bytea, bytea, uuid, uuid, inet, text, text
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.publish_sla_calendar_v1(
  uuid, uuid, integer, jsonb, bytea, bytea, uuid, uuid, inet, text, text
) TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.publish_sla_policy_v1(
  p_tenant_id uuid,
  p_policy_id uuid,
  p_expected_resource_version integer,
  p_document jsonb,
  p_key_digest bytea,
  p_request_digest bytea,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE(
  resource_id uuid,
  resource_version integer,
  active_version integer,
  replayed boolean
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor_membership uuid := app.current_tenant_membership_id();
  command_row public.sla_configuration_commands%ROWTYPE;
  shell public.sla_policies%ROWTYPE;
  next_active_version integer;
  next_resource_version integer;
  key_value text;
  object_types public.sla_object_type[];
BEGIN
  IF NOT app.private_sla_context_allows_v1(
       'sla.manage', p_tenant_id, NULL, NULL
     ) OR p_policy_id IS NULL
     OR p_expected_resource_version NOT BETWEEN 0 AND 2147483646
     OR jsonb_typeof(p_document) <> 'object'
     OR pg_column_size(p_document) > 8388608
     OR octet_length(p_key_digest) <> 32
     OR octet_length(p_request_digest) <> 32
     OR p_request_id IS NULL OR p_correlation_id IS NULL
     OR jsonb_typeof(p_document -> 'object_types') <> 'array'
     OR jsonb_typeof(p_document -> 'match_rule') <> 'object'
     OR jsonb_typeof(p_document -> 'metrics') <> 'array'
     OR jsonb_typeof(p_document -> 'triggers') <> 'array'
     OR p_document ->> 'revision_digest' !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'SLA policy publication is invalid'
      USING ERRCODE = '22023';
  END IF;
  key_value := p_document ->> 'key';
  SELECT array_agg(value::public.sla_object_type ORDER BY value)
  INTO object_types
  FROM jsonb_array_elements_text(p_document -> 'object_types') AS item(value);
  IF key_value IS NULL OR cardinality(object_types) NOT BETWEEN 1 AND 3
     OR cardinality(object_types) <> (
       SELECT count(DISTINCT value)
       FROM unnest(object_types) AS object_type(value)
     )
     OR jsonb_array_length(p_document -> 'metrics') NOT BETWEEN 1 AND 32
     OR jsonb_array_length(p_document -> 'triggers') > 256 THEN
    RAISE EXCEPTION 'SLA policy document is invalid'
      USING ERRCODE = '22023';
  END IF;

  PERFORM pg_advisory_xact_lock(
    hashtextextended(encode(p_key_digest, 'hex'), 0)
  );
  SELECT command.* INTO command_row
  FROM public.sla_configuration_commands AS command
  WHERE command.tenant_id = p_tenant_id
    AND command.actor_membership_id = actor_membership
    AND command.operation = 'sla.policy.publish'
    AND command.key_digest = p_key_digest;
  IF FOUND THEN
    IF command_row.request_digest IS DISTINCT FROM p_request_digest
       OR command_row.resource_id IS DISTINCT FROM p_policy_id THEN
      RAISE EXCEPTION 'SLA policy idempotency conflict'
        USING ERRCODE = '23505';
    END IF;
    RETURN QUERY SELECT command_row.resource_id,
      command_row.resource_version, command_row.active_version, true;
    RETURN;
  END IF;

  IF p_expected_resource_version = 0 THEN
    next_active_version := 1;
    next_resource_version := 1;
    INSERT INTO public.sla_policies (
      id, tenant_id, key, active_version, resource_version,
      created_by_membership_id, updated_by_membership_id
    ) VALUES (
      p_policy_id, p_tenant_id, key_value, 1, 1,
      actor_membership, actor_membership
    );
  ELSE
    SELECT policy.* INTO shell
    FROM public.sla_policies AS policy
    WHERE policy.tenant_id = p_tenant_id AND policy.id = p_policy_id
    FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'SLA policy not found' USING ERRCODE = 'P0002';
    END IF;
    IF shell.archived_at IS NOT NULL
       OR shell.resource_version <> p_expected_resource_version
       OR shell.key <> key_value
       OR shell.resource_version >= 2147483646
       OR shell.active_version >= 2147483646 THEN
      RAISE EXCEPTION 'SLA policy precondition failed'
        USING ERRCODE = '40001';
    END IF;
    next_active_version := shell.active_version + 1;
    next_resource_version := shell.resource_version + 1;
    UPDATE public.sla_policies
    SET active_version = next_active_version,
        resource_version = next_resource_version,
        updated_by_membership_id = actor_membership,
        updated_at = transaction_timestamp()
    WHERE tenant_id = p_tenant_id AND id = p_policy_id;
  END IF;

  INSERT INTO public.sla_policy_versions (
    tenant_id, policy_id, version, name, description, priority,
    object_types, match_rule, effective_from, effective_until,
    enabled, apply_to_sla_engine_source, revision_digest,
    created_by_membership_id, created_at
  ) VALUES (
    p_tenant_id, p_policy_id, next_active_version,
    p_document ->> 'name', coalesce(p_document ->> 'description', ''),
    (p_document ->> 'priority')::integer, object_types,
    p_document -> 'match_rule',
    (p_document ->> 'effective_from')::timestamp with time zone,
    (p_document ->> 'effective_until')::timestamp with time zone,
    (p_document ->> 'enabled')::boolean,
    coalesce((p_document ->> 'apply_to_sla_engine_source')::boolean, false),
    decode(p_document ->> 'revision_digest', 'hex'),
    actor_membership, transaction_timestamp()
  );

  INSERT INTO public.sla_metric_definitions (
    tenant_id, policy_id, policy_version, id, key, label, description,
    duration_micros, clock, calendar_id, calendar_version,
    start_event, pause_event, resume_event, completion_event,
    reset_event, reset_policy, warning_kind, warning_consumed_percent,
    warning_remaining_micros, breach_grace_micros, display_format,
    customer_visible, api_visible, position, definition_digest, created_at
  )
  SELECT p_tenant_id, p_policy_id, next_active_version,
    metric.id, metric.key, metric.label, coalesce(metric.description, ''),
    metric.duration_micros, metric.clock::public.sla_clock_type,
    metric.calendar_id, metric.calendar_version, metric.start_event,
    metric.pause_event, metric.resume_event, metric.completion_event,
    metric.reset_event, metric.reset_policy::public.sla_reset_policy,
    metric.warning_kind::public.sla_warning_kind,
    metric.warning_consumed_percent, metric.warning_remaining_micros,
    metric.breach_grace_micros, metric.display_format,
    metric.customer_visible, metric.api_visible, metric.position,
    decode(metric.definition_digest, 'hex'), transaction_timestamp()
  FROM jsonb_to_recordset(p_document -> 'metrics') AS metric(
    id uuid, key text, label text, description text,
    duration_micros bigint, clock text, calendar_id uuid,
    calendar_version integer, start_event text, pause_event text,
    resume_event text, completion_event text, reset_event text,
    reset_policy text, warning_kind text,
    warning_consumed_percent integer, warning_remaining_micros bigint,
    breach_grace_micros bigint, display_format text,
    customer_visible boolean, api_visible boolean, position integer,
    definition_digest text
  );

  INSERT INTO public.sla_trigger_definitions (
    tenant_id, policy_id, policy_version, id, metric_definition_id,
    key, kind, consumed_percent, remaining_micros, offset_micros,
    repeat_interval_micros, target_state, action_kind,
    action_configuration_id, action_value, allow_recursive_sla,
    position, definition_digest, created_at
  )
  SELECT p_tenant_id, p_policy_id, next_active_version,
    trigger_row.id, trigger_row.metric_definition_id, trigger_row.key,
    trigger_row.kind::public.sla_trigger_kind,
    trigger_row.consumed_percent, trigger_row.remaining_micros,
    trigger_row.offset_micros, trigger_row.repeat_interval_micros,
    trigger_row.target_state::public.sla_metric_state,
    trigger_row.action_kind::public.sla_trigger_action_kind,
    trigger_row.action_configuration_id, trigger_row.action_value,
    trigger_row.allow_recursive_sla, trigger_row.position,
    decode(trigger_row.definition_digest, 'hex'), transaction_timestamp()
  FROM jsonb_to_recordset(p_document -> 'triggers') AS trigger_row(
    id uuid, metric_definition_id uuid, key text, kind text,
    consumed_percent integer, remaining_micros bigint,
    offset_micros bigint, repeat_interval_micros bigint,
    target_state text, action_kind text, action_configuration_id uuid,
    action_value text, allow_recursive_sla boolean, position integer,
    definition_digest text
  );

  INSERT INTO public.sla_configuration_commands (
    tenant_id, actor_membership_id, operation, key_digest,
    request_digest, resource_id, resource_version, active_version,
    archived
  ) VALUES (
    p_tenant_id, actor_membership, 'sla.policy.publish',
    p_key_digest, p_request_digest, p_policy_id,
    next_resource_version, next_active_version, false
  );
  PERFORM app.private_append_sla_mutation_effects_v1(
    'sla.policy.published', 'sla_policy', p_policy_id,
    next_resource_version,
    CASE WHEN p_expected_resource_version = 0 THEN NULL
         ELSE jsonb_build_object('resourceVersion', p_expected_resource_version)
    END,
    jsonb_build_object(
      'resourceVersion', next_resource_version,
      'activeVersion', next_active_version
    ),
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method
  );
  RETURN QUERY SELECT p_policy_id, next_resource_version,
    next_active_version, false;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.publish_sla_policy_v1(
  uuid, uuid, integer, jsonb, bytea, bytea, uuid, uuid, inet, text, text
) OWNER TO periapsis_sla_api_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.publish_sla_policy_v1(
  uuid, uuid, integer, jsonb, bytea, bytea, uuid, uuid, inet, text, text
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.publish_sla_policy_v1(
  uuid, uuid, integer, jsonb, bytea, bytea, uuid, uuid, inet, text, text
) TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.publish_sla_column_v1(
  p_tenant_id uuid,
  p_column_id uuid,
  p_expected_resource_version integer,
  p_document jsonb,
  p_key_digest bytea,
  p_request_digest bytea,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE(
  resource_id uuid,
  resource_version integer,
  active_version integer,
  replayed boolean
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor_membership uuid := app.current_tenant_membership_id();
  command_row public.sla_configuration_commands%ROWTYPE;
  shell public.sla_columns%ROWTYPE;
  next_active_version integer;
  next_resource_version integer;
  key_value text;
  role_keys text[];
BEGIN
  IF NOT app.private_sla_context_allows_v1(
       'sla.manage', p_tenant_id, NULL, NULL
     ) OR p_column_id IS NULL
     OR p_expected_resource_version NOT BETWEEN 0 AND 2147483646
     OR jsonb_typeof(p_document) <> 'object'
     OR pg_column_size(p_document) > 262144
     OR octet_length(p_key_digest) <> 32
     OR octet_length(p_request_digest) <> 32
     OR p_request_id IS NULL OR p_correlation_id IS NULL
     OR jsonb_typeof(p_document -> 'visible_role_keys') <> 'array'
     OR jsonb_typeof(p_document -> 'style_rules') <> 'array'
     OR p_document ->> 'revision_digest' !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'SLA column publication is invalid'
      USING ERRCODE = '22023';
  END IF;
  key_value := p_document ->> 'key';
  SELECT coalesce(array_agg(value ORDER BY value), ARRAY[]::text[])
  INTO role_keys
  FROM jsonb_array_elements_text(p_document -> 'visible_role_keys')
       AS item(value);
  IF key_value IS NULL OR cardinality(role_keys) > 128
     OR cardinality(role_keys) <> (
       SELECT count(DISTINCT value)
       FROM unnest(role_keys) AS role_key(value)
     ) THEN
    RAISE EXCEPTION 'SLA column document is invalid'
      USING ERRCODE = '22023';
  END IF;

  PERFORM pg_advisory_xact_lock(
    hashtextextended(encode(p_key_digest, 'hex'), 0)
  );
  SELECT command.* INTO command_row
  FROM public.sla_configuration_commands AS command
  WHERE command.tenant_id = p_tenant_id
    AND command.actor_membership_id = actor_membership
    AND command.operation = 'sla.column.publish'
    AND command.key_digest = p_key_digest;
  IF FOUND THEN
    IF command_row.request_digest IS DISTINCT FROM p_request_digest
       OR command_row.resource_id IS DISTINCT FROM p_column_id THEN
      RAISE EXCEPTION 'SLA column idempotency conflict'
        USING ERRCODE = '23505';
    END IF;
    RETURN QUERY SELECT command_row.resource_id,
      command_row.resource_version, command_row.active_version, true;
    RETURN;
  END IF;

  IF p_expected_resource_version = 0 THEN
    next_active_version := 1;
    next_resource_version := 1;
    INSERT INTO public.sla_columns (
      id, tenant_id, key, active_version, resource_version,
      created_by_membership_id, updated_by_membership_id
    ) VALUES (
      p_column_id, p_tenant_id, key_value, 1, 1,
      actor_membership, actor_membership
    );
  ELSE
    SELECT column_row.* INTO shell
    FROM public.sla_columns AS column_row
    WHERE column_row.tenant_id = p_tenant_id
      AND column_row.id = p_column_id
    FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'SLA column not found' USING ERRCODE = 'P0002';
    END IF;
    IF shell.archived_at IS NOT NULL
       OR shell.resource_version <> p_expected_resource_version
       OR shell.key <> key_value
       OR shell.resource_version >= 2147483646
       OR shell.active_version >= 2147483646 THEN
      RAISE EXCEPTION 'SLA column precondition failed'
        USING ERRCODE = '40001';
    END IF;
    next_active_version := shell.active_version + 1;
    next_resource_version := shell.resource_version + 1;
    UPDATE public.sla_columns
    SET active_version = next_active_version,
        resource_version = next_resource_version,
        updated_by_membership_id = actor_membership,
        updated_at = transaction_timestamp()
    WHERE tenant_id = p_tenant_id AND id = p_column_id;
  END IF;

  INSERT INTO public.sla_column_versions (
    tenant_id, column_id, version, label, metric_definition_id,
    calculation, format, sortable, filterable, customer_visible,
    visible_role_keys, position, style_rules, revision_digest,
    created_by_membership_id, created_at
  ) VALUES (
    p_tenant_id, p_column_id, next_active_version,
    p_document ->> 'label',
    (p_document ->> 'metric_definition_id')::uuid,
    (p_document ->> 'calculation')::public.sla_column_calculation,
    (p_document ->> 'format')::public.sla_column_format,
    (p_document ->> 'sortable')::boolean,
    (p_document ->> 'filterable')::boolean,
    (p_document ->> 'customer_visible')::boolean,
    role_keys, (p_document ->> 'position')::integer,
    p_document -> 'style_rules',
    decode(p_document ->> 'revision_digest', 'hex'),
    actor_membership, transaction_timestamp()
  );
  INSERT INTO public.sla_configuration_commands (
    tenant_id, actor_membership_id, operation, key_digest,
    request_digest, resource_id, resource_version, active_version,
    archived
  ) VALUES (
    p_tenant_id, actor_membership, 'sla.column.publish',
    p_key_digest, p_request_digest, p_column_id,
    next_resource_version, next_active_version, false
  );
  PERFORM app.private_append_sla_mutation_effects_v1(
    'sla.column.published', 'sla_column', p_column_id,
    next_resource_version,
    CASE WHEN p_expected_resource_version = 0 THEN NULL
         ELSE jsonb_build_object('resourceVersion', p_expected_resource_version)
    END,
    jsonb_build_object(
      'resourceVersion', next_resource_version,
      'activeVersion', next_active_version
    ),
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method
  );
  RETURN QUERY SELECT p_column_id, next_resource_version,
    next_active_version, false;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.publish_sla_column_v1(
  uuid, uuid, integer, jsonb, bytea, bytea, uuid, uuid, inet, text, text
) OWNER TO periapsis_sla_api_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.publish_sla_column_v1(
  uuid, uuid, integer, jsonb, bytea, bytea, uuid, uuid, inet, text, text
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.publish_sla_column_v1(
  uuid, uuid, integer, jsonb, bytea, bytea, uuid, uuid, inet, text, text
) TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.archive_sla_configuration_v1(
  p_tenant_id uuid,
  p_kind text,
  p_resource_id uuid,
  p_expected_resource_version integer,
  p_reason text,
  p_key_digest bytea,
  p_request_digest bytea,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE(
  resource_version integer,
  replayed boolean
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor_membership uuid := app.current_tenant_membership_id();
  operation_name text;
  resource_type text;
  action_name text;
  command_row public.sla_configuration_commands%ROWTYPE;
  current_resource_version integer;
  archived_at timestamp with time zone;
  next_resource_version integer;
BEGIN
  IF NOT app.private_sla_context_allows_v1(
       'sla.manage', p_tenant_id, NULL, NULL
     ) OR p_kind NOT IN ('calendar', 'policy', 'column')
     OR p_resource_id IS NULL
     OR p_expected_resource_version NOT BETWEEN 1 AND 2147483646
     OR p_reason IS NULL OR octet_length(p_reason) NOT BETWEEN 3 AND 2000
     OR btrim(p_reason) <> p_reason OR p_reason ~ '[[:cntrl:]]'
     OR octet_length(p_key_digest) <> 32
     OR octet_length(p_request_digest) <> 32
     OR p_request_id IS NULL OR p_correlation_id IS NULL THEN
    RAISE EXCEPTION 'SLA configuration archive is invalid'
      USING ERRCODE = '22023';
  END IF;
  operation_name := 'sla.' || p_kind || '.archive';
  resource_type := CASE p_kind
    WHEN 'calendar' THEN 'sla_business_calendar'
    WHEN 'policy' THEN 'sla_policy'
    ELSE 'sla_column'
  END;
  action_name := 'sla.' || p_kind || '.archived';
  PERFORM pg_advisory_xact_lock(
    hashtextextended(encode(p_key_digest, 'hex'), 0)
  );
  SELECT command.* INTO command_row
  FROM public.sla_configuration_commands AS command
  WHERE command.tenant_id = p_tenant_id
    AND command.actor_membership_id = actor_membership
    AND command.operation = operation_name
    AND command.key_digest = p_key_digest;
  IF FOUND THEN
    IF command_row.request_digest IS DISTINCT FROM p_request_digest
       OR command_row.resource_id IS DISTINCT FROM p_resource_id THEN
      RAISE EXCEPTION 'SLA archive idempotency conflict'
        USING ERRCODE = '23505';
    END IF;
    RETURN QUERY SELECT command_row.resource_version, true;
    RETURN;
  END IF;

  IF p_kind = 'calendar' THEN
    SELECT calendar.resource_version, calendar.archived_at
    INTO current_resource_version, archived_at
    FROM public.sla_business_calendars AS calendar
    WHERE calendar.tenant_id = p_tenant_id AND calendar.id = p_resource_id
    FOR UPDATE;
  ELSIF p_kind = 'policy' THEN
    SELECT policy.resource_version, policy.archived_at
    INTO current_resource_version, archived_at
    FROM public.sla_policies AS policy
    WHERE policy.tenant_id = p_tenant_id AND policy.id = p_resource_id
    FOR UPDATE;
  ELSE
    SELECT column_row.resource_version, column_row.archived_at
    INTO current_resource_version, archived_at
    FROM public.sla_columns AS column_row
    WHERE column_row.tenant_id = p_tenant_id AND column_row.id = p_resource_id
    FOR UPDATE;
  END IF;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'SLA configuration not found' USING ERRCODE = 'P0002';
  END IF;
  IF archived_at IS NOT NULL
     OR current_resource_version <> p_expected_resource_version
     OR current_resource_version >= 2147483646 THEN
    RAISE EXCEPTION 'SLA archive precondition failed'
      USING ERRCODE = '40001';
  END IF;
  next_resource_version := current_resource_version + 1;
  IF p_kind = 'calendar' THEN
    UPDATE public.sla_business_calendars
    SET resource_version = next_resource_version,
        archived_by_membership_id = actor_membership,
        archived_at = transaction_timestamp(),
        updated_by_membership_id = actor_membership,
        updated_at = transaction_timestamp()
    WHERE tenant_id = p_tenant_id AND id = p_resource_id;
  ELSIF p_kind = 'policy' THEN
    UPDATE public.sla_policies
    SET resource_version = next_resource_version,
        archived_by_membership_id = actor_membership,
        archived_at = transaction_timestamp(),
        updated_by_membership_id = actor_membership,
        updated_at = transaction_timestamp()
    WHERE tenant_id = p_tenant_id AND id = p_resource_id;
  ELSE
    UPDATE public.sla_columns
    SET resource_version = next_resource_version,
        archived_by_membership_id = actor_membership,
        archived_at = transaction_timestamp(),
        updated_by_membership_id = actor_membership,
        updated_at = transaction_timestamp()
    WHERE tenant_id = p_tenant_id AND id = p_resource_id;
  END IF;
  INSERT INTO public.sla_configuration_commands (
    tenant_id, actor_membership_id, operation, key_digest,
    request_digest, resource_id, resource_version, active_version,
    archived
  ) VALUES (
    p_tenant_id, actor_membership, operation_name,
    p_key_digest, p_request_digest, p_resource_id,
    next_resource_version, NULL, true
  );
  PERFORM app.private_append_sla_mutation_effects_v1(
    action_name, resource_type, p_resource_id, next_resource_version,
    jsonb_build_object('resourceVersion', current_resource_version),
    jsonb_build_object('resourceVersion', next_resource_version, 'archived', true),
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method
  );
  RETURN QUERY SELECT next_resource_version, false;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.archive_sla_configuration_v1(
  uuid, text, uuid, integer, text, bytea, bytea, uuid, uuid,
  inet, text, text
) OWNER TO periapsis_sla_api_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.archive_sla_configuration_v1(
  uuid, text, uuid, integer, text, bytea, bytea, uuid, uuid,
  inet, text, text
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.archive_sla_configuration_v1(
  uuid, text, uuid, integer, text, bytea, bytea, uuid, uuid,
  inet, text, text
) TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.read_sla_configuration_v1(
  p_tenant_id uuid,
  p_kind text,
  p_resource_id uuid DEFAULT NULL,
  p_after_key text DEFAULT NULL,
  p_after_id uuid DEFAULT NULL,
  p_limit integer DEFAULT 50,
  p_include_archived boolean DEFAULT false
)
RETURNS TABLE(document jsonb)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF NOT app.private_sla_context_allows_v1(
       'sla.read', p_tenant_id, NULL, NULL
     ) OR p_kind NOT IN ('calendar', 'policy', 'column')
     OR p_limit NOT BETWEEN 1 AND 201
     OR (p_after_key IS NULL) <> (p_after_id IS NULL) THEN
    RAISE EXCEPTION 'SLA configuration read is invalid'
      USING ERRCODE = '22023';
  END IF;
  IF p_kind = 'calendar' THEN
    RETURN QUERY
    SELECT jsonb_build_object(
      'id', shell.id, 'key', shell.key,
      'resource_version', shell.resource_version,
      'active_version', shell.active_version,
      'archived_at', shell.archived_at,
      'label', version.label, 'timezone', version.timezone,
      'weekly_schedule', version.weekly_schedule,
      'exceptions', version.exceptions,
      'revision_digest', encode(version.revision_digest, 'hex'),
      'created_at', shell.created_at, 'updated_at', shell.updated_at
    )
    FROM public.sla_business_calendars AS shell
    JOIN public.sla_business_calendar_versions AS version
      ON version.tenant_id = shell.tenant_id
     AND version.calendar_id = shell.id
     AND version.version = shell.active_version
    WHERE shell.tenant_id = p_tenant_id
      AND (p_resource_id IS NULL OR shell.id = p_resource_id)
      AND (p_include_archived OR shell.archived_at IS NULL)
      AND (p_after_key IS NULL OR (shell.key, shell.id) > (p_after_key, p_after_id))
    ORDER BY shell.key, shell.id LIMIT p_limit;
  ELSIF p_kind = 'policy' THEN
    RETURN QUERY
    SELECT jsonb_build_object(
      'id', shell.id, 'key', shell.key,
      'resource_version', shell.resource_version,
      'active_version', shell.active_version,
      'archived_at', shell.archived_at,
      'name', version.name, 'description', version.description,
      'priority', version.priority, 'object_types', version.object_types,
      'match_rule', version.match_rule,
      'effective_from', version.effective_from,
      'effective_until', version.effective_until,
      'enabled', version.enabled,
      'apply_to_sla_engine_source', version.apply_to_sla_engine_source,
      'revision_digest', encode(version.revision_digest, 'hex'),
      'metrics', coalesce((
        SELECT jsonb_agg(to_jsonb(metric) - 'tenant_id' - 'policy_id'
                         - 'policy_version' - 'created_at'
                         ORDER BY metric.position, metric.id)
        FROM public.sla_metric_definitions AS metric
        WHERE metric.tenant_id = version.tenant_id
          AND metric.policy_id = version.policy_id
          AND metric.policy_version = version.version
      ), '[]'::jsonb),
      'triggers', coalesce((
        SELECT jsonb_agg(to_jsonb(trigger_row) - 'tenant_id' - 'policy_id'
                         - 'policy_version' - 'created_at'
                         ORDER BY trigger_row.position, trigger_row.id)
        FROM public.sla_trigger_definitions AS trigger_row
        WHERE trigger_row.tenant_id = version.tenant_id
          AND trigger_row.policy_id = version.policy_id
          AND trigger_row.policy_version = version.version
      ), '[]'::jsonb),
      'created_at', shell.created_at, 'updated_at', shell.updated_at
    )
    FROM public.sla_policies AS shell
    JOIN public.sla_policy_versions AS version
      ON version.tenant_id = shell.tenant_id
     AND version.policy_id = shell.id
     AND version.version = shell.active_version
    WHERE shell.tenant_id = p_tenant_id
      AND (p_resource_id IS NULL OR shell.id = p_resource_id)
      AND (p_include_archived OR shell.archived_at IS NULL)
      AND (p_after_key IS NULL OR (shell.key, shell.id) > (p_after_key, p_after_id))
    ORDER BY shell.key, shell.id LIMIT p_limit;
  ELSE
    RETURN QUERY
    SELECT jsonb_build_object(
      'id', shell.id, 'key', shell.key,
      'resource_version', shell.resource_version,
      'active_version', shell.active_version,
      'archived_at', shell.archived_at,
      'label', version.label,
      'metric_definition_id', version.metric_definition_id,
      'calculation', version.calculation, 'format', version.format,
      'sortable', version.sortable, 'filterable', version.filterable,
      'customer_visible', version.customer_visible,
      'visible_role_keys', version.visible_role_keys,
      'position', version.position, 'style_rules', version.style_rules,
      'revision_digest', encode(version.revision_digest, 'hex'),
      'created_at', shell.created_at, 'updated_at', shell.updated_at
    )
    FROM public.sla_columns AS shell
    JOIN public.sla_column_versions AS version
      ON version.tenant_id = shell.tenant_id
     AND version.column_id = shell.id
     AND version.version = shell.active_version
    WHERE shell.tenant_id = p_tenant_id
      AND (p_resource_id IS NULL OR shell.id = p_resource_id)
      AND (p_include_archived OR shell.archived_at IS NULL)
      AND (p_after_key IS NULL OR (shell.key, shell.id) > (p_after_key, p_after_id))
    ORDER BY shell.key, shell.id LIMIT p_limit;
  END IF;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.read_sla_configuration_v1(
  uuid, text, uuid, text, uuid, integer, boolean
) OWNER TO periapsis_sla_api_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.read_sla_configuration_v1(
  uuid, text, uuid, text, uuid, integer, boolean
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.read_sla_configuration_v1(
  uuid, text, uuid, text, uuid, integer, boolean
) TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.private_apply_sla_runtime_plan_v1(
  p_tenant_id uuid,
  p_sla_instance_id uuid,
  p_object_type public.sla_object_type,
  p_object_id uuid,
  p_plan jsonb,
  p_observed_at timestamp with time zone
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
  metric jsonb;
  cursor_row jsonb;
  occurrence jsonb;
  column_value jsonb;
  affected integer;
  existing_occurrence record;
BEGIN
  IF p_tenant_id IS NULL OR p_sla_instance_id IS NULL OR p_object_id IS NULL
     OR jsonb_typeof(p_plan) <> 'object'
     OR pg_column_size(p_plan) > 16777216
     OR jsonb_typeof(p_plan -> 'metrics') <> 'array'
     OR jsonb_array_length(p_plan -> 'metrics') > 32
     OR jsonb_typeof(p_plan -> 'cursors') <> 'array'
     OR jsonb_array_length(p_plan -> 'cursors') > 8192
     OR jsonb_typeof(p_plan -> 'occurrences') <> 'array'
     OR jsonb_array_length(p_plan -> 'occurrences') > 8192
     OR jsonb_typeof(p_plan -> 'columns') <> 'array'
     OR jsonb_array_length(p_plan -> 'columns') > 8192
     OR p_observed_at IS NULL THEN
    RAISE EXCEPTION 'SLA runtime plan is invalid' USING ERRCODE = '22023';
  END IF;

  FOR metric IN SELECT value FROM jsonb_array_elements(p_plan -> 'metrics') LOOP
    IF jsonb_typeof(metric) <> 'object'
       OR (metric ->> 'id') IS NULL
       OR (metric ->> 'version')::integer NOT BETWEEN 1 AND 2147483646 THEN
      RAISE EXCEPTION 'SLA metric plan is invalid' USING ERRCODE = '22023';
    END IF;
    INSERT INTO public.sla_metric_instances (
      id, tenant_id, sla_instance_id, definition_id,
      policy_id, policy_version, version, lifecycle, state,
      created_at, updated_at, extension_micros, consumed_micros,
      started_at, last_resumed_at, paused_at, completed_at, due_at,
      breach_threshold_at, breached_at, last_event_id, last_event_key,
      last_event_at, last_override_id, last_override_digest
    ) VALUES (
      (metric ->> 'id')::uuid, p_tenant_id, p_sla_instance_id,
      (metric ->> 'definition_id')::uuid,
      (metric ->> 'policy_id')::uuid,
      (metric ->> 'policy_version')::integer,
      (metric ->> 'version')::integer,
      (metric ->> 'lifecycle')::public.sla_metric_lifecycle,
      (metric ->> 'state')::public.sla_metric_state,
      (metric ->> 'created_at')::timestamp with time zone,
      (metric ->> 'updated_at')::timestamp with time zone,
      (metric ->> 'extension_micros')::bigint,
      (metric ->> 'consumed_micros')::bigint,
      (metric ->> 'started_at')::timestamp with time zone,
      (metric ->> 'last_resumed_at')::timestamp with time zone,
      (metric ->> 'paused_at')::timestamp with time zone,
      (metric ->> 'completed_at')::timestamp with time zone,
      (metric ->> 'due_at')::timestamp with time zone,
      (metric ->> 'breach_threshold_at')::timestamp with time zone,
      (metric ->> 'breached_at')::timestamp with time zone,
      (metric ->> 'last_event_id')::uuid,
      nullif(metric ->> 'last_event_key', ''),
      (metric ->> 'last_event_at')::timestamp with time zone,
      (metric ->> 'last_override_id')::uuid,
      CASE WHEN metric ->> 'last_override_digest' IS NULL THEN NULL
           ELSE decode(metric ->> 'last_override_digest', 'hex') END
    )
    ON CONFLICT (id) DO UPDATE
    SET definition_id = EXCLUDED.definition_id,
        policy_id = EXCLUDED.policy_id,
        policy_version = EXCLUDED.policy_version,
        version = EXCLUDED.version,
        lifecycle = EXCLUDED.lifecycle,
        state = EXCLUDED.state,
        updated_at = EXCLUDED.updated_at,
        extension_micros = EXCLUDED.extension_micros,
        consumed_micros = EXCLUDED.consumed_micros,
        started_at = EXCLUDED.started_at,
        last_resumed_at = EXCLUDED.last_resumed_at,
        paused_at = EXCLUDED.paused_at,
        completed_at = EXCLUDED.completed_at,
        due_at = EXCLUDED.due_at,
        breach_threshold_at = EXCLUDED.breach_threshold_at,
        breached_at = EXCLUDED.breached_at,
        last_event_id = EXCLUDED.last_event_id,
        last_event_key = EXCLUDED.last_event_key,
        last_event_at = EXCLUDED.last_event_at,
        last_override_id = EXCLUDED.last_override_id,
        last_override_digest = EXCLUDED.last_override_digest
    WHERE sla_metric_instances.tenant_id = p_tenant_id
      AND sla_metric_instances.sla_instance_id = p_sla_instance_id
      AND sla_metric_instances.version = EXCLUDED.version - 1;
    GET DIAGNOSTICS affected = ROW_COUNT;
    IF affected <> 1 THEN
      RAISE EXCEPTION 'SLA metric plan precondition failed'
        USING ERRCODE = '40001';
    END IF;
  END LOOP;

  FOR cursor_row IN
    SELECT value FROM jsonb_array_elements(p_plan -> 'cursors')
  LOOP
    INSERT INTO public.sla_trigger_cursors (
      tenant_id, metric_instance_id, trigger_definition_id,
      initialized, last_observed_at, last_state, last_percentage,
      last_remaining_micros, last_repeat_window, last_fired_at,
      fire_count, updated_at
    ) VALUES (
      p_tenant_id, (cursor_row ->> 'metric_instance_id')::uuid,
      (cursor_row ->> 'trigger_definition_id')::uuid,
      (cursor_row ->> 'initialized')::boolean,
      (cursor_row ->> 'last_observed_at')::timestamp with time zone,
      (cursor_row ->> 'last_state')::public.sla_metric_state,
      (cursor_row ->> 'last_percentage')::double precision,
      (cursor_row ->> 'last_remaining_micros')::bigint,
      (cursor_row ->> 'last_repeat_window')::bigint,
      (cursor_row ->> 'last_fired_at')::timestamp with time zone,
      (cursor_row ->> 'fire_count')::bigint, p_observed_at
    )
    ON CONFLICT (tenant_id, metric_instance_id, trigger_definition_id)
    DO UPDATE SET
      initialized = EXCLUDED.initialized,
      last_observed_at = EXCLUDED.last_observed_at,
      last_state = EXCLUDED.last_state,
      last_percentage = EXCLUDED.last_percentage,
      last_remaining_micros = EXCLUDED.last_remaining_micros,
      last_repeat_window = EXCLUDED.last_repeat_window,
      last_fired_at = EXCLUDED.last_fired_at,
      fire_count = EXCLUDED.fire_count,
      updated_at = EXCLUDED.updated_at
    WHERE sla_trigger_cursors.updated_at <= EXCLUDED.updated_at;
    GET DIAGNOSTICS affected = ROW_COUNT;
    IF affected <> 1 THEN
      RAISE EXCEPTION 'SLA cursor plan precondition failed'
        USING ERRCODE = '40001';
    END IF;
  END LOOP;

  FOR occurrence IN
    SELECT value FROM jsonb_array_elements(p_plan -> 'occurrences')
  LOOP
    INSERT INTO public.sla_trigger_occurrences (
      id, tenant_id, sla_instance_id, metric_instance_id,
      trigger_definition_id, scheduled_at, deduplication_digest,
      action_kind, action_configuration_id, action_value,
      allow_recursive_sla, created_at
    ) VALUES (
      (occurrence ->> 'id')::uuid, p_tenant_id, p_sla_instance_id,
      (occurrence ->> 'metric_instance_id')::uuid,
      (occurrence ->> 'trigger_definition_id')::uuid,
      (occurrence ->> 'scheduled_at')::timestamp with time zone,
      decode(occurrence ->> 'deduplication_digest', 'hex'),
      (occurrence ->> 'action_kind')::public.sla_trigger_action_kind,
      (occurrence ->> 'action_configuration_id')::uuid,
      occurrence ->> 'action_value',
      (occurrence ->> 'allow_recursive_sla')::boolean,
      p_observed_at
    )
    ON CONFLICT (tenant_id, deduplication_digest) DO NOTHING;
    GET DIAGNOSTICS affected = ROW_COUNT;
    IF affected = 0 THEN
      SELECT existing.id, existing.sla_instance_id,
             existing.metric_instance_id, existing.trigger_definition_id,
             existing.scheduled_at, existing.action_kind,
             existing.action_configuration_id, existing.action_value,
             existing.allow_recursive_sla
      INTO existing_occurrence
      FROM public.sla_trigger_occurrences AS existing
      WHERE existing.tenant_id = p_tenant_id
        AND existing.deduplication_digest = decode(
          occurrence ->> 'deduplication_digest', 'hex'
        );
      IF NOT FOUND
         OR existing_occurrence.id IS DISTINCT FROM
              (occurrence ->> 'id')::uuid
         OR existing_occurrence.sla_instance_id IS DISTINCT FROM
              p_sla_instance_id
         OR existing_occurrence.metric_instance_id IS DISTINCT FROM
              (occurrence ->> 'metric_instance_id')::uuid
         OR existing_occurrence.trigger_definition_id IS DISTINCT FROM
              (occurrence ->> 'trigger_definition_id')::uuid
         OR existing_occurrence.scheduled_at IS DISTINCT FROM
              (occurrence ->> 'scheduled_at')::timestamp with time zone
         OR existing_occurrence.action_kind IS DISTINCT FROM
              (occurrence ->> 'action_kind')::public.sla_trigger_action_kind
         OR existing_occurrence.action_configuration_id IS DISTINCT FROM
              (occurrence ->> 'action_configuration_id')::uuid
         OR existing_occurrence.action_value IS DISTINCT FROM
              occurrence ->> 'action_value'
         OR existing_occurrence.allow_recursive_sla IS DISTINCT FROM
              (occurrence ->> 'allow_recursive_sla')::boolean THEN
        RAISE EXCEPTION 'SLA occurrence deduplication conflict'
          USING ERRCODE = '23505';
      END IF;
    END IF;
  END LOOP;

  FOR column_value IN
    SELECT value FROM jsonb_array_elements(p_plan -> 'columns')
  LOOP
    INSERT INTO public.sla_materialized_column_values (
      tenant_id, object_type, object_id, sla_instance_id,
      metric_instance_id, column_id, column_version, state_value,
      instant_value, duration_micros_value, percentage_value, style_key,
      next_refresh_at, materialized_at
    ) VALUES (
      p_tenant_id, p_object_type, p_object_id, p_sla_instance_id,
      (column_value ->> 'metric_instance_id')::uuid,
      (column_value ->> 'column_id')::uuid,
      (column_value ->> 'column_version')::integer,
      (column_value ->> 'state_value')::public.sla_metric_state,
      (column_value ->> 'instant_value')::timestamp with time zone,
      (column_value ->> 'duration_micros_value')::bigint,
      (column_value ->> 'percentage_value')::double precision,
      nullif(column_value ->> 'style_key', ''),
      (column_value ->> 'next_refresh_at')::timestamp with time zone,
      p_observed_at
    )
    ON CONFLICT (tenant_id, object_type, object_id, column_id)
    DO UPDATE SET
      sla_instance_id = EXCLUDED.sla_instance_id,
      metric_instance_id = EXCLUDED.metric_instance_id,
      column_version = EXCLUDED.column_version,
      state_value = EXCLUDED.state_value,
      instant_value = EXCLUDED.instant_value,
      duration_micros_value = EXCLUDED.duration_micros_value,
      percentage_value = EXCLUDED.percentage_value,
      style_key = EXCLUDED.style_key,
      next_refresh_at = EXCLUDED.next_refresh_at,
      materialized_at = EXCLUDED.materialized_at
    WHERE sla_materialized_column_values.sla_instance_id = p_sla_instance_id
      AND sla_materialized_column_values.materialized_at <= EXCLUDED.materialized_at;
    GET DIAGNOSTICS affected = ROW_COUNT;
    IF affected <> 1 THEN
      RAISE EXCEPTION 'SLA column materialization precondition failed'
        USING ERRCODE = '40001';
    END IF;
  END LOOP;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_apply_sla_runtime_plan_v1(
  uuid, uuid, public.sla_object_type, uuid, jsonb,
  timestamp with time zone
) OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_apply_sla_runtime_plan_v1(
  uuid, uuid, public.sla_object_type, uuid, jsonb,
  timestamp with time zone
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.private_apply_sla_runtime_plan_v1(
  uuid, uuid, public.sla_object_type, uuid, jsonb,
  timestamp with time zone
) TO periapsis_sla_api_owner, periapsis_sla_worker_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_upsert_sla_evaluation_job_v1(
  p_tenant_id uuid,
  p_sla_instance_id uuid,
  p_expected_aggregate_version integer,
  p_available_at timestamp with time zone,
  p_maximum_attempts integer DEFAULT 12
)
RETURNS uuid
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
  job_id uuid;
BEGIN
  IF p_available_at IS NULL THEN
    RETURN NULL;
  END IF;
  SELECT job.id INTO job_id
  FROM public.sla_evaluation_jobs AS job
  WHERE job.tenant_id = p_tenant_id
    AND job.sla_instance_id = p_sla_instance_id
    AND job.status IN ('queued', 'leased', 'retry_scheduled')
  FOR UPDATE;
  IF FOUND THEN
    IF EXISTS (
      SELECT 1 FROM public.sla_evaluation_jobs AS job
      WHERE job.tenant_id = p_tenant_id AND job.id = job_id
        AND job.status = 'leased'
    ) THEN
      RAISE EXCEPTION 'leased SLA job cannot be rescheduled'
        USING ERRCODE = '40001';
    END IF;
    UPDATE public.sla_evaluation_jobs
    SET expected_aggregate_version = p_expected_aggregate_version,
        status = 'queued', available_at = p_available_at,
        attempt = 0, maximum_attempts = p_maximum_attempts,
        worker_id = NULL, lease_expires_at = NULL,
        last_failure_code = NULL, completed_at = NULL,
        dead_lettered_at = NULL, updated_at = transaction_timestamp()
    WHERE tenant_id = p_tenant_id AND id = job_id;
    RETURN job_id;
  END IF;
  job_id := uuidv7();
  INSERT INTO public.sla_evaluation_jobs (
    id, tenant_id, sla_instance_id, expected_aggregate_version,
    status, available_at, maximum_attempts, created_at, updated_at
  ) VALUES (
    job_id, p_tenant_id, p_sla_instance_id,
    p_expected_aggregate_version, 'queued', p_available_at,
    p_maximum_attempts, transaction_timestamp(), transaction_timestamp()
  );
  RETURN job_id;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_upsert_sla_evaluation_job_v1(
  uuid, uuid, integer, timestamp with time zone, integer
) OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_upsert_sla_evaluation_job_v1(
  uuid, uuid, integer, timestamp with time zone, integer
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.private_upsert_sla_evaluation_job_v1(
  uuid, uuid, integer, timestamp with time zone, integer
) TO periapsis_sla_api_owner, periapsis_sla_worker_owner;
--> statement-breakpoint

CREATE FUNCTION app.commit_sla_object_event_v1(
  p_tenant_id uuid,
  p_event_id uuid,
  p_object_type public.sla_object_type,
  p_object_id uuid,
  p_origin text,
  p_origin_id uuid,
  p_outcome public.sla_event_outcome,
  p_sla_instance_id uuid,
  p_expected_aggregate_version integer,
  p_next_aggregate_version integer,
  p_policy_id uuid,
  p_policy_version integer,
  p_occurred_at timestamp with time zone,
  p_plan jsonb,
  p_key_digest bytea,
  p_request_digest bytea,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE(
  event_id uuid,
  outcome public.sla_event_outcome,
  sla_instance_id uuid,
  aggregate_version integer,
  policy_id uuid,
  policy_version integer,
  replayed boolean
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  existing public.sla_object_event_ledger%ROWTYPE;
  aggregate public.sla_instances%ROWTYPE;
  read_permission text;
  next_evaluation_at timestamp with time zone;
BEGIN
  read_permission := CASE p_object_type
    WHEN 'alert' THEN 'alert.read'
    WHEN 'case' THEN 'case.read'
    ELSE NULL
  END;
  IF read_permission IS NULL
     OR NOT app.private_sla_context_allows_v1(
       read_permission, p_tenant_id, p_object_type, p_object_id
     )
     OR p_event_id IS NULL OR p_object_id IS NULL OR p_origin_id IS NULL
     OR p_origin IS NULL OR p_origin !~ '^[a-z][a-z0-9_.-]{0,127}$'
     OR p_occurred_at IS NULL
     OR jsonb_typeof(p_plan) <> 'object'
     OR octet_length(p_key_digest) <> 32
     OR octet_length(p_request_digest) <> 32
     OR p_request_id IS NULL OR p_correlation_id IS NULL
     OR NOT (
       p_outcome = 'no_policy' AND p_sla_instance_id IS NULL
         AND p_expected_aggregate_version = 0
         AND p_next_aggregate_version = 0
         AND p_policy_id IS NULL AND p_policy_version = 0
       OR p_outcome = 'assigned' AND p_sla_instance_id IS NOT NULL
         AND p_expected_aggregate_version = 0
         AND p_next_aggregate_version = 1
         AND p_policy_id IS NOT NULL
         AND p_policy_version BETWEEN 1 AND 2147483646
       OR p_outcome = 'updated' AND p_sla_instance_id IS NOT NULL
         AND p_expected_aggregate_version BETWEEN 1 AND 2147483645
         AND p_next_aggregate_version = p_expected_aggregate_version + 1
         AND p_policy_id IS NOT NULL
         AND p_policy_version BETWEEN 1 AND 2147483646
     ) THEN
    RAISE EXCEPTION 'SLA object event command is invalid'
      USING ERRCODE = '22023';
  END IF;

  PERFORM pg_advisory_xact_lock(
    hashtextextended(encode(p_key_digest, 'hex'), 0)
  );
  SELECT ledger.* INTO existing
  FROM public.sla_object_event_ledger AS ledger
  WHERE ledger.tenant_id = p_tenant_id
    AND ledger.key_digest = p_key_digest;
  IF FOUND THEN
    IF existing.request_digest IS DISTINCT FROM p_request_digest
       OR existing.event_id IS DISTINCT FROM p_event_id
       OR existing.object_type IS DISTINCT FROM p_object_type
       OR existing.object_id IS DISTINCT FROM p_object_id
       OR existing.origin IS DISTINCT FROM p_origin
       OR existing.origin_id IS DISTINCT FROM p_origin_id THEN
      RAISE EXCEPTION 'SLA event idempotency conflict'
        USING ERRCODE = '23505';
    END IF;
    RETURN QUERY SELECT existing.event_id, existing.outcome,
      existing.sla_instance_id, existing.aggregate_version,
      existing.policy_id, existing.policy_version, true;
    RETURN;
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.sla_object_event_ledger AS ledger
    WHERE ledger.tenant_id = p_tenant_id AND ledger.event_id = p_event_id
  ) THEN
    RAISE EXCEPTION 'SLA event identity conflict' USING ERRCODE = '23505';
  END IF;

  IF p_outcome = 'assigned' THEN
    INSERT INTO public.sla_instances (
      id, tenant_id, object_type, object_id, policy_id, policy_version,
      aggregate_version, assignment_event_id, created_at, updated_at
    ) VALUES (
      p_sla_instance_id, p_tenant_id, p_object_type, p_object_id,
      p_policy_id, p_policy_version, 1, p_event_id,
      p_occurred_at, p_occurred_at
    );
    PERFORM app.private_apply_sla_runtime_plan_v1(
      p_tenant_id, p_sla_instance_id, p_object_type, p_object_id,
      p_plan, p_occurred_at
    );
  ELSIF p_outcome = 'updated' THEN
    SELECT instance.* INTO aggregate
    FROM public.sla_instances AS instance
    WHERE instance.tenant_id = p_tenant_id
      AND instance.id = p_sla_instance_id
    FOR UPDATE;
    IF NOT FOUND OR aggregate.object_type IS DISTINCT FROM p_object_type
       OR aggregate.object_id IS DISTINCT FROM p_object_id
       OR aggregate.policy_id IS DISTINCT FROM p_policy_id
       OR aggregate.policy_version IS DISTINCT FROM p_policy_version
       OR aggregate.aggregate_version IS DISTINCT FROM
            p_expected_aggregate_version
       OR p_occurred_at < aggregate.updated_at THEN
      RAISE EXCEPTION 'SLA event aggregate precondition failed'
        USING ERRCODE = '40001';
    END IF;
    UPDATE public.sla_instances
    SET aggregate_version = p_next_aggregate_version,
        updated_at = p_occurred_at,
        completed_at = CASE
          WHEN (p_plan ->> 'aggregate_completed_at') IS NULL
            THEN completed_at
          ELSE (p_plan ->> 'aggregate_completed_at')::timestamp with time zone
        END
    WHERE tenant_id = p_tenant_id AND id = p_sla_instance_id;
    PERFORM app.private_apply_sla_runtime_plan_v1(
      p_tenant_id, p_sla_instance_id, p_object_type, p_object_id,
      p_plan, p_occurred_at
    );
  END IF;

  IF p_outcome <> 'no_policy' THEN
    next_evaluation_at := (p_plan ->> 'next_evaluation_at')::timestamp with time zone;
    PERFORM app.private_upsert_sla_evaluation_job_v1(
      p_tenant_id, p_sla_instance_id, p_next_aggregate_version,
      next_evaluation_at, 12
    );
  END IF;

  INSERT INTO public.sla_object_event_ledger (
    tenant_id, event_id, object_type, object_id, origin, origin_id,
    key_digest, request_digest, outcome, sla_instance_id,
    aggregate_version, policy_id, policy_version, occurred_at, committed_at
  ) VALUES (
    p_tenant_id, p_event_id, p_object_type, p_object_id, p_origin,
    p_origin_id, p_key_digest, p_request_digest, p_outcome,
    p_sla_instance_id, p_next_aggregate_version, p_policy_id,
    p_policy_version, p_occurred_at, transaction_timestamp()
  );
  PERFORM app.private_append_sla_mutation_effects_v1(
    'sla.event.processed',
    CASE WHEN p_sla_instance_id IS NULL THEN 'sla_object'
         ELSE 'sla_instance' END,
    coalesce(p_sla_instance_id, p_object_id), p_next_aggregate_version,
    NULL,
    jsonb_build_object(
      'aggregateVersion', p_next_aggregate_version,
      'outcome', p_outcome
    ),
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method
  );
  RETURN QUERY SELECT p_event_id, p_outcome, p_sla_instance_id,
    p_next_aggregate_version, p_policy_id, p_policy_version, false;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.commit_sla_object_event_v1(
  uuid, uuid, public.sla_object_type, uuid, text, uuid,
  public.sla_event_outcome, uuid, integer, integer, uuid, integer,
  timestamp with time zone, jsonb, bytea, bytea, uuid, uuid,
  inet, text, text
) OWNER TO periapsis_sla_api_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.commit_sla_object_event_v1(
  uuid, uuid, public.sla_object_type, uuid, text, uuid,
  public.sla_event_outcome, uuid, integer, integer, uuid, integer,
  timestamp with time zone, jsonb, bytea, bytea, uuid, uuid,
  inet, text, text
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.commit_sla_object_event_v1(
  uuid, uuid, public.sla_object_type, uuid, text, uuid,
  public.sla_event_outcome, uuid, integer, integer, uuid, integer,
  timestamp with time zone, jsonb, bytea, bytea, uuid, uuid,
  inet, text, text
) TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.commit_sla_override_v1(
  p_tenant_id uuid,
  p_override_id uuid,
  p_object_type public.sla_object_type,
  p_object_id uuid,
  p_sla_instance_id uuid,
  p_metric_instance_id uuid,
  p_kind public.sla_override_kind,
  p_reason text,
  p_outcome public.sla_override_outcome,
  p_expected_aggregate_version integer,
  p_next_aggregate_version integer,
  p_previous_version integer,
  p_current_version integer,
  p_policy_id uuid,
  p_policy_version integer,
  p_permission_epoch bigint,
  p_subject_epoch bigint,
  p_occurred_at timestamp with time zone,
  p_command_digest bytea,
  p_simulation_digest bytea,
  p_plan jsonb,
  p_key_digest bytea,
  p_request_digest bytea,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE(
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
  replayed boolean
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor_membership uuid := app.current_tenant_membership_id();
  permission_key text;
  current_permission_epoch bigint;
  current_subject_epoch bigint;
  existing public.sla_overrides%ROWTYPE;
  aggregate public.sla_instances%ROWTYPE;
  next_evaluation_at timestamp with time zone;
BEGIN
  permission_key := CASE p_object_type
    WHEN 'alert' THEN 'alert.sla.override'
    WHEN 'case' THEN 'case.sla.override'
    ELSE NULL
  END;
  IF permission_key IS NULL
     OR NOT app.private_sla_context_allows_v1(
       permission_key, p_tenant_id, p_object_type, p_object_id
     )
     OR p_override_id IS NULL OR p_sla_instance_id IS NULL
     OR p_object_id IS NULL
     OR p_reason IS NULL OR octet_length(p_reason) NOT BETWEEN 3 AND 2000
     OR btrim(p_reason) <> p_reason OR p_reason ~ '[[:cntrl:]]'
     OR p_expected_aggregate_version NOT BETWEEN 1 AND 2147483645
     OR p_next_aggregate_version <> p_expected_aggregate_version + 1
     OR p_previous_version NOT BETWEEN 1 AND 2147483645
     OR p_current_version <> p_previous_version + 1
     OR p_policy_id IS NULL OR p_policy_version NOT BETWEEN 1 AND 2147483646
     OR p_permission_epoch NOT BETWEEN 1 AND 9223372036854775806
     OR p_subject_epoch NOT BETWEEN 1 AND 2147483646
     OR p_occurred_at IS NULL
     OR octet_length(p_command_digest) <> 32
     OR (p_simulation_digest IS NOT NULL
       AND octet_length(p_simulation_digest) <> 32)
     OR jsonb_typeof(p_plan) <> 'object'
     OR pg_column_size(p_plan) > 16777216
     OR octet_length(p_key_digest) <> 32
     OR octet_length(p_request_digest) <> 32
     OR p_request_id IS NULL OR p_correlation_id IS NULL
     OR NOT (
       p_outcome = 'metric_updated' AND p_metric_instance_id IS NOT NULL
       OR p_outcome = 'policy_changed' AND p_metric_instance_id IS NULL
         AND p_current_version = p_next_aggregate_version
     ) THEN
    RAISE EXCEPTION 'SLA override command is invalid'
      USING ERRCODE = '22023';
  END IF;
  SELECT epochs.permission_epoch, epochs.subject_epoch
  INTO current_permission_epoch, current_subject_epoch
  FROM app.private_lock_sla_authority_epochs_v1(
    p_tenant_id, actor_membership
  ) AS epochs;
  IF NOT FOUND OR current_permission_epoch IS DISTINCT FROM p_permission_epoch
     OR current_subject_epoch IS DISTINCT FROM p_subject_epoch THEN
    RAISE EXCEPTION 'SLA override authority epoch is stale'
      USING ERRCODE = '42501';
  END IF;

  PERFORM pg_advisory_xact_lock(
    hashtextextended(encode(p_key_digest, 'hex'), 0)
  );
  SELECT override_row.* INTO existing
  FROM public.sla_overrides AS override_row
  WHERE override_row.tenant_id = p_tenant_id
    AND override_row.actor_membership_id = actor_membership
    AND override_row.key_digest = p_key_digest;
  IF FOUND THEN
    IF existing.request_digest IS DISTINCT FROM p_request_digest
       OR existing.id IS DISTINCT FROM p_override_id
       OR existing.object_type IS DISTINCT FROM p_object_type
       OR existing.object_id IS DISTINCT FROM p_object_id
       OR existing.sla_instance_id IS DISTINCT FROM p_sla_instance_id
       OR existing.kind IS DISTINCT FROM p_kind THEN
      RAISE EXCEPTION 'SLA override idempotency conflict'
        USING ERRCODE = '23505';
    END IF;
    RETURN QUERY SELECT existing.id, existing.outcome,
      existing.metric_instance_id, existing.current_version,
      existing.aggregate_version, existing.policy_id,
      existing.policy_version, existing.permission_epoch,
      existing.subject_epoch, existing.occurred_at, true;
    RETURN;
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.sla_overrides AS override_row
    WHERE override_row.tenant_id = p_tenant_id
      AND override_row.id = p_override_id
  ) THEN
    RAISE EXCEPTION 'SLA override identity conflict' USING ERRCODE = '23505';
  END IF;

  SELECT instance.* INTO aggregate
  FROM public.sla_instances AS instance
  WHERE instance.tenant_id = p_tenant_id
    AND instance.id = p_sla_instance_id
  FOR UPDATE;
  IF NOT FOUND OR aggregate.object_type IS DISTINCT FROM p_object_type
     OR aggregate.object_id IS DISTINCT FROM p_object_id
     OR aggregate.aggregate_version IS DISTINCT FROM
          p_expected_aggregate_version
     OR p_occurred_at < aggregate.updated_at THEN
    RAISE EXCEPTION 'SLA override aggregate precondition failed'
      USING ERRCODE = '40001';
  END IF;
  IF p_outcome = 'metric_updated' AND NOT EXISTS (
    SELECT 1 FROM public.sla_metric_instances AS metric
    WHERE metric.tenant_id = p_tenant_id
      AND metric.sla_instance_id = p_sla_instance_id
      AND metric.id = p_metric_instance_id
      AND metric.version = p_previous_version
  ) THEN
    RAISE EXCEPTION 'SLA override metric precondition failed'
      USING ERRCODE = '40001';
  END IF;

  UPDATE public.sla_instances
  SET policy_id = p_policy_id, policy_version = p_policy_version,
      aggregate_version = p_next_aggregate_version,
      updated_at = p_occurred_at,
      completed_at = CASE
        WHEN (p_plan ->> 'aggregate_completed_at') IS NULL
          THEN completed_at
        ELSE (p_plan ->> 'aggregate_completed_at')::timestamp with time zone
      END
  WHERE tenant_id = p_tenant_id AND id = p_sla_instance_id;
  PERFORM app.private_apply_sla_runtime_plan_v1(
    p_tenant_id, p_sla_instance_id, p_object_type, p_object_id,
    p_plan, p_occurred_at
  );
  next_evaluation_at := (p_plan ->> 'next_evaluation_at')::timestamp with time zone;
  PERFORM app.private_upsert_sla_evaluation_job_v1(
    p_tenant_id, p_sla_instance_id, p_next_aggregate_version,
    next_evaluation_at, 12
  );

  INSERT INTO public.sla_overrides (
    id, tenant_id, actor_membership_id, object_type, object_id,
    sla_instance_id, metric_instance_id, kind, reason,
    key_digest, request_digest, command_digest, simulation_digest,
    outcome, previous_version, current_version, aggregate_version,
    policy_id, policy_version, permission_epoch, subject_epoch,
    previous_snapshot, current_snapshot, occurred_at, created_at
  ) VALUES (
    p_override_id, p_tenant_id, actor_membership, p_object_type,
    p_object_id, p_sla_instance_id, p_metric_instance_id, p_kind,
    p_reason, p_key_digest, p_request_digest, p_command_digest,
    p_simulation_digest, p_outcome, p_previous_version,
    p_current_version, p_next_aggregate_version, p_policy_id,
    p_policy_version, p_permission_epoch, p_subject_epoch,
    p_plan -> 'previous_snapshot', p_plan -> 'current_snapshot',
    p_occurred_at, transaction_timestamp()
  );
  PERFORM app.private_append_sla_mutation_effects_v1(
    'sla.override.committed',
    CASE WHEN p_metric_instance_id IS NULL
      THEN 'sla_instance' ELSE 'sla_metric_instance' END,
    coalesce(p_metric_instance_id, p_sla_instance_id),
    p_current_version,
    jsonb_build_object('version', p_previous_version),
    jsonb_build_object(
      'version', p_current_version,
      'aggregateVersion', p_next_aggregate_version,
      'kind', p_kind
    ),
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method
  );
  RETURN QUERY SELECT p_override_id, p_outcome, p_metric_instance_id,
    p_current_version, p_next_aggregate_version, p_policy_id,
    p_policy_version, p_permission_epoch, p_subject_epoch,
    p_occurred_at, false;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.commit_sla_override_v1(
  uuid, uuid, public.sla_object_type, uuid, uuid, uuid,
  public.sla_override_kind, text, public.sla_override_outcome,
  integer, integer, integer, integer, uuid, integer, bigint, bigint,
  timestamp with time zone, bytea, bytea, jsonb, bytea, bytea,
  uuid, uuid, inet, text, text
) OWNER TO periapsis_sla_api_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.commit_sla_override_v1(
  uuid, uuid, public.sla_object_type, uuid, uuid, uuid,
  public.sla_override_kind, text, public.sla_override_outcome,
  integer, integer, integer, integer, uuid, integer, bigint, bigint,
  timestamp with time zone, bytea, bytea, jsonb, bytea, bytea,
  uuid, uuid, inet, text, text
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.commit_sla_override_v1(
  uuid, uuid, public.sla_object_type, uuid, uuid, uuid,
  public.sla_override_kind, text, public.sla_override_outcome,
  integer, integer, integer, integer, uuid, integer, bigint, bigint,
  timestamp with time zone, bytea, bytea, jsonb, bytea, bytea,
  uuid, uuid, inet, text, text
) TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.claim_sla_evaluation_jobs_v1(
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
SET search_path = pg_catalog, public
AS $function$
BEGIN
  IF p_worker_id IS NULL
     OR (uuid_extract_version(p_worker_id) = 7) IS NOT TRUE
     OR p_observed_at IS NULL
     OR p_batch_size NOT BETWEEN 1 AND 100
     OR p_lease_micros NOT BETWEEN 1000000 AND 300000000 THEN
    RAISE EXCEPTION 'SLA claim request is invalid' USING ERRCODE = '22023';
  END IF;
  RETURN QUERY
  WITH candidates AS (
    SELECT job.tenant_id, job.id
    FROM public.sla_evaluation_jobs AS job
    WHERE job.attempt < job.maximum_attempts
      AND (
        job.status IN ('queued', 'retry_scheduled')
          AND job.available_at <= p_observed_at
        OR job.status = 'leased'
          AND job.lease_expires_at <= p_observed_at
      )
    ORDER BY coalesce(job.lease_expires_at, job.available_at),
             job.tenant_id, job.id
    FOR UPDATE SKIP LOCKED
    LIMIT p_batch_size
  ), claimed AS (
    UPDATE public.sla_evaluation_jobs AS job
    SET status = 'leased', worker_id = p_worker_id,
        lease_expires_at = p_observed_at
          + p_lease_micros * interval '1 microsecond',
        attempt = job.attempt + 1, fence = job.fence + 1,
        updated_at = p_observed_at
    FROM candidates
    WHERE job.tenant_id = candidates.tenant_id
      AND job.id = candidates.id
    RETURNING job.*
  )
  SELECT claimed.id, claimed.tenant_id, claimed.sla_instance_id,
    claimed.expected_aggregate_version, claimed.fence, claimed.attempt,
    p_observed_at, claimed.lease_expires_at,
    jsonb_build_object(
      'aggregate', to_jsonb(aggregate_row),
      'metrics', coalesce((
        SELECT jsonb_agg(
          to_jsonb(metric) || jsonb_build_object(
            'definition', to_jsonb(definition),
            'calendar', to_jsonb(calendar_version),
            'triggers', coalesce((
              SELECT jsonb_agg(to_jsonb(trigger_row)
                               ORDER BY trigger_row.position, trigger_row.id)
              FROM public.sla_trigger_definitions AS trigger_row
              WHERE trigger_row.tenant_id = metric.tenant_id
                AND trigger_row.policy_id = metric.policy_id
                AND trigger_row.policy_version = metric.policy_version
                AND trigger_row.metric_definition_id = metric.definition_id
            ), '[]'::jsonb),
            'cursors', coalesce((
              SELECT jsonb_agg(to_jsonb(cursor_row)
                               ORDER BY cursor_row.trigger_definition_id)
              FROM public.sla_trigger_cursors AS cursor_row
              WHERE cursor_row.tenant_id = metric.tenant_id
                AND cursor_row.metric_instance_id = metric.id
            ), '[]'::jsonb),
            'columns', coalesce((
              SELECT jsonb_agg(to_jsonb(column_version)
                               ORDER BY column_version.position,
                                        column_version.column_id)
              FROM public.sla_columns AS column_shell
              JOIN public.sla_column_versions AS column_version
                ON column_version.tenant_id = column_shell.tenant_id
               AND column_version.column_id = column_shell.id
               AND column_version.version = column_shell.active_version
              WHERE column_shell.tenant_id = metric.tenant_id
                AND column_shell.archived_at IS NULL
                AND column_version.metric_definition_id = metric.definition_id
            ), '[]'::jsonb)
          ) ORDER BY definition.position, metric.id
        )
        FROM public.sla_metric_instances AS metric
        JOIN public.sla_metric_definitions AS definition
          ON definition.tenant_id = metric.tenant_id
         AND definition.id = metric.definition_id
        LEFT JOIN public.sla_business_calendar_versions AS calendar_version
          ON calendar_version.tenant_id = definition.tenant_id
         AND calendar_version.calendar_id = definition.calendar_id
         AND calendar_version.version = definition.calendar_version
        WHERE metric.tenant_id = claimed.tenant_id
          AND metric.sla_instance_id = claimed.sla_instance_id
      ), '[]'::jsonb)
    )
  FROM claimed
  JOIN public.sla_instances AS aggregate_row
    ON aggregate_row.tenant_id = claimed.tenant_id
   AND aggregate_row.id = claimed.sla_instance_id
  ORDER BY claimed.lease_expires_at, claimed.tenant_id, claimed.id;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.claim_sla_evaluation_jobs_v1(
  uuid, timestamp with time zone, integer, bigint
) OWNER TO periapsis_sla_worker_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.claim_sla_evaluation_jobs_v1(
  uuid, timestamp with time zone, integer, bigint
) FROM PUBLIC, periapsis_api, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.claim_sla_evaluation_jobs_v1(
  uuid, timestamp with time zone, integer, bigint
) TO periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.finalize_sla_evaluation_job_v1(
  p_worker_id uuid,
  p_job_id uuid,
  p_tenant_id uuid,
  p_sla_instance_id uuid,
  p_expected_aggregate_version integer,
  p_fence bigint,
  p_completed_at timestamp with time zone,
  p_plan jsonb
)
RETURNS integer
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  job public.sla_evaluation_jobs%ROWTYPE;
  aggregate public.sla_instances%ROWTYPE;
  next_aggregate_version integer;
  next_evaluation_at timestamp with time zone;
  occurrence jsonb;
BEGIN
  IF p_worker_id IS NULL OR p_job_id IS NULL OR p_tenant_id IS NULL
     OR p_sla_instance_id IS NULL
     OR p_expected_aggregate_version NOT BETWEEN 1 AND 2147483645
     OR p_fence NOT BETWEEN 1 AND 9223372036854775806
     OR p_completed_at IS NULL OR jsonb_typeof(p_plan) <> 'object' THEN
    RAISE EXCEPTION 'SLA finalize request is invalid' USING ERRCODE = '22023';
  END IF;
  SELECT candidate.* INTO job
  FROM public.sla_evaluation_jobs AS candidate
  WHERE candidate.tenant_id = p_tenant_id AND candidate.id = p_job_id
  FOR UPDATE;
  IF NOT FOUND OR job.status <> 'leased'
     OR job.sla_instance_id IS DISTINCT FROM p_sla_instance_id
     OR job.expected_aggregate_version IS DISTINCT FROM
          p_expected_aggregate_version
     OR job.worker_id IS DISTINCT FROM p_worker_id
     OR job.fence IS DISTINCT FROM p_fence
     OR job.lease_expires_at < p_completed_at THEN
    RAISE EXCEPTION 'SLA finalize lease is stale' USING ERRCODE = '40001';
  END IF;
  SELECT instance.* INTO aggregate
  FROM public.sla_instances AS instance
  WHERE instance.tenant_id = p_tenant_id
    AND instance.id = p_sla_instance_id
  FOR UPDATE;
  IF NOT FOUND OR aggregate.aggregate_version IS DISTINCT FROM
       p_expected_aggregate_version
     OR p_completed_at < aggregate.updated_at THEN
    RAISE EXCEPTION 'SLA finalize aggregate is stale'
      USING ERRCODE = '40001';
  END IF;
  next_aggregate_version := p_expected_aggregate_version + 1;
  UPDATE public.sla_instances
  SET aggregate_version = next_aggregate_version,
      updated_at = p_completed_at,
      completed_at = CASE
        WHEN (p_plan ->> 'aggregate_completed_at') IS NULL
          THEN completed_at
        ELSE (p_plan ->> 'aggregate_completed_at')::timestamp with time zone
      END
  WHERE tenant_id = p_tenant_id AND id = p_sla_instance_id;
  PERFORM app.private_apply_sla_runtime_plan_v1(
    p_tenant_id, p_sla_instance_id, aggregate.object_type,
    aggregate.object_id, p_plan, p_completed_at
  );

  FOR occurrence IN
    SELECT value FROM jsonb_array_elements(p_plan -> 'occurrences')
  LOOP
    INSERT INTO public.outbox_events (
      id, tenant_id, aggregate_type, aggregate_id, aggregate_version,
      event_type, schema_version, payload, deduplication_key,
      actor_kind, producer, maximum_audience, occurred_at
    ) VALUES (
      uuidv7(), p_tenant_id, 'sla_instance', p_sla_instance_id,
      next_aggregate_version, 'sla.trigger.fired', 1,
      jsonb_build_object(
        'slaInstanceId', p_sla_instance_id,
        'occurrenceId', (occurrence ->> 'id')::uuid,
        'actionKind', occurrence ->> 'action_kind'
      ),
      'sla:occurrence:' || (occurrence ->> 'deduplication_digest'),
      'system', 'sla-worker', 'operator', p_completed_at
    )
    ON CONFLICT (tenant_id, deduplication_key) DO NOTHING;
  END LOOP;

  UPDATE public.sla_evaluation_jobs
  SET status = 'completed', worker_id = NULL, lease_expires_at = NULL,
      completed_at = p_completed_at, updated_at = p_completed_at
  WHERE tenant_id = p_tenant_id AND id = p_job_id;
  next_evaluation_at := (p_plan ->> 'next_evaluation_at')::timestamp with time zone;
  PERFORM app.private_upsert_sla_evaluation_job_v1(
    p_tenant_id, p_sla_instance_id, next_aggregate_version,
    next_evaluation_at, job.maximum_attempts
  );
  RETURN next_aggregate_version;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.finalize_sla_evaluation_job_v1(
  uuid, uuid, uuid, uuid, integer, bigint,
  timestamp with time zone, jsonb
) OWNER TO periapsis_sla_worker_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.finalize_sla_evaluation_job_v1(
  uuid, uuid, uuid, uuid, integer, bigint,
  timestamp with time zone, jsonb
) FROM PUBLIC, periapsis_api, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.finalize_sla_evaluation_job_v1(
  uuid, uuid, uuid, uuid, integer, bigint,
  timestamp with time zone, jsonb
) TO periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.fail_sla_evaluation_job_v1(
  p_worker_id uuid,
  p_job_id uuid,
  p_tenant_id uuid,
  p_fence bigint,
  p_attempt integer,
  p_failure_code text,
  p_permanent boolean,
  p_failed_at timestamp with time zone,
  p_retry_at timestamp with time zone
)
RETURNS public.sla_job_status
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
  job public.sla_evaluation_jobs%ROWTYPE;
  next_status public.sla_job_status;
BEGIN
  IF p_worker_id IS NULL OR p_job_id IS NULL OR p_tenant_id IS NULL
     OR p_fence NOT BETWEEN 1 AND 9223372036854775806
     OR p_attempt NOT BETWEEN 1 AND 65535
     OR p_failure_code IS NULL
     OR p_failure_code !~ '^[a-z][a-z0-9_.-]{0,127}$'
     OR p_failed_at IS NULL
     OR (NOT p_permanent AND (p_retry_at IS NULL OR p_retry_at <= p_failed_at))
     OR (p_permanent AND p_retry_at IS NOT NULL) THEN
    RAISE EXCEPTION 'SLA failure request is invalid' USING ERRCODE = '22023';
  END IF;
  SELECT candidate.* INTO job
  FROM public.sla_evaluation_jobs AS candidate
  WHERE candidate.tenant_id = p_tenant_id AND candidate.id = p_job_id
  FOR UPDATE;
  IF NOT FOUND OR job.status <> 'leased'
     OR job.worker_id IS DISTINCT FROM p_worker_id
     OR job.fence IS DISTINCT FROM p_fence
     OR job.attempt IS DISTINCT FROM p_attempt
     OR job.lease_expires_at < p_failed_at THEN
    RAISE EXCEPTION 'SLA failure lease is stale' USING ERRCODE = '40001';
  END IF;
  next_status := CASE
    WHEN p_permanent OR job.attempt >= job.maximum_attempts
      THEN 'dead_lettered'::public.sla_job_status
    ELSE 'retry_scheduled'::public.sla_job_status
  END;
  UPDATE public.sla_evaluation_jobs
  SET status = next_status,
      available_at = CASE WHEN next_status = 'retry_scheduled'
                          THEN p_retry_at ELSE available_at END,
      worker_id = NULL, lease_expires_at = NULL,
      last_failure_code = p_failure_code,
      dead_lettered_at = CASE WHEN next_status = 'dead_lettered'
                              THEN p_failed_at ELSE NULL END,
      updated_at = p_failed_at
  WHERE tenant_id = p_tenant_id AND id = p_job_id;
  RETURN next_status;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.fail_sla_evaluation_job_v1(
  uuid, uuid, uuid, bigint, integer, text, boolean,
  timestamp with time zone, timestamp with time zone
) OWNER TO periapsis_sla_worker_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.fail_sla_evaluation_job_v1(
  uuid, uuid, uuid, bigint, integer, text, boolean,
  timestamp with time zone, timestamp with time zone
) FROM PUBLIC, periapsis_api, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.fail_sla_evaluation_job_v1(
  uuid, uuid, uuid, bigint, integer, text, boolean,
  timestamp with time zone, timestamp with time zone
) TO periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.read_sla_runtime_state_v1(
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
  aggregate_row public.sla_instances%ROWTYPE;
  fact_document jsonb;
  permission_epoch bigint;
  subject_epoch integer;
BEGIN
  IF p_at IS NULL OR p_object_id IS NULL
     OR p_capability NOT IN (
       'alert.read', 'case.read',
       'alert.sla.override', 'case.sla.override'
     ) OR NOT app.private_sla_context_allows_v1(
       p_capability, p_tenant_id, p_object_type, p_object_id
     ) THEN
    RAISE EXCEPTION 'SLA runtime read is forbidden' USING ERRCODE = '42501';
  END IF;
  IF p_object_type = 'alert' THEN
    SELECT jsonb_build_object(
      'object_type', 'alert', 'object_id', alert.id,
      'state', alert.state_key, 'priority', alert.priority,
      'severity', alert.severity, 'category', alert.category,
      'classification', alert.classification, 'source', alert.source,
      'tags', alert.tags, 'custom_fields', alert.custom_fields,
      'customer_custom_fields', alert.customer_custom_fields,
      'assigned_team_id', alert.assigned_team_id,
      'assignee_user_id', alert.assignee_user_id,
      'claimed_by_user_id', alert.claimed_by_user_id,
      'evaluated_at', p_at
    ) INTO fact_document
    FROM public.alerts AS alert
    WHERE alert.tenant_id = p_tenant_id AND alert.id = p_object_id;
  ELSIF p_object_type = 'case' THEN
    SELECT jsonb_build_object(
      'object_type', 'case', 'object_id', case_row.id,
      'state', case_row.state_key, 'priority', case_row.priority,
      'severity', case_row.severity, 'category', case_row.category,
      'classification', case_row.classification, 'source', 'case',
      'tags', case_row.tags, 'custom_fields', case_row.custom_fields,
      'customer_custom_fields', case_row.customer_custom_fields,
      'assigned_team_id', case_row.assigned_team_id,
      'assignee_user_id', case_row.assignee_user_id,
      'claimed_by_user_id', case_row.claimed_by_user_id,
      'evaluated_at', p_at
    ) INTO fact_document
    FROM public.cases AS case_row
    WHERE case_row.tenant_id = p_tenant_id AND case_row.id = p_object_id;
  ELSE
    RAISE EXCEPTION 'SLA runtime object type is unsupported'
      USING ERRCODE = '22023';
  END IF;
  IF fact_document IS NULL THEN
    RAISE EXCEPTION 'SLA runtime object not found' USING ERRCODE = 'P0002';
  END IF;

  SELECT instance.* INTO aggregate_row
  FROM public.sla_instances AS instance
  WHERE instance.tenant_id = p_tenant_id
    AND instance.object_type = p_object_type
    AND instance.object_id = p_object_id;
  SELECT state.revision, profile.version
  INTO permission_epoch, subject_epoch
  FROM public.tenant_authorization_states AS state
  JOIN public.tenant_user_profiles AS profile
    ON profile.tenant_id = state.tenant_id
   AND profile.membership_id = app.current_tenant_membership_id()
  WHERE state.tenant_id = p_tenant_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'SLA runtime authority projection is unavailable'
      USING ERRCODE = '42501';
  END IF;

  RETURN jsonb_build_object(
    'facts', fact_document,
    'permission_epoch', permission_epoch,
    'subject_epoch', subject_epoch,
    'aggregate', CASE WHEN aggregate_row.id IS NULL THEN NULL
      ELSE to_jsonb(aggregate_row) END,
    'metrics', CASE WHEN aggregate_row.id IS NULL THEN '[]'::jsonb ELSE
      coalesce((
        SELECT jsonb_agg(
          to_jsonb(metric) || jsonb_build_object(
            'definition', to_jsonb(definition),
            'calendar', to_jsonb(calendar_version),
            'triggers', coalesce((
              SELECT jsonb_agg(to_jsonb(trigger_row)
                               ORDER BY trigger_row.position, trigger_row.id)
              FROM public.sla_trigger_definitions AS trigger_row
              WHERE trigger_row.tenant_id = metric.tenant_id
                AND trigger_row.policy_id = metric.policy_id
                AND trigger_row.policy_version = metric.policy_version
                AND trigger_row.metric_definition_id = metric.definition_id
            ), '[]'::jsonb),
            'cursors', coalesce((
              SELECT jsonb_agg(to_jsonb(cursor_row)
                               ORDER BY cursor_row.trigger_definition_id)
              FROM public.sla_trigger_cursors AS cursor_row
              WHERE cursor_row.tenant_id = metric.tenant_id
                AND cursor_row.metric_instance_id = metric.id
            ), '[]'::jsonb)
          ) ORDER BY definition.position, metric.id
        )
        FROM public.sla_metric_instances AS metric
        JOIN public.sla_metric_definitions AS definition
          ON definition.tenant_id = metric.tenant_id
         AND definition.id = metric.definition_id
        LEFT JOIN public.sla_business_calendar_versions AS calendar_version
          ON calendar_version.tenant_id = definition.tenant_id
         AND calendar_version.calendar_id = definition.calendar_id
         AND calendar_version.version = definition.calendar_version
        WHERE metric.tenant_id = p_tenant_id
          AND metric.sla_instance_id = aggregate_row.id
      ), '[]'::jsonb) END,
    'materialized_columns', CASE WHEN aggregate_row.id IS NULL
      THEN '[]'::jsonb ELSE coalesce((
        SELECT jsonb_agg(to_jsonb(value_row)
                         ORDER BY value_row.column_id)
        FROM public.sla_materialized_column_values AS value_row
        WHERE value_row.tenant_id = p_tenant_id
          AND value_row.sla_instance_id = aggregate_row.id
      ), '[]'::jsonb) END,
    'active_policies', coalesce((
      SELECT jsonb_agg(
        to_jsonb(policy_version) || jsonb_build_object(
          'id', policy_shell.id, 'key', policy_shell.key,
          'metrics', coalesce((
            SELECT jsonb_agg(to_jsonb(metric)
                             ORDER BY metric.position, metric.id)
            FROM public.sla_metric_definitions AS metric
            WHERE metric.tenant_id = policy_version.tenant_id
              AND metric.policy_id = policy_version.policy_id
              AND metric.policy_version = policy_version.version
          ), '[]'::jsonb),
          'triggers', coalesce((
            SELECT jsonb_agg(to_jsonb(trigger_row)
                             ORDER BY trigger_row.position, trigger_row.id)
            FROM public.sla_trigger_definitions AS trigger_row
            WHERE trigger_row.tenant_id = policy_version.tenant_id
              AND trigger_row.policy_id = policy_version.policy_id
              AND trigger_row.policy_version = policy_version.version
          ), '[]'::jsonb)
        ) ORDER BY policy_version.priority DESC,
                   policy_shell.key, policy_shell.id
      )
      FROM public.sla_policies AS policy_shell
      JOIN public.sla_policy_versions AS policy_version
        ON policy_version.tenant_id = policy_shell.tenant_id
       AND policy_version.policy_id = policy_shell.id
       AND policy_version.version = policy_shell.active_version
      WHERE policy_shell.tenant_id = p_tenant_id
        AND policy_shell.archived_at IS NULL
        AND policy_version.enabled
        AND p_object_type = ANY(policy_version.object_types)
        AND policy_version.effective_from <= p_at
        AND (policy_version.effective_until IS NULL
          OR p_at < policy_version.effective_until)
    ), '[]'::jsonb),
    'active_calendars', coalesce((
      SELECT jsonb_agg(
        to_jsonb(calendar_version) || jsonb_build_object(
          'id', calendar_shell.id, 'key', calendar_shell.key
        ) ORDER BY calendar_shell.key, calendar_shell.id
      )
      FROM public.sla_business_calendars AS calendar_shell
      JOIN public.sla_business_calendar_versions AS calendar_version
        ON calendar_version.tenant_id = calendar_shell.tenant_id
       AND calendar_version.calendar_id = calendar_shell.id
       AND calendar_version.version = calendar_shell.active_version
      WHERE calendar_shell.tenant_id = p_tenant_id
        AND calendar_shell.archived_at IS NULL
    ), '[]'::jsonb),
    'active_columns', coalesce((
      SELECT jsonb_agg(
        to_jsonb(column_version) || jsonb_build_object(
          'id', column_shell.id, 'key', column_shell.key
        ) ORDER BY column_version.position, column_shell.key,
                   column_shell.id
      )
      FROM public.sla_columns AS column_shell
      JOIN public.sla_column_versions AS column_version
        ON column_version.tenant_id = column_shell.tenant_id
       AND column_version.column_id = column_shell.id
       AND column_version.version = column_shell.active_version
      WHERE column_shell.tenant_id = p_tenant_id
        AND column_shell.archived_at IS NULL
    ), '[]'::jsonb)
  );
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.read_sla_runtime_state_v1(
  uuid, public.sla_object_type, uuid, text, timestamp with time zone
) OWNER TO periapsis_sla_api_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.read_sla_runtime_state_v1(
  uuid, public.sla_object_type, uuid, text, timestamp with time zone
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.read_sla_runtime_state_v1(
  uuid, public.sla_object_type, uuid, text, timestamp with time zone
) TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.schema_compatibility_v21()
RETURNS TABLE(
  applied_count bigint,
  latest_created_at bigint,
  latest_hash text,
  migration_fingerprint text
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
  journal_count bigint;
  journal_latest_created_at bigint;
  migration_0106_rows bigint;
BEGIN
  EXECUTE $query$
    SELECT count(*)::bigint, max(migration.created_at)::bigint,
           count(*) FILTER (
             WHERE migration.created_at = 1787699142047
           )::bigint
    FROM drizzle.__drizzle_migrations AS migration
  $query$ INTO journal_count, journal_latest_created_at, migration_0106_rows;
  IF journal_count = 107
     AND journal_latest_created_at = 1787699142047
     AND migration_0106_rows = 1 THEN
    RETURN QUERY EXECUTE $query$
      SELECT count(*)::bigint, max(migration.created_at)::bigint,
             (SELECT lower(latest.hash::text)
              FROM drizzle.__drizzle_migrations AS latest
              ORDER BY latest.created_at DESC, latest.id DESC LIMIT 1),
             string_agg(
               migration.created_at::text || '@' || lower(migration.hash::text),
               ':' ORDER BY migration.created_at, migration.id
             )
      FROM drizzle.__drizzle_migrations AS migration
    $query$;
    RETURN;
  END IF;
  RETURN QUERY SELECT 0::bigint, 0::bigint,
                      'UNSUPPORTED'::text, 'UNSUPPORTED'::text;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.schema_compatibility_v21()
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.schema_compatibility_v21()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v21()
TO periapsis_api, periapsis_worker, periapsis_sla_readiness_owner;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.schema_compatibility_v20()
RETURNS TABLE(
  applied_count bigint,
  latest_created_at bigint,
  latest_hash text,
  migration_fingerprint text
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
SET app.schema_compatibility_fingerprint = 'UNSEALED'
AS $function$
DECLARE
  full_count bigint;
  full_latest_created_at bigint;
  full_fingerprint text;
BEGIN
  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.migration_fingerprint
  INTO full_count, full_latest_created_at, full_fingerprint
  FROM app.schema_compatibility_v21() AS compatibility;
  IF full_count = 107
     AND full_latest_created_at = 1787699142047
     AND full_fingerprint = current_setting(
       'app.schema_compatibility_fingerprint', true
     ) THEN
    RETURN QUERY EXECUTE $query$
      WITH ordered_migrations AS (
        SELECT migration.id, migration.created_at,
               lower(migration.hash::text) AS migration_hash,
               row_number() OVER (
                 ORDER BY migration.created_at, migration.id
               ) AS migration_ordinal
        FROM drizzle.__drizzle_migrations AS migration
      )
      SELECT count(*)::bigint, max(migration.created_at)::bigint,
             (SELECT prefix.migration_hash
              FROM ordered_migrations AS prefix
              WHERE prefix.migration_ordinal = 104),
             string_agg(
               migration.created_at::text || '@' || migration.migration_hash,
               ':' ORDER BY migration.created_at, migration.id
             )
      FROM ordered_migrations AS migration
      WHERE migration.migration_ordinal <= 104
    $query$;
    RETURN;
  END IF;
  RETURN QUERY SELECT 0::bigint, 0::bigint,
                      'UNSUPPORTED'::text, 'UNSUPPORTED'::text;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.schema_compatibility_v20()
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.schema_compatibility_v20()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v20()
TO periapsis_api, periapsis_worker, periapsis_sla_readiness_owner;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.schema_compatibility_v19()
RETURNS TABLE(
  applied_count bigint,
  latest_created_at bigint,
  latest_hash text,
  migration_fingerprint text
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
  RETURN QUERY SELECT 0::bigint, 0::bigint,
                      'UNSUPPORTED'::text, 'UNSUPPORTED'::text;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.schema_compatibility_v19()
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.schema_compatibility_v19()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v19()
TO periapsis_api, periapsis_worker, periapsis_sla_readiness_owner;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.seal_schema_compatibility_manifest(
  p_expected_count bigint,
  p_expected_latest_created_at bigint,
  p_expected_latest_hash text,
  p_expected_migration_fingerprint text
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
  fingerprint_entries text[];
  fingerprint_created_at bigint[];
  actual_count bigint;
  actual_latest_created_at bigint;
  actual_latest_hash text;
  actual_fingerprint text;
  predecessor_count bigint;
  predecessor_latest_created_at bigint;
  predecessor_latest_hash text;
  predecessor_fingerprint text;
  expected_predecessor_hash text;
  expected_predecessor_fingerprint text;
  retired_count bigint;
BEGIN
  fingerprint_entries := string_to_array(
    p_expected_migration_fingerprint, ':'
  );
  IF p_expected_count IS DISTINCT FROM 107
     OR p_expected_latest_created_at IS DISTINCT FROM 1787699142047
     OR p_expected_latest_hash IS NULL
     OR p_expected_latest_hash !~ '^[0-9a-f]{64}$'
     OR p_expected_migration_fingerprint IS NULL
     OR p_expected_migration_fingerprint !~
          '^[1-9][0-9]*@[0-9a-f]{64}(:[1-9][0-9]*@[0-9a-f]{64})*$'
     OR cardinality(fingerprint_entries) IS DISTINCT FROM 107
     OR fingerprint_entries[107] IS DISTINCT FROM (
       p_expected_latest_created_at::text || '@' || p_expected_latest_hash
     ) THEN
    RAISE EXCEPTION 'invalid schema compatibility v21 manifest'
      USING ERRCODE = '22023';
  END IF;

  SELECT array_agg(
    split_part(entry.value, '@', 1)::bigint ORDER BY entry.ordinality
  ) INTO fingerprint_created_at
  FROM unnest(fingerprint_entries) WITH ORDINALITY
       AS entry(value, ordinality);
  IF fingerprint_created_at IS DISTINCT FROM ARRAY[
    1787472409685, 1787472415216, 1787473527702, 1787473536723,
    1787474082034, 1787474089267, 1787475027656, 1787475184077,
    1787488565252, 1787488569966, 1787492910536, 1787493031146,
    1787494284382, 1787495115125, 1787495293635, 1787495819997,
    1787495999394, 1787496124539, 1787496880587, 1787496982733,
    1787496987011, 1787501702276, 1787506296280, 1787507888755,
    1787508523197, 1787516694668, 1787571776845, 1787581350373,
    1787581530382, 1787582150087, 1787591930962, 1787591938733,
    1787592230466, 1787612620574, 1787613580320, 1787613592459,
    1787613744526, 1787613746038, 1787613747552, 1787613749000,
    1787635396524, 1787635417084, 1787635433516, 1787635452090,
    1787635459707, 1787635471570, 1787635525474, 1787635788324,
    1787635828723, 1787637794128, 1787637795761, 1787643146844,
    1787643153628, 1787643609827, 1787648180127, 1787648190820,
    1787648201836, 1787648215689, 1787648225321, 1787649465766,
    1787649478666, 1787649523649, 1787649541586, 1787650610199,
    1787650730983, 1787653130160, 1787653143051, 1787653149806,
    1787653151267, 1787653305313, 1787655186569, 1787655192148,
    1787655197869, 1787655813403, 1787655819028, 1787655824109,
    1787657661213, 1787657666680, 1787658281433, 1787658434202,
    1787659622481, 1787659623982, 1787664581262, 1787664767505,
    1787664955067, 1787665119323, 1787665128173, 1787672101246,
    1787672114811, 1787672134042, 1787673489517, 1787677373554,
    1787677383849, 1787677403239, 1787677416302, 1787677427915,
    1787679172524, 1787680410777, 1787680424626, 1787682162037,
    1787686749137, 1787689670779, 1787692062461, 1787693815749,
    1787698427209, 1787698449287, 1787699142047
  ]::bigint[] THEN
    RAISE EXCEPTION 'invalid schema compatibility v21 timestamp sequence'
      USING ERRCODE = '22023';
  END IF;

  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
  INTO actual_count, actual_latest_created_at, actual_latest_hash,
       actual_fingerprint
  FROM app.schema_compatibility_v21() AS compatibility;
  IF actual_count IS DISTINCT FROM p_expected_count
     OR actual_latest_created_at IS DISTINCT FROM p_expected_latest_created_at
     OR actual_latest_hash IS DISTINCT FROM p_expected_latest_hash
     OR actual_fingerprint IS DISTINCT FROM p_expected_migration_fingerprint THEN
    RAISE EXCEPTION 'schema compatibility v21 manifest does not match the applied journal'
      USING ERRCODE = '55000';
  END IF;

  PERFORM set_config(
    'app.schema_compatibility_fingerprint',
    p_expected_migration_fingerprint, true
  );
  EXECUTE $statement$
    ALTER FUNCTION app.schema_compatibility_v20()
      SET app.schema_compatibility_fingerprint FROM CURRENT
  $statement$;
  expected_predecessor_hash := split_part(fingerprint_entries[104], '@', 2);
  expected_predecessor_fingerprint := array_to_string(
    fingerprint_entries[1:104], ':'
  );
  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
  INTO predecessor_count, predecessor_latest_created_at,
       predecessor_latest_hash, predecessor_fingerprint
  FROM app.schema_compatibility_v20() AS compatibility;
  IF predecessor_count IS DISTINCT FROM 104
     OR predecessor_latest_created_at IS DISTINCT FROM 1787693815749
     OR predecessor_latest_hash IS DISTINCT FROM expected_predecessor_hash
     OR predecessor_fingerprint IS DISTINCT FROM expected_predecessor_fingerprint THEN
    RAISE EXCEPTION 'sealed schema compatibility v20 prefix is not exact'
      USING ERRCODE = '55000';
  END IF;
  SELECT compatibility.applied_count INTO retired_count
  FROM app.schema_compatibility_v19() AS compatibility;
  IF retired_count IS DISTINCT FROM 0 THEN
    RAISE EXCEPTION 'schema compatibility v19 must be retired'
      USING ERRCODE = '55000';
  END IF;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.seal_schema_compatibility_manifest(
  bigint, bigint, text, text
) OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.seal_schema_compatibility_manifest(
  bigint, bigint, text, text
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner;
--> statement-breakpoint

CREATE FUNCTION app.sla_schema_readiness_v1()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  current_count bigint;
  predecessor_count bigint;
  retired_count bigint;
  seed_definition text;
  expected_index record;
BEGIN
  IF EXISTS (
    SELECT 1
    FROM (VALUES
      ('periapsis_sla_api_owner'),
      ('periapsis_sla_worker_owner'),
      ('periapsis_sla_readiness_owner')
    ) AS expected(role_name)
    LEFT JOIN pg_roles AS role ON role.rolname = expected.role_name
    WHERE role.oid IS NULL OR role.rolcanlogin OR role.rolsuper
       OR role.rolcreatedb OR role.rolcreaterole OR role.rolinherit
       OR role.rolreplication OR role.rolbypassrls
  ) THEN
    RETURN false;
  END IF;
  IF EXISTS (
    SELECT 1
    FROM (VALUES
      ('sla_business_calendars'), ('sla_business_calendar_versions'),
      ('sla_policies'), ('sla_policy_versions'),
      ('sla_metric_definitions'), ('sla_trigger_definitions'),
      ('sla_columns'), ('sla_column_versions'),
      ('sla_configuration_commands'), ('sla_instances'),
      ('sla_metric_instances'), ('sla_trigger_cursors'),
      ('sla_trigger_occurrences'), ('sla_materialized_column_values'),
      ('sla_object_event_ledger'), ('sla_evaluation_jobs'),
      ('sla_overrides')
    ) AS expected(table_name)
    LEFT JOIN pg_class AS table_row
      ON table_row.relname = expected.table_name
    LEFT JOIN pg_namespace AS namespace
      ON namespace.oid = table_row.relnamespace
     AND namespace.nspname = 'public'
    LEFT JOIN pg_attribute AS tenant_column
      ON tenant_column.attrelid = table_row.oid
     AND tenant_column.attname = 'tenant_id'
     AND NOT tenant_column.attisdropped
    WHERE table_row.oid IS NULL OR namespace.oid IS NULL
       OR table_row.relkind <> 'r'
       OR NOT table_row.relrowsecurity OR NOT table_row.relforcerowsecurity
       OR pg_get_userbyid(table_row.relowner) <> 'periapsis_migrator'
       OR tenant_column.attnum IS NULL OR NOT tenant_column.attnotnull
  ) THEN
    RETURN false;
  END IF;
  IF EXISTS (
    SELECT 1
    FROM (VALUES
      ('sla_business_calendars'), ('sla_business_calendar_versions'),
      ('sla_policies'), ('sla_policy_versions'),
      ('sla_metric_definitions'), ('sla_trigger_definitions'),
      ('sla_columns'), ('sla_column_versions'),
      ('sla_configuration_commands'), ('sla_instances'),
      ('sla_metric_instances'), ('sla_trigger_cursors'),
      ('sla_trigger_occurrences'), ('sla_materialized_column_values'),
      ('sla_object_event_ledger'), ('sla_evaluation_jobs'),
      ('sla_overrides')
    ) AS expected(table_name)
    CROSS JOIN (VALUES
      ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE'), ('TRUNCATE'),
      ('REFERENCES'), ('TRIGGER')
    ) AS privilege(privilege_name)
    CROSS JOIN (VALUES ('periapsis_api'), ('periapsis_worker'))
      AS runtime(role_name)
    WHERE has_table_privilege(
      runtime.role_name, 'public.' || expected.table_name,
      privilege.privilege_name
    )
  ) THEN
    RETURN false;
  END IF;
  IF EXISTS (
    SELECT 1
    FROM (VALUES
      ('app.private_lock_sla_authority_epochs_v1(uuid,uuid)', 'periapsis_migrator', 'v'::"char"),
      ('app.publish_sla_calendar_v1(uuid,uuid,integer,jsonb,bytea,bytea,uuid,uuid,inet,text,text)', 'periapsis_sla_api_owner', 'v'::"char"),
      ('app.publish_sla_policy_v1(uuid,uuid,integer,jsonb,bytea,bytea,uuid,uuid,inet,text,text)', 'periapsis_sla_api_owner', 'v'::"char"),
      ('app.publish_sla_column_v1(uuid,uuid,integer,jsonb,bytea,bytea,uuid,uuid,inet,text,text)', 'periapsis_sla_api_owner', 'v'::"char"),
      ('app.archive_sla_configuration_v1(uuid,text,uuid,integer,text,bytea,bytea,uuid,uuid,inet,text,text)', 'periapsis_sla_api_owner', 'v'::"char"),
      ('app.read_sla_configuration_v1(uuid,text,uuid,text,uuid,integer,boolean)', 'periapsis_sla_api_owner', 's'::"char"),
      ('app.read_sla_runtime_state_v1(uuid,public.sla_object_type,uuid,text,timestamp with time zone)', 'periapsis_sla_api_owner', 's'::"char"),
      ('app.commit_sla_object_event_v1(uuid,uuid,public.sla_object_type,uuid,text,uuid,public.sla_event_outcome,uuid,integer,integer,uuid,integer,timestamp with time zone,jsonb,bytea,bytea,uuid,uuid,inet,text,text)', 'periapsis_sla_api_owner', 'v'::"char"),
      ('app.commit_sla_override_v1(uuid,uuid,public.sla_object_type,uuid,uuid,uuid,public.sla_override_kind,text,public.sla_override_outcome,integer,integer,integer,integer,uuid,integer,bigint,bigint,timestamp with time zone,bytea,bytea,jsonb,bytea,bytea,uuid,uuid,inet,text,text)', 'periapsis_sla_api_owner', 'v'::"char"),
      ('app.claim_sla_evaluation_jobs_v1(uuid,timestamp with time zone,integer,bigint)', 'periapsis_sla_worker_owner', 'v'::"char"),
      ('app.finalize_sla_evaluation_job_v1(uuid,uuid,uuid,uuid,integer,bigint,timestamp with time zone,jsonb)', 'periapsis_sla_worker_owner', 'v'::"char"),
      ('app.fail_sla_evaluation_job_v1(uuid,uuid,uuid,bigint,integer,text,boolean,timestamp with time zone,timestamp with time zone)', 'periapsis_sla_worker_owner', 'v'::"char")
    ) AS expected(signature, owner_name, volatility)
    LEFT JOIN pg_proc AS procedure
      ON procedure.oid = to_regprocedure(expected.signature)
    WHERE procedure.oid IS NULL OR NOT procedure.prosecdef
       OR procedure.provolatile <> expected.volatility
       OR pg_get_userbyid(procedure.proowner) <> expected.owner_name
  ) THEN
    RETURN false;
  END IF;
  IF EXISTS (
    SELECT 1
    FROM (VALUES
      ('periapsis_api', 'app.publish_sla_calendar_v1(uuid,uuid,integer,jsonb,bytea,bytea,uuid,uuid,inet,text,text)'),
      ('periapsis_api', 'app.publish_sla_policy_v1(uuid,uuid,integer,jsonb,bytea,bytea,uuid,uuid,inet,text,text)'),
      ('periapsis_api', 'app.publish_sla_column_v1(uuid,uuid,integer,jsonb,bytea,bytea,uuid,uuid,inet,text,text)'),
      ('periapsis_api', 'app.archive_sla_configuration_v1(uuid,text,uuid,integer,text,bytea,bytea,uuid,uuid,inet,text,text)'),
      ('periapsis_api', 'app.read_sla_configuration_v1(uuid,text,uuid,text,uuid,integer,boolean)'),
      ('periapsis_api', 'app.read_sla_runtime_state_v1(uuid,public.sla_object_type,uuid,text,timestamp with time zone)'),
      ('periapsis_api', 'app.commit_sla_object_event_v1(uuid,uuid,public.sla_object_type,uuid,text,uuid,public.sla_event_outcome,uuid,integer,integer,uuid,integer,timestamp with time zone,jsonb,bytea,bytea,uuid,uuid,inet,text,text)'),
      ('periapsis_api', 'app.commit_sla_override_v1(uuid,uuid,public.sla_object_type,uuid,uuid,uuid,public.sla_override_kind,text,public.sla_override_outcome,integer,integer,integer,integer,uuid,integer,bigint,bigint,timestamp with time zone,bytea,bytea,jsonb,bytea,bytea,uuid,uuid,inet,text,text)'),
      ('periapsis_worker', 'app.claim_sla_evaluation_jobs_v1(uuid,timestamp with time zone,integer,bigint)'),
      ('periapsis_worker', 'app.finalize_sla_evaluation_job_v1(uuid,uuid,uuid,uuid,integer,bigint,timestamp with time zone,jsonb)'),
      ('periapsis_worker', 'app.fail_sla_evaluation_job_v1(uuid,uuid,uuid,bigint,integer,text,boolean,timestamp with time zone,timestamp with time zone)')
    ) AS expected(role_name, signature)
    WHERE NOT has_function_privilege(
      expected.role_name, expected.signature, 'EXECUTE'
    )
  ) THEN
    RETURN false;
  END IF;
  IF enum_range(NULL::public.sla_warning_kind)::text[] IS DISTINCT FROM
       ARRAY['none', 'consumed_percent', 'remaining_duration']::text[]
     OR enum_range(NULL::public.sla_trigger_kind)::text[] IS DISTINCT FROM
       ARRAY[
         'consumed_percent', 'remaining_duration', 'due', 'after_breach',
         'repeated_after_breach', 'state_changed', 'resumed'
       ]::text[]
     OR enum_range(NULL::public.sla_column_calculation)::text[] IS DISTINCT FROM
       ARRAY[
         'due_at', 'remaining_seconds', 'state', 'consumed_percentage',
         'breached_at'
       ]::text[] THEN
    RETURN false;
  END IF;
  IF EXISTS (
    SELECT 1
    FROM (VALUES
      ('sla_business_calendar_versions_immutable_v1'),
      ('sla_policy_versions_immutable_v1'),
      ('sla_metric_definitions_immutable_v1'),
      ('sla_trigger_definitions_immutable_v1'),
      ('sla_column_versions_immutable_v1'),
      ('sla_configuration_commands_immutable_v1'),
      ('sla_object_event_ledger_immutable_v1'),
      ('sla_trigger_occurrences_immutable_v1'),
      ('sla_overrides_immutable_v1'),
      ('sla_metric_instances_identity_v1'),
      ('sla_trigger_cursors_identity_v1'),
      ('sla_trigger_occurrences_identity_v1'),
      ('sla_materialized_columns_identity_v1'),
      ('sla_object_event_ledger_identity_v1'),
      ('sla_evaluation_jobs_identity_v1'),
      ('sla_overrides_identity_v1')
    ) AS expected(trigger_name)
    LEFT JOIN pg_trigger AS trigger_row
      ON trigger_row.tgname = expected.trigger_name
     AND NOT trigger_row.tgisinternal
    WHERE trigger_row.oid IS NULL OR trigger_row.tgenabled <> 'O'
  ) THEN
    RETURN false;
  END IF;
  FOR expected_index IN
    SELECT * FROM (VALUES
      ('sla_evaluation_jobs_claim_idx'),
      ('sla_evaluation_jobs_reclaim_idx'),
      ('sla_evaluation_jobs_live_aggregate_key'),
      ('sla_instances_object_projection_idx'),
      ('sla_metric_instances_schedule_idx'),
      ('sla_trigger_occurrences_dedup_key')
    ) AS required(index_name)
  LOOP
    IF NOT EXISTS (
      SELECT 1 FROM pg_index AS index_row
      JOIN pg_class AS index_class
        ON index_class.oid = index_row.indexrelid
      WHERE index_class.relname = expected_index.index_name
        AND index_row.indisvalid AND index_row.indisready
        AND index_row.indislive
    ) THEN
      RETURN false;
    END IF;
  END LOOP;
  IF EXISTS (
    SELECT 1
    FROM (VALUES
      ('sla.read', 'tenant'::public.authorization_scope),
      ('sla.manage', 'tenant'::public.authorization_scope),
      ('sla.simulate', 'tenant'::public.authorization_scope),
      ('alert.sla.override', 'own'::public.authorization_scope),
      ('alert.sla.override', 'assigned'::public.authorization_scope),
      ('alert.sla.override', 'operator_team'::public.authorization_scope),
      ('alert.sla.override', 'tenant'::public.authorization_scope),
      ('case.sla.override', 'own'::public.authorization_scope),
      ('case.sla.override', 'assigned'::public.authorization_scope),
      ('case.sla.override', 'operator_team'::public.authorization_scope),
      ('case.sla.override', 'tenant'::public.authorization_scope)
    ) AS expected(permission_key, scope)
    LEFT JOIN public.tenant_permissions AS permission
      ON permission.key = expected.permission_key
     AND NOT permission.service_account_allowed
    LEFT JOIN public.tenant_permission_scopes AS permission_scope
      ON permission_scope.permission_id = permission.id
     AND permission_scope.scope = expected.scope
    WHERE permission_scope.permission_id IS NULL
  ) THEN
    RETURN false;
  END IF;
  SELECT pg_get_functiondef(
    to_regprocedure('app.seed_tenant_authorization(uuid,uuid)')
  ) INTO seed_definition;
  IF seed_definition IS NULL OR seed_definition NOT LIKE
       '%private_seed_tenant_sla_authorization_v1%' THEN
    RETURN false;
  END IF;

  SELECT compatibility.applied_count INTO current_count
  FROM app.schema_compatibility_v21() AS compatibility;
  SELECT compatibility.applied_count INTO predecessor_count
  FROM app.schema_compatibility_v20() AS compatibility;
  SELECT compatibility.applied_count INTO retired_count
  FROM app.schema_compatibility_v19() AS compatibility;
  RETURN current_count = 107 AND predecessor_count = 104
    AND retired_count = 0;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.sla_schema_readiness_v1()
  OWNER TO periapsis_sla_readiness_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.sla_schema_readiness_v1()
FROM PUBLIC, periapsis_notifier, periapsis_auditor,
  periapsis_sla_api_owner, periapsis_sla_worker_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.sla_schema_readiness_v1()
TO periapsis_api, periapsis_worker;
--> statement-breakpoint

-- Keep existing readiness entry points truthful after v19 is retired.
CREATE OR REPLACE FUNCTION app.audit_reader_schema_readiness_v1()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE current_count bigint; predecessor_count bigint; retired_count bigint;
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_roles AS role
    WHERE role.rolname = 'periapsis_audit_reader_owner'
      AND NOT role.rolcanlogin AND NOT role.rolsuper
      AND NOT role.rolcreatedb AND NOT role.rolcreaterole
      AND NOT role.rolinherit AND NOT role.rolreplication
      AND NOT role.rolbypassrls
  ) OR NOT has_function_privilege(
    'periapsis_api',
    'app.list_tenant_audit_events_v1(uuid,text,bigint,integer,timestamp with time zone,timestamp with time zone,public.audit_actor_type,uuid,uuid,text,text,uuid,uuid,uuid,public.audit_outcome,text,uuid,uuid,uuid,inet,text)',
    'EXECUTE'
  ) OR NOT EXISTS (
    SELECT 1 FROM public.tenant_permissions AS permission
    JOIN public.tenant_permission_scopes AS scope
      ON scope.permission_id = permission.id
    WHERE permission.key = 'audit.read'
      AND NOT permission.service_account_allowed AND scope.scope = 'tenant'
  ) THEN
    RETURN false;
  END IF;
  SELECT applied_count INTO current_count FROM app.schema_compatibility_v21();
  SELECT applied_count INTO predecessor_count FROM app.schema_compatibility_v20();
  SELECT applied_count INTO retired_count FROM app.schema_compatibility_v19();
  RETURN current_count = 107 AND predecessor_count = 104
    AND retired_count = 0;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.audit_reader_schema_readiness_v1()
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.audit_reader_schema_readiness_v1()
FROM PUBLIC, periapsis_notifier, periapsis_auditor,
  periapsis_audit_reader_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.audit_reader_schema_readiness_v1()
TO periapsis_api, periapsis_worker;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.ticket_search_schema_readiness_v1()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE current_count bigint; predecessor_count bigint; retired_count bigint;
BEGIN
  IF EXISTS (
    SELECT 1
    FROM (VALUES
      ('alerts', 'alerts_ticket_search_idx'),
      ('cases', 'cases_ticket_search_idx')
    ) AS expected(table_name, index_name)
    LEFT JOIN pg_class AS index_class
      ON index_class.relname = expected.index_name
    LEFT JOIN pg_index AS index_row
      ON index_row.indexrelid = index_class.oid
    WHERE index_row.indexrelid IS NULL OR NOT index_row.indisvalid
       OR NOT index_row.indisready OR NOT index_row.indislive
  ) THEN
    RETURN false;
  END IF;
  SELECT applied_count INTO current_count FROM app.schema_compatibility_v21();
  SELECT applied_count INTO predecessor_count FROM app.schema_compatibility_v20();
  SELECT applied_count INTO retired_count FROM app.schema_compatibility_v19();
  RETURN current_count = 107 AND predecessor_count = 104
    AND retired_count = 0;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.ticket_search_schema_readiness_v1()
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.ticket_search_schema_readiness_v1()
FROM PUBLIC, periapsis_notifier, periapsis_auditor,
  periapsis_audit_reader_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.ticket_search_schema_readiness_v1()
TO periapsis_api, periapsis_worker;
--> statement-breakpoint
