-- Production SLA object-event ingress. Ticket mutations remain the source of
-- truth: this stream is populated transactionally from their outbox rows and
-- freezes the only configuration snapshot that may drive initial assignment.

CREATE TABLE public.sla_object_event_ingress (
  id uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
  tenant_id uuid NOT NULL,
  object_type public.sla_object_type NOT NULL,
  object_id uuid NOT NULL,
  object_sequence integer NOT NULL,
  source_event_id uuid NOT NULL,
  source_event_type text NOT NULL,
  source_schema_version integer NOT NULL,
  source_aggregate_version integer,
  source_digest bytea NOT NULL,
  event_key text NOT NULL,
  occurred_at timestamp with time zone NOT NULL,
  assignment_snapshot jsonb,
  assignment_snapshot_digest bytea,
  status public.sla_job_status DEFAULT 'queued' NOT NULL,
  available_at timestamp with time zone NOT NULL,
  attempt integer DEFAULT 0 NOT NULL,
  maximum_attempts integer DEFAULT 12 NOT NULL,
  worker_id uuid,
  lease_expires_at timestamp with time zone,
  fence bigint DEFAULT 0 NOT NULL,
  last_failure_code text,
  completed_at timestamp with time zone,
  dead_lettered_at timestamp with time zone,
  plan_digest bytea,
  receipt_digest bytea,
  created_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
  updated_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
  CONSTRAINT sla_object_event_ingress_tenant_id_id_key
    UNIQUE (tenant_id, id),
  CONSTRAINT sla_object_event_ingress_source_key
    UNIQUE (tenant_id, source_event_id),
  CONSTRAINT sla_object_event_ingress_sequence_key
    UNIQUE (tenant_id, object_type, object_id, object_sequence),
  CONSTRAINT sla_object_event_ingress_tenant_fk
    FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT,
  CONSTRAINT sla_object_event_ingress_source_fk
    FOREIGN KEY (tenant_id, source_event_id)
    REFERENCES public.outbox_events(tenant_id, id) ON DELETE RESTRICT,
  CONSTRAINT sla_object_event_ingress_id_check
    CHECK ((uuid_extract_version(id) = 7) IS TRUE),
  CONSTRAINT sla_object_event_ingress_source_id_check
    CHECK ((uuid_extract_version(source_event_id) = 7) IS TRUE),
  CONSTRAINT sla_object_event_ingress_object_id_check
    CHECK ((uuid_extract_version(object_id) = 7) IS TRUE),
  CONSTRAINT sla_object_event_ingress_source_check CHECK (
    object_type IN ('alert', 'case')
    AND object_sequence BETWEEN 1 AND 2147483646
    AND source_event_type ~
      '^(sla\.)?(alert|case)\.[a-z][a-z0-9_.-]{1,63}$'
    AND source_schema_version BETWEEN 1 AND 2147483646
    AND (source_aggregate_version IS NULL
      OR source_aggregate_version BETWEEN 1 AND 2147483646)
    AND octet_length(source_digest) = 32
    AND source_digest <> decode(repeat('00', 32), 'hex')
    AND event_key ~ '^[a-z][a-z0-9_.-]{0,62}[a-z0-9]$'
  ),
  CONSTRAINT sla_object_event_ingress_snapshot_check CHECK (
    object_sequence = 1 AND event_key = 'ticket.created'
      AND jsonb_typeof(assignment_snapshot) = 'object'
      AND pg_column_size(assignment_snapshot) <= 16777216
      AND octet_length(assignment_snapshot_digest) = 32
      AND assignment_snapshot_digest <> decode(repeat('00', 32), 'hex')
    OR assignment_snapshot IS NULL AND assignment_snapshot_digest IS NULL
      AND (object_sequence > 1 OR event_key <> 'ticket.created')
  ),
  CONSTRAINT sla_object_event_ingress_bounds_check CHECK (
    attempt BETWEEN 0 AND 65535
    AND maximum_attempts BETWEEN 1 AND 65535
    AND attempt <= maximum_attempts
    AND fence BETWEEN 0 AND 9223372036854775806
    AND updated_at >= created_at
    AND (last_failure_code IS NULL
      OR last_failure_code ~ '^[a-z][a-z0-9_.-]{0,127}$')
    AND (plan_digest IS NULL OR octet_length(plan_digest) = 32)
    AND (receipt_digest IS NULL OR octet_length(receipt_digest) = 32)
  ),
  CONSTRAINT sla_object_event_ingress_state_check CHECK (
    status IN ('queued', 'retry_scheduled')
      AND worker_id IS NULL AND lease_expires_at IS NULL
      AND completed_at IS NULL AND dead_lettered_at IS NULL
      AND plan_digest IS NULL AND receipt_digest IS NULL
    OR status = 'leased'
      AND worker_id IS NOT NULL AND lease_expires_at IS NOT NULL
      AND lease_expires_at > updated_at
      AND completed_at IS NULL AND dead_lettered_at IS NULL
      AND plan_digest IS NULL AND receipt_digest IS NULL
    OR status = 'completed'
      AND worker_id IS NULL AND lease_expires_at IS NULL
      AND completed_at IS NOT NULL AND dead_lettered_at IS NULL
      AND plan_digest IS NOT NULL AND receipt_digest IS NOT NULL
    OR status = 'dead_lettered'
      AND worker_id IS NULL AND lease_expires_at IS NULL
      AND completed_at IS NULL AND dead_lettered_at IS NOT NULL
      AND last_failure_code IS NOT NULL
      AND plan_digest IS NULL AND receipt_digest IS NULL
  )
);
--> statement-breakpoint
CREATE INDEX sla_object_event_ingress_claim_idx
ON public.sla_object_event_ingress (
  available_at, tenant_id, object_type, object_id
) WHERE status IN ('queued', 'retry_scheduled');
--> statement-breakpoint
CREATE INDEX sla_object_event_ingress_reclaim_idx
ON public.sla_object_event_ingress (
  lease_expires_at, tenant_id, object_type, object_id
) WHERE status = 'leased';
--> statement-breakpoint
CREATE INDEX sla_object_event_ingress_object_idx
ON public.sla_object_event_ingress (
  tenant_id, object_type, object_id, object_sequence
);
--> statement-breakpoint
ALTER TABLE public.sla_object_event_ingress
  OWNER TO periapsis_migrator;
--> statement-breakpoint
ALTER TABLE public.sla_object_event_ingress ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
ALTER TABLE public.sla_object_event_ingress FORCE ROW LEVEL SECURITY;
--> statement-breakpoint
REVOKE ALL ON TABLE public.sla_object_event_ingress
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_readiness_owner;
--> statement-breakpoint
GRANT SELECT, INSERT, UPDATE ON TABLE public.sla_object_event_ingress
TO periapsis_sla_worker_owner;
--> statement-breakpoint
CREATE POLICY sla_object_event_ingress_owner_access
ON public.sla_object_event_ingress AS PERMISSIVE FOR ALL
TO periapsis_sla_worker_owner USING (true) WITH CHECK (true);
--> statement-breakpoint

-- The definer remains NOLOGIN. These are the exact additional projections it
-- needs to freeze ticket facts and to attest public comment provenance.
GRANT SELECT ON TABLE public.tenants, public.ticket_comments,
  public.sla_policies
TO periapsis_sla_worker_owner;
--> statement-breakpoint
CREATE POLICY tenants_sla_event_owner_read_v1
ON public.tenants AS PERMISSIVE FOR SELECT TO periapsis_sla_worker_owner
USING (id = app.context_tenant_id());
--> statement-breakpoint
CREATE POLICY ticket_comments_sla_event_owner_read_v1
ON public.ticket_comments AS PERMISSIVE FOR SELECT
TO periapsis_sla_worker_owner
USING (tenant_id = app.context_tenant_id());
--> statement-breakpoint
CREATE POLICY outbox_events_sla_event_owner_read_v1
ON public.outbox_events AS PERMISSIVE FOR SELECT
TO periapsis_sla_worker_owner
USING (
  tenant_id = app.context_tenant_id()
  AND event_type IN (
    'sla.alert.created', 'sla.case.created',
    'sla.alert.transitioned', 'sla.case.transitioned',
    'sla.alert.assigned', 'sla.case.assigned',
    'sla.alert.claimed', 'sla.case.claimed',
    'sla.alert.released', 'sla.case.released',
    'sla.alert.transferred', 'sla.case.transferred',
    'alert.commented', 'case.commented'
  )
);
--> statement-breakpoint
CREATE POLICY sla_policies_sla_event_owner_read_v1
ON public.sla_policies AS PERMISSIVE FOR SELECT
TO periapsis_sla_worker_owner USING (true);
--> statement-breakpoint
CREATE POLICY audit_events_sla_event_owner_insert_v1
ON public.audit_events AS PERMISSIVE FOR INSERT
TO periapsis_sla_worker_owner
WITH CHECK (
  tenant_id = app.context_tenant_id()
  AND actor_type = 'system'
  AND action IN (
    'tenant.sla.event.ingested',
    'tenant.sla.event.dead_lettered'
  )
);
--> statement-breakpoint

-- The ingress definer may append its machine receipt and read only the fields
-- needed to establish predecessor/replay state. It never receives table-wide
-- ledger privileges or authority over the generated identity column.
REVOKE ALL ON TABLE public.sla_object_event_ledger
FROM periapsis_sla_worker_owner;
--> statement-breakpoint
GRANT SELECT (
  tenant_id, event_id, outcome, sla_instance_id, aggregate_version
) ON TABLE public.sla_object_event_ledger
TO periapsis_sla_worker_owner;
--> statement-breakpoint
GRANT INSERT (
  tenant_id, event_id, object_type, object_id, origin, origin_id,
  key_digest, request_digest, outcome, sla_instance_id,
  aggregate_version, policy_id, policy_version, occurred_at, committed_at
) ON TABLE public.sla_object_event_ledger
TO periapsis_sla_worker_owner;
--> statement-breakpoint
CREATE POLICY sla_object_event_ledger_sla_event_owner_read_v1
ON public.sla_object_event_ledger AS PERMISSIVE FOR SELECT
TO periapsis_sla_worker_owner
USING (
  tenant_id = app.context_tenant_id()
  AND origin = 'ticket_outbox'
  AND event_id = origin_id
);
--> statement-breakpoint
CREATE POLICY sla_object_event_ledger_sla_event_owner_insert_v1
ON public.sla_object_event_ledger AS PERMISSIVE FOR INSERT
TO periapsis_sla_worker_owner
WITH CHECK (
  tenant_id = app.context_tenant_id()
  AND origin = 'ticket_outbox'
  AND event_id = origin_id
);
--> statement-breakpoint

CREATE FUNCTION app.private_guard_sla_object_event_ingress_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'SLA object event ingress is append-only'
      USING ERRCODE = '55000';
  END IF;
  IF ROW(
       NEW.id, NEW.tenant_id, NEW.object_type, NEW.object_id,
       NEW.object_sequence, NEW.source_event_id, NEW.source_event_type,
       NEW.source_schema_version, NEW.source_aggregate_version,
       NEW.source_digest, NEW.event_key, NEW.occurred_at,
       NEW.assignment_snapshot, NEW.assignment_snapshot_digest,
       NEW.maximum_attempts, NEW.created_at
     ) IS DISTINCT FROM ROW(
       OLD.id, OLD.tenant_id, OLD.object_type, OLD.object_id,
       OLD.object_sequence, OLD.source_event_id, OLD.source_event_type,
       OLD.source_schema_version, OLD.source_aggregate_version,
       OLD.source_digest, OLD.event_key, OLD.occurred_at,
       OLD.assignment_snapshot, OLD.assignment_snapshot_digest,
       OLD.maximum_attempts, OLD.created_at
     ) OR OLD.status IN ('completed', 'dead_lettered')
     OR NOT (
       OLD.status IN ('queued', 'retry_scheduled') AND NEW.status = 'leased'
       OR OLD.status = 'leased'
         AND NEW.status IN (
           'leased', 'retry_scheduled', 'completed', 'dead_lettered'
         )
     ) THEN
    RAISE EXCEPTION 'SLA object event ingress transition is invalid'
      USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_guard_sla_object_event_ingress_v1()
  OWNER TO periapsis_sla_worker_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_guard_sla_object_event_ingress_v1()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_readiness_owner;
--> statement-breakpoint
CREATE TRIGGER sla_object_event_ingress_guard_v1
BEFORE UPDATE OR DELETE ON public.sla_object_event_ingress
FOR EACH ROW EXECUTE FUNCTION app.private_guard_sla_object_event_ingress_v1();
--> statement-breakpoint

CREATE FUNCTION app.private_sla_event_metric_document_v1(
  p_tenant_id uuid,
  p_metric_definition_id uuid
)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
  SELECT to_jsonb(metric) - 'tenant_id' - 'policy_id'
           - 'policy_version' - 'created_at' - 'definition_digest'
         || jsonb_build_object(
           'definition_digest', encode(metric.definition_digest, 'hex')
         )
  FROM public.sla_metric_definitions AS metric
  WHERE metric.tenant_id = p_tenant_id
    AND metric.id = p_metric_definition_id
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_sla_event_metric_document_v1(uuid, uuid)
  OWNER TO periapsis_sla_worker_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_sla_event_metric_document_v1(uuid, uuid)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_readiness_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_sla_event_configuration_document_v1(
  p_tenant_id uuid,
  p_kind text,
  p_resource_id uuid,
  p_version integer
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
DECLARE document jsonb;
BEGIN
  IF p_tenant_id IS NULL OR p_resource_id IS NULL
     OR p_kind NOT IN ('calendar', 'policy', 'column')
     OR p_version NOT BETWEEN 1 AND 2147483646 THEN
    RAISE EXCEPTION 'SLA event configuration identity is invalid'
      USING ERRCODE = '22023';
  END IF;
  IF p_kind = 'calendar' THEN
    SELECT jsonb_build_object(
      'id', shell.id, 'tenant_id', shell.tenant_id, 'key', shell.key,
      'label', version.label, 'timezone', version.timezone,
      'weekly_schedule', version.weekly_schedule,
      'exceptions', version.exceptions, 'version', version.version,
      'revision_digest', encode(version.revision_digest, 'hex')
    ) INTO document
    FROM public.sla_business_calendars AS shell
    JOIN public.sla_business_calendar_versions AS version
      ON version.tenant_id = shell.tenant_id
     AND version.calendar_id = shell.id
     AND version.version = p_version
    WHERE shell.tenant_id = p_tenant_id AND shell.id = p_resource_id;
  ELSIF p_kind = 'policy' THEN
    SELECT jsonb_build_object(
      'id', shell.id, 'tenant_id', shell.tenant_id, 'key', shell.key,
      'version', version.version, 'name', version.name,
      'description', version.description, 'priority', version.priority,
      'object_types', version.object_types, 'match_rule', version.match_rule,
      'effective_from', version.effective_from,
      'effective_until', version.effective_until, 'enabled', version.enabled,
      'apply_to_sla_engine_source', version.apply_to_sla_engine_source,
      'revision_digest', encode(version.revision_digest, 'hex'),
      'metrics', coalesce((
        SELECT jsonb_agg(
          app.private_sla_event_metric_document_v1(metric.tenant_id, metric.id)
          ORDER BY metric.position, metric.id
        )
        FROM public.sla_metric_definitions AS metric
        WHERE metric.tenant_id = version.tenant_id
          AND metric.policy_id = version.policy_id
          AND metric.policy_version = version.version
      ), '[]'::jsonb),
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
        WHERE trigger_row.tenant_id = version.tenant_id
          AND trigger_row.policy_id = version.policy_id
          AND trigger_row.policy_version = version.version
      ), '[]'::jsonb)
    ) INTO document
    FROM public.sla_policies AS shell
    JOIN public.sla_policy_versions AS version
      ON version.tenant_id = shell.tenant_id
     AND version.policy_id = shell.id
     AND version.version = p_version
    WHERE shell.tenant_id = p_tenant_id AND shell.id = p_resource_id;
  ELSE
    SELECT jsonb_build_object(
      'id', shell.id, 'tenant_id', shell.tenant_id, 'key', shell.key,
      'label', version.label,
      'metric_definition_id', version.metric_definition_id,
      'metric', app.private_sla_event_metric_document_v1(
        version.tenant_id, version.metric_definition_id
      ),
      'calculation', version.calculation, 'format', version.format,
      'sortable', version.sortable, 'filterable', version.filterable,
      'customer_visible', version.customer_visible,
      'visible_role_keys', version.visible_role_keys,
      'position', version.position, 'style_rules', version.style_rules,
      'version', version.version,
      'revision_digest', encode(version.revision_digest, 'hex')
    ) INTO document
    FROM public.sla_columns AS shell
    JOIN public.sla_column_versions AS version
      ON version.tenant_id = shell.tenant_id
     AND version.column_id = shell.id
     AND version.version = p_version
    WHERE shell.tenant_id = p_tenant_id AND shell.id = p_resource_id;
  END IF;
  IF document IS NULL OR pg_column_size(document) > 16777216 THEN
    RAISE EXCEPTION 'SLA event configuration is unavailable or oversized'
      USING ERRCODE = 'P0002';
  END IF;
  RETURN document;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_sla_event_configuration_document_v1(
  uuid, text, uuid, integer
) OWNER TO periapsis_sla_worker_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_sla_event_configuration_document_v1(
  uuid, text, uuid, integer
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_readiness_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_sla_event_assignment_snapshot_v1(
  p_tenant_id uuid,
  p_object_type public.sla_object_type,
  p_object_id uuid,
  p_occurred_at timestamp with time zone,
  p_force_no_policy boolean DEFAULT false
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
DECLARE
  tenant_timezone text;
  base jsonb;
  fact_values jsonb := '[]'::jsonb;
  custom_field record;
  custom_values jsonb;
  policies jsonb := '[]'::jsonb;
  calendars jsonb := '[]'::jsonb;
  columns jsonb := '[]'::jsonb;
  result jsonb;
BEGIN
  IF p_tenant_id IS NULL OR p_object_type NOT IN ('alert', 'case')
     OR p_object_id IS NULL OR p_occurred_at IS NULL
     OR p_occurred_at <> date_trunc('microseconds', p_occurred_at) THEN
    RAISE EXCEPTION 'SLA event assignment snapshot identity is invalid'
      USING ERRCODE = '22023';
  END IF;
  SELECT tenant.timezone INTO tenant_timezone
  FROM public.tenants AS tenant
  WHERE tenant.id = p_tenant_id;
  IF tenant_timezone IS NULL THEN
    RAISE EXCEPTION 'SLA event assignment tenant is unavailable'
      USING ERRCODE = 'P0002';
  END IF;

  IF p_object_type = 'alert' THEN
    SELECT jsonb_build_object(
      'severity', alert.severity, 'priority', alert.priority,
      'category', alert.category, 'source', alert.source,
      'tags', alert.tags, 'assigned_team_id', alert.assigned_team_id,
      'custom_fields', alert.custom_fields,
      'customer_custom_fields', alert.customer_custom_fields
    ) INTO base
    FROM public.alerts AS alert
    WHERE alert.tenant_id = p_tenant_id AND alert.id = p_object_id
      AND alert.deleted_at IS NULL;
  ELSE
    SELECT jsonb_build_object(
      'severity', case_row.severity, 'priority', case_row.priority,
      'category', case_row.category, 'source', 'case',
      'tags', case_row.tags, 'assigned_team_id', case_row.assigned_team_id,
      'custom_fields', case_row.custom_fields,
      'customer_custom_fields', case_row.customer_custom_fields
    ) INTO base
    FROM public.cases AS case_row
    WHERE case_row.tenant_id = p_tenant_id AND case_row.id = p_object_id;
  END IF;
  IF base IS NULL THEN
    RAISE EXCEPTION 'SLA event assignment object is unavailable'
      USING ERRCODE = 'P0002';
  END IF;

  fact_values := fact_values
    || jsonb_build_array(jsonb_build_object(
      'kind', 'severity', 'key', NULL,
      'values', jsonb_build_array(base ->> 'severity')
    ))
    || jsonb_build_array(jsonb_build_object(
      'kind', 'priority', 'key', NULL,
      'values', jsonb_build_array(base ->> 'priority')
    ))
    || jsonb_build_array(jsonb_build_object(
      'kind', 'category', 'key', NULL,
      'values', jsonb_build_array(base ->> 'category')
    ))
    || jsonb_build_array(jsonb_build_object(
      'kind', 'source', 'key', NULL,
      'values', jsonb_build_array(base ->> 'source')
    ));
  IF jsonb_array_length(coalesce(base -> 'tags', '[]'::jsonb)) > 0 THEN
    fact_values := fact_values || jsonb_build_array(jsonb_build_object(
      'kind', 'tag', 'key', NULL, 'values', base -> 'tags'
    ));
  END IF;
  IF base ->> 'assigned_team_id' IS NOT NULL THEN
    fact_values := fact_values || jsonb_build_array(jsonb_build_object(
      'kind', 'operator_team', 'key', NULL,
      'values', jsonb_build_array(base ->> 'assigned_team_id')
    ));
  END IF;
  FOR custom_field IN
    SELECT field.key, field.value
    FROM jsonb_each(
      coalesce(base -> 'customer_custom_fields', '{}'::jsonb)
        || coalesce(base -> 'custom_fields', '{}'::jsonb)
    ) AS field(key, value)
    ORDER BY field.key
  LOOP
    IF jsonb_typeof(custom_field.value) = 'array' THEN
      SELECT coalesce(
        jsonb_agg(element #>> '{}' ORDER BY ordinal), '[]'::jsonb
      ) INTO custom_values
      FROM jsonb_array_elements(custom_field.value)
        WITH ORDINALITY AS item(element, ordinal)
      WHERE jsonb_typeof(element) <> 'null';
    ELSIF jsonb_typeof(custom_field.value) = 'null' THEN
      custom_values := '[]'::jsonb;
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

  IF NOT p_force_no_policy THEN
    SELECT coalesce(jsonb_agg(
      app.private_sla_event_configuration_document_v1(
        shell.tenant_id, 'policy', shell.id, shell.active_version
      ) ORDER BY version.priority DESC, shell.key, shell.id
    ), '[]'::jsonb) INTO policies
    FROM public.sla_policies AS shell
    JOIN public.sla_policy_versions AS version
      ON version.tenant_id = shell.tenant_id
     AND version.policy_id = shell.id
     AND version.version = shell.active_version
    WHERE shell.tenant_id = p_tenant_id AND shell.archived_at IS NULL
      AND version.enabled AND p_object_type = ANY(version.object_types)
      AND version.effective_from <= p_occurred_at
      AND (version.effective_until IS NULL
        OR p_occurred_at < version.effective_until);
    SELECT coalesce(jsonb_agg(
      app.private_sla_event_configuration_document_v1(
        shell.tenant_id, 'calendar', shell.id, shell.active_version
      ) ORDER BY shell.key, shell.id
    ), '[]'::jsonb) INTO calendars
    FROM public.sla_business_calendars AS shell
    WHERE shell.tenant_id = p_tenant_id AND shell.archived_at IS NULL;
    SELECT coalesce(jsonb_agg(
      app.private_sla_event_configuration_document_v1(
        shell.tenant_id, 'column', shell.id, shell.active_version
      ) ORDER BY version.position, shell.key, shell.id
    ), '[]'::jsonb) INTO columns
    FROM public.sla_columns AS shell
    JOIN public.sla_column_versions AS version
      ON version.tenant_id = shell.tenant_id
     AND version.column_id = shell.id
     AND version.version = shell.active_version
    WHERE shell.tenant_id = p_tenant_id AND shell.archived_at IS NULL;
  END IF;
  IF jsonb_array_length(policies) > 512
     OR jsonb_array_length(calendars) > 512
     OR jsonb_array_length(columns) > 256
     OR jsonb_array_length(fact_values) > 256 THEN
    RAISE EXCEPTION 'SLA event assignment inventory is oversized'
      USING ERRCODE = '54000';
  END IF;
  result := jsonb_build_object(
    'facts', jsonb_build_object(
      'tenant_id', p_tenant_id, 'object_type', p_object_type,
      'object_id', p_object_id, 'evaluated_at', p_occurred_at,
      'timezone', tenant_timezone, 'facts', fact_values
    ),
    'policies', policies, 'calendars', calendars, 'columns', columns
  );
  IF pg_column_size(result) > 16777216 THEN
    RAISE EXCEPTION 'SLA event assignment snapshot is oversized'
      USING ERRCODE = '54000';
  END IF;
  RETURN result;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_sla_event_assignment_snapshot_v1(
  uuid, public.sla_object_type, uuid, timestamp with time zone, boolean
) OWNER TO periapsis_sla_worker_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_sla_event_assignment_snapshot_v1(
  uuid, public.sla_object_type, uuid, timestamp with time zone, boolean
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_readiness_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_sla_event_source_digest_v1(
  p_source public.outbox_events,
  p_object_type public.sla_object_type,
  p_object_sequence integer,
  p_event_key text,
  p_source_aggregate_version integer,
  p_assignment_snapshot_digest bytea
)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
SET TimeZone = 'UTC'
AS $function$
  SELECT pg_catalog.sha256(
    pg_catalog.convert_to(
      'periapsis/sla-object-event/source/v1', 'UTF8'
    ) || '\x00'::bytea || pg_catalog.convert_to(jsonb_build_object(
      'id', p_source.id, 'tenant_id', p_source.tenant_id,
      'aggregate_type', p_source.aggregate_type,
      'aggregate_id', p_source.aggregate_id,
      'aggregate_version', p_source.aggregate_version,
      'event_type', p_source.event_type,
      'schema_version', p_source.schema_version,
      'payload', p_source.payload,
      'deduplication_key', p_source.deduplication_key,
      'correlation_id', p_source.correlation_id,
      'causation_id', p_source.causation_id,
      'actor_kind', p_source.actor_kind, 'actor_id', p_source.actor_id,
      'producer', p_source.producer,
      'maximum_audience', p_source.maximum_audience,
      'traceparent', p_source.traceparent,
      'tracestate', p_source.tracestate,
      'occurred_at', p_source.occurred_at,
      'object_type', p_object_type,
      'object_sequence', p_object_sequence,
      'event_key', p_event_key,
      'source_aggregate_version', p_source_aggregate_version,
      'assignment_snapshot_digest', CASE
        WHEN p_assignment_snapshot_digest IS NULL THEN NULL
        ELSE encode(p_assignment_snapshot_digest, 'hex')
      END
    )::text, 'UTF8')
  )
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_sla_event_source_digest_v1(
  public.outbox_events, public.sla_object_type, integer, text, integer, bytea
) OWNER TO periapsis_sla_worker_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_sla_event_source_digest_v1(
  public.outbox_events, public.sla_object_type, integer, text, integer, bytea
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_readiness_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_enqueue_sla_object_event_v1(
  p_source public.outbox_events,
  p_force_no_policy boolean DEFAULT false
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
DECLARE
  mapped_object_type public.sla_object_type;
  mapped_event_key text;
  mapped_version integer;
  mapped_state_key text;
  mapped_terminal boolean;
  comment_row record;
  next_sequence integer;
  snapshot jsonb;
  snapshot_digest bytea;
  source_digest bytea;
  existing public.sla_object_event_ingress%ROWTYPE;
BEGIN
  IF p_source.id IS NULL OR p_source.tenant_id IS NULL
     OR p_source.aggregate_id IS NULL
     OR p_source.aggregate_type NOT IN ('alert', 'case')
     OR jsonb_typeof(p_source.payload) <> 'object' THEN
    RETURN;
  END IF;
  mapped_object_type := p_source.aggregate_type::public.sla_object_type;
  PERFORM set_config('app.tenant_id', p_source.tenant_id::text, true);

  IF p_source.event_type =
       'sla.' || p_source.aggregate_type || '.created'
     AND p_source.schema_version = 1 THEN
    IF p_source.payload ->> (p_source.aggregate_type || '_id')
         IS DISTINCT FROM p_source.aggregate_id::text
       OR p_source.payload ->> 'version' IS NULL THEN
      RAISE EXCEPTION 'SLA create source envelope is invalid'
        USING ERRCODE = '22023';
    END IF;
    mapped_version := (p_source.payload ->> 'version')::integer;
    mapped_event_key := 'ticket.created';
  ELSIF p_source.event_type =
          'sla.' || p_source.aggregate_type || '.transitioned'
        AND p_source.schema_version = 1 THEN
    IF p_source.payload ->> (p_source.aggregate_type || '_id')
         IS DISTINCT FROM p_source.aggregate_id::text
       OR p_source.payload ->> 'version' IS NULL
       OR p_source.payload ->> 'action' IS DISTINCT FROM 'transitioned' THEN
      RAISE EXCEPTION 'SLA transition source envelope is invalid'
        USING ERRCODE = '22023';
    END IF;
    mapped_version := (p_source.payload ->> 'version')::integer;
    IF mapped_object_type = 'alert' THEN
      SELECT alert.state_key, coalesce((state.value ->> 'terminal')::boolean, false)
      INTO mapped_state_key, mapped_terminal
      FROM public.alerts AS alert
      JOIN public.ticket_workflow_versions AS workflow
        ON workflow.tenant_id = alert.tenant_id
       AND workflow.workflow_id = alert.workflow_id
       AND workflow.version = alert.workflow_version
       AND workflow.aggregate_kind = 'alert'
      CROSS JOIN LATERAL jsonb_array_elements(workflow.states) AS state(value)
      WHERE alert.tenant_id = p_source.tenant_id
        AND alert.id = p_source.aggregate_id
        AND alert.deleted_at IS NULL AND alert.version = mapped_version
        AND state.value ->> 'key' = alert.state_key;
    ELSE
      SELECT case_row.state_key,
             coalesce((state.value ->> 'terminal')::boolean, false)
      INTO mapped_state_key, mapped_terminal
      FROM public.cases AS case_row
      JOIN public.ticket_workflow_versions AS workflow
        ON workflow.tenant_id = case_row.tenant_id
       AND workflow.workflow_id = case_row.workflow_id
       AND workflow.version = case_row.workflow_version
       AND workflow.aggregate_kind = 'case'
      CROSS JOIN LATERAL jsonb_array_elements(workflow.states) AS state(value)
      WHERE case_row.tenant_id = p_source.tenant_id
        AND case_row.id = p_source.aggregate_id
        AND case_row.version = mapped_version
        AND state.value ->> 'key' = case_row.state_key;
    END IF;
    IF mapped_state_key IS NULL THEN
      RAISE EXCEPTION 'SLA transition state projection is unavailable'
        USING ERRCODE = 'P0002';
    END IF;
    mapped_event_key := CASE WHEN mapped_terminal THEN 'ticket.resolved'
      ELSE 'ticket.' || mapped_state_key END;
  ELSIF p_source.event_type IN (
          'sla.alert.assigned', 'sla.case.assigned',
          'sla.alert.claimed', 'sla.case.claimed',
          'sla.alert.released', 'sla.case.released',
          'sla.alert.transferred', 'sla.case.transferred'
        )
        AND p_source.schema_version = 1 THEN
    IF p_source.payload ->> (p_source.aggregate_type || '_id')
         IS DISTINCT FROM p_source.aggregate_id::text
       OR p_source.payload ->> 'version' IS NULL
       OR p_source.payload ->> 'action' NOT IN (
         'assigned', 'claimed', 'released', 'transferred'
       )
       OR p_source.event_type IS DISTINCT FROM
            'sla.' || p_source.aggregate_type || '.'
              || (p_source.payload ->> 'action') THEN
      RAISE EXCEPTION 'SLA assignment source envelope is invalid'
        USING ERRCODE = '22023';
    END IF;
    mapped_version := (p_source.payload ->> 'version')::integer;
    mapped_event_key := 'ticket.' || (p_source.payload ->> 'action');
  ELSIF p_source.event_type =
          p_source.aggregate_type || '.commented'
        AND p_source.schema_version = 1 THEN
    IF p_source.payload ->> (p_source.aggregate_type || '_id')
         IS DISTINCT FROM p_source.aggregate_id::text
       OR p_source.payload ->> 'version' IS NULL
       OR p_source.payload ->> 'comment_id' IS NULL
       OR p_source.payload ->> 'comment_revision' IS NULL
       OR (p_source.payload ->> 'content_redacted')::boolean IS NOT TRUE THEN
      RAISE EXCEPTION 'SLA comment source envelope is invalid'
        USING ERRCODE = '22023';
    END IF;
    mapped_version := (p_source.payload ->> 'version')::integer;
    SELECT comment.visibility, comment.origin, comment.revision,
           comment.alert_id, comment.case_id,
           comment.author_membership_id, comment.author_user_id
    INTO comment_row
    FROM public.ticket_comments AS comment
    WHERE comment.tenant_id = p_source.tenant_id
      AND comment.id = (p_source.payload ->> 'comment_id')::uuid
      AND comment.revision =
            (p_source.payload ->> 'comment_revision')::integer
      AND (mapped_object_type = 'alert'
        AND comment.alert_id = p_source.aggregate_id
        OR mapped_object_type = 'case'
        AND comment.case_id = p_source.aggregate_id);
    IF NOT FOUND THEN
      RAISE EXCEPTION 'SLA comment source projection is unavailable'
        USING ERRCODE = 'P0002';
    END IF;
    IF comment_row.visibility <> 'public'
       OR comment_row.origin IN ('system', 'escalation_copy') THEN
      RETURN;
    ELSIF comment_row.origin = 'api'
          AND comment_row.author_membership_id IS NOT NULL
          AND comment_row.author_user_id IS NOT NULL THEN
      mapped_event_key := 'response.first';
    ELSIF comment_row.origin = 'customer_portal' THEN
      mapped_event_key := 'ticket.customer_replied';
    ELSE
      RETURN;
    END IF;
  ELSE
    RETURN;
  END IF;
  IF mapped_version NOT BETWEEN 1 AND 2147483646
     OR p_source.aggregate_version IS NOT NULL
       AND p_source.aggregate_version IS DISTINCT FROM mapped_version
     OR p_source.occurred_at IS NULL
     OR p_source.occurred_at < '1970-01-01 00:00:00+00'::timestamptz
     OR p_source.occurred_at <> date_trunc('microseconds', p_source.occurred_at)
     OR octet_length(mapped_event_key) NOT BETWEEN 2 AND 64
     OR mapped_event_key !~ '^[a-z][a-z0-9_.-]*[a-z0-9]$' THEN
    RAISE EXCEPTION 'SLA mapped event envelope is invalid'
      USING ERRCODE = '22023';
  END IF;

  PERFORM pg_advisory_xact_lock(hashtextextended(
    p_source.tenant_id::text || ':' || mapped_object_type::text
      || ':' || p_source.aggregate_id::text,
    0
  ));
  SELECT ingress.* INTO existing
  FROM public.sla_object_event_ingress AS ingress
  WHERE ingress.tenant_id = p_source.tenant_id
    AND ingress.source_event_id = p_source.id;
  IF FOUND THEN
    source_digest := app.private_sla_event_source_digest_v1(
      p_source, existing.object_type, existing.object_sequence,
      existing.event_key, existing.source_aggregate_version,
      existing.assignment_snapshot_digest
    );
    IF existing.source_digest IS DISTINCT FROM source_digest THEN
      RAISE EXCEPTION 'SLA source event replay conflict'
        USING ERRCODE = '23505';
    END IF;
    RETURN;
  END IF;
  SELECT coalesce(max(ingress.object_sequence), 0) + 1
  INTO next_sequence
  FROM public.sla_object_event_ingress AS ingress
  WHERE ingress.tenant_id = p_source.tenant_id
    AND ingress.object_type = mapped_object_type
    AND ingress.object_id = p_source.aggregate_id;
  IF next_sequence NOT BETWEEN 1 AND 2147483646 THEN
    RAISE EXCEPTION 'SLA object event sequence is exhausted'
      USING ERRCODE = '54000';
  END IF;
  IF next_sequence = 1 AND mapped_event_key = 'ticket.created' THEN
    snapshot := app.private_sla_event_assignment_snapshot_v1(
      p_source.tenant_id, mapped_object_type, p_source.aggregate_id,
      p_source.occurred_at, p_force_no_policy
    );
    snapshot_digest := pg_catalog.sha256(
      pg_catalog.convert_to(
        'periapsis/sla-object-event/assignment-snapshot/v1', 'UTF8'
      ) || '\x00'::bytea
        || pg_catalog.convert_to(snapshot::text, 'UTF8')
    );
  END IF;
  source_digest := app.private_sla_event_source_digest_v1(
    p_source, mapped_object_type, next_sequence, mapped_event_key,
    mapped_version, snapshot_digest
  );
  INSERT INTO public.sla_object_event_ingress (
    id, tenant_id, object_type, object_id, object_sequence,
    source_event_id, source_event_type, source_schema_version,
    source_aggregate_version, source_digest, event_key, occurred_at,
    assignment_snapshot, assignment_snapshot_digest, status, available_at,
    maximum_attempts, created_at, updated_at
  ) VALUES (
    uuidv7(), p_source.tenant_id, mapped_object_type,
    p_source.aggregate_id, next_sequence, p_source.id,
    p_source.event_type, p_source.schema_version, mapped_version,
    source_digest, mapped_event_key, p_source.occurred_at,
    snapshot, snapshot_digest, 'queued', transaction_timestamp(), 12,
    transaction_timestamp(), transaction_timestamp()
  );
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_enqueue_sla_object_event_v1(
  public.outbox_events, boolean
) OWNER TO periapsis_sla_worker_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_enqueue_sla_object_event_v1(
  public.outbox_events, boolean
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_readiness_owner;
--> statement-breakpoint

CREATE FUNCTION app.capture_sla_object_event_ingress_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  PERFORM app.private_enqueue_sla_object_event_v1(
    NEW, coalesce(NEW.producer = 'sla-ingress-cutover', false)
  );
  RETURN NEW;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.capture_sla_object_event_ingress_v1()
  OWNER TO periapsis_sla_worker_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.capture_sla_object_event_ingress_v1()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_readiness_owner;
--> statement-breakpoint
CREATE TRIGGER outbox_events_capture_sla_object_event_ingress_v1
AFTER INSERT ON public.outbox_events
FOR EACH ROW EXECUTE FUNCTION app.capture_sla_object_event_ingress_v1();
--> statement-breakpoint

CREATE FUNCTION app.private_sla_event_state_document_v1(
  p_tenant_id uuid,
  p_sla_instance_id uuid,
  p_expected_aggregate_version integer
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
DECLARE document jsonb;
BEGIN
  SELECT jsonb_build_object(
    'aggregate', jsonb_build_object(
      'id', aggregate_row.id, 'tenant_id', aggregate_row.tenant_id,
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
  ) INTO document
  FROM public.sla_instances AS aggregate_row
  WHERE aggregate_row.tenant_id = p_tenant_id
    AND aggregate_row.id = p_sla_instance_id
    AND aggregate_row.aggregate_version = p_expected_aggregate_version;
  IF document IS NULL
     OR jsonb_array_length(document -> 'metrics') NOT BETWEEN 1 AND 32
     OR pg_column_size(document) > 16777216 THEN
    RAISE EXCEPTION 'SLA object event state is unavailable or stale'
      USING ERRCODE = '40001';
  END IF;
  RETURN document;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_sla_event_state_document_v1(uuid, uuid, integer)
  OWNER TO periapsis_sla_worker_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_sla_event_state_document_v1(
  uuid, uuid, integer
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_readiness_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_append_sla_event_worker_effects_v1(
  p_tenant_id uuid,
  p_job_id uuid,
  p_source_event_id uuid,
  p_action text,
  p_occurred_at timestamp with time zone,
  p_metadata jsonb
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
DECLARE outbox_event_type text;
BEGIN
  IF p_tenant_id IS NULL OR p_job_id IS NULL OR p_source_event_id IS NULL
     OR p_action NOT IN ('ingested', 'dead_lettered')
     OR p_occurred_at IS NULL OR jsonb_typeof(p_metadata) <> 'object'
     OR pg_column_size(p_metadata) > 16384
     OR p_tenant_id IS DISTINCT FROM app.context_tenant_id() THEN
    RAISE EXCEPTION 'SLA object event worker effect is invalid'
      USING ERRCODE = '22023';
  END IF;
  INSERT INTO public.audit_events (
    id, tenant_id, sequence, occurred_at, actor_type, action,
    resource_type, resource_id, authentication_method, outcome,
    before, after, metadata
  ) VALUES (
    uuidv7(), p_tenant_id, 0, p_occurred_at, 'system',
    'tenant.sla.event.' || p_action, 'sla_object_event_ingress', p_job_id,
    'system', CASE WHEN p_action = 'ingested'
      THEN 'success'::public.audit_outcome
      ELSE 'failure'::public.audit_outcome END,
    NULL, NULL, p_metadata || jsonb_build_object(
      'sourceEventId', p_source_event_id, 'contentRedacted', true
    )
  );
  outbox_event_type := 'sla.object_event.' || p_action;
  INSERT INTO public.outbox_events (
    id, tenant_id, aggregate_type, aggregate_id, event_type,
    schema_version, payload, deduplication_key, actor_kind, producer,
    maximum_audience, traceparent, tracestate, occurred_at, available_at
  ) VALUES (
    uuidv7(), p_tenant_id, 'sla_object_event', p_job_id,
    outbox_event_type, 1,
    p_metadata || jsonb_build_object(
      'jobId', p_job_id, 'sourceEventId', p_source_event_id,
      'contentRedacted', true
    ),
    'sla:event-ingress:' || p_job_id::text || ':' || p_action,
    'system', 'sla-event-ingress', 'operator',
    nullif(current_setting('app.traceparent', true), ''),
    nullif(current_setting('app.tracestate', true), ''),
    p_occurred_at, p_occurred_at
  );
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_append_sla_event_worker_effects_v1(
  uuid, uuid, uuid, text, timestamp with time zone, jsonb
) OWNER TO periapsis_sla_worker_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_append_sla_event_worker_effects_v1(
  uuid, uuid, uuid, text, timestamp with time zone, jsonb
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_readiness_owner;
--> statement-breakpoint

CREATE FUNCTION app.claim_sla_object_events_v1(
  p_worker_id uuid,
  p_observed_at timestamp with time zone,
  p_batch_size integer,
  p_lease_micros bigint
)
RETURNS TABLE(
  job_id uuid,
  tenant_id uuid,
  object_type public.sla_object_type,
  object_id uuid,
  object_sequence integer,
  source_event_id uuid,
  source_digest bytea,
  event_key text,
  occurred_at timestamp with time zone,
  state_mode text,
  sla_instance_id uuid,
  aggregate_version integer,
  policy_id uuid,
  policy_version integer,
  fence bigint,
  attempt integer,
  claimed_at timestamp with time zone,
  lease_expires_at timestamp with time zone,
  state_document jsonb
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
DECLARE
  exhausted record;
  claimed record;
  aggregate_row public.sla_instances%ROWTYPE;
  predecessor_outcome public.sla_event_outcome;
  current_source public.outbox_events%ROWTYPE;
  current_digest bytea;
BEGIN
  IF p_worker_id IS NULL
     OR (uuid_extract_version(p_worker_id) = 7) IS NOT TRUE
     OR p_observed_at IS NULL
     OR p_observed_at <> date_trunc('microseconds', p_observed_at)
     OR p_batch_size NOT BETWEEN 1 AND 100
     OR p_lease_micros NOT BETWEEN 1000000 AND 900000000 THEN
    RAISE EXCEPTION 'SLA object event claim is invalid'
      USING ERRCODE = '22023';
  END IF;

  -- A worker can disappear after the last allowed attempt. Terminalize those
  -- expired leases before selecting new work so they cannot remain immortal.
  FOR exhausted IN
    SELECT ingress.*
    FROM public.sla_object_event_ingress AS ingress
    WHERE ingress.status = 'leased'
      AND ingress.lease_expires_at <= p_observed_at
      AND ingress.attempt >= ingress.maximum_attempts
    ORDER BY ingress.lease_expires_at, ingress.tenant_id, ingress.id
    FOR UPDATE SKIP LOCKED
    LIMIT p_batch_size
  LOOP
    PERFORM set_config('app.tenant_id', exhausted.tenant_id::text, true);
    UPDATE public.sla_object_event_ingress AS ingress
    SET status = 'dead_lettered', worker_id = NULL,
        lease_expires_at = NULL, last_failure_code = 'attempts_exhausted',
        dead_lettered_at = p_observed_at, updated_at = p_observed_at
    WHERE ingress.tenant_id = exhausted.tenant_id
      AND ingress.id = exhausted.id;
    PERFORM app.private_append_sla_event_worker_effects_v1(
      exhausted.tenant_id, exhausted.id, exhausted.source_event_id,
      'dead_lettered', p_observed_at,
      jsonb_build_object('failureCode', 'attempts_exhausted')
    );
  END LOOP;

  FOR claimed IN
    WITH candidates AS (
      SELECT ingress.tenant_id, ingress.id
      FROM public.sla_object_event_ingress AS ingress
      WHERE ingress.attempt < ingress.maximum_attempts
        AND (
          ingress.status IN ('queued', 'retry_scheduled')
            AND ingress.available_at <= p_observed_at
          OR ingress.status = 'leased'
            AND ingress.lease_expires_at <= p_observed_at
        )
        AND NOT EXISTS (
          SELECT 1
          FROM public.sla_object_event_ingress AS predecessor
          WHERE predecessor.tenant_id = ingress.tenant_id
            AND predecessor.object_type = ingress.object_type
            AND predecessor.object_id = ingress.object_id
            AND predecessor.object_sequence < ingress.object_sequence
            AND predecessor.status <> 'completed'
        )
      ORDER BY coalesce(ingress.lease_expires_at, ingress.available_at),
               ingress.tenant_id, ingress.object_type,
               ingress.object_id, ingress.object_sequence
      FOR UPDATE SKIP LOCKED
      LIMIT p_batch_size
    ), leased AS (
      UPDATE public.sla_object_event_ingress AS ingress
      SET status = 'leased', worker_id = p_worker_id,
          lease_expires_at = p_observed_at
            + p_lease_micros * interval '1 microsecond',
          attempt = ingress.attempt + 1, fence = ingress.fence + 1,
          updated_at = p_observed_at
      FROM candidates
      WHERE ingress.tenant_id = candidates.tenant_id
        AND ingress.id = candidates.id
      RETURNING ingress.*
    )
    SELECT leased.* FROM leased
    ORDER BY leased.lease_expires_at, leased.tenant_id, leased.id
  LOOP
    PERFORM set_config('app.tenant_id', claimed.tenant_id::text, true);
    SELECT source.* INTO current_source
    FROM public.outbox_events AS source
    WHERE source.tenant_id = claimed.tenant_id
      AND source.id = claimed.source_event_id;
    current_digest := app.private_sla_event_source_digest_v1(
      current_source, claimed.object_type, claimed.object_sequence,
      claimed.event_key, claimed.source_aggregate_version,
      claimed.assignment_snapshot_digest
    );
    SELECT instance.* INTO aggregate_row
    FROM public.sla_instances AS instance
    WHERE instance.tenant_id = claimed.tenant_id
      AND instance.object_type = claimed.object_type
      AND instance.object_id = claimed.object_id;
    predecessor_outcome := NULL;
    IF aggregate_row.id IS NULL AND claimed.object_sequence > 1 THEN
      SELECT ledger.outcome INTO predecessor_outcome
      FROM public.sla_object_event_ingress AS predecessor
      JOIN public.sla_object_event_ledger AS ledger
        ON ledger.tenant_id = predecessor.tenant_id
       AND ledger.event_id = predecessor.source_event_id
      WHERE predecessor.tenant_id = claimed.tenant_id
        AND predecessor.object_type = claimed.object_type
        AND predecessor.object_id = claimed.object_id
        AND predecessor.object_sequence < claimed.object_sequence
        AND predecessor.status = 'completed'
      ORDER BY predecessor.object_sequence DESC
      LIMIT 1;
    END IF;

    job_id := claimed.id;
    tenant_id := claimed.tenant_id;
    object_type := claimed.object_type;
    object_id := claimed.object_id;
    object_sequence := claimed.object_sequence;
    source_event_id := claimed.source_event_id;
    source_digest := claimed.source_digest;
    event_key := claimed.event_key;
    occurred_at := claimed.occurred_at;
    fence := claimed.fence;
    attempt := claimed.attempt;
    claimed_at := p_observed_at;
    lease_expires_at := claimed.lease_expires_at;
    IF aggregate_row.id IS NOT NULL THEN
      state_mode := 'existing';
      sla_instance_id := aggregate_row.id;
      aggregate_version := aggregate_row.aggregate_version;
      policy_id := aggregate_row.policy_id;
      policy_version := aggregate_row.policy_version;
      BEGIN
        state_document := app.private_sla_event_state_document_v1(
          aggregate_row.tenant_id, aggregate_row.id,
          aggregate_row.aggregate_version
        );
      EXCEPTION WHEN OTHERS THEN
        -- Corrupt pinned state is isolated to this fenced event. Returning the
        -- deliberately invalid projection lets the worker use the normal
        -- permanent-failure/dead-letter path without aborting sibling claims.
        state_document := '{}'::jsonb;
      END;
    ELSIF predecessor_outcome = 'no_policy' THEN
      state_mode := 'no_policy';
      sla_instance_id := NULL;
      aggregate_version := 0;
      policy_id := NULL;
      policy_version := 0;
      state_document := NULL;
    ELSE
      state_mode := 'unassigned';
      sla_instance_id := NULL;
      aggregate_version := 0;
      policy_id := NULL;
      policy_version := 0;
      state_document := claimed.assignment_snapshot;
    END IF;
    IF current_source.id IS NULL
       OR current_digest IS DISTINCT FROM claimed.source_digest
       OR state_mode = 'unassigned' AND state_document IS NULL THEN
      state_document := '{}'::jsonb;
    END IF;
    RETURN NEXT;
  END LOOP;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.claim_sla_object_events_v1(
  uuid, timestamp with time zone, integer, bigint
) OWNER TO periapsis_sla_worker_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.claim_sla_object_events_v1(
  uuid, timestamp with time zone, integer, bigint
) FROM PUBLIC, periapsis_migrator, periapsis_api, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_readiness_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.claim_sla_object_events_v1(
  uuid, timestamp with time zone, integer, bigint
) TO periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.claim_sla_evaluation_jobs_v3(
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
SET TimeZone = 'UTC'
AS $function$
BEGIN
  IF p_worker_id IS NULL
     OR (uuid_extract_version(p_worker_id) = 7) IS NOT TRUE
     OR p_observed_at IS NULL
     OR p_observed_at <> date_trunc('microseconds', p_observed_at)
     OR p_batch_size NOT BETWEEN 1 AND 100
     OR p_lease_micros NOT BETWEEN 1000000 AND 300000000 THEN
    RAISE EXCEPTION 'SLA timer claim request is invalid'
      USING ERRCODE = '22023';
  END IF;
  RETURN QUERY
  WITH candidates AS (
    SELECT job.tenant_id, job.id
    FROM public.sla_evaluation_jobs AS job
    JOIN public.sla_instances AS instance
      ON instance.tenant_id = job.tenant_id
     AND instance.id = job.sla_instance_id
    WHERE job.attempt < job.maximum_attempts
      AND (
        job.status IN ('queued', 'retry_scheduled')
          AND job.available_at <= p_observed_at
        OR job.status = 'leased'
          AND job.lease_expires_at <= p_observed_at
      )
      AND NOT EXISTS (
        SELECT 1
        FROM public.sla_object_event_ingress AS ingress
        WHERE ingress.tenant_id = instance.tenant_id
          AND ingress.object_type = instance.object_type
          AND ingress.object_id = instance.object_id
          AND ingress.status <> 'completed'
      )
    ORDER BY coalesce(job.lease_expires_at, job.available_at),
             job.tenant_id, job.id
    FOR UPDATE OF job SKIP LOCKED
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
    app.private_sla_worker_job_document_v2(
      claimed.tenant_id, claimed.sla_instance_id,
      claimed.expected_aggregate_version
    )
  FROM claimed
  ORDER BY claimed.lease_expires_at, claimed.tenant_id, claimed.id;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.claim_sla_evaluation_jobs_v3(
  uuid, timestamp with time zone, integer, bigint
) OWNER TO periapsis_sla_worker_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.claim_sla_evaluation_jobs_v3(
  uuid, timestamp with time zone, integer, bigint
) FROM PUBLIC, periapsis_migrator, periapsis_api, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_readiness_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.claim_sla_evaluation_jobs_v3(
  uuid, timestamp with time zone, integer, bigint
) TO periapsis_worker;
--> statement-breakpoint
-- Preserve the v2 rolling ABI, but make bypassing the ingress barrier
-- impossible for an older worker binary.
CREATE OR REPLACE FUNCTION app.claim_sla_evaluation_jobs_v2(
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
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
  SELECT *
  FROM app.claim_sla_evaluation_jobs_v3(
    p_worker_id, p_observed_at, p_batch_size, p_lease_micros
  )
$function$;
--> statement-breakpoint
ALTER FUNCTION app.claim_sla_evaluation_jobs_v2(
  uuid, timestamp with time zone, integer, bigint
) OWNER TO periapsis_sla_worker_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.claim_sla_evaluation_jobs_v2(
  uuid, timestamp with time zone, integer, bigint
) FROM PUBLIC, periapsis_migrator, periapsis_api, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_readiness_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.claim_sla_evaluation_jobs_v2(
  uuid, timestamp with time zone, integer, bigint
) TO periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.commit_sla_object_event_ingress_v1(
  p_worker_id uuid,
  p_job_id uuid,
  p_tenant_id uuid,
  p_fence bigint,
  p_source_digest bytea,
  p_outcome public.sla_event_outcome,
  p_sla_instance_id uuid,
  p_expected_aggregate_version integer,
  p_next_aggregate_version integer,
  p_policy_id uuid,
  p_policy_version integer,
  p_completed_at timestamp with time zone,
  p_plan jsonb
)
RETURNS TABLE(
  transition text,
  outcome public.sla_event_outcome,
  sla_instance_id uuid,
  aggregate_version integer
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
DECLARE
  ingress public.sla_object_event_ingress%ROWTYPE;
  source public.outbox_events%ROWTYPE;
  aggregate_row public.sla_instances%ROWTYPE;
  replay_outcome public.sla_event_outcome;
  replay_sla_instance_id uuid;
  replay_aggregate_version integer;
  current_source_digest bytea;
  computed_plan_digest bytea;
  computed_receipt_digest bytea;
  next_evaluation_at timestamp with time zone;
  aggregate_completed_at timestamp with time zone;
  predecessor_outcome public.sla_event_outcome;
BEGIN
  IF p_worker_id IS NULL OR (uuid_extract_version(p_worker_id) = 7) IS NOT TRUE
     OR p_job_id IS NULL OR (uuid_extract_version(p_job_id) = 7) IS NOT TRUE
     OR p_tenant_id IS NULL OR p_fence NOT BETWEEN 1 AND 9223372036854775806
     OR octet_length(p_source_digest) <> 32
     OR p_completed_at IS NULL
     OR p_completed_at <> date_trunc('microseconds', p_completed_at)
     OR jsonb_typeof(p_plan) <> 'object'
     OR pg_column_size(p_plan) > 16777216
     OR p_plan - 'metrics' - 'cursors' - 'occurrences' - 'columns'
          - 'next_evaluation_at' - 'aggregate_completed_at' <> '{}'::jsonb
     OR jsonb_typeof(p_plan -> 'metrics') <> 'array'
     OR jsonb_array_length(p_plan -> 'metrics') > 32
     OR jsonb_typeof(p_plan -> 'cursors') <> 'array'
     OR jsonb_array_length(p_plan -> 'cursors') > 8192
     OR jsonb_typeof(p_plan -> 'occurrences') <> 'array'
     OR jsonb_array_length(p_plan -> 'occurrences') > 8192
     OR jsonb_typeof(p_plan -> 'columns') <> 'array'
     OR jsonb_array_length(p_plan -> 'columns') > 8192
     OR NOT (
       p_outcome = 'no_policy' AND p_sla_instance_id IS NULL
         AND p_expected_aggregate_version = 0
         AND p_next_aggregate_version = 0
         AND p_policy_id IS NULL AND p_policy_version = 0
       OR p_outcome = 'assigned' AND p_sla_instance_id IS NOT NULL
         AND (uuid_extract_version(p_sla_instance_id) = 7) IS TRUE
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
    RAISE EXCEPTION 'SLA object event commit is invalid'
      USING ERRCODE = '22023';
  END IF;
  BEGIN
    next_evaluation_at := (p_plan ->> 'next_evaluation_at')::timestamptz;
    aggregate_completed_at :=
      (p_plan ->> 'aggregate_completed_at')::timestamptz;
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'SLA object event plan timestamps are invalid'
      USING ERRCODE = '22023';
  END;
  IF next_evaluation_at IS NOT NULL AND (
       next_evaluation_at <> date_trunc('microseconds', next_evaluation_at)
       OR next_evaluation_at < '1970-01-01 00:00:00+00'::timestamptz
     ) OR aggregate_completed_at IS NOT NULL AND (
       aggregate_completed_at < '1970-01-01 00:00:00+00'::timestamptz
       OR aggregate_completed_at <>
            date_trunc('microseconds', aggregate_completed_at)
     ) THEN
    RAISE EXCEPTION 'SLA object event plan timestamps are invalid'
      USING ERRCODE = '22023';
  END IF;
  IF p_outcome = 'no_policy' AND (
       jsonb_array_length(p_plan -> 'metrics') <> 0
       OR jsonb_array_length(p_plan -> 'cursors') <> 0
       OR jsonb_array_length(p_plan -> 'occurrences') <> 0
       OR jsonb_array_length(p_plan -> 'columns') <> 0
       OR next_evaluation_at IS NOT NULL
       OR aggregate_completed_at IS NOT NULL
     ) THEN
    RAISE EXCEPTION 'SLA no-policy plan must be empty'
      USING ERRCODE = '22023';
  END IF;
  computed_plan_digest := pg_catalog.sha256(
    pg_catalog.convert_to('periapsis/sla-object-event/plan/v1', 'UTF8')
      || '\x00'::bytea || pg_catalog.convert_to(p_plan::text, 'UTF8')
  );
  computed_receipt_digest := pg_catalog.sha256(
    pg_catalog.convert_to('periapsis/sla-object-event/receipt/v1', 'UTF8')
      || '\x00'::bytea || pg_catalog.convert_to(jsonb_build_object(
        'worker_id', p_worker_id, 'job_id', p_job_id,
        'tenant_id', p_tenant_id, 'fence', p_fence,
        'source_digest', encode(p_source_digest, 'hex'),
        'outcome', p_outcome, 'sla_instance_id', p_sla_instance_id,
        'expected_aggregate_version', p_expected_aggregate_version,
        'next_aggregate_version', p_next_aggregate_version,
        'policy_id', p_policy_id, 'policy_version', p_policy_version,
        'completed_at', p_completed_at,
        'plan_digest', encode(computed_plan_digest, 'hex')
      )::text, 'UTF8')
  );

  SELECT current_ingress.* INTO ingress
  FROM public.sla_object_event_ingress AS current_ingress
  WHERE current_ingress.tenant_id = p_tenant_id
    AND current_ingress.id = p_job_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'fence_lost'::text, p_outcome,
      p_sla_instance_id, p_next_aggregate_version;
    RETURN;
  END IF;
  PERFORM set_config('app.tenant_id', p_tenant_id::text, true);
  IF ingress.status = 'completed' THEN
    IF ingress.source_digest IS DISTINCT FROM p_source_digest
       OR ingress.plan_digest IS DISTINCT FROM computed_plan_digest
       OR ingress.receipt_digest IS DISTINCT FROM computed_receipt_digest THEN
      RAISE EXCEPTION 'SLA object event receipt replay conflict'
        USING ERRCODE = '23505';
    END IF;
    SELECT ledger.outcome, ledger.sla_instance_id, ledger.aggregate_version
    INTO replay_outcome, replay_sla_instance_id, replay_aggregate_version
    FROM public.sla_object_event_ledger AS ledger
    WHERE ledger.tenant_id = p_tenant_id
      AND ledger.event_id = ingress.source_event_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'SLA object event receipt ledger is unavailable'
        USING ERRCODE = '55000';
    END IF;
    RETURN QUERY SELECT 'replayed'::text, replay_outcome,
      replay_sla_instance_id, replay_aggregate_version;
    RETURN;
  END IF;
  IF ingress.status <> 'leased'
     OR ingress.worker_id IS DISTINCT FROM p_worker_id
     OR ingress.fence IS DISTINCT FROM p_fence
     OR ingress.source_digest IS DISTINCT FROM p_source_digest
     OR p_completed_at < ingress.updated_at
     OR p_completed_at > ingress.lease_expires_at THEN
    RETURN QUERY SELECT 'fence_lost'::text, p_outcome,
      p_sla_instance_id, p_next_aggregate_version;
    RETURN;
  END IF;
  IF EXISTS (
    SELECT 1
    FROM public.sla_object_event_ingress AS predecessor
    WHERE predecessor.tenant_id = ingress.tenant_id
      AND predecessor.object_type = ingress.object_type
      AND predecessor.object_id = ingress.object_id
      AND predecessor.object_sequence < ingress.object_sequence
      AND predecessor.status <> 'completed'
  ) THEN
    RAISE EXCEPTION 'SLA object event predecessor is incomplete'
      USING ERRCODE = '40001';
  END IF;
  SELECT source_row.* INTO source
  FROM public.outbox_events AS source_row
  WHERE source_row.tenant_id = ingress.tenant_id
    AND source_row.id = ingress.source_event_id;
  current_source_digest := app.private_sla_event_source_digest_v1(
    source, ingress.object_type, ingress.object_sequence,
    ingress.event_key, ingress.source_aggregate_version,
    ingress.assignment_snapshot_digest
  );
  IF source.id IS NULL
     OR current_source_digest IS DISTINCT FROM ingress.source_digest THEN
    RAISE EXCEPTION 'SLA object event source attestation failed'
      USING ERRCODE = '23505';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM jsonb_array_elements(p_plan -> 'metrics') AS metric(value)
    WHERE metric.value ->> 'policy_id' IS DISTINCT FROM p_policy_id::text
       OR (metric.value ->> 'policy_version')::integer
            IS DISTINCT FROM p_policy_version
       OR p_outcome = 'updated' AND (
         metric.value ->> 'last_event_id'
           IS DISTINCT FROM ingress.source_event_id::text
         OR metric.value ->> 'last_event_key'
           IS DISTINCT FROM ingress.event_key
         OR (metric.value ->> 'last_event_at')::timestamptz
           IS DISTINCT FROM ingress.occurred_at
       )
       OR p_outcome = 'assigned' AND NOT (
         metric.value ->> 'last_event_id' = ingress.source_event_id::text
           AND metric.value ->> 'last_event_key' = ingress.event_key
           AND (metric.value ->> 'last_event_at')::timestamptz
             = ingress.occurred_at
         OR metric.value ->> 'last_event_id' IS NULL
           AND metric.value ->> 'last_event_key' IS NULL
           AND metric.value ->> 'last_event_at' IS NULL
       )
  ) OR aggregate_completed_at IS NOT NULL
       AND aggregate_completed_at IS DISTINCT FROM ingress.occurred_at THEN
    RAISE EXCEPTION 'SLA object event plan source binding is invalid'
      USING ERRCODE = '22023';
  END IF;

  predecessor_outcome := NULL;
  IF ingress.object_sequence > 1 THEN
    SELECT ledger.outcome INTO predecessor_outcome
    FROM public.sla_object_event_ingress AS predecessor
    JOIN public.sla_object_event_ledger AS ledger
      ON ledger.tenant_id = predecessor.tenant_id
     AND ledger.event_id = predecessor.source_event_id
    WHERE predecessor.tenant_id = ingress.tenant_id
      AND predecessor.object_type = ingress.object_type
      AND predecessor.object_id = ingress.object_id
      AND predecessor.object_sequence < ingress.object_sequence
      AND predecessor.status = 'completed'
    ORDER BY predecessor.object_sequence DESC
    LIMIT 1;
  END IF;
  IF p_outcome = 'assigned' THEN
    IF ingress.assignment_snapshot IS NULL
       OR NOT EXISTS (
         SELECT 1
         FROM jsonb_array_elements(
           ingress.assignment_snapshot -> 'policies'
         ) AS policy(value)
         WHERE policy.value ->> 'id' = p_policy_id::text
           AND (policy.value ->> 'version')::integer = p_policy_version
       ) OR jsonb_array_length(p_plan -> 'metrics') IS DISTINCT FROM (
         SELECT count(*)::integer
         FROM public.sla_metric_definitions AS definition
         WHERE definition.tenant_id = p_tenant_id
           AND definition.policy_id = p_policy_id
           AND definition.policy_version = p_policy_version
       ) OR EXISTS (
         SELECT 1 FROM public.sla_instances AS instance
         WHERE instance.tenant_id = p_tenant_id
           AND instance.object_type = ingress.object_type
           AND instance.object_id = ingress.object_id
       ) THEN
      RAISE EXCEPTION 'SLA event assignment precondition failed'
        USING ERRCODE = '40001';
    END IF;
    INSERT INTO public.sla_instances (
      id, tenant_id, object_type, object_id, policy_id, policy_version,
      aggregate_version, assignment_event_id, created_at, updated_at
    ) VALUES (
      p_sla_instance_id, p_tenant_id, ingress.object_type,
      ingress.object_id, p_policy_id, p_policy_version, 1,
      ingress.source_event_id, ingress.occurred_at, ingress.occurred_at
    );
    PERFORM app.private_apply_sla_runtime_plan_v1(
      p_tenant_id, p_sla_instance_id, ingress.object_type,
      ingress.object_id, p_plan, ingress.occurred_at
    );
  ELSIF p_outcome = 'updated' THEN
    SELECT instance.* INTO aggregate_row
    FROM public.sla_instances AS instance
    WHERE instance.tenant_id = p_tenant_id
      AND instance.id = p_sla_instance_id
    FOR UPDATE;
    IF NOT FOUND OR aggregate_row.object_type IS DISTINCT FROM ingress.object_type
       OR aggregate_row.object_id IS DISTINCT FROM ingress.object_id
       OR aggregate_row.policy_id IS DISTINCT FROM p_policy_id
       OR aggregate_row.policy_version IS DISTINCT FROM p_policy_version
       OR aggregate_row.aggregate_version IS DISTINCT FROM
            p_expected_aggregate_version
       OR ingress.occurred_at < aggregate_row.updated_at THEN
      RAISE EXCEPTION 'SLA event aggregate precondition failed'
        USING ERRCODE = '40001';
    END IF;
    UPDATE public.sla_instances AS instance
    SET aggregate_version = p_next_aggregate_version,
        updated_at = ingress.occurred_at,
        completed_at = coalesce(instance.completed_at, aggregate_completed_at)
    WHERE instance.tenant_id = p_tenant_id
      AND instance.id = p_sla_instance_id;
    PERFORM app.private_apply_sla_runtime_plan_v1(
      p_tenant_id, p_sla_instance_id, ingress.object_type,
      ingress.object_id, p_plan, ingress.occurred_at
    );
  ELSE
    IF EXISTS (
         SELECT 1 FROM public.sla_instances AS instance
         WHERE instance.tenant_id = p_tenant_id
           AND instance.object_type = ingress.object_type
           AND instance.object_id = ingress.object_id
       ) OR NOT (
         ingress.object_sequence = 1
           AND ingress.assignment_snapshot IS NOT NULL
         OR ingress.object_sequence > 1
           AND predecessor_outcome = 'no_policy'
       ) THEN
      RAISE EXCEPTION 'SLA no-policy precondition failed'
        USING ERRCODE = '40001';
    END IF;
  END IF;

  IF p_outcome <> 'no_policy' THEN
    IF next_evaluation_at IS NOT NULL THEN
      PERFORM app.private_upsert_sla_evaluation_job_v1(
        p_tenant_id, p_sla_instance_id, p_next_aggregate_version,
        next_evaluation_at, 12
      );
    ELSE
      IF EXISTS (
        SELECT 1 FROM public.sla_evaluation_jobs AS job
        WHERE job.tenant_id = p_tenant_id
          AND job.sla_instance_id = p_sla_instance_id
          AND job.status = 'leased'
      ) THEN
        RAISE EXCEPTION 'leased SLA timer cannot be superseded'
          USING ERRCODE = '40001';
      END IF;
      UPDATE public.sla_evaluation_jobs AS job
      SET status = 'completed', worker_id = NULL,
          lease_expires_at = NULL, completed_at = p_completed_at,
          last_failure_code = NULL, updated_at = p_completed_at
      WHERE job.tenant_id = p_tenant_id
        AND job.sla_instance_id = p_sla_instance_id
        AND job.status IN ('queued', 'retry_scheduled');
    END IF;
  END IF;
  INSERT INTO public.sla_object_event_ledger (
    tenant_id, event_id, object_type, object_id, origin, origin_id,
    key_digest, request_digest, outcome, sla_instance_id,
    aggregate_version, policy_id, policy_version, occurred_at, committed_at
  ) VALUES (
    p_tenant_id, ingress.source_event_id, ingress.object_type,
    ingress.object_id, 'ticket_outbox', ingress.source_event_id,
    ingress.source_digest, computed_plan_digest, p_outcome,
    p_sla_instance_id, p_next_aggregate_version, p_policy_id,
    p_policy_version, ingress.occurred_at, p_completed_at
  );
  PERFORM app.private_append_sla_event_worker_effects_v1(
    p_tenant_id, ingress.id, ingress.source_event_id, 'ingested',
    p_completed_at,
    jsonb_build_object(
      'objectType', ingress.object_type,
      'objectId', ingress.object_id,
      'objectSequence', ingress.object_sequence,
      'eventKey', ingress.event_key, 'outcome', p_outcome,
      'slaInstanceId', p_sla_instance_id,
      'aggregateVersion', p_next_aggregate_version,
      'policyId', p_policy_id, 'policyVersion', p_policy_version,
      'planDigest', encode(computed_plan_digest, 'hex')
    )
  );
  UPDATE public.sla_object_event_ingress AS current_ingress
  SET status = 'completed', worker_id = NULL, lease_expires_at = NULL,
      completed_at = p_completed_at, last_failure_code = NULL,
      plan_digest = computed_plan_digest,
      receipt_digest = computed_receipt_digest,
      updated_at = p_completed_at
  WHERE current_ingress.tenant_id = p_tenant_id
    AND current_ingress.id = p_job_id;
  RETURN QUERY SELECT 'applied'::text, p_outcome,
    p_sla_instance_id, p_next_aggregate_version;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.commit_sla_object_event_ingress_v1(
  uuid, uuid, uuid, bigint, bytea, public.sla_event_outcome,
  uuid, integer, integer, uuid, integer, timestamp with time zone, jsonb
) OWNER TO periapsis_sla_worker_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.commit_sla_object_event_ingress_v1(
  uuid, uuid, uuid, bigint, bytea, public.sla_event_outcome,
  uuid, integer, integer, uuid, integer, timestamp with time zone, jsonb
) FROM PUBLIC, periapsis_migrator, periapsis_api, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_readiness_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.commit_sla_object_event_ingress_v1(
  uuid, uuid, uuid, bigint, bytea, public.sla_event_outcome,
  uuid, integer, integer, uuid, integer, timestamp with time zone, jsonb
) TO periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.fail_sla_object_event_ingress_v1(
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
RETURNS text
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
DECLARE ingress public.sla_object_event_ingress%ROWTYPE;
  terminal boolean;
BEGIN
  IF p_worker_id IS NULL OR (uuid_extract_version(p_worker_id) = 7) IS NOT TRUE
     OR p_job_id IS NULL OR (uuid_extract_version(p_job_id) = 7) IS NOT TRUE
     OR p_tenant_id IS NULL OR p_fence NOT BETWEEN 1 AND 9223372036854775806
     OR p_attempt NOT BETWEEN 1 AND 65535
     OR p_failure_code !~ '^[a-z][a-z0-9_.-]{0,127}$'
     OR p_permanent IS NULL OR p_failed_at IS NULL
     OR p_failed_at <> date_trunc('microseconds', p_failed_at)
     OR p_permanent AND p_retry_at IS NOT NULL
     OR NOT p_permanent AND (
       p_retry_at IS NULL OR p_retry_at <= p_failed_at
       OR p_retry_at > p_failed_at + interval '24 hours'
       OR p_retry_at <> date_trunc('microseconds', p_retry_at)
     ) THEN
    RAISE EXCEPTION 'SLA object event failure is invalid'
      USING ERRCODE = '22023';
  END IF;
  SELECT current_ingress.* INTO ingress
  FROM public.sla_object_event_ingress AS current_ingress
  WHERE current_ingress.tenant_id = p_tenant_id
    AND current_ingress.id = p_job_id
  FOR UPDATE;
  IF NOT FOUND OR ingress.status <> 'leased'
     OR ingress.worker_id IS DISTINCT FROM p_worker_id
     OR ingress.fence IS DISTINCT FROM p_fence
     OR ingress.attempt IS DISTINCT FROM p_attempt
     OR p_failed_at < ingress.updated_at
     OR p_failed_at > ingress.lease_expires_at THEN
    RETURN 'fence_lost';
  END IF;
  PERFORM set_config('app.tenant_id', p_tenant_id::text, true);
  terminal := p_permanent OR ingress.attempt >= ingress.maximum_attempts;
  IF terminal THEN
    UPDATE public.sla_object_event_ingress AS current_ingress
    SET status = 'dead_lettered', worker_id = NULL,
        lease_expires_at = NULL, last_failure_code = p_failure_code,
        dead_lettered_at = p_failed_at, updated_at = p_failed_at
    WHERE current_ingress.tenant_id = p_tenant_id
      AND current_ingress.id = p_job_id;
    PERFORM app.private_append_sla_event_worker_effects_v1(
      p_tenant_id, ingress.id, ingress.source_event_id,
      'dead_lettered', p_failed_at,
      jsonb_build_object(
        'failureCode', p_failure_code, 'attempt', p_attempt,
        'permanent', p_permanent
      )
    );
    RETURN 'dead_lettered';
  END IF;
  UPDATE public.sla_object_event_ingress AS current_ingress
  SET status = 'retry_scheduled', worker_id = NULL,
      lease_expires_at = NULL, last_failure_code = p_failure_code,
      available_at = p_retry_at, updated_at = p_failed_at
  WHERE current_ingress.tenant_id = p_tenant_id
    AND current_ingress.id = p_job_id;
  RETURN 'retry_scheduled';
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.fail_sla_object_event_ingress_v1(
  uuid, uuid, uuid, bigint, integer, text, boolean,
  timestamp with time zone, timestamp with time zone
) OWNER TO periapsis_sla_worker_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.fail_sla_object_event_ingress_v1(
  uuid, uuid, uuid, bigint, integer, text, boolean,
  timestamp with time zone, timestamp with time zone
) FROM PUBLIC, periapsis_migrator, periapsis_api, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_readiness_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.fail_sla_object_event_ingress_v1(
  uuid, uuid, uuid, bigint, integer, text, boolean,
  timestamp with time zone, timestamp with time zone
) TO periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.read_sla_object_event_ingress_queue_metrics_v1()
RETURNS TABLE(
  observed_at timestamp with time zone,
  pending_events bigint,
  reclaimable_events bigint,
  dead_lettered_events bigint,
  oldest_pending_micros bigint
)
LANGUAGE sql
VOLATILE
ROWS 1
SECURITY DEFINER
SET search_path = pg_catalog, public
SET TimeZone = 'UTC'
AS $function$
  WITH observed AS MATERIALIZED (
    SELECT date_trunc('microseconds', clock_timestamp()) AS observed_at
  ), eligible AS (
    SELECT ingress.available_at AS ready_at, false AS reclaimable
    FROM public.sla_object_event_ingress AS ingress
    CROSS JOIN observed
    WHERE ingress.status IN ('queued', 'retry_scheduled')
      AND ingress.available_at <= observed.observed_at
    UNION ALL
    SELECT ingress.lease_expires_at AS ready_at, true AS reclaimable
    FROM public.sla_object_event_ingress AS ingress
    CROSS JOIN observed
    WHERE ingress.status = 'leased'
      AND ingress.lease_expires_at <= observed.observed_at
  ), queue AS (
    SELECT count(*)::bigint AS pending_events,
           count(*) FILTER (WHERE eligible.reclaimable)::bigint
             AS reclaimable_events,
           min(eligible.ready_at) AS oldest_ready_at
    FROM eligible
  ), dead_letters AS (
    SELECT count(*)::bigint AS dead_lettered_events
    FROM public.sla_object_event_ingress AS ingress
    WHERE ingress.status = 'dead_lettered'
  )
  SELECT observed.observed_at, queue.pending_events,
         queue.reclaimable_events, dead_letters.dead_lettered_events,
         CASE WHEN queue.oldest_ready_at IS NULL THEN 0::bigint
           ELSE greatest(0::bigint, floor(extract(epoch FROM
             observed.observed_at - queue.oldest_ready_at
           ) * 1000000)::bigint) END
  FROM observed CROSS JOIN queue CROSS JOIN dead_letters
$function$;
--> statement-breakpoint
ALTER FUNCTION app.read_sla_object_event_ingress_queue_metrics_v1()
  OWNER TO periapsis_sla_worker_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.read_sla_object_event_ingress_queue_metrics_v1()
FROM PUBLIC, periapsis_migrator, periapsis_api, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_readiness_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.read_sla_object_event_ingress_queue_metrics_v1()
TO periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.sla_object_event_ingress_schema_readiness_v1()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE ingress_table regclass;
  ledger_table regclass;
  expected_function regprocedure;
  expected_role record;
  runtime_role text;
  table_privilege text;
  ledger_column text;
  required_ledger_insert_columns text[] := ARRAY[
    'tenant_id', 'event_id', 'object_type', 'object_id', 'origin',
    'origin_id', 'key_digest', 'request_digest', 'outcome',
    'sla_instance_id', 'aggregate_version', 'policy_id', 'policy_version',
    'occurred_at', 'committed_at'
  ];
  required_ledger_select_columns text[] := ARRAY[
    'tenant_id', 'event_id', 'outcome', 'sla_instance_id',
    'aggregate_version'
  ];
BEGIN
  ingress_table := to_regclass('public.sla_object_event_ingress');
  ledger_table := to_regclass('public.sla_object_event_ledger');
  IF ingress_table IS NULL OR NOT EXISTS (
    SELECT 1 FROM pg_class AS relation
    WHERE relation.oid = ingress_table
      AND relation.relrowsecurity AND relation.relforcerowsecurity
      AND pg_get_userbyid(relation.relowner) = 'periapsis_migrator'
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_trigger AS trigger_row
    WHERE trigger_row.tgrelid = 'public.outbox_events'::regclass
      AND trigger_row.tgname =
            'outbox_events_capture_sla_object_event_ingress_v1'
      AND trigger_row.tgenabled = 'O' AND NOT trigger_row.tgisinternal
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_trigger AS trigger_row
    WHERE trigger_row.tgrelid = ingress_table
      AND trigger_row.tgname = 'sla_object_event_ingress_guard_v1'
      AND trigger_row.tgenabled = 'O' AND NOT trigger_row.tgisinternal
  ) THEN
    RETURN false;
  END IF;
  SELECT role.rolcanlogin, role.rolsuper, role.rolbypassrls,
         role.rolinherit
  INTO expected_role
  FROM pg_roles AS role
  WHERE role.rolname = 'periapsis_sla_worker_owner';
  IF NOT FOUND OR expected_role.rolcanlogin OR expected_role.rolsuper
     OR expected_role.rolbypassrls OR expected_role.rolinherit THEN
    RETURN false;
  END IF;
  IF pg_has_role(
       'periapsis_worker', 'periapsis_sla_worker_owner', 'MEMBER'
     ) THEN
    RETURN false;
  END IF;
  IF ledger_table IS NULL THEN
    RETURN false;
  END IF;
  FOREACH table_privilege IN ARRAY ARRAY[
    'SELECT', 'INSERT', 'UPDATE', 'DELETE',
    'TRUNCATE', 'REFERENCES', 'TRIGGER'
  ] LOOP
    IF has_table_privilege(
      'periapsis_sla_worker_owner', ledger_table, table_privilege
    ) THEN
      RETURN false;
    END IF;
  END LOOP;
  FOREACH ledger_column IN ARRAY required_ledger_insert_columns LOOP
    IF NOT has_column_privilege(
      'periapsis_sla_worker_owner', ledger_table, ledger_column, 'INSERT'
    ) THEN
      RETURN false;
    END IF;
  END LOOP;
  IF EXISTS (
    SELECT 1
    FROM pg_attribute AS attribute
    WHERE attribute.attrelid = ledger_table
      AND attribute.attnum > 0 AND NOT attribute.attisdropped
      AND NOT (attribute.attname = ANY(required_ledger_insert_columns))
      AND has_column_privilege(
        'periapsis_sla_worker_owner', ledger_table,
        attribute.attname, 'INSERT'
      )
  ) THEN
    RETURN false;
  END IF;
  FOREACH ledger_column IN ARRAY required_ledger_select_columns LOOP
    IF NOT has_column_privilege(
      'periapsis_sla_worker_owner', ledger_table, ledger_column, 'SELECT'
    ) THEN
      RETURN false;
    END IF;
  END LOOP;
  IF EXISTS (
    SELECT 1
    FROM pg_attribute AS attribute
    WHERE attribute.attrelid = ledger_table
      AND attribute.attnum > 0 AND NOT attribute.attisdropped
      AND NOT (attribute.attname = ANY(required_ledger_select_columns))
      AND has_column_privilege(
        'periapsis_sla_worker_owner', ledger_table,
        attribute.attname, 'SELECT'
      )
  ) OR NOT EXISTS (
    SELECT 1
    FROM pg_policy AS policy
    WHERE policy.polrelid = ledger_table
      AND policy.polname =
            'sla_object_event_ledger_sla_event_owner_read_v1'
      AND policy.polcmd = 'r'
      AND policy.polroles =
            ARRAY['periapsis_sla_worker_owner'::regrole]::oid[]
      AND replace(
            pg_get_expr(policy.polqual, policy.polrelid), 'app.', ''
          ) LIKE '%tenant_id = context_tenant_id()%'
      AND pg_get_expr(policy.polqual, policy.polrelid)
            LIKE '%origin = ''ticket_outbox''::text%'
      AND pg_get_expr(policy.polqual, policy.polrelid)
            LIKE '%event_id = origin_id%'
  ) OR NOT EXISTS (
    SELECT 1
    FROM pg_policy AS policy
    WHERE policy.polrelid = ledger_table
      AND policy.polname =
            'sla_object_event_ledger_sla_event_owner_insert_v1'
      AND policy.polcmd = 'a'
      AND policy.polroles =
            ARRAY['periapsis_sla_worker_owner'::regrole]::oid[]
      AND replace(
            pg_get_expr(policy.polwithcheck, policy.polrelid), 'app.', ''
          ) LIKE '%tenant_id = context_tenant_id()%'
      AND pg_get_expr(policy.polwithcheck, policy.polrelid)
            LIKE '%origin = ''ticket_outbox''::text%'
      AND pg_get_expr(policy.polwithcheck, policy.polrelid)
            LIKE '%event_id = origin_id%'
  ) THEN
    RETURN false;
  END IF;
  FOREACH runtime_role IN ARRAY ARRAY[
    'periapsis_worker', 'periapsis_api',
    'periapsis_notifier', 'periapsis_auditor'
  ] LOOP
    FOREACH table_privilege IN ARRAY ARRAY[
      'SELECT', 'INSERT', 'UPDATE', 'DELETE',
      'TRUNCATE', 'REFERENCES', 'TRIGGER'
    ] LOOP
      IF has_table_privilege(
           runtime_role, ingress_table, table_privilege
         ) THEN
        RETURN false;
      END IF;
    END LOOP;
  END LOOP;
  FOREACH expected_function IN ARRAY ARRAY[
    'app.claim_sla_object_events_v1(uuid,timestamp with time zone,integer,bigint)'::regprocedure,
    'app.commit_sla_object_event_ingress_v1(uuid,uuid,uuid,bigint,bytea,public.sla_event_outcome,uuid,integer,integer,uuid,integer,timestamp with time zone,jsonb)'::regprocedure,
    'app.fail_sla_object_event_ingress_v1(uuid,uuid,uuid,bigint,integer,text,boolean,timestamp with time zone,timestamp with time zone)'::regprocedure,
    'app.read_sla_object_event_ingress_queue_metrics_v1()'::regprocedure,
    'app.claim_sla_evaluation_jobs_v3(uuid,timestamp with time zone,integer,bigint)'::regprocedure,
    'app.claim_sla_evaluation_jobs_v2(uuid,timestamp with time zone,integer,bigint)'::regprocedure
  ] LOOP
    IF pg_get_userbyid(
         (SELECT procedure.proowner FROM pg_proc AS procedure
          WHERE procedure.oid = expected_function)
       ) IS DISTINCT FROM 'periapsis_sla_worker_owner'
       OR NOT has_function_privilege(
         'periapsis_worker', expected_function, 'EXECUTE'
       ) THEN
      RETURN false;
    END IF;
  END LOOP;
  IF pg_get_functiondef(
       'app.claim_sla_evaluation_jobs_v2(uuid,timestamp with time zone,integer,bigint)'::regprocedure
     ) NOT LIKE '%claim_sla_evaluation_jobs_v3%' THEN
    RETURN false;
  END IF;
  RETURN true;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.sla_object_event_ingress_schema_readiness_v1()
  OWNER TO periapsis_sla_readiness_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.sla_object_event_ingress_schema_readiness_v1()
FROM PUBLIC, periapsis_migrator, periapsis_api, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.sla_object_event_ingress_schema_readiness_v1()
TO periapsis_worker;
--> statement-breakpoint

-- Pre-rollout tickets without an assigned SLA are pinned to an explicit empty
-- creation snapshot. This avoids retroactive assignment from whatever policy
-- happens to be active during deployment. Existing SLA instances need no
-- snapshot: their first future event reads only the already-pinned revisions.
DO $cutover$
DECLARE ticket record;
BEGIN
  FOR ticket IN
    SELECT alert.tenant_id, 'alert'::text AS object_type, alert.id,
           alert.version, alert.created_at, alert.source
    FROM public.alerts AS alert
    WHERE alert.deleted_at IS NULL
      AND NOT EXISTS (
        SELECT 1 FROM public.sla_instances AS instance
        WHERE instance.tenant_id = alert.tenant_id
          AND instance.object_type = 'alert'
          AND instance.object_id = alert.id
      )
    UNION ALL
    SELECT case_row.tenant_id, 'case'::text, case_row.id,
           case_row.version, case_row.created_at, 'case'::text
    FROM public.cases AS case_row
    WHERE NOT EXISTS (
      SELECT 1 FROM public.sla_instances AS instance
      WHERE instance.tenant_id = case_row.tenant_id
        AND instance.object_type = 'case'
        AND instance.object_id = case_row.id
    )
    ORDER BY 1, 2, 3
  LOOP
    PERFORM set_config('app.tenant_id', ticket.tenant_id::text, true);
    INSERT INTO public.outbox_events (
      id, tenant_id, aggregate_type, aggregate_id, aggregate_version,
      event_type, schema_version, payload, deduplication_key,
      actor_kind, producer, maximum_audience, occurred_at, available_at
    ) VALUES (
      uuidv7(), ticket.tenant_id, ticket.object_type, ticket.id,
      ticket.version, 'sla.' || ticket.object_type || '.created', 1,
      jsonb_build_object(
        ticket.object_type || '_id', ticket.id,
        'version', ticket.version, 'action', 'created',
        'source', 'sla-ingress-cutover'
      ),
      'sla:ingress:cutover:' || ticket.object_type || ':' || ticket.id::text,
      'system', 'sla-ingress-cutover', 'operator',
      ticket.created_at, transaction_timestamp()
    ) ON CONFLICT (tenant_id, deduplication_key) DO NOTHING;
  END LOOP;
END;
$cutover$;
--> statement-breakpoint
