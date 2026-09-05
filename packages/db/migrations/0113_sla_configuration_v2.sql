-- Phase 5 SLA configuration ABI v2. The sealed v1 writers remain callable
-- only by the definer owner. Runtime callers receive the complete current
-- representation from the same transaction, including exact replays that
-- have since advanced to a later immutable revision.

CREATE FUNCTION app.private_sla_metric_document_v2(
  p_tenant_id uuid,
  p_metric_definition_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE document jsonb;
BEGIN
  IF p_tenant_id IS NULL OR p_metric_definition_id IS NULL THEN
    RAISE EXCEPTION 'SLA metric document identity is invalid'
      USING ERRCODE = '22023';
  END IF;
  SELECT to_jsonb(metric) - 'tenant_id' - 'policy_id'
           - 'policy_version' - 'created_at' - 'definition_digest'
           || jsonb_build_object(
             'definition_digest', encode(metric.definition_digest, 'hex')
           )
  INTO document
  FROM public.sla_metric_definitions AS metric
  WHERE metric.tenant_id = p_tenant_id
    AND metric.id = p_metric_definition_id;
  IF document IS NULL THEN
    RAISE EXCEPTION 'SLA metric definition not found'
      USING ERRCODE = 'P0002';
  END IF;
  RETURN document;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_sla_metric_document_v2(uuid, uuid)
  OWNER TO periapsis_sla_api_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_sla_metric_document_v2(uuid, uuid)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_sla_configuration_document_v2(
  p_tenant_id uuid,
  p_kind text,
  p_resource_id uuid,
  p_version integer DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE document jsonb;
BEGIN
  IF p_tenant_id IS NULL OR p_resource_id IS NULL
     OR p_kind NOT IN ('calendar', 'policy', 'column')
     OR (p_version IS NOT NULL AND p_version NOT BETWEEN 1 AND 2147483646) THEN
    RAISE EXCEPTION 'SLA configuration document identity is invalid'
      USING ERRCODE = '22023';
  END IF;
  IF p_kind = 'calendar' THEN
    SELECT jsonb_build_object(
      'id', shell.id, 'key', shell.key,
      'resource_version', shell.resource_version,
      'active_version', version.version,
      'archived_at', shell.archived_at,
      'label', version.label, 'timezone', version.timezone,
      'weekly_schedule', version.weekly_schedule,
      'exceptions', version.exceptions,
      'revision_digest', encode(version.revision_digest, 'hex'),
      'created_at', shell.created_at, 'updated_at', shell.updated_at
    ) INTO document
    FROM public.sla_business_calendars AS shell
    JOIN public.sla_business_calendar_versions AS version
      ON version.tenant_id = shell.tenant_id
     AND version.calendar_id = shell.id
     AND version.version = coalesce(p_version, shell.active_version)
    WHERE shell.tenant_id = p_tenant_id AND shell.id = p_resource_id;
  ELSIF p_kind = 'policy' THEN
    SELECT jsonb_build_object(
      'id', shell.id, 'key', shell.key,
      'resource_version', shell.resource_version,
      'active_version', version.version,
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
        SELECT jsonb_agg(
          app.private_sla_metric_document_v2(metric.tenant_id, metric.id)
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
      ), '[]'::jsonb),
      'created_at', shell.created_at, 'updated_at', shell.updated_at
    ) INTO document
    FROM public.sla_policies AS shell
    JOIN public.sla_policy_versions AS version
      ON version.tenant_id = shell.tenant_id
     AND version.policy_id = shell.id
     AND version.version = coalesce(p_version, shell.active_version)
    WHERE shell.tenant_id = p_tenant_id AND shell.id = p_resource_id;
  ELSE
    SELECT jsonb_build_object(
      'id', shell.id, 'key', shell.key,
      'resource_version', shell.resource_version,
      'active_version', version.version,
      'archived_at', shell.archived_at,
      'label', version.label,
      'metric_definition_id', version.metric_definition_id,
      'metric', app.private_sla_metric_document_v2(
        version.tenant_id, version.metric_definition_id
      ),
      'calculation', version.calculation, 'format', version.format,
      'sortable', version.sortable, 'filterable', version.filterable,
      'customer_visible', version.customer_visible,
      'visible_role_keys', version.visible_role_keys,
      'position', version.position, 'style_rules', version.style_rules,
      'revision_digest', encode(version.revision_digest, 'hex'),
      'created_at', shell.created_at, 'updated_at', shell.updated_at
    ) INTO document
    FROM public.sla_columns AS shell
    JOIN public.sla_column_versions AS version
      ON version.tenant_id = shell.tenant_id
     AND version.column_id = shell.id
     AND version.version = coalesce(p_version, shell.active_version)
    WHERE shell.tenant_id = p_tenant_id AND shell.id = p_resource_id;
  END IF;
  IF document IS NULL OR pg_column_size(document) > 16777216 THEN
    RAISE EXCEPTION 'SLA configuration document not found or oversized'
      USING ERRCODE = 'P0002';
  END IF;
  RETURN document;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_sla_configuration_document_v2(
  uuid, text, uuid, integer
) OWNER TO periapsis_sla_api_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_sla_configuration_document_v2(
  uuid, text, uuid, integer
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
--> statement-breakpoint

CREATE FUNCTION app.publish_sla_calendar_v2(
  p_tenant_id uuid, p_calendar_id uuid,
  p_expected_resource_version integer, p_document jsonb,
  p_key_digest bytea, p_request_digest bytea,
  p_request_id uuid, p_correlation_id uuid, p_ip_address inet,
  p_user_agent text, p_authentication_method text
)
RETURNS TABLE(
  resource_id uuid, resource_version integer, active_version integer,
  replayed boolean, document jsonb
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE receipt record;
BEGIN
  SELECT * INTO STRICT receipt FROM app.publish_sla_calendar_v1(
    p_tenant_id, p_calendar_id, p_expected_resource_version, p_document,
    p_key_digest, p_request_digest, p_request_id, p_correlation_id,
    p_ip_address, p_user_agent, p_authentication_method
  );
  RETURN QUERY SELECT receipt.resource_id, receipt.resource_version,
    receipt.active_version, receipt.replayed,
    app.private_sla_configuration_document_v2(
      p_tenant_id, 'calendar', receipt.resource_id, NULL
    );
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.publish_sla_calendar_v2(
  uuid, uuid, integer, jsonb, bytea, bytea, uuid, uuid, inet, text, text
) OWNER TO periapsis_sla_api_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.publish_sla_calendar_v2(
  uuid, uuid, integer, jsonb, bytea, bytea, uuid, uuid, inet, text, text
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor,
  periapsis_audit_reader_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.publish_sla_calendar_v2(
  uuid, uuid, integer, jsonb, bytea, bytea, uuid, uuid, inet, text, text
) TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.publish_sla_policy_v2(
  p_tenant_id uuid, p_policy_id uuid,
  p_expected_resource_version integer, p_document jsonb,
  p_key_digest bytea, p_request_digest bytea,
  p_request_id uuid, p_correlation_id uuid, p_ip_address inet,
  p_user_agent text, p_authentication_method text
)
RETURNS TABLE(
  resource_id uuid, resource_version integer, active_version integer,
  replayed boolean, document jsonb
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE receipt record;
BEGIN
  SELECT * INTO STRICT receipt FROM app.publish_sla_policy_v1(
    p_tenant_id, p_policy_id, p_expected_resource_version, p_document,
    p_key_digest, p_request_digest, p_request_id, p_correlation_id,
    p_ip_address, p_user_agent, p_authentication_method
  );
  RETURN QUERY SELECT receipt.resource_id, receipt.resource_version,
    receipt.active_version, receipt.replayed,
    app.private_sla_configuration_document_v2(
      p_tenant_id, 'policy', receipt.resource_id, NULL
    );
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.publish_sla_policy_v2(
  uuid, uuid, integer, jsonb, bytea, bytea, uuid, uuid, inet, text, text
) OWNER TO periapsis_sla_api_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.publish_sla_policy_v2(
  uuid, uuid, integer, jsonb, bytea, bytea, uuid, uuid, inet, text, text
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor,
  periapsis_audit_reader_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.publish_sla_policy_v2(
  uuid, uuid, integer, jsonb, bytea, bytea, uuid, uuid, inet, text, text
) TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.publish_sla_column_v2(
  p_tenant_id uuid, p_column_id uuid,
  p_expected_resource_version integer, p_document jsonb,
  p_key_digest bytea, p_request_digest bytea,
  p_request_id uuid, p_correlation_id uuid, p_ip_address inet,
  p_user_agent text, p_authentication_method text
)
RETURNS TABLE(
  resource_id uuid, resource_version integer, active_version integer,
  replayed boolean, document jsonb
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE receipt record;
BEGIN
  SELECT * INTO STRICT receipt FROM app.publish_sla_column_v1(
    p_tenant_id, p_column_id, p_expected_resource_version, p_document,
    p_key_digest, p_request_digest, p_request_id, p_correlation_id,
    p_ip_address, p_user_agent, p_authentication_method
  );
  RETURN QUERY SELECT receipt.resource_id, receipt.resource_version,
    receipt.active_version, receipt.replayed,
    app.private_sla_configuration_document_v2(
      p_tenant_id, 'column', receipt.resource_id, NULL
    );
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.publish_sla_column_v2(
  uuid, uuid, integer, jsonb, bytea, bytea, uuid, uuid, inet, text, text
) OWNER TO periapsis_sla_api_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.publish_sla_column_v2(
  uuid, uuid, integer, jsonb, bytea, bytea, uuid, uuid, inet, text, text
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor,
  periapsis_audit_reader_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.publish_sla_column_v2(
  uuid, uuid, integer, jsonb, bytea, bytea, uuid, uuid, inet, text, text
) TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.read_sla_configuration_v2(
  p_tenant_id uuid, p_kind text, p_resource_id uuid DEFAULT NULL,
  p_after_key text DEFAULT NULL, p_after_id uuid DEFAULT NULL,
  p_limit integer DEFAULT 50, p_include_archived boolean DEFAULT false
)
RETURNS TABLE(document jsonb)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE source jsonb;
BEGIN
  FOR source IN SELECT current.document
    FROM app.read_sla_configuration_v1(
      p_tenant_id, p_kind, p_resource_id, p_after_key, p_after_id,
      p_limit, p_include_archived
    ) AS current
  LOOP
    IF p_kind = 'column' THEN
      source := source || jsonb_build_object(
        'metric', app.private_sla_metric_document_v2(
          p_tenant_id, (source ->> 'metric_definition_id')::uuid
        )
      );
    END IF;
    document := source;
    RETURN NEXT;
  END LOOP;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.read_sla_configuration_v2(
  uuid, text, uuid, text, uuid, integer, boolean
) OWNER TO periapsis_sla_api_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.read_sla_configuration_v2(
  uuid, text, uuid, text, uuid, integer, boolean
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor,
  periapsis_audit_reader_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.read_sla_configuration_v2(
  uuid, text, uuid, text, uuid, integer, boolean
) TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.read_sla_configuration_revision_v2(
  p_tenant_id uuid, p_kind text, p_resource_id uuid,
  p_version integer, p_capability text
)
RETURNS TABLE(document jsonb)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_capability NOT IN ('sla.read', 'sla.manage', 'sla.simulate')
     OR NOT app.private_sla_context_allows_v1(
       p_capability, p_tenant_id, NULL, NULL
     ) THEN
    RAISE EXCEPTION 'SLA configuration revision read is forbidden'
      USING ERRCODE = '42501';
  END IF;
  RETURN QUERY SELECT app.private_sla_configuration_document_v2(
    p_tenant_id, p_kind, p_resource_id, p_version
  );
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.read_sla_configuration_revision_v2(
  uuid, text, uuid, integer, text
) OWNER TO periapsis_sla_api_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.read_sla_configuration_revision_v2(
  uuid, text, uuid, integer, text
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor,
  periapsis_audit_reader_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.read_sla_configuration_revision_v2(
  uuid, text, uuid, integer, text
) TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.read_sla_metric_definition_v2(
  p_tenant_id uuid, p_metric_definition_id uuid, p_capability text
)
RETURNS TABLE(document jsonb)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_capability NOT IN ('sla.read', 'sla.manage', 'sla.simulate')
     OR NOT app.private_sla_context_allows_v1(
       p_capability, p_tenant_id, NULL, NULL
     ) THEN
    RAISE EXCEPTION 'SLA metric definition read is forbidden'
      USING ERRCODE = '42501';
  END IF;
  RETURN QUERY SELECT app.private_sla_metric_document_v2(
    p_tenant_id, p_metric_definition_id
  );
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.read_sla_metric_definition_v2(uuid, uuid, text)
  OWNER TO periapsis_sla_api_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.read_sla_metric_definition_v2(uuid, uuid, text)
FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor,
  periapsis_audit_reader_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.read_sla_metric_definition_v2(uuid, uuid, text)
TO periapsis_api;
--> statement-breakpoint

-- v1 is retained as an internal implementation detail for the v2 wrappers.
REVOKE EXECUTE ON FUNCTION app.publish_sla_calendar_v1(
  uuid, uuid, integer, jsonb, bytea, bytea, uuid, uuid, inet, text, text
) FROM periapsis_api;
--> statement-breakpoint
REVOKE EXECUTE ON FUNCTION app.publish_sla_policy_v1(
  uuid, uuid, integer, jsonb, bytea, bytea, uuid, uuid, inet, text, text
) FROM periapsis_api;
--> statement-breakpoint
REVOKE EXECUTE ON FUNCTION app.publish_sla_column_v1(
  uuid, uuid, integer, jsonb, bytea, bytea, uuid, uuid, inet, text, text
) FROM periapsis_api;
--> statement-breakpoint
REVOKE EXECUTE ON FUNCTION app.read_sla_configuration_v1(
  uuid, text, uuid, text, uuid, integer, boolean
) FROM periapsis_api;
