-- Private ticket saved-view ownership, RLS, immutable replay evidence, and
-- catalog/authorization helpers. Public ABI entry points follow separately so
-- rolling binaries never observe a partially installed contract.

ALTER ROLE periapsis_ticket_saved_view_owner
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOLOGIN NOREPLICATION
  NOBYPASSRLS NOINHERIT;
ALTER ROLE periapsis_ticket_saved_view_owner
  SET search_path = pg_catalog, public, app;
GRANT USAGE ON SCHEMA app, public TO periapsis_ticket_saved_view_owner;
GRANT EXECUTE ON FUNCTION app.context_tenant_id(), app.context_user_id(),
  app.current_tenant_membership_id()
TO periapsis_ticket_saved_view_owner;

ALTER TABLE public.ticket_saved_views
  OWNER TO periapsis_ticket_saved_view_owner;
ALTER TABLE public.ticket_saved_view_commands
  OWNER TO periapsis_ticket_saved_view_owner;
ALTER TABLE public.ticket_saved_views FORCE ROW LEVEL SECURITY;
ALTER TABLE public.ticket_saved_view_commands FORCE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE public.ticket_saved_views,
  public.ticket_saved_view_commands
FROM PUBLIC, periapsis_migrator, periapsis_api, periapsis_worker,
  periapsis_notifier, periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_saved_view_exact_keys_v1(
  p_document jsonb,
  p_expected text[]
)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
  SELECT jsonb_typeof(p_document) = 'object'
     AND cardinality(p_expected) = (
       SELECT count(*)::integer FROM jsonb_object_keys(p_document)
     )
     AND NOT EXISTS (
       SELECT 1
       FROM jsonb_object_keys(p_document) AS actual(key)
       WHERE actual.key <> ALL(p_expected)
     )
     AND NOT EXISTS (
       SELECT 1
       FROM unnest(p_expected) AS expected(key)
       WHERE NOT p_document ? expected.key
     );
$function$;
ALTER FUNCTION app.private_ticket_saved_view_exact_keys_v1(jsonb, text[])
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_saved_view_exact_keys_v1(jsonb, text[])
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner;
GRANT EXECUTE ON FUNCTION app.private_ticket_saved_view_exact_keys_v1(
  jsonb, text[]
) TO periapsis_ticket_saved_view_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_saved_view_json_string_v1(p_value text)
RETURNS text
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
  SELECT replace(
           replace(
             replace(
               replace(
                 replace(to_json(p_value)::text, '<', E'\\u003c'),
                 '>', E'\\u003e'
               ),
               '&', E'\\u0026'
             ),
             U&'\2028', E'\\u2028'
           ),
           U&'\2029', E'\\u2029'
         );
$function$;
ALTER FUNCTION app.private_ticket_saved_view_json_string_v1(text)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_saved_view_json_string_v1(text)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_saved_view_uuid_v1(
  p_value text,
  p_allow_empty boolean
)
RETURNS uuid
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
DECLARE
  parsed uuid;
BEGIN
  IF p_allow_empty AND p_value = '' THEN
    RETURN NULL;
  END IF;
  IF p_value IS NULL OR p_value = '' THEN
    RAISE EXCEPTION 'saved-view UUID is required' USING ERRCODE = '22023';
  END IF;
  BEGIN
    parsed := p_value::uuid;
  EXCEPTION WHEN invalid_text_representation THEN
    RAISE EXCEPTION 'saved-view UUID is malformed' USING ERRCODE = '22023';
  END;
  IF parsed::text IS DISTINCT FROM p_value
     OR (uuid_extract_version(parsed) = 7) IS NOT TRUE THEN
    RAISE EXCEPTION 'saved-view UUID is not canonical UUIDv7'
      USING ERRCODE = '22023';
  END IF;
  RETURN parsed;
END;
$function$;
ALTER FUNCTION app.private_ticket_saved_view_uuid_v1(text, boolean)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_saved_view_uuid_v1(text, boolean)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner;
GRANT EXECUTE ON FUNCTION app.private_ticket_saved_view_uuid_v1(
  text, boolean
) TO periapsis_ticket_saved_view_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_saved_view_base64_v1(p_value text)
RETURNS text
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
  SELECT translate(
    encode(convert_to(p_value, 'UTF8'), 'base64'), E'\n=', ''
  );
$function$;
ALTER FUNCTION app.private_ticket_saved_view_base64_v1(text)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_saved_view_base64_v1(text)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner;
GRANT EXECUTE ON FUNCTION app.private_ticket_saved_view_base64_v1(text)
TO periapsis_ticket_saved_view_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_saved_view_decode_base64_v1(p_value text)
RETURNS text
LANGUAGE plpgsql
IMMUTABLE
STRICT
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
DECLARE
  padding integer;
  decoded bytea;
  result text;
BEGIN
  IF octet_length(p_value) NOT BETWEEN 1 AND 349526
     OR p_value !~ '^[A-Za-z0-9+/]+$'
     OR length(p_value) % 4 = 1 THEN
    RAISE EXCEPTION 'saved-view canonical base64 is invalid'
      USING ERRCODE = '22023';
  END IF;
  padding := (4 - length(p_value) % 4) % 4;
  BEGIN
    decoded := decode(p_value || repeat('=', padding), 'base64');
    result := convert_from(decoded, 'UTF8');
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'saved-view canonical base64 is invalid'
      USING ERRCODE = '22023';
  END;
  IF octet_length(result) NOT BETWEEN 1 AND 262144
     OR app.private_ticket_saved_view_base64_v1(result) IS DISTINCT FROM p_value THEN
    RAISE EXCEPTION 'saved-view canonical base64 is not minimal'
      USING ERRCODE = '22023';
  END IF;
  RETURN result;
END;
$function$;
ALTER FUNCTION app.private_ticket_saved_view_decode_base64_v1(text)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_saved_view_decode_base64_v1(text)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner;
GRANT EXECUTE ON FUNCTION app.private_ticket_saved_view_decode_base64_v1(text)
TO periapsis_ticket_saved_view_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_saved_view_assert_authority_v1(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_owner_membership_id uuid,
  p_aggregate_kind public.ticket_aggregate_kind,
  p_lock_authorization boolean
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  current_membership uuid;
  permission_key text;
BEGIN
  IF p_tenant_id IS NULL OR p_actor_user_id IS NULL
     OR p_owner_membership_id IS NULL OR p_aggregate_kind IS NULL
     OR p_lock_authorization IS NULL
     OR p_tenant_id IS DISTINCT FROM app.context_tenant_id()
     OR p_actor_user_id IS DISTINCT FROM app.context_user_id()
     OR (uuid_extract_version(p_tenant_id) = 7) IS NOT TRUE
     OR (uuid_extract_version(p_actor_user_id) = 7) IS NOT TRUE
     OR (uuid_extract_version(p_owner_membership_id) = 7) IS NOT TRUE THEN
    RAISE EXCEPTION 'saved-view authority context is forbidden'
      USING ERRCODE = '42501';
  END IF;
  IF p_lock_authorization THEN
    PERFORM app.lock_current_tenant_authorization_state();
  END IF;
  current_membership := app.current_tenant_membership_id();
  IF current_membership IS DISTINCT FROM p_owner_membership_id
     OR NOT EXISTS (
       SELECT 1
       FROM public.tenants AS tenant
       JOIN public.tenant_memberships AS membership
         ON membership.tenant_id = tenant.id
       JOIN public.users AS identity ON identity.id = membership.user_id
       WHERE tenant.id = p_tenant_id
         AND tenant.status = 'active'
         AND membership.id = p_owner_membership_id
         AND membership.user_id = p_actor_user_id
         AND membership.status = 'active'
         AND identity.active
     ) THEN
    RAISE EXCEPTION 'saved-view owner is not a live human membership'
      USING ERRCODE = '42501';
  END IF;

  -- Operator-route intent is independent of membership.role. An exact active
  -- linked contact is a customer principal for this boundary even if a legacy
  -- or malformed grant graph also carries an operator-looking role label.
  IF EXISTS (
    SELECT 1
    FROM public.customer_contacts AS contact
    WHERE contact.tenant_id = p_tenant_id
      AND contact.linked_membership_id = p_owner_membership_id
      AND contact.linked_user_id = p_actor_user_id
      AND contact.active AND contact.archived_at IS NULL
  ) THEN
    RAISE EXCEPTION 'customer principals cannot use operator saved views'
      USING ERRCODE = '42501';
  END IF;

  permission_key := CASE p_aggregate_kind
    WHEN 'alert' THEN 'alert.read'
    WHEN 'case' THEN 'case.read'
    ELSE NULL
  END;
  IF permission_key IS NULL OR NOT (
       app.current_tenant_human_has_exact_permission_v3(permission_key, 'own')
       OR app.current_tenant_human_has_exact_permission_v3(permission_key, 'assigned')
       OR app.current_tenant_human_has_exact_permission_v3(permission_key, 'operator_team')
       OR app.current_tenant_human_has_exact_permission_v3(permission_key, 'tenant')
     ) THEN
    RAISE EXCEPTION 'live ticket-read capability is required'
      USING ERRCODE = '42501';
  END IF;
END;
$function$;
ALTER FUNCTION app.private_ticket_saved_view_assert_authority_v1(
  uuid, uuid, uuid, public.ticket_aggregate_kind, boolean
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_saved_view_assert_authority_v1(
  uuid, uuid, uuid, public.ticket_aggregate_kind, boolean
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
GRANT EXECUTE ON FUNCTION app.private_ticket_saved_view_assert_authority_v1(
  uuid, uuid, uuid, public.ticket_aggregate_kind, boolean
) TO periapsis_ticket_saved_view_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_saved_view_custom_pin_v1(
  p_tenant_id uuid,
  p_aggregate_kind public.ticket_aggregate_kind,
  p_definition_id uuid,
  p_expected_version bigint,
  p_require_filter boolean,
  p_require_sort boolean
)
RETURNS TABLE(
  definition_key text,
  data_type public.custom_field_data_type,
  digest_hex text
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_tenant_id IS NULL OR p_definition_id IS NULL
     OR p_aggregate_kind IS NULL OR p_expected_version NOT BETWEEN 1 AND 2147483647
     OR p_require_filter IS NULL OR p_require_sort IS NULL
     OR (uuid_extract_version(p_definition_id) = 7) IS NOT TRUE THEN
    RAISE EXCEPTION 'custom-field pin request is invalid'
      USING ERRCODE = '22023';
  END IF;
  RETURN QUERY
  SELECT definition.key, definition.data_type,
         encode(
           pg_catalog.sha256(convert_to(revision.snapshot::text, 'UTF8')),
           'hex'
         )
  FROM public.custom_field_definitions AS definition
  JOIN public.custom_field_definition_revisions AS revision
    ON revision.tenant_id = definition.tenant_id
   AND revision.definition_id = definition.id
   AND revision.schema_version = definition.schema_version
  JOIN public.custom_field_permissions AS permission
    ON permission.tenant_id = definition.tenant_id
   AND permission.definition_id = definition.id
   AND permission.audience = 'operator'
   AND permission.schema_version = definition.schema_version
   AND permission.can_read
  WHERE definition.tenant_id = p_tenant_id
    AND definition.id = p_definition_id
    AND definition.object_type::text = p_aggregate_kind::text
    AND definition.schema_version = p_expected_version
    AND definition.archived_at IS NULL
    AND definition.show_in_list
    AND (NOT p_require_filter OR definition.filterable)
    AND (NOT p_require_sort OR (
      definition.sortable
      AND definition.data_type IN (
        'short_text', 'integer', 'decimal', 'boolean', 'date', 'datetime',
        'duration', 'single_select', 'url', 'email', 'ip', 'cidr', 'user',
        'operator_team', 'customer_contact', 'asset_reference', 'ioc_reference'
      )
    ));
  IF NOT FOUND THEN
    RAISE EXCEPTION 'custom-field pin is stale or hidden'
      USING ERRCODE = '55000';
  END IF;
END;
$function$;
ALTER FUNCTION app.private_ticket_saved_view_custom_pin_v1(
  uuid, public.ticket_aggregate_kind, uuid, bigint, boolean, boolean
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_saved_view_custom_pin_v1(
  uuid, public.ticket_aggregate_kind, uuid, bigint, boolean, boolean
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_saved_view_sla_pin_v1(
  p_tenant_id uuid,
  p_aggregate_kind public.ticket_aggregate_kind,
  p_definition_id uuid,
  p_expected_version integer,
  p_require_sort boolean
)
RETURNS TABLE(
  definition_key text,
  column_format public.sla_column_format,
  digest_hex text
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_tenant_id IS NULL OR p_definition_id IS NULL
     OR p_aggregate_kind IS NULL OR p_expected_version NOT BETWEEN 1 AND 2147483647
     OR p_require_sort IS NULL
     OR (uuid_extract_version(p_definition_id) = 7) IS NOT TRUE THEN
    RAISE EXCEPTION 'SLA pin request is invalid' USING ERRCODE = '22023';
  END IF;
  RETURN QUERY
  SELECT shell.key, version.format, encode(version.revision_digest, 'hex')
  FROM public.sla_columns AS shell
  JOIN public.sla_column_versions AS version
    ON version.tenant_id = shell.tenant_id
   AND version.column_id = shell.id
   AND version.version = shell.active_version
  JOIN public.sla_metric_definitions AS metric
    ON metric.tenant_id = version.tenant_id
   AND metric.id = version.metric_definition_id
  JOIN public.sla_policies AS policy
    ON policy.tenant_id = metric.tenant_id
   AND policy.id = metric.policy_id
   AND policy.active_version = metric.policy_version
   AND policy.archived_at IS NULL
  JOIN public.sla_policy_versions AS policy_version
    ON policy_version.tenant_id = metric.tenant_id
   AND policy_version.policy_id = metric.policy_id
   AND policy_version.version = metric.policy_version
  WHERE shell.tenant_id = p_tenant_id
    AND shell.id = p_definition_id
    AND shell.active_version = p_expected_version
    AND shell.archived_at IS NULL
    AND p_aggregate_kind::public.sla_object_type = ANY(policy_version.object_types)
    AND (NOT p_require_sort OR (
      version.sortable
      AND version.format IN ('datetime', 'duration', 'percentage', 'state_badge')
    ))
    AND (
      cardinality(version.visible_role_keys) = 0
      OR EXISTS (
        SELECT 1
        FROM app.resolve_current_tenant_human_role_grant_paths(201) AS role_path
        WHERE role_path.role_key = ANY(version.visible_role_keys)
      )
    );
  IF NOT FOUND THEN
    RAISE EXCEPTION 'SLA pin is stale or hidden' USING ERRCODE = '55000';
  END IF;
END;
$function$;
ALTER FUNCTION app.private_ticket_saved_view_sla_pin_v1(
  uuid, public.ticket_aggregate_kind, uuid, integer, boolean
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_saved_view_sla_pin_v1(
  uuid, public.ticket_aggregate_kind, uuid, integer, boolean
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_saved_view_canonical_scalar_v1(
  p_tenant_id uuid,
  p_definition_id uuid,
  p_expected_version bigint,
  p_value jsonb
)
RETURNS text
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  definition public.custom_field_definitions%ROWTYPE;
  value_kind text;
  value_text text;
  canonical text;
  number_value numeric;
  integer_value bigint;
  instant timestamp with time zone;
  address inet;
  prefix cidr;
BEGIN
  IF p_tenant_id IS NULL OR p_definition_id IS NULL
     OR p_expected_version NOT BETWEEN 1 AND 2147483647
     OR p_value IS NULL
     OR pg_column_size(p_value) > 196608 THEN
    RAISE EXCEPTION 'saved-view scalar request is invalid'
      USING ERRCODE = '22023';
  END IF;
  SELECT candidate.* INTO definition
  FROM public.custom_field_definitions AS candidate
  WHERE candidate.tenant_id = p_tenant_id
    AND candidate.id = p_definition_id
    AND candidate.schema_version = p_expected_version
    AND candidate.archived_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'saved-view scalar definition is stale'
      USING ERRCODE = '55000';
  END IF;

  value_kind := jsonb_typeof(p_value);
  IF value_kind NOT IN ('string', 'number', 'boolean') THEN
    RAISE EXCEPTION 'saved-view equality filter requires a scalar'
      USING ERRCODE = '22023';
  END IF;
  IF value_kind = 'string' THEN
    value_text := p_value #>> '{}';
  ELSE
    value_text := p_value::text;
  END IF;

  CASE
    WHEN definition.data_type IN ('short_text', 'long_text') THEN
      IF value_kind <> 'string'
         OR octet_length(value_text) > (CASE
              WHEN definition.data_type = 'short_text' THEN 1024 ELSE 65536
            END)
         OR btrim(value_text) IS DISTINCT FROM value_text
         OR value_text ~ '[[:cntrl:]\u200e\u200f\u202a-\u202e\u2066-\u2069]'
         OR (definition.minimum_length IS NOT NULL
             AND char_length(value_text) < definition.minimum_length)
         OR (definition.maximum_length IS NOT NULL
             AND char_length(value_text) > definition.maximum_length)
         -- PostgreSQL's backtracking regexp engine is not an acceptable
         -- request-time execution surface for an administrator-authored
         -- pattern. Patterned fields remain queryable inline, but are not
         -- persistable as saved-view equality filters in v1.
         OR definition.validation_pattern IS NOT NULL THEN
        RAISE EXCEPTION 'saved-view text scalar is invalid'
          USING ERRCODE = '22023';
      END IF;
      canonical := app.private_ticket_saved_view_json_string_v1(value_text);

    WHEN definition.data_type IN ('integer', 'duration') THEN
      IF value_kind = 'string' THEN
        canonical := value_text;
      ELSE
        canonical := p_value::text;
      END IF;
      IF octet_length(canonical) > 20
         OR canonical !~ '^-?(0|[1-9][0-9]*)$' THEN
        RAISE EXCEPTION 'saved-view integer scalar is invalid'
          USING ERRCODE = '22023';
      END IF;
      BEGIN
        integer_value := canonical::bigint;
      EXCEPTION WHEN numeric_value_out_of_range OR invalid_text_representation THEN
        RAISE EXCEPTION 'saved-view integer scalar is invalid'
          USING ERRCODE = '22023';
      END;
      IF definition.data_type = 'duration' AND integer_value < 0 THEN
        RAISE EXCEPTION 'saved-view duration scalar is invalid'
          USING ERRCODE = '22023';
      END IF;
      canonical := integer_value::text;
      number_value := integer_value::numeric;

    WHEN definition.data_type = 'decimal' THEN
      canonical := value_text;
      IF octet_length(canonical) > 256
         OR canonical !~ '^-?(0|[1-9][0-9]*)(\.[0-9]+)?$' THEN
        RAISE EXCEPTION 'saved-view decimal scalar is invalid'
          USING ERRCODE = '22023';
      END IF;
      IF position('.' IN canonical) > 0 THEN
        canonical := rtrim(rtrim(canonical, '0'), '.');
      END IF;
      IF canonical = '-0' THEN
        canonical := '0';
      END IF;
      BEGIN
        number_value := canonical::numeric;
      EXCEPTION WHEN numeric_value_out_of_range OR invalid_text_representation THEN
        RAISE EXCEPTION 'saved-view decimal scalar is invalid'
          USING ERRCODE = '22023';
      END;

    WHEN definition.data_type = 'boolean' THEN
      IF value_kind <> 'boolean' THEN
        RAISE EXCEPTION 'saved-view boolean scalar is invalid'
          USING ERRCODE = '22023';
      END IF;
      canonical := value_text;

    WHEN definition.data_type = 'date' THEN
      IF value_kind <> 'string' OR value_text !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$' THEN
        RAISE EXCEPTION 'saved-view date scalar is invalid'
          USING ERRCODE = '22023';
      END IF;
      BEGIN
        IF to_char(value_text::date, 'YYYY-MM-DD') IS DISTINCT FROM value_text THEN
          RAISE EXCEPTION 'saved-view date scalar is not canonical'
            USING ERRCODE = '22023';
        END IF;
      EXCEPTION WHEN datetime_field_overflow OR invalid_datetime_format THEN
        RAISE EXCEPTION 'saved-view date scalar is invalid'
          USING ERRCODE = '22023';
      END;
      canonical := app.private_ticket_saved_view_json_string_v1(value_text);

    WHEN definition.data_type = 'datetime' THEN
      IF value_kind <> 'string'
         OR value_text !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?(Z|[+-][0-9]{2}:[0-9]{2})$' THEN
        RAISE EXCEPTION 'saved-view datetime scalar is invalid'
          USING ERRCODE = '22023';
      END IF;
      BEGIN
        instant := value_text::timestamptz;
      EXCEPTION WHEN datetime_field_overflow OR invalid_datetime_format THEN
        RAISE EXCEPTION 'saved-view datetime scalar is invalid'
          USING ERRCODE = '22023';
      END;
      value_text := to_char(
        instant AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US'
      );
      value_text := rtrim(rtrim(value_text, '0'), '.');
      canonical := app.private_ticket_saved_view_json_string_v1(value_text || 'Z');

    WHEN definition.data_type = 'single_select' THEN
      IF value_kind <> 'string'
         OR value_text !~ '^[a-z][a-z0-9_.-]{0,63}$'
         OR NOT EXISTS (
           SELECT 1
           FROM public.custom_field_options AS option_record
           WHERE option_record.tenant_id = p_tenant_id
             AND option_record.definition_id = p_definition_id
             AND option_record.key = value_text
             AND option_record.introduced_in_schema_version <= p_expected_version
             AND (
               option_record.archived_in_schema_version IS NULL
               OR option_record.archived_in_schema_version > p_expected_version
             )
         ) THEN
        RAISE EXCEPTION 'saved-view option scalar is invalid'
          USING ERRCODE = '22023';
      END IF;
      canonical := app.private_ticket_saved_view_json_string_v1(value_text);

    WHEN definition.data_type = 'email' THEN
      IF value_kind <> 'string' OR octet_length(value_text) > 320
         OR value_text !~ '^[!-~]+@[A-Za-z0-9.-]+$'
         OR split_part(value_text, '@', 1) = ''
         OR split_part(value_text, '@', 2) = ''
         OR value_text IS DISTINCT FROM
              split_part(value_text, '@', 1) || '@' || lower(split_part(value_text, '@', 2)) THEN
        RAISE EXCEPTION 'saved-view email scalar is not canonical'
          USING ERRCODE = '22023';
      END IF;
      canonical := app.private_ticket_saved_view_json_string_v1(value_text);

    WHEN definition.data_type = 'url' THEN
      -- SQL deliberately accepts only the already-canonical safe subset. The
      -- Go resolver may normalize richer IDNA/IPv6 URLs before a future ABI.
      IF value_kind <> 'string' OR octet_length(value_text) > 8192
         OR value_text !~ '^https?://[a-z0-9.-]+(:[1-9][0-9]{0,4})?(/[^[:cntrl:]]*)?$'
         OR value_text ~ '^http://[^/]+:80(/|$)'
         OR value_text ~ '^https://[^/]+:443(/|$)'
         OR definition.validation_pattern IS NOT NULL THEN
        RAISE EXCEPTION 'saved-view URL scalar is not canonical'
          USING ERRCODE = '22023';
      END IF;
      canonical := app.private_ticket_saved_view_json_string_v1(value_text);

    WHEN definition.data_type = 'ip' THEN
      IF value_kind <> 'string' THEN
        RAISE EXCEPTION 'saved-view IP scalar is invalid'
          USING ERRCODE = '22023';
      END IF;
      BEGIN
        address := value_text::inet;
      EXCEPTION WHEN invalid_text_representation THEN
        RAISE EXCEPTION 'saved-view IP scalar is invalid'
          USING ERRCODE = '22023';
      END;
      IF masklen(address) <> (
           CASE family(address) WHEN 4 THEN 32 ELSE 128 END
         )
         OR host(address) IS DISTINCT FROM value_text THEN
        RAISE EXCEPTION 'saved-view IP scalar is not canonical'
          USING ERRCODE = '22023';
      END IF;
      canonical := app.private_ticket_saved_view_json_string_v1(value_text);

    WHEN definition.data_type = 'cidr' THEN
      IF value_kind <> 'string' THEN
        RAISE EXCEPTION 'saved-view CIDR scalar is invalid'
          USING ERRCODE = '22023';
      END IF;
      BEGIN
        prefix := value_text::cidr;
      EXCEPTION WHEN invalid_text_representation THEN
        RAISE EXCEPTION 'saved-view CIDR scalar is invalid'
          USING ERRCODE = '22023';
      END;
      IF prefix::text IS DISTINCT FROM value_text THEN
        RAISE EXCEPTION 'saved-view CIDR scalar is not canonical'
          USING ERRCODE = '22023';
      END IF;
      canonical := app.private_ticket_saved_view_json_string_v1(value_text);

    WHEN definition.data_type IN (
      'user', 'operator_team', 'customer_contact',
      'asset_reference', 'ioc_reference'
    ) THEN
      IF value_kind <> 'string'
         OR app.private_ticket_saved_view_uuid_v1(value_text, false) IS NULL THEN
        RAISE EXCEPTION 'saved-view reference scalar is invalid'
          USING ERRCODE = '22023';
      END IF;
      canonical := app.private_ticket_saved_view_json_string_v1(value_text);

    ELSE
      RAISE EXCEPTION 'saved-view scalar type is unsupported'
        USING ERRCODE = '22023';
  END CASE;

  IF definition.data_type IN ('integer', 'duration', 'decimal')
     AND (
       definition.minimum_number IS NOT NULL
       AND number_value < definition.minimum_number::numeric
       OR definition.maximum_number IS NOT NULL
       AND number_value > definition.maximum_number::numeric
     ) THEN
    RAISE EXCEPTION 'saved-view numeric scalar is outside constraints'
      USING ERRCODE = '22023';
  END IF;
  IF octet_length(canonical) NOT BETWEEN 1 AND 196608 THEN
    RAISE EXCEPTION 'saved-view scalar is too large'
      USING ERRCODE = '22023';
  END IF;
  RETURN canonical;
END;
$function$;
ALTER FUNCTION app.private_ticket_saved_view_canonical_scalar_v1(
  uuid, uuid, bigint, jsonb
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_saved_view_canonical_scalar_v1(
  uuid, uuid, bigint, jsonb
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_resolve_ticket_saved_view_spec_v1(p_request jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  tenant_id uuid;
  actor_id uuid;
  owner_membership_id uuid;
  aggregate_kind public.ticket_aggregate_kind;
  filters jsonb;
  sort_plan jsonb;
  columns_plan jsonb;
  item jsonb;
  source text;
  core_key text;
  definition_id uuid;
  definition_version bigint;
  direction text;
  nulls_order text;
  pin_value text;
  definition_json text;
  signature text;
  identifier text;
  key_identifier text;
  custom_pin record;
  sla_pin record;
  scalar text;
  state_items text;
  severity_items text;
  priority_items text;
  custom_items text := '';
  column_items text := '';
  sort_json text;
  canonical text;
  item_count integer;
  visible_count integer := 0;
  visible_ticket boolean := false;
  scalar_bytes integer := 0;
  index_value integer := 0;
  position_value integer;
  width_value integer;
  version_value bigint;
  pin_identifiers text[] := ARRAY[]::text[];
  pin_signatures text[] := ARRAY[]::text[];
  pin_keys text[] := ARRAY[]::text[];
  pin_key_signatures text[] := ARRAY[]::text[];
  column_identifiers text[] := ARRAY[]::text[];
  column_signatures text[] := ARRAY[]::text[];
BEGIN
  IF p_request IS NULL OR pg_column_size(p_request) > 262144
     OR NOT app.private_ticket_saved_view_exact_keys_v1(
       p_request,
       ARRAY[
         'schemaVersion', 'tenantId', 'actorId', 'ownerMembershipId',
         'aggregateKind', 'filters', 'sort', 'columns'
       ]
     )
     OR jsonb_typeof(p_request -> 'schemaVersion') <> 'number'
     OR p_request ->> 'schemaVersion' <> '1'
     OR jsonb_typeof(p_request -> 'tenantId') <> 'string'
     OR jsonb_typeof(p_request -> 'actorId') <> 'string'
     OR jsonb_typeof(p_request -> 'ownerMembershipId') <> 'string'
     OR jsonb_typeof(p_request -> 'aggregateKind') <> 'string' THEN
    RAISE EXCEPTION 'saved-view resolver request is invalid'
      USING ERRCODE = '22023';
  END IF;
  tenant_id := app.private_ticket_saved_view_uuid_v1(
    p_request ->> 'tenantId', false
  );
  actor_id := app.private_ticket_saved_view_uuid_v1(
    p_request ->> 'actorId', false
  );
  owner_membership_id := app.private_ticket_saved_view_uuid_v1(
    p_request ->> 'ownerMembershipId', false
  );
  BEGIN
    aggregate_kind := (p_request ->> 'aggregateKind')::public.ticket_aggregate_kind;
  EXCEPTION WHEN invalid_text_representation THEN
    RAISE EXCEPTION 'saved-view aggregate kind is invalid'
      USING ERRCODE = '22023';
  END;
  PERFORM app.private_ticket_saved_view_assert_authority_v1(
    tenant_id, actor_id, owner_membership_id, aggregate_kind, false
  );

  filters := p_request -> 'filters';
  sort_plan := p_request -> 'sort';
  columns_plan := p_request -> 'columns';
  IF NOT app.private_ticket_saved_view_exact_keys_v1(
       filters,
       ARRAY[
         'states', 'severities', 'priorities', 'assignedTeamId',
         'assigneeUserId', 'claimedBy', 'queue', 'customerVisible',
         'search', 'custom'
       ]
     )
     OR jsonb_typeof(filters -> 'states') <> 'array'
     OR jsonb_typeof(filters -> 'severities') <> 'array'
     OR jsonb_typeof(filters -> 'priorities') <> 'array'
     OR jsonb_typeof(filters -> 'assignedTeamId') <> 'string'
     OR jsonb_typeof(filters -> 'assigneeUserId') <> 'string'
     OR jsonb_typeof(filters -> 'claimedBy') <> 'string'
     OR jsonb_typeof(filters -> 'queue') <> 'string'
     OR jsonb_typeof(filters -> 'customerVisible') NOT IN ('null', 'boolean')
     OR jsonb_typeof(filters -> 'search') <> 'string'
     OR jsonb_typeof(filters -> 'custom') <> 'array'
     OR jsonb_typeof(columns_plan) <> 'array'
     OR NOT app.private_ticket_saved_view_exact_keys_v1(
       sort_plan,
       ARRAY[
         'source', 'coreKey', 'definitionId', 'expectedDefinitionVersion',
         'direction', 'nulls'
       ]
     ) THEN
    RAISE EXCEPTION 'saved-view resolver shape is invalid'
      USING ERRCODE = '22023';
  END IF;

  -- Canonical set filters are duplicate-free and sorted by bytewise text.
  IF jsonb_array_length(filters -> 'states') > 20
     OR EXISTS (
       SELECT 1 FROM jsonb_array_elements(filters -> 'states') AS element(value)
       WHERE jsonb_typeof(element.value) <> 'string'
          OR element.value #>> '{}' !~ '^[a-z][a-z0-9_.-]{0,63}$'
     )
     OR (
       SELECT count(*) FROM jsonb_array_elements_text(filters -> 'states')
     ) <> (
       SELECT count(DISTINCT value COLLATE "C")
       FROM jsonb_array_elements_text(filters -> 'states') AS element(value)
     ) THEN
    RAISE EXCEPTION 'saved-view state filters are invalid'
      USING ERRCODE = '22023';
  END IF;
  SELECT coalesce(
    string_agg(
      app.private_ticket_saved_view_json_string_v1(element.value),
      ',' ORDER BY element.value COLLATE "C"
    ), ''
  ) INTO state_items
  FROM jsonb_array_elements_text(filters -> 'states') AS element(value);

  IF jsonb_array_length(filters -> 'severities') > 5
     OR EXISTS (
       SELECT 1 FROM jsonb_array_elements(filters -> 'severities') AS element(value)
       WHERE jsonb_typeof(element.value) <> 'string'
          OR element.value #>> '{}' NOT IN (
            'informational', 'low', 'medium', 'high', 'critical'
          )
     )
     OR (
       SELECT count(*) FROM jsonb_array_elements_text(filters -> 'severities')
     ) <> (
       SELECT count(DISTINCT value COLLATE "C")
       FROM jsonb_array_elements_text(filters -> 'severities') AS element(value)
     ) THEN
    RAISE EXCEPTION 'saved-view severity filters are invalid'
      USING ERRCODE = '22023';
  END IF;
  SELECT coalesce(
    string_agg(
      app.private_ticket_saved_view_json_string_v1(element.value),
      ',' ORDER BY element.value COLLATE "C"
    ), ''
  ) INTO severity_items
  FROM jsonb_array_elements_text(filters -> 'severities') AS element(value);

  IF jsonb_array_length(filters -> 'priorities') > 5
     OR EXISTS (
       SELECT 1 FROM jsonb_array_elements(filters -> 'priorities') AS element(value)
       WHERE jsonb_typeof(element.value) <> 'string'
          OR element.value #>> '{}' NOT IN (
            'low', 'medium', 'high', 'urgent', 'critical'
          )
     )
     OR (
       SELECT count(*) FROM jsonb_array_elements_text(filters -> 'priorities')
     ) <> (
       SELECT count(DISTINCT value COLLATE "C")
       FROM jsonb_array_elements_text(filters -> 'priorities') AS element(value)
     ) THEN
    RAISE EXCEPTION 'saved-view priority filters are invalid'
      USING ERRCODE = '22023';
  END IF;
  SELECT coalesce(
    string_agg(
      app.private_ticket_saved_view_json_string_v1(element.value),
      ',' ORDER BY element.value COLLATE "C"
    ), ''
  ) INTO priority_items
  FROM jsonb_array_elements_text(filters -> 'priorities') AS element(value);

  PERFORM app.private_ticket_saved_view_uuid_v1(
    filters ->> 'assignedTeamId', true
  );
  PERFORM app.private_ticket_saved_view_uuid_v1(
    filters ->> 'assigneeUserId', true
  );
  PERFORM app.private_ticket_saved_view_uuid_v1(
    filters ->> 'claimedBy', true
  );
  IF filters ->> 'queue' NOT IN (
       'all', 'assigned_to_me', 'my_operator_teams', 'unassigned'
     )
     OR octet_length(filters ->> 'search') > 240
     OR btrim(filters ->> 'search') IS DISTINCT FROM filters ->> 'search'
     OR filters ->> 'search' ~ '[[:cntrl:]\u200e\u200f\u202a-\u202e\u2066-\u2069]'
     OR jsonb_array_length(filters -> 'custom') > 8 THEN
    RAISE EXCEPTION 'saved-view filter values are invalid'
      USING ERRCODE = '22023';
  END IF;

  FOR item IN
    SELECT element.value
    FROM jsonb_array_elements(filters -> 'custom') AS element(value)
    ORDER BY element.value ->> 'definitionId' COLLATE "C"
  LOOP
    IF NOT app.private_ticket_saved_view_exact_keys_v1(
         item,
         ARRAY['definitionId', 'expectedDefinitionVersion', 'operator', 'value']
       )
       OR jsonb_typeof(item -> 'definitionId') <> 'string'
       OR jsonb_typeof(item -> 'expectedDefinitionVersion') <> 'number'
       OR item ->> 'expectedDefinitionVersion' !~ '^[1-9][0-9]{0,9}$'
       OR jsonb_typeof(item -> 'operator') <> 'string'
       OR item ->> 'operator' <> 'eq' THEN
      RAISE EXCEPTION 'saved-view custom filter is invalid'
        USING ERRCODE = '22023';
    END IF;
    definition_id := app.private_ticket_saved_view_uuid_v1(
      item ->> 'definitionId', false
    );
    definition_version := (item ->> 'expectedDefinitionVersion')::bigint;
    IF definition_version NOT BETWEEN 1 AND 2147483647 THEN
      RAISE EXCEPTION 'saved-view custom filter version is invalid'
        USING ERRCODE = '22023';
    END IF;
    identifier := 'custom_field:' || definition_id::text;
    IF identifier = ANY(pin_identifiers) THEN
      RAISE EXCEPTION 'saved-view custom filter is duplicated'
        USING ERRCODE = '22023';
    END IF;
    SELECT * INTO STRICT custom_pin
    FROM app.private_ticket_saved_view_custom_pin_v1(
      tenant_id, aggregate_kind, definition_id,
      definition_version, true, false
    );
    scalar := app.private_ticket_saved_view_canonical_scalar_v1(
      tenant_id, definition_id, definition_version, item -> 'value'
    );
    scalar_bytes := scalar_bytes + octet_length(scalar);
    IF scalar_bytes > 196608 THEN
      RAISE EXCEPTION 'saved-view custom filter budget is exceeded'
        USING ERRCODE = '22023';
    END IF;
    signature := definition_version::text || ':' || custom_pin.definition_key ||
      ':' || custom_pin.digest_hex;
    key_identifier := 'custom_field:' || custom_pin.definition_key;
    IF key_identifier = ANY(pin_keys) THEN
      RAISE EXCEPTION 'saved-view custom definition key is ambiguous'
        USING ERRCODE = '55000';
    END IF;
    pin_identifiers := array_append(pin_identifiers, identifier);
    pin_signatures := array_append(pin_signatures, signature);
    pin_keys := array_append(pin_keys, key_identifier);
    pin_key_signatures := array_append(pin_key_signatures, signature);
    definition_json := '{"id":' ||
      app.private_ticket_saved_view_json_string_v1(definition_id::text) ||
      ',"tenantId":' || app.private_ticket_saved_view_json_string_v1(tenant_id::text) ||
      ',"kind":' || app.private_ticket_saved_view_json_string_v1(aggregate_kind::text) ||
      ',"key":' || app.private_ticket_saved_view_json_string_v1(custom_pin.definition_key) ||
      ',"version":' || definition_version::text ||
      ',"digest":' || app.private_ticket_saved_view_json_string_v1(custom_pin.digest_hex) || '}';
    IF custom_items <> '' THEN
      custom_items := custom_items || ',';
    END IF;
    custom_items := custom_items || '{"definition":' || definition_json ||
      ',"dataType":' || app.private_ticket_saved_view_json_string_v1(custom_pin.data_type::text) ||
      ',"operator":"eq","value":' || scalar || '}';
  END LOOP;

  item_count := jsonb_array_length(columns_plan);
  IF item_count NOT BETWEEN 1 AND 64 THEN
    RAISE EXCEPTION 'saved-view columns are invalid'
      USING ERRCODE = '22023';
  END IF;
  FOR item IN
    SELECT element.value
    FROM jsonb_array_elements(columns_plan) WITH ORDINALITY
         AS element(value, ordinality)
    ORDER BY element.ordinality
  LOOP
    index_value := index_value + 1;
    IF NOT app.private_ticket_saved_view_exact_keys_v1(
         item,
         ARRAY[
           'source', 'coreKey', 'definitionId', 'expectedDefinitionVersion',
           'width', 'visible', 'pin'
         ]
       )
       OR jsonb_typeof(item -> 'source') <> 'string'
       OR jsonb_typeof(item -> 'coreKey') <> 'string'
       OR jsonb_typeof(item -> 'definitionId') <> 'string'
       OR jsonb_typeof(item -> 'expectedDefinitionVersion') <> 'number'
       OR item ->> 'expectedDefinitionVersion' !~ '^(0|[1-9][0-9]{0,9})$'
       OR jsonb_typeof(item -> 'width') <> 'number'
       OR item ->> 'width' !~ '^(0|[1-9][0-9]{0,3})$'
       OR jsonb_typeof(item -> 'visible') <> 'boolean'
       OR jsonb_typeof(item -> 'pin') <> 'string'
       OR item ->> 'pin' NOT IN ('none', 'start', 'end') THEN
      RAISE EXCEPTION 'saved-view column shape is invalid'
        USING ERRCODE = '22023';
    END IF;
    source := item ->> 'source';
    core_key := item ->> 'coreKey';
    width_value := (item ->> 'width')::integer;
    IF width_value <> 0 AND width_value NOT BETWEEN 80 AND 1200 THEN
      RAISE EXCEPTION 'saved-view column width is invalid'
        USING ERRCODE = '22023';
    END IF;
    IF (item ->> 'visible')::boolean THEN
      visible_count := visible_count + 1;
    END IF;

    IF source = 'core' THEN
      IF item ->> 'definitionId' <> ''
         OR item ->> 'expectedDefinitionVersion' <> '0'
         OR core_key NOT IN (
           'ticket', 'state', 'risk', 'assignment', 'category', 'source',
           'customer_visibility', 'created', 'updated'
         ) THEN
        RAISE EXCEPTION 'saved-view core column is invalid'
          USING ERRCODE = '22023';
      END IF;
      identifier := 'core:' || core_key;
      definition_json := NULL;
      visible_ticket := visible_ticket OR (
        core_key = 'ticket' AND (item ->> 'visible')::boolean
      );
    ELSIF source IN ('custom_field', 'sla') THEN
      IF core_key <> ''
         OR item ->> 'definitionId' = ''
         OR item ->> 'expectedDefinitionVersion' !~ '^[1-9][0-9]{0,9}$' THEN
        RAISE EXCEPTION 'saved-view dynamic column is invalid'
          USING ERRCODE = '22023';
      END IF;
      definition_id := app.private_ticket_saved_view_uuid_v1(
        item ->> 'definitionId', false
      );
      definition_version := (item ->> 'expectedDefinitionVersion')::bigint;
      IF definition_version NOT BETWEEN 1 AND 2147483647 THEN
        RAISE EXCEPTION 'saved-view dynamic column version is invalid'
          USING ERRCODE = '22023';
      END IF;
      identifier := source || ':' || definition_id::text;
      IF source = 'custom_field' THEN
        SELECT * INTO STRICT custom_pin
        FROM app.private_ticket_saved_view_custom_pin_v1(
          tenant_id, aggregate_kind, definition_id,
          definition_version, false, false
        );
        signature := definition_version::text || ':' || custom_pin.definition_key ||
          ':' || custom_pin.digest_hex;
        core_key := custom_pin.definition_key;
        pin_value := custom_pin.digest_hex;
      ELSE
        SELECT * INTO STRICT sla_pin
        FROM app.private_ticket_saved_view_sla_pin_v1(
          tenant_id, aggregate_kind, definition_id,
          definition_version::integer, false
        );
        signature := definition_version::text || ':' || sla_pin.definition_key ||
          ':' || sla_pin.digest_hex;
        core_key := sla_pin.definition_key;
        pin_value := sla_pin.digest_hex;
      END IF;
      key_identifier := source || ':' || core_key;
      position_value := array_position(pin_identifiers, identifier);
      IF position_value IS NOT NULL
         AND pin_signatures[position_value] IS DISTINCT FROM signature THEN
        RAISE EXCEPTION 'saved-view dynamic definition pin is inconsistent'
          USING ERRCODE = '55000';
      END IF;
      position_value := array_position(pin_keys, key_identifier);
      IF position_value IS NOT NULL
         AND pin_key_signatures[position_value] IS DISTINCT FROM signature THEN
        RAISE EXCEPTION 'saved-view dynamic definition key is ambiguous'
          USING ERRCODE = '55000';
      END IF;
      IF NOT identifier = ANY(pin_identifiers) THEN
        pin_identifiers := array_append(pin_identifiers, identifier);
        pin_signatures := array_append(pin_signatures, signature);
      END IF;
      IF NOT key_identifier = ANY(pin_keys) THEN
        pin_keys := array_append(pin_keys, key_identifier);
        pin_key_signatures := array_append(pin_key_signatures, signature);
      END IF;
      definition_json := '{"id":' ||
        app.private_ticket_saved_view_json_string_v1(definition_id::text) ||
        ',"tenantId":' || app.private_ticket_saved_view_json_string_v1(tenant_id::text) ||
        ',"kind":' || app.private_ticket_saved_view_json_string_v1(aggregate_kind::text) ||
        ',"key":' || app.private_ticket_saved_view_json_string_v1(core_key) ||
        ',"version":' || definition_version::text ||
        ',"digest":' || app.private_ticket_saved_view_json_string_v1(pin_value) || '}';
    ELSE
      RAISE EXCEPTION 'saved-view column source is invalid'
        USING ERRCODE = '22023';
    END IF;
    IF identifier = ANY(column_identifiers) THEN
      RAISE EXCEPTION 'saved-view column is duplicated'
        USING ERRCODE = '22023';
    END IF;
    column_identifiers := array_append(column_identifiers, identifier);
    column_signatures := array_append(
      column_signatures, coalesce(signature, identifier)
    );
    IF column_items <> '' THEN
      column_items := column_items || ',';
    END IF;
    column_items := column_items || '{"source":' ||
      app.private_ticket_saved_view_json_string_v1(source);
    IF source = 'core' THEN
      column_items := column_items || ',"coreKey":' ||
        app.private_ticket_saved_view_json_string_v1(core_key);
    ELSE
      column_items := column_items || ',"definition":' || definition_json;
    END IF;
    column_items := column_items || ',"width":' || width_value::text ||
      ',"visible":' || lower((item ->> 'visible')::boolean::text) ||
      ',"pin":' || app.private_ticket_saved_view_json_string_v1(item ->> 'pin') || '}';
    signature := NULL;
  END LOOP;
  IF visible_count = 0 OR NOT visible_ticket THEN
    RAISE EXCEPTION 'saved-view requires a visible ticket identity column'
      USING ERRCODE = '22023';
  END IF;

  IF jsonb_typeof(sort_plan -> 'source') <> 'string'
     OR jsonb_typeof(sort_plan -> 'coreKey') <> 'string'
     OR jsonb_typeof(sort_plan -> 'definitionId') <> 'string'
     OR jsonb_typeof(sort_plan -> 'expectedDefinitionVersion') <> 'number'
     OR sort_plan ->> 'expectedDefinitionVersion' !~ '^(0|[1-9][0-9]{0,9})$'
     OR jsonb_typeof(sort_plan -> 'direction') <> 'string'
     OR sort_plan ->> 'direction' NOT IN ('asc', 'desc')
     OR jsonb_typeof(sort_plan -> 'nulls') <> 'string'
     OR sort_plan ->> 'nulls' NOT IN ('first', 'last') THEN
    RAISE EXCEPTION 'saved-view sort shape is invalid'
      USING ERRCODE = '22023';
  END IF;
  source := sort_plan ->> 'source';
  direction := sort_plan ->> 'direction';
  nulls_order := sort_plan ->> 'nulls';
  core_key := sort_plan ->> 'coreKey';
  IF source = 'core' THEN
    IF sort_plan ->> 'definitionId' <> ''
       OR sort_plan ->> 'expectedDefinitionVersion' <> '0'
       OR nulls_order <> 'last'
       OR core_key NOT IN ('updated_at', 'created_at', 'priority', 'oldest_unclaimed')
       OR core_key = 'oldest_unclaimed' AND direction <> 'asc' THEN
      RAISE EXCEPTION 'saved-view core sort is invalid'
        USING ERRCODE = '22023';
    END IF;
    sort_json := '{"source":"core","coreKey":' ||
      app.private_ticket_saved_view_json_string_v1(core_key) ||
      ',"direction":' || app.private_ticket_saved_view_json_string_v1(direction) ||
      ',"nulls":"last"}';
  ELSIF source IN ('custom_field', 'sla') THEN
    IF core_key <> '' OR sort_plan ->> 'definitionId' = ''
       OR sort_plan ->> 'expectedDefinitionVersion' !~ '^[1-9][0-9]{0,9}$' THEN
      RAISE EXCEPTION 'saved-view dynamic sort is invalid'
        USING ERRCODE = '22023';
    END IF;
    definition_id := app.private_ticket_saved_view_uuid_v1(
      sort_plan ->> 'definitionId', false
    );
    definition_version := (sort_plan ->> 'expectedDefinitionVersion')::bigint;
    identifier := source || ':' || definition_id::text;
    position_value := array_position(column_identifiers, identifier);
    IF position_value IS NULL THEN
      RAISE EXCEPTION 'saved-view dynamic sort is not projected'
        USING ERRCODE = '22023';
    END IF;
    IF source = 'custom_field' THEN
      SELECT * INTO STRICT custom_pin
      FROM app.private_ticket_saved_view_custom_pin_v1(
        tenant_id, aggregate_kind, definition_id,
        definition_version, false, true
      );
      signature := definition_version::text || ':' || custom_pin.definition_key ||
        ':' || custom_pin.digest_hex;
      core_key := custom_pin.definition_key;
      pin_value := custom_pin.digest_hex;
    ELSE
      SELECT * INTO STRICT sla_pin
      FROM app.private_ticket_saved_view_sla_pin_v1(
        tenant_id, aggregate_kind, definition_id,
        definition_version::integer, true
      );
      signature := definition_version::text || ':' || sla_pin.definition_key ||
        ':' || sla_pin.digest_hex;
      core_key := sla_pin.definition_key;
      pin_value := sla_pin.digest_hex;
    END IF;
    IF column_signatures[position_value] IS DISTINCT FROM signature THEN
      RAISE EXCEPTION 'saved-view dynamic sort pin is inconsistent'
        USING ERRCODE = '55000';
    END IF;
    definition_json := '{"id":' ||
      app.private_ticket_saved_view_json_string_v1(definition_id::text) ||
      ',"tenantId":' || app.private_ticket_saved_view_json_string_v1(tenant_id::text) ||
      ',"kind":' || app.private_ticket_saved_view_json_string_v1(aggregate_kind::text) ||
      ',"key":' || app.private_ticket_saved_view_json_string_v1(core_key) ||
      ',"version":' || definition_version::text ||
      ',"digest":' || app.private_ticket_saved_view_json_string_v1(pin_value) || '}';
    sort_json := '{"source":' || app.private_ticket_saved_view_json_string_v1(source) ||
      ',"definition":' || definition_json ||
      ',"direction":' || app.private_ticket_saved_view_json_string_v1(direction) ||
      ',"nulls":' || app.private_ticket_saved_view_json_string_v1(nulls_order) || '}';
  ELSE
    RAISE EXCEPTION 'saved-view sort source is invalid'
      USING ERRCODE = '22023';
  END IF;

  canonical := '{"version":1,"filters":{"states":[' || state_items ||
    '],"severities":[' || severity_items || '],"priorities":[' || priority_items || ']';
  IF filters ->> 'assignedTeamId' <> '' THEN
    canonical := canonical || ',"assignedTeamId":' ||
      app.private_ticket_saved_view_json_string_v1(filters ->> 'assignedTeamId');
  END IF;
  IF filters ->> 'assigneeUserId' <> '' THEN
    canonical := canonical || ',"assigneeUserId":' ||
      app.private_ticket_saved_view_json_string_v1(filters ->> 'assigneeUserId');
  END IF;
  IF filters ->> 'claimedBy' <> '' THEN
    canonical := canonical || ',"claimedBy":' ||
      app.private_ticket_saved_view_json_string_v1(filters ->> 'claimedBy');
  END IF;
  canonical := canonical || ',"queue":' ||
    app.private_ticket_saved_view_json_string_v1(filters ->> 'queue');
  IF jsonb_typeof(filters -> 'customerVisible') = 'boolean' THEN
    canonical := canonical || ',"customerVisible":' ||
      lower((filters ->> 'customerVisible')::boolean::text);
  END IF;
  IF filters ->> 'search' <> '' THEN
    canonical := canonical || ',"search":' ||
      app.private_ticket_saved_view_json_string_v1(filters ->> 'search');
  END IF;
  canonical := canonical || ',"custom":[' || custom_items || ']},"sort":' ||
    sort_json || ',"columns":[' || column_items || ']}';
  IF octet_length(canonical) > 262144 THEN
    RAISE EXCEPTION 'saved-view canonical specification is too large'
      USING ERRCODE = '22023';
  END IF;
  RETURN jsonb_build_object(
    'schemaVersion', 1,
    'specCanonicalBase64', app.private_ticket_saved_view_base64_v1(canonical),
    'specSha256', encode(
      pg_catalog.sha256(convert_to(canonical, 'UTF8')), 'hex'
    )
  );
END;
$function$;
ALTER FUNCTION app.private_resolve_ticket_saved_view_spec_v1(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_resolve_ticket_saved_view_spec_v1(jsonb)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
GRANT EXECUTE ON FUNCTION app.private_resolve_ticket_saved_view_spec_v1(jsonb)
TO periapsis_ticket_saved_view_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_saved_view_spec_pins_current_v1(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_owner_membership_id uuid,
  p_aggregate_kind public.ticket_aggregate_kind,
  p_spec_canonical text
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  document jsonb;
  filters jsonb;
  sort_plan jsonb;
  columns_plan jsonb;
  resolver_filters jsonb;
  resolver_sort jsonb;
  resolver_columns jsonb;
  resolver_custom jsonb;
  result jsonb;
  round_trip text;
BEGIN
  IF p_tenant_id IS NULL OR p_actor_user_id IS NULL
     OR p_owner_membership_id IS NULL OR p_aggregate_kind IS NULL
     OR p_spec_canonical IS NULL
     OR octet_length(p_spec_canonical) NOT BETWEEN 1 AND 262144 THEN
    RAISE EXCEPTION 'saved-view canonical pin request is invalid'
      USING ERRCODE = '22023';
  END IF;
  BEGIN
    document := p_spec_canonical::jsonb;
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'saved-view canonical specification is malformed'
      USING ERRCODE = '22023';
  END;
  IF NOT app.private_ticket_saved_view_exact_keys_v1(
       document, ARRAY['version', 'filters', 'sort', 'columns']
     )
     OR jsonb_typeof(document -> 'version') <> 'number'
     OR document ->> 'version' <> '1'
     OR jsonb_typeof(document -> 'filters') <> 'object'
     OR jsonb_typeof(document -> 'sort') <> 'object'
     OR jsonb_typeof(document -> 'columns') <> 'array' THEN
    RAISE EXCEPTION 'saved-view canonical specification shape is invalid'
      USING ERRCODE = '22023';
  END IF;
  filters := document -> 'filters';
  sort_plan := document -> 'sort';
  columns_plan := document -> 'columns';
  IF NOT (
       filters ?& ARRAY['states', 'severities', 'priorities', 'queue', 'custom']
     )
     OR EXISTS (
       SELECT 1 FROM jsonb_object_keys(filters) AS actual(key)
       WHERE actual.key <> ALL(ARRAY[
         'states', 'severities', 'priorities', 'assignedTeamId',
         'assigneeUserId', 'claimedBy', 'queue', 'customerVisible',
         'search', 'custom'
       ])
     ) THEN
    RAISE EXCEPTION 'saved-view canonical filters are invalid'
      USING ERRCODE = '22023';
  END IF;

  SELECT coalesce(
    jsonb_agg(
      jsonb_build_object(
        'definitionId', element.value #>> '{definition,id}',
        'expectedDefinitionVersion',
          (element.value #>> '{definition,version}')::bigint,
        'operator', element.value ->> 'operator',
        'value', element.value -> 'value'
      ) ORDER BY element.ordinality
    ), '[]'::jsonb
  ) INTO resolver_custom
  FROM jsonb_array_elements(filters -> 'custom') WITH ORDINALITY
       AS element(value, ordinality);
  resolver_filters := jsonb_build_object(
    'states', filters -> 'states',
    'severities', filters -> 'severities',
    'priorities', filters -> 'priorities',
    'assignedTeamId', coalesce(filters ->> 'assignedTeamId', ''),
    'assigneeUserId', coalesce(filters ->> 'assigneeUserId', ''),
    'claimedBy', coalesce(filters ->> 'claimedBy', ''),
    'queue', filters ->> 'queue',
    'customerVisible', CASE
      WHEN filters ? 'customerVisible' THEN filters -> 'customerVisible'
      ELSE 'null'::jsonb
    END,
    'search', coalesce(filters ->> 'search', ''),
    'custom', resolver_custom
  );

  SELECT coalesce(
    jsonb_agg(
      jsonb_build_object(
        'source', element.value ->> 'source',
        'coreKey', coalesce(element.value ->> 'coreKey', ''),
        'definitionId', coalesce(element.value #>> '{definition,id}', ''),
        'expectedDefinitionVersion', coalesce(
          (element.value #>> '{definition,version}')::bigint, 0
        ),
        'width', element.value -> 'width',
        'visible', element.value -> 'visible',
        'pin', element.value ->> 'pin'
      ) ORDER BY element.ordinality
    ), '[]'::jsonb
  ) INTO resolver_columns
  FROM jsonb_array_elements(columns_plan) WITH ORDINALITY
       AS element(value, ordinality);
  resolver_sort := jsonb_build_object(
    'source', sort_plan ->> 'source',
    'coreKey', coalesce(sort_plan ->> 'coreKey', ''),
    'definitionId', coalesce(sort_plan #>> '{definition,id}', ''),
    'expectedDefinitionVersion', coalesce(
      (sort_plan #>> '{definition,version}')::bigint, 0
    ),
    'direction', sort_plan ->> 'direction',
    'nulls', sort_plan ->> 'nulls'
  );
  result := app.private_resolve_ticket_saved_view_spec_v1(
    jsonb_build_object(
      'schemaVersion', 1,
      'tenantId', p_tenant_id::text,
      'actorId', p_actor_user_id::text,
      'ownerMembershipId', p_owner_membership_id::text,
      'aggregateKind', p_aggregate_kind::text,
      'filters', resolver_filters,
      'sort', resolver_sort,
      'columns', resolver_columns
    )
  );
  round_trip := app.private_ticket_saved_view_decode_base64_v1(
    result ->> 'specCanonicalBase64'
  );
  IF round_trip IS DISTINCT FROM p_spec_canonical
     OR result ->> 'specSha256' IS DISTINCT FROM encode(
       pg_catalog.sha256(convert_to(p_spec_canonical, 'UTF8')), 'hex'
     ) THEN
    RAISE EXCEPTION 'saved-view canonical specification is not exact'
      USING ERRCODE = '55000';
  END IF;
END;
$function$;
ALTER FUNCTION app.private_ticket_saved_view_spec_pins_current_v1(
  uuid, uuid, uuid, public.ticket_aggregate_kind, text
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_saved_view_spec_pins_current_v1(
  uuid, uuid, uuid, public.ticket_aggregate_kind, text
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
GRANT EXECUTE ON FUNCTION app.private_ticket_saved_view_spec_pins_current_v1(
  uuid, uuid, uuid, public.ticket_aggregate_kind, text
) TO periapsis_ticket_saved_view_owner;
--> statement-breakpoint

CREATE FUNCTION app.guard_ticket_saved_view_row_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF current_user <> 'periapsis_ticket_saved_view_owner'
     OR TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'saved-view rows are ABI-owned and cannot be deleted'
      USING ERRCODE = '55000';
  END IF;
  IF NEW.tenant_id IS DISTINCT FROM app.context_tenant_id()
     OR NEW.owner_membership_id IS DISTINCT FROM
          app.current_tenant_membership_id()
     OR NEW.spec_digest IS DISTINCT FROM pg_catalog.sha256(
       convert_to(NEW.spec_canonical, 'UTF8')
     ) THEN
    RAISE EXCEPTION 'saved-view row ownership or digest is invalid'
      USING ERRCODE = '55000';
  END IF;
  IF TG_OP = 'INSERT' THEN
    IF NEW.revision <> 1 OR NEW.status <> 'active'
       OR NEW.archived_at IS NOT NULL
       OR NEW.created_at IS DISTINCT FROM NEW.updated_at THEN
      RAISE EXCEPTION 'saved-view create row is invalid'
        USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.owner_membership_id IS DISTINCT FROM OLD.owner_membership_id
     OR NEW.aggregate_kind IS DISTINCT FROM OLD.aggregate_kind
     OR NEW.created_at IS DISTINCT FROM OLD.created_at
     OR NEW.revision <> OLD.revision + 1
     OR NEW.updated_at < OLD.updated_at
     OR OLD.status = 'archived' AND NEW.status = 'archived'
     OR OLD.status = 'active' AND NEW.status = 'archived' AND (
       NEW.name IS DISTINCT FROM OLD.name
       OR NEW.spec_canonical IS DISTINCT FROM OLD.spec_canonical
       OR NEW.spec_digest IS DISTINCT FROM OLD.spec_digest
     )
     OR OLD.status = 'archived' AND NEW.status = 'active' AND (
       NEW.name IS DISTINCT FROM OLD.name
       OR NEW.spec_canonical IS DISTINCT FROM OLD.spec_canonical
       OR NEW.spec_digest IS DISTINCT FROM OLD.spec_digest
     ) THEN
    RAISE EXCEPTION 'saved-view row transition is invalid'
      USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$function$;
ALTER FUNCTION app.guard_ticket_saved_view_row_v1()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.guard_ticket_saved_view_row_v1()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner;
CREATE TRIGGER ticket_saved_views_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.ticket_saved_views
FOR EACH ROW EXECUTE FUNCTION app.guard_ticket_saved_view_row_v1();
--> statement-breakpoint

CREATE FUNCTION app.guard_ticket_saved_view_command_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  current_view public.ticket_saved_views%ROWTYPE;
BEGIN
  IF current_user <> 'periapsis_ticket_saved_view_owner' THEN
    RAISE EXCEPTION 'saved-view command evidence is ABI-owned'
      USING ERRCODE = '55000';
  END IF;
  IF TG_OP = 'DELETE' THEN
    IF OLD.expires_at <= clock_timestamp() THEN
      RETURN OLD;
    END IF;
    RAISE EXCEPTION 'unexpired saved-view command evidence is immutable'
      USING ERRCODE = '55000';
  END IF;
  IF TG_OP = 'UPDATE' THEN
    RAISE EXCEPTION 'saved-view command evidence is immutable'
      USING ERRCODE = '55000';
  END IF;
  IF NEW.tenant_id IS DISTINCT FROM app.context_tenant_id()
     OR NEW.owner_membership_id IS DISTINCT FROM
          app.current_tenant_membership_id()
     OR NEW.actor_user_id IS DISTINCT FROM app.context_user_id()
     OR NEW.result_spec_digest IS DISTINCT FROM pg_catalog.sha256(
       convert_to(NEW.result_spec_canonical, 'UTF8')
     ) THEN
    RAISE EXCEPTION 'saved-view command ownership or digest is invalid'
      USING ERRCODE = '55000';
  END IF;
  SELECT view_record.* INTO current_view
  FROM public.ticket_saved_views AS view_record
  WHERE view_record.tenant_id = NEW.tenant_id
    AND view_record.id = NEW.result_view_id;
  IF NOT FOUND
     OR current_view.owner_membership_id IS DISTINCT FROM NEW.owner_membership_id
     OR current_view.aggregate_kind IS DISTINCT FROM NEW.aggregate_kind
     OR current_view.name IS DISTINCT FROM NEW.result_name
     OR current_view.spec_canonical IS DISTINCT FROM NEW.result_spec_canonical
     OR current_view.spec_digest IS DISTINCT FROM NEW.result_spec_digest
     OR current_view.status IS DISTINCT FROM NEW.result_status
     OR current_view.revision IS DISTINCT FROM NEW.next_revision
     OR current_view.created_at IS DISTINCT FROM NEW.result_created_at
     OR current_view.updated_at IS DISTINCT FROM NEW.result_updated_at
     OR current_view.archived_at IS DISTINCT FROM NEW.result_archived_at THEN
    RAISE EXCEPTION 'saved-view command snapshot does not match the result row'
      USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$function$;
ALTER FUNCTION app.guard_ticket_saved_view_command_v1()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.guard_ticket_saved_view_command_v1()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner;
CREATE TRIGGER ticket_saved_view_commands_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.ticket_saved_view_commands
FOR EACH ROW EXECUTE FUNCTION app.guard_ticket_saved_view_command_v1();
--> statement-breakpoint

CREATE FUNCTION app.private_append_ticket_saved_view_effects_v1(
  p_tenant_id uuid,
  p_actor_user_id uuid,
  p_owner_membership_id uuid,
  p_aggregate_kind public.ticket_aggregate_kind,
  p_action text,
  p_view_id uuid,
  p_revision integer,
  p_status text,
  p_command_id uuid,
  p_audit_event_id uuid,
  p_outbox_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_remote_address inet,
  p_user_agent text,
  p_authentication_method text,
  p_changed_at timestamp with time zone
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  before_state jsonb;
  after_state jsonb;
BEGIN
  IF p_tenant_id IS DISTINCT FROM app.context_tenant_id()
     OR p_actor_user_id IS DISTINCT FROM app.context_user_id()
     OR p_owner_membership_id IS DISTINCT FROM
          app.current_tenant_membership_id()
     OR p_action NOT IN ('create', 'replace', 'archive', 'restore')
     OR p_status NOT IN ('active', 'archived')
     OR p_revision NOT BETWEEN 1 AND 2147483647
     OR p_changed_at IS NULL
     OR (uuid_extract_version(p_view_id) = 7) IS NOT TRUE
     OR (uuid_extract_version(p_command_id) = 7) IS NOT TRUE
     OR (uuid_extract_version(p_audit_event_id) = 7) IS NOT TRUE
     OR (uuid_extract_version(p_outbox_event_id) = 7) IS NOT TRUE
     OR p_request_id IS NULL
     OR (uuid_extract_version(p_request_id) = 7) IS NOT TRUE
     OR p_correlation_id IS NULL
     OR (uuid_extract_version(p_correlation_id) = 7) IS NOT TRUE
     OR p_remote_address IS NULL OR p_remote_address::text LIKE '%\%%'
     OR p_user_agent IS NULL OR octet_length(p_user_agent) > 512
     OR p_authentication_method NOT IN (
       'bootstrap_totp', 'totp', 'recovery_code', 'ldap',
       'oidc', 'saml', 'passkey'
     ) THEN
    RAISE EXCEPTION 'saved-view effect envelope is invalid'
      USING ERRCODE = '22023';
  END IF;
  before_state := CASE p_action
    WHEN 'create' THEN '{}'::jsonb
    ELSE jsonb_build_object(
      'revision', p_revision - 1,
      'status', CASE WHEN p_action = 'restore' THEN 'archived' ELSE 'active' END,
      'aggregate_kind', p_aggregate_kind
    )
  END;
  after_state := jsonb_build_object(
    'revision', p_revision,
    'status', p_status,
    'aggregate_kind', p_aggregate_kind
  );
  PERFORM app.append_tenant_authorization_audit(
    p_audit_event_id, 'tenant.ticket_saved_view.' || p_action,
    'ticket_saved_view', p_view_id, p_request_id, p_correlation_id,
    p_remote_address, p_user_agent, p_authentication_method,
    before_state, after_state,
    jsonb_build_object(
      'owner_membership_id', p_owner_membership_id,
      'content_redacted', true
    )
  );
  INSERT INTO public.outbox_events (
    id, tenant_id, aggregate_type, aggregate_id, aggregate_version,
    event_type, schema_version, payload, deduplication_key,
    correlation_id, causation_id, actor_kind, actor_id, producer,
    maximum_audience, occurred_at, available_at
  ) VALUES (
    p_outbox_event_id, p_tenant_id, 'ticket_saved_view', p_view_id,
    p_revision, 'ticket_saved_view.' || p_action, 1,
    jsonb_build_object(
      'view_id', p_view_id,
      'aggregate_kind', p_aggregate_kind,
      'action', p_action,
      'status', p_status,
      'revision', p_revision
    ),
    'ticket_saved_view.' || p_action || ':' || p_command_id::text,
    p_correlation_id, p_request_id, 'human', p_actor_user_id,
    'api.ticket_saved_view', 'operator', p_changed_at, p_changed_at
  );
END;
$function$;
ALTER FUNCTION app.private_append_ticket_saved_view_effects_v1(
  uuid, uuid, uuid, public.ticket_aggregate_kind, text, uuid,
  integer, text, uuid, uuid, uuid, uuid, uuid, inet, text, text,
  timestamp with time zone
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_append_ticket_saved_view_effects_v1(
  uuid, uuid, uuid, public.ticket_aggregate_kind, text, uuid,
  integer, text, uuid, uuid, uuid, uuid, uuid, inet, text, text,
  timestamp with time zone
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
GRANT EXECUTE ON FUNCTION app.private_append_ticket_saved_view_effects_v1(
  uuid, uuid, uuid, public.ticket_aggregate_kind, text, uuid,
  integer, text, uuid, uuid, uuid, uuid, uuid, inet, text, text,
  timestamp with time zone
) TO periapsis_ticket_saved_view_owner;
--> statement-breakpoint
