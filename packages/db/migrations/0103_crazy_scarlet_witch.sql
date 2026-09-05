CREATE ROLE "periapsis_audit_reader_owner" WITH NOINHERIT;--> statement-breakpoint
CREATE INDEX "audit_events_tenant_action_sequence_idx" ON "audit_events" USING btree ("tenant_id","action","sequence");--> statement-breakpoint
CREATE INDEX "audit_events_tenant_outcome_sequence_idx" ON "audit_events" USING btree ("tenant_id","outcome","sequence");--> statement-breakpoint
CREATE INDEX "audit_events_tenant_actor_user_sequence_idx" ON "audit_events" USING btree ("tenant_id","actor_user_id","sequence");--> statement-breakpoint
CREATE INDEX "audit_events_tenant_actor_service_sequence_idx" ON "audit_events" USING btree ("tenant_id","actor_service_account_id","sequence");--> statement-breakpoint
CREATE INDEX "platform_audit_events_action_sequence_idx" ON "platform_audit_events" USING btree ("action","sequence");--> statement-breakpoint
CREATE INDEX "platform_audit_events_outcome_sequence_idx" ON "platform_audit_events" USING btree ("outcome","sequence");--> statement-breakpoint
CREATE INDEX "platform_audit_events_actor_user_sequence_idx" ON "platform_audit_events" USING btree ("actor_user_id","sequence");--> statement-breakpoint
CREATE POLICY "audit_chain_heads_reader_select" ON "audit_chain_heads" AS PERMISSIVE FOR SELECT TO "periapsis_audit_reader_owner" USING ("audit_chain_heads"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
        and app.current_tenant_human_has_exact_permission_v3('audit.read', 'tenant'));--> statement-breakpoint
CREATE POLICY "audit_events_reader_select" ON "audit_events" AS PERMISSIVE FOR SELECT TO "periapsis_audit_reader_owner" USING ("audit_events"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
        and app.current_tenant_human_has_exact_permission_v3('audit.read', 'tenant'));--> statement-breakpoint
CREATE POLICY "platform_audit_chain_head_reader_select" ON "platform_audit_chain_head" AS PERMISSIVE FOR SELECT TO "periapsis_audit_reader_owner" USING (app.platform_user_has_permission(app.context_user_id(), 'platform.audit.read'));--> statement-breakpoint
CREATE POLICY "platform_audit_events_reader_select" ON "platform_audit_events" AS PERMISSIVE FOR SELECT TO "periapsis_audit_reader_owner" USING (app.platform_user_has_permission(app.context_user_id(), 'platform.audit.read'));
--> statement-breakpoint

-- Audit reads are deliberately state-changing: each bounded projection appends
-- access evidence in the same transaction. The function owner is non-login and
-- remains subject to FORCE RLS; the API receives EXECUTE on four entry points
-- and no direct audit-table visibility.
ALTER ROLE periapsis_audit_reader_owner
  WITH NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
--> statement-breakpoint
REVOKE ALL ON TABLE public.audit_events, public.audit_chain_heads,
  public.platform_audit_events, public.platform_audit_chain_head
FROM periapsis_api;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.verify_audit_chain(uuid),
  app.calculate_audit_event_hash(public.audit_events, character),
  app.audit_event_payload(public.audit_events),
  app.read_platform_audit_events(bigint, integer),
  app.verify_platform_audit_chain(),
  app.calculate_platform_audit_event_hash(public.platform_audit_events, character),
  app.platform_audit_event_payload(public.platform_audit_events)
FROM periapsis_api;
--> statement-breakpoint
GRANT USAGE ON SCHEMA app, public TO periapsis_audit_reader_owner;
--> statement-breakpoint
GRANT SELECT ON TABLE public.audit_events, public.audit_chain_heads,
  public.platform_audit_events, public.platform_audit_chain_head
TO periapsis_audit_reader_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.context_tenant_id(), app.context_user_id(),
  app.current_tenant_human_has_exact_permission_v3(text, public.authorization_scope),
  app.platform_user_has_permission(uuid, text),
  app.audit_event_payload(public.audit_events),
  app.platform_audit_event_payload(public.platform_audit_events),
  app.calculate_audit_event_hash(public.audit_events, character),
  app.calculate_platform_audit_event_hash(public.platform_audit_events, character),
  app.append_tenant_authorization_audit(uuid, text, text, uuid, uuid, uuid, inet, text, text, jsonb, jsonb, jsonb),
  app.append_platform_audit_event(uuid, public.audit_actor_type, uuid, text, text, uuid, uuid, uuid, inet, text, text, public.audit_outcome, text, jsonb)
TO periapsis_audit_reader_owner;
--> statement-breakpoint

INSERT INTO public.tenant_permissions (
  id, key, display_name, description, service_account_allowed
)
VALUES (
  uuidv7(), 'audit.read', 'Read security audit log',
  'Read and verify the tenant security audit stream.', false
)
ON CONFLICT (key) DO NOTHING;
--> statement-breakpoint
INSERT INTO public.tenant_permission_scopes (permission_id, scope)
SELECT permission.id, 'tenant'::public.authorization_scope
FROM public.tenant_permissions AS permission
WHERE permission.key = 'audit.read'
ON CONFLICT DO NOTHING;
--> statement-breakpoint
INSERT INTO public.platform_permissions (id, key, description)
VALUES (
  uuidv7(), 'platform.audit.read',
  'Read and verify the independent platform security audit stream.'
)
ON CONFLICT (key) DO NOTHING;
--> statement-breakpoint
INSERT INTO public.platform_roles (id, key, display_name, system)
VALUES (uuidv7(), 'platform_auditor', 'Platform auditor', true)
ON CONFLICT (key) DO NOTHING;
--> statement-breakpoint
INSERT INTO public.platform_role_permissions (role_id, permission_id)
SELECT role.id, permission.id
FROM public.platform_roles AS role
CROSS JOIN public.platform_permissions AS permission
WHERE role.key IN ('platform_super_admin', 'platform_auditor')
  AND permission.key = 'platform.audit.read'
ON CONFLICT DO NOTHING;
--> statement-breakpoint

CREATE FUNCTION app.private_seed_tenant_audit_authorization_v1(p_tenant_id uuid)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_tenant_id IS NULL OR NOT EXISTS (
    SELECT 1 FROM public.tenants AS tenant WHERE tenant.id = p_tenant_id
  ) THEN
    RAISE EXCEPTION 'tenant not found' USING ERRCODE = 'P0002';
  END IF;

  INSERT INTO public.tenant_role_permissions (
    tenant_id, role_id, permission_id, scope
  )
  SELECT p_tenant_id, role.id, permission.id,
         'tenant'::public.authorization_scope
  FROM public.tenant_roles AS role
  CROSS JOIN public.tenant_permissions AS permission
  WHERE role.tenant_id = p_tenant_id
    AND role.key = 'tenant_admin'
    AND role.system_role
    AND role.archived_at IS NULL
    AND role.principal_kind = 'human'
    AND permission.key = 'audit.read'
  ON CONFLICT DO NOTHING;

  INSERT INTO public.tenant_role_delegation_ceilings (
    tenant_id, role_id, permission_id, scope
  )
  SELECT grant_row.tenant_id, grant_row.role_id,
         grant_row.permission_id, grant_row.scope
  FROM public.tenant_role_permissions AS grant_row
  JOIN public.tenant_roles AS role
    ON role.tenant_id = grant_row.tenant_id
   AND role.id = grant_row.role_id
  JOIN public.tenant_permissions AS permission
    ON permission.id = grant_row.permission_id
  WHERE grant_row.tenant_id = p_tenant_id
    AND role.key = 'tenant_admin'
    AND role.system_role
    AND role.archived_at IS NULL
    AND role.principal_kind = 'human'
    AND permission.key = 'audit.read'
    AND grant_row.scope = 'tenant'::public.authorization_scope
  ON CONFLICT DO NOTHING;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_seed_tenant_audit_authorization_v1(uuid)
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_seed_tenant_audit_authorization_v1(uuid)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner;
--> statement-breakpoint
SELECT app.private_seed_tenant_audit_authorization_v1(tenant.id)
FROM public.tenants AS tenant
ORDER BY tenant.id;
--> statement-breakpoint

-- Rename first, then create the successor under the canonical name. This
-- avoids the PL/pgSQL late-binding self-recursion that a create-then-rename
-- sequence would introduce.
ALTER FUNCTION app.seed_tenant_authorization(uuid, uuid)
  RENAME TO seed_tenant_authorization_audit_compatibility_impl;
--> statement-breakpoint
CREATE FUNCTION app.seed_tenant_authorization(
  p_tenant_id uuid,
  p_bootstrap_user_id uuid
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  PERFORM app.seed_tenant_authorization_audit_compatibility_impl(
    p_tenant_id, p_bootstrap_user_id
  );
  PERFORM app.private_seed_tenant_audit_authorization_v1(p_tenant_id);
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.seed_tenant_authorization(uuid, uuid)
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.seed_tenant_authorization(uuid, uuid),
  app.seed_tenant_authorization_audit_compatibility_impl(uuid, uuid)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner;
--> statement-breakpoint

CREATE FUNCTION app.audit_json_key_value_safe_v1(
  p_key text,
  p_value jsonb
)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
STRICT
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
DECLARE
  canonical_key text := regexp_replace(lower(p_key), '[^[:alnum:]]', '', 'g');
  scalar_text text;
  safe_boolean_keys constant text[] := ARRAY[
    'authorizationinitialized', 'bindsecretconfigured',
    'passwordconfigured', 'privatekeyconfigured',
    'secretmaterialarchived', 'secretmaterialincluded'
  ];
  safe_identifier_keys constant text[] := ARRAY[
    'apikeyid', 'bindsecretid', 'credentialid', 'fencetoken',
    'predecessorcredentialid', 'replacementcredentialid', 'secretid'
  ];
  safe_integer_keys constant text[] := ARRAY[
    'authorizationrevision', 'bindsecretkeyversion', 'bindsecretversion',
    'credentialkeyversion', 'credentialversion', 'secretversion'
  ];
  safe_kind_keys constant text[] := ARRAY[
    'bindsecretalgorithm', 'credentialkind', 'secretkind', 'tokenkind'
  ];
  prohibited_keys constant text[] := ARRAY[
    'accesstoken', 'accesstokendigest', 'apikey', 'apikeydigest',
    'assertion', 'authorization', 'bindpassword', 'clientassertion',
    'clientsecret', 'cookie', 'credential', 'credentials',
    'csrfsecret', 'csrfsecretdigest', 'csrftoken', 'encryptionkey',
    'idtoken', 'idtokendigest', 'keymaterial', 'passphrase',
    'password', 'passwordphc', 'privatekey', 'privatekeyciphertext',
    'recoverycode', 'recoverycodes', 'refreshtoken',
    'refreshtokendigest', 'samlassertion', 'secret',
    'secretciphertext', 'sessiontoken', 'token', 'tokendigest',
    'totpsecret'
  ];
  sensitive_fragments constant text[] := ARRAY[
    'accesstoken', 'apikey', 'assertion', 'bindpassword',
    'clientassertion', 'clientsecret', 'cookie', 'credential',
    'csrfsecret', 'csrftoken', 'encryptionkey', 'idtoken',
    'keymaterial', 'passphrase', 'password', 'privatekey',
    'recoverycode', 'refreshtoken', 'samlassertion', 'secret',
    'sessiontoken', 'token', 'totpsecret'
  ];
BEGIN
  IF canonical_key = ANY(safe_boolean_keys) THEN
    RETURN jsonb_typeof(p_value) = 'boolean';
  END IF;
  IF canonical_key = ANY(safe_identifier_keys) THEN
    IF jsonb_typeof(p_value) = 'null' THEN
      RETURN true;
    END IF;
    IF jsonb_typeof(p_value) <> 'string' THEN
      RETURN false;
    END IF;
    scalar_text := p_value #>> '{}';
    RETURN scalar_text ~* '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$';
  END IF;
  IF canonical_key = ANY(safe_integer_keys) THEN
    IF jsonb_typeof(p_value) <> 'number' THEN
      RETURN false;
    END IF;
    scalar_text := p_value::text;
    RETURN scalar_text ~ '^(0|[1-9][0-9]*)$'
      AND (length(scalar_text) < 19
        OR length(scalar_text) = 19
          AND scalar_text <= '9223372036854775807');
  END IF;
  IF canonical_key = ANY(safe_kind_keys) THEN
    IF jsonb_typeof(p_value) <> 'string' THEN
      RETURN false;
    END IF;
    scalar_text := p_value #>> '{}';
    RETURN length(scalar_text) BETWEEN 1 AND 64
      AND scalar_text ~ '^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)*$';
  END IF;
  IF canonical_key = ANY(prohibited_keys) THEN
    RETURN false;
  END IF;
  RETURN NOT EXISTS (
    SELECT 1
    FROM unnest(sensitive_fragments) AS fragment(value)
    WHERE position(fragment.value IN canonical_key) > 0
  );
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.audit_json_document_safe_v1(
  p_document jsonb,
  p_maximum_bytes integer,
  p_nullable boolean
)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, app
AS $function$
DECLARE
  node_count bigint;
  deepest integer;
  unsafe_value boolean;
BEGIN
  IF p_maximum_bytes IS NULL OR p_maximum_bytes NOT BETWEEN 2 AND 65536
     OR p_nullable IS NULL THEN
    RETURN false;
  END IF;
  IF p_document IS NULL OR jsonb_typeof(p_document) = 'null' THEN
    RETURN p_nullable;
  END IF;
  IF jsonb_typeof(p_document) <> 'object'
     OR octet_length(convert_to(p_document::text, 'UTF8')) > p_maximum_bytes THEN
    RETURN false;
  END IF;

  WITH RECURSIVE nodes(value, key_name, depth) AS (
    SELECT p_document, NULL::text, 1
    UNION ALL
    SELECT child.value, child.key_name, parent.depth + 1
    FROM nodes AS parent
    CROSS JOIN LATERAL (
      SELECT object_entry.value, object_entry.key AS key_name
      FROM jsonb_each(
        CASE WHEN jsonb_typeof(parent.value) = 'object'
          THEN parent.value ELSE '{}'::jsonb END
      ) AS object_entry
      UNION ALL
      SELECT array_entry.value, NULL::text
      FROM jsonb_array_elements(
        CASE WHEN jsonb_typeof(parent.value) = 'array'
          THEN parent.value ELSE '[]'::jsonb END
      ) AS array_entry(value)
    ) AS child
    WHERE parent.depth <= 32
  )
  SELECT count(*), coalesce(max(depth), 0),
         coalesce(bool_or(
           key_name IS NOT NULL
           AND NOT app.audit_json_key_value_safe_v1(key_name, value)
         ), false)
  INTO node_count, deepest, unsafe_value
  FROM nodes;

  RETURN node_count <= 8192 AND deepest <= 32 AND NOT unsafe_value;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.guard_audit_json_documents_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF NOT app.audit_json_document_safe_v1(NEW.before, 65536, true)
     OR NOT app.audit_json_document_safe_v1(NEW.after, 65536, true)
     OR NOT app.audit_json_document_safe_v1(NEW.metadata, 16384, false) THEN
    RAISE EXCEPTION 'audit document violates recursive redaction or size limits'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.audit_json_key_value_safe_v1(text, jsonb)
  OWNER TO periapsis_migrator;
--> statement-breakpoint
ALTER FUNCTION app.audit_json_document_safe_v1(jsonb, integer, boolean)
  OWNER TO periapsis_migrator;
--> statement-breakpoint
ALTER FUNCTION app.guard_audit_json_documents_v1()
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.audit_json_key_value_safe_v1(text, jsonb),
  app.audit_json_document_safe_v1(jsonb, integer, boolean),
  app.guard_audit_json_documents_v1()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner;
--> statement-breakpoint

DO $historical_audit_redaction$
BEGIN
  IF EXISTS (
    SELECT 1 FROM public.audit_events AS event
    WHERE NOT app.audit_json_document_safe_v1(event.before, 65536, true)
       OR NOT app.audit_json_document_safe_v1(event.after, 65536, true)
       OR NOT app.audit_json_document_safe_v1(event.metadata, 16384, false)
  ) OR EXISTS (
    SELECT 1 FROM public.platform_audit_events AS event
    WHERE NOT app.audit_json_document_safe_v1(event.before, 65536, true)
       OR NOT app.audit_json_document_safe_v1(event.after, 65536, true)
       OR NOT app.audit_json_document_safe_v1(event.metadata, 16384, false)
  ) THEN
    RAISE EXCEPTION 'historical audit document violates recursive redaction or size limits'
      USING ERRCODE = '23514';
  END IF;
END
$historical_audit_redaction$;
--> statement-breakpoint
CREATE TRIGGER audit_events_json_documents_guard_v1
BEFORE INSERT ON public.audit_events
FOR EACH ROW EXECUTE FUNCTION app.guard_audit_json_documents_v1();
--> statement-breakpoint
CREATE TRIGGER platform_audit_events_json_documents_guard_v1
BEFORE INSERT ON public.platform_audit_events
FOR EACH ROW EXECUTE FUNCTION app.guard_audit_json_documents_v1();
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.append_tenant_authorization_audit(
  p_event_id uuid,
  p_action text,
  p_resource_type text,
  p_resource_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text,
  p_before jsonb,
  p_after jsonb,
  p_metadata jsonb
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_id uuid := app.context_user_id();
BEGIN
  PERFORM app.current_tenant_membership_id();
  IF p_action IS NULL OR length(p_action) NOT BETWEEN 1 AND 128
     OR p_action !~ '^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)*$'
     OR p_resource_type IS NULL
     OR length(p_resource_type) NOT BETWEEN 1 AND 128
     OR p_resource_type !~ '^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)*$'
     OR p_user_agent IS NULL OR length(p_user_agent) NOT BETWEEN 1 AND 1024
     OR p_authentication_method NOT IN (
       'bootstrap_totp', 'totp', 'recovery_code', 'ldap',
       'oidc', 'saml', 'passkey'
     ) THEN
    RAISE EXCEPTION 'tenant audit envelope is invalid' USING ERRCODE = '22023';
  END IF;

  INSERT INTO public.audit_events (
    id, tenant_id, sequence, actor_type, actor_user_id, action,
    resource_type, resource_id, request_id, correlation_id,
    ip_address, user_agent, authentication_method, outcome,
    before, after, metadata
  ) VALUES (
    p_event_id, context_tenant, 0, 'user', actor_id, p_action,
    p_resource_type, p_resource_id, p_request_id, p_correlation_id,
    p_ip_address, p_user_agent, p_authentication_method, 'success',
    p_before, p_after, coalesce(p_metadata, '{}'::jsonb)
  );
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.append_tenant_authorization_audit(
  uuid, text, text, uuid, uuid, uuid, inet, text, text,
  jsonb, jsonb, jsonb
) OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.append_tenant_authorization_audit(
  uuid, text, text, uuid, uuid, uuid, inet, text, text,
  jsonb, jsonb, jsonb
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.append_tenant_authorization_audit(
  uuid, text, text, uuid, uuid, uuid, inet, text, text,
  jsonb, jsonb, jsonb
) TO periapsis_audit_reader_owner;
--> statement-breakpoint

CREATE FUNCTION app.require_live_audit_session_v1(
  p_session_id uuid,
  p_expected_tenant_id uuid
)
RETURNS text
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  live_authentication_method text;
BEGIN
  IF p_session_id IS NULL
     OR (uuid_extract_version(p_session_id) = 7) IS NOT TRUE
     OR (p_expected_tenant_id IS NOT NULL
       AND (uuid_extract_version(p_expected_tenant_id) = 7) IS NOT TRUE) THEN
    RAISE EXCEPTION 'live audit session is required' USING ERRCODE = '42501';
  END IF;

  SELECT session.authentication_method
  INTO live_authentication_method
  FROM public.auth_sessions AS session
  JOIN public.users AS identity ON identity.id = session.user_id
  LEFT JOIN public.tenants AS tenant
    ON tenant.id = p_expected_tenant_id
  LEFT JOIN public.tenant_memberships AS membership
    ON membership.tenant_id = p_expected_tenant_id
   AND membership.user_id = session.user_id
  WHERE session.id = p_session_id
    AND session.user_id = app.context_user_id()
    AND session.revoked_at IS NULL
    AND session.created_at <= transaction_timestamp()
    AND session.last_seen_at <= transaction_timestamp()
    AND session.idle_expires_at > transaction_timestamp()
    AND session.absolute_expires_at > transaction_timestamp()
    AND session.mfa_satisfied_at IS NOT NULL
    AND session.mfa_satisfied_at <= transaction_timestamp()
    AND identity.active
    AND (
      p_expected_tenant_id IS NULL
      OR (
        session.active_tenant_id = p_expected_tenant_id
        AND tenant.status = 'active'
        AND membership.status = 'active'
      )
    );

  IF live_authentication_method IS NULL
     OR live_authentication_method NOT IN (
       'bootstrap_totp', 'totp', 'recovery_code', 'ldap',
       'oidc', 'saml', 'passkey'
     ) THEN
    RAISE EXCEPTION 'live audit session is required' USING ERRCODE = '42501';
  END IF;
  RETURN live_authentication_method;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.require_live_audit_session_v1(uuid, uuid)
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.require_live_audit_session_v1(uuid, uuid)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.require_live_audit_session_v1(uuid, uuid)
TO periapsis_audit_reader_owner;
--> statement-breakpoint

CREATE FUNCTION app.list_tenant_audit_events_v1(
  p_session_id uuid,
  p_permission text,
  p_after_sequence bigint,
  p_limit integer,
  p_occurred_from timestamp with time zone,
  p_occurred_before timestamp with time zone,
  p_actor_type public.audit_actor_type,
  p_actor_user_id uuid,
  p_actor_service_account_id uuid,
  p_action_prefix text,
  p_resource_type text,
  p_resource_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_outcome public.audit_outcome,
  p_search text,
  p_access_audit_id uuid,
  p_access_request_id uuid,
  p_access_correlation_id uuid,
  p_access_ip_address inet,
  p_access_user_agent text
)
RETURNS SETOF public.audit_events
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  authentication_method text;
  returned_count integer;
  filters_applied integer;
BEGIN
  IF p_permission IS DISTINCT FROM 'audit.read'
     OR p_after_sequence IS NULL OR p_after_sequence < 0
     OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 101
     OR (p_occurred_from IS NOT NULL AND p_occurred_before IS NOT NULL
       AND p_occurred_from >= p_occurred_before)
     OR (p_actor_user_id IS NOT NULL AND p_actor_service_account_id IS NOT NULL)
     OR (p_actor_type = 'user' AND p_actor_service_account_id IS NOT NULL)
     OR (p_actor_type = 'service_account' AND p_actor_user_id IS NOT NULL)
     OR (p_actor_type = 'system'
       AND (p_actor_user_id IS NOT NULL OR p_actor_service_account_id IS NOT NULL))
     OR (p_action_prefix IS NOT NULL AND (
       length(p_action_prefix) NOT BETWEEN 1 AND 128
       OR p_action_prefix !~ '^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)*$'
     ))
     OR (p_resource_type IS NOT NULL AND (
       length(p_resource_type) NOT BETWEEN 1 AND 128
       OR p_resource_type !~ '^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)*$'
     ))
     OR (p_search IS NOT NULL AND (
       length(p_search) NOT BETWEEN 1 AND 256 OR p_search ~ '[[:cntrl:]]'
     ))
     OR (uuid_extract_version(p_access_audit_id) = 7) IS NOT TRUE
     OR (uuid_extract_version(p_access_request_id) = 7) IS NOT TRUE
     OR (uuid_extract_version(p_access_correlation_id) = 7) IS NOT TRUE
     OR p_access_ip_address IS NULL
     OR p_access_user_agent IS NULL
     OR length(p_access_user_agent) NOT BETWEEN 1 AND 1024 THEN
    RAISE EXCEPTION 'invalid tenant audit read' USING ERRCODE = '22023';
  END IF;

  authentication_method := app.require_live_audit_session_v1(
    p_session_id, context_tenant
  );
  IF NOT app.current_tenant_human_has_exact_permission_v3(
    'audit.read', 'tenant'
  ) THEN
    RAISE EXCEPTION 'audit.read tenant scope is required'
      USING ERRCODE = '42501';
  END IF;

  RETURN QUERY
  SELECT event.*
  FROM public.audit_events AS event
  WHERE event.tenant_id = context_tenant
    AND event.sequence > p_after_sequence
    AND (p_occurred_from IS NULL OR event.occurred_at >= p_occurred_from)
    AND (p_occurred_before IS NULL OR event.occurred_at < p_occurred_before)
    AND (p_actor_type IS NULL OR event.actor_type = p_actor_type)
    AND (p_actor_user_id IS NULL OR event.actor_user_id = p_actor_user_id)
    AND (p_actor_service_account_id IS NULL
      OR event.actor_service_account_id = p_actor_service_account_id)
    AND (p_action_prefix IS NULL OR event.action = p_action_prefix
      OR left(event.action, length(p_action_prefix) + 1) = p_action_prefix || '.')
    AND (p_resource_type IS NULL OR event.resource_type = p_resource_type)
    AND (p_resource_id IS NULL OR event.resource_id = p_resource_id)
    AND (p_request_id IS NULL OR event.request_id = p_request_id)
    AND (p_correlation_id IS NULL OR event.correlation_id = p_correlation_id)
    AND (p_outcome IS NULL OR event.outcome = p_outcome)
    AND (p_search IS NULL
      OR position(lower(p_search) IN lower(event.action)) > 0
      OR position(lower(p_search) IN lower(event.resource_type)) > 0
      OR position(lower(p_search) IN lower(coalesce(event.reason, ''))) > 0)
  ORDER BY event.sequence
  LIMIT p_limit;
  GET DIAGNOSTICS returned_count = ROW_COUNT;

  filters_applied := num_nonnulls(
    p_occurred_from, p_occurred_before, p_actor_type, p_actor_user_id,
    p_actor_service_account_id, p_action_prefix, p_resource_type,
    p_resource_id, p_request_id, p_correlation_id, p_outcome, p_search
  );
  PERFORM app.append_tenant_authorization_audit(
    p_access_audit_id, 'audit.accessed', 'audit_log', context_tenant,
    p_access_request_id, p_access_correlation_id, p_access_ip_address,
    p_access_user_agent, authentication_method, NULL, NULL,
    jsonb_build_object(
      'afterSequence', p_after_sequence,
      'limit', p_limit,
      'returnedCount', returned_count,
      'filtersApplied', filters_applied
    )
  );
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.list_platform_audit_events_v1(
  p_session_id uuid,
  p_permission text,
  p_after_sequence bigint,
  p_limit integer,
  p_occurred_from timestamp with time zone,
  p_occurred_before timestamp with time zone,
  p_actor_type public.audit_actor_type,
  p_actor_user_id uuid,
  p_action_prefix text,
  p_resource_type text,
  p_resource_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_outcome public.audit_outcome,
  p_search text,
  p_access_audit_id uuid,
  p_access_request_id uuid,
  p_access_correlation_id uuid,
  p_access_ip_address inet,
  p_access_user_agent text
)
RETURNS SETOF public.platform_audit_events
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor_id uuid := app.context_user_id();
  authentication_method text;
  returned_count integer;
  filters_applied integer;
BEGIN
  IF p_permission IS DISTINCT FROM 'platform.audit.read'
     OR p_after_sequence IS NULL OR p_after_sequence < 0
     OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 101
     OR (p_occurred_from IS NOT NULL AND p_occurred_before IS NOT NULL
       AND p_occurred_from >= p_occurred_before)
     OR (p_actor_type = 'service_account')
     OR (p_actor_type IN ('system', 'service_account')
       AND p_actor_user_id IS NOT NULL)
     OR (p_action_prefix IS NOT NULL AND (
       length(p_action_prefix) NOT BETWEEN 1 AND 128
       OR p_action_prefix !~ '^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)*$'
     ))
     OR (p_resource_type IS NOT NULL AND (
       length(p_resource_type) NOT BETWEEN 1 AND 128
       OR p_resource_type !~ '^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)*$'
     ))
     OR (p_search IS NOT NULL AND (
       length(p_search) NOT BETWEEN 1 AND 256 OR p_search ~ '[[:cntrl:]]'
     ))
     OR (uuid_extract_version(p_access_audit_id) = 7) IS NOT TRUE
     OR (uuid_extract_version(p_access_request_id) = 7) IS NOT TRUE
     OR (uuid_extract_version(p_access_correlation_id) = 7) IS NOT TRUE
     OR p_access_ip_address IS NULL
     OR p_access_user_agent IS NULL
     OR length(p_access_user_agent) NOT BETWEEN 1 AND 1024 THEN
    RAISE EXCEPTION 'invalid platform audit read' USING ERRCODE = '22023';
  END IF;

  authentication_method := app.require_live_audit_session_v1(
    p_session_id, NULL
  );
  IF NOT app.platform_user_has_permission(actor_id, 'platform.audit.read') THEN
    RAISE EXCEPTION 'platform.audit.read permission is required'
      USING ERRCODE = '42501';
  END IF;

  RETURN QUERY
  SELECT event.*
  FROM public.platform_audit_events AS event
  WHERE event.sequence > p_after_sequence
    AND (p_occurred_from IS NULL OR event.occurred_at >= p_occurred_from)
    AND (p_occurred_before IS NULL OR event.occurred_at < p_occurred_before)
    AND (p_actor_type IS NULL OR event.actor_type = p_actor_type)
    AND (p_actor_user_id IS NULL OR event.actor_user_id = p_actor_user_id)
    AND (p_action_prefix IS NULL OR event.action = p_action_prefix
      OR left(event.action, length(p_action_prefix) + 1) = p_action_prefix || '.')
    AND (p_resource_type IS NULL OR event.resource_type = p_resource_type)
    AND (p_resource_id IS NULL OR event.resource_id = p_resource_id)
    AND (p_request_id IS NULL OR event.request_id = p_request_id)
    AND (p_correlation_id IS NULL OR event.correlation_id = p_correlation_id)
    AND (p_outcome IS NULL OR event.outcome = p_outcome)
    AND (p_search IS NULL
      OR position(lower(p_search) IN lower(event.action)) > 0
      OR position(lower(p_search) IN lower(event.resource_type)) > 0
      OR position(lower(p_search) IN lower(coalesce(event.reason, ''))) > 0)
  ORDER BY event.sequence
  LIMIT p_limit;
  GET DIAGNOSTICS returned_count = ROW_COUNT;

  filters_applied := num_nonnulls(
    p_occurred_from, p_occurred_before, p_actor_type, p_actor_user_id,
    p_action_prefix, p_resource_type, p_resource_id, p_request_id,
    p_correlation_id, p_outcome, p_search
  );
  PERFORM app.append_platform_audit_event(
    p_access_audit_id, 'user', actor_id, 'audit.accessed',
    'platform_audit_log', NULL, p_access_request_id,
    p_access_correlation_id, p_access_ip_address, p_access_user_agent,
    authentication_method, 'success', NULL,
    jsonb_build_object(
      'afterSequence', p_after_sequence,
      'limit', p_limit,
      'returnedCount', returned_count,
      'filtersApplied', filters_applied
    )
  );
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.verify_tenant_audit_chain_v1(
  p_session_id uuid,
  p_permission text,
  p_access_audit_id uuid,
  p_access_request_id uuid,
  p_access_correlation_id uuid,
  p_access_ip_address inet,
  p_access_user_agent text,
  p_tenant_id uuid
)
RETURNS TABLE (
  event_count bigint,
  last_sequence bigint,
  first_invalid_sequence bigint,
  head_valid boolean,
  valid boolean,
  verified_at timestamp with time zone
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  authentication_method text;
  result_event_count bigint;
  result_last_sequence bigint;
  result_first_invalid_sequence bigint;
  result_head_valid boolean;
  result_valid boolean;
  result_verified_at timestamp with time zone := transaction_timestamp();
  result_last_hash character(64);
BEGIN
  IF p_permission IS DISTINCT FROM 'audit.read'
     OR p_tenant_id IS DISTINCT FROM context_tenant
     OR (uuid_extract_version(p_access_audit_id) = 7) IS NOT TRUE
     OR (uuid_extract_version(p_access_request_id) = 7) IS NOT TRUE
     OR (uuid_extract_version(p_access_correlation_id) = 7) IS NOT TRUE
     OR p_access_ip_address IS NULL
     OR p_access_user_agent IS NULL
     OR length(p_access_user_agent) NOT BETWEEN 1 AND 1024 THEN
    RAISE EXCEPTION 'invalid tenant audit verification'
      USING ERRCODE = '22023';
  END IF;
  authentication_method := app.require_live_audit_session_v1(
    p_session_id, context_tenant
  );
  IF NOT app.current_tenant_human_has_exact_permission_v3(
    'audit.read', 'tenant'
  ) THEN
    RAISE EXCEPTION 'audit.read tenant scope is required'
      USING ERRCODE = '42501';
  END IF;

  WITH ordered AS (
    SELECT event AS event_record, event.sequence, event.event_hash,
           event.previous_hash,
           row_number() OVER (ORDER BY event.sequence) AS expected_sequence,
           lag(event.event_hash, 1, repeat('0', 64)::character(64))
             OVER (ORDER BY event.sequence) AS expected_previous_hash
    FROM public.audit_events AS event
    WHERE event.tenant_id = context_tenant
  ),
  checked AS (
    SELECT ordered.*,
           (
             ordered.sequence = ordered.expected_sequence
             AND ordered.previous_hash = ordered.expected_previous_hash
             AND ordered.event_hash = app.calculate_audit_event_hash(
               ordered.event_record, ordered.expected_previous_hash
             )
           ) IS TRUE AS row_valid
    FROM ordered
  ),
  summary AS (
    SELECT count(*)::bigint AS event_count,
           coalesce(max(sequence), 0)::bigint AS last_sequence,
           min(sequence) FILTER (WHERE NOT row_valid) AS first_invalid_sequence,
           coalesce((array_agg(event_hash ORDER BY sequence DESC))[1],
             repeat('0', 64)::character(64)) AS last_hash
    FROM checked
  )
  SELECT summary.event_count, summary.last_sequence,
         summary.first_invalid_sequence, summary.last_hash,
         EXISTS (
           SELECT 1 FROM public.audit_chain_heads AS head
           WHERE head.tenant_id = context_tenant
             AND head.last_sequence = summary.last_sequence
             AND head.last_event_hash = summary.last_hash
         )
  INTO result_event_count, result_last_sequence,
       result_first_invalid_sequence, result_last_hash, result_head_valid
  FROM summary;

  result_valid := result_head_valid
    AND result_first_invalid_sequence IS NULL
    AND result_event_count = result_last_sequence;

  PERFORM app.append_tenant_authorization_audit(
    p_access_audit_id, 'audit.chain_verified', 'audit_log', context_tenant,
    p_access_request_id, p_access_correlation_id, p_access_ip_address,
    p_access_user_agent, authentication_method, NULL, NULL,
    jsonb_build_object(
      'eventCount', result_event_count,
      'lastSequence', result_last_sequence,
      'firstInvalidSequence', result_first_invalid_sequence,
      'headValid', result_head_valid,
      'valid', result_valid
    )
  );

  RETURN QUERY SELECT result_event_count, result_last_sequence,
    result_first_invalid_sequence, result_head_valid, result_valid,
    result_verified_at;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.verify_platform_audit_chain_v1(
  p_session_id uuid,
  p_permission text,
  p_access_audit_id uuid,
  p_access_request_id uuid,
  p_access_correlation_id uuid,
  p_access_ip_address inet,
  p_access_user_agent text
)
RETURNS TABLE (
  event_count bigint,
  last_sequence bigint,
  first_invalid_sequence bigint,
  head_valid boolean,
  valid boolean,
  verified_at timestamp with time zone
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor_id uuid := app.context_user_id();
  authentication_method text;
  result_event_count bigint;
  result_last_sequence bigint;
  result_first_invalid_sequence bigint;
  result_head_valid boolean;
  result_valid boolean;
  result_verified_at timestamp with time zone := transaction_timestamp();
  result_last_hash character(64);
BEGIN
  IF p_permission IS DISTINCT FROM 'platform.audit.read'
     OR (uuid_extract_version(p_access_audit_id) = 7) IS NOT TRUE
     OR (uuid_extract_version(p_access_request_id) = 7) IS NOT TRUE
     OR (uuid_extract_version(p_access_correlation_id) = 7) IS NOT TRUE
     OR p_access_ip_address IS NULL
     OR p_access_user_agent IS NULL
     OR length(p_access_user_agent) NOT BETWEEN 1 AND 1024 THEN
    RAISE EXCEPTION 'invalid platform audit verification'
      USING ERRCODE = '22023';
  END IF;
  authentication_method := app.require_live_audit_session_v1(
    p_session_id, NULL
  );
  IF NOT app.platform_user_has_permission(actor_id, 'platform.audit.read') THEN
    RAISE EXCEPTION 'platform.audit.read permission is required'
      USING ERRCODE = '42501';
  END IF;

  WITH ordered AS (
    SELECT event AS event_record, event.sequence, event.event_hash,
           event.previous_hash,
           row_number() OVER (ORDER BY event.sequence) AS expected_sequence,
           lag(event.event_hash, 1, repeat('0', 64)::character(64))
             OVER (ORDER BY event.sequence) AS expected_previous_hash
    FROM public.platform_audit_events AS event
  ),
  checked AS (
    SELECT ordered.*,
           (
             ordered.sequence = ordered.expected_sequence
             AND ordered.previous_hash = ordered.expected_previous_hash
             AND ordered.event_hash = app.calculate_platform_audit_event_hash(
               ordered.event_record, ordered.expected_previous_hash
             )
           ) IS TRUE AS row_valid
    FROM ordered
  ),
  summary AS (
    SELECT count(*)::bigint AS event_count,
           coalesce(max(sequence), 0)::bigint AS last_sequence,
           min(sequence) FILTER (WHERE NOT row_valid) AS first_invalid_sequence,
           coalesce((array_agg(event_hash ORDER BY sequence DESC))[1],
             repeat('0', 64)::character(64)) AS last_hash
    FROM checked
  )
  SELECT summary.event_count, summary.last_sequence,
         summary.first_invalid_sequence, summary.last_hash,
         EXISTS (
           SELECT 1 FROM public.platform_audit_chain_head AS head
           WHERE head.singleton
             AND head.last_sequence = summary.last_sequence
             AND head.last_event_hash = summary.last_hash
         )
  INTO result_event_count, result_last_sequence,
       result_first_invalid_sequence, result_last_hash, result_head_valid
  FROM summary;

  result_valid := result_head_valid
    AND result_first_invalid_sequence IS NULL
    AND result_event_count = result_last_sequence;

  PERFORM app.append_platform_audit_event(
    p_access_audit_id, 'user', actor_id, 'audit.chain_verified',
    'platform_audit_log', NULL, p_access_request_id,
    p_access_correlation_id, p_access_ip_address, p_access_user_agent,
    authentication_method, 'success', NULL,
    jsonb_build_object(
      'eventCount', result_event_count,
      'lastSequence', result_last_sequence,
      'firstInvalidSequence', result_first_invalid_sequence,
      'headValid', result_head_valid,
      'valid', result_valid
    )
  );

  RETURN QUERY SELECT result_event_count, result_last_sequence,
    result_first_invalid_sequence, result_head_valid, result_valid,
    result_verified_at;
END;
$function$;
--> statement-breakpoint

ALTER FUNCTION app.list_tenant_audit_events_v1(
  uuid, text, bigint, integer, timestamp with time zone,
  timestamp with time zone, public.audit_actor_type, uuid, uuid, text,
  text, uuid, uuid, uuid, public.audit_outcome, text, uuid, uuid, uuid,
  inet, text
) OWNER TO periapsis_audit_reader_owner;
--> statement-breakpoint
ALTER FUNCTION app.list_platform_audit_events_v1(
  uuid, text, bigint, integer, timestamp with time zone,
  timestamp with time zone, public.audit_actor_type, uuid, text, text,
  uuid, uuid, uuid, public.audit_outcome, text, uuid, uuid, uuid, inet, text
) OWNER TO periapsis_audit_reader_owner;
--> statement-breakpoint
ALTER FUNCTION app.verify_tenant_audit_chain_v1(
  uuid, text, uuid, uuid, uuid, inet, text, uuid
) OWNER TO periapsis_audit_reader_owner;
--> statement-breakpoint
ALTER FUNCTION app.verify_platform_audit_chain_v1(
  uuid, text, uuid, uuid, uuid, inet, text
) OWNER TO periapsis_audit_reader_owner;
--> statement-breakpoint

REVOKE ALL ON FUNCTION app.list_tenant_audit_events_v1(
  uuid, text, bigint, integer, timestamp with time zone,
  timestamp with time zone, public.audit_actor_type, uuid, uuid, text,
  text, uuid, uuid, uuid, public.audit_outcome, text, uuid, uuid, uuid,
  inet, text
), app.list_platform_audit_events_v1(
  uuid, text, bigint, integer, timestamp with time zone,
  timestamp with time zone, public.audit_actor_type, uuid, text, text,
  uuid, uuid, uuid, public.audit_outcome, text, uuid, uuid, uuid, inet, text
), app.verify_tenant_audit_chain_v1(
  uuid, text, uuid, uuid, uuid, inet, text, uuid
), app.verify_platform_audit_chain_v1(
  uuid, text, uuid, uuid, uuid, inet, text
)
FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.list_tenant_audit_events_v1(
  uuid, text, bigint, integer, timestamp with time zone,
  timestamp with time zone, public.audit_actor_type, uuid, uuid, text,
  text, uuid, uuid, uuid, public.audit_outcome, text, uuid, uuid, uuid,
  inet, text
), app.list_platform_audit_events_v1(
  uuid, text, bigint, integer, timestamp with time zone,
  timestamp with time zone, public.audit_actor_type, uuid, text, text,
  uuid, uuid, uuid, public.audit_outcome, text, uuid, uuid, uuid, inet, text
), app.verify_tenant_audit_chain_v1(
  uuid, text, uuid, uuid, uuid, inet, text, uuid
), app.verify_platform_audit_chain_v1(
  uuid, text, uuid, uuid, uuid, inet, text
)
TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.schema_compatibility_v20()
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
  migration_0103_rows bigint;
BEGIN
  EXECUTE $query$
    SELECT count(*)::bigint, max(migration.created_at)::bigint,
           count(*) FILTER (
             WHERE migration.created_at = 1787693815749
           )::bigint
    FROM drizzle.__drizzle_migrations AS migration
  $query$ INTO journal_count, journal_latest_created_at, migration_0103_rows;
  IF journal_count = 104
     AND journal_latest_created_at = 1787693815749
     AND migration_0103_rows = 1 THEN
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
ALTER FUNCTION app.schema_compatibility_v20()
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.schema_compatibility_v20()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor, periapsis_audit_reader_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v20()
  TO periapsis_api, periapsis_worker;
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
  FROM app.schema_compatibility_v20() AS compatibility;
  IF full_count = 104
     AND full_latest_created_at = 1787693815749
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
              WHERE prefix.migration_ordinal = 103),
             string_agg(
               migration.created_at::text || '@' || migration.migration_hash,
               ':' ORDER BY migration.created_at, migration.id
             )
      FROM ordered_migrations AS migration
      WHERE migration.migration_ordinal <= 103
    $query$;
    RETURN;
  END IF;
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
       periapsis_auditor, periapsis_audit_reader_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v19()
  TO periapsis_api, periapsis_worker;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.schema_compatibility_v18()
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
ALTER FUNCTION app.schema_compatibility_v18()
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.schema_compatibility_v18()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor, periapsis_audit_reader_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v18()
  TO periapsis_api, periapsis_worker;
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
  IF p_expected_count IS DISTINCT FROM 104
     OR p_expected_latest_created_at IS DISTINCT FROM 1787693815749
     OR p_expected_latest_hash IS NULL
     OR p_expected_latest_hash !~ '^[0-9a-f]{64}$'
     OR p_expected_migration_fingerprint IS NULL
     OR p_expected_migration_fingerprint !~
          '^[1-9][0-9]*@[0-9a-f]{64}(:[1-9][0-9]*@[0-9a-f]{64})*$'
     OR cardinality(fingerprint_entries) IS DISTINCT FROM 104
     OR fingerprint_entries[104] IS DISTINCT FROM (
       p_expected_latest_created_at::text || '@' || p_expected_latest_hash
     ) THEN
    RAISE EXCEPTION 'invalid schema compatibility v20 manifest'
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
    1787686749137, 1787689670779, 1787692062461, 1787693815749
  ]::bigint[] THEN
    RAISE EXCEPTION 'invalid schema compatibility v20 timestamp sequence'
      USING ERRCODE = '22023';
  END IF;

  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
  INTO actual_count, actual_latest_created_at, actual_latest_hash,
       actual_fingerprint
  FROM app.schema_compatibility_v20() AS compatibility;
  IF actual_count IS DISTINCT FROM p_expected_count
     OR actual_latest_created_at IS DISTINCT FROM p_expected_latest_created_at
     OR actual_latest_hash IS DISTINCT FROM p_expected_latest_hash
     OR actual_fingerprint IS DISTINCT FROM p_expected_migration_fingerprint THEN
    RAISE EXCEPTION 'schema compatibility v20 manifest does not match the applied journal'
      USING ERRCODE = '55000';
  END IF;

  PERFORM set_config(
    'app.schema_compatibility_fingerprint',
    p_expected_migration_fingerprint, true
  );
  EXECUTE $statement$
    ALTER FUNCTION app.schema_compatibility_v19()
      SET app.schema_compatibility_fingerprint FROM CURRENT
  $statement$;
  expected_predecessor_hash := split_part(fingerprint_entries[103], '@', 2);
  expected_predecessor_fingerprint := array_to_string(
    fingerprint_entries[1:103], ':'
  );
  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
  INTO predecessor_count, predecessor_latest_created_at,
       predecessor_latest_hash, predecessor_fingerprint
  FROM app.schema_compatibility_v19() AS compatibility;
  IF predecessor_count IS DISTINCT FROM 103
     OR predecessor_latest_created_at IS DISTINCT FROM 1787692062461
     OR predecessor_latest_hash IS DISTINCT FROM expected_predecessor_hash
     OR predecessor_fingerprint IS DISTINCT FROM expected_predecessor_fingerprint THEN
    RAISE EXCEPTION 'sealed schema compatibility v19 prefix is not exact'
      USING ERRCODE = '55000';
  END IF;
  SELECT compatibility.applied_count INTO retired_count
  FROM app.schema_compatibility_v18() AS compatibility;
  IF retired_count IS DISTINCT FROM 0 THEN
    RAISE EXCEPTION 'schema compatibility v18 must be retired'
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
       periapsis_auditor, periapsis_audit_reader_owner;
--> statement-breakpoint

CREATE FUNCTION app.audit_reader_schema_readiness_v1()
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
  append_definition text;
  expected_index text;
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_roles AS role
    WHERE role.rolname = 'periapsis_audit_reader_owner'
      AND NOT role.rolcanlogin AND NOT role.rolsuper
      AND NOT role.rolcreatedb AND NOT role.rolcreaterole
      AND NOT role.rolinherit AND NOT role.rolreplication
      AND NOT role.rolbypassrls
  ) THEN
    RETURN false;
  END IF;
  IF EXISTS (
    SELECT 1
    FROM (VALUES
      ('audit_events'), ('audit_chain_heads'),
      ('platform_audit_events'), ('platform_audit_chain_head')
    ) AS expected(table_name)
    LEFT JOIN pg_class AS table_row
      ON table_row.relname = expected.table_name
    LEFT JOIN pg_namespace AS namespace
      ON namespace.oid = table_row.relnamespace
     AND namespace.nspname = 'public'
    WHERE table_row.oid IS NULL OR namespace.oid IS NULL
       OR NOT table_row.relrowsecurity OR NOT table_row.relforcerowsecurity
       OR pg_get_userbyid(table_row.relowner) <> 'periapsis_migrator'
  ) THEN
    RETURN false;
  END IF;
  IF EXISTS (
    SELECT 1
    FROM (VALUES
      ('audit_events'), ('audit_chain_heads'),
      ('platform_audit_events'), ('platform_audit_chain_head')
    ) AS expected(table_name)
    CROSS JOIN (VALUES
      ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE'), ('TRUNCATE'),
      ('REFERENCES'), ('TRIGGER')
    ) AS privilege(privilege_name)
    WHERE has_table_privilege(
      'periapsis_api', 'public.' || expected.table_name,
      privilege.privilege_name
    )
  ) OR EXISTS (
    SELECT 1
    FROM (VALUES
      ('audit_events'), ('audit_chain_heads'),
      ('platform_audit_events'), ('platform_audit_chain_head')
    ) AS expected(table_name)
    CROSS JOIN (VALUES
      ('INSERT'), ('UPDATE'), ('DELETE'), ('TRUNCATE'),
      ('REFERENCES'), ('TRIGGER')
    ) AS privilege(privilege_name)
    WHERE has_table_privilege(
      'periapsis_audit_reader_owner', 'public.' || expected.table_name,
      privilege.privilege_name
    )
  ) OR EXISTS (
    SELECT 1
    FROM (VALUES
      ('audit_events'), ('audit_chain_heads'),
      ('platform_audit_events'), ('platform_audit_chain_head')
    ) AS expected(table_name)
    WHERE NOT has_table_privilege(
      'periapsis_audit_reader_owner', 'public.' || expected.table_name,
      'SELECT'
    )
  ) THEN
    RETURN false;
  END IF;
  IF EXISTS (
    SELECT 1
    FROM (VALUES
      ('app.list_tenant_audit_events_v1(uuid,text,bigint,integer,timestamp with time zone,timestamp with time zone,public.audit_actor_type,uuid,uuid,text,text,uuid,uuid,uuid,public.audit_outcome,text,uuid,uuid,uuid,inet,text)'),
      ('app.list_platform_audit_events_v1(uuid,text,bigint,integer,timestamp with time zone,timestamp with time zone,public.audit_actor_type,uuid,text,text,uuid,uuid,uuid,public.audit_outcome,text,uuid,uuid,uuid,inet,text)'),
      ('app.verify_tenant_audit_chain_v1(uuid,text,uuid,uuid,uuid,inet,text,uuid)'),
      ('app.verify_platform_audit_chain_v1(uuid,text,uuid,uuid,uuid,inet,text)')
    ) AS expected(signature)
    LEFT JOIN pg_proc AS procedure
      ON procedure.oid = to_regprocedure(expected.signature)
    WHERE procedure.oid IS NULL OR NOT procedure.prosecdef
       OR procedure.provolatile <> 'v'
       OR pg_get_userbyid(procedure.proowner) <> 'periapsis_audit_reader_owner'
       OR procedure.proconfig IS DISTINCT FROM
          ARRAY['search_path=pg_catalog, public, app']::text[]
  ) THEN
    RETURN false;
  END IF;
  IF has_function_privilege(
    'periapsis_api',
    'app.append_tenant_authorization_audit(uuid,text,text,uuid,uuid,uuid,inet,text,text,jsonb,jsonb,jsonb)',
    'EXECUTE'
  ) OR has_function_privilege(
    'periapsis_api',
    'app.append_platform_audit_event(uuid,public.audit_actor_type,uuid,text,text,uuid,uuid,uuid,inet,text,text,public.audit_outcome,text,jsonb)',
    'EXECUTE'
  ) OR has_function_privilege(
    'periapsis_api', 'app.require_live_audit_session_v1(uuid,uuid)',
    'EXECUTE'
  ) THEN
    RETURN false;
  END IF;
  IF NOT has_function_privilege(
    'periapsis_audit_reader_owner',
    'app.audit_event_payload(public.audit_events)', 'EXECUTE'
  ) OR NOT has_function_privilege(
    'periapsis_audit_reader_owner',
    'app.platform_audit_event_payload(public.platform_audit_events)', 'EXECUTE'
  ) OR NOT has_function_privilege(
    'periapsis_audit_reader_owner',
    'app.calculate_audit_event_hash(public.audit_events,character)',
    'EXECUTE'
  ) OR NOT has_function_privilege(
    'periapsis_audit_reader_owner',
    'app.calculate_platform_audit_event_hash(public.platform_audit_events,character)',
    'EXECUTE'
  ) THEN
    RETURN false;
  END IF;
  IF NOT has_function_privilege(
    'periapsis_api',
    'app.list_tenant_audit_events_v1(uuid,text,bigint,integer,timestamp with time zone,timestamp with time zone,public.audit_actor_type,uuid,uuid,text,text,uuid,uuid,uuid,public.audit_outcome,text,uuid,uuid,uuid,inet,text)',
    'EXECUTE'
  ) OR NOT has_function_privilege(
    'periapsis_api',
    'app.list_platform_audit_events_v1(uuid,text,bigint,integer,timestamp with time zone,timestamp with time zone,public.audit_actor_type,uuid,text,text,uuid,uuid,uuid,public.audit_outcome,text,uuid,uuid,uuid,inet,text)',
    'EXECUTE'
  ) OR NOT has_function_privilege(
    'periapsis_api',
    'app.verify_tenant_audit_chain_v1(uuid,text,uuid,uuid,uuid,inet,text,uuid)',
    'EXECUTE'
  ) OR NOT has_function_privilege(
    'periapsis_api',
    'app.verify_platform_audit_chain_v1(uuid,text,uuid,uuid,uuid,inet,text)',
    'EXECUTE'
  ) THEN
    RETURN false;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger AS trigger_row
    JOIN pg_class AS table_row ON table_row.oid = trigger_row.tgrelid
    JOIN pg_namespace AS namespace ON namespace.oid = table_row.relnamespace
    WHERE namespace.nspname = 'public'
      AND table_row.relname = 'audit_events'
      AND trigger_row.tgname = 'audit_events_json_documents_guard_v1'
      AND trigger_row.tgenabled = 'O' AND NOT trigger_row.tgisinternal
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_trigger AS trigger_row
    JOIN pg_class AS table_row ON table_row.oid = trigger_row.tgrelid
    JOIN pg_namespace AS namespace ON namespace.oid = table_row.relnamespace
    WHERE namespace.nspname = 'public'
      AND table_row.relname = 'platform_audit_events'
      AND trigger_row.tgname = 'platform_audit_events_json_documents_guard_v1'
      AND trigger_row.tgenabled = 'O' AND NOT trigger_row.tgisinternal
  ) THEN
    RETURN false;
  END IF;

  FOREACH expected_index IN ARRAY ARRAY[
    'audit_events_tenant_action_sequence_idx',
    'audit_events_tenant_outcome_sequence_idx',
    'audit_events_tenant_actor_user_sequence_idx',
    'audit_events_tenant_actor_service_sequence_idx',
    'platform_audit_events_action_sequence_idx',
    'platform_audit_events_outcome_sequence_idx',
    'platform_audit_events_actor_user_sequence_idx'
  ] LOOP
    IF NOT EXISTS (
      SELECT 1 FROM pg_index AS index_row
      JOIN pg_class AS index_class ON index_class.oid = index_row.indexrelid
      WHERE index_class.relname = expected_index
        AND index_row.indisvalid AND index_row.indisready
        AND index_row.indislive
    ) THEN
      RETURN false;
    END IF;
  END LOOP;

  SELECT pg_get_functiondef(
    to_regprocedure('app.seed_tenant_authorization(uuid,uuid)')
  ) INTO seed_definition;
  SELECT pg_get_functiondef(
    to_regprocedure('app.append_tenant_authorization_audit(uuid,text,text,uuid,uuid,uuid,inet,text,text,jsonb,jsonb,jsonb)')
  ) INTO append_definition;
  IF seed_definition IS NULL
     OR seed_definition NOT LIKE
          '%seed_tenant_authorization_audit_compatibility_impl%'
     OR seed_definition NOT LIKE
          '%private_seed_tenant_audit_authorization_v1%'
     OR append_definition IS NULL
     OR append_definition NOT LIKE '%''ldap''%'
     OR append_definition NOT LIKE '%''oidc''%'
     OR append_definition NOT LIKE '%''saml''%'
     OR append_definition NOT LIKE '%''passkey''%' THEN
    RETURN false;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM public.tenant_permissions AS permission
    JOIN public.tenant_permission_scopes AS permission_scope
      ON permission_scope.permission_id = permission.id
    WHERE permission.key = 'audit.read'
      AND NOT permission.service_account_allowed
      AND permission_scope.scope = 'tenant'
  ) OR NOT EXISTS (
    SELECT 1 FROM public.platform_permissions AS permission
    JOIN public.platform_role_permissions AS role_permission
      ON role_permission.permission_id = permission.id
    JOIN public.platform_roles AS role
      ON role.id = role_permission.role_id
    WHERE permission.key = 'platform.audit.read'
      AND role.key = 'platform_auditor' AND role.system
  ) THEN
    RETURN false;
  END IF;

  SELECT compatibility.applied_count INTO current_count
  FROM app.schema_compatibility_v20() AS compatibility;
  SELECT compatibility.applied_count INTO predecessor_count
  FROM app.schema_compatibility_v19() AS compatibility;
  SELECT compatibility.applied_count INTO retired_count
  FROM app.schema_compatibility_v18() AS compatibility;
  RETURN current_count = 104 AND predecessor_count = 103
    AND retired_count = 0;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.audit_reader_schema_readiness_v1()
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.audit_reader_schema_readiness_v1()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor, periapsis_audit_reader_owner;
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
DECLARE
  expected_index record;
  index_definition text;
  current_count bigint;
  predecessor_count bigint;
  retired_count bigint;
  seed_definition text;
BEGIN
  FOR expected_index IN
    SELECT * FROM (VALUES
      ('alerts', 'alerts_ticket_search_idx'),
      ('cases', 'cases_ticket_search_idx')
    ) AS expected(table_name, index_name)
  LOOP
    SELECT pg_get_indexdef(index_row.indexrelid)
    INTO index_definition
    FROM pg_index AS index_row
    JOIN pg_class AS table_class ON table_class.oid = index_row.indrelid
    JOIN pg_namespace AS namespace ON namespace.oid = table_class.relnamespace
    JOIN pg_class AS index_class ON index_class.oid = index_row.indexrelid
    JOIN pg_am AS access_method ON access_method.oid = index_class.relam
    WHERE namespace.nspname = 'public'
      AND table_class.relname = expected_index.table_name
      AND index_class.relname = expected_index.index_name
      AND access_method.amname = 'gin'
      AND index_row.indisvalid AND index_row.indisready
      AND index_row.indislive AND index_row.indpred IS NULL
      AND index_row.indexprs IS NOT NULL;
    IF index_definition IS NULL
       OR index_definition !~* 'to_tsvector'
       OR index_definition !~* '\mnumber\M'
       OR index_definition !~* '\mtitle\M'
       OR index_definition !~* '\mdescription\M'
       OR index_definition ~* '\m(raw_payload|custom_fields|customer_custom_fields|summary|classification|tags)\M' THEN
      RETURN false;
    END IF;
  END LOOP;

  SELECT pg_get_functiondef(
    to_regprocedure('app.seed_tenant_authorization(uuid,uuid)')
  ) INTO seed_definition;
  IF seed_definition IS NULL
     OR seed_definition NOT LIKE
          '%seed_tenant_authorization_audit_compatibility_impl%' THEN
    RETURN false;
  END IF;

  SELECT compatibility.applied_count INTO current_count
  FROM app.schema_compatibility_v20() AS compatibility;
  SELECT compatibility.applied_count INTO predecessor_count
  FROM app.schema_compatibility_v19() AS compatibility;
  SELECT compatibility.applied_count INTO retired_count
  FROM app.schema_compatibility_v18() AS compatibility;
  RETURN current_count = 104 AND predecessor_count = 103
    AND retired_count = 0;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.ticket_search_schema_readiness_v1()
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.ticket_search_schema_readiness_v1()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor, periapsis_audit_reader_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.ticket_search_schema_readiness_v1()
  TO periapsis_api, periapsis_worker;
