-- A single tenant-status predicate is shared by generated RLS policies and
-- the dedicated queue owners.  The migrator owns it so callers cannot bypass
-- tenant RLS to read lifecycle state through any broader surface.
CREATE FUNCTION app.tenant_is_active_v1(p_tenant_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
STRICT
PARALLEL SAFE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
  SELECT EXISTS (
    SELECT 1
    FROM public.tenants AS tenant
    WHERE tenant.id = p_tenant_id
      AND tenant.status = 'active'
  );
$function$;
--> statement-breakpoint
ALTER FUNCTION app.tenant_is_active_v1(uuid) OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.tenant_is_active_v1(uuid)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_notification_admin_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.tenant_is_active_v1(uuid)
TO periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_notification_admin_owner, periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner;
--> statement-breakpoint

-- Keep the predecessor session ABI safe before publishing the new permission.
-- v3 exposes the complete catalog to current binaries; v2 removes exactly the
-- lifecycle key that predecessor binaries cannot deserialize.
CREATE FUNCTION app.get_auth_session_v3(p_token_digest bytea)
RETURNS TABLE (
  session_id uuid,
  user_id uuid,
  rotation_family_id uuid,
  email text,
  display_name text,
  active_tenant_id uuid,
  csrf_secret_digest bytea,
  authentication_method text,
  mfa_satisfied_at timestamp with time zone,
  created_at timestamp with time zone,
  last_seen_at timestamp with time zone,
  idle_expires_at timestamp with time zone,
  absolute_expires_at timestamp with time zone,
  platform_permissions text[]
)
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT session.id, session.user_id, session.rotation_family_id,
         identity.email, identity.display_name, session.active_tenant_id,
         session.csrf_secret_digest, session.authentication_method,
         session.mfa_satisfied_at, session.created_at, session.last_seen_at,
         session.idle_expires_at, session.absolute_expires_at,
         ARRAY(
           SELECT DISTINCT permission.key
           FROM public.user_platform_roles AS user_role
           JOIN public.platform_role_permissions AS role_permission
             ON role_permission.role_id = user_role.role_id
           JOIN public.platform_permissions AS permission
             ON permission.id = role_permission.permission_id
           WHERE user_role.user_id = session.user_id
             AND user_role.revoked_at IS NULL
           ORDER BY permission.key
         )
  FROM public.auth_sessions AS session
  JOIN public.users AS identity ON identity.id = session.user_id
  WHERE session.token_digest = p_token_digest
    AND octet_length(p_token_digest) = 32
    AND session.revoked_at IS NULL
    AND session.idle_expires_at > statement_timestamp()
    AND session.absolute_expires_at > statement_timestamp()
    AND identity.active = true
    AND app.session_tenant_allowed(session.user_id, session.active_tenant_id);
$function$;
--> statement-breakpoint
CREATE OR REPLACE FUNCTION app.get_auth_session_v2(p_token_digest bytea)
RETURNS TABLE (
  session_id uuid,
  user_id uuid,
  rotation_family_id uuid,
  email text,
  display_name text,
  active_tenant_id uuid,
  csrf_secret_digest bytea,
  authentication_method text,
  mfa_satisfied_at timestamp with time zone,
  created_at timestamp with time zone,
  last_seen_at timestamp with time zone,
  idle_expires_at timestamp with time zone,
  absolute_expires_at timestamp with time zone,
  platform_permissions text[]
)
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT current_session.session_id,
         current_session.user_id,
         current_session.rotation_family_id,
         current_session.email,
         current_session.display_name,
         current_session.active_tenant_id,
         current_session.csrf_secret_digest,
         current_session.authentication_method,
         current_session.mfa_satisfied_at,
         current_session.created_at,
         current_session.last_seen_at,
         current_session.idle_expires_at,
         current_session.absolute_expires_at,
         ARRAY(
           SELECT permission_key
           FROM unnest(current_session.platform_permissions) AS permission_key
           WHERE permission_key <> 'platform.tenant.manage'
           ORDER BY permission_key
         )
  FROM app.get_auth_session_v3(p_token_digest) AS current_session;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.get_auth_session_v3(bytea) OWNER TO periapsis_migrator;
--> statement-breakpoint
ALTER FUNCTION app.get_auth_session_v2(bytea) OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.get_auth_session_v3(bytea)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.get_auth_session_v2(bytea)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.get_auth_session_v3(bytea) TO periapsis_api;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.get_auth_session_v2(bytea) TO periapsis_api;
--> statement-breakpoint

INSERT INTO public.platform_permissions (id, key, description)
VALUES (
  uuidv7(),
  'platform.tenant.manage',
  'Suspend and reactivate tenants through the platform control plane.'
)
ON CONFLICT (key) DO NOTHING;
--> statement-breakpoint
INSERT INTO public.platform_role_permissions (role_id, permission_id)
SELECT role.id, permission.id
FROM public.platform_roles AS role
CROSS JOIN public.platform_permissions AS permission
WHERE role.key = 'platform_super_admin'
  AND permission.key = 'platform.tenant.manage'
ON CONFLICT DO NOTHING;
--> statement-breakpoint

-- Audit reasons are operator-supplied, so reject high-confidence credential
-- shapes in addition to the structural lifecycle constraints below.
CREATE FUNCTION app.private_platform_audit_reason_is_safe_v1(p_reason text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
  SELECT p_reason !~* '-----BEGIN[[:space:]]+[^-]*PRIVATE[[:space:]]+KEY-----'
     AND p_reason !~* '(^|[^[:alnum:]_])(bearer|basic)[[:space:]]+[A-Za-z0-9+/._~=-]{12,}'
     AND p_reason !~* '(password|passwd|passphrase|secret|token|api[ _-]?key|assertion|recovery[ _-]?code|totp)[[:space:]]*[:=][[:space:]]*[^[:space:]]{12,}'
     AND p_reason !~ '(^|[^A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\\.eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}';
$function$;
--> statement-breakpoint
CREATE FUNCTION app.private_platform_lifecycle_reason_is_valid_v1(p_reason text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
SET search_path = pg_catalog, app
AS $function$
  SELECT octet_length(p_reason) BETWEEN 1 AND 2048
     AND NOT EXISTS (
       SELECT 1
       FROM generate_series(1, char_length(p_reason)) AS character(position)
       CROSS JOIN LATERAL (
         SELECT ascii(substr(p_reason, character.position, 1)) AS codepoint
       ) AS decoded
       WHERE decoded.codepoint BETWEEN 0 AND 31
          OR decoded.codepoint BETWEEN 127 AND 159
          OR decoded.codepoint = 173
          OR decoded.codepoint BETWEEN 1536 AND 1541
          OR decoded.codepoint IN (1564, 1757, 1807, 6158, 65279, 69821, 69837, 917505)
          OR decoded.codepoint BETWEEN 2192 AND 2193
          OR decoded.codepoint = 2274
          OR decoded.codepoint BETWEEN 8203 AND 8207
          OR decoded.codepoint BETWEEN 8234 AND 8238
          OR decoded.codepoint BETWEEN 8288 AND 8292
          OR decoded.codepoint BETWEEN 8294 AND 8303
          OR decoded.codepoint BETWEEN 65529 AND 65531
          OR decoded.codepoint BETWEEN 78896 AND 78911
          OR decoded.codepoint BETWEEN 113824 AND 113827
          OR decoded.codepoint BETWEEN 119155 AND 119162
          OR decoded.codepoint BETWEEN 917536 AND 917631
     )
     AND ascii(substr(p_reason, 1, 1)) NOT IN (32, 160, 5760, 8232, 8233, 8239, 8287, 12288)
     AND ascii(substr(p_reason, char_length(p_reason), 1)) NOT IN (32, 160, 5760, 8232, 8233, 8239, 8287, 12288)
     AND NOT ascii(substr(p_reason, 1, 1)) BETWEEN 8192 AND 8202
     AND NOT ascii(substr(p_reason, char_length(p_reason), 1)) BETWEEN 8192 AND 8202
     AND app.private_platform_audit_reason_is_safe_v1(p_reason);
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_platform_audit_reason_is_safe_v1(text)
OWNER TO periapsis_migrator;
--> statement-breakpoint
ALTER FUNCTION app.private_platform_lifecycle_reason_is_valid_v1(text)
OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_platform_audit_reason_is_safe_v1(text)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_platform_lifecycle_reason_is_valid_v1(text)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.append_platform_audit_event(
  p_id uuid,
  p_actor_type public.audit_actor_type,
  p_actor_user_id uuid,
  p_action text,
  p_resource_type text,
  p_resource_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text,
  p_outcome public.audit_outcome,
  p_reason text,
  p_metadata jsonb
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_user_agent IS NOT NULL
     AND p_user_agent <> ''
     AND length(p_user_agent) NOT BETWEEN 1 AND 1024 THEN
    RAISE EXCEPTION 'platform audit user agent exceeds 1024 characters'
      USING ERRCODE = '22023';
  END IF;
  IF p_authentication_method IS NOT NULL
     AND p_authentication_method !~ '^[a-z][a-z0-9_]{0,63}$' THEN
    RAISE EXCEPTION 'platform audit authentication method is invalid'
      USING ERRCODE = '22023';
  END IF;
  IF p_reason IS NOT NULL
     AND (
       octet_length(p_reason) NOT BETWEEN 1 AND 2048
       OR NOT app.private_platform_audit_reason_is_safe_v1(p_reason)
     ) THEN
    RAISE EXCEPTION 'platform audit reason is invalid' USING ERRCODE = '22023';
  END IF;
  IF pg_column_size(coalesce(p_metadata, '{}'::jsonb)) > 8192 THEN
    RAISE EXCEPTION 'platform audit metadata exceeds 8192 bytes' USING ERRCODE = '22023';
  END IF;
  IF coalesce(p_metadata, '{}'::jsonb) ?| ARRAY[
    'password', 'password_phc', 'token', 'token_digest', 'csrf_token',
    'totp_secret', 'recovery_code', 'assertion'
  ] THEN
    RAISE EXCEPTION 'platform audit metadata contains a prohibited credential field'
      USING ERRCODE = '22023';
  END IF;
  INSERT INTO public.platform_audit_events (
    id, sequence, actor_type, actor_user_id, action, resource_type, resource_id,
    request_id, correlation_id, ip_address, user_agent, authentication_method,
    outcome, reason, metadata
  )
  VALUES (
    p_id, 1, p_actor_type, p_actor_user_id, p_action, p_resource_type, p_resource_id,
    p_request_id, p_correlation_id, p_ip_address, nullif(p_user_agent, ''),
    p_authentication_method, p_outcome, p_reason, coalesce(p_metadata, '{}'::jsonb)
  );
  RETURN p_id;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.append_platform_audit_event(
  uuid, public.audit_actor_type, uuid, text, text, uuid, uuid, uuid, inet,
  text, text, public.audit_outcome, text, jsonb
) OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.append_platform_audit_event(
  uuid, public.audit_actor_type, uuid, text, text, uuid, uuid, uuid, inet,
  text, text, public.audit_outcome, text, jsonb
) FROM PUBLIC;
--> statement-breakpoint

CREATE FUNCTION app.change_platform_tenant_lifecycle(
  p_session_id uuid,
  p_tenant_id uuid,
  p_target public.tenant_status,
  p_expected_version integer,
  p_reason text,
  p_platform_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE (
  tenant_id uuid,
  previous_status public.tenant_status,
  status public.tenant_status,
  version integer,
  updated_at timestamp with time zone,
  replayed boolean
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor_id uuid;
  authorization_revision bigint;
  tenant_record public.tenants%ROWTYPE;
  changed_at timestamp with time zone;
  action text;
  notification_attempts_fenced integer := 0;
  notification_deliveries_fenced integer := 0;
  sla_jobs_fenced integer := 0;
BEGIN
  actor_id := app.context_user_id();

  IF p_session_id IS NULL
     OR uuid_extract_version(p_session_id) IS DISTINCT FROM 7
     OR p_tenant_id IS NULL
     OR uuid_extract_version(p_tenant_id) IS DISTINCT FROM 7
     OR p_platform_audit_event_id IS NULL
     OR uuid_extract_version(p_platform_audit_event_id) IS DISTINCT FROM 7
     OR p_request_id IS NULL
     OR p_request_id = '00000000-0000-0000-0000-000000000000'::uuid
     OR p_correlation_id IS NULL
     OR p_correlation_id = '00000000-0000-0000-0000-000000000000'::uuid
     OR p_ip_address IS NULL
     OR p_expected_version IS NULL
     OR p_expected_version NOT BETWEEN 1 AND 2147483646
     OR p_target IS NULL
     OR p_reason IS NULL
     OR p_authentication_method IS NULL
     OR p_authentication_method NOT IN (
       'bootstrap_totp', 'oidc', 'passkey', 'recovery_code', 'saml', 'totp'
     )
     OR p_user_agent IS NULL
     OR octet_length(p_user_agent) > 512
     OR EXISTS (
       SELECT 1
       FROM generate_series(1, char_length(p_user_agent)) AS character(position)
       WHERE ascii(substr(p_user_agent, character.position, 1)) BETWEEN 0 AND 31
          OR ascii(substr(p_user_agent, character.position, 1)) BETWEEN 127 AND 159
     )
     OR NOT app.private_platform_lifecycle_reason_is_valid_v1(p_reason) THEN
    RAISE EXCEPTION 'invalid platform tenant lifecycle command'
      USING ERRCODE = '22023';
  END IF;

  -- Lock the exact authenticated session and its user so a concurrent revoke,
  -- expiry-bound rotation, user disable, or method substitution cannot race the
  -- control-plane mutation.
  PERFORM 1
  FROM public.auth_sessions AS session
  JOIN public.users AS actor ON actor.id = session.user_id
  WHERE session.id = p_session_id
    AND session.user_id = actor_id
    AND session.authentication_method = p_authentication_method
    AND session.revoked_at IS NULL
    AND session.idle_expires_at > transaction_timestamp()
    AND session.absolute_expires_at > transaction_timestamp()
    AND actor.active = true
    AND app.session_tenant_allowed(session.user_id, session.active_tenant_id)
  FOR SHARE OF session, actor;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'live platform session authority is required'
      USING ERRCODE = '42501';
  END IF;

  -- Lock every row that contributes the live grant. Concurrent revocation or
  -- catalog mutation must complete before or after this transaction, never in
  -- the permission-check/mutation gap.
  PERFORM 1
  FROM public.user_platform_roles AS user_role
  JOIN public.platform_role_permissions AS role_permission
    ON role_permission.role_id = user_role.role_id
  JOIN public.platform_permissions AS permission
    ON permission.id = role_permission.permission_id
  WHERE user_role.user_id = actor_id
    AND user_role.revoked_at IS NULL
    AND permission.key = 'platform.tenant.manage'
  FOR SHARE OF user_role, role_permission, permission;
  IF NOT FOUND OR NOT app.platform_user_has_permission(actor_id, 'platform.tenant.manage') THEN
    RAISE EXCEPTION 'platform.tenant.manage permission is required'
      USING ERRCODE = '42501';
  END IF;

  -- Tenant authorization state is the cross-process suspension fence.  Every
  -- credential and ticket write path takes a conflicting state lock before it
  -- can observe an active tenant, so the lifecycle commit linearizes all
  -- future tenant work.  Keep this lock before the tenant row everywhere.
  SELECT authorization_state.revision INTO authorization_revision
  FROM public.tenant_authorization_states AS authorization_state
  WHERE authorization_state.tenant_id = p_tenant_id
  FOR UPDATE;
  IF NOT FOUND THEN
    IF NOT EXISTS (
      SELECT 1 FROM public.tenants AS tenant WHERE tenant.id = p_tenant_id
    ) THEN
      RAISE EXCEPTION 'platform tenant does not exist' USING ERRCODE = 'P0002';
    END IF;
    RAISE EXCEPTION 'platform tenant authorization state is unavailable'
      USING ERRCODE = '55000';
  END IF;
  IF authorization_revision >= 9223372036854775806 THEN
    RAISE EXCEPTION 'platform tenant authorization revision is exhausted'
      USING ERRCODE = '55000';
  END IF;

  SELECT tenant.* INTO tenant_record
  FROM public.tenants AS tenant
  WHERE tenant.id = p_tenant_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'platform tenant does not exist' USING ERRCODE = 'P0002';
  END IF;
  IF tenant_record.version <> p_expected_version
     OR tenant_record.status = p_target THEN
    RAISE EXCEPTION 'platform tenant lifecycle revision conflict'
      USING ERRCODE = '40001';
  END IF;

  IF tenant_record.status = 'active' AND p_target = 'suspended' THEN
    action := 'platform.tenant.suspended';
  ELSIF tenant_record.status = 'suspended' AND p_target = 'active' THEN
    action := 'platform.tenant.reactivated';
  ELSE
    RAISE EXCEPTION 'invalid platform tenant lifecycle transition'
      USING ERRCODE = '22023';
  END IF;

  changed_at := transaction_timestamp();
  UPDATE public.tenants AS tenant
  SET status = p_target,
      version = tenant_record.version + 1,
      updated_at = changed_at
  WHERE tenant.id = p_tenant_id;

  -- Invalidate every authorization cache derived before this transition.
  UPDATE public.tenant_authorization_states AS authorization_state
  SET revision = authorization_revision + 1,
      updated_at = changed_at
  WHERE authorization_state.tenant_id = p_tenant_id;

  IF p_target = 'suspended' THEN
    -- Finish the current unreserved attempt before clearing its delivery
    -- fence. Reserved deliveries are intentionally retained because an
    -- external submission may already have occurred and must be reconciled.
    UPDATE public.tenant_notification_delivery_attempts AS attempt
    SET completed_at = changed_at,
        outcome = 'fenced',
        failure_class = 'security'
    FROM public.tenant_notification_deliveries AS delivery
    WHERE delivery.tenant_id = p_tenant_id
      AND delivery.id = attempt.delivery_id
      AND delivery.tenant_id = attempt.tenant_id
      AND delivery.status IN ('queued', 'retry_scheduled', 'leased')
      AND delivery.stable_message_id IS NULL
      AND delivery.reserved_at IS NULL
      AND attempt.attempt = delivery.attempt_count
      AND attempt.completed_at IS NULL
      AND attempt.outcome IS NULL;
    GET DIAGNOSTICS notification_attempts_fenced = ROW_COUNT;

    UPDATE public.tenant_notification_deliveries AS delivery
    SET status = 'dead_lettered',
        next_attempt_at = NULL,
        lease_owner = NULL,
        fence_token = NULL,
        lease_until = NULL,
        failure_at = changed_at,
        failure_class = 'security',
        failure_code = 'tenant_suspended',
        updated_at = changed_at
    WHERE delivery.tenant_id = p_tenant_id
      AND delivery.status IN ('queued', 'retry_scheduled', 'leased')
      AND delivery.stable_message_id IS NULL
      AND delivery.reserved_at IS NULL;
    GET DIAGNOSTICS notification_deliveries_fenced = ROW_COUNT;

    UPDATE public.sla_evaluation_jobs AS job
    SET status = 'dead_lettered',
        worker_id = NULL,
        lease_expires_at = NULL,
        last_failure_code = 'tenant_suspended',
        dead_lettered_at = changed_at,
        updated_at = changed_at
    WHERE job.tenant_id = p_tenant_id
      AND job.status IN ('queued', 'retry_scheduled', 'leased');
    GET DIAGNOSTICS sla_jobs_fenced = ROW_COUNT;
  END IF;

  PERFORM app.append_platform_audit_event(
    p_platform_audit_event_id,
    'user',
    actor_id,
    action,
    'tenant',
    p_tenant_id,
    p_request_id,
    p_correlation_id,
    p_ip_address,
    p_user_agent,
    p_authentication_method,
    'success',
    p_reason,
    jsonb_build_object(
      'previous_status', tenant_record.status,
      'status', p_target,
      'previous_version', tenant_record.version,
      'version', tenant_record.version + 1,
      'previous_authorization_revision', authorization_revision,
      'authorization_revision', authorization_revision + 1,
      'notification_attempts_fenced', notification_attempts_fenced,
      'notification_deliveries_fenced', notification_deliveries_fenced,
      'sla_jobs_fenced', sla_jobs_fenced
    )
  );

  RETURN QUERY
  SELECT p_tenant_id,
         tenant_record.status,
         p_target,
         tenant_record.version + 1,
         changed_at,
         false;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.change_platform_tenant_lifecycle(
  uuid, uuid, public.tenant_status, integer, text, uuid, uuid, uuid, inet, text, text
) OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.change_platform_tenant_lifecycle(
  uuid, uuid, public.tenant_status, integer, text, uuid, uuid, uuid, inet, text, text
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.change_platform_tenant_lifecycle(
  uuid, uuid, public.tenant_status, integer, text, uuid, uuid, uuid, inet, text, text
) TO periapsis_api;
