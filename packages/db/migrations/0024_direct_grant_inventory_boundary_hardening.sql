-- Fail closed when a database caller omits an HTTP-backed optimistic-lock
-- version. PostgreSQL's ordinary <> operator yields NULL for a NULL operand,
-- which PL/pgSQL would otherwise treat as a false IF predicate.
CREATE OR REPLACE FUNCTION "app"."update_tenant_role_metadata"(
  p_role_id uuid,
  p_expected_version integer,
  p_name text,
  p_description text,
  p_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS integer
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  target_role record;
  next_version integer;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  IF NOT app.current_tenant_has_exact_permission('role.manage', 'tenant') THEN
    RAISE EXCEPTION 'role.manage tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_name IS NULL AND p_description IS NULL THEN
    RAISE EXCEPTION 'at least one role metadata field is required'
      USING ERRCODE = '22023';
  END IF;
  IF p_name IS NOT NULL
     AND (btrim(p_name) = '' OR char_length(p_name) > 120
       OR p_name ~ '[[:cntrl:]]') THEN
    RAISE EXCEPTION 'tenant role name must be nonblank, control-free, and at most 120 characters'
      USING ERRCODE = '22023';
  END IF;
  IF p_description IS NOT NULL
     AND (char_length(p_description) > 500
       OR p_description ~ '[[:cntrl:]]') THEN
    RAISE EXCEPTION 'tenant role description must be control-free and at most 500 characters'
      USING ERRCODE = '22023';
  END IF;

  SELECT role.* INTO target_role
  FROM public.tenant_roles AS role
  WHERE role.tenant_id = context_tenant
    AND role.id = p_role_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant role was not found' USING ERRCODE = 'P0002';
  END IF;
  IF target_role.version IS DISTINCT FROM p_expected_version THEN
    RAISE EXCEPTION 'tenant role version conflict' USING ERRCODE = '40001';
  END IF;
  IF target_role.system_role OR target_role.protected_role THEN
    RAISE EXCEPTION 'built-in or protected roles cannot be edited'
      USING ERRCODE = '55000';
  END IF;
  IF target_role.archived_at IS NOT NULL THEN
    RAISE EXCEPTION 'archived role cannot be edited' USING ERRCODE = '55000';
  END IF;
  IF target_role.version >= 2147483647 THEN
    RAISE EXCEPTION 'tenant role version is exhausted' USING ERRCODE = '55000';
  END IF;

  next_version := target_role.version + 1;
  UPDATE public.tenant_roles AS role
  SET display_name = coalesce(p_name, role.display_name),
      description = coalesce(p_description, role.description),
      version = next_version,
      updated_at = transaction_timestamp()
  WHERE role.tenant_id = context_tenant
    AND role.id = p_role_id;

  PERFORM app.append_tenant_authorization_audit(
    p_audit_event_id, 'tenant.role.metadata_updated', 'tenant_role', p_role_id,
    p_request_id, p_correlation_id,
    p_ip_address, p_user_agent, p_authentication_method,
    jsonb_build_object(
      'name', target_role.display_name,
      'description', target_role.description,
      'version', target_role.version
    ),
    jsonb_build_object(
      'name', coalesce(p_name, target_role.display_name),
      'description', coalesce(p_description, target_role.description),
      'version', next_version
    ),
    '{}'::jsonb
  );
  RETURN next_version;
END;
$function$;--> statement-breakpoint

CREATE OR REPLACE FUNCTION "app"."revoke_tenant_user_role_grant"(
  p_grant_id uuid,
  p_expected_version integer,
  p_reason text,
  p_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS integer
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid;
  target_grant record;
  next_version integer;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF NOT app.current_tenant_has_exact_permission('role.grant', 'tenant') THEN
    RAISE EXCEPTION 'role.grant tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_reason IS NULL OR btrim(p_reason) = ''
     OR char_length(p_reason) > 500 OR p_reason ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION 'direct role revoke reason is invalid'
      USING ERRCODE = '22023';
  END IF;

  SELECT role_grant.*, role.archived_at AS role_archived_at
    INTO target_grant
  FROM public.tenant_membership_role_grants AS role_grant
  JOIN public.tenant_authorization_sources AS source
    ON source.tenant_id = role_grant.tenant_id
   AND source.id = role_grant.source_id
  JOIN public.tenant_roles AS role
    ON role.tenant_id = role_grant.tenant_id
   AND role.id = role_grant.role_id
  WHERE role_grant.tenant_id = context_tenant
    AND role_grant.id = p_grant_id
    AND source.kind = 'manual'
  FOR UPDATE OF role_grant;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'direct tenant role grant was not found'
      USING ERRCODE = 'P0002';
  END IF;
  IF target_grant.version IS DISTINCT FROM p_expected_version THEN
    RAISE EXCEPTION 'tenant role grant version conflict'
      USING ERRCODE = '40001';
  END IF;
  IF target_grant.revoked_at IS NOT NULL THEN
    RAISE EXCEPTION 'direct tenant role grant is already revoked'
      USING ERRCODE = '55000';
  END IF;
  IF target_grant.version >= 2147483647 THEN
    RAISE EXCEPTION 'tenant role grant version is exhausted'
      USING ERRCODE = '55000';
  END IF;

  IF target_grant.role_archived_at IS NULL
     AND (
       target_grant.expires_at IS NULL
       OR target_grant.expires_at > transaction_timestamp()
     ) THEN
    PERFORM app.assert_actor_can_grant_role(
      target_grant.role_id, target_grant.expires_at
    );
  END IF;

  next_version := target_grant.version + 1;
  UPDATE public.tenant_membership_role_grants AS role_grant
  SET revoked_at = transaction_timestamp(),
      revoked_by_membership_id = actor_membership,
      revoke_reason = p_reason,
      version = next_version,
      updated_at = transaction_timestamp()
  WHERE role_grant.tenant_id = context_tenant
    AND role_grant.id = p_grant_id;

  PERFORM app.append_tenant_authorization_audit(
    p_audit_event_id, 'tenant.role_grant.revoked',
    'tenant_membership_role_grant', p_grant_id,
    p_request_id, p_correlation_id,
    p_ip_address, p_user_agent, p_authentication_method,
    jsonb_build_object(
      'revoked_at', NULL, 'version', target_grant.version
    ),
    jsonb_build_object(
      'revoked_at', transaction_timestamp(),
      'reason', p_reason, 'version', next_version
    ),
    jsonb_build_object('actor_membership_id', actor_membership)
  );
  RETURN next_version;
END;
$function$;--> statement-breakpoint

-- The inventory is an ownership history, not a manual-mutation queue. Return
-- every known direct edge and keep path identity separate from source origin.
DROP FUNCTION "app"."list_tenant_membership_role_grants"(
  uuid, uuid, boolean, integer
);--> statement-breakpoint

CREATE FUNCTION "app"."list_tenant_membership_role_grants"(
  p_target_user_id uuid,
  p_after_grant_id uuid,
  p_include_revoked boolean,
  p_limit integer
)
RETURNS TABLE (
  grant_id uuid,
  membership_id uuid,
  role_id uuid,
  role_key text,
  role_name text,
  role_description text,
  role_system boolean,
  role_archived_at timestamp with time zone,
  role_version integer,
  role_created_at timestamp with time zone,
  role_updated_at timestamp with time zone,
  source_id uuid,
  source_kind "public"."authorization_source_kind",
  source_authoritative boolean,
  source_retired_at timestamp with time zone,
  source_type text,
  granted_by_membership_id uuid,
  granted_by_user_id uuid,
  grant_reason text,
  granted_at timestamp with time zone,
  expires_at timestamp with time zone,
  revoked_at timestamp with time zone,
  revoked_by_membership_id uuid,
  revoked_by_user_id uuid,
  revoke_reason text,
  grant_state text,
  version integer,
  updated_at timestamp with time zone
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  target_membership_id uuid;
BEGIN
  PERFORM app.current_tenant_membership_id();
  IF NOT app.current_tenant_has_exact_permission('role.read', 'tenant') THEN
    RAISE EXCEPTION 'role.read tenant scope is required' USING ERRCODE = '42501';
  END IF;
  IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 101 THEN
    RAISE EXCEPTION 'role grant page limit must be between 1 and 101'
      USING ERRCODE = '22023';
  END IF;
  IF p_include_revoked IS NULL THEN
    RAISE EXCEPTION 'include revoked must be explicit'
      USING ERRCODE = '22023';
  END IF;

  SELECT membership.id INTO target_membership_id
  FROM public.tenant_memberships AS membership
  WHERE membership.tenant_id = context_tenant
    AND membership.user_id = p_target_user_id;

  IF target_membership_id IS NULL THEN
    RAISE EXCEPTION 'tenant user membership was not found'
      USING ERRCODE = 'P0002';
  END IF;

  RETURN QUERY
  SELECT role_grant.id, role_grant.membership_id, role_grant.role_id,
         role.key, role.display_name, role.description, role.system_role,
         role.archived_at, role.version, role.created_at, role.updated_at,
         role_grant.source_id, source.kind, source.authoritative,
         source.retired_at,
         CASE source.kind
           WHEN 'manual' THEN 'direct'
           WHEN 'identity_mapping' THEN 'identity_provider'
           ELSE 'system'
         END,
         role_grant.granted_by_membership_id, grantor.user_id,
         role_grant.grant_reason, role_grant.granted_at,
         role_grant.expires_at, role_grant.revoked_at,
         role_grant.revoked_by_membership_id, revoker.user_id,
         role_grant.revoke_reason,
         CASE
           WHEN role_grant.revoked_at IS NOT NULL THEN 'revoked'
           WHEN role_grant.expires_at IS NOT NULL
             AND role_grant.expires_at <= transaction_timestamp() THEN 'expired'
           ELSE 'active'
         END,
         role_grant.version, role_grant.updated_at
  FROM public.tenant_membership_role_grants AS role_grant
  JOIN public.tenant_roles AS role
    ON role.tenant_id = role_grant.tenant_id
   AND role.id = role_grant.role_id
  JOIN public.tenant_authorization_sources AS source
    ON source.tenant_id = role_grant.tenant_id
   AND source.id = role_grant.source_id
  LEFT JOIN public.tenant_memberships AS grantor
    ON grantor.tenant_id = role_grant.tenant_id
   AND grantor.id = role_grant.granted_by_membership_id
  LEFT JOIN public.tenant_memberships AS revoker
    ON revoker.tenant_id = role_grant.tenant_id
   AND revoker.id = role_grant.revoked_by_membership_id
  WHERE role_grant.tenant_id = context_tenant
    AND role_grant.membership_id = target_membership_id
    AND (p_include_revoked OR role_grant.revoked_at IS NULL)
    AND (p_after_grant_id IS NULL OR role_grant.id > p_after_grant_id)
  ORDER BY role_grant.id
  LIMIT p_limit;
END;
$function$;--> statement-breakpoint

DROP FUNCTION "app"."get_tenant_membership_role_grant"(uuid);--> statement-breakpoint

CREATE FUNCTION "app"."get_tenant_membership_role_grant"(p_grant_id uuid)
RETURNS TABLE (
  grant_id uuid,
  membership_id uuid,
  target_user_id uuid,
  role_id uuid,
  role_key text,
  role_name text,
  role_description text,
  role_system boolean,
  role_archived_at timestamp with time zone,
  role_version integer,
  role_created_at timestamp with time zone,
  role_updated_at timestamp with time zone,
  source_id uuid,
  source_kind "public"."authorization_source_kind",
  source_authoritative boolean,
  source_retired_at timestamp with time zone,
  source_type text,
  granted_by_membership_id uuid,
  granted_by_user_id uuid,
  grant_reason text,
  granted_at timestamp with time zone,
  expires_at timestamp with time zone,
  revoked_at timestamp with time zone,
  revoked_by_membership_id uuid,
  revoked_by_user_id uuid,
  revoke_reason text,
  grant_state text,
  version integer,
  updated_at timestamp with time zone
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
BEGIN
  PERFORM app.current_tenant_membership_id();
  IF NOT (
    app.current_tenant_has_exact_permission('role.read', 'tenant')
    OR app.current_tenant_has_exact_permission('role.grant', 'tenant')
  ) THEN
    RAISE EXCEPTION 'role.read or role.grant tenant scope is required'
      USING ERRCODE = '42501';
  END IF;

  RETURN QUERY
  SELECT role_grant.id, role_grant.membership_id, target.user_id,
         role_grant.role_id, role.key, role.display_name, role.description,
         role.system_role, role.archived_at, role.version,
         role.created_at, role.updated_at,
         role_grant.source_id, source.kind, source.authoritative,
         source.retired_at,
         CASE source.kind
           WHEN 'manual' THEN 'direct'
           WHEN 'identity_mapping' THEN 'identity_provider'
           ELSE 'system'
         END,
         role_grant.granted_by_membership_id, grantor.user_id,
         role_grant.grant_reason, role_grant.granted_at,
         role_grant.expires_at, role_grant.revoked_at,
         role_grant.revoked_by_membership_id, revoker.user_id,
         role_grant.revoke_reason,
         CASE
           WHEN role_grant.revoked_at IS NOT NULL THEN 'revoked'
           WHEN role_grant.expires_at IS NOT NULL
             AND role_grant.expires_at <= transaction_timestamp() THEN 'expired'
           ELSE 'active'
         END,
         role_grant.version, role_grant.updated_at
  FROM public.tenant_membership_role_grants AS role_grant
  JOIN public.tenant_memberships AS target
    ON target.tenant_id = role_grant.tenant_id
   AND target.id = role_grant.membership_id
  JOIN public.tenant_roles AS role
    ON role.tenant_id = role_grant.tenant_id
   AND role.id = role_grant.role_id
  JOIN public.tenant_authorization_sources AS source
    ON source.tenant_id = role_grant.tenant_id
   AND source.id = role_grant.source_id
  LEFT JOIN public.tenant_memberships AS grantor
    ON grantor.tenant_id = role_grant.tenant_id
   AND grantor.id = role_grant.granted_by_membership_id
  LEFT JOIN public.tenant_memberships AS revoker
    ON revoker.tenant_id = role_grant.tenant_id
   AND revoker.id = role_grant.revoked_by_membership_id
  WHERE role_grant.tenant_id = context_tenant
    AND role_grant.id = p_grant_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant role grant was not found' USING ERRCODE = 'P0002';
  END IF;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION "app"."update_tenant_role_metadata"(
  uuid, integer, text, text, uuid, uuid, uuid, inet, text, text
) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."revoke_tenant_user_role_grant"(
  uuid, integer, text, uuid, uuid, uuid, inet, text, text
) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."list_tenant_membership_role_grants"(
  uuid, uuid, boolean, integer
) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."get_tenant_membership_role_grant"(uuid)
  OWNER TO "periapsis_migrator";--> statement-breakpoint

REVOKE ALL ON FUNCTION "app"."update_tenant_role_metadata"(
  uuid, integer, text, text, uuid, uuid, uuid, inet, text, text
) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."revoke_tenant_user_role_grant"(
  uuid, integer, text, uuid, uuid, uuid, inet, text, text
) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."list_tenant_membership_role_grants"(
  uuid, uuid, boolean, integer
) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."get_tenant_membership_role_grant"(uuid)
  FROM PUBLIC;--> statement-breakpoint

GRANT EXECUTE ON FUNCTION "app"."update_tenant_role_metadata"(
  uuid, integer, text, text, uuid, uuid, uuid, inet, text, text
) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."revoke_tenant_user_role_grant"(
  uuid, integer, text, uuid, uuid, uuid, inet, text, text
) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."list_tenant_membership_role_grants"(
  uuid, uuid, boolean, integer
) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."get_tenant_membership_role_grant"(uuid)
  TO "periapsis_api";
