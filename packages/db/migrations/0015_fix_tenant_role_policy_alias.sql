-- Avoid a PL/pgSQL name collision between the requested record variable and
-- the input-row aliases used while replacing a role policy. This is additive
-- so databases that already applied the Phase 2B security migration are
-- repaired without rewriting migration history.
CREATE OR REPLACE FUNCTION "app"."replace_tenant_role_policy"(
  p_role_id uuid,
  p_expected_version integer,
  p_permission_keys text[],
  p_scopes "public"."authorization_scope"[],
  p_delegation_permission_keys text[],
  p_delegation_scopes "public"."authorization_scope"[],
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
  target_role record;
  requested record;
  has_live_grants boolean;
  has_unbounded_grants boolean;
  maximum_grant_expiry timestamp with time zone;
  required_expiry timestamp with time zone;
  old_permission_count integer;
  old_ceiling_count integer;
  next_version integer;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF NOT app.current_tenant_has_exact_permission('role.manage', 'tenant') THEN
    RAISE EXCEPTION 'role.manage tenant scope is required'
      USING ERRCODE = '42501';
  END IF;

  SELECT role.* INTO target_role
  FROM public.tenant_roles AS role
  WHERE role.tenant_id = context_tenant
    AND role.id = p_role_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant role was not found' USING ERRCODE = 'P0002';
  END IF;
  IF target_role.version <> p_expected_version THEN
    RAISE EXCEPTION 'tenant role version conflict' USING ERRCODE = '40001';
  END IF;
  IF target_role.system_role OR target_role.protected_role THEN
    RAISE EXCEPTION 'built-in or protected role policies cannot be replaced'
      USING ERRCODE = '55000';
  END IF;
  IF target_role.archived_at IS NOT NULL THEN
    RAISE EXCEPTION 'archived role policy cannot be replaced'
      USING ERRCODE = '55000';
  END IF;
  IF target_role.version >= 2147483647 THEN
    RAISE EXCEPTION 'tenant role version is exhausted' USING ERRCODE = '55000';
  END IF;

  PERFORM app.validate_tenant_role_policy(
    p_permission_keys, p_scopes,
    p_delegation_permission_keys, p_delegation_scopes
  );

  SELECT count(*) > 0,
         coalesce(bool_or(role_grant.expires_at IS NULL), false),
         max(role_grant.expires_at)
    INTO has_live_grants, has_unbounded_grants, maximum_grant_expiry
  FROM public.tenant_membership_role_grants AS role_grant
  JOIN public.tenant_authorization_sources AS source
    ON source.tenant_id = role_grant.tenant_id
   AND source.id = role_grant.source_id
  WHERE role_grant.tenant_id = context_tenant
    AND role_grant.role_id = p_role_id
    AND role_grant.revoked_at IS NULL
    AND (role_grant.expires_at IS NULL
      OR role_grant.expires_at > transaction_timestamp())
    AND source.retired_at IS NULL;

  required_expiry := CASE
    WHEN has_live_grants AND has_unbounded_grants THEN NULL
    WHEN has_live_grants THEN maximum_grant_expiry
    ELSE transaction_timestamp()
  END;

  -- The actor must cover both the authority being removed and the replacement.
  -- When a live grant exists, coverage must last for that grant's full horizon.
  FOR requested IN
    SELECT permission.key AS permission_key, policy.scope
    FROM public.tenant_role_permissions AS policy
    JOIN public.tenant_permissions AS permission
      ON permission.id = policy.permission_id
    WHERE policy.tenant_id = context_tenant
      AND policy.role_id = p_role_id
    UNION
    SELECT replacement.permission_key, replacement.scope
    FROM unnest(p_permission_keys, p_scopes)
      AS replacement(permission_key, scope)
  LOOP
    IF NOT app.tenant_user_can_delegate_exact_permission(
      context_tenant, app.context_user_id(), requested.permission_key,
      requested.scope, required_expiry
    ) THEN
      RAISE EXCEPTION 'role policy change exceeds the exact delegation ceiling or active grant lifetime'
        USING ERRCODE = '42501';
    END IF;
  END LOOP;

  SELECT count(*) INTO old_permission_count
  FROM public.tenant_role_permissions AS policy
  WHERE policy.tenant_id = context_tenant
    AND policy.role_id = p_role_id;
  SELECT count(*) INTO old_ceiling_count
  FROM public.tenant_role_delegation_ceilings AS ceiling
  WHERE ceiling.tenant_id = context_tenant
    AND ceiling.role_id = p_role_id;

  DELETE FROM public.tenant_role_delegation_ceilings AS ceiling
  WHERE ceiling.tenant_id = context_tenant
    AND ceiling.role_id = p_role_id;
  DELETE FROM public.tenant_role_permissions AS policy
  WHERE policy.tenant_id = context_tenant
    AND policy.role_id = p_role_id;

  INSERT INTO public.tenant_role_permissions (
    tenant_id, role_id, permission_id, scope, created_by_membership_id
  )
  SELECT context_tenant, p_role_id, permission.id, policy_input.scope,
         actor_membership
  FROM unnest(p_permission_keys, p_scopes)
    AS policy_input(permission_key, scope)
  JOIN public.tenant_permissions AS permission
    ON permission.key = policy_input.permission_key;

  INSERT INTO public.tenant_role_delegation_ceilings (
    tenant_id, role_id, permission_id, scope, created_by_membership_id
  )
  SELECT context_tenant, p_role_id, permission.id, ceiling_input.scope,
         actor_membership
  FROM unnest(p_delegation_permission_keys, p_delegation_scopes)
    AS ceiling_input(permission_key, scope)
  JOIN public.tenant_permissions AS permission
    ON permission.key = ceiling_input.permission_key;

  next_version := target_role.version + 1;
  UPDATE public.tenant_roles AS role
  SET version = next_version,
      updated_at = transaction_timestamp()
  WHERE role.tenant_id = context_tenant
    AND role.id = p_role_id;

  PERFORM app.append_tenant_authorization_audit(
    p_audit_event_id, 'tenant.role.policy_replaced', 'tenant_role', p_role_id,
    p_request_id, p_correlation_id,
    p_ip_address, p_user_agent, p_authentication_method,
    jsonb_build_object(
      'permissions', old_permission_count,
      'delegation_ceiling', old_ceiling_count,
      'version', target_role.version
    ),
    jsonb_build_object(
      'permissions', cardinality(p_permission_keys),
      'delegation_ceiling', cardinality(p_delegation_permission_keys),
      'version', next_version
    ),
    jsonb_build_object('actor_membership_id', actor_membership)
  );
  RETURN next_version;
END;
$function$;
