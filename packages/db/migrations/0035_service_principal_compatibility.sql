-- Harden every predecessor human-authorization ABI before the built-in
-- service-account role changes principal kind. The four permissions delivered
-- by the following security migration must remain invisible to older replicas.
CREATE OR REPLACE FUNCTION "app"."tenant_user_has_exact_permission"(
  p_tenant_id uuid,
  p_user_id uuid,
  p_permission_key text,
  p_scope "public"."authorization_scope"
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT p_scope <> 'platform'
     AND p_permission_key NOT IN (
       'service_account.read',
       'service_account.manage',
       'service_account.credential.manage',
       'alert.create'
     )
     AND EXISTS (
       SELECT 1
       FROM public.tenant_memberships AS membership
       JOIN public.users AS identity ON identity.id = membership.user_id
       JOIN public.tenants AS tenant ON tenant.id = membership.tenant_id
       JOIN public.tenant_authorization_states AS state
         ON state.tenant_id = membership.tenant_id
       CROSS JOIN LATERAL (
         SELECT direct_grant.role_id
         FROM public.tenant_membership_role_grants AS direct_grant
         JOIN public.tenant_authorization_sources AS direct_source
           ON direct_source.tenant_id = direct_grant.tenant_id
          AND direct_source.id = direct_grant.source_id
         WHERE direct_grant.tenant_id = membership.tenant_id
           AND direct_grant.membership_id = membership.id
           AND direct_grant.revoked_at IS NULL
           AND (direct_grant.expires_at IS NULL
             OR direct_grant.expires_at > transaction_timestamp())
           AND direct_source.retired_at IS NULL

         UNION ALL

         SELECT group_grant.role_id
         FROM public.tenant_security_group_memberships AS group_member
         JOIN public.tenant_authorization_sources AS member_source
           ON member_source.tenant_id = group_member.tenant_id
          AND member_source.id = group_member.source_id
         JOIN public.tenant_security_groups AS security_group
           ON security_group.tenant_id = group_member.tenant_id
          AND security_group.id = group_member.group_id
         JOIN public.tenant_security_group_role_grants AS group_grant
           ON group_grant.tenant_id = group_member.tenant_id
          AND group_grant.group_id = group_member.group_id
         JOIN public.tenant_authorization_sources AS grant_source
           ON grant_source.tenant_id = group_grant.tenant_id
          AND grant_source.id = group_grant.source_id
         WHERE group_member.tenant_id = membership.tenant_id
           AND group_member.membership_id = membership.id
           AND group_member.revoked_at IS NULL
           AND (group_member.expires_at IS NULL
             OR group_member.expires_at > transaction_timestamp())
           AND member_source.retired_at IS NULL
           AND security_group.archived_at IS NULL
           AND group_grant.revoked_at IS NULL
           AND (group_grant.expires_at IS NULL
             OR group_grant.expires_at > transaction_timestamp())
           AND grant_source.retired_at IS NULL
       ) AS authority_path
       JOIN public.tenant_roles AS role
         ON role.tenant_id = membership.tenant_id
        AND role.id = authority_path.role_id
       JOIN public.tenant_role_permissions AS role_permission
         ON role_permission.tenant_id = role.tenant_id
        AND role_permission.role_id = role.id
       JOIN public.tenant_permissions AS permission
         ON permission.id = role_permission.permission_id
       WHERE membership.tenant_id = p_tenant_id
         AND membership.user_id = p_user_id
         AND membership.status = 'active'
         AND identity.active
         AND tenant.status = 'active'
         AND state.initialized_at IS NOT NULL
         AND role.principal_kind = 'human'
         AND role.archived_at IS NULL
         AND permission.key = p_permission_key
         AND role_permission.scope = p_scope
         AND role_permission.scope <> 'platform'
     );
$function$;--> statement-breakpoint

CREATE OR REPLACE FUNCTION "app"."tenant_user_can_delegate_exact_permission"(
  p_tenant_id uuid,
  p_user_id uuid,
  p_permission_key text,
  p_scope "public"."authorization_scope",
  p_requested_expires_at timestamp with time zone
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT p_scope <> 'platform'
     AND p_permission_key NOT IN (
       'service_account.read',
       'service_account.manage',
       'service_account.credential.manage',
       'alert.create'
     )
     AND EXISTS (
       SELECT 1
       FROM public.tenant_memberships AS membership
       JOIN public.users AS identity ON identity.id = membership.user_id
       JOIN public.tenants AS tenant ON tenant.id = membership.tenant_id
       JOIN public.tenant_authorization_states AS state
         ON state.tenant_id = membership.tenant_id
       CROSS JOIN LATERAL (
         SELECT direct_grant.role_id, direct_grant.expires_at
         FROM public.tenant_membership_role_grants AS direct_grant
         JOIN public.tenant_authorization_sources AS direct_source
           ON direct_source.tenant_id = direct_grant.tenant_id
          AND direct_source.id = direct_grant.source_id
         WHERE direct_grant.tenant_id = membership.tenant_id
           AND direct_grant.membership_id = membership.id
           AND direct_grant.revoked_at IS NULL
           AND (direct_grant.expires_at IS NULL
             OR direct_grant.expires_at > transaction_timestamp())
           AND direct_source.retired_at IS NULL

         UNION ALL

         SELECT group_grant.role_id,
                app.earliest_authorization_expiry(
                  group_member.expires_at, group_grant.expires_at
                )
         FROM public.tenant_security_group_memberships AS group_member
         JOIN public.tenant_authorization_sources AS member_source
           ON member_source.tenant_id = group_member.tenant_id
          AND member_source.id = group_member.source_id
         JOIN public.tenant_security_groups AS security_group
           ON security_group.tenant_id = group_member.tenant_id
          AND security_group.id = group_member.group_id
         JOIN public.tenant_security_group_role_grants AS group_grant
           ON group_grant.tenant_id = group_member.tenant_id
          AND group_grant.group_id = group_member.group_id
         JOIN public.tenant_authorization_sources AS grant_source
           ON grant_source.tenant_id = group_grant.tenant_id
          AND grant_source.id = group_grant.source_id
         WHERE group_member.tenant_id = membership.tenant_id
           AND group_member.membership_id = membership.id
           AND group_member.revoked_at IS NULL
           AND (group_member.expires_at IS NULL
             OR group_member.expires_at > transaction_timestamp())
           AND member_source.retired_at IS NULL
           AND security_group.archived_at IS NULL
           AND group_grant.revoked_at IS NULL
           AND (group_grant.expires_at IS NULL
             OR group_grant.expires_at > transaction_timestamp())
           AND grant_source.retired_at IS NULL
       ) AS authority_path
       JOIN public.tenant_roles AS role
         ON role.tenant_id = membership.tenant_id
        AND role.id = authority_path.role_id
       JOIN public.tenant_role_delegation_ceilings AS ceiling
         ON ceiling.tenant_id = role.tenant_id
        AND ceiling.role_id = role.id
       JOIN public.tenant_permissions AS permission
         ON permission.id = ceiling.permission_id
       WHERE membership.tenant_id = p_tenant_id
         AND membership.user_id = p_user_id
         AND membership.status = 'active'
         AND identity.active
         AND tenant.status = 'active'
         AND state.initialized_at IS NOT NULL
         AND role.principal_kind = 'human'
         AND role.archived_at IS NULL
         AND permission.key = p_permission_key
         AND ceiling.scope = p_scope
         AND ceiling.scope <> 'platform'
         AND (
           (p_requested_expires_at IS NULL
             AND authority_path.expires_at IS NULL)
           OR (p_requested_expires_at IS NOT NULL
             AND (authority_path.expires_at IS NULL
               OR authority_path.expires_at >= p_requested_expires_at))
         )
     );
$function$;--> statement-breakpoint

ALTER FUNCTION "app"."tenant_user_has_exact_permission"(uuid, uuid, text, "public"."authorization_scope") OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."tenant_user_can_delegate_exact_permission"(uuid, uuid, text, "public"."authorization_scope", timestamp with time zone) OWNER TO "periapsis_migrator";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."tenant_user_has_exact_permission"(uuid, uuid, text, "public"."authorization_scope") FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."tenant_user_can_delegate_exact_permission"(uuid, uuid, text, "public"."authorization_scope", timestamp with time zone) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint

CREATE OR REPLACE FUNCTION "app"."resolve_current_tenant_human_authority_v2"(
  p_limit integer
)
RETURNS TABLE (
  permission_key text,
  scope "public"."authorization_scope",
  delegable boolean,
  delegation_expires_at timestamp with time zone
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  context_membership uuid := app.current_tenant_membership_id();
BEGIN
  IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 501 THEN
    RAISE EXCEPTION 'tenant authority limit must be between 1 and 501'
      USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  WITH role_paths AS (
    SELECT direct_grant.role_id, direct_grant.expires_at
    FROM public.tenant_membership_role_grants AS direct_grant
    JOIN public.tenant_authorization_sources AS direct_source
      ON direct_source.tenant_id = direct_grant.tenant_id
     AND direct_source.id = direct_grant.source_id
    WHERE direct_grant.tenant_id = context_tenant
      AND direct_grant.membership_id = context_membership
      AND direct_grant.revoked_at IS NULL
      AND (direct_grant.expires_at IS NULL
        OR direct_grant.expires_at > transaction_timestamp())
      AND direct_source.retired_at IS NULL

    UNION ALL

    SELECT group_grant.role_id,
           app.earliest_authorization_expiry(
             group_member.expires_at, group_grant.expires_at
           )
    FROM public.tenant_security_group_memberships AS group_member
    JOIN public.tenant_authorization_sources AS member_source
      ON member_source.tenant_id = group_member.tenant_id
     AND member_source.id = group_member.source_id
    JOIN public.tenant_security_groups AS security_group
      ON security_group.tenant_id = group_member.tenant_id
     AND security_group.id = group_member.group_id
    JOIN public.tenant_security_group_role_grants AS group_grant
      ON group_grant.tenant_id = group_member.tenant_id
     AND group_grant.group_id = group_member.group_id
    JOIN public.tenant_authorization_sources AS grant_source
      ON grant_source.tenant_id = group_grant.tenant_id
     AND grant_source.id = group_grant.source_id
    WHERE group_member.tenant_id = context_tenant
      AND group_member.membership_id = context_membership
      AND group_member.revoked_at IS NULL
      AND (group_member.expires_at IS NULL
        OR group_member.expires_at > transaction_timestamp())
      AND member_source.retired_at IS NULL
      AND security_group.archived_at IS NULL
      AND group_grant.revoked_at IS NULL
      AND (group_grant.expires_at IS NULL
        OR group_grant.expires_at > transaction_timestamp())
      AND grant_source.retired_at IS NULL
  ), effective AS (
    SELECT permission.key AS permission_key,
           role_permission.scope,
           ceiling.permission_id IS NOT NULL AS is_delegable,
           role_path.expires_at
    FROM role_paths AS role_path
    JOIN public.tenant_roles AS role
      ON role.tenant_id = context_tenant
     AND role.id = role_path.role_id
    JOIN public.tenant_role_permissions AS role_permission
      ON role_permission.tenant_id = role.tenant_id
     AND role_permission.role_id = role.id
    JOIN public.tenant_permissions AS permission
      ON permission.id = role_permission.permission_id
    LEFT JOIN public.tenant_role_delegation_ceilings AS ceiling
      ON ceiling.tenant_id = role_permission.tenant_id
     AND ceiling.role_id = role_permission.role_id
     AND ceiling.permission_id = role_permission.permission_id
     AND ceiling.scope = role_permission.scope
    WHERE role.principal_kind = 'human'
      AND role.archived_at IS NULL
      AND role_permission.scope <> 'platform'
      AND permission.key NOT IN (
        'service_account.read',
        'service_account.manage',
        'service_account.credential.manage',
        'alert.create'
      )
  )
  SELECT effective.permission_key,
         effective.scope,
         bool_or(effective.is_delegable),
         CASE
           WHEN bool_or(effective.is_delegable AND effective.expires_at IS NULL)
             THEN NULL
           ELSE max(effective.expires_at) FILTER (WHERE effective.is_delegable)
         END
  FROM effective
  GROUP BY effective.permission_key, effective.scope
  ORDER BY effective.permission_key, effective.scope
  LIMIT p_limit;
END;
$function$;--> statement-breakpoint

CREATE OR REPLACE FUNCTION "app"."resolve_current_tenant_human_authority"(
  p_limit integer
)
RETURNS TABLE (
  permission_key text,
  scope "public"."authorization_scope",
  delegable boolean,
  delegation_expires_at timestamp with time zone
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 501 THEN
    RAISE EXCEPTION 'tenant authority limit must be between 1 and 501'
      USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  SELECT authority.permission_key,
         authority.scope,
         authority.delegable,
         authority.delegation_expires_at
  FROM app.resolve_current_tenant_human_authority_v2(501) AS authority
  WHERE authority.permission_key NOT IN (
    'operator_team.read',
    'operator_team.manage',
    'operator_team.roster.manage',
    'service_account.read',
    'service_account.manage',
    'service_account.credential.manage',
    'alert.create'
  )
  ORDER BY authority.permission_key, authority.scope
  LIMIT p_limit;
END;
$function$;--> statement-breakpoint

CREATE OR REPLACE FUNCTION "app"."list_tenant_permission_catalog_v2"(
  p_after_id uuid,
  p_limit integer
)
RETURNS TABLE (
  permission_id uuid,
  permission_key text,
  display_name text,
  description text,
  allowed_scopes "public"."authorization_scope"[],
  principal_kinds text[]
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  PERFORM app.current_tenant_membership_id();
  IF NOT app.current_tenant_has_exact_permission('permission.read', 'tenant') THEN
    RAISE EXCEPTION 'permission.read tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 101 THEN
    RAISE EXCEPTION 'permission page limit must be between 1 and 101'
      USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  SELECT permission.id, permission.key, permission.display_name,
         permission.description,
         array_agg(
           permission_scope.scope ORDER BY permission_scope.scope
         )::public.authorization_scope[],
         ARRAY['human']::text[]
  FROM public.tenant_permissions AS permission
  JOIN public.tenant_permission_scopes AS permission_scope
    ON permission_scope.permission_id = permission.id
  WHERE (p_after_id IS NULL OR permission.id > p_after_id)
    AND permission.key NOT IN (
      'service_account.read',
      'service_account.manage',
      'service_account.credential.manage',
      'alert.create'
    )
  GROUP BY permission.id, permission.key, permission.display_name,
           permission.description
  ORDER BY permission.id
  LIMIT p_limit;
END;
$function$;--> statement-breakpoint

CREATE OR REPLACE FUNCTION "app"."list_tenant_permission_catalog"(
  p_after_id uuid,
  p_limit integer
)
RETURNS TABLE (
  permission_id uuid,
  permission_key text,
  display_name text,
  description text,
  allowed_scopes "public"."authorization_scope"[],
  principal_kinds text[]
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 101 THEN
    RAISE EXCEPTION 'permission page limit must be between 1 and 101'
      USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  SELECT catalog.permission_id,
         catalog.permission_key,
         catalog.display_name,
         catalog.description,
         catalog.allowed_scopes,
         catalog.principal_kinds
  FROM app.list_tenant_permission_catalog_v2(p_after_id, 101) AS catalog
  WHERE catalog.permission_key NOT IN (
    'operator_team.read',
    'operator_team.manage',
    'operator_team.roster.manage',
    'service_account.read',
    'service_account.manage',
    'service_account.credential.manage',
    'alert.create'
  )
  ORDER BY catalog.permission_id
  LIMIT p_limit;
END;
$function$;--> statement-breakpoint

CREATE OR REPLACE FUNCTION "app"."get_tenant_role_policy_v2"(
  p_role_id uuid,
  p_limit integer
)
RETURNS TABLE (
  permission_key text,
  scope "public"."authorization_scope",
  delegable boolean
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
    OR app.current_tenant_has_exact_permission('role.manage', 'tenant')
    OR app.current_tenant_has_exact_permission('role.grant', 'tenant')
  ) THEN
    RAISE EXCEPTION 'role.read, role.manage, or role.grant tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 501 THEN
    RAISE EXCEPTION 'role policy limit must be between 1 and 501'
      USING ERRCODE = '22023';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM public.tenant_roles AS role
    WHERE role.tenant_id = context_tenant
      AND role.id = p_role_id
      AND role.principal_kind = 'human'
  ) THEN
    RAISE EXCEPTION 'tenant role was not found' USING ERRCODE = 'P0002';
  END IF;

  RETURN QUERY
  SELECT permission.key, policy.scope, ceiling.permission_id IS NOT NULL
  FROM public.tenant_role_permissions AS policy
  JOIN public.tenant_permissions AS permission
    ON permission.id = policy.permission_id
  LEFT JOIN public.tenant_role_delegation_ceilings AS ceiling
    ON ceiling.tenant_id = policy.tenant_id
   AND ceiling.role_id = policy.role_id
   AND ceiling.permission_id = policy.permission_id
   AND ceiling.scope = policy.scope
  WHERE policy.tenant_id = context_tenant
    AND policy.role_id = p_role_id
    AND permission.key NOT IN (
      'service_account.read',
      'service_account.manage',
      'service_account.credential.manage',
      'alert.create'
    )
  ORDER BY permission.key, policy.scope
  LIMIT p_limit;
END;
$function$;--> statement-breakpoint

CREATE OR REPLACE FUNCTION "app"."get_tenant_role_policy"(
  p_role_id uuid,
  p_limit integer
)
RETURNS TABLE (
  permission_key text,
  scope "public"."authorization_scope",
  delegable boolean
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 501 THEN
    RAISE EXCEPTION 'role policy limit must be between 1 and 501'
      USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  SELECT policy.permission_key, policy.scope, policy.delegable
  FROM app.get_tenant_role_policy_v2(p_role_id, 501) AS policy
  WHERE policy.permission_key NOT IN (
    'operator_team.read',
    'operator_team.manage',
    'operator_team.roster.manage',
    'service_account.read',
    'service_account.manage',
    'service_account.credential.manage',
    'alert.create'
  )
  ORDER BY policy.permission_key, policy.scope
  LIMIT p_limit;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION "app"."resolve_current_tenant_human_authority_v2"(integer) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."resolve_current_tenant_human_authority"(integer) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."list_tenant_permission_catalog_v2"(uuid, integer) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."list_tenant_permission_catalog"(uuid, integer) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."get_tenant_role_policy_v2"(uuid, integer) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."get_tenant_role_policy"(uuid, integer) OWNER TO "periapsis_migrator";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."resolve_current_tenant_human_authority_v2"(integer) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."resolve_current_tenant_human_authority"(integer) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."list_tenant_permission_catalog_v2"(uuid, integer) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."list_tenant_permission_catalog"(uuid, integer) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."get_tenant_role_policy_v2"(uuid, integer) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."get_tenant_role_policy"(uuid, integer) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."resolve_current_tenant_human_authority_v2"(integer) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."resolve_current_tenant_human_authority"(integer) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."list_tenant_permission_catalog_v2"(uuid, integer) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."list_tenant_permission_catalog"(uuid, integer) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."get_tenant_role_policy_v2"(uuid, integer) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."get_tenant_role_policy"(uuid, integer) TO "periapsis_api";

-- Role-path projections carry no permission rows, so exclude machine roles at
-- the role join while retaining historical machine edges in the administrative
-- list/get/revoke inventory functions.
CREATE OR REPLACE FUNCTION "app"."resolve_current_tenant_human_role_grants"(
  p_limit integer
)
RETURNS TABLE (
  grant_id uuid,
  role_id uuid,
  role_key text,
  role_name text,
  source_id uuid,
  source_type text,
  granted_by_user_id uuid,
  grant_reason text,
  granted_at timestamp with time zone,
  expires_at timestamp with time zone,
  version integer
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  context_membership uuid := app.current_tenant_membership_id();
BEGIN
  IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 201 THEN
    RAISE EXCEPTION 'effective role grant limit must be between 1 and 201'
      USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  SELECT role_grant.id, role.id, role.key, role.display_name, source.id,
         CASE source.kind
           WHEN 'manual' THEN 'direct'
           WHEN 'identity_mapping' THEN 'identity_provider'
           ELSE 'system'
         END,
         grantor.user_id, role_grant.grant_reason, role_grant.granted_at,
         role_grant.expires_at, role_grant.version
  FROM public.tenant_membership_role_grants AS role_grant
  JOIN public.tenant_authorization_sources AS source
    ON source.tenant_id = role_grant.tenant_id
   AND source.id = role_grant.source_id
  JOIN public.tenant_roles AS role
    ON role.tenant_id = role_grant.tenant_id
   AND role.id = role_grant.role_id
  LEFT JOIN public.tenant_memberships AS grantor
    ON grantor.tenant_id = role_grant.tenant_id
   AND grantor.id = role_grant.granted_by_membership_id
  WHERE role_grant.tenant_id = context_tenant
    AND role_grant.membership_id = context_membership
    AND role_grant.revoked_at IS NULL
    AND (role_grant.expires_at IS NULL
      OR role_grant.expires_at > transaction_timestamp())
    AND source.retired_at IS NULL
    AND role.principal_kind = 'human'
    AND role.archived_at IS NULL
  ORDER BY role_grant.id
  LIMIT p_limit;
END;
$function$;--> statement-breakpoint

CREATE OR REPLACE FUNCTION "app"."resolve_current_tenant_human_role_grant_paths"(
  p_limit integer
)
RETURNS TABLE (
  path_type text,
  source_type text,
  effective_expires_at timestamp with time zone,
  role_id uuid,
  role_key text,
  role_name text,
  role_grant_id uuid,
  role_source_id uuid,
  role_source_kind "public"."authorization_source_kind",
  role_source_authoritative boolean,
  role_source_retired_at timestamp with time zone,
  role_granted_by_user_id uuid,
  role_grant_reason text,
  role_granted_at timestamp with time zone,
  role_grant_expires_at timestamp with time zone,
  role_grant_version integer,
  group_id uuid,
  group_key text,
  group_name text,
  group_membership_id uuid,
  membership_source_id uuid,
  membership_source_kind "public"."authorization_source_kind",
  membership_source_authoritative boolean,
  membership_source_retired_at timestamp with time zone,
  membership_granted_by_user_id uuid,
  membership_grant_reason text,
  membership_granted_at timestamp with time zone,
  membership_expires_at timestamp with time zone,
  membership_version integer
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  context_membership uuid := app.current_tenant_membership_id();
BEGIN
  IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 201 THEN
    RAISE EXCEPTION 'effective role path limit must be between 1 and 201'
      USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  SELECT 'direct'::text,
         CASE direct_source.kind
           WHEN 'manual' THEN 'direct'
           WHEN 'identity_mapping' THEN 'identity_provider'
           ELSE 'system'
         END,
         direct_grant.expires_at,
         role.id, role.key, role.display_name, direct_grant.id,
         direct_source.id, direct_source.kind, direct_source.authoritative,
         direct_source.retired_at, grantor.user_id,
         direct_grant.grant_reason, direct_grant.granted_at,
         direct_grant.expires_at, direct_grant.version,
         NULL::uuid, NULL::text, NULL::text, NULL::uuid,
         NULL::uuid, NULL::public.authorization_source_kind,
         NULL::boolean, NULL::timestamp with time zone, NULL::uuid,
         NULL::text, NULL::timestamp with time zone,
         NULL::timestamp with time zone, NULL::integer
  FROM public.tenant_membership_role_grants AS direct_grant
  JOIN public.tenant_authorization_sources AS direct_source
    ON direct_source.tenant_id = direct_grant.tenant_id
   AND direct_source.id = direct_grant.source_id
  JOIN public.tenant_roles AS role
    ON role.tenant_id = direct_grant.tenant_id
   AND role.id = direct_grant.role_id
  LEFT JOIN public.tenant_memberships AS grantor
    ON grantor.tenant_id = direct_grant.tenant_id
   AND grantor.id = direct_grant.granted_by_membership_id
  WHERE direct_grant.tenant_id = context_tenant
    AND direct_grant.membership_id = context_membership
    AND direct_grant.revoked_at IS NULL
    AND (direct_grant.expires_at IS NULL
      OR direct_grant.expires_at > transaction_timestamp())
    AND direct_source.retired_at IS NULL
    AND role.principal_kind = 'human'
    AND role.archived_at IS NULL

  UNION ALL

  SELECT 'group'::text, 'group'::text,
         app.earliest_authorization_expiry(
           group_member.expires_at, group_grant.expires_at
         ),
         role.id, role.key, role.display_name, group_grant.id,
         grant_source.id, grant_source.kind, grant_source.authoritative,
         grant_source.retired_at, role_grantor.user_id,
         group_grant.grant_reason, group_grant.granted_at,
         group_grant.expires_at, group_grant.version,
         security_group.id, security_group.key, security_group.display_name,
         group_member.id, member_source.id, member_source.kind,
         member_source.authoritative, member_source.retired_at,
         member_grantor.user_id, group_member.grant_reason,
         group_member.granted_at, group_member.expires_at,
         group_member.version
  FROM public.tenant_security_group_memberships AS group_member
  JOIN public.tenant_authorization_sources AS member_source
    ON member_source.tenant_id = group_member.tenant_id
   AND member_source.id = group_member.source_id
  JOIN public.tenant_security_groups AS security_group
    ON security_group.tenant_id = group_member.tenant_id
   AND security_group.id = group_member.group_id
  JOIN public.tenant_security_group_role_grants AS group_grant
    ON group_grant.tenant_id = group_member.tenant_id
   AND group_grant.group_id = group_member.group_id
  JOIN public.tenant_authorization_sources AS grant_source
    ON grant_source.tenant_id = group_grant.tenant_id
   AND grant_source.id = group_grant.source_id
  JOIN public.tenant_roles AS role
    ON role.tenant_id = group_grant.tenant_id
   AND role.id = group_grant.role_id
  LEFT JOIN public.tenant_memberships AS role_grantor
    ON role_grantor.tenant_id = group_grant.tenant_id
   AND role_grantor.id = group_grant.granted_by_membership_id
  LEFT JOIN public.tenant_memberships AS member_grantor
    ON member_grantor.tenant_id = group_member.tenant_id
   AND member_grantor.id = group_member.granted_by_membership_id
  WHERE group_member.tenant_id = context_tenant
    AND group_member.membership_id = context_membership
    AND group_member.revoked_at IS NULL
    AND (group_member.expires_at IS NULL
      OR group_member.expires_at > transaction_timestamp())
    AND member_source.retired_at IS NULL
    AND security_group.archived_at IS NULL
    AND group_grant.revoked_at IS NULL
    AND (group_grant.expires_at IS NULL
      OR group_grant.expires_at > transaction_timestamp())
    AND grant_source.retired_at IS NULL
    AND role.principal_kind = 'human'
    AND role.archived_at IS NULL
  ORDER BY 1, 4, 7, 20
  LIMIT p_limit;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION "app"."resolve_current_tenant_human_role_grants"(integer) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."resolve_current_tenant_human_role_grant_paths"(integer) OWNER TO "periapsis_migrator";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."resolve_current_tenant_human_role_grants"(integer) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."resolve_current_tenant_human_role_grant_paths"(integer) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."resolve_current_tenant_human_role_grants"(integer) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."resolve_current_tenant_human_role_grant_paths"(integer) TO "periapsis_api";

-- New replicas consume v3. Unlike v2, this projection includes every current
-- human permission while still excluding machine-role paths.
CREATE FUNCTION "app"."resolve_current_tenant_human_authority_v3"(
  p_limit integer
)
RETURNS TABLE (
  permission_key text,
  scope "public"."authorization_scope",
  delegable boolean,
  delegation_expires_at timestamp with time zone
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  context_membership uuid := app.current_tenant_membership_id();
BEGIN
  IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 501 THEN
    RAISE EXCEPTION 'tenant authority limit must be between 1 and 501'
      USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  WITH role_paths AS (
    SELECT direct_grant.role_id, direct_grant.expires_at
    FROM public.tenant_membership_role_grants AS direct_grant
    JOIN public.tenant_authorization_sources AS direct_source
      ON direct_source.tenant_id = direct_grant.tenant_id
     AND direct_source.id = direct_grant.source_id
    WHERE direct_grant.tenant_id = context_tenant
      AND direct_grant.membership_id = context_membership
      AND direct_grant.revoked_at IS NULL
      AND (direct_grant.expires_at IS NULL
        OR direct_grant.expires_at > transaction_timestamp())
      AND direct_source.retired_at IS NULL

    UNION ALL

    SELECT group_grant.role_id,
           app.earliest_authorization_expiry(
             group_member.expires_at, group_grant.expires_at
           )
    FROM public.tenant_security_group_memberships AS group_member
    JOIN public.tenant_authorization_sources AS member_source
      ON member_source.tenant_id = group_member.tenant_id
     AND member_source.id = group_member.source_id
    JOIN public.tenant_security_groups AS security_group
      ON security_group.tenant_id = group_member.tenant_id
     AND security_group.id = group_member.group_id
    JOIN public.tenant_security_group_role_grants AS group_grant
      ON group_grant.tenant_id = group_member.tenant_id
     AND group_grant.group_id = group_member.group_id
    JOIN public.tenant_authorization_sources AS grant_source
      ON grant_source.tenant_id = group_grant.tenant_id
     AND grant_source.id = group_grant.source_id
    WHERE group_member.tenant_id = context_tenant
      AND group_member.membership_id = context_membership
      AND group_member.revoked_at IS NULL
      AND (group_member.expires_at IS NULL
        OR group_member.expires_at > transaction_timestamp())
      AND member_source.retired_at IS NULL
      AND security_group.archived_at IS NULL
      AND group_grant.revoked_at IS NULL
      AND (group_grant.expires_at IS NULL
        OR group_grant.expires_at > transaction_timestamp())
      AND grant_source.retired_at IS NULL
  ), effective AS (
    SELECT permission.key AS permission_key,
           role_permission.scope,
           ceiling.permission_id IS NOT NULL AS is_delegable,
           role_path.expires_at
    FROM role_paths AS role_path
    JOIN public.tenant_roles AS role
      ON role.tenant_id = context_tenant
     AND role.id = role_path.role_id
    JOIN public.tenant_role_permissions AS role_permission
      ON role_permission.tenant_id = role.tenant_id
     AND role_permission.role_id = role.id
    JOIN public.tenant_permissions AS permission
      ON permission.id = role_permission.permission_id
    LEFT JOIN public.tenant_role_delegation_ceilings AS ceiling
      ON ceiling.tenant_id = role_permission.tenant_id
     AND ceiling.role_id = role_permission.role_id
     AND ceiling.permission_id = role_permission.permission_id
     AND ceiling.scope = role_permission.scope
    WHERE role.principal_kind = 'human'
      AND role.archived_at IS NULL
      AND role_permission.scope <> 'platform'
  )
  SELECT effective.permission_key,
         effective.scope,
         bool_or(effective.is_delegable),
         CASE
           WHEN bool_or(effective.is_delegable AND effective.expires_at IS NULL)
             THEN NULL
           ELSE max(effective.expires_at) FILTER (WHERE effective.is_delegable)
         END
  FROM effective
  GROUP BY effective.permission_key, effective.scope
  ORDER BY effective.permission_key, effective.scope
  LIMIT p_limit;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."list_tenant_permission_catalog_v3"(
  p_after_id uuid,
  p_limit integer
)
RETURNS TABLE (
  permission_id uuid,
  permission_key text,
  display_name text,
  description text,
  allowed_scopes "public"."authorization_scope"[],
  principal_kinds text[]
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  PERFORM app.current_tenant_membership_id();
  IF NOT app.current_tenant_has_exact_permission('permission.read', 'tenant') THEN
    RAISE EXCEPTION 'permission.read tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 101 THEN
    RAISE EXCEPTION 'permission page limit must be between 1 and 101'
      USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  SELECT permission.id, permission.key, permission.display_name,
         permission.description,
         array_agg(
           permission_scope.scope ORDER BY permission_scope.scope
         )::public.authorization_scope[],
         CASE
           WHEN permission.service_account_allowed
             THEN ARRAY['human', 'service_account']::text[]
           ELSE ARRAY['human']::text[]
         END
  FROM public.tenant_permissions AS permission
  JOIN public.tenant_permission_scopes AS permission_scope
    ON permission_scope.permission_id = permission.id
  WHERE p_after_id IS NULL OR permission.id > p_after_id
  GROUP BY permission.id, permission.key, permission.display_name,
           permission.description, permission.service_account_allowed
  ORDER BY permission.id
  LIMIT p_limit;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."list_tenant_roles_v3"(
  p_after_id uuid,
  p_include_archived boolean,
  p_limit integer
)
RETURNS TABLE (
  role_id uuid,
  role_key text,
  display_name text,
  description text,
  principal_kind text,
  system_role boolean,
  protected_role boolean,
  version integer,
  archived_at timestamp with time zone,
  created_at timestamp with time zone,
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
  IF NOT app.current_tenant_has_exact_permission('role.read', 'tenant') THEN
    RAISE EXCEPTION 'role.read tenant scope is required' USING ERRCODE = '42501';
  END IF;
  IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 101 THEN
    RAISE EXCEPTION 'role page limit must be between 1 and 101'
      USING ERRCODE = '22023';
  END IF;
  IF p_include_archived IS NULL THEN
    RAISE EXCEPTION 'include archived must be explicit'
      USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  SELECT role.id, role.key, role.display_name, role.description,
         role.principal_kind::text, role.system_role, role.protected_role,
         role.version, role.archived_at, role.created_at, role.updated_at
  FROM public.tenant_roles AS role
  WHERE role.tenant_id = context_tenant
    AND (p_include_archived OR role.archived_at IS NULL)
    AND (p_after_id IS NULL OR role.id > p_after_id)
  ORDER BY role.id
  LIMIT p_limit;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."get_tenant_role_v3"(p_role_id uuid)
RETURNS TABLE (
  role_id uuid,
  role_key text,
  display_name text,
  description text,
  principal_kind text,
  system_role boolean,
  protected_role boolean,
  version integer,
  archived_at timestamp with time zone,
  created_at timestamp with time zone,
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
    OR app.current_tenant_has_exact_permission('role.manage', 'tenant')
    OR app.current_tenant_has_exact_permission('role.grant', 'tenant')
  ) THEN
    RAISE EXCEPTION 'role.read, role.manage, or role.grant tenant scope is required'
      USING ERRCODE = '42501';
  END IF;

  RETURN QUERY
  SELECT role.id, role.key, role.display_name, role.description,
         role.principal_kind::text, role.system_role, role.protected_role,
         role.version, role.archived_at, role.created_at, role.updated_at
  FROM public.tenant_roles AS role
  WHERE role.tenant_id = context_tenant
    AND role.id = p_role_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant role was not found' USING ERRCODE = 'P0002';
  END IF;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."get_tenant_role_policy_v3"(p_role_id uuid)
RETURNS TABLE (
  permission_key text,
  scope "public"."authorization_scope",
  delegable boolean
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
    OR app.current_tenant_has_exact_permission('role.manage', 'tenant')
    OR app.current_tenant_has_exact_permission('role.grant', 'tenant')
  ) THEN
    RAISE EXCEPTION 'role.read, role.manage, or role.grant tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM public.tenant_roles AS role
    WHERE role.tenant_id = context_tenant AND role.id = p_role_id
  ) THEN
    RAISE EXCEPTION 'tenant role was not found' USING ERRCODE = 'P0002';
  END IF;

  RETURN QUERY
  SELECT permission.key, policy.scope, ceiling.permission_id IS NOT NULL
  FROM public.tenant_role_permissions AS policy
  JOIN public.tenant_permissions AS permission
    ON permission.id = policy.permission_id
  LEFT JOIN public.tenant_role_delegation_ceilings AS ceiling
    ON ceiling.tenant_id = policy.tenant_id
   AND ceiling.role_id = policy.role_id
   AND ceiling.permission_id = policy.permission_id
   AND ceiling.scope = policy.scope
  WHERE policy.tenant_id = context_tenant
    AND policy.role_id = p_role_id
  ORDER BY permission.key, policy.scope
  LIMIT 501;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION "app"."resolve_current_tenant_human_authority_v3"(integer) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."list_tenant_permission_catalog_v3"(uuid, integer) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."list_tenant_roles_v3"(uuid, boolean, integer) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."get_tenant_role_v3"(uuid) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."get_tenant_role_policy_v3"(uuid) OWNER TO "periapsis_migrator";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."resolve_current_tenant_human_authority_v3"(integer) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."list_tenant_permission_catalog_v3"(uuid, integer) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."list_tenant_roles_v3"(uuid, boolean, integer) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."get_tenant_role_v3"(uuid) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."get_tenant_role_policy_v3"(uuid) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."resolve_current_tenant_human_authority_v3"(integer) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."list_tenant_permission_catalog_v3"(uuid, integer) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."list_tenant_roles_v3"(uuid, boolean, integer) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."get_tenant_role_v3"(uuid) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."get_tenant_role_policy_v3"(uuid) TO "periapsis_api";

-- The predecessor mutation ABIs have no principal-kind input. Keep them for
-- rolling replicas, but reject machine roles and every tuple introduced by the
-- service-principal slice. Existing machine-role edges remain untouched and
-- continue to be visible through inventory and revocable through their
-- existing revoke functions.
CREATE FUNCTION "app"."assert_legacy_human_role_projection"(
  p_role_id uuid,
  p_permission_keys text[],
  p_delegation_permission_keys text[]
)
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  target_principal_kind public.tenant_principal_kind;
BEGIN
  PERFORM app.current_tenant_membership_id();

  IF EXISTS (
    SELECT 1
    FROM unnest(
      coalesce(p_permission_keys, ARRAY[]::text[])
      || coalesce(p_delegation_permission_keys, ARRAY[]::text[])
    ) AS requested(permission_key)
    WHERE requested.permission_key IN (
      'service_account.read',
      'service_account.manage',
      'service_account.credential.manage',
      'alert.create'
    )
  ) THEN
    RAISE EXCEPTION 'legacy human-role ABI cannot represent service-principal permissions'
      USING ERRCODE = '55000';
  END IF;

  SELECT role.principal_kind
  INTO target_principal_kind
  FROM public.tenant_roles AS role
  WHERE role.tenant_id = context_tenant
    AND role.id = p_role_id;

  IF FOUND AND target_principal_kind IS DISTINCT FROM 'human' THEN
    RAISE EXCEPTION 'legacy human-role ABI cannot mutate a machine role'
      USING ERRCODE = '55000';
  END IF;

  IF FOUND AND EXISTS (
    SELECT 1
    FROM (
      SELECT policy.permission_id
      FROM public.tenant_role_permissions AS policy
      WHERE policy.tenant_id = context_tenant
        AND policy.role_id = p_role_id
      UNION
      SELECT ceiling.permission_id
      FROM public.tenant_role_delegation_ceilings AS ceiling
      WHERE ceiling.tenant_id = context_tenant
        AND ceiling.role_id = p_role_id
    ) AS current_tuple
    JOIN public.tenant_permissions AS permission
      ON permission.id = current_tuple.permission_id
    WHERE permission.key IN (
      'service_account.read',
      'service_account.manage',
      'service_account.credential.manage',
      'alert.create'
    )
  ) THEN
    RAISE EXCEPTION 'legacy human-role ABI cannot mutate a service-principal policy'
      USING ERRCODE = '55000';
  END IF;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION "app"."assert_legacy_human_role_projection"(uuid, text[], text[]) OWNER TO "periapsis_migrator";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."assert_legacy_human_role_projection"(uuid, text[], text[]) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint

ALTER FUNCTION "app"."create_tenant_role"(
  uuid, bytea, text, text, text, text[], "public"."authorization_scope"[],
  text[], "public"."authorization_scope"[], uuid, uuid, uuid, inet, text, text
) RENAME TO "create_tenant_role_legacy_human_impl";--> statement-breakpoint

ALTER FUNCTION "app"."create_tenant_role_legacy_human_impl"(
  uuid, bytea, text, text, text, text[], "public"."authorization_scope"[],
  text[], "public"."authorization_scope"[], uuid, uuid, uuid, inet, text, text
) OWNER TO "periapsis_migrator";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."create_tenant_role_legacy_human_impl"(
  uuid, bytea, text, text, text, text[], "public"."authorization_scope"[],
  text[], "public"."authorization_scope"[], uuid, uuid, uuid, inet, text, text
) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint

CREATE FUNCTION "app"."create_tenant_role"(
  p_role_id uuid,
  p_idempotency_key_digest bytea,
  p_key text,
  p_name text,
  p_description text,
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
RETURNS TABLE (
  result_resource_id uuid,
  result_version integer,
  replayed boolean
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  PERFORM app.assert_legacy_human_role_projection(
    p_role_id, p_permission_keys, p_delegation_permission_keys
  );
  RETURN QUERY
  SELECT result.result_resource_id, result.result_version, result.replayed
  FROM app.create_tenant_role_legacy_human_impl(
    p_role_id, p_idempotency_key_digest, p_key, p_name, p_description,
    p_permission_keys, p_scopes,
    p_delegation_permission_keys, p_delegation_scopes,
    p_audit_event_id, p_request_id, p_correlation_id,
    p_ip_address, p_user_agent, p_authentication_method
  ) AS result;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION "app"."create_tenant_role"(
  uuid, bytea, text, text, text, text[], "public"."authorization_scope"[],
  text[], "public"."authorization_scope"[], uuid, uuid, uuid, inet, text, text
) OWNER TO "periapsis_migrator";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."create_tenant_role"(
  uuid, bytea, text, text, text, text[], "public"."authorization_scope"[],
  text[], "public"."authorization_scope"[], uuid, uuid, uuid, inet, text, text
) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."create_tenant_role"(
  uuid, bytea, text, text, text, text[], "public"."authorization_scope"[],
  text[], "public"."authorization_scope"[], uuid, uuid, uuid, inet, text, text
) TO "periapsis_api";--> statement-breakpoint

ALTER FUNCTION "app"."replace_tenant_role_policy_v2"(
  uuid, integer, text[], "public"."authorization_scope"[], text[],
  "public"."authorization_scope"[], uuid, uuid, uuid, inet, text, text
) RENAME TO "replace_tenant_role_policy_v2_legacy_human_impl";--> statement-breakpoint

-- sqlc's migration catalog does not model ALTER FUNCTION ... RENAME. On a
-- migrated PostgreSQL database the old name is already absent, while this
-- no-op removes the stale symbol from sqlc's in-memory catalog.
DROP FUNCTION IF EXISTS "app"."replace_tenant_role_policy_v2"(
  uuid, integer, text[], "public"."authorization_scope"[], text[],
  "public"."authorization_scope"[], uuid, uuid, uuid, inet, text, text
);--> statement-breakpoint

ALTER FUNCTION "app"."replace_tenant_role_policy_v2_legacy_human_impl"(
  uuid, integer, text[], "public"."authorization_scope"[], text[],
  "public"."authorization_scope"[], uuid, uuid, uuid, inet, text, text
) OWNER TO "periapsis_migrator";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."replace_tenant_role_policy_v2_legacy_human_impl"(
  uuid, integer, text[], "public"."authorization_scope"[], text[],
  "public"."authorization_scope"[], uuid, uuid, uuid, inet, text, text
) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint

CREATE FUNCTION "app"."replace_tenant_role_policy_v2"(
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
BEGIN
  PERFORM app.assert_legacy_human_role_projection(
    p_role_id, p_permission_keys, p_delegation_permission_keys
  );
  RETURN app.replace_tenant_role_policy_v2_legacy_human_impl(
    p_role_id, p_expected_version,
    p_permission_keys, p_scopes,
    p_delegation_permission_keys, p_delegation_scopes,
    p_audit_event_id, p_request_id, p_correlation_id,
    p_ip_address, p_user_agent, p_authentication_method
  );
END;
$function$;--> statement-breakpoint

ALTER FUNCTION "app"."replace_tenant_role_policy_v2"(
  uuid, integer, text[], "public"."authorization_scope"[], text[],
  "public"."authorization_scope"[], uuid, uuid, uuid, inet, text, text
) OWNER TO "periapsis_migrator";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."replace_tenant_role_policy_v2"(
  uuid, integer, text[], "public"."authorization_scope"[], text[],
  "public"."authorization_scope"[], uuid, uuid, uuid, inet, text, text
) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."replace_tenant_role_policy_v2"(
  uuid, integer, text[], "public"."authorization_scope"[], text[],
  "public"."authorization_scope"[], uuid, uuid, uuid, inet, text, text
) TO "periapsis_api";--> statement-breakpoint

ALTER FUNCTION "app"."grant_tenant_user_role"(
  uuid, bytea, uuid, uuid, text, timestamp with time zone,
  uuid, uuid, uuid, inet, text, text
) RENAME TO "grant_tenant_user_role_legacy_human_impl";--> statement-breakpoint

ALTER FUNCTION "app"."grant_tenant_user_role_legacy_human_impl"(
  uuid, bytea, uuid, uuid, text, timestamp with time zone,
  uuid, uuid, uuid, inet, text, text
) OWNER TO "periapsis_migrator";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."grant_tenant_user_role_legacy_human_impl"(
  uuid, bytea, uuid, uuid, text, timestamp with time zone,
  uuid, uuid, uuid, inet, text, text
) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint

CREATE FUNCTION "app"."grant_tenant_user_role"(
  p_grant_id uuid,
  p_idempotency_key_digest bytea,
  p_target_user_id uuid,
  p_role_id uuid,
  p_reason text,
  p_expires_at timestamp with time zone,
  p_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE (
  result_resource_id uuid,
  result_version integer,
  replayed boolean
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  PERFORM app.assert_legacy_human_role_projection(
    p_role_id, ARRAY[]::text[], ARRAY[]::text[]
  );
  RETURN QUERY
  SELECT result.result_resource_id, result.result_version, result.replayed
  FROM app.grant_tenant_user_role_legacy_human_impl(
    p_grant_id, p_idempotency_key_digest, p_target_user_id, p_role_id,
    p_reason, p_expires_at, p_audit_event_id, p_request_id,
    p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method
  ) AS result;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION "app"."grant_tenant_user_role"(
  uuid, bytea, uuid, uuid, text, timestamp with time zone,
  uuid, uuid, uuid, inet, text, text
) OWNER TO "periapsis_migrator";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."grant_tenant_user_role"(
  uuid, bytea, uuid, uuid, text, timestamp with time zone,
  uuid, uuid, uuid, inet, text, text
) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."grant_tenant_user_role"(
  uuid, bytea, uuid, uuid, text, timestamp with time zone,
  uuid, uuid, uuid, inet, text, text
) TO "periapsis_api";--> statement-breakpoint

ALTER FUNCTION "app"."grant_tenant_security_group_role"(
  uuid, bytea, uuid, uuid, text, timestamp with time zone,
  uuid, uuid, uuid, inet, text, text
) RENAME TO "grant_tenant_security_group_role_legacy_human_impl";--> statement-breakpoint

ALTER FUNCTION "app"."grant_tenant_security_group_role_legacy_human_impl"(
  uuid, bytea, uuid, uuid, text, timestamp with time zone,
  uuid, uuid, uuid, inet, text, text
) OWNER TO "periapsis_migrator";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."grant_tenant_security_group_role_legacy_human_impl"(
  uuid, bytea, uuid, uuid, text, timestamp with time zone,
  uuid, uuid, uuid, inet, text, text
) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint

CREATE FUNCTION "app"."grant_tenant_security_group_role"(
  p_group_role_grant_id uuid,
  p_idempotency_key_digest bytea,
  p_group_id uuid,
  p_role_id uuid,
  p_reason text,
  p_expires_at timestamp with time zone,
  p_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE (
  result_resource_id uuid,
  result_version integer,
  replayed boolean
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  PERFORM app.assert_legacy_human_role_projection(
    p_role_id, ARRAY[]::text[], ARRAY[]::text[]
  );
  RETURN QUERY
  SELECT result.result_resource_id, result.result_version, result.replayed
  FROM app.grant_tenant_security_group_role_legacy_human_impl(
    p_group_role_grant_id, p_idempotency_key_digest, p_group_id,
    p_role_id, p_reason, p_expires_at, p_audit_event_id, p_request_id,
    p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method
  ) AS result;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION "app"."grant_tenant_security_group_role"(
  uuid, bytea, uuid, uuid, text, timestamp with time zone,
  uuid, uuid, uuid, inet, text, text
) OWNER TO "periapsis_migrator";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."grant_tenant_security_group_role"(
  uuid, bytea, uuid, uuid, text, timestamp with time zone,
  uuid, uuid, uuid, inet, text, text
) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."grant_tenant_security_group_role"(
  uuid, bytea, uuid, uuid, text, timestamp with time zone,
  uuid, uuid, uuid, inet, text, text
) TO "periapsis_api";

-- Adding a nullable actor column must not change any historical audit payload
-- byte. Remove precisely the new key while it is null; retain it for future
-- service-account events. The existing hash and timestamp exclusions remain
-- byte-for-byte equivalent.
CREATE OR REPLACE FUNCTION "app"."audit_event_payload"(
  p_event "public"."audit_events"
)
RETURNS jsonb
LANGUAGE sql
STABLE
STRICT
PARALLEL SAFE
SET search_path = pg_catalog, public, app
AS $function$
  SELECT
    (
      CASE
        WHEN p_event.actor_service_account_id IS NULL
          THEN to_jsonb(p_event) - 'actor_service_account_id'
        ELSE to_jsonb(p_event)
      END
      - 'previous_hash' - 'event_hash' - 'occurred_at'
    )
    || jsonb_build_object(
      'occurred_at',
      to_char(
        p_event.occurred_at AT TIME ZONE 'UTC',
        'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
      )
    );
$function$;--> statement-breakpoint

ALTER FUNCTION "app"."audit_event_payload"("public"."audit_events") OWNER TO "periapsis_migrator";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."audit_event_payload"("public"."audit_events") FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."audit_event_payload"("public"."audit_events") TO "periapsis_api", "periapsis_auditor";--> statement-breakpoint

-- Resolve the legacy user identifier to exactly one tenant membership before
-- the final migration installs the human-or-service-account creator XOR.
DO $alert_creator_backfill$
DECLARE
  invalid_alert_id uuid;
BEGIN
  SELECT alert.id
  INTO invalid_alert_id
  FROM public.alerts AS alert
  WHERE (
    SELECT count(*)
    FROM public.tenant_memberships AS membership
    WHERE membership.tenant_id = alert.tenant_id
      AND membership.user_id = alert.created_by
  ) <> 1
  ORDER BY alert.tenant_id, alert.id
  LIMIT 1;

  IF invalid_alert_id IS NOT NULL THEN
    RAISE EXCEPTION
      'service-principal alert backfill failed: alert % does not have exactly one creator membership',
      invalid_alert_id
      USING ERRCODE = '23514';
  END IF;

  SELECT alert.id
  INTO invalid_alert_id
  FROM public.alerts AS alert
  WHERE alert.created_by_membership_id IS NOT NULL
    AND NOT EXISTS (
      SELECT 1
      FROM public.tenant_memberships AS membership
      WHERE membership.tenant_id = alert.tenant_id
        AND membership.id = alert.created_by_membership_id
        AND membership.user_id = alert.created_by
    )
  ORDER BY alert.tenant_id, alert.id
  LIMIT 1;

  IF invalid_alert_id IS NOT NULL THEN
    RAISE EXCEPTION
      'service-principal alert backfill failed: alert % has conflicting creator attribution',
      invalid_alert_id
      USING ERRCODE = '23514';
  END IF;

  UPDATE public.alerts AS alert
  SET created_by_membership_id = (
    SELECT membership.id
    FROM public.tenant_memberships AS membership
    WHERE membership.tenant_id = alert.tenant_id
      AND membership.user_id = alert.created_by
  )
  WHERE alert.created_by_membership_id IS NULL;

  IF EXISTS (
    SELECT 1
    FROM public.alerts AS alert
    WHERE alert.created_by_membership_id IS NULL
      OR alert.created_by_service_account_id IS NOT NULL
      OR NOT EXISTS (
        SELECT 1
        FROM public.tenant_memberships AS membership
        WHERE membership.tenant_id = alert.tenant_id
          AND membership.id = alert.created_by_membership_id
          AND membership.user_id = alert.created_by
      )
  ) THEN
    RAISE EXCEPTION 'service-principal alert creator backfill is incomplete'
      USING ERRCODE = '23514';
  END IF;
END;
$alert_creator_backfill$;--> statement-breakpoint

-- Keep future tenant seeding compatible with the new principal-kind invariant.
-- The predecessor implementation still establishes every historical row and
-- recovery edge; this wrapper changes only the empty built-in machine role.
ALTER FUNCTION "app"."seed_tenant_authorization"(uuid, uuid)
  RENAME TO "seed_tenant_authorization_legacy_impl";--> statement-breakpoint
-- See the sqlc rename-catalog compatibility note above.
DROP FUNCTION IF EXISTS "app"."seed_tenant_authorization"(uuid, uuid);--> statement-breakpoint
ALTER FUNCTION "app"."seed_tenant_authorization_legacy_impl"(uuid, uuid)
  OWNER TO "periapsis_migrator";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."seed_tenant_authorization_legacy_impl"(uuid, uuid)
  FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint

CREATE FUNCTION "app"."seed_tenant_authorization"(
  p_tenant_id uuid,
  p_initial_admin_membership_id uuid
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  machine_role record;
BEGIN
  PERFORM app.seed_tenant_authorization_legacy_impl(
    p_tenant_id, p_initial_admin_membership_id
  );

  SELECT role.*
  INTO STRICT machine_role
  FROM public.tenant_roles AS role
  WHERE role.tenant_id = p_tenant_id
    AND role.key = 'service_account'
    AND role.system_role
    AND NOT role.protected_role
    AND role.archived_at IS NULL
  FOR UPDATE;

  IF machine_role.principal_kind NOT IN ('human', 'service_account') THEN
    RAISE EXCEPTION 'built-in service-account role has an invalid principal kind'
      USING ERRCODE = '23514';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM public.tenant_role_permissions AS policy
    WHERE policy.tenant_id = p_tenant_id
      AND policy.role_id = machine_role.id
    UNION ALL
    SELECT 1
    FROM public.tenant_role_delegation_ceilings AS ceiling
    WHERE ceiling.tenant_id = p_tenant_id
      AND ceiling.role_id = machine_role.id
  ) THEN
    RAISE EXCEPTION 'built-in service-account role must be empty during compatibility seeding'
      USING ERRCODE = '23514';
  END IF;

  UPDATE public.tenant_roles AS role
  SET principal_kind = 'service_account'
  WHERE role.tenant_id = p_tenant_id
    AND role.id = machine_role.id
    AND role.principal_kind = 'human';

  IF NOT EXISTS (
    SELECT 1
    FROM public.tenant_roles AS role
    WHERE role.tenant_id = p_tenant_id
      AND role.id = machine_role.id
      AND role.principal_kind = 'service_account'
  ) THEN
    RAISE EXCEPTION 'built-in service-account role transition failed'
      USING ERRCODE = '23514';
  END IF;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION "app"."seed_tenant_authorization"(uuid, uuid) OWNER TO "periapsis_migrator";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."seed_tenant_authorization"(uuid, uuid) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint

-- Transition exactly the canonical empty built-in role for every tenant. A
-- historical direct/group edge may still name it; those edges are deliberately
-- neither rewritten nor deleted.
DO $service_account_role_transition$
DECLARE
  transitioned_count bigint;
  expected_count bigint;
BEGIN
  IF EXISTS (
    SELECT tenant.id
    FROM public.tenants AS tenant
    LEFT JOIN public.tenant_roles AS role
      ON role.tenant_id = tenant.id
     AND role.key = 'service_account'
    GROUP BY tenant.id
    HAVING count(role.id) <> 1
       OR bool_or(
         role.system_role IS DISTINCT FROM true
         OR role.protected_role IS DISTINCT FROM false
         OR role.archived_at IS NOT NULL
       )
  ) THEN
    RAISE EXCEPTION 'each tenant must have exactly one live built-in service-account role'
      USING ERRCODE = '23514';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM public.tenant_roles AS role
    WHERE role.principal_kind <> 'human'
  ) THEN
    RAISE EXCEPTION 'unexpected pre-transition machine role exists'
      USING ERRCODE = '23514';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM public.tenant_roles AS role
    WHERE role.key = 'service_account'
      AND (
        EXISTS (
          SELECT 1
          FROM public.tenant_role_permissions AS policy
          WHERE policy.tenant_id = role.tenant_id
            AND policy.role_id = role.id
        )
        OR EXISTS (
          SELECT 1
          FROM public.tenant_role_delegation_ceilings AS ceiling
          WHERE ceiling.tenant_id = role.tenant_id
            AND ceiling.role_id = role.id
        )
      )
  ) THEN
    RAISE EXCEPTION 'built-in service-account role must be empty before transition'
      USING ERRCODE = '23514';
  END IF;

  SELECT count(*) INTO expected_count FROM public.tenants;

  UPDATE public.tenant_roles AS role
  SET principal_kind = 'service_account'
  WHERE role.key = 'service_account'
    AND role.system_role
    AND NOT role.protected_role
    AND role.archived_at IS NULL
    AND role.principal_kind = 'human';
  GET DIAGNOSTICS transitioned_count = ROW_COUNT;

  IF transitioned_count IS DISTINCT FROM expected_count THEN
    RAISE EXCEPTION
      'built-in service-account role transition count % does not match tenant count %',
      transitioned_count, expected_count
      USING ERRCODE = '23514';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM public.tenant_roles AS role
    WHERE (role.key = 'service_account')
      IS DISTINCT FROM (role.principal_kind = 'service_account')
  ) THEN
    RAISE EXCEPTION 'only the built-in service-account role may be a machine role'
      USING ERRCODE = '23514';
  END IF;
END;
$service_account_role_transition$;

-- Migration-local sentinels make ordering and fail-closed compatibility
-- properties explicit before the following migration enables the new catalog
-- entries and service-account runtime surface.
DO $compatibility_assertions$
DECLARE
  authority_v2_definition text;
  catalog_v2_definition text;
  policy_v2_definition text;
  required_key text;
BEGIN
  IF EXISTS (
    SELECT 1
    FROM public.tenant_permissions AS permission
    WHERE permission.key IN (
      'service_account.read',
      'service_account.manage',
      'service_account.credential.manage',
      'alert.create'
    )
  ) THEN
    RAISE EXCEPTION 'service-principal permissions were enabled before compatibility hardening'
      USING ERRCODE = '55000';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM public.tenant_roles AS role
    WHERE (role.key = 'service_account')
      IS DISTINCT FROM (role.principal_kind = 'service_account')
       OR (role.principal_kind = 'service_account' AND (
         NOT role.system_role
         OR role.protected_role
         OR role.archived_at IS NOT NULL
         OR EXISTS (
           SELECT 1
           FROM public.tenant_role_permissions AS policy
           WHERE policy.tenant_id = role.tenant_id
             AND policy.role_id = role.id
         )
         OR EXISTS (
           SELECT 1
           FROM public.tenant_role_delegation_ceilings AS ceiling
           WHERE ceiling.tenant_id = role.tenant_id
             AND ceiling.role_id = role.id
         )
       ))
  ) THEN
    RAISE EXCEPTION 'service-account role compatibility invariant is not sealed'
      USING ERRCODE = '55000';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM public.alerts AS alert
    WHERE alert.created_by_membership_id IS NULL
      OR alert.created_by_service_account_id IS NOT NULL
      OR NOT EXISTS (
        SELECT 1
        FROM public.tenant_memberships AS membership
        WHERE membership.tenant_id = alert.tenant_id
          AND membership.id = alert.created_by_membership_id
          AND membership.user_id = alert.created_by
      )
  ) THEN
    RAISE EXCEPTION 'legacy Alert creator attribution is not sealed'
      USING ERRCODE = '55000';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM public.audit_events AS event
    WHERE event.actor_service_account_id IS NULL
      AND app.audit_event_payload(event) ? 'actor_service_account_id'
  ) THEN
    RAISE EXCEPTION 'historical audit payload contains the additive actor key'
      USING ERRCODE = '55000';
  END IF;

  SELECT pg_get_functiondef(
    'app.resolve_current_tenant_human_authority_v2(integer)'::regprocedure
  ) INTO authority_v2_definition;
  SELECT pg_get_functiondef(
    'app.list_tenant_permission_catalog_v2(uuid,integer)'::regprocedure
  ) INTO catalog_v2_definition;
  SELECT pg_get_functiondef(
    'app.get_tenant_role_policy_v2(uuid,integer)'::regprocedure
  ) INTO policy_v2_definition;

  IF position('principal_kind = ''human''' IN authority_v2_definition) = 0
     OR position('principal_kind = ''human''' IN policy_v2_definition) = 0 THEN
    RAISE EXCEPTION 'predecessor human ABI is missing its principal-kind sentinel'
      USING ERRCODE = '55000';
  END IF;

  FOREACH required_key IN ARRAY ARRAY[
    'service_account.read',
    'service_account.manage',
    'service_account.credential.manage',
    'alert.create'
  ]::text[] LOOP
    IF position(required_key IN authority_v2_definition) = 0
       OR position(required_key IN catalog_v2_definition) = 0
       OR position(required_key IN policy_v2_definition) = 0 THEN
      RAISE EXCEPTION 'predecessor ABI denylist is missing key %', required_key
        USING ERRCODE = '55000';
    END IF;
  END LOOP;

  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_proc AS procedure
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = procedure.pronamespace
    WHERE namespace.nspname = 'app'
      AND procedure.proname IN (
        'create_tenant_role_legacy_human_impl',
        'replace_tenant_role_policy_v2_legacy_human_impl',
        'grant_tenant_user_role_legacy_human_impl',
        'grant_tenant_security_group_role_legacy_human_impl',
        'seed_tenant_authorization_legacy_impl'
      )
      AND (
        pg_catalog.has_function_privilege(
          'periapsis_api', procedure.oid, 'EXECUTE'
        )
        OR pg_catalog.has_function_privilege(
          'periapsis_worker', procedure.oid, 'EXECUTE'
        )
        OR pg_catalog.has_function_privilege(
          'periapsis_notifier', procedure.oid, 'EXECUTE'
        )
        OR pg_catalog.has_function_privilege(
          'periapsis_auditor', procedure.oid, 'EXECUTE'
        )
      )
  ) THEN
    RAISE EXCEPTION 'a private predecessor mutation implementation is runtime-executable'
      USING ERRCODE = '55000';
  END IF;
END;
$compatibility_assertions$;
