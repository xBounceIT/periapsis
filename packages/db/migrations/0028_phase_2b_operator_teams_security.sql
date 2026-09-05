-- Phase 2B.2b operator-team security boundary. The generated 0027 migration
-- remains the canonical structural schema; this migration owns forced RLS,
-- least-privilege definer entry points, rolling authorization ABI isolation,
-- exact-epoch relationship evaluation, command replay guards, and atomic audit.

ALTER TABLE "public"."operator_teams" OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER TABLE "public"."platform_commands" OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER TABLE "public"."operator_team_assignment_epochs" OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER TABLE "public"."operator_team_roster_entries" OWNER TO "periapsis_migrator";--> statement-breakpoint

ALTER TABLE "public"."operator_teams" FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "public"."platform_commands" FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "public"."operator_team_assignment_epochs" FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "public"."operator_team_roster_entries" FORCE ROW LEVEL SECURITY;--> statement-breakpoint

REVOKE ALL ON TABLE "public"."operator_teams" FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON TABLE "public"."platform_commands" FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON TABLE "public"."operator_team_assignment_epochs" FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON TABLE "public"."operator_team_roster_entries" FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint

INSERT INTO "public"."platform_permissions" ("id", "key", "description")
VALUES
  (uuidv7(), 'platform.operator_team.read', 'List and inspect global operator teams'),
  (uuidv7(), 'platform.operator_team.manage', 'Create, update, and archive global operator teams')
ON CONFLICT ("key") DO NOTHING;--> statement-breakpoint

INSERT INTO "public"."platform_role_permissions" ("role_id", "permission_id")
SELECT role.id, permission.id
FROM "public"."platform_roles" AS role
CROSS JOIN "public"."platform_permissions" AS permission
WHERE role.key = 'platform_super_admin'
  AND role.system
  AND permission.key IN (
    'platform.operator_team.read', 'platform.operator_team.manage'
  )
ON CONFLICT DO NOTHING;--> statement-breakpoint

DO $block$
BEGIN
  IF (
    SELECT count(*)
    FROM public.platform_permissions AS permission
    WHERE permission.key IN (
      'platform.operator_team.read', 'platform.operator_team.manage'
    )
  ) <> 2 OR (
    SELECT count(*)
    FROM public.platform_role_permissions AS role_permission
    JOIN public.platform_roles AS role
      ON role.id = role_permission.role_id
    JOIN public.platform_permissions AS permission
      ON permission.id = role_permission.permission_id
    WHERE role.key = 'platform_super_admin'
      AND role.system
      AND permission.key IN (
        'platform.operator_team.read', 'platform.operator_team.manage'
      )
  ) <> 2 THEN
    RAISE EXCEPTION 'operator-team platform permission catalog is invalid'
      USING ERRCODE = '55000';
  END IF;
END;
$block$;--> statement-breakpoint

INSERT INTO "public"."tenant_permissions" (
  "id", "key", "display_name", "description", "service_account_allowed"
)
VALUES
  (uuidv7(), 'operator_team.read', 'Read operator-team assignments', 'Read tenant assignment epochs and exact-epoch roster provenance.', false),
  (uuidv7(), 'operator_team.manage', 'Manage operator-team assignments', 'Start and end tenant assignment epochs for global operator teams.', false),
  (uuidv7(), 'operator_team.roster.manage', 'Manage operator-team rosters', 'Add and revoke exact-epoch operator-team roster entries.', false)
ON CONFLICT ("key") DO NOTHING;--> statement-breakpoint

INSERT INTO "public"."tenant_permission_scopes" ("permission_id", "scope")
SELECT permission.id, allowed.scope
FROM "public"."tenant_permissions" AS permission
JOIN (
  VALUES
    ('operator_team.read'::text, 'tenant'::public.authorization_scope),
    ('operator_team.read'::text, 'operator_team'::public.authorization_scope),
    ('operator_team.manage'::text, 'tenant'::public.authorization_scope),
    ('operator_team.roster.manage'::text, 'tenant'::public.authorization_scope),
    ('operator_team.roster.manage'::text, 'operator_team'::public.authorization_scope)
) AS allowed(permission_key, scope)
  ON allowed.permission_key = permission.key
ON CONFLICT DO NOTHING;--> statement-breakpoint

DO $block$
BEGIN
  IF (
    SELECT count(*)
    FROM public.tenant_permissions AS permission
    JOIN public.tenant_permission_scopes AS permission_scope
      ON permission_scope.permission_id = permission.id
    WHERE permission.key IN (
      'operator_team.read',
      'operator_team.manage',
      'operator_team.roster.manage'
    )
      AND permission.service_account_allowed IS FALSE
  ) <> 5 OR EXISTS (
    SELECT 1
    FROM public.tenant_permissions AS permission
    JOIN public.tenant_permission_scopes AS permission_scope
      ON permission_scope.permission_id = permission.id
    WHERE permission.key = 'operator_team.read'
      AND permission_scope.scope NOT IN ('tenant', 'operator_team')
       OR permission.key = 'operator_team.manage'
      AND permission_scope.scope <> 'tenant'
       OR permission.key = 'operator_team.roster.manage'
      AND permission_scope.scope NOT IN ('tenant', 'operator_team')
  ) THEN
    RAISE EXCEPTION 'operator-team tenant permission catalog is invalid'
      USING ERRCODE = '55000';
  END IF;
END;
$block$;--> statement-breakpoint

-- Existing initialized tenant administrators receive all five new tuples as
-- one strong-representation change. An idempotent rerun adds no rows and does
-- not advance the role version, while every inspected role receives audit.
DO $block$
DECLARE
  target_state record;
  target_role record;
  policy_rows_added integer;
  ceiling_rows_added integer;
  result_version integer;
BEGIN
  -- Runtime authorization mutations lock the tenant state before any role.
  -- Preserve that same order while backfilling each initialized tenant so a
  -- rolling old-ABI mutation cannot deadlock this unreleased migration.
  FOR target_state IN
    SELECT state.tenant_id
    FROM public.tenant_authorization_states AS state
    WHERE state.initialized_at IS NOT NULL
    ORDER BY state.tenant_id
    FOR UPDATE
  LOOP
    FOR target_role IN
    SELECT role.tenant_id, role.id, role.version
    FROM public.tenant_roles AS role
    WHERE role.tenant_id = target_state.tenant_id
      AND role.key = 'tenant_admin'
      AND role.system_role
      AND role.protected_role
      AND role.archived_at IS NULL
    ORDER BY role.id
    FOR UPDATE
    LOOP
    IF target_role.version >= 2147483647 AND EXISTS (
      SELECT 1
      FROM public.tenant_permission_scopes AS permission_scope
      JOIN public.tenant_permissions AS permission
        ON permission.id = permission_scope.permission_id
      WHERE permission.key IN (
        'operator_team.read',
        'operator_team.manage',
        'operator_team.roster.manage'
      )
        AND (
          NOT EXISTS (
            SELECT 1
            FROM public.tenant_role_permissions AS policy
            WHERE policy.tenant_id = target_role.tenant_id
              AND policy.role_id = target_role.id
              AND policy.permission_id = permission_scope.permission_id
              AND policy.scope = permission_scope.scope
          ) OR NOT EXISTS (
            SELECT 1
            FROM public.tenant_role_delegation_ceilings AS ceiling
            WHERE ceiling.tenant_id = target_role.tenant_id
              AND ceiling.role_id = target_role.id
              AND ceiling.permission_id = permission_scope.permission_id
              AND ceiling.scope = permission_scope.scope
          )
        )
    ) THEN
      RAISE EXCEPTION 'tenant_admin role version is exhausted during operator-team backfill'
        USING ERRCODE = '55000';
    END IF;

    INSERT INTO public.tenant_role_permissions (
      tenant_id, role_id, permission_id, scope, created_by_membership_id
    )
    SELECT target_role.tenant_id, target_role.id,
           permission_scope.permission_id, permission_scope.scope, NULL
    FROM public.tenant_permission_scopes AS permission_scope
    JOIN public.tenant_permissions AS permission
      ON permission.id = permission_scope.permission_id
    WHERE permission.key IN (
      'operator_team.read',
      'operator_team.manage',
      'operator_team.roster.manage'
    )
    ON CONFLICT DO NOTHING;
    GET DIAGNOSTICS policy_rows_added = ROW_COUNT;

    INSERT INTO public.tenant_role_delegation_ceilings (
      tenant_id, role_id, permission_id, scope, created_by_membership_id
    )
    SELECT target_role.tenant_id, target_role.id,
           permission_scope.permission_id, permission_scope.scope, NULL
    FROM public.tenant_permission_scopes AS permission_scope
    JOIN public.tenant_permissions AS permission
      ON permission.id = permission_scope.permission_id
    WHERE permission.key IN (
      'operator_team.read',
      'operator_team.manage',
      'operator_team.roster.manage'
    )
    ON CONFLICT DO NOTHING;
    GET DIAGNOSTICS ceiling_rows_added = ROW_COUNT;

    result_version := target_role.version;
    IF policy_rows_added > 0 OR ceiling_rows_added > 0 THEN
      result_version := target_role.version + 1;
      UPDATE public.tenant_roles AS role
      SET version = result_version,
          updated_at = transaction_timestamp()
      WHERE role.tenant_id = target_role.tenant_id
        AND role.id = target_role.id;
    END IF;

    INSERT INTO public.audit_events (
      id, tenant_id, sequence, actor_type, action, resource_type, resource_id,
      authentication_method, outcome, after, metadata
    ) VALUES (
      uuidv7(), target_role.tenant_id, 0, 'system',
      'tenant.authorization.operator_teams_enabled', 'tenant_role',
      target_role.id, 'database_migration', 'success',
      jsonb_build_object(
        'permissions', jsonb_build_array(
          'operator_team.read',
          'operator_team.manage',
          'operator_team.roster.manage'
        ),
        'prior_version', target_role.version,
        'result_version', result_version
      ),
      jsonb_build_object(
        'migration', '0028_phase_2b_operator_teams_security',
        'policy_rows_added', policy_rows_added,
        'delegation_rows_added', ceiling_rows_added,
        'prior_version', target_role.version,
        'result_version', result_version
      )
    );
    END LOOP;
  END LOOP;
END;
$block$;--> statement-breakpoint

CREATE TRIGGER "operator_team_assignment_epochs_touch"
BEFORE INSERT OR UPDATE OR DELETE ON "public"."operator_team_assignment_epochs"
FOR EACH ROW EXECUTE FUNCTION "app"."touch_tenant_authorization_row"();--> statement-breakpoint
CREATE TRIGGER "operator_team_roster_entries_touch"
BEFORE INSERT OR UPDATE OR DELETE ON "public"."operator_team_roster_entries"
FOR EACH ROW EXECUTE FUNCTION "app"."touch_tenant_authorization_row"();--> statement-breakpoint

-- Rolling authorization ABI. New entry points expose the complete catalog;
-- predecessor entry points remove exactly the Phase 2B.2b keys so older
-- binaries never deserialize or replace tuples they cannot represent.
CREATE FUNCTION "app"."get_auth_session_v2"(p_token_digest bytea)
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
$function$;--> statement-breakpoint

CREATE OR REPLACE FUNCTION "app"."get_auth_session"(p_token_digest bytea)
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
           FROM unnest(current_session.platform_permissions)
             AS permission_key
           WHERE permission_key NOT IN (
             'platform.operator_team.read',
             'platform.operator_team.manage'
           )
           ORDER BY permission_key
         )
  FROM app.get_auth_session_v2(p_token_digest) AS current_session;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."resolve_current_tenant_human_authority_v2"(
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
    WHERE role.archived_at IS NULL
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
    'operator_team.roster.manage'
  )
  ORDER BY authority.permission_key, authority.scope
  LIMIT p_limit;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."list_tenant_permission_catalog_v2"(
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
  WHERE p_after_id IS NULL OR permission.id > p_after_id
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
    'operator_team.roster.manage'
  )
  ORDER BY catalog.permission_id
  LIMIT p_limit;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."get_tenant_role_policy_v2"(
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
    'operator_team.roster.manage'
  )
  ORDER BY policy.permission_key, policy.scope
  LIMIT p_limit;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."current_tenant_has_live_operator_team_relationship"(
  p_operator_team_id uuid,
  p_assignment_epoch_id uuid
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT EXISTS (
    SELECT 1
    FROM public.operator_team_assignment_epochs AS assignment
    JOIN public.operator_teams AS operator_team
      ON operator_team.id = assignment.operator_team_id
    JOIN public.operator_team_roster_entries AS roster
      ON roster.tenant_id = assignment.tenant_id
     AND roster.assignment_epoch_id = assignment.id
    JOIN public.tenant_authorization_sources AS source
      ON source.tenant_id = roster.tenant_id
     AND source.id = roster.source_id
    JOIN public.tenant_memberships AS membership
      ON membership.tenant_id = roster.tenant_id
     AND membership.id = roster.membership_id
    JOIN public.users AS identity
      ON identity.id = membership.user_id
    JOIN public.tenants AS tenant
      ON tenant.id = assignment.tenant_id
    JOIN public.tenant_authorization_states AS state
      ON state.tenant_id = assignment.tenant_id
     AND state.initialized_at IS NOT NULL
    WHERE assignment.tenant_id = app.context_tenant_id()
      AND assignment.operator_team_id = p_operator_team_id
      AND assignment.id = p_assignment_epoch_id
      AND assignment.ended_at IS NULL
      AND operator_team.archived_at IS NULL
      AND roster.membership_id = app.current_tenant_membership_id()
      AND roster.revoked_at IS NULL
      AND (roster.expires_at IS NULL
        OR roster.expires_at > transaction_timestamp())
      AND source.retired_at IS NULL
      AND membership.status = 'active'
      AND identity.active
      AND tenant.status = 'active'
  );
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."current_tenant_can_read_operator_team"(
  p_operator_team_id uuid,
  p_assignment_epoch_id uuid
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT app.current_tenant_has_exact_permission(
           'operator_team.read', 'tenant'
         )
      OR (
        app.current_tenant_has_exact_permission(
          'operator_team.read', 'operator_team'
        )
        AND app.current_tenant_has_live_operator_team_relationship(
          p_operator_team_id, p_assignment_epoch_id
        )
      );
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."current_tenant_can_manage_operator_team_roster"(
  p_operator_team_id uuid,
  p_assignment_epoch_id uuid
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT app.current_tenant_has_exact_permission(
           'operator_team.roster.manage', 'tenant'
         )
      OR (
        app.current_tenant_has_exact_permission(
          'operator_team.roster.manage', 'operator_team'
        )
        AND app.current_tenant_has_live_operator_team_relationship(
          p_operator_team_id, p_assignment_epoch_id
        )
      );
$function$;--> statement-breakpoint

-- Recheck only the target's effective operator_team-scoped role tuples. The
-- required delegation horizon is the minimum of each live authority path and
-- the roster edge, then the maximum across paths for the same exact tuple.
CREATE FUNCTION "app"."assert_actor_can_change_operator_team_roster"(
  p_target_membership_id uuid,
  p_roster_expires_at timestamp with time zone
)
RETURNS integer
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  consequence record;
  checked_count integer := 0;
BEGIN
  FOR consequence IN
    WITH role_paths AS (
      SELECT direct_grant.role_id, direct_grant.expires_at
      FROM public.tenant_membership_role_grants AS direct_grant
      JOIN public.tenant_authorization_sources AS direct_source
        ON direct_source.tenant_id = direct_grant.tenant_id
       AND direct_source.id = direct_grant.source_id
      WHERE direct_grant.tenant_id = context_tenant
        AND direct_grant.membership_id = p_target_membership_id
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
        AND group_member.membership_id = p_target_membership_id
        AND group_member.revoked_at IS NULL
        AND (group_member.expires_at IS NULL
          OR group_member.expires_at > transaction_timestamp())
        AND member_source.retired_at IS NULL
        AND security_group.archived_at IS NULL
        AND group_grant.revoked_at IS NULL
        AND (group_grant.expires_at IS NULL
          OR group_grant.expires_at > transaction_timestamp())
        AND grant_source.retired_at IS NULL
    ), live_target AS (
      SELECT membership.id
      FROM public.tenant_memberships AS membership
      JOIN public.users AS identity ON identity.id = membership.user_id
      JOIN public.tenants AS tenant ON tenant.id = membership.tenant_id
      WHERE membership.tenant_id = context_tenant
        AND membership.id = p_target_membership_id
        AND membership.status = 'active'
        AND identity.active
        AND tenant.status = 'active'
    ), scoped_paths AS (
      SELECT permission.key AS permission_key,
             app.earliest_authorization_expiry(
               role_path.expires_at, p_roster_expires_at
             ) AS effective_expires_at
      FROM role_paths AS role_path
      CROSS JOIN live_target
      JOIN public.tenant_roles AS role
        ON role.tenant_id = context_tenant
       AND role.id = role_path.role_id
      JOIN public.tenant_role_permissions AS policy
        ON policy.tenant_id = role.tenant_id
       AND policy.role_id = role.id
       AND policy.scope = 'operator_team'
      JOIN public.tenant_permissions AS permission
        ON permission.id = policy.permission_id
      WHERE role.archived_at IS NULL
    )
    SELECT scoped_path.permission_key,
           CASE
             WHEN bool_or(scoped_path.effective_expires_at IS NULL) THEN NULL
             ELSE max(scoped_path.effective_expires_at)
           END AS required_expires_at
    FROM scoped_paths AS scoped_path
    GROUP BY scoped_path.permission_key
    ORDER BY scoped_path.permission_key
    LIMIT 501
  LOOP
    checked_count := checked_count + 1;
    IF checked_count > 500 THEN
      RAISE EXCEPTION 'operator-team roster consequence limit exceeded'
        USING ERRCODE = '54000';
    END IF;
    IF NOT app.tenant_user_can_delegate_exact_permission(
      context_tenant,
      app.context_user_id(),
      consequence.permission_key,
      'operator_team',
      consequence.required_expires_at
    ) THEN
      RAISE EXCEPTION 'operator-team roster change exceeds the exact delegation ceiling or lifetime'
        USING ERRCODE = '42501';
    END IF;
  END LOOP;

  RETURN checked_count;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."resolve_current_tenant_operator_teams"(
  p_limit integer
)
RETURNS TABLE (
  operator_team_id uuid,
  assignment_epoch_id uuid
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
    RAISE EXCEPTION 'operator-team relationship limit must be between 1 and 201'
      USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  -- This is a relationship set, not a provenance inventory. Full source and
  -- edge detail remains available through the roster list/get projections.
  SELECT DISTINCT assignment.operator_team_id,
         assignment.id
  FROM public.operator_team_assignment_epochs AS assignment
  JOIN public.operator_teams AS operator_team
    ON operator_team.id = assignment.operator_team_id
  JOIN public.operator_team_roster_entries AS roster
    ON roster.tenant_id = assignment.tenant_id
   AND roster.assignment_epoch_id = assignment.id
  JOIN public.tenant_authorization_sources AS source
    ON source.tenant_id = roster.tenant_id
   AND source.id = roster.source_id
  JOIN public.tenant_memberships AS membership
    ON membership.tenant_id = roster.tenant_id
   AND membership.id = roster.membership_id
  JOIN public.users AS identity ON identity.id = membership.user_id
  JOIN public.tenants AS tenant ON tenant.id = assignment.tenant_id
  JOIN public.tenant_authorization_states AS state
    ON state.tenant_id = assignment.tenant_id
   AND state.initialized_at IS NOT NULL
  WHERE assignment.tenant_id = context_tenant
    AND assignment.ended_at IS NULL
    AND operator_team.archived_at IS NULL
    AND roster.membership_id = context_membership
    AND roster.revoked_at IS NULL
    AND (roster.expires_at IS NULL
      OR roster.expires_at > transaction_timestamp())
    AND source.retired_at IS NULL
    AND membership.status = 'active'
    AND identity.active
    AND tenant.status = 'active'
  ORDER BY assignment.operator_team_id, assignment.id
  LIMIT p_limit;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."list_platform_operator_teams"(
  p_after_id uuid,
  p_include_archived boolean,
  p_limit integer
)
RETURNS TABLE (
  operator_team_id uuid,
  team_key text,
  display_name text,
  description text,
  version integer,
  created_by_user_id uuid,
  archived_at timestamp with time zone,
  archived_by_user_id uuid,
  archive_reason text,
  active_assignment_count bigint,
  created_at timestamp with time zone,
  updated_at timestamp with time zone
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor_id uuid := app.context_user_id();
BEGIN
  IF NOT app.platform_user_has_permission(
    actor_id, 'platform.operator_team.read'
  ) THEN
    RAISE EXCEPTION 'platform.operator_team.read permission is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_include_archived IS NULL THEN
    RAISE EXCEPTION 'include archived must be explicit'
      USING ERRCODE = '22023';
  END IF;
  IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 101 THEN
    RAISE EXCEPTION 'operator-team page limit must be between 1 and 101'
      USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  SELECT operator_team.id,
         operator_team.key,
         operator_team.display_name,
         operator_team.description,
         operator_team.version,
         operator_team.created_by_user_id,
         operator_team.archived_at,
         operator_team.archived_by_user_id,
         operator_team.archive_reason,
         (
           SELECT count(*)
           FROM public.operator_team_assignment_epochs AS assignment
           WHERE assignment.operator_team_id = operator_team.id
             AND assignment.ended_at IS NULL
             AND operator_team.archived_at IS NULL
         ),
         operator_team.created_at,
         operator_team.updated_at
  FROM public.operator_teams AS operator_team
  WHERE (p_include_archived OR operator_team.archived_at IS NULL)
    AND (p_after_id IS NULL OR operator_team.id > p_after_id)
  ORDER BY operator_team.id
  LIMIT p_limit;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."get_platform_operator_team"(
  p_operator_team_id uuid
)
RETURNS TABLE (
  operator_team_id uuid,
  team_key text,
  display_name text,
  description text,
  version integer,
  created_by_user_id uuid,
  archived_at timestamp with time zone,
  archived_by_user_id uuid,
  archive_reason text,
  active_assignment_count bigint,
  created_at timestamp with time zone,
  updated_at timestamp with time zone
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor_id uuid := app.context_user_id();
BEGIN
  IF NOT (
    app.platform_user_has_permission(actor_id, 'platform.operator_team.read')
    OR app.platform_user_has_permission(
      actor_id, 'platform.operator_team.manage'
    )
  ) THEN
    RAISE EXCEPTION 'platform operator-team read or manage permission is required'
      USING ERRCODE = '42501';
  END IF;

  RETURN QUERY
  SELECT operator_team.id,
         operator_team.key,
         operator_team.display_name,
         operator_team.description,
         operator_team.version,
         operator_team.created_by_user_id,
         operator_team.archived_at,
         operator_team.archived_by_user_id,
         operator_team.archive_reason,
         (
           SELECT count(*)
           FROM public.operator_team_assignment_epochs AS assignment
           WHERE assignment.operator_team_id = operator_team.id
             AND assignment.ended_at IS NULL
             AND operator_team.archived_at IS NULL
         ),
         operator_team.created_at,
         operator_team.updated_at
  FROM public.operator_teams AS operator_team
  WHERE operator_team.id = p_operator_team_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'operator team was not found'
      USING ERRCODE = 'P0002';
  END IF;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."create_platform_operator_team"(
  p_operator_team_id uuid,
  p_idempotency_key_digest bytea,
  p_key text,
  p_display_name text,
  p_description text,
  p_platform_audit_event_id uuid,
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
DECLARE
  actor_id uuid := app.context_user_id();
  canonical_request_digest bytea;
  replay record;
BEGIN
  IF NOT app.platform_user_has_permission(
    actor_id, 'platform.operator_team.manage'
  ) THEN
    RAISE EXCEPTION 'platform.operator_team.manage permission is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_authentication_method NOT IN (
    'bootstrap_totp', 'totp', 'recovery_code'
  ) THEN
    RAISE EXCEPTION 'operator-team mutation requires a live authentication method'
      USING ERRCODE = '22023';
  END IF;
  IF p_idempotency_key_digest IS NULL
     OR octet_length(p_idempotency_key_digest) <> 32 THEN
    RAISE EXCEPTION 'idempotency key digest must be SHA-256'
      USING ERRCODE = '22023';
  END IF;
  IF p_key IS NULL OR p_key !~ '^[a-z][a-z0-9_]{2,63}$'
     OR p_display_name IS NULL OR btrim(p_display_name) = ''
     OR char_length(p_display_name) > 120
     OR p_display_name ~ '[[:cntrl:]]'
     OR p_description IS NULL OR char_length(p_description) > 500
     OR p_description ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION 'operator-team attributes violate the canonical contract'
      USING ERRCODE = '22023';
  END IF;

  SELECT sha256(convert_to(jsonb_build_object(
    'key', p_key,
    'display_name', p_display_name,
    'description', p_description
  )::text, 'UTF8')) INTO canonical_request_digest;

  -- Serialize every payload-bound platform command for this actor. Without a
  -- stable existing row lock, concurrent retries can both observe no command
  -- and one returns an unrelated resource/command unique violation.
  PERFORM 1
  FROM public.users AS actor
  WHERE actor.id = actor_id
    AND actor.active
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'active platform actor was not found'
      USING ERRCODE = '42501';
  END IF;

  DELETE FROM public.platform_commands AS command
  WHERE command.actor_user_id = actor_id
    AND command.operation = 'operator_team.create'
    AND command.key_digest = p_idempotency_key_digest
    AND command.expires_at <= transaction_timestamp();

  SELECT command.* INTO replay
  FROM public.platform_commands AS command
  WHERE command.actor_user_id = actor_id
    AND command.operation = 'operator_team.create'
    AND command.key_digest = p_idempotency_key_digest
  FOR UPDATE;

  IF FOUND THEN
    IF replay.request_digest IS DISTINCT FROM canonical_request_digest THEN
      RAISE EXCEPTION 'idempotency key was already used for a different request'
        USING ERRCODE = '23505',
              CONSTRAINT = 'platform_commands_replay_key';
    END IF;
    RETURN QUERY
    SELECT replay.result_resource_id, replay.result_version, true;
    RETURN;
  END IF;

  INSERT INTO public.operator_teams (
    id, key, display_name, description, created_by_user_id
  ) VALUES (
    p_operator_team_id, p_key, p_display_name, p_description, actor_id
  );

  PERFORM app.append_platform_audit_event(
    p_platform_audit_event_id,
    'user',
    actor_id,
    'platform.operator_team.created',
    'operator_team',
    p_operator_team_id,
    p_request_id,
    p_correlation_id,
    p_ip_address,
    p_user_agent,
    p_authentication_method,
    'success',
    NULL,
    jsonb_build_object(
      'key', p_key,
      'display_name', p_display_name,
      'description', p_description,
      'version', 1
    )
  );

  INSERT INTO public.platform_commands (
    actor_user_id, operation, key_digest, request_digest,
    result_resource_id, result_version
  ) VALUES (
    actor_id, 'operator_team.create', p_idempotency_key_digest,
    canonical_request_digest, p_operator_team_id, 1
  );

  RETURN QUERY SELECT p_operator_team_id, 1::integer, false;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."update_platform_operator_team_metadata"(
  p_operator_team_id uuid,
  p_expected_version integer,
  p_display_name text,
  p_description text,
  p_platform_audit_event_id uuid,
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
  actor_id uuid := app.context_user_id();
  target_team record;
  next_version integer;
BEGIN
  IF NOT app.platform_user_has_permission(
    actor_id, 'platform.operator_team.manage'
  ) THEN
    RAISE EXCEPTION 'platform.operator_team.manage permission is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_authentication_method NOT IN (
    'bootstrap_totp', 'totp', 'recovery_code'
  ) THEN
    RAISE EXCEPTION 'operator-team mutation requires a live authentication method'
      USING ERRCODE = '22023';
  END IF;
  IF p_display_name IS NULL AND p_description IS NULL THEN
    RAISE EXCEPTION 'at least one operator-team metadata field is required'
      USING ERRCODE = '22023';
  END IF;
  IF p_display_name IS NOT NULL
     AND (btrim(p_display_name) = ''
       OR char_length(p_display_name) > 120
       OR p_display_name ~ '[[:cntrl:]]') THEN
    RAISE EXCEPTION 'operator-team display name is invalid'
      USING ERRCODE = '22023';
  END IF;
  IF p_description IS NOT NULL
     AND (char_length(p_description) > 500
       OR p_description ~ '[[:cntrl:]]') THEN
    RAISE EXCEPTION 'operator-team description is invalid'
      USING ERRCODE = '22023';
  END IF;

  SELECT operator_team.* INTO target_team
  FROM public.operator_teams AS operator_team
  WHERE operator_team.id = p_operator_team_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'operator team was not found'
      USING ERRCODE = 'P0002';
  END IF;
  IF target_team.version IS DISTINCT FROM p_expected_version THEN
    RAISE EXCEPTION 'operator team version conflict'
      USING ERRCODE = '40001';
  END IF;
  IF target_team.archived_at IS NOT NULL THEN
    RAISE EXCEPTION 'archived operator team cannot be updated'
      USING ERRCODE = '55000';
  END IF;
  IF target_team.version >= 2147483647 THEN
    RAISE EXCEPTION 'operator team version is exhausted'
      USING ERRCODE = '55000';
  END IF;

  next_version := target_team.version + 1;
  UPDATE public.operator_teams AS operator_team
  SET display_name = coalesce(p_display_name, operator_team.display_name),
      description = coalesce(p_description, operator_team.description),
      version = next_version,
      updated_at = transaction_timestamp()
  WHERE operator_team.id = p_operator_team_id;

  PERFORM app.append_platform_audit_event(
    p_platform_audit_event_id,
    'user',
    actor_id,
    'platform.operator_team.metadata_updated',
    'operator_team',
    p_operator_team_id,
    p_request_id,
    p_correlation_id,
    p_ip_address,
    p_user_agent,
    p_authentication_method,
    'success',
    NULL,
    jsonb_build_object(
      'before', jsonb_build_object(
        'display_name', target_team.display_name,
        'description', target_team.description,
        'version', target_team.version
      ),
      'after', jsonb_build_object(
        'display_name', coalesce(p_display_name, target_team.display_name),
        'description', coalesce(p_description, target_team.description),
        'version', next_version
      )
    )
  );

  RETURN next_version;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."archive_platform_operator_team"(
  p_operator_team_id uuid,
  p_expected_version integer,
  p_reason text,
  p_platform_audit_event_id uuid,
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
  actor_id uuid := app.context_user_id();
  target_team record;
  next_version integer;
BEGIN
  IF NOT app.platform_user_has_permission(
    actor_id, 'platform.operator_team.manage'
  ) THEN
    RAISE EXCEPTION 'platform.operator_team.manage permission is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_authentication_method NOT IN (
    'bootstrap_totp', 'totp', 'recovery_code'
  ) THEN
    RAISE EXCEPTION 'operator-team mutation requires a live authentication method'
      USING ERRCODE = '22023';
  END IF;
  IF p_reason IS NULL OR btrim(p_reason) = ''
     OR char_length(p_reason) > 500 OR p_reason ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION 'operator-team archive reason is invalid'
      USING ERRCODE = '22023';
  END IF;

  -- Assignment start takes this same global row lock before checking archive.
  SELECT operator_team.* INTO target_team
  FROM public.operator_teams AS operator_team
  WHERE operator_team.id = p_operator_team_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'operator team was not found'
      USING ERRCODE = 'P0002';
  END IF;
  IF target_team.version IS DISTINCT FROM p_expected_version THEN
    RAISE EXCEPTION 'operator team version conflict'
      USING ERRCODE = '40001';
  END IF;
  IF target_team.archived_at IS NOT NULL THEN
    RAISE EXCEPTION 'operator team is already archived'
      USING ERRCODE = '55000';
  END IF;
  IF target_team.version >= 2147483647 THEN
    RAISE EXCEPTION 'operator team version is exhausted'
      USING ERRCODE = '55000';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM public.operator_team_assignment_epochs AS assignment
    WHERE assignment.operator_team_id = p_operator_team_id
      AND assignment.ended_at IS NULL
  ) THEN
    RAISE EXCEPTION 'operator team has active tenant assignments'
      USING ERRCODE = '23503',
            CONSTRAINT = 'operator_team_assignment_epochs_active_team';
  END IF;

  next_version := target_team.version + 1;
  UPDATE public.operator_teams AS operator_team
  SET archived_at = transaction_timestamp(),
      archived_by_user_id = actor_id,
      archive_reason = p_reason,
      version = next_version,
      updated_at = transaction_timestamp()
  WHERE operator_team.id = p_operator_team_id;

  PERFORM app.append_platform_audit_event(
    p_platform_audit_event_id,
    'user',
    actor_id,
    'platform.operator_team.archived',
    'operator_team',
    p_operator_team_id,
    p_request_id,
    p_correlation_id,
    p_ip_address,
    p_user_agent,
    p_authentication_method,
    'success',
    p_reason,
    jsonb_build_object(
      'prior_version', target_team.version,
      'result_version', next_version,
      'archived_by_user_id', actor_id
    )
  );

  RETURN next_version;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."list_tenant_operator_team_assignment_epochs"(
  p_operator_team_id uuid,
  p_after_epoch_id uuid,
  p_include_ended boolean,
  p_limit integer
)
RETURNS TABLE (
  assignment_epoch_id uuid,
  operator_team_id uuid,
  team_key text,
  team_display_name text,
  team_archived_at timestamp with time zone,
  assigned_by_membership_id uuid,
  assigned_by_user_id uuid,
  assignment_reason text,
  assigned_at timestamp with time zone,
  ended_at timestamp with time zone,
  ended_by_membership_id uuid,
  ended_by_user_id uuid,
  end_reason text,
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
  IF NOT app.current_tenant_has_exact_permission(
    'operator_team.read', 'tenant'
  ) THEN
    RAISE EXCEPTION 'operator_team.read tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_include_ended IS NULL THEN
    RAISE EXCEPTION 'include ended must be explicit'
      USING ERRCODE = '22023';
  END IF;
  IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 101 THEN
    RAISE EXCEPTION 'operator-team assignment page limit must be between 1 and 101'
      USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  SELECT assignment.id,
         assignment.operator_team_id,
         operator_team.key,
         operator_team.display_name,
         operator_team.archived_at,
         assignment.assigned_by_membership_id,
         assigner.user_id,
         assignment.assignment_reason,
         assignment.assigned_at,
         assignment.ended_at,
         assignment.ended_by_membership_id,
         ender.user_id,
         assignment.end_reason,
         assignment.version,
         assignment.updated_at
  FROM public.operator_team_assignment_epochs AS assignment
  JOIN public.operator_teams AS operator_team
    ON operator_team.id = assignment.operator_team_id
  JOIN public.tenant_memberships AS assigner
    ON assigner.tenant_id = assignment.tenant_id
   AND assigner.id = assignment.assigned_by_membership_id
  LEFT JOIN public.tenant_memberships AS ender
    ON ender.tenant_id = assignment.tenant_id
   AND ender.id = assignment.ended_by_membership_id
  WHERE assignment.tenant_id = context_tenant
    AND (p_operator_team_id IS NULL
      OR assignment.operator_team_id = p_operator_team_id)
    AND (p_include_ended OR assignment.ended_at IS NULL)
    AND (p_after_epoch_id IS NULL OR assignment.id > p_after_epoch_id)
  ORDER BY assignment.id
  LIMIT p_limit;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."get_tenant_operator_team_assignment_epoch"(
  p_operator_team_id uuid,
  p_assignment_epoch_id uuid
)
RETURNS TABLE (
  assignment_epoch_id uuid,
  operator_team_id uuid,
  team_key text,
  team_display_name text,
  team_archived_at timestamp with time zone,
  assigned_by_membership_id uuid,
  assigned_by_user_id uuid,
  assignment_reason text,
  assigned_at timestamp with time zone,
  ended_at timestamp with time zone,
  ended_by_membership_id uuid,
  ended_by_user_id uuid,
  end_reason text,
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
    app.current_tenant_can_read_operator_team(
      p_operator_team_id, p_assignment_epoch_id
    )
    OR app.current_tenant_has_exact_permission(
      'operator_team.manage', 'tenant'
    )
    OR app.current_tenant_can_manage_operator_team_roster(
      p_operator_team_id, p_assignment_epoch_id
    )
  ) THEN
    RAISE EXCEPTION 'operator-team assignment read or management authority is required'
      USING ERRCODE = '42501';
  END IF;

  RETURN QUERY
  SELECT assignment.id,
         assignment.operator_team_id,
         operator_team.key,
         operator_team.display_name,
         operator_team.archived_at,
         assignment.assigned_by_membership_id,
         assigner.user_id,
         assignment.assignment_reason,
         assignment.assigned_at,
         assignment.ended_at,
         assignment.ended_by_membership_id,
         ender.user_id,
         assignment.end_reason,
         assignment.version,
         assignment.updated_at
  FROM public.operator_team_assignment_epochs AS assignment
  JOIN public.operator_teams AS operator_team
    ON operator_team.id = assignment.operator_team_id
  JOIN public.tenant_memberships AS assigner
    ON assigner.tenant_id = assignment.tenant_id
   AND assigner.id = assignment.assigned_by_membership_id
  LEFT JOIN public.tenant_memberships AS ender
    ON ender.tenant_id = assignment.tenant_id
   AND ender.id = assignment.ended_by_membership_id
  WHERE assignment.tenant_id = context_tenant
    AND assignment.operator_team_id = p_operator_team_id
    AND assignment.id = p_assignment_epoch_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant operator-team assignment epoch was not found'
      USING ERRCODE = 'P0002';
  END IF;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."start_tenant_operator_team_assignment"(
  p_assignment_epoch_id uuid,
  p_idempotency_key_digest bytea,
  p_operator_team_id uuid,
  p_reason text,
  p_tenant_audit_event_id uuid,
  p_platform_audit_event_id uuid,
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
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid;
  actor_id uuid := app.context_user_id();
  canonical_request_digest bytea;
  replay record;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF NOT app.current_tenant_has_exact_permission(
    'operator_team.manage', 'tenant'
  ) THEN
    RAISE EXCEPTION 'operator_team.manage tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_idempotency_key_digest IS NULL
     OR octet_length(p_idempotency_key_digest) <> 32 THEN
    RAISE EXCEPTION 'idempotency key digest must be SHA-256'
      USING ERRCODE = '22023';
  END IF;
  IF p_reason IS NULL OR btrim(p_reason) = ''
     OR char_length(p_reason) > 500 OR p_reason ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION 'operator-team assignment reason is invalid'
      USING ERRCODE = '22023';
  END IF;

  SELECT sha256(convert_to(jsonb_build_object(
    'operator_team_id', p_operator_team_id,
    'reason', p_reason
  )::text, 'UTF8')) INTO canonical_request_digest;

  DELETE FROM public.tenant_authorization_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.actor_membership_id = actor_membership
    AND command.operation = 'operator_team_assignment.create'
    AND command.key_digest = p_idempotency_key_digest
    AND command.expires_at <= transaction_timestamp();

  SELECT command.* INTO replay
  FROM public.tenant_authorization_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.actor_membership_id = actor_membership
    AND command.operation = 'operator_team_assignment.create'
    AND command.key_digest = p_idempotency_key_digest
  FOR UPDATE;

  IF FOUND THEN
    IF replay.request_digest IS DISTINCT FROM canonical_request_digest THEN
      RAISE EXCEPTION 'idempotency key was already used for a different request'
        USING ERRCODE = '23505',
              CONSTRAINT = 'tenant_authorization_commands_replay_key';
    END IF;
    RETURN QUERY
    SELECT replay.result_resource_id, replay.result_version, true;
    RETURN;
  END IF;

  -- Team archive takes this same row lock before checking active assignments.
  PERFORM 1
  FROM public.operator_teams AS operator_team
  WHERE operator_team.id = p_operator_team_id
    AND operator_team.archived_at IS NULL
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'active operator team was not found'
      USING ERRCODE = 'P0002';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM public.operator_team_assignment_epochs AS assignment
    WHERE assignment.tenant_id = context_tenant
      AND assignment.operator_team_id = p_operator_team_id
      AND assignment.ended_at IS NULL
  ) THEN
    RAISE EXCEPTION 'an active operator-team assignment already exists'
      USING ERRCODE = '23505',
            CONSTRAINT = 'operator_team_assignment_epochs_active_key';
  END IF;

  INSERT INTO public.operator_team_assignment_epochs (
    id, tenant_id, operator_team_id, assigned_by_membership_id,
    assignment_reason
  ) VALUES (
    p_assignment_epoch_id, context_tenant, p_operator_team_id,
    actor_membership, p_reason
  );

  PERFORM app.append_tenant_authorization_audit(
    p_tenant_audit_event_id,
    'tenant.operator_team.assignment_started',
    'operator_team_assignment_epoch',
    p_assignment_epoch_id,
    p_request_id,
    p_correlation_id,
    p_ip_address,
    p_user_agent,
    p_authentication_method,
    NULL,
    jsonb_build_object(
      'operator_team_id', p_operator_team_id,
      'reason', p_reason,
      'version', 1
    ),
    jsonb_build_object(
      'actor_membership_id', actor_membership,
      'platform_audit_event_id', p_platform_audit_event_id
    )
  );

  PERFORM app.append_platform_audit_event(
    p_platform_audit_event_id,
    'user',
    actor_id,
    'platform.operator_team.assignment_started',
    'operator_team_assignment_epoch',
    p_assignment_epoch_id,
    p_request_id,
    p_correlation_id,
    p_ip_address,
    p_user_agent,
    p_authentication_method,
    'success',
    NULL,
    jsonb_build_object(
      'tenant_id', context_tenant,
      'operator_team_id', p_operator_team_id,
      'reason', p_reason,
      'tenant_audit_event_id', p_tenant_audit_event_id,
      'actor_membership_id', actor_membership
    )
  );

  INSERT INTO public.tenant_authorization_commands (
    tenant_id, actor_membership_id, operation, key_digest, request_digest,
    result_resource_id, result_version
  ) VALUES (
    context_tenant, actor_membership, 'operator_team_assignment.create',
    p_idempotency_key_digest, canonical_request_digest,
    p_assignment_epoch_id, 1
  );

  RETURN QUERY SELECT p_assignment_epoch_id, 1::integer, false;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."end_tenant_operator_team_assignment"(
  p_operator_team_id uuid,
  p_assignment_epoch_id uuid,
  p_expected_version integer,
  p_reason text,
  p_tenant_audit_event_id uuid,
  p_platform_audit_event_id uuid,
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
  actor_id uuid := app.context_user_id();
  target_assignment record;
  live_roster record;
  roster_entries_checked integer := 0;
  consequences_checked integer := 0;
  next_version integer;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF NOT app.current_tenant_has_exact_permission(
    'operator_team.manage', 'tenant'
  ) THEN
    RAISE EXCEPTION 'operator_team.manage tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  IF NOT app.current_tenant_has_exact_permission('role.grant', 'tenant') THEN
    RAISE EXCEPTION 'role.grant tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_reason IS NULL OR btrim(p_reason) = ''
     OR char_length(p_reason) > 500 OR p_reason ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION 'operator-team assignment end reason is invalid'
      USING ERRCODE = '22023';
  END IF;

  SELECT assignment.* INTO target_assignment
  FROM public.operator_team_assignment_epochs AS assignment
  WHERE assignment.tenant_id = context_tenant
    AND assignment.operator_team_id = p_operator_team_id
    AND assignment.id = p_assignment_epoch_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant operator-team assignment epoch was not found'
      USING ERRCODE = 'P0002';
  END IF;
  IF target_assignment.version IS DISTINCT FROM p_expected_version THEN
    RAISE EXCEPTION 'operator-team assignment version conflict'
      USING ERRCODE = '40001';
  END IF;
  IF target_assignment.ended_at IS NOT NULL THEN
    RAISE EXCEPTION 'operator-team assignment is already ended'
      USING ERRCODE = '55000';
  END IF;
  IF target_assignment.version >= 2147483647 THEN
    RAISE EXCEPTION 'operator-team assignment version is exhausted'
      USING ERRCODE = '55000';
  END IF;

  FOR live_roster IN
    SELECT roster.id, roster.membership_id, roster.expires_at
    FROM public.operator_team_roster_entries AS roster
    JOIN public.tenant_authorization_sources AS source
      ON source.tenant_id = roster.tenant_id
     AND source.id = roster.source_id
    JOIN public.tenant_memberships AS membership
      ON membership.tenant_id = roster.tenant_id
     AND membership.id = roster.membership_id
    JOIN public.users AS identity ON identity.id = membership.user_id
    WHERE roster.tenant_id = context_tenant
      AND roster.assignment_epoch_id = p_assignment_epoch_id
      AND roster.revoked_at IS NULL
      AND (roster.expires_at IS NULL
        OR roster.expires_at > transaction_timestamp())
      AND source.retired_at IS NULL
      AND membership.status = 'active'
      AND identity.active
    ORDER BY roster.id
    LIMIT 501
  LOOP
    roster_entries_checked := roster_entries_checked + 1;
    IF roster_entries_checked > 500 THEN
      RAISE EXCEPTION 'operator-team assignment consequence limit exceeded'
        USING ERRCODE = '54000';
    END IF;
    consequences_checked := consequences_checked
      + app.assert_actor_can_change_operator_team_roster(
          live_roster.membership_id, live_roster.expires_at
        );
  END LOOP;

  next_version := target_assignment.version + 1;
  UPDATE public.operator_team_assignment_epochs AS assignment
  SET ended_at = transaction_timestamp(),
      ended_by_membership_id = actor_membership,
      end_reason = p_reason,
      version = next_version,
      updated_at = transaction_timestamp()
  WHERE assignment.tenant_id = context_tenant
    AND assignment.operator_team_id = p_operator_team_id
    AND assignment.id = p_assignment_epoch_id;

  PERFORM app.append_tenant_authorization_audit(
    p_tenant_audit_event_id,
    'tenant.operator_team.assignment_ended',
    'operator_team_assignment_epoch',
    p_assignment_epoch_id,
    p_request_id,
    p_correlation_id,
    p_ip_address,
    p_user_agent,
    p_authentication_method,
    jsonb_build_object(
      'ended_at', NULL,
      'version', target_assignment.version
    ),
    jsonb_build_object(
      'ended_at', transaction_timestamp(),
      'reason', p_reason,
      'version', next_version
    ),
    jsonb_build_object(
      'operator_team_id', p_operator_team_id,
      'actor_membership_id', actor_membership,
      'roster_entries_checked', roster_entries_checked,
      'operator_team_consequences_checked', consequences_checked,
      'platform_audit_event_id', p_platform_audit_event_id
    )
  );

  PERFORM app.append_platform_audit_event(
    p_platform_audit_event_id,
    'user',
    actor_id,
    'platform.operator_team.assignment_ended',
    'operator_team_assignment_epoch',
    p_assignment_epoch_id,
    p_request_id,
    p_correlation_id,
    p_ip_address,
    p_user_agent,
    p_authentication_method,
    'success',
    p_reason,
    jsonb_build_object(
      'tenant_id', context_tenant,
      'operator_team_id', p_operator_team_id,
      'prior_version', target_assignment.version,
      'result_version', next_version,
      'tenant_audit_event_id', p_tenant_audit_event_id,
      'actor_membership_id', actor_membership
    )
  );

  RETURN next_version;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."list_tenant_operator_team_roster_entries"(
  p_operator_team_id uuid,
  p_assignment_epoch_id uuid,
  p_after_entry_id uuid,
  p_include_revoked boolean,
  p_limit integer
)
RETURNS TABLE (
  roster_entry_id uuid,
  operator_team_id uuid,
  team_key text,
  team_display_name text,
  team_archived_at timestamp with time zone,
  assignment_epoch_id uuid,
  assignment_ended_at timestamp with time zone,
  membership_id uuid,
  target_user_id uuid,
  email text,
  display_name text,
  membership_status "public"."membership_status",
  compatibility_role "public"."membership_role",
  user_active boolean,
  source_id uuid,
  source_kind "public"."authorization_source_kind",
  source_key text,
  source_authoritative boolean,
  source_retired_at timestamp with time zone,
  granted_by_membership_id uuid,
  granted_by_user_id uuid,
  grant_reason text,
  granted_at timestamp with time zone,
  expires_at timestamp with time zone,
  revoked_at timestamp with time zone,
  revoked_by_membership_id uuid,
  revoked_by_user_id uuid,
  revoke_reason text,
  roster_state text,
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
    app.current_tenant_can_read_operator_team(
      p_operator_team_id, p_assignment_epoch_id
    )
    AND app.current_tenant_has_exact_permission('user.read', 'tenant')
  ) THEN
    RAISE EXCEPTION 'operator-team read authority and user.read tenant scope are required'
      USING ERRCODE = '42501';
  END IF;
  IF p_include_revoked IS NULL THEN
    RAISE EXCEPTION 'include revoked must be explicit'
      USING ERRCODE = '22023';
  END IF;
  IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 101 THEN
    RAISE EXCEPTION 'operator-team roster page limit must be between 1 and 101'
      USING ERRCODE = '22023';
  END IF;
  IF NOT EXISTS (
    SELECT 1
    FROM public.operator_team_assignment_epochs AS assignment
    WHERE assignment.tenant_id = context_tenant
      AND assignment.operator_team_id = p_operator_team_id
      AND assignment.id = p_assignment_epoch_id
  ) THEN
    RAISE EXCEPTION 'tenant operator-team assignment epoch was not found'
      USING ERRCODE = 'P0002';
  END IF;

  RETURN QUERY
  SELECT roster.id,
         assignment.operator_team_id,
         operator_team.key,
         operator_team.display_name,
         operator_team.archived_at,
         assignment.id,
         assignment.ended_at,
         membership.id,
         identity.id,
         identity.email,
         identity.display_name,
         membership.status,
         membership.role,
         identity.active,
         source.id,
         source.kind,
         source.key,
         source.authoritative,
         source.retired_at,
         roster.granted_by_membership_id,
         grantor.user_id,
         roster.grant_reason,
         roster.granted_at,
         roster.expires_at,
         roster.revoked_at,
         roster.revoked_by_membership_id,
         revoker.user_id,
         roster.revoke_reason,
         CASE
           WHEN roster.revoked_at IS NOT NULL THEN 'revoked'
           WHEN (roster.expires_at IS NOT NULL
             AND roster.expires_at <= transaction_timestamp())
             OR source.retired_at IS NOT NULL
             OR assignment.ended_at IS NOT NULL
             OR operator_team.archived_at IS NOT NULL
             OR membership.status <> 'active'
             OR NOT identity.active
             OR tenant.status <> 'active' THEN 'expired'
           ELSE 'active'
         END,
         roster.version,
         roster.updated_at
  FROM public.operator_team_assignment_epochs AS assignment
  JOIN public.operator_teams AS operator_team
    ON operator_team.id = assignment.operator_team_id
  JOIN public.operator_team_roster_entries AS roster
    ON roster.tenant_id = assignment.tenant_id
   AND roster.assignment_epoch_id = assignment.id
  JOIN public.tenant_memberships AS membership
    ON membership.tenant_id = roster.tenant_id
   AND membership.id = roster.membership_id
  JOIN public.users AS identity ON identity.id = membership.user_id
  JOIN public.tenants AS tenant ON tenant.id = assignment.tenant_id
  JOIN public.tenant_authorization_sources AS source
    ON source.tenant_id = roster.tenant_id
   AND source.id = roster.source_id
  LEFT JOIN public.tenant_memberships AS grantor
    ON grantor.tenant_id = roster.tenant_id
   AND grantor.id = roster.granted_by_membership_id
  LEFT JOIN public.tenant_memberships AS revoker
    ON revoker.tenant_id = roster.tenant_id
   AND revoker.id = roster.revoked_by_membership_id
  WHERE assignment.tenant_id = context_tenant
    AND assignment.operator_team_id = p_operator_team_id
    AND assignment.id = p_assignment_epoch_id
    AND (p_include_revoked OR roster.revoked_at IS NULL)
    AND (p_after_entry_id IS NULL OR roster.id > p_after_entry_id)
  ORDER BY roster.id
  LIMIT p_limit;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."get_tenant_operator_team_roster_entry"(
  p_operator_team_id uuid,
  p_assignment_epoch_id uuid,
  p_roster_entry_id uuid
)
RETURNS TABLE (
  roster_entry_id uuid,
  operator_team_id uuid,
  team_key text,
  team_display_name text,
  team_archived_at timestamp with time zone,
  assignment_epoch_id uuid,
  assignment_ended_at timestamp with time zone,
  membership_id uuid,
  target_user_id uuid,
  email text,
  display_name text,
  membership_status "public"."membership_status",
  compatibility_role "public"."membership_role",
  user_active boolean,
  source_id uuid,
  source_kind "public"."authorization_source_kind",
  source_key text,
  source_authoritative boolean,
  source_retired_at timestamp with time zone,
  granted_by_membership_id uuid,
  granted_by_user_id uuid,
  grant_reason text,
  granted_at timestamp with time zone,
  expires_at timestamp with time zone,
  revoked_at timestamp with time zone,
  revoked_by_membership_id uuid,
  revoked_by_user_id uuid,
  revoke_reason text,
  roster_state text,
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
    (
      app.current_tenant_can_read_operator_team(
        p_operator_team_id, p_assignment_epoch_id
      )
      AND app.current_tenant_has_exact_permission('user.read', 'tenant')
    )
    OR (
      app.current_tenant_can_manage_operator_team_roster(
        p_operator_team_id, p_assignment_epoch_id
      )
      AND app.current_tenant_has_exact_permission('role.grant', 'tenant')
    )
    OR (
      app.current_tenant_has_exact_permission(
        'operator_team.manage', 'tenant'
      )
      AND app.current_tenant_has_exact_permission('role.grant', 'tenant')
    )
  ) THEN
    RAISE EXCEPTION 'operator-team roster read or management authority is required'
      USING ERRCODE = '42501';
  END IF;

  RETURN QUERY
  SELECT roster.id,
         assignment.operator_team_id,
         operator_team.key,
         operator_team.display_name,
         operator_team.archived_at,
         assignment.id,
         assignment.ended_at,
         membership.id,
         identity.id,
         identity.email,
         identity.display_name,
         membership.status,
         membership.role,
         identity.active,
         source.id,
         source.kind,
         source.key,
         source.authoritative,
         source.retired_at,
         roster.granted_by_membership_id,
         grantor.user_id,
         roster.grant_reason,
         roster.granted_at,
         roster.expires_at,
         roster.revoked_at,
         roster.revoked_by_membership_id,
         revoker.user_id,
         roster.revoke_reason,
         CASE
           WHEN roster.revoked_at IS NOT NULL THEN 'revoked'
           WHEN (roster.expires_at IS NOT NULL
             AND roster.expires_at <= transaction_timestamp())
             OR source.retired_at IS NOT NULL
             OR assignment.ended_at IS NOT NULL
             OR operator_team.archived_at IS NOT NULL
             OR membership.status <> 'active'
             OR NOT identity.active
             OR tenant.status <> 'active' THEN 'expired'
           ELSE 'active'
         END,
         roster.version,
         roster.updated_at
  FROM public.operator_team_assignment_epochs AS assignment
  JOIN public.operator_teams AS operator_team
    ON operator_team.id = assignment.operator_team_id
  JOIN public.operator_team_roster_entries AS roster
    ON roster.tenant_id = assignment.tenant_id
   AND roster.assignment_epoch_id = assignment.id
  JOIN public.tenant_memberships AS membership
    ON membership.tenant_id = roster.tenant_id
   AND membership.id = roster.membership_id
  JOIN public.users AS identity ON identity.id = membership.user_id
  JOIN public.tenants AS tenant ON tenant.id = assignment.tenant_id
  JOIN public.tenant_authorization_sources AS source
    ON source.tenant_id = roster.tenant_id
   AND source.id = roster.source_id
  LEFT JOIN public.tenant_memberships AS grantor
    ON grantor.tenant_id = roster.tenant_id
   AND grantor.id = roster.granted_by_membership_id
  LEFT JOIN public.tenant_memberships AS revoker
    ON revoker.tenant_id = roster.tenant_id
   AND revoker.id = roster.revoked_by_membership_id
  WHERE assignment.tenant_id = context_tenant
    AND assignment.operator_team_id = p_operator_team_id
    AND assignment.id = p_assignment_epoch_id
    AND roster.tenant_id = context_tenant
    AND roster.assignment_epoch_id = p_assignment_epoch_id
    AND roster.id = p_roster_entry_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant operator-team roster entry was not found'
      USING ERRCODE = 'P0002';
  END IF;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."add_tenant_operator_team_roster_entry"(
  p_roster_entry_id uuid,
  p_idempotency_key_digest bytea,
  p_operator_team_id uuid,
  p_assignment_epoch_id uuid,
  p_membership_id uuid,
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
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid;
  manual_source uuid;
  canonical_request_digest bytea;
  replay record;
  consequences_checked integer;
  superseded_entries jsonb := '[]'::jsonb;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF NOT app.current_tenant_can_manage_operator_team_roster(
    p_operator_team_id, p_assignment_epoch_id
  ) THEN
    RAISE EXCEPTION 'operator_team.roster.manage authority is required for the exact team epoch'
      USING ERRCODE = '42501';
  END IF;
  IF NOT app.current_tenant_has_exact_permission('role.grant', 'tenant') THEN
    RAISE EXCEPTION 'role.grant tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_idempotency_key_digest IS NULL
     OR octet_length(p_idempotency_key_digest) <> 32 THEN
    RAISE EXCEPTION 'idempotency key digest must be SHA-256'
      USING ERRCODE = '22023';
  END IF;
  IF p_reason IS NULL OR btrim(p_reason) = ''
     OR char_length(p_reason) > 500 OR p_reason ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION 'operator-team roster grant reason is invalid'
      USING ERRCODE = '22023';
  END IF;

  SELECT sha256(convert_to(jsonb_build_object(
    'operator_team_id', p_operator_team_id,
    'assignment_epoch_id', p_assignment_epoch_id,
    'membership_id', p_membership_id,
    'reason', p_reason,
    'expires_at', p_expires_at
  )::text, 'UTF8')) INTO canonical_request_digest;

  DELETE FROM public.tenant_authorization_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.actor_membership_id = actor_membership
    AND command.operation = 'operator_team_roster_entry.create'
    AND command.key_digest = p_idempotency_key_digest
    AND command.expires_at <= transaction_timestamp();

  SELECT command.* INTO replay
  FROM public.tenant_authorization_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.actor_membership_id = actor_membership
    AND command.operation = 'operator_team_roster_entry.create'
    AND command.key_digest = p_idempotency_key_digest
  FOR UPDATE;

  IF FOUND THEN
    IF replay.request_digest IS DISTINCT FROM canonical_request_digest THEN
      RAISE EXCEPTION 'idempotency key was already used for a different request'
        USING ERRCODE = '23505',
              CONSTRAINT = 'tenant_authorization_commands_replay_key';
    END IF;
    RETURN QUERY
    SELECT replay.result_resource_id, replay.result_version, true;
    RETURN;
  END IF;

  IF p_expires_at IS NOT NULL
     AND p_expires_at <= transaction_timestamp() THEN
    RAISE EXCEPTION 'operator-team roster expiry must be in the future'
      USING ERRCODE = '22023';
  END IF;

  PERFORM 1
  FROM public.operator_team_assignment_epochs AS assignment
  JOIN public.operator_teams AS operator_team
    ON operator_team.id = assignment.operator_team_id
  WHERE assignment.tenant_id = context_tenant
    AND assignment.operator_team_id = p_operator_team_id
    AND assignment.id = p_assignment_epoch_id
    AND assignment.ended_at IS NULL
    AND operator_team.archived_at IS NULL
  FOR UPDATE OF assignment;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'active exact operator-team assignment epoch was not found'
      USING ERRCODE = 'P0002';
  END IF;

  PERFORM 1
  FROM public.tenant_memberships AS membership
  JOIN public.users AS identity ON identity.id = membership.user_id
  WHERE membership.tenant_id = context_tenant
    AND membership.id = p_membership_id
    AND membership.status = 'active'
    AND identity.active
  FOR UPDATE OF membership;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'active target tenant membership was not found'
      USING ERRCODE = 'P0002';
  END IF;

  SELECT source.id INTO STRICT manual_source
  FROM public.tenant_authorization_sources AS source
  WHERE source.tenant_id = context_tenant
    AND source.key = 'manual'
    AND source.kind = 'manual'
    AND source.protected
    AND source.retired_at IS NULL;

  IF EXISTS (
    SELECT 1
    FROM public.operator_team_roster_entries AS expired_entry
    WHERE expired_entry.tenant_id = context_tenant
      AND expired_entry.assignment_epoch_id = p_assignment_epoch_id
      AND expired_entry.membership_id = p_membership_id
      AND expired_entry.source_id = manual_source
      AND expired_entry.revoked_at IS NULL
      AND expired_entry.expires_at <= transaction_timestamp()
      AND expired_entry.version >= 2147483647
  ) THEN
    RAISE EXCEPTION 'expired operator-team roster entry version is exhausted'
      USING ERRCODE = '55000';
  END IF;

  SELECT coalesce(jsonb_agg(jsonb_build_object(
           'roster_entry_id', expired_entry.id,
           'prior_version', expired_entry.version,
           'result_version', expired_entry.version + 1
         ) ORDER BY expired_entry.id), '[]'::jsonb)
    INTO superseded_entries
  FROM public.operator_team_roster_entries AS expired_entry
  WHERE expired_entry.tenant_id = context_tenant
    AND expired_entry.assignment_epoch_id = p_assignment_epoch_id
    AND expired_entry.membership_id = p_membership_id
    AND expired_entry.source_id = manual_source
    AND expired_entry.revoked_at IS NULL
    AND expired_entry.expires_at <= transaction_timestamp();

  UPDATE public.operator_team_roster_entries AS expired_entry
  SET revoked_at = transaction_timestamp(),
      revoked_by_membership_id = actor_membership,
      revoke_reason = 'Superseded after the prior manual roster entry expired.',
      version = expired_entry.version + 1,
      updated_at = transaction_timestamp()
  WHERE expired_entry.tenant_id = context_tenant
    AND expired_entry.assignment_epoch_id = p_assignment_epoch_id
    AND expired_entry.membership_id = p_membership_id
    AND expired_entry.source_id = manual_source
    AND expired_entry.revoked_at IS NULL
    AND expired_entry.expires_at <= transaction_timestamp();

  IF EXISTS (
    SELECT 1
    FROM public.operator_team_roster_entries AS existing
    WHERE existing.tenant_id = context_tenant
      AND existing.assignment_epoch_id = p_assignment_epoch_id
      AND existing.membership_id = p_membership_id
      AND existing.source_id = manual_source
      AND existing.revoked_at IS NULL
  ) THEN
    RAISE EXCEPTION 'an active manual operator-team roster entry already exists'
      USING ERRCODE = '23505',
            CONSTRAINT = 'operator_team_roster_entries_active_key';
  END IF;

  consequences_checked := app.assert_actor_can_change_operator_team_roster(
    p_membership_id, p_expires_at
  );

  INSERT INTO public.operator_team_roster_entries (
    id, tenant_id, assignment_epoch_id, membership_id, source_id,
    granted_by_membership_id, grant_reason, expires_at
  ) VALUES (
    p_roster_entry_id, context_tenant, p_assignment_epoch_id,
    p_membership_id, manual_source, actor_membership, p_reason, p_expires_at
  );

  PERFORM app.append_tenant_authorization_audit(
    p_audit_event_id,
    'tenant.operator_team.roster_entry_added',
    'operator_team_roster_entry',
    p_roster_entry_id,
    p_request_id,
    p_correlation_id,
    p_ip_address,
    p_user_agent,
    p_authentication_method,
    NULL,
    jsonb_build_object(
      'operator_team_id', p_operator_team_id,
      'assignment_epoch_id', p_assignment_epoch_id,
      'membership_id', p_membership_id,
      'source_id', manual_source,
      'source_kind', 'manual',
      'reason', p_reason,
      'expires_at', p_expires_at,
      'version', 1
    ),
    jsonb_build_object(
      'actor_membership_id', actor_membership,
      'operator_team_consequences_checked', consequences_checked,
      'superseded_entries', superseded_entries
    )
  );

  INSERT INTO public.tenant_authorization_commands (
    tenant_id, actor_membership_id, operation, key_digest, request_digest,
    result_resource_id, result_version
  ) VALUES (
    context_tenant, actor_membership, 'operator_team_roster_entry.create',
    p_idempotency_key_digest, canonical_request_digest, p_roster_entry_id, 1
  );

  RETURN QUERY SELECT p_roster_entry_id, 1::integer, false;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."revoke_tenant_operator_team_roster_entry"(
  p_operator_team_id uuid,
  p_assignment_epoch_id uuid,
  p_roster_entry_id uuid,
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
  target_entry record;
  consequences_checked integer;
  next_version integer;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF NOT app.current_tenant_can_manage_operator_team_roster(
    p_operator_team_id, p_assignment_epoch_id
  ) THEN
    RAISE EXCEPTION 'operator_team.roster.manage authority is required for the exact team epoch'
      USING ERRCODE = '42501';
  END IF;
  IF NOT app.current_tenant_has_exact_permission('role.grant', 'tenant') THEN
    RAISE EXCEPTION 'role.grant tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_reason IS NULL OR btrim(p_reason) = ''
     OR char_length(p_reason) > 500 OR p_reason ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION 'operator-team roster revoke reason is invalid'
      USING ERRCODE = '22023';
  END IF;

  SELECT roster.*,
         assignment.ended_at AS assignment_ended_at,
         operator_team.archived_at AS team_archived_at
    INTO target_entry
  FROM public.operator_team_assignment_epochs AS assignment
  JOIN public.operator_teams AS operator_team
    ON operator_team.id = assignment.operator_team_id
  JOIN public.operator_team_roster_entries AS roster
    ON roster.tenant_id = assignment.tenant_id
   AND roster.assignment_epoch_id = assignment.id
  JOIN public.tenant_authorization_sources AS source
    ON source.tenant_id = roster.tenant_id
   AND source.id = roster.source_id
  WHERE assignment.tenant_id = context_tenant
    AND assignment.operator_team_id = p_operator_team_id
    AND assignment.id = p_assignment_epoch_id
    AND roster.tenant_id = context_tenant
    AND roster.assignment_epoch_id = p_assignment_epoch_id
    AND roster.id = p_roster_entry_id
    AND source.kind = 'manual'
    AND source.key = 'manual'
    AND source.protected
    AND source.retired_at IS NULL
  FOR UPDATE OF roster;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'live manual operator-team roster entry was not found'
      USING ERRCODE = 'P0002';
  END IF;
  IF target_entry.version IS DISTINCT FROM p_expected_version THEN
    RAISE EXCEPTION 'operator-team roster entry version conflict'
      USING ERRCODE = '40001';
  END IF;
  IF target_entry.revoked_at IS NOT NULL
     OR (target_entry.expires_at IS NOT NULL
       AND target_entry.expires_at <= transaction_timestamp())
     OR target_entry.assignment_ended_at IS NOT NULL
     OR target_entry.team_archived_at IS NOT NULL THEN
    RAISE EXCEPTION 'operator-team roster entry is not live'
      USING ERRCODE = '55000';
  END IF;
  IF target_entry.version >= 2147483647 THEN
    RAISE EXCEPTION 'operator-team roster entry version is exhausted'
      USING ERRCODE = '55000';
  END IF;

  consequences_checked := app.assert_actor_can_change_operator_team_roster(
    target_entry.membership_id, target_entry.expires_at
  );

  next_version := target_entry.version + 1;
  UPDATE public.operator_team_roster_entries AS roster
  SET revoked_at = transaction_timestamp(),
      revoked_by_membership_id = actor_membership,
      revoke_reason = p_reason,
      version = next_version,
      updated_at = transaction_timestamp()
  WHERE roster.tenant_id = context_tenant
    AND roster.assignment_epoch_id = p_assignment_epoch_id
    AND roster.id = p_roster_entry_id;

  PERFORM app.append_tenant_authorization_audit(
    p_audit_event_id,
    'tenant.operator_team.roster_entry_revoked',
    'operator_team_roster_entry',
    p_roster_entry_id,
    p_request_id,
    p_correlation_id,
    p_ip_address,
    p_user_agent,
    p_authentication_method,
    jsonb_build_object(
      'revoked_at', NULL,
      'version', target_entry.version
    ),
    jsonb_build_object(
      'revoked_at', transaction_timestamp(),
      'reason', p_reason,
      'version', next_version
    ),
    jsonb_build_object(
      'operator_team_id', p_operator_team_id,
      'assignment_epoch_id', p_assignment_epoch_id,
      'membership_id', target_entry.membership_id,
      'actor_membership_id', actor_membership,
      'operator_team_consequences_checked', consequences_checked
    )
  );

  RETURN next_version;
END;
$function$;--> statement-breakpoint

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
  IF target_role.version IS DISTINCT FROM p_expected_version THEN
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
    IF requested.scope = 'operator_team' THEN
      WITH role_paths AS (
        SELECT direct_grant.membership_id, direct_grant.expires_at
        FROM public.tenant_membership_role_grants AS direct_grant
        JOIN public.tenant_authorization_sources AS direct_source
          ON direct_source.tenant_id = direct_grant.tenant_id
         AND direct_source.id = direct_grant.source_id
        WHERE direct_grant.tenant_id = context_tenant
          AND direct_grant.role_id = p_role_id
          AND direct_grant.revoked_at IS NULL
          AND (direct_grant.expires_at IS NULL
            OR direct_grant.expires_at > transaction_timestamp())
          AND direct_source.retired_at IS NULL

        UNION ALL

        SELECT group_member.membership_id,
               app.earliest_authorization_expiry(
                 group_member.expires_at, group_grant.expires_at
               )
        FROM public.tenant_security_group_role_grants AS group_grant
        JOIN public.tenant_authorization_sources AS grant_source
          ON grant_source.tenant_id = group_grant.tenant_id
         AND grant_source.id = group_grant.source_id
        JOIN public.tenant_security_groups AS security_group
          ON security_group.tenant_id = group_grant.tenant_id
         AND security_group.id = group_grant.group_id
        JOIN public.tenant_security_group_memberships AS group_member
          ON group_member.tenant_id = group_grant.tenant_id
         AND group_member.group_id = group_grant.group_id
        JOIN public.tenant_authorization_sources AS member_source
          ON member_source.tenant_id = group_member.tenant_id
         AND member_source.id = group_member.source_id
        WHERE group_grant.tenant_id = context_tenant
          AND group_grant.role_id = p_role_id
          AND group_grant.revoked_at IS NULL
          AND (group_grant.expires_at IS NULL
            OR group_grant.expires_at > transaction_timestamp())
          AND grant_source.retired_at IS NULL
          AND security_group.archived_at IS NULL
          AND group_member.revoked_at IS NULL
          AND (group_member.expires_at IS NULL
            OR group_member.expires_at > transaction_timestamp())
          AND member_source.retired_at IS NULL
      ), effective_paths AS (
        SELECT app.earliest_authorization_expiry(
                 role_path.expires_at, roster.expires_at
               ) AS expires_at
        FROM role_paths AS role_path
        JOIN public.tenant_memberships AS membership
          ON membership.tenant_id = context_tenant
         AND membership.id = role_path.membership_id
        JOIN public.users AS identity ON identity.id = membership.user_id
        JOIN public.operator_team_roster_entries AS roster
          ON roster.tenant_id = membership.tenant_id
         AND roster.membership_id = membership.id
        JOIN public.tenant_authorization_sources AS roster_source
          ON roster_source.tenant_id = roster.tenant_id
         AND roster_source.id = roster.source_id
        JOIN public.operator_team_assignment_epochs AS assignment
          ON assignment.tenant_id = roster.tenant_id
         AND assignment.id = roster.assignment_epoch_id
        JOIN public.operator_teams AS operator_team
          ON operator_team.id = assignment.operator_team_id
        WHERE membership.status = 'active'
          AND identity.active
          AND roster.revoked_at IS NULL
          AND (roster.expires_at IS NULL
            OR roster.expires_at > transaction_timestamp())
          AND roster_source.retired_at IS NULL
          AND assignment.ended_at IS NULL
          AND operator_team.archived_at IS NULL
      )
      SELECT count(*) > 0,
             coalesce(bool_or(effective_paths.expires_at IS NULL), false),
             max(effective_paths.expires_at)
        INTO has_live_grants, has_unbounded_grants, maximum_grant_expiry
      FROM effective_paths;
    ELSE
      WITH live_grants AS (
        SELECT direct_grant.expires_at
        FROM public.tenant_membership_role_grants AS direct_grant
        JOIN public.tenant_authorization_sources AS source
          ON source.tenant_id = direct_grant.tenant_id
         AND source.id = direct_grant.source_id
        WHERE direct_grant.tenant_id = context_tenant
          AND direct_grant.role_id = p_role_id
          AND direct_grant.revoked_at IS NULL
          AND (direct_grant.expires_at IS NULL
            OR direct_grant.expires_at > transaction_timestamp())
          AND source.retired_at IS NULL

        UNION ALL

        SELECT app.earliest_authorization_expiry(
                 group_member.expires_at, group_grant.expires_at
               )
        FROM public.tenant_security_group_role_grants AS group_grant
        JOIN public.tenant_authorization_sources AS source
          ON source.tenant_id = group_grant.tenant_id
         AND source.id = group_grant.source_id
        JOIN public.tenant_security_groups AS security_group
          ON security_group.tenant_id = group_grant.tenant_id
         AND security_group.id = group_grant.group_id
        JOIN public.tenant_security_group_memberships AS group_member
          ON group_member.tenant_id = group_grant.tenant_id
         AND group_member.group_id = group_grant.group_id
        JOIN public.tenant_authorization_sources AS member_source
          ON member_source.tenant_id = group_member.tenant_id
         AND member_source.id = group_member.source_id
        WHERE group_grant.tenant_id = context_tenant
          AND group_grant.role_id = p_role_id
          AND group_grant.revoked_at IS NULL
          AND (group_grant.expires_at IS NULL
            OR group_grant.expires_at > transaction_timestamp())
          AND source.retired_at IS NULL
          AND security_group.archived_at IS NULL
          AND group_member.revoked_at IS NULL
          AND (group_member.expires_at IS NULL
            OR group_member.expires_at > transaction_timestamp())
          AND member_source.retired_at IS NULL
      )
      SELECT count(*) > 0,
             coalesce(bool_or(live_grants.expires_at IS NULL), false),
             max(live_grants.expires_at)
        INTO has_live_grants, has_unbounded_grants, maximum_grant_expiry
      FROM live_grants;
    END IF;

    required_expiry := CASE
      WHEN has_live_grants AND has_unbounded_grants THEN NULL
      WHEN has_live_grants THEN maximum_grant_expiry
      ELSE transaction_timestamp()
    END;

    IF NOT app.tenant_user_can_delegate_exact_permission(
      context_tenant,
      app.context_user_id(),
      requested.permission_key,
      requested.scope,
      required_expiry
    ) THEN
      RAISE EXCEPTION 'role policy change exceeds the exact delegation ceiling or active consequence lifetime'
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
    p_audit_event_id,
    'tenant.role.policy_replaced',
    'tenant_role',
    p_role_id,
    p_request_id,
    p_correlation_id,
    p_ip_address,
    p_user_agent,
    p_authentication_method,
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
$function$;--> statement-breakpoint

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
BEGIN
  -- Hold the same serialization row as v2 before checking for an unrepresentable
  -- current policy, so a concurrent v2 replacement cannot race this guard.
  PERFORM app.lock_current_tenant_authorization_state();
  IF EXISTS (
    SELECT 1
    FROM unnest(
      coalesce(p_permission_keys, ARRAY[]::text[])
      || coalesce(p_delegation_permission_keys, ARRAY[]::text[])
    ) AS requested(permission_key)
    WHERE requested.permission_key IN (
      'operator_team.read',
      'operator_team.manage',
      'operator_team.roster.manage'
    )
  ) OR EXISTS (
    SELECT 1
    FROM (
      SELECT policy.permission_id
      FROM public.tenant_role_permissions AS policy
      WHERE policy.tenant_id = app.context_tenant_id()
        AND policy.role_id = p_role_id
      UNION
      SELECT ceiling.permission_id
      FROM public.tenant_role_delegation_ceilings AS ceiling
      WHERE ceiling.tenant_id = app.context_tenant_id()
        AND ceiling.role_id = p_role_id
    ) AS current_tuple
    JOIN public.tenant_permissions AS permission
      ON permission.id = current_tuple.permission_id
    WHERE permission.key IN (
      'operator_team.read',
      'operator_team.manage',
      'operator_team.roster.manage'
    )
  ) THEN
    RAISE EXCEPTION 'legacy role-policy ABI cannot represent operator-team tuples'
      USING ERRCODE = '55000';
  END IF;

  RETURN app.replace_tenant_role_policy_v2(
    p_role_id,
    p_expected_version,
    p_permission_keys,
    p_scopes,
    p_delegation_permission_keys,
    p_delegation_scopes,
    p_audit_event_id,
    p_request_id,
    p_correlation_id,
    p_ip_address,
    p_user_agent,
    p_authentication_method
  );
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."replace_tenant_role_policy_with_result_v2"(
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
RETURNS TABLE (
  role_id uuid,
  role_key text,
  display_name text,
  description text,
  system_role boolean,
  protected_role boolean,
  version integer,
  archived_at timestamp with time zone,
  created_at timestamp with time zone,
  updated_at timestamp with time zone,
  permission_keys text[],
  permission_scopes "public"."authorization_scope"[],
  delegation_permission_keys text[],
  delegation_scopes "public"."authorization_scope"[]
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  mutated_version integer;
BEGIN
  mutated_version := app.replace_tenant_role_policy_v2(
    p_role_id,
    p_expected_version,
    p_permission_keys,
    p_scopes,
    p_delegation_permission_keys,
    p_delegation_scopes,
    p_audit_event_id,
    p_request_id,
    p_correlation_id,
    p_ip_address,
    p_user_agent,
    p_authentication_method
  );

  RETURN QUERY
  SELECT role.id,
         role.key::text,
         role.display_name::text,
         role.description::text,
         role.system_role,
         role.protected_role,
         role.version,
         role.archived_at,
         role.created_at,
         role.updated_at,
         ARRAY(
           SELECT permission.key::text
           FROM public.tenant_role_permissions AS policy
           JOIN public.tenant_permissions AS permission
             ON permission.id = policy.permission_id
           WHERE policy.tenant_id = context_tenant
             AND policy.role_id = p_role_id
           ORDER BY permission.key, policy.scope
         ),
         ARRAY(
           SELECT policy.scope
           FROM public.tenant_role_permissions AS policy
           JOIN public.tenant_permissions AS permission
             ON permission.id = policy.permission_id
           WHERE policy.tenant_id = context_tenant
             AND policy.role_id = p_role_id
           ORDER BY permission.key, policy.scope
         ),
         ARRAY(
           SELECT permission.key::text
           FROM public.tenant_role_delegation_ceilings AS ceiling
           JOIN public.tenant_permissions AS permission
             ON permission.id = ceiling.permission_id
           WHERE ceiling.tenant_id = context_tenant
             AND ceiling.role_id = p_role_id
           ORDER BY permission.key, ceiling.scope
         ),
         ARRAY(
           SELECT ceiling.scope
           FROM public.tenant_role_delegation_ceilings AS ceiling
           JOIN public.tenant_permissions AS permission
             ON permission.id = ceiling.permission_id
           WHERE ceiling.tenant_id = context_tenant
             AND ceiling.role_id = p_role_id
           ORDER BY permission.key, ceiling.scope
         )
  FROM public.tenant_roles AS role
  WHERE role.tenant_id = context_tenant
    AND role.id = p_role_id
    AND role.version = mutated_version;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant role mutation result was not found'
      USING ERRCODE = 'XX000';
  END IF;
END;
$function$;--> statement-breakpoint

CREATE OR REPLACE FUNCTION "app"."guard_tenant_authorization_command"()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    RAISE EXCEPTION 'tenant authorization command rows are append-only'
      USING ERRCODE = '55000';
  END IF;

  IF TG_OP = 'DELETE' THEN
    IF OLD.expires_at > transaction_timestamp() THEN
      RAISE EXCEPTION 'unexpired tenant authorization commands cannot be pruned'
        USING ERRCODE = '55000';
    END IF;
    RETURN OLD;
  END IF;

  IF NEW.operation = 'tenant_role.create' THEN
    IF NOT EXISTS (
      SELECT 1 FROM public.tenant_roles AS resource
      WHERE resource.tenant_id = NEW.tenant_id
        AND resource.id = NEW.result_resource_id
        AND resource.version = NEW.result_version
    ) THEN
      RAISE EXCEPTION 'tenant role idempotency result is invalid'
        USING ERRCODE = '23503',
              CONSTRAINT = 'tenant_authorization_commands_result_fk';
    END IF;
  ELSIF NEW.operation = 'tenant_role_grant.create' THEN
    IF NOT EXISTS (
      SELECT 1 FROM public.tenant_membership_role_grants AS resource
      WHERE resource.tenant_id = NEW.tenant_id
        AND resource.id = NEW.result_resource_id
        AND resource.version = NEW.result_version
    ) THEN
      RAISE EXCEPTION 'tenant role grant idempotency result is invalid'
        USING ERRCODE = '23503',
              CONSTRAINT = 'tenant_authorization_commands_result_fk';
    END IF;
  ELSIF NEW.operation = 'tenant_security_group.create' THEN
    IF NOT EXISTS (
      SELECT 1 FROM public.tenant_security_groups AS resource
      WHERE resource.tenant_id = NEW.tenant_id
        AND resource.id = NEW.result_resource_id
        AND resource.version = NEW.result_version
    ) THEN
      RAISE EXCEPTION 'tenant security group idempotency result is invalid'
        USING ERRCODE = '23503',
              CONSTRAINT = 'tenant_authorization_commands_result_fk';
    END IF;
  ELSIF NEW.operation = 'tenant_security_group_membership.create' THEN
    IF NOT EXISTS (
      SELECT 1 FROM public.tenant_security_group_memberships AS resource
      WHERE resource.tenant_id = NEW.tenant_id
        AND resource.id = NEW.result_resource_id
        AND resource.version = NEW.result_version
    ) THEN
      RAISE EXCEPTION 'tenant security group membership idempotency result is invalid'
        USING ERRCODE = '23503',
              CONSTRAINT = 'tenant_authorization_commands_result_fk';
    END IF;
  ELSIF NEW.operation = 'tenant_security_group_role_grant.create' THEN
    IF NOT EXISTS (
      SELECT 1 FROM public.tenant_security_group_role_grants AS resource
      WHERE resource.tenant_id = NEW.tenant_id
        AND resource.id = NEW.result_resource_id
        AND resource.version = NEW.result_version
    ) THEN
      RAISE EXCEPTION 'tenant security group role grant idempotency result is invalid'
        USING ERRCODE = '23503',
              CONSTRAINT = 'tenant_authorization_commands_result_fk';
    END IF;
  ELSIF NEW.operation = 'operator_team_assignment.create' THEN
    IF NOT EXISTS (
      SELECT 1 FROM public.operator_team_assignment_epochs AS resource
      WHERE resource.tenant_id = NEW.tenant_id
        AND resource.id = NEW.result_resource_id
        AND resource.version = NEW.result_version
    ) THEN
      RAISE EXCEPTION 'operator-team assignment idempotency result is invalid'
        USING ERRCODE = '23503',
              CONSTRAINT = 'tenant_authorization_commands_result_fk';
    END IF;
  ELSIF NEW.operation = 'operator_team_roster_entry.create' THEN
    IF NOT EXISTS (
      SELECT 1 FROM public.operator_team_roster_entries AS resource
      WHERE resource.tenant_id = NEW.tenant_id
        AND resource.id = NEW.result_resource_id
        AND resource.version = NEW.result_version
    ) THEN
      RAISE EXCEPTION 'operator-team roster idempotency result is invalid'
        USING ERRCODE = '23503',
              CONSTRAINT = 'tenant_authorization_commands_result_fk';
    END IF;
  ELSE
    RAISE EXCEPTION 'unsupported tenant authorization command operation'
      USING ERRCODE = '22023';
  END IF;

  RETURN NEW;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."guard_platform_command"()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    RAISE EXCEPTION 'platform command rows are append-only'
      USING ERRCODE = '55000';
  END IF;

  IF TG_OP = 'DELETE' THEN
    IF OLD.expires_at > transaction_timestamp() THEN
      RAISE EXCEPTION 'unexpired platform commands cannot be pruned'
        USING ERRCODE = '55000';
    END IF;
    RETURN OLD;
  END IF;

  IF NEW.operation <> 'operator_team.create' THEN
    RAISE EXCEPTION 'unsupported platform command operation'
      USING ERRCODE = '22023';
  END IF;
  IF NOT EXISTS (
    SELECT 1
    FROM public.operator_teams AS resource
    WHERE resource.id = NEW.result_resource_id
      AND resource.version = NEW.result_version
  ) THEN
    RAISE EXCEPTION 'operator-team idempotency result is invalid'
      USING ERRCODE = '23503',
            CONSTRAINT = 'platform_commands_result_fk';
  END IF;

  RETURN NEW;
END;
$function$;--> statement-breakpoint

CREATE TRIGGER "platform_commands_guard"
BEFORE INSERT OR UPDATE OR DELETE ON "public"."platform_commands"
FOR EACH ROW EXECUTE FUNCTION "app"."guard_platform_command"();--> statement-breakpoint

ALTER FUNCTION "app"."get_auth_session_v2"(bytea) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."get_auth_session"(bytea) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."resolve_current_tenant_human_authority_v2"(integer) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."resolve_current_tenant_human_authority"(integer) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."list_tenant_permission_catalog_v2"(uuid, integer) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."list_tenant_permission_catalog"(uuid, integer) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."get_tenant_role_policy_v2"(uuid, integer) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."get_tenant_role_policy"(uuid, integer) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."current_tenant_has_live_operator_team_relationship"(uuid, uuid) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."current_tenant_can_read_operator_team"(uuid, uuid) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."current_tenant_can_manage_operator_team_roster"(uuid, uuid) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."assert_actor_can_change_operator_team_roster"(uuid, timestamp with time zone) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."resolve_current_tenant_operator_teams"(integer) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."list_platform_operator_teams"(uuid, boolean, integer) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."get_platform_operator_team"(uuid) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."create_platform_operator_team"(uuid, bytea, text, text, text, uuid, uuid, uuid, inet, text, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."update_platform_operator_team_metadata"(uuid, integer, text, text, uuid, uuid, uuid, inet, text, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."archive_platform_operator_team"(uuid, integer, text, uuid, uuid, uuid, inet, text, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."list_tenant_operator_team_assignment_epochs"(uuid, uuid, boolean, integer) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."get_tenant_operator_team_assignment_epoch"(uuid, uuid) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."start_tenant_operator_team_assignment"(uuid, bytea, uuid, text, uuid, uuid, uuid, uuid, inet, text, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."end_tenant_operator_team_assignment"(uuid, uuid, integer, text, uuid, uuid, uuid, uuid, inet, text, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."list_tenant_operator_team_roster_entries"(uuid, uuid, uuid, boolean, integer) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."get_tenant_operator_team_roster_entry"(uuid, uuid, uuid) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."add_tenant_operator_team_roster_entry"(uuid, bytea, uuid, uuid, uuid, text, timestamp with time zone, uuid, uuid, uuid, inet, text, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."revoke_tenant_operator_team_roster_entry"(uuid, uuid, uuid, integer, text, uuid, uuid, uuid, inet, text, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."replace_tenant_role_policy_v2"(uuid, integer, text[], "public"."authorization_scope"[], text[], "public"."authorization_scope"[], uuid, uuid, uuid, inet, text, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."replace_tenant_role_policy"(uuid, integer, text[], "public"."authorization_scope"[], text[], "public"."authorization_scope"[], uuid, uuid, uuid, inet, text, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."replace_tenant_role_policy_with_result_v2"(uuid, integer, text[], "public"."authorization_scope"[], text[], "public"."authorization_scope"[], uuid, uuid, uuid, inet, text, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."replace_tenant_role_policy_with_result"(uuid, integer, text[], "public"."authorization_scope"[], text[], "public"."authorization_scope"[], uuid, uuid, uuid, inet, text, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."guard_tenant_authorization_command"() OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."guard_platform_command"() OWNER TO "periapsis_migrator";--> statement-breakpoint

REVOKE ALL ON FUNCTION "app"."get_auth_session_v2"(bytea) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."get_auth_session"(bytea) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."resolve_current_tenant_human_authority_v2"(integer) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."resolve_current_tenant_human_authority"(integer) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."list_tenant_permission_catalog_v2"(uuid, integer) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."list_tenant_permission_catalog"(uuid, integer) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."get_tenant_role_policy_v2"(uuid, integer) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."get_tenant_role_policy"(uuid, integer) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."current_tenant_has_live_operator_team_relationship"(uuid, uuid) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."current_tenant_can_read_operator_team"(uuid, uuid) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."current_tenant_can_manage_operator_team_roster"(uuid, uuid) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."assert_actor_can_change_operator_team_roster"(uuid, timestamp with time zone) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."guard_tenant_authorization_command"() FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."guard_platform_command"() FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint

REVOKE ALL ON FUNCTION "app"."resolve_current_tenant_operator_teams"(integer) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."list_platform_operator_teams"(uuid, boolean, integer) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."get_platform_operator_team"(uuid) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."create_platform_operator_team"(uuid, bytea, text, text, text, uuid, uuid, uuid, inet, text, text) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."update_platform_operator_team_metadata"(uuid, integer, text, text, uuid, uuid, uuid, inet, text, text) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."archive_platform_operator_team"(uuid, integer, text, uuid, uuid, uuid, inet, text, text) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."list_tenant_operator_team_assignment_epochs"(uuid, uuid, boolean, integer) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."get_tenant_operator_team_assignment_epoch"(uuid, uuid) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."start_tenant_operator_team_assignment"(uuid, bytea, uuid, text, uuid, uuid, uuid, uuid, inet, text, text) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."end_tenant_operator_team_assignment"(uuid, uuid, integer, text, uuid, uuid, uuid, uuid, inet, text, text) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."list_tenant_operator_team_roster_entries"(uuid, uuid, uuid, boolean, integer) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."get_tenant_operator_team_roster_entry"(uuid, uuid, uuid) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."add_tenant_operator_team_roster_entry"(uuid, bytea, uuid, uuid, uuid, text, timestamp with time zone, uuid, uuid, uuid, inet, text, text) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."revoke_tenant_operator_team_roster_entry"(uuid, uuid, uuid, integer, text, uuid, uuid, uuid, inet, text, text) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."replace_tenant_role_policy_v2"(uuid, integer, text[], "public"."authorization_scope"[], text[], "public"."authorization_scope"[], uuid, uuid, uuid, inet, text, text) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."replace_tenant_role_policy"(uuid, integer, text[], "public"."authorization_scope"[], text[], "public"."authorization_scope"[], uuid, uuid, uuid, inet, text, text) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."replace_tenant_role_policy_with_result_v2"(uuid, integer, text[], "public"."authorization_scope"[], text[], "public"."authorization_scope"[], uuid, uuid, uuid, inet, text, text) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."replace_tenant_role_policy_with_result"(uuid, integer, text[], "public"."authorization_scope"[], text[], "public"."authorization_scope"[], uuid, uuid, uuid, inet, text, text) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint

GRANT EXECUTE ON FUNCTION "app"."get_auth_session_v2"(bytea) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."get_auth_session"(bytea) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."resolve_current_tenant_human_authority_v2"(integer) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."resolve_current_tenant_human_authority"(integer) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."list_tenant_permission_catalog_v2"(uuid, integer) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."list_tenant_permission_catalog"(uuid, integer) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."get_tenant_role_policy_v2"(uuid, integer) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."get_tenant_role_policy"(uuid, integer) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."resolve_current_tenant_operator_teams"(integer) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."list_platform_operator_teams"(uuid, boolean, integer) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."get_platform_operator_team"(uuid) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."create_platform_operator_team"(uuid, bytea, text, text, text, uuid, uuid, uuid, inet, text, text) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."update_platform_operator_team_metadata"(uuid, integer, text, text, uuid, uuid, uuid, inet, text, text) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."archive_platform_operator_team"(uuid, integer, text, uuid, uuid, uuid, inet, text, text) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."list_tenant_operator_team_assignment_epochs"(uuid, uuid, boolean, integer) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."get_tenant_operator_team_assignment_epoch"(uuid, uuid) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."start_tenant_operator_team_assignment"(uuid, bytea, uuid, text, uuid, uuid, uuid, uuid, inet, text, text) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."end_tenant_operator_team_assignment"(uuid, uuid, integer, text, uuid, uuid, uuid, uuid, inet, text, text) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."list_tenant_operator_team_roster_entries"(uuid, uuid, uuid, boolean, integer) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."get_tenant_operator_team_roster_entry"(uuid, uuid, uuid) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."add_tenant_operator_team_roster_entry"(uuid, bytea, uuid, uuid, uuid, text, timestamp with time zone, uuid, uuid, uuid, inet, text, text) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."revoke_tenant_operator_team_roster_entry"(uuid, uuid, uuid, integer, text, uuid, uuid, uuid, inet, text, text) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."replace_tenant_role_policy_v2"(uuid, integer, text[], "public"."authorization_scope"[], text[], "public"."authorization_scope"[], uuid, uuid, uuid, inet, text, text) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."replace_tenant_role_policy"(uuid, integer, text[], "public"."authorization_scope"[], text[], "public"."authorization_scope"[], uuid, uuid, uuid, inet, text, text) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."replace_tenant_role_policy_with_result_v2"(uuid, integer, text[], "public"."authorization_scope"[], text[], "public"."authorization_scope"[], uuid, uuid, uuid, inet, text, text) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."replace_tenant_role_policy_with_result"(uuid, integer, text[], "public"."authorization_scope"[], text[], "public"."authorization_scope"[], uuid, uuid, uuid, inet, text, text) TO "periapsis_api";
