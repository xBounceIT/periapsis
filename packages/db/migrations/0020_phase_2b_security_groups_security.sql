-- Phase 2B.2a tenant security groups. The generated structural migrations
-- remain canonical; this migration owns forced RLS, bounded definer entry
-- points, live authority derivation, audit coupling, and serialization.

ALTER TABLE "public"."tenant_security_groups" OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER TABLE "public"."tenant_security_group_memberships" OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER TABLE "public"."tenant_security_group_role_grants" OWNER TO "periapsis_migrator";--> statement-breakpoint

ALTER TABLE "public"."tenant_security_groups" FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "public"."tenant_security_group_memberships" FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "public"."tenant_security_group_role_grants" FORCE ROW LEVEL SECURITY;--> statement-breakpoint

REVOKE ALL ON TABLE "public"."tenant_security_groups" FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON TABLE "public"."tenant_security_group_memberships" FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON TABLE "public"."tenant_security_group_role_grants" FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint

INSERT INTO "public"."tenant_permissions" (
  "id", "key", "display_name", "description", "service_account_allowed"
)
VALUES
  (uuidv7(), 'group.read', 'Read security groups', 'Read tenant security groups and their provenance-preserving membership paths.', false),
  (uuidv7(), 'group.manage', 'Manage security groups', 'Create, update, and archive tenant security groups.', false),
  (uuidv7(), 'group.membership.manage', 'Manage security group memberships', 'Add and revoke tenant security group membership paths.', false)
ON CONFLICT ("key") DO NOTHING;--> statement-breakpoint

INSERT INTO "public"."tenant_permission_scopes" ("permission_id", "scope")
SELECT permission.id, 'tenant'::"public"."authorization_scope"
FROM "public"."tenant_permissions" AS permission
WHERE permission.key IN (
  'group.read', 'group.manage', 'group.membership.manage'
)
ON CONFLICT DO NOTHING;--> statement-breakpoint

DO $block$
BEGIN
  IF (
    SELECT count(*)
    FROM public.tenant_permissions AS permission
    JOIN public.tenant_permission_scopes AS permission_scope
      ON permission_scope.permission_id = permission.id
    WHERE permission.key IN (
      'group.read', 'group.manage', 'group.membership.manage'
    )
      AND permission.service_account_allowed IS FALSE
      AND permission_scope.scope = 'tenant'
  ) <> 3 OR EXISTS (
    SELECT 1
    FROM public.tenant_permissions AS permission
    JOIN public.tenant_permission_scopes AS permission_scope
      ON permission_scope.permission_id = permission.id
    WHERE permission.key IN (
      'group.read', 'group.manage', 'group.membership.manage'
    )
      AND permission_scope.scope <> 'tenant'
  ) THEN
    RAISE EXCEPTION 'tenant security-group permission catalog is invalid'
      USING ERRCODE = '55000';
  END IF;
END;
$block$;--> statement-breakpoint

-- Existing initialized tenants receive the three new administrative tuples.
-- A policy change is part of the role's strong representation, so every
-- affected protected tenant_admin advances exactly one role version even
-- though multiple policy and delegation rows are inserted. Future tenant
-- seeding starts with the complete catalog and therefore remains at version 1.
DO $block$
DECLARE
  target_role record;
  policy_rows_added integer;
  ceiling_rows_added integer;
  result_version integer;
BEGIN
  FOR target_role IN
    SELECT role.tenant_id, role.id, role.version
    FROM public.tenant_roles AS role
    JOIN public.tenant_authorization_states AS state
      ON state.tenant_id = role.tenant_id
     AND state.initialized_at IS NOT NULL
    WHERE role.key = 'tenant_admin'
      AND role.system_role
      AND role.protected_role
      AND role.archived_at IS NULL
    ORDER BY role.tenant_id, role.id
    FOR UPDATE OF role
  LOOP
    IF target_role.version >= 2147483647 AND EXISTS (
      SELECT 1
      FROM public.tenant_permission_scopes AS permission_scope
      JOIN public.tenant_permissions AS permission
        ON permission.id = permission_scope.permission_id
      WHERE permission.key IN (
        'group.read', 'group.manage', 'group.membership.manage'
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
      RAISE EXCEPTION 'tenant_admin role version is exhausted during security-group backfill'
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
      'group.read', 'group.manage', 'group.membership.manage'
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
      'group.read', 'group.manage', 'group.membership.manage'
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
      'tenant.authorization.security_groups_enabled', 'tenant_role',
      target_role.id, 'database_migration', 'success',
      jsonb_build_object(
        'permissions', jsonb_build_array(
          'group.read', 'group.manage', 'group.membership.manage'
        ),
        'prior_version', target_role.version,
        'result_version', result_version
      ),
      jsonb_build_object(
        'migration', '0020_phase_2b_security_groups_security',
        'policy_rows_added', policy_rows_added,
        'delegation_rows_added', ceiling_rows_added,
        'prior_version', target_role.version,
        'result_version', result_version
      )
    );
  END LOOP;
END;
$block$;--> statement-breakpoint

CREATE TRIGGER "tenant_security_groups_touch"
BEFORE INSERT OR UPDATE OR DELETE ON "public"."tenant_security_groups"
FOR EACH ROW EXECUTE FUNCTION "app"."touch_tenant_authorization_row"();--> statement-breakpoint
CREATE TRIGGER "tenant_security_group_memberships_touch"
BEFORE INSERT OR UPDATE OR DELETE ON "public"."tenant_security_group_memberships"
FOR EACH ROW EXECUTE FUNCTION "app"."touch_tenant_authorization_row"();--> statement-breakpoint
CREATE TRIGGER "tenant_security_group_role_grants_touch"
BEFORE INSERT OR UPDATE OR DELETE ON "public"."tenant_security_group_role_grants"
FOR EACH ROW EXECUTE FUNCTION "app"."touch_tenant_authorization_row"();--> statement-breakpoint

CREATE FUNCTION "app"."earliest_authorization_expiry"(
  p_left timestamp with time zone,
  p_right timestamp with time zone
)
RETURNS timestamp with time zone
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, public, app
AS $function$
  SELECT CASE
    WHEN p_left IS NULL THEN p_right
    WHEN p_right IS NULL THEN p_left
    ELSE least(p_left, p_right)
  END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."assert_actor_can_change_security_group_member"(
  p_group_id uuid,
  p_membership_expires_at timestamp with time zone
)
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  role_grant record;
  checked_count integer := 0;
BEGIN
  FOR role_grant IN
    SELECT group_grant.role_id,
           app.earliest_authorization_expiry(
             p_membership_expires_at, group_grant.expires_at
           ) AS effective_expires_at
    FROM public.tenant_security_group_role_grants AS group_grant
    JOIN public.tenant_authorization_sources AS source
      ON source.tenant_id = group_grant.tenant_id
     AND source.id = group_grant.source_id
    JOIN public.tenant_roles AS role
      ON role.tenant_id = group_grant.tenant_id
     AND role.id = group_grant.role_id
    WHERE group_grant.tenant_id = context_tenant
      AND group_grant.group_id = p_group_id
      AND group_grant.revoked_at IS NULL
      AND (group_grant.expires_at IS NULL
        OR group_grant.expires_at > transaction_timestamp())
      AND source.retired_at IS NULL
      AND role.archived_at IS NULL
    ORDER BY group_grant.id
    LIMIT 501
  LOOP
    checked_count := checked_count + 1;
    IF checked_count > 500 THEN
      RAISE EXCEPTION 'security group role consequence limit exceeded'
        USING ERRCODE = '54000';
    END IF;
    IF role_grant.effective_expires_at IS NULL
       OR role_grant.effective_expires_at > transaction_timestamp() THEN
      PERFORM app.assert_actor_can_grant_role(
        role_grant.role_id, role_grant.effective_expires_at
      );
    END IF;
  END LOOP;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."assert_actor_can_change_security_group_roles"(
  p_group_id uuid
)
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  role_grant record;
  checked_count integer := 0;
BEGIN
  FOR role_grant IN
    SELECT group_grant.role_id, group_grant.expires_at
    FROM public.tenant_security_group_role_grants AS group_grant
    JOIN public.tenant_authorization_sources AS source
      ON source.tenant_id = group_grant.tenant_id
     AND source.id = group_grant.source_id
    JOIN public.tenant_roles AS role
      ON role.tenant_id = group_grant.tenant_id
     AND role.id = group_grant.role_id
    WHERE group_grant.tenant_id = context_tenant
      AND group_grant.group_id = p_group_id
      AND group_grant.revoked_at IS NULL
      AND (group_grant.expires_at IS NULL
        OR group_grant.expires_at > transaction_timestamp())
      AND source.retired_at IS NULL
      AND role.archived_at IS NULL
    ORDER BY group_grant.id
    LIMIT 501
  LOOP
    checked_count := checked_count + 1;
    IF checked_count > 500 THEN
      RAISE EXCEPTION 'security group role consequence limit exceeded'
        USING ERRCODE = '54000';
    END IF;
    PERFORM app.assert_actor_can_grant_role(
      role_grant.role_id, role_grant.expires_at
    );
  END LOOP;
END;
$function$;--> statement-breakpoint

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

/* Removed before the public function surface was frozen: permission-expanded
   rows are not a safe role-grant projection because policy cardinality can
   truncate otherwise valid role paths. The aggregate authority function and
   the one-row-per-role-path projection below are the supported boundaries.
CREATE FUNCTION "app"."resolve_current_tenant_human_authority_paths"(
  p_limit integer
)
RETURNS TABLE (
  path_type text,
  permission_key text,
  scope "public"."authorization_scope",
  delegable boolean,
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
  IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 1001 THEN
    RAISE EXCEPTION 'tenant authority path limit must be between 1 and 1001'
      USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  WITH paths AS (
    SELECT 'direct'::text AS path_type,
           direct_grant.role_id,
           direct_grant.id AS role_grant_id,
           direct_source.id AS role_source_id,
           direct_source.kind AS role_source_kind,
           direct_source.authoritative AS role_source_authoritative,
           direct_source.retired_at AS role_source_retired_at,
           grantor.user_id AS role_granted_by_user_id,
           direct_grant.grant_reason AS role_grant_reason,
           direct_grant.granted_at AS role_granted_at,
           direct_grant.expires_at AS role_grant_expires_at,
           direct_grant.version AS role_grant_version,
           NULL::uuid AS group_id,
           NULL::text AS group_key,
           NULL::text AS group_name,
           NULL::uuid AS group_membership_id,
           NULL::uuid AS membership_source_id,
           NULL::public.authorization_source_kind AS membership_source_kind,
           NULL::boolean AS membership_source_authoritative,
           NULL::timestamp with time zone AS membership_source_retired_at,
           NULL::uuid AS membership_granted_by_user_id,
           NULL::text AS membership_grant_reason,
           NULL::timestamp with time zone AS membership_granted_at,
           NULL::timestamp with time zone AS membership_expires_at,
           NULL::integer AS membership_version,
           direct_grant.expires_at AS effective_expires_at
    FROM public.tenant_membership_role_grants AS direct_grant
    JOIN public.tenant_authorization_sources AS direct_source
      ON direct_source.tenant_id = direct_grant.tenant_id
     AND direct_source.id = direct_grant.source_id
    LEFT JOIN public.tenant_memberships AS grantor
      ON grantor.tenant_id = direct_grant.tenant_id
     AND grantor.id = direct_grant.granted_by_membership_id
    WHERE direct_grant.tenant_id = context_tenant
      AND direct_grant.membership_id = context_membership
      AND direct_grant.revoked_at IS NULL
      AND (direct_grant.expires_at IS NULL
        OR direct_grant.expires_at > transaction_timestamp())
      AND direct_source.retired_at IS NULL

    UNION ALL

    SELECT 'group'::text,
           group_grant.role_id,
           group_grant.id,
           grant_source.id,
           grant_source.kind,
           grant_source.authoritative,
           grant_source.retired_at,
           role_grantor.user_id,
           group_grant.grant_reason,
           group_grant.granted_at,
           group_grant.expires_at,
           group_grant.version,
           security_group.id,
           security_group.key,
           security_group.display_name,
           group_member.id,
           member_source.id,
           member_source.kind,
           member_source.authoritative,
           member_source.retired_at,
           member_grantor.user_id,
           group_member.grant_reason,
           group_member.granted_at,
           group_member.expires_at,
           group_member.version,
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
  )
  SELECT path.path_type, permission.key, role_permission.scope,
         ceiling.permission_id IS NOT NULL, path.effective_expires_at,
         role.id, role.key, role.display_name,
         path.role_grant_id, path.role_source_id, path.role_source_kind,
         path.role_source_authoritative, path.role_source_retired_at,
         path.role_granted_by_user_id, path.role_grant_reason,
         path.role_granted_at, path.role_grant_expires_at,
         path.role_grant_version, path.group_id, path.group_key,
         path.group_name, path.group_membership_id,
         path.membership_source_id, path.membership_source_kind,
         path.membership_source_authoritative,
         path.membership_source_retired_at,
         path.membership_granted_by_user_id,
         path.membership_grant_reason, path.membership_granted_at,
         path.membership_expires_at, path.membership_version
  FROM paths AS path
  JOIN public.tenant_roles AS role
    ON role.tenant_id = context_tenant
   AND role.id = path.role_id
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
  ORDER BY permission.key, role_permission.scope, path.path_type,
           role.id, path.role_grant_id, path.group_membership_id
  LIMIT p_limit;
END;
$function$;
*/

CREATE FUNCTION "app"."resolve_current_tenant_human_role_grant_paths"(
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
    AND role.archived_at IS NULL
  ORDER BY 1, 4, 7, 20
  LIMIT p_limit;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."list_tenant_security_groups"(
  p_after_group_id uuid,
  p_include_archived boolean,
  p_limit integer
)
RETURNS TABLE (
  group_id uuid,
  group_key text,
  group_name text,
  group_description text,
  created_by_membership_id uuid,
  created_by_user_id uuid,
  archived_at timestamp with time zone,
  version integer,
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
  IF NOT app.current_tenant_has_exact_permission('group.read', 'tenant') THEN
    RAISE EXCEPTION 'group.read tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_include_archived IS NULL THEN
    RAISE EXCEPTION 'include archived must be explicit'
      USING ERRCODE = '22023';
  END IF;
  IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 101 THEN
    RAISE EXCEPTION 'security group page limit must be between 1 and 101'
      USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  SELECT security_group.id, security_group.key,
         security_group.display_name, security_group.description,
         security_group.created_by_membership_id, creator.user_id,
         security_group.archived_at, security_group.version,
         security_group.created_at, security_group.updated_at
  FROM public.tenant_security_groups AS security_group
  LEFT JOIN public.tenant_memberships AS creator
    ON creator.tenant_id = security_group.tenant_id
   AND creator.id = security_group.created_by_membership_id
  WHERE security_group.tenant_id = context_tenant
    AND (p_include_archived OR security_group.archived_at IS NULL)
    AND (p_after_group_id IS NULL OR security_group.id > p_after_group_id)
  ORDER BY security_group.id
  LIMIT p_limit;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."get_tenant_security_group"(p_group_id uuid)
RETURNS TABLE (
  group_id uuid,
  group_key text,
  group_name text,
  group_description text,
  created_by_membership_id uuid,
  created_by_user_id uuid,
  archived_at timestamp with time zone,
  version integer,
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
    app.current_tenant_has_exact_permission('group.read', 'tenant')
    OR app.current_tenant_has_exact_permission('group.manage', 'tenant')
  ) THEN
    RAISE EXCEPTION 'group.read or group.manage tenant scope is required'
      USING ERRCODE = '42501';
  END IF;

  RETURN QUERY
  SELECT security_group.id, security_group.key,
         security_group.display_name, security_group.description,
         security_group.created_by_membership_id, creator.user_id,
         security_group.archived_at, security_group.version,
         security_group.created_at, security_group.updated_at
  FROM public.tenant_security_groups AS security_group
  LEFT JOIN public.tenant_memberships AS creator
    ON creator.tenant_id = security_group.tenant_id
   AND creator.id = security_group.created_by_membership_id
  WHERE security_group.tenant_id = context_tenant
    AND security_group.id = p_group_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant security group was not found'
      USING ERRCODE = 'P0002';
  END IF;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."create_tenant_security_group"(
  p_group_id uuid,
  p_idempotency_key_digest bytea,
  p_key text,
  p_name text,
  p_description text,
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
  canonical_request_digest bytea;
  replay record;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF NOT app.current_tenant_has_exact_permission('group.manage', 'tenant') THEN
    RAISE EXCEPTION 'group.manage tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_idempotency_key_digest IS NULL
     OR octet_length(p_idempotency_key_digest) <> 32 THEN
    RAISE EXCEPTION 'idempotency key digest must be SHA-256'
      USING ERRCODE = '22023';
  END IF;

  SELECT sha256(convert_to(jsonb_build_object(
    'key', p_key,
    'name', p_name,
    'description', coalesce(p_description, '')
  )::text, 'UTF8')) INTO canonical_request_digest;

  DELETE FROM public.tenant_authorization_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.actor_membership_id = actor_membership
    AND command.operation = 'tenant_security_group.create'
    AND command.key_digest = p_idempotency_key_digest
    AND command.expires_at <= transaction_timestamp();

  SELECT command.* INTO replay
  FROM public.tenant_authorization_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.actor_membership_id = actor_membership
    AND command.operation = 'tenant_security_group.create'
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

  IF p_key IS NULL OR p_key !~ '^[a-z][a-z0-9_]{2,63}$' THEN
    RAISE EXCEPTION 'security group key is invalid'
      USING ERRCODE = '22023';
  END IF;
  IF p_name IS NULL OR btrim(p_name) = ''
     OR char_length(p_name) > 120 OR p_name ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION 'security group name is invalid'
      USING ERRCODE = '22023';
  END IF;
  IF p_description IS NOT NULL
     AND (char_length(p_description) > 500
       OR p_description ~ '[[:cntrl:]]') THEN
    RAISE EXCEPTION 'security group description is invalid'
      USING ERRCODE = '22023';
  END IF;

  INSERT INTO public.tenant_security_groups (
    id, tenant_id, key, display_name, description, created_by_membership_id
  ) VALUES (
    p_group_id, context_tenant, p_key, p_name, coalesce(p_description, ''),
    actor_membership
  );

  PERFORM app.append_tenant_authorization_audit(
    p_audit_event_id, 'tenant.security_group.created',
    'tenant_security_group', p_group_id,
    p_request_id, p_correlation_id,
    p_ip_address, p_user_agent, p_authentication_method, NULL,
    jsonb_build_object(
      'key', p_key, 'name', p_name, 'version', 1
    ),
    jsonb_build_object('actor_membership_id', actor_membership)
  );

  INSERT INTO public.tenant_authorization_commands (
    tenant_id, actor_membership_id, operation, key_digest, request_digest,
    result_resource_id, result_version
  ) VALUES (
    context_tenant, actor_membership, 'tenant_security_group.create',
    p_idempotency_key_digest, canonical_request_digest, p_group_id, 1
  );
  RETURN QUERY SELECT p_group_id, 1::integer, false;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."update_tenant_security_group_metadata"(
  p_group_id uuid,
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
  actor_membership uuid;
  target_group record;
  next_version integer;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF NOT app.current_tenant_has_exact_permission('group.manage', 'tenant') THEN
    RAISE EXCEPTION 'group.manage tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_name IS NULL AND p_description IS NULL THEN
    RAISE EXCEPTION 'at least one security group metadata field is required'
      USING ERRCODE = '22023';
  END IF;
  IF p_name IS NOT NULL AND (
    btrim(p_name) = '' OR char_length(p_name) > 120
    OR p_name ~ '[[:cntrl:]]'
  ) THEN
    RAISE EXCEPTION 'security group name is invalid'
      USING ERRCODE = '22023';
  END IF;
  IF p_description IS NOT NULL AND (
    char_length(p_description) > 500 OR p_description ~ '[[:cntrl:]]'
  ) THEN
    RAISE EXCEPTION 'security group description is invalid'
      USING ERRCODE = '22023';
  END IF;

  SELECT security_group.* INTO target_group
  FROM public.tenant_security_groups AS security_group
  WHERE security_group.tenant_id = context_tenant
    AND security_group.id = p_group_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant security group was not found'
      USING ERRCODE = 'P0002';
  END IF;
  IF target_group.version IS DISTINCT FROM p_expected_version THEN
    RAISE EXCEPTION 'tenant security group version conflict'
      USING ERRCODE = '40001';
  END IF;
  IF target_group.archived_at IS NOT NULL THEN
    RAISE EXCEPTION 'archived security group cannot be updated'
      USING ERRCODE = '55000';
  END IF;
  IF target_group.version >= 2147483647 THEN
    RAISE EXCEPTION 'tenant security group version is exhausted'
      USING ERRCODE = '55000';
  END IF;

  next_version := target_group.version + 1;
  UPDATE public.tenant_security_groups AS security_group
  SET display_name = coalesce(p_name, security_group.display_name),
      description = coalesce(p_description, security_group.description),
      version = next_version,
      updated_at = transaction_timestamp()
  WHERE security_group.tenant_id = context_tenant
    AND security_group.id = p_group_id;

  PERFORM app.append_tenant_authorization_audit(
    p_audit_event_id, 'tenant.security_group.metadata_updated',
    'tenant_security_group', p_group_id,
    p_request_id, p_correlation_id,
    p_ip_address, p_user_agent, p_authentication_method,
    jsonb_build_object(
      'name', target_group.display_name,
      'description', target_group.description,
      'version', target_group.version
    ),
    jsonb_build_object(
      'name', coalesce(p_name, target_group.display_name),
      'description', coalesce(p_description, target_group.description),
      'version', next_version
    ),
    jsonb_build_object('actor_membership_id', actor_membership)
  );
  RETURN next_version;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."archive_tenant_security_group"(
  p_group_id uuid,
  p_expected_version integer,
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
  target_group record;
  has_live_roles boolean;
  next_version integer;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF NOT app.current_tenant_has_exact_permission('group.manage', 'tenant') THEN
    RAISE EXCEPTION 'group.manage tenant scope is required'
      USING ERRCODE = '42501';
  END IF;

  SELECT security_group.* INTO target_group
  FROM public.tenant_security_groups AS security_group
  WHERE security_group.tenant_id = context_tenant
    AND security_group.id = p_group_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant security group was not found'
      USING ERRCODE = 'P0002';
  END IF;
  IF target_group.version IS DISTINCT FROM p_expected_version THEN
    RAISE EXCEPTION 'tenant security group version conflict'
      USING ERRCODE = '40001';
  END IF;
  IF target_group.archived_at IS NOT NULL THEN
    RAISE EXCEPTION 'tenant security group is already archived'
      USING ERRCODE = '55000';
  END IF;
  IF target_group.version >= 2147483647 THEN
    RAISE EXCEPTION 'tenant security group version is exhausted'
      USING ERRCODE = '55000';
  END IF;

  SELECT EXISTS (
    SELECT 1
    FROM public.tenant_security_group_role_grants AS group_grant
    JOIN public.tenant_authorization_sources AS source
      ON source.tenant_id = group_grant.tenant_id
     AND source.id = group_grant.source_id
    JOIN public.tenant_roles AS role
      ON role.tenant_id = group_grant.tenant_id
     AND role.id = group_grant.role_id
    WHERE group_grant.tenant_id = context_tenant
      AND group_grant.group_id = p_group_id
      AND group_grant.revoked_at IS NULL
      AND (group_grant.expires_at IS NULL
        OR group_grant.expires_at > transaction_timestamp())
      AND source.retired_at IS NULL
      AND role.archived_at IS NULL
  ) INTO has_live_roles;

  IF has_live_roles THEN
    IF NOT app.current_tenant_has_exact_permission('role.grant', 'tenant') THEN
      RAISE EXCEPTION 'role.grant tenant scope is required to archive an authority-bearing group'
        USING ERRCODE = '42501';
    END IF;
    PERFORM app.assert_actor_can_change_security_group_roles(p_group_id);
  END IF;

  next_version := target_group.version + 1;
  UPDATE public.tenant_security_groups AS security_group
  SET archived_at = transaction_timestamp(),
      version = next_version,
      updated_at = transaction_timestamp()
  WHERE security_group.tenant_id = context_tenant
    AND security_group.id = p_group_id;

  PERFORM app.append_tenant_authorization_audit(
    p_audit_event_id, 'tenant.security_group.archived',
    'tenant_security_group', p_group_id,
    p_request_id, p_correlation_id,
    p_ip_address, p_user_agent, p_authentication_method,
    jsonb_build_object('archived_at', NULL, 'version', target_group.version),
    jsonb_build_object(
      'archived_at', transaction_timestamp(), 'version', next_version
    ),
    jsonb_build_object(
      'actor_membership_id', actor_membership,
      'authority_bearing', has_live_roles
    )
  );
  RETURN next_version;
END;
$function$;

CREATE FUNCTION "app"."list_tenant_security_group_memberships"(
  p_group_id uuid,
  p_after_group_membership_id uuid,
  p_include_revoked boolean,
  p_limit integer
)
RETURNS TABLE (
  group_membership_id uuid,
  group_id uuid,
  group_key text,
  group_name text,
  group_description text,
  group_archived_at timestamp with time zone,
  group_version integer,
  group_created_at timestamp with time zone,
  group_updated_at timestamp with time zone,
  membership_id uuid,
  target_user_id uuid,
  email text,
  display_name text,
  membership_status "public"."membership_status",
  compatibility_role "public"."membership_role",
  user_active boolean,
  membership_created_at timestamp with time zone,
  membership_updated_at timestamp with time zone,
  source_id uuid,
  source_kind "public"."authorization_source_kind",
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
    app.current_tenant_has_exact_permission('group.read', 'tenant')
    AND app.current_tenant_has_exact_permission('user.read', 'tenant')
  ) THEN
    RAISE EXCEPTION 'group.read and user.read tenant scope are required'
      USING ERRCODE = '42501';
  END IF;
  IF p_include_revoked IS NULL THEN
    RAISE EXCEPTION 'include revoked must be explicit'
      USING ERRCODE = '22023';
  END IF;
  IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 101 THEN
    RAISE EXCEPTION 'security group membership page limit must be between 1 and 101'
      USING ERRCODE = '22023';
  END IF;
  IF NOT EXISTS (
    SELECT 1
    FROM public.tenant_security_groups AS security_group
    WHERE security_group.tenant_id = context_tenant
      AND security_group.id = p_group_id
  ) THEN
    RAISE EXCEPTION 'tenant security group was not found'
      USING ERRCODE = 'P0002';
  END IF;

  RETURN QUERY
  SELECT group_member.id, security_group.id, security_group.key,
         security_group.display_name, security_group.description,
         security_group.archived_at, security_group.version,
         security_group.created_at, security_group.updated_at,
         target.id, identity.id, identity.email,
         identity.display_name, target.status, target.role, identity.active,
         target.created_at, target.updated_at,
         source.id, source.kind, source.authoritative, source.retired_at,
         group_member.granted_by_membership_id, grantor.user_id,
         group_member.grant_reason, group_member.granted_at,
         group_member.expires_at, group_member.revoked_at,
         group_member.revoked_by_membership_id, revoker.user_id,
         group_member.revoke_reason,
         CASE
           WHEN group_member.revoked_at IS NOT NULL THEN 'revoked'
           WHEN group_member.expires_at IS NOT NULL
             AND group_member.expires_at <= transaction_timestamp()
             THEN 'expired'
           ELSE 'active'
         END,
         group_member.version, group_member.updated_at
  FROM public.tenant_security_group_memberships AS group_member
  JOIN public.tenant_security_groups AS security_group
    ON security_group.tenant_id = group_member.tenant_id
   AND security_group.id = group_member.group_id
  JOIN public.tenant_memberships AS target
    ON target.tenant_id = group_member.tenant_id
   AND target.id = group_member.membership_id
  JOIN public.users AS identity ON identity.id = target.user_id
  JOIN public.tenant_authorization_sources AS source
    ON source.tenant_id = group_member.tenant_id
   AND source.id = group_member.source_id
  LEFT JOIN public.tenant_memberships AS grantor
    ON grantor.tenant_id = group_member.tenant_id
   AND grantor.id = group_member.granted_by_membership_id
  LEFT JOIN public.tenant_memberships AS revoker
    ON revoker.tenant_id = group_member.tenant_id
   AND revoker.id = group_member.revoked_by_membership_id
  WHERE group_member.tenant_id = context_tenant
    AND group_member.group_id = p_group_id
    AND (p_include_revoked OR group_member.revoked_at IS NULL)
    AND (p_after_group_membership_id IS NULL
      OR group_member.id > p_after_group_membership_id)
  ORDER BY group_member.id
  LIMIT p_limit;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."get_tenant_security_group_membership"(
  p_group_id uuid,
  p_group_membership_id uuid
)
RETURNS TABLE (
  group_membership_id uuid,
  group_id uuid,
  group_key text,
  group_name text,
  group_description text,
  group_archived_at timestamp with time zone,
  group_version integer,
  group_created_at timestamp with time zone,
  group_updated_at timestamp with time zone,
  membership_id uuid,
  target_user_id uuid,
  email text,
  display_name text,
  membership_status "public"."membership_status",
  compatibility_role "public"."membership_role",
  user_active boolean,
  membership_created_at timestamp with time zone,
  membership_updated_at timestamp with time zone,
  source_id uuid,
  source_kind "public"."authorization_source_kind",
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
    (
      app.current_tenant_has_exact_permission('group.read', 'tenant')
      AND app.current_tenant_has_exact_permission('user.read', 'tenant')
    ) OR (
      app.current_tenant_has_exact_permission(
        'group.membership.manage', 'tenant'
      )
      AND app.current_tenant_has_exact_permission('role.grant', 'tenant')
    )
  ) THEN
    RAISE EXCEPTION 'group membership read or management authority is required'
      USING ERRCODE = '42501';
  END IF;

  RETURN QUERY
  SELECT group_member.id, security_group.id, security_group.key,
         security_group.display_name, security_group.description,
         security_group.archived_at, security_group.version,
         security_group.created_at, security_group.updated_at,
         target.id, identity.id, identity.email,
         identity.display_name, target.status, target.role, identity.active,
         target.created_at, target.updated_at,
         source.id, source.kind, source.authoritative, source.retired_at,
         group_member.granted_by_membership_id, grantor.user_id,
         group_member.grant_reason, group_member.granted_at,
         group_member.expires_at, group_member.revoked_at,
         group_member.revoked_by_membership_id, revoker.user_id,
         group_member.revoke_reason,
         CASE
           WHEN group_member.revoked_at IS NOT NULL THEN 'revoked'
           WHEN group_member.expires_at IS NOT NULL
             AND group_member.expires_at <= transaction_timestamp()
             THEN 'expired'
           ELSE 'active'
         END,
         group_member.version, group_member.updated_at
  FROM public.tenant_security_group_memberships AS group_member
  JOIN public.tenant_security_groups AS security_group
    ON security_group.tenant_id = group_member.tenant_id
   AND security_group.id = group_member.group_id
  JOIN public.tenant_memberships AS target
    ON target.tenant_id = group_member.tenant_id
   AND target.id = group_member.membership_id
  JOIN public.users AS identity ON identity.id = target.user_id
  JOIN public.tenant_authorization_sources AS source
    ON source.tenant_id = group_member.tenant_id
   AND source.id = group_member.source_id
  LEFT JOIN public.tenant_memberships AS grantor
    ON grantor.tenant_id = group_member.tenant_id
   AND grantor.id = group_member.granted_by_membership_id
  LEFT JOIN public.tenant_memberships AS revoker
    ON revoker.tenant_id = group_member.tenant_id
   AND revoker.id = group_member.revoked_by_membership_id
  WHERE group_member.tenant_id = context_tenant
    AND group_member.group_id = p_group_id
    AND group_member.id = p_group_membership_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant security group membership was not found'
      USING ERRCODE = 'P0002';
  END IF;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."add_tenant_security_group_member"(
  p_group_membership_id uuid,
  p_idempotency_key_digest bytea,
  p_group_id uuid,
  p_target_user_id uuid,
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
  target_membership uuid;
  manual_source uuid;
  canonical_request_digest bytea;
  replay record;
  superseded_memberships jsonb := '[]'::jsonb;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF NOT app.current_tenant_has_exact_permission(
    'group.membership.manage', 'tenant'
  ) THEN
    RAISE EXCEPTION 'group.membership.manage tenant scope is required'
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
    RAISE EXCEPTION 'security group membership reason is invalid'
      USING ERRCODE = '22023';
  END IF;
  SELECT sha256(convert_to(jsonb_build_object(
    'group_id', p_group_id,
    'target_user_id', p_target_user_id,
    'reason', p_reason,
    'expires_at', p_expires_at
  )::text, 'UTF8')) INTO canonical_request_digest;

  DELETE FROM public.tenant_authorization_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.actor_membership_id = actor_membership
    AND command.operation = 'tenant_security_group_membership.create'
    AND command.key_digest = p_idempotency_key_digest
    AND command.expires_at <= transaction_timestamp();

  SELECT command.* INTO replay
  FROM public.tenant_authorization_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.actor_membership_id = actor_membership
    AND command.operation = 'tenant_security_group_membership.create'
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
    RAISE EXCEPTION 'security group membership expiry must be in the future'
      USING ERRCODE = '22023';
  END IF;

  PERFORM 1
  FROM public.tenant_security_groups AS security_group
  WHERE security_group.tenant_id = context_tenant
    AND security_group.id = p_group_id
    AND security_group.archived_at IS NULL
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'active tenant security group was not found'
      USING ERRCODE = 'P0002';
  END IF;

  SELECT membership.id INTO target_membership
  FROM public.tenant_memberships AS membership
  JOIN public.users AS identity ON identity.id = membership.user_id
  WHERE membership.tenant_id = context_tenant
    AND membership.user_id = p_target_user_id
    AND membership.status IN ('active', 'invited', 'suspended')
    AND identity.active
  FOR UPDATE OF membership;
  IF target_membership IS NULL THEN
    RAISE EXCEPTION 'tenant user membership was not found'
      USING ERRCODE = 'P0002';
  END IF;

  PERFORM app.assert_actor_can_change_security_group_member(
    p_group_id, p_expires_at
  );

  SELECT source.id INTO STRICT manual_source
  FROM public.tenant_authorization_sources AS source
  WHERE source.tenant_id = context_tenant
    AND source.key = 'manual'
    AND source.kind = 'manual'
    AND source.protected
    AND source.retired_at IS NULL;

  SELECT coalesce(jsonb_agg(jsonb_build_object(
           'group_membership_id', old_membership.id,
           'prior_version', old_membership.version,
           'result_version', old_membership.version + 1
         ) ORDER BY old_membership.id), '[]'::jsonb)
    INTO superseded_memberships
  FROM public.tenant_security_group_memberships AS old_membership
  WHERE old_membership.tenant_id = context_tenant
    AND old_membership.group_id = p_group_id
    AND old_membership.membership_id = target_membership
    AND old_membership.source_id = manual_source
    AND old_membership.revoked_at IS NULL
    AND old_membership.expires_at <= transaction_timestamp()
    AND old_membership.version < 2147483647;

  UPDATE public.tenant_security_group_memberships AS old_membership
  SET revoked_at = transaction_timestamp(),
      revoked_by_membership_id = actor_membership,
      revoke_reason = 'Superseded after the prior group membership expired.',
      version = old_membership.version + 1,
      updated_at = transaction_timestamp()
  WHERE old_membership.tenant_id = context_tenant
    AND old_membership.group_id = p_group_id
    AND old_membership.membership_id = target_membership
    AND old_membership.source_id = manual_source
    AND old_membership.revoked_at IS NULL
    AND old_membership.expires_at <= transaction_timestamp()
    AND old_membership.version < 2147483647;

  IF EXISTS (
    SELECT 1
    FROM public.tenant_security_group_memberships AS existing
    WHERE existing.tenant_id = context_tenant
      AND existing.group_id = p_group_id
      AND existing.membership_id = target_membership
      AND existing.source_id = manual_source
      AND existing.revoked_at IS NULL
  ) THEN
    RAISE EXCEPTION 'an active manual group membership already exists'
      USING ERRCODE = '23505',
            CONSTRAINT = 'tenant_security_group_memberships_active_key';
  END IF;

  INSERT INTO public.tenant_security_group_memberships (
    id, tenant_id, group_id, membership_id, source_id,
    granted_by_membership_id, grant_reason, expires_at
  ) VALUES (
    p_group_membership_id, context_tenant, p_group_id, target_membership,
    manual_source, actor_membership, p_reason, p_expires_at
  );

  PERFORM app.append_tenant_authorization_audit(
    p_audit_event_id, 'tenant.security_group.membership_added',
    'tenant_security_group_membership', p_group_membership_id,
    p_request_id, p_correlation_id,
    p_ip_address, p_user_agent, p_authentication_method, NULL,
    jsonb_build_object(
      'group_id', p_group_id,
      'target_user_id', p_target_user_id,
      'target_membership_id', target_membership,
      'source_id', manual_source,
      'source_kind', 'manual',
      'reason', p_reason,
      'expires_at', p_expires_at,
      'version', 1
    ),
    jsonb_build_object(
      'actor_membership_id', actor_membership,
      'superseded_memberships', superseded_memberships
    )
  );

  INSERT INTO public.tenant_authorization_commands (
    tenant_id, actor_membership_id, operation, key_digest, request_digest,
    result_resource_id, result_version
  ) VALUES (
    context_tenant, actor_membership,
    'tenant_security_group_membership.create',
    p_idempotency_key_digest, canonical_request_digest,
    p_group_membership_id, 1
  );
  RETURN QUERY SELECT p_group_membership_id, 1::integer, false;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."revoke_tenant_security_group_membership"(
  p_group_id uuid,
  p_group_membership_id uuid,
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
  target_membership record;
  target_group_archived_at timestamp with time zone;
  next_version integer;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF NOT app.current_tenant_has_exact_permission(
    'group.membership.manage', 'tenant'
  ) THEN
    RAISE EXCEPTION 'group.membership.manage tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  IF NOT app.current_tenant_has_exact_permission('role.grant', 'tenant') THEN
    RAISE EXCEPTION 'role.grant tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_reason IS NULL OR btrim(p_reason) = ''
     OR char_length(p_reason) > 500 OR p_reason ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION 'security group membership revoke reason is invalid'
      USING ERRCODE = '22023';
  END IF;

  SELECT group_member.* INTO target_membership
  FROM public.tenant_security_group_memberships AS group_member
  JOIN public.tenant_authorization_sources AS source
    ON source.tenant_id = group_member.tenant_id
   AND source.id = group_member.source_id
  WHERE group_member.tenant_id = context_tenant
    AND group_member.group_id = p_group_id
    AND group_member.id = p_group_membership_id
    AND source.kind = 'manual'
    AND source.key = 'manual'
    AND source.protected
    AND source.retired_at IS NULL
  FOR UPDATE OF group_member;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'manual tenant security group membership was not found'
      USING ERRCODE = 'P0002';
  END IF;
  IF target_membership.version IS DISTINCT FROM p_expected_version THEN
    RAISE EXCEPTION 'tenant security group membership version conflict'
      USING ERRCODE = '40001';
  END IF;
  IF target_membership.revoked_at IS NOT NULL THEN
    RAISE EXCEPTION 'tenant security group membership is already revoked'
      USING ERRCODE = '55000';
  END IF;
  IF target_membership.version >= 2147483647 THEN
    RAISE EXCEPTION 'tenant security group membership version is exhausted'
      USING ERRCODE = '55000';
  END IF;

  SELECT security_group.archived_at INTO target_group_archived_at
  FROM public.tenant_security_groups AS security_group
  WHERE security_group.tenant_id = context_tenant
    AND security_group.id = target_membership.group_id
  FOR UPDATE;

  IF target_group_archived_at IS NULL
     AND (target_membership.expires_at IS NULL
       OR target_membership.expires_at > transaction_timestamp()) THEN
    PERFORM app.assert_actor_can_change_security_group_member(
      target_membership.group_id, target_membership.expires_at
    );
  END IF;

  next_version := target_membership.version + 1;
  UPDATE public.tenant_security_group_memberships AS group_member
  SET revoked_at = transaction_timestamp(),
      revoked_by_membership_id = actor_membership,
      revoke_reason = p_reason,
      version = next_version,
      updated_at = transaction_timestamp()
  WHERE group_member.tenant_id = context_tenant
    AND group_member.id = p_group_membership_id;

  PERFORM app.append_tenant_authorization_audit(
    p_audit_event_id, 'tenant.security_group.membership_revoked',
    'tenant_security_group_membership', p_group_membership_id,
    p_request_id, p_correlation_id,
    p_ip_address, p_user_agent, p_authentication_method,
    jsonb_build_object(
      'revoked_at', NULL, 'version', target_membership.version
    ),
    jsonb_build_object(
      'revoked_at', transaction_timestamp(),
      'reason', p_reason, 'version', next_version
    ),
    jsonb_build_object(
      'group_id', p_group_id,
      'target_membership_id', target_membership.membership_id,
      'actor_membership_id', actor_membership
    )
  );
  RETURN next_version;
END;
$function$;

CREATE FUNCTION "app"."list_tenant_security_group_role_grants"(
  p_group_id uuid,
  p_after_group_role_grant_id uuid,
  p_include_revoked boolean,
  p_limit integer
)
RETURNS TABLE (
  group_role_grant_id uuid,
  group_id uuid,
  group_key text,
  group_name text,
  group_description text,
  group_archived_at timestamp with time zone,
  group_version integer,
  group_created_at timestamp with time zone,
  group_updated_at timestamp with time zone,
  role_id uuid,
  role_key text,
  role_name text,
  role_description text,
  role_system boolean,
  role_protected boolean,
  role_archived_at timestamp with time zone,
  role_version integer,
  role_created_at timestamp with time zone,
  role_updated_at timestamp with time zone,
  source_id uuid,
  source_kind "public"."authorization_source_kind",
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
    app.current_tenant_has_exact_permission('group.read', 'tenant')
    AND app.current_tenant_has_exact_permission('role.read', 'tenant')
  ) THEN
    RAISE EXCEPTION 'group.read and role.read tenant scope are required'
      USING ERRCODE = '42501';
  END IF;
  IF p_include_revoked IS NULL THEN
    RAISE EXCEPTION 'include revoked must be explicit'
      USING ERRCODE = '22023';
  END IF;
  IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 101 THEN
    RAISE EXCEPTION 'security group role grant page limit must be between 1 and 101'
      USING ERRCODE = '22023';
  END IF;
  IF NOT EXISTS (
    SELECT 1
    FROM public.tenant_security_groups AS security_group
    WHERE security_group.tenant_id = context_tenant
      AND security_group.id = p_group_id
  ) THEN
    RAISE EXCEPTION 'tenant security group was not found'
      USING ERRCODE = 'P0002';
  END IF;

  RETURN QUERY
  SELECT group_grant.id, security_group.id, security_group.key,
         security_group.display_name, security_group.description,
         security_group.archived_at, security_group.version,
         security_group.created_at, security_group.updated_at,
         role.id, role.key, role.display_name,
         role.description, role.system_role, role.protected_role,
         role.archived_at, role.version, role.created_at, role.updated_at,
         source.id, source.kind, source.authoritative, source.retired_at,
         group_grant.granted_by_membership_id, grantor.user_id,
         group_grant.grant_reason, group_grant.granted_at,
         group_grant.expires_at, group_grant.revoked_at,
         group_grant.revoked_by_membership_id, revoker.user_id,
         group_grant.revoke_reason,
         CASE
           WHEN group_grant.revoked_at IS NOT NULL THEN 'revoked'
           WHEN group_grant.expires_at IS NOT NULL
             AND group_grant.expires_at <= transaction_timestamp()
             THEN 'expired'
           ELSE 'active'
         END,
         group_grant.version, group_grant.updated_at
  FROM public.tenant_security_group_role_grants AS group_grant
  JOIN public.tenant_security_groups AS security_group
    ON security_group.tenant_id = group_grant.tenant_id
   AND security_group.id = group_grant.group_id
  JOIN public.tenant_roles AS role
    ON role.tenant_id = group_grant.tenant_id
   AND role.id = group_grant.role_id
  JOIN public.tenant_authorization_sources AS source
    ON source.tenant_id = group_grant.tenant_id
   AND source.id = group_grant.source_id
  LEFT JOIN public.tenant_memberships AS grantor
    ON grantor.tenant_id = group_grant.tenant_id
   AND grantor.id = group_grant.granted_by_membership_id
  LEFT JOIN public.tenant_memberships AS revoker
    ON revoker.tenant_id = group_grant.tenant_id
   AND revoker.id = group_grant.revoked_by_membership_id
  WHERE group_grant.tenant_id = context_tenant
    AND group_grant.group_id = p_group_id
    AND (p_include_revoked OR group_grant.revoked_at IS NULL)
    AND (p_after_group_role_grant_id IS NULL
      OR group_grant.id > p_after_group_role_grant_id)
  ORDER BY group_grant.id
  LIMIT p_limit;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."get_tenant_security_group_role_grant"(
  p_group_id uuid,
  p_group_role_grant_id uuid
)
RETURNS TABLE (
  group_role_grant_id uuid,
  group_id uuid,
  group_key text,
  group_name text,
  group_description text,
  group_archived_at timestamp with time zone,
  group_version integer,
  group_created_at timestamp with time zone,
  group_updated_at timestamp with time zone,
  role_id uuid,
  role_key text,
  role_name text,
  role_description text,
  role_system boolean,
  role_protected boolean,
  role_archived_at timestamp with time zone,
  role_version integer,
  role_created_at timestamp with time zone,
  role_updated_at timestamp with time zone,
  source_id uuid,
  source_kind "public"."authorization_source_kind",
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
    (
      app.current_tenant_has_exact_permission('group.read', 'tenant')
      AND app.current_tenant_has_exact_permission('role.read', 'tenant')
    ) OR (
      app.current_tenant_has_exact_permission('group.manage', 'tenant')
      AND app.current_tenant_has_exact_permission('role.grant', 'tenant')
    )
  ) THEN
    RAISE EXCEPTION 'group role grant read or management authority is required'
      USING ERRCODE = '42501';
  END IF;

  RETURN QUERY
  SELECT group_grant.id, security_group.id, security_group.key,
         security_group.display_name, security_group.description,
         security_group.archived_at, security_group.version,
         security_group.created_at, security_group.updated_at,
         role.id, role.key, role.display_name,
         role.description, role.system_role, role.protected_role,
         role.archived_at, role.version, role.created_at, role.updated_at,
         source.id, source.kind, source.authoritative, source.retired_at,
         group_grant.granted_by_membership_id, grantor.user_id,
         group_grant.grant_reason, group_grant.granted_at,
         group_grant.expires_at, group_grant.revoked_at,
         group_grant.revoked_by_membership_id, revoker.user_id,
         group_grant.revoke_reason,
         CASE
           WHEN group_grant.revoked_at IS NOT NULL THEN 'revoked'
           WHEN group_grant.expires_at IS NOT NULL
             AND group_grant.expires_at <= transaction_timestamp()
             THEN 'expired'
           ELSE 'active'
         END,
         group_grant.version, group_grant.updated_at
  FROM public.tenant_security_group_role_grants AS group_grant
  JOIN public.tenant_security_groups AS security_group
    ON security_group.tenant_id = group_grant.tenant_id
   AND security_group.id = group_grant.group_id
  JOIN public.tenant_roles AS role
    ON role.tenant_id = group_grant.tenant_id
   AND role.id = group_grant.role_id
  JOIN public.tenant_authorization_sources AS source
    ON source.tenant_id = group_grant.tenant_id
   AND source.id = group_grant.source_id
  LEFT JOIN public.tenant_memberships AS grantor
    ON grantor.tenant_id = group_grant.tenant_id
   AND grantor.id = group_grant.granted_by_membership_id
  LEFT JOIN public.tenant_memberships AS revoker
    ON revoker.tenant_id = group_grant.tenant_id
   AND revoker.id = group_grant.revoked_by_membership_id
  WHERE group_grant.tenant_id = context_tenant
    AND group_grant.group_id = p_group_id
    AND group_grant.id = p_group_role_grant_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant security group role grant was not found'
      USING ERRCODE = 'P0002';
  END IF;
END;
$function$;--> statement-breakpoint

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
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid;
  manual_source uuid;
  canonical_request_digest bytea;
  replay record;
  superseded_role_grants jsonb := '[]'::jsonb;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF NOT app.current_tenant_has_exact_permission('group.manage', 'tenant') THEN
    RAISE EXCEPTION 'group.manage tenant scope is required'
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
    RAISE EXCEPTION 'security group role grant reason is invalid'
      USING ERRCODE = '22023';
  END IF;

  SELECT sha256(convert_to(jsonb_build_object(
    'group_id', p_group_id,
    'role_id', p_role_id,
    'reason', p_reason,
    'expires_at', p_expires_at
  )::text, 'UTF8')) INTO canonical_request_digest;

  DELETE FROM public.tenant_authorization_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.actor_membership_id = actor_membership
    AND command.operation = 'tenant_security_group_role_grant.create'
    AND command.key_digest = p_idempotency_key_digest
    AND command.expires_at <= transaction_timestamp();

  SELECT command.* INTO replay
  FROM public.tenant_authorization_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.actor_membership_id = actor_membership
    AND command.operation = 'tenant_security_group_role_grant.create'
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

  PERFORM 1
  FROM public.tenant_security_groups AS security_group
  WHERE security_group.tenant_id = context_tenant
    AND security_group.id = p_group_id
    AND security_group.archived_at IS NULL
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'active tenant security group was not found'
      USING ERRCODE = 'P0002';
  END IF;

  PERFORM app.assert_actor_can_grant_role(p_role_id, p_expires_at);

  SELECT source.id INTO STRICT manual_source
  FROM public.tenant_authorization_sources AS source
  WHERE source.tenant_id = context_tenant
    AND source.key = 'manual'
    AND source.kind = 'manual'
    AND source.protected
    AND source.retired_at IS NULL;

  SELECT coalesce(jsonb_agg(jsonb_build_object(
           'group_role_grant_id', old_grant.id,
           'prior_version', old_grant.version,
           'result_version', old_grant.version + 1
         ) ORDER BY old_grant.id), '[]'::jsonb)
    INTO superseded_role_grants
  FROM public.tenant_security_group_role_grants AS old_grant
  WHERE old_grant.tenant_id = context_tenant
    AND old_grant.group_id = p_group_id
    AND old_grant.role_id = p_role_id
    AND old_grant.source_id = manual_source
    AND old_grant.revoked_at IS NULL
    AND old_grant.expires_at <= transaction_timestamp()
    AND old_grant.version < 2147483647;

  UPDATE public.tenant_security_group_role_grants AS old_grant
  SET revoked_at = transaction_timestamp(),
      revoked_by_membership_id = actor_membership,
      revoke_reason = 'Superseded after the prior group role grant expired.',
      version = old_grant.version + 1,
      updated_at = transaction_timestamp()
  WHERE old_grant.tenant_id = context_tenant
    AND old_grant.group_id = p_group_id
    AND old_grant.role_id = p_role_id
    AND old_grant.source_id = manual_source
    AND old_grant.revoked_at IS NULL
    AND old_grant.expires_at <= transaction_timestamp()
    AND old_grant.version < 2147483647;

  IF EXISTS (
    SELECT 1
    FROM public.tenant_security_group_role_grants AS existing
    WHERE existing.tenant_id = context_tenant
      AND existing.group_id = p_group_id
      AND existing.role_id = p_role_id
      AND existing.source_id = manual_source
      AND existing.revoked_at IS NULL
  ) THEN
    RAISE EXCEPTION 'an active manual group role grant already exists'
      USING ERRCODE = '23505',
            CONSTRAINT = 'tenant_security_group_role_grants_active_key';
  END IF;

  INSERT INTO public.tenant_security_group_role_grants (
    id, tenant_id, group_id, role_id, source_id,
    granted_by_membership_id, grant_reason, expires_at
  ) VALUES (
    p_group_role_grant_id, context_tenant, p_group_id, p_role_id,
    manual_source, actor_membership, p_reason, p_expires_at
  );

  PERFORM app.append_tenant_authorization_audit(
    p_audit_event_id, 'tenant.security_group.role_grant_created',
    'tenant_security_group_role_grant', p_group_role_grant_id,
    p_request_id, p_correlation_id,
    p_ip_address, p_user_agent, p_authentication_method, NULL,
    jsonb_build_object(
      'group_id', p_group_id,
      'role_id', p_role_id,
      'source_id', manual_source,
      'source_kind', 'manual',
      'reason', p_reason,
      'expires_at', p_expires_at,
      'version', 1
    ),
    jsonb_build_object(
      'actor_membership_id', actor_membership,
      'superseded_role_grants', superseded_role_grants
    )
  );

  INSERT INTO public.tenant_authorization_commands (
    tenant_id, actor_membership_id, operation, key_digest, request_digest,
    result_resource_id, result_version
  ) VALUES (
    context_tenant, actor_membership,
    'tenant_security_group_role_grant.create',
    p_idempotency_key_digest, canonical_request_digest,
    p_group_role_grant_id, 1
  );
  RETURN QUERY SELECT p_group_role_grant_id, 1::integer, false;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."revoke_tenant_security_group_role_grant"(
  p_group_id uuid,
  p_group_role_grant_id uuid,
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
  IF NOT app.current_tenant_has_exact_permission('group.manage', 'tenant') THEN
    RAISE EXCEPTION 'group.manage tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  IF NOT app.current_tenant_has_exact_permission('role.grant', 'tenant') THEN
    RAISE EXCEPTION 'role.grant tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_reason IS NULL OR btrim(p_reason) = ''
     OR char_length(p_reason) > 500 OR p_reason ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION 'security group role revoke reason is invalid'
      USING ERRCODE = '22023';
  END IF;

  SELECT group_grant.*,
         security_group.archived_at AS group_archived_at,
         role.archived_at AS role_archived_at
    INTO target_grant
  FROM public.tenant_security_group_role_grants AS group_grant
  JOIN public.tenant_authorization_sources AS source
    ON source.tenant_id = group_grant.tenant_id
   AND source.id = group_grant.source_id
  JOIN public.tenant_security_groups AS security_group
    ON security_group.tenant_id = group_grant.tenant_id
   AND security_group.id = group_grant.group_id
  JOIN public.tenant_roles AS role
    ON role.tenant_id = group_grant.tenant_id
   AND role.id = group_grant.role_id
  WHERE group_grant.tenant_id = context_tenant
    AND group_grant.group_id = p_group_id
    AND group_grant.id = p_group_role_grant_id
    AND source.kind = 'manual'
    AND source.key = 'manual'
    AND source.protected
    AND source.retired_at IS NULL
  FOR UPDATE OF group_grant;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'manual tenant security group role grant was not found'
      USING ERRCODE = 'P0002';
  END IF;
  IF target_grant.version IS DISTINCT FROM p_expected_version THEN
    RAISE EXCEPTION 'tenant security group role grant version conflict'
      USING ERRCODE = '40001';
  END IF;
  IF target_grant.revoked_at IS NOT NULL THEN
    RAISE EXCEPTION 'tenant security group role grant is already revoked'
      USING ERRCODE = '55000';
  END IF;
  IF target_grant.version >= 2147483647 THEN
    RAISE EXCEPTION 'tenant security group role grant version is exhausted'
      USING ERRCODE = '55000';
  END IF;

  IF target_grant.group_archived_at IS NULL
     AND target_grant.role_archived_at IS NULL
     AND (
       target_grant.expires_at IS NULL
       OR target_grant.expires_at > transaction_timestamp()
     ) THEN
    PERFORM app.assert_actor_can_grant_role(
      target_grant.role_id, target_grant.expires_at
    );
  END IF;

  next_version := target_grant.version + 1;
  UPDATE public.tenant_security_group_role_grants AS group_grant
  SET revoked_at = transaction_timestamp(),
      revoked_by_membership_id = actor_membership,
      revoke_reason = p_reason,
      version = next_version,
      updated_at = transaction_timestamp()
  WHERE group_grant.tenant_id = context_tenant
    AND group_grant.id = p_group_role_grant_id;

  PERFORM app.append_tenant_authorization_audit(
    p_audit_event_id, 'tenant.security_group.role_grant_revoked',
    'tenant_security_group_role_grant', p_group_role_grant_id,
    p_request_id, p_correlation_id,
    p_ip_address, p_user_agent, p_authentication_method,
    jsonb_build_object('revoked_at', NULL, 'version', target_grant.version),
    jsonb_build_object(
      'revoked_at', transaction_timestamp(),
      'reason', p_reason, 'version', next_version
    ),
    jsonb_build_object(
      'group_id', p_group_id,
      'role_id', target_grant.role_id,
      'actor_membership_id', actor_membership
    )
  );
  RETURN next_version;
END;
$function$;

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

    SELECT group_grant.expires_at
    FROM public.tenant_security_group_role_grants AS group_grant
    JOIN public.tenant_authorization_sources AS source
      ON source.tenant_id = group_grant.tenant_id
     AND source.id = group_grant.source_id
    JOIN public.tenant_security_groups AS security_group
      ON security_group.tenant_id = group_grant.tenant_id
     AND security_group.id = group_grant.group_id
    WHERE group_grant.tenant_id = context_tenant
      AND group_grant.role_id = p_role_id
      AND group_grant.revoked_at IS NULL
      AND (group_grant.expires_at IS NULL
        OR group_grant.expires_at > transaction_timestamp())
      AND source.retired_at IS NULL
      AND security_group.archived_at IS NULL
  )
  SELECT count(*) > 0,
         coalesce(bool_or(live_grants.expires_at IS NULL), false),
         max(live_grants.expires_at)
    INTO has_live_grants, has_unbounded_grants, maximum_grant_expiry
  FROM live_grants;

  required_expiry := CASE
    WHEN has_live_grants AND has_unbounded_grants THEN NULL
    WHEN has_live_grants THEN maximum_grant_expiry
    ELSE transaction_timestamp()
  END;

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
$function$;--> statement-breakpoint

CREATE OR REPLACE FUNCTION "app"."archive_tenant_role"(
  p_role_id uuid,
  p_expected_version integer,
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
  requested record;
  has_live_grants boolean;
  has_unbounded_grants boolean;
  maximum_grant_expiry timestamp with time zone;
  required_expiry timestamp with time zone;
  next_version integer;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
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
    RAISE EXCEPTION 'built-in or protected roles cannot be archived'
      USING ERRCODE = '55000';
  END IF;
  IF target_role.archived_at IS NOT NULL THEN
    RAISE EXCEPTION 'tenant role is already archived' USING ERRCODE = '55000';
  END IF;
  IF target_role.version >= 2147483647 THEN
    RAISE EXCEPTION 'tenant role version is exhausted' USING ERRCODE = '55000';
  END IF;

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

    SELECT group_grant.expires_at
    FROM public.tenant_security_group_role_grants AS group_grant
    JOIN public.tenant_authorization_sources AS source
      ON source.tenant_id = group_grant.tenant_id
     AND source.id = group_grant.source_id
    JOIN public.tenant_security_groups AS security_group
      ON security_group.tenant_id = group_grant.tenant_id
     AND security_group.id = group_grant.group_id
    WHERE group_grant.tenant_id = context_tenant
      AND group_grant.role_id = p_role_id
      AND group_grant.revoked_at IS NULL
      AND (group_grant.expires_at IS NULL
        OR group_grant.expires_at > transaction_timestamp())
      AND source.retired_at IS NULL
      AND security_group.archived_at IS NULL
  )
  SELECT count(*) > 0,
         coalesce(bool_or(live_grants.expires_at IS NULL), false),
         max(live_grants.expires_at)
    INTO has_live_grants, has_unbounded_grants, maximum_grant_expiry
  FROM live_grants;

  required_expiry := CASE
    WHEN has_live_grants AND has_unbounded_grants THEN NULL
    WHEN has_live_grants THEN maximum_grant_expiry
    ELSE transaction_timestamp()
  END;

  FOR requested IN
    SELECT permission.key AS permission_key, policy.scope
    FROM public.tenant_role_permissions AS policy
    JOIN public.tenant_permissions AS permission
      ON permission.id = policy.permission_id
    WHERE policy.tenant_id = context_tenant
      AND policy.role_id = p_role_id
  LOOP
    IF NOT app.tenant_user_can_delegate_exact_permission(
      context_tenant, app.context_user_id(), requested.permission_key,
      requested.scope, required_expiry
    ) THEN
      RAISE EXCEPTION 'role archival exceeds the exact delegation ceiling or active grant lifetime'
        USING ERRCODE = '42501';
    END IF;
  END LOOP;

  next_version := target_role.version + 1;
  UPDATE public.tenant_roles AS role
  SET archived_at = transaction_timestamp(),
      version = next_version,
      updated_at = transaction_timestamp()
  WHERE role.tenant_id = context_tenant
    AND role.id = p_role_id;

  PERFORM app.append_tenant_authorization_audit(
    p_audit_event_id, 'tenant.role.archived', 'tenant_role', p_role_id,
    p_request_id, p_correlation_id,
    p_ip_address, p_user_agent, p_authentication_method,
    jsonb_build_object('archived_at', NULL, 'version', target_role.version),
    jsonb_build_object(
      'archived_at', transaction_timestamp(), 'version', next_version
    ),
    '{}'::jsonb
  );
  RETURN next_version;
END;
$function$;

CREATE OR REPLACE FUNCTION "app"."set_tenant_user_membership_status"(
  p_target_user_id uuid,
  p_status "public"."membership_status",
  p_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS uuid
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid;
  target_membership record;
  role_grant record;
  checked_count integer := 0;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF NOT app.current_tenant_has_exact_permission('membership.manage', 'tenant') THEN
    RAISE EXCEPTION 'membership.manage tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_status NOT IN ('active', 'suspended') THEN
    RAISE EXCEPTION 'tenant user status must be active or suspended'
      USING ERRCODE = '22023';
  END IF;

  SELECT membership.* INTO target_membership
  FROM public.tenant_memberships AS membership
  WHERE membership.tenant_id = context_tenant
    AND membership.user_id = p_target_user_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant user membership was not found'
      USING ERRCODE = 'P0002';
  END IF;
  IF target_membership.status = p_status THEN
    RETURN target_membership.id;
  END IF;

  -- Status changes activate or remove every direct and group-derived path.
  -- Exact consequence checks use the common horizon of both group edges.
  FOR role_grant IN
    SELECT path.role_id, path.effective_expires_at
    FROM (
      SELECT direct_grant.role_id,
             direct_grant.expires_at AS effective_expires_at,
             direct_grant.id AS ordering_id
      FROM public.tenant_membership_role_grants AS direct_grant
      JOIN public.tenant_authorization_sources AS source
        ON source.tenant_id = direct_grant.tenant_id
       AND source.id = direct_grant.source_id
      JOIN public.tenant_roles AS role
        ON role.tenant_id = direct_grant.tenant_id
       AND role.id = direct_grant.role_id
      WHERE direct_grant.tenant_id = context_tenant
        AND direct_grant.membership_id = target_membership.id
        AND direct_grant.revoked_at IS NULL
        AND (direct_grant.expires_at IS NULL
          OR direct_grant.expires_at > transaction_timestamp())
        AND source.retired_at IS NULL
        AND role.archived_at IS NULL

      UNION ALL

      SELECT group_grant.role_id,
             app.earliest_authorization_expiry(
               group_member.expires_at, group_grant.expires_at
             ),
             group_member.id
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
      WHERE group_member.tenant_id = context_tenant
        AND group_member.membership_id = target_membership.id
        AND group_member.revoked_at IS NULL
        AND (group_member.expires_at IS NULL
          OR group_member.expires_at > transaction_timestamp())
        AND member_source.retired_at IS NULL
        AND security_group.archived_at IS NULL
        AND group_grant.revoked_at IS NULL
        AND (group_grant.expires_at IS NULL
          OR group_grant.expires_at > transaction_timestamp())
        AND grant_source.retired_at IS NULL
        AND role.archived_at IS NULL
    ) AS path
    ORDER BY path.ordering_id, path.role_id
    LIMIT 501
  LOOP
    checked_count := checked_count + 1;
    IF checked_count > 500 THEN
      RAISE EXCEPTION 'membership authority consequence limit exceeded'
        USING ERRCODE = '54000';
    END IF;
    PERFORM app.assert_actor_can_grant_role(
      role_grant.role_id, role_grant.effective_expires_at
    );
  END LOOP;

  PERFORM app.append_tenant_authorization_audit(
    p_audit_event_id, 'tenant.membership.status_changed',
    'tenant_membership', target_membership.id,
    p_request_id, p_correlation_id,
    p_ip_address, p_user_agent, p_authentication_method,
    jsonb_build_object('status', target_membership.status),
    jsonb_build_object('status', p_status),
    jsonb_build_object(
      'target_user_id', p_target_user_id,
      'actor_membership_id', actor_membership,
      'authority_paths_checked', checked_count
    )
  );

  UPDATE public.tenant_memberships AS membership
  SET status = p_status,
      updated_at = transaction_timestamp()
  WHERE membership.tenant_id = context_tenant
    AND membership.id = target_membership.id;

  RETURN target_membership.id;
END;
$function$;--> statement-breakpoint

CREATE OR REPLACE FUNCTION "app"."create_platform_tenant"(
  p_tenant_id uuid,
  p_membership_id uuid,
  p_slug text,
  p_name text,
  p_timezone text,
  p_locale text,
  p_platform_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE (
  id uuid,
  slug text,
  name text,
  status "public"."tenant_status",
  timezone text,
  locale text,
  version integer,
  created_at timestamp with time zone,
  updated_at timestamp with time zone
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor_id uuid;
  tenant_audit_event_id uuid := uuidv7();
  tenant_admin_permission_count integer;
BEGIN
  actor_id := app.context_user_id();
  IF NOT app.platform_user_has_permission(actor_id, 'platform.tenant.create') THEN
    RAISE EXCEPTION 'platform.tenant.create permission is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_slug IS DISTINCT FROM lower(btrim(p_slug))
     OR p_slug !~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'
     OR p_name IS NULL OR btrim(p_name) = ''
     OR char_length(p_name) > 160 OR p_name ~ '[[:cntrl:]]'
     OR p_timezone IS NULL OR char_length(p_timezone) NOT BETWEEN 1 AND 64
     OR p_timezone ~ '[[:cntrl:]]'
     OR lower(p_timezone) IN ('local', 'localtime')
     OR NOT EXISTS (
       SELECT 1
       FROM pg_catalog.pg_timezone_names AS timezone
       WHERE timezone.name = p_timezone
     )
     OR p_locale IS NULL OR char_length(p_locale) > 35
     OR p_locale !~ '^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$'
     OR lower(split_part(p_locale, '-', 1)) = 'und' THEN
    RAISE EXCEPTION 'tenant attributes violate the canonical contract'
      USING ERRCODE = '22023';
  END IF;
  IF p_authentication_method NOT IN (
    'bootstrap_totp', 'totp', 'recovery_code'
  ) THEN
    RAISE EXCEPTION 'tenant creation requires a live session authentication method'
      USING ERRCODE = '22023';
  END IF;

  INSERT INTO public.tenants (id, slug, name, timezone, locale)
  VALUES (p_tenant_id, p_slug, p_name, p_timezone, p_locale);

  INSERT INTO public.audit_chain_heads (tenant_id)
  VALUES (p_tenant_id);

  INSERT INTO public.tenant_memberships (id, tenant_id, user_id, role, status)
  VALUES (p_membership_id, p_tenant_id, actor_id, 'tenant_admin', 'active');

  PERFORM app.seed_tenant_authorization(p_tenant_id, p_membership_id);

  SELECT count(*) INTO tenant_admin_permission_count
  FROM public.tenant_role_permissions AS policy
  JOIN public.tenant_roles AS role
    ON role.tenant_id = policy.tenant_id
   AND role.id = policy.role_id
  WHERE role.tenant_id = p_tenant_id
    AND role.key = 'tenant_admin'
    AND role.system_role
    AND role.protected_role;

  IF tenant_admin_permission_count < 9 THEN
    RAISE EXCEPTION 'tenant administrator policy is incomplete after seeding'
      USING ERRCODE = '55000';
  END IF;

  INSERT INTO public.audit_events (
    id, tenant_id, sequence, actor_type, actor_user_id, action,
    resource_type, resource_id, request_id, correlation_id,
    ip_address, user_agent, authentication_method, outcome,
    after, metadata
  ) VALUES (
    tenant_audit_event_id, p_tenant_id, 0, 'user', actor_id,
    'tenant.authorization.initialized', 'tenant', p_tenant_id,
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method, 'success',
    jsonb_build_object(
      'creator_membership_id', p_membership_id,
      'built_in_roles', 8,
      'tenant_admin_permissions', tenant_admin_permission_count
    ),
    jsonb_build_object('source', 'platform_tenant_creation')
  );

  PERFORM app.append_platform_audit_event(
    p_platform_audit_event_id, 'user', actor_id, 'platform.tenant.created',
    'tenant', p_tenant_id, p_request_id, p_correlation_id,
    p_ip_address, p_user_agent, p_authentication_method, 'success', NULL,
    jsonb_build_object(
      'slug', p_slug,
      'creator_membership_id', p_membership_id,
      'tenant_authorization_initialized', true,
      'tenant_audit_event_id', tenant_audit_event_id
    )
  );

  RETURN QUERY
  SELECT tenant.id, tenant.slug, tenant.name, tenant.status, tenant.timezone,
         tenant.locale, tenant.version, tenant.created_at, tenant.updated_at
  FROM public.tenants AS tenant
  WHERE tenant.id = p_tenant_id;
END;
$function$;

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
  ELSE
    RAISE EXCEPTION 'unsupported tenant authorization command operation'
      USING ERRCODE = '22023';
  END IF;

  RETURN NEW;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION "app"."earliest_authorization_expiry"(timestamp with time zone, timestamp with time zone) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."assert_actor_can_change_security_group_member"(uuid, timestamp with time zone) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."assert_actor_can_change_security_group_roles"(uuid) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."resolve_current_tenant_human_role_grant_paths"(integer) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."list_tenant_security_groups"(uuid, boolean, integer) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."get_tenant_security_group"(uuid) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."create_tenant_security_group"(uuid, bytea, text, text, text, uuid, uuid, uuid, inet, text, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."update_tenant_security_group_metadata"(uuid, integer, text, text, uuid, uuid, uuid, inet, text, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."archive_tenant_security_group"(uuid, integer, uuid, uuid, uuid, inet, text, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."list_tenant_security_group_memberships"(uuid, uuid, boolean, integer) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."get_tenant_security_group_membership"(uuid, uuid) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."add_tenant_security_group_member"(uuid, bytea, uuid, uuid, text, timestamp with time zone, uuid, uuid, uuid, inet, text, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."revoke_tenant_security_group_membership"(uuid, uuid, integer, text, uuid, uuid, uuid, inet, text, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."list_tenant_security_group_role_grants"(uuid, uuid, boolean, integer) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."get_tenant_security_group_role_grant"(uuid, uuid) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."grant_tenant_security_group_role"(uuid, bytea, uuid, uuid, text, timestamp with time zone, uuid, uuid, uuid, inet, text, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."revoke_tenant_security_group_role_grant"(uuid, uuid, integer, text, uuid, uuid, uuid, inet, text, text) OWNER TO "periapsis_migrator";--> statement-breakpoint

REVOKE ALL ON FUNCTION "app"."earliest_authorization_expiry"(timestamp with time zone, timestamp with time zone) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."assert_actor_can_change_security_group_member"(uuid, timestamp with time zone) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."assert_actor_can_change_security_group_roles"(uuid) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."resolve_current_tenant_human_role_grant_paths"(integer) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."list_tenant_security_groups"(uuid, boolean, integer) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."get_tenant_security_group"(uuid) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."create_tenant_security_group"(uuid, bytea, text, text, text, uuid, uuid, uuid, inet, text, text) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."update_tenant_security_group_metadata"(uuid, integer, text, text, uuid, uuid, uuid, inet, text, text) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."archive_tenant_security_group"(uuid, integer, uuid, uuid, uuid, inet, text, text) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."list_tenant_security_group_memberships"(uuid, uuid, boolean, integer) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."get_tenant_security_group_membership"(uuid, uuid) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."add_tenant_security_group_member"(uuid, bytea, uuid, uuid, text, timestamp with time zone, uuid, uuid, uuid, inet, text, text) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."revoke_tenant_security_group_membership"(uuid, uuid, integer, text, uuid, uuid, uuid, inet, text, text) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."list_tenant_security_group_role_grants"(uuid, uuid, boolean, integer) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."get_tenant_security_group_role_grant"(uuid, uuid) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."grant_tenant_security_group_role"(uuid, bytea, uuid, uuid, text, timestamp with time zone, uuid, uuid, uuid, inet, text, text) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."revoke_tenant_security_group_role_grant"(uuid, uuid, integer, text, uuid, uuid, uuid, inet, text, text) FROM PUBLIC;--> statement-breakpoint

-- Retire the Phase 2B.1 direct-only projection. The role-path resolver is the
-- sole runtime source of effective grant provenance from this migration on.
REVOKE ALL ON FUNCTION "app"."resolve_current_tenant_human_role_grants"(integer) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
DROP FUNCTION "app"."resolve_current_tenant_human_role_grants"(integer);--> statement-breakpoint

GRANT EXECUTE ON FUNCTION "app"."resolve_current_tenant_human_role_grant_paths"(integer) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."list_tenant_security_groups"(uuid, boolean, integer) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."get_tenant_security_group"(uuid) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."create_tenant_security_group"(uuid, bytea, text, text, text, uuid, uuid, uuid, inet, text, text) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."update_tenant_security_group_metadata"(uuid, integer, text, text, uuid, uuid, uuid, inet, text, text) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."archive_tenant_security_group"(uuid, integer, uuid, uuid, uuid, inet, text, text) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."list_tenant_security_group_memberships"(uuid, uuid, boolean, integer) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."get_tenant_security_group_membership"(uuid, uuid) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."add_tenant_security_group_member"(uuid, bytea, uuid, uuid, text, timestamp with time zone, uuid, uuid, uuid, inet, text, text) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."revoke_tenant_security_group_membership"(uuid, uuid, integer, text, uuid, uuid, uuid, inet, text, text) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."list_tenant_security_group_role_grants"(uuid, uuid, boolean, integer) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."get_tenant_security_group_role_grant"(uuid, uuid) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."grant_tenant_security_group_role"(uuid, bytea, uuid, uuid, text, timestamp with time zone, uuid, uuid, uuid, inet, text, text) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."revoke_tenant_security_group_role_grant"(uuid, uuid, integer, text, uuid, uuid, uuid, inet, text, text) TO "periapsis_api";
