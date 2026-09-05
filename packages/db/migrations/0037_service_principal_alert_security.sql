-- Service-principal and Alert command security boundary. The generated 0036
-- migration owns structure; this migration owns catalog activation, forced
-- RLS, least-privilege entry points, permanent replay tombstones, and atomic
-- Alert side effects.

ALTER TABLE "public"."tenant_service_accounts" OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER TABLE "public"."tenant_service_account_role_grants" OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER TABLE "public"."tenant_api_credentials" OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER TABLE "public"."tenant_api_credential_permissions" OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER TABLE "public"."tenant_api_credential_networks" OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER TABLE "public"."tenant_api_credential_commands" OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER TABLE "public"."alert_activities" OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER TABLE "public"."alert_commands" OWNER TO "periapsis_migrator";--> statement-breakpoint

ALTER TABLE "public"."tenant_service_accounts" FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "public"."tenant_service_account_role_grants" FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "public"."tenant_api_credentials" FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "public"."tenant_api_credential_permissions" FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "public"."tenant_api_credential_networks" FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "public"."tenant_api_credential_commands" FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "public"."alert_activities" FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "public"."alert_commands" FORCE ROW LEVEL SECURITY;--> statement-breakpoint

REVOKE ALL ON TABLE "public"."tenant_service_accounts" FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON TABLE "public"."tenant_service_account_role_grants" FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON TABLE "public"."tenant_api_credentials" FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON TABLE "public"."tenant_api_credential_permissions" FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON TABLE "public"."tenant_api_credential_networks" FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON TABLE "public"."tenant_api_credential_commands" FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON TABLE "public"."alert_activities" FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON TABLE "public"."alert_commands" FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint

-- Table-level revocation is supplemented with the historical column grants:
-- PostgreSQL retains a column privilege when only its table counterpart is
-- revoked.
REVOKE INSERT, UPDATE, DELETE ON TABLE "public"."alerts" FROM "periapsis_api";--> statement-breakpoint
REVOKE INSERT ("id", "tenant_id", "external_id", "title", "description", "status", "severity", "created_by", "created_at", "updated_at", "version") ON TABLE "public"."alerts" FROM "periapsis_api";--> statement-breakpoint
REVOKE UPDATE ("title", "description", "status", "severity", "updated_at", "version") ON TABLE "public"."alerts" FROM "periapsis_api";--> statement-breakpoint
REVOKE INSERT, UPDATE, DELETE ON TABLE "public"."audit_events" FROM "periapsis_api";--> statement-breakpoint
REVOKE INSERT ("id", "tenant_id", "occurred_at", "actor_type", "actor_user_id", "impersonated_by_user_id", "action", "resource_type", "resource_id", "request_id", "correlation_id", "ip_address", "user_agent", "authentication_method", "outcome", "reason", "before", "after", "metadata") ON TABLE "public"."audit_events" FROM "periapsis_api";--> statement-breakpoint
REVOKE INSERT, UPDATE, DELETE ON TABLE "public"."outbox_events" FROM "periapsis_api";--> statement-breakpoint
REVOKE INSERT ("id", "tenant_id", "aggregate_type", "aggregate_id", "event_type", "schema_version", "payload", "deduplication_key", "correlation_id", "causation_id", "occurred_at", "available_at", "max_attempts", "created_at") ON TABLE "public"."outbox_events" FROM "periapsis_api";--> statement-breakpoint

-- Keep the database write boundary aligned with the canonical HTTP shape:
-- a present external identifier is nonblank, bounded, and control-free.
ALTER TABLE "public"."alerts"
  DROP CONSTRAINT "alerts_external_id_check";--> statement-breakpoint
ALTER TABLE "public"."alerts"
  ADD CONSTRAINT "alerts_external_id_check"
  CHECK (
    "external_id" IS NULL
    OR (
      btrim("external_id") <> ''
      AND char_length("external_id") <= 200
      AND "external_id" !~ '[[:cntrl:]]'
    )
  );--> statement-breakpoint

-- The old FOR ALL policy was also an ungoverned active-membership read path.
-- Alert list/detail is deliberately deferred, so no replacement direct-table
-- policy is installed; bounded create definers are the only new Alert surface.
DROP POLICY IF EXISTS "alerts_api_tenant" ON "public"."alerts";--> statement-breakpoint

-- Preserve historical hash bytes: omit exactly the additive actor key for a
-- null value and retain it for service-account events. Never strip unrelated
-- null keys.
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

-- Activate the closed catalog in one transaction. Administration remains
-- human-only; alert.create is the sole machine-capable permission.
INSERT INTO public.tenant_permissions (
  id, key, display_name, description, service_account_allowed
)
VALUES
  (uuidv7(), 'service_account.read', 'Read service accounts', 'List service accounts, role grants, and redacted API credential metadata.', false),
  (uuidv7(), 'service_account.manage', 'Manage service accounts', 'Create, update, archive, and grant roles to tenant service accounts.', false),
  (uuidv7(), 'service_account.credential.manage', 'Manage service-account credentials', 'Issue, rotate, and permanently revoke tenant API credentials.', false),
  (uuidv7(), 'alert.create', 'Create alerts', 'Create the bounded first Alert command.', true)
ON CONFLICT (key) DO NOTHING;--> statement-breakpoint

INSERT INTO public.tenant_permission_scopes (permission_id, scope)
SELECT permission.id, 'tenant'::public.authorization_scope
FROM public.tenant_permissions AS permission
WHERE permission.key IN (
  'service_account.read',
  'service_account.manage',
  'service_account.credential.manage',
  'alert.create'
)
ON CONFLICT DO NOTHING;--> statement-breakpoint

CREATE FUNCTION "app"."private_seed_tenant_service_principal_authorization_v1"(
  p_tenant_id uuid
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  state_revision bigint;
  administrator_role record;
  machine_role record;
  inserted_policies integer;
  inserted_ceilings integer;
  role_changed boolean;
  next_version integer;
BEGIN
  SELECT state.revision
    INTO state_revision
  FROM public.tenant_authorization_states AS state
  WHERE state.tenant_id = p_tenant_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant authorization state is required for service-principal seeding'
      USING ERRCODE = '55000';
  END IF;

  SELECT role.* INTO STRICT machine_role
  FROM public.tenant_roles AS role
  WHERE role.tenant_id = p_tenant_id
    AND role.key = 'service_account'
    AND role.principal_kind = 'service_account'
    AND role.system_role
    AND NOT role.protected_role
    AND role.archived_at IS NULL
  FOR UPDATE;

  IF EXISTS (
    SELECT 1
    FROM public.tenant_role_permissions AS policy
    JOIN public.tenant_permissions AS permission
      ON permission.id = policy.permission_id
    WHERE policy.tenant_id = p_tenant_id
      AND policy.role_id = machine_role.id
      AND (permission.key <> 'alert.create' OR policy.scope <> 'tenant')
  ) OR EXISTS (
    SELECT 1
    FROM public.tenant_role_delegation_ceilings AS ceiling
    WHERE ceiling.tenant_id = p_tenant_id
      AND ceiling.role_id = machine_role.id
  ) THEN
    RAISE EXCEPTION 'built-in service-account role contains authority outside alert.create@tenant'
      USING ERRCODE = '55000';
  END IF;

  INSERT INTO public.tenant_role_permissions (
    tenant_id, role_id, permission_id, scope, created_by_membership_id
  )
  SELECT p_tenant_id, machine_role.id, permission.id, 'tenant', NULL
  FROM public.tenant_permissions AS permission
  WHERE permission.key = 'alert.create'
    AND permission.service_account_allowed
  ON CONFLICT DO NOTHING;
  GET DIAGNOSTICS inserted_policies = ROW_COUNT;

  role_changed := inserted_policies > 0;
  next_version := machine_role.version;
  IF role_changed THEN
    IF machine_role.version >= 2147483647 THEN
      RAISE EXCEPTION 'built-in service-account role version is exhausted'
        USING ERRCODE = '55000';
    END IF;
    next_version := machine_role.version + 1;
    UPDATE public.tenant_roles AS role
    SET version = next_version,
        updated_at = transaction_timestamp()
    WHERE role.tenant_id = p_tenant_id
      AND role.id = machine_role.id;

    INSERT INTO public.audit_events (
      id, tenant_id, sequence, actor_type, action, resource_type,
      resource_id, authentication_method, outcome, after, metadata
    ) VALUES (
      uuidv7(), p_tenant_id, 0, 'system',
      'tenant.authorization.service_principal_enabled', 'tenant_role',
      machine_role.id, 'database_migration', 'success',
      jsonb_build_object(
        'permission', 'alert.create',
        'scope', 'tenant',
        'prior_version', machine_role.version,
        'result_version', next_version
      ),
      jsonb_build_object(
        'migration', '0037_service_principal_alert_security',
        'principal_kind', 'service_account'
      )
    );
  END IF;

  SELECT role.* INTO STRICT administrator_role
  FROM public.tenant_roles AS role
  WHERE role.tenant_id = p_tenant_id
    AND role.key = 'tenant_admin'
    AND role.principal_kind = 'human'
    AND role.system_role
    AND role.protected_role
    AND role.archived_at IS NULL
  FOR UPDATE;

  INSERT INTO public.tenant_role_permissions (
    tenant_id, role_id, permission_id, scope, created_by_membership_id
  )
  SELECT p_tenant_id, administrator_role.id, permission.id, 'tenant', NULL
  FROM public.tenant_permissions AS permission
  WHERE permission.key IN (
    'service_account.read',
    'service_account.manage',
    'service_account.credential.manage',
    'alert.create'
  )
  ON CONFLICT DO NOTHING;
  GET DIAGNOSTICS inserted_policies = ROW_COUNT;

  INSERT INTO public.tenant_role_delegation_ceilings (
    tenant_id, role_id, permission_id, scope, created_by_membership_id
  )
  SELECT p_tenant_id, administrator_role.id, permission.id, 'tenant', NULL
  FROM public.tenant_permissions AS permission
  WHERE permission.key IN (
    'service_account.read',
    'service_account.manage',
    'service_account.credential.manage',
    'alert.create'
  )
  ON CONFLICT DO NOTHING;
  GET DIAGNOSTICS inserted_ceilings = ROW_COUNT;

  role_changed := inserted_policies > 0 OR inserted_ceilings > 0;
  next_version := administrator_role.version;
  IF role_changed THEN
    IF administrator_role.version >= 2147483647 THEN
      RAISE EXCEPTION 'tenant_admin role version is exhausted during service-principal seeding'
        USING ERRCODE = '55000';
    END IF;
    next_version := administrator_role.version + 1;
    UPDATE public.tenant_roles AS role
    SET version = next_version,
        updated_at = transaction_timestamp()
    WHERE role.tenant_id = p_tenant_id
      AND role.id = administrator_role.id;

    INSERT INTO public.audit_events (
      id, tenant_id, sequence, actor_type, action, resource_type,
      resource_id, authentication_method, outcome, after, metadata
    ) VALUES (
      uuidv7(), p_tenant_id, 0, 'system',
      'tenant.authorization.service_principal_administration_enabled',
      'tenant_role', administrator_role.id, 'database_migration', 'success',
      jsonb_build_object(
        'permissions', jsonb_build_array(
          'service_account.read',
          'service_account.manage',
          'service_account.credential.manage',
          'alert.create'
        ),
        'scope', 'tenant',
        'prior_version', administrator_role.version,
        'result_version', next_version
      ),
      jsonb_build_object(
        'migration', '0037_service_principal_alert_security',
        'principal_kind', 'human'
      )
    );
  END IF;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION "app"."private_seed_tenant_service_principal_authorization_v1"(uuid) OWNER TO "periapsis_migrator";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."private_seed_tenant_service_principal_authorization_v1"(uuid) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint

DO $service_principal_catalog_seed$
DECLARE
  tenant_record record;
BEGIN
  FOR tenant_record IN
    SELECT tenant.id
    FROM public.tenants AS tenant
    ORDER BY tenant.id
  LOOP
    PERFORM app.private_seed_tenant_service_principal_authorization_v1(
      tenant_record.id
    );
  END LOOP;
END;
$service_principal_catalog_seed$;--> statement-breakpoint

-- Future tenants must cross the same catalog invariant before their
-- authorization state becomes usable.
ALTER FUNCTION "app"."seed_tenant_authorization"(uuid, uuid)
  RENAME TO "seed_tenant_authorization_service_principal_compatibility_impl";--> statement-breakpoint
-- sqlc's migration parser does not model ALTER FUNCTION ... RENAME. This is a
-- no-op in PostgreSQL after the rename and removes only sqlc's stale symbol.
DROP FUNCTION IF EXISTS "app"."seed_tenant_authorization"(uuid, uuid);--> statement-breakpoint
ALTER FUNCTION "app"."seed_tenant_authorization_service_principal_compatibility_impl"(uuid, uuid) OWNER TO "periapsis_migrator";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."seed_tenant_authorization_service_principal_compatibility_impl"(uuid, uuid) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint

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
BEGIN
  PERFORM app.seed_tenant_authorization_service_principal_compatibility_impl(
    p_tenant_id, p_initial_admin_membership_id
  );
  PERFORM app.private_seed_tenant_service_principal_authorization_v1(
    p_tenant_id
  );
END;
$function$;--> statement-breakpoint

ALTER FUNCTION "app"."seed_tenant_authorization"(uuid, uuid) OWNER TO "periapsis_migrator";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."seed_tenant_authorization"(uuid, uuid) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint

DO $service_principal_catalog_assertions$
DECLARE
  expected_keys text[] := ARRAY[
    'alert.create',
    'service_account.credential.manage',
    'service_account.manage',
    'service_account.read'
  ]::text[];
BEGIN
  IF (
    SELECT array_agg(permission.key ORDER BY permission.key)
    FROM public.tenant_permissions AS permission
    WHERE permission.key = ANY(expected_keys)
  ) IS DISTINCT FROM expected_keys THEN
    RAISE EXCEPTION 'service-principal permission catalog is incomplete'
      USING ERRCODE = '55000';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM public.tenant_permissions AS permission
    WHERE permission.key = ANY(expected_keys)
      AND permission.service_account_allowed IS DISTINCT FROM
        (permission.key = 'alert.create')
  ) OR EXISTS (
    SELECT 1
    FROM public.tenant_permissions AS permission
    WHERE permission.service_account_allowed
      AND permission.key <> 'alert.create'
  ) THEN
    RAISE EXCEPTION 'alert.create must be the sole machine-capable permission'
      USING ERRCODE = '55000';
  END IF;

  IF EXISTS (
    SELECT permission.id
    FROM public.tenant_permissions AS permission
    LEFT JOIN public.tenant_permission_scopes AS permission_scope
      ON permission_scope.permission_id = permission.id
    WHERE permission.key = ANY(expected_keys)
    GROUP BY permission.id
    HAVING array_agg(permission_scope.scope ORDER BY permission_scope.scope)
      IS DISTINCT FROM ARRAY['tenant'::public.authorization_scope]
  ) THEN
    RAISE EXCEPTION 'service-principal permissions require exact tenant scope'
      USING ERRCODE = '55000';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM public.tenant_roles AS role
    WHERE role.key = 'service_account'
      AND (
        role.principal_kind <> 'service_account'
        OR NOT role.system_role
        OR role.protected_role
        OR role.archived_at IS NOT NULL
        OR (
          SELECT count(*)
          FROM public.tenant_role_permissions AS policy
          JOIN public.tenant_permissions AS permission
            ON permission.id = policy.permission_id
          WHERE policy.tenant_id = role.tenant_id
            AND policy.role_id = role.id
            AND permission.key = 'alert.create'
            AND policy.scope = 'tenant'
        ) <> 1
        OR (
          SELECT count(*)
          FROM public.tenant_role_permissions AS policy
          WHERE policy.tenant_id = role.tenant_id
            AND policy.role_id = role.id
        ) <> 1
        OR EXISTS (
          SELECT 1
          FROM public.tenant_role_delegation_ceilings AS ceiling
          WHERE ceiling.tenant_id = role.tenant_id
            AND ceiling.role_id = role.id
        )
      )
  ) THEN
    RAISE EXCEPTION 'built-in service-account role policy is not exact'
      USING ERRCODE = '55000';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM public.tenant_roles AS role
    WHERE role.key = 'tenant_admin'
      AND (
        role.principal_kind <> 'human'
        OR (
          SELECT count(*)
          FROM public.tenant_role_permissions AS policy
          JOIN public.tenant_permissions AS permission
            ON permission.id = policy.permission_id
          WHERE policy.tenant_id = role.tenant_id
            AND policy.role_id = role.id
            AND permission.key = ANY(expected_keys)
            AND policy.scope = 'tenant'
        ) <> 4
        OR (
          SELECT count(*)
          FROM public.tenant_role_delegation_ceilings AS ceiling
          JOIN public.tenant_permissions AS permission
            ON permission.id = ceiling.permission_id
          WHERE ceiling.tenant_id = role.tenant_id
            AND ceiling.role_id = role.id
            AND permission.key = ANY(expected_keys)
            AND ceiling.scope = 'tenant'
        ) <> 4
      )
  ) THEN
    RAISE EXCEPTION 'tenant_admin service-principal policy or ceiling is incomplete'
      USING ERRCODE = '55000';
  END IF;
END;
$service_principal_catalog_assertions$;--> statement-breakpoint

CREATE TRIGGER "tenant_service_accounts_authorization_touch"
BEFORE INSERT OR UPDATE OR DELETE ON "public"."tenant_service_accounts"
FOR EACH ROW EXECUTE FUNCTION "app"."touch_tenant_authorization_row"();--> statement-breakpoint
CREATE TRIGGER "tenant_service_account_role_grants_authorization_touch"
BEFORE INSERT OR UPDATE OR DELETE ON "public"."tenant_service_account_role_grants"
FOR EACH ROW EXECUTE FUNCTION "app"."touch_tenant_authorization_row"();--> statement-breakpoint

CREATE FUNCTION "app"."guard_service_principal_append_only_v1"()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP = 'INSERT' THEN
    RETURN NEW;
  END IF;
  IF TG_TABLE_NAME = 'alert_activities' THEN
    RAISE EXCEPTION 'alert activity rows are append-only'
      USING ERRCODE = '55000';
  ELSIF TG_TABLE_NAME = 'alert_commands' THEN
    RAISE EXCEPTION 'alert command rows are append-only'
      USING ERRCODE = '55000';
  ELSIF TG_TABLE_NAME = 'tenant_api_credential_commands' THEN
    RAISE EXCEPTION 'API credential command rows are append-only'
      USING ERRCODE = '55000';
  END IF;
  RAISE EXCEPTION 'unsupported append-only service-principal relation'
    USING ERRCODE = '55000';
END;
$function$;--> statement-breakpoint

ALTER FUNCTION "app"."guard_service_principal_append_only_v1"() OWNER TO "periapsis_migrator";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."guard_service_principal_append_only_v1"() FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint

CREATE TRIGGER "alert_activities_immutable_guard"
BEFORE UPDATE OR DELETE ON "public"."alert_activities"
FOR EACH ROW EXECUTE FUNCTION "app"."guard_service_principal_append_only_v1"();--> statement-breakpoint
CREATE TRIGGER "alert_commands_immutable_guard"
BEFORE UPDATE OR DELETE ON "public"."alert_commands"
FOR EACH ROW EXECUTE FUNCTION "app"."guard_service_principal_append_only_v1"();--> statement-breakpoint
CREATE TRIGGER "tenant_api_credential_commands_immutable_guard"
BEFORE UPDATE OR DELETE ON "public"."tenant_api_credential_commands"
FOR EACH ROW EXECUTE FUNCTION "app"."guard_service_principal_append_only_v1"();--> statement-breakpoint

-- v2 remains the frozen rolling projection. New 0037 entry points use these
-- human-only v3 predicates so the newly activated permission tuples are
-- enforceable without widening an old binary's view.
CREATE FUNCTION "app"."tenant_human_has_exact_permission_v3"(
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
  WITH role_paths AS (
    SELECT direct_grant.role_id
    FROM public.tenant_membership_role_grants AS direct_grant
    JOIN public.tenant_authorization_sources AS direct_source
      ON direct_source.tenant_id = direct_grant.tenant_id
     AND direct_source.id = direct_grant.source_id
    JOIN public.tenant_memberships AS membership
      ON membership.tenant_id = direct_grant.tenant_id
     AND membership.id = direct_grant.membership_id
    JOIN public.users AS identity ON identity.id = membership.user_id
    JOIN public.tenants AS tenant ON tenant.id = membership.tenant_id
    JOIN public.tenant_authorization_states AS state
      ON state.tenant_id = membership.tenant_id
     AND state.initialized_at IS NOT NULL
    WHERE membership.tenant_id = p_tenant_id
      AND membership.user_id = p_user_id
      AND membership.status = 'active'
      AND identity.active
      AND tenant.status = 'active'
      AND direct_grant.revoked_at IS NULL
      AND (direct_grant.expires_at IS NULL
        OR direct_grant.expires_at > transaction_timestamp())
      AND direct_source.retired_at IS NULL

    UNION ALL

    SELECT group_grant.role_id
    FROM public.tenant_security_group_memberships AS group_member
    JOIN public.tenant_memberships AS membership
      ON membership.tenant_id = group_member.tenant_id
     AND membership.id = group_member.membership_id
    JOIN public.users AS identity ON identity.id = membership.user_id
    JOIN public.tenants AS tenant ON tenant.id = membership.tenant_id
    JOIN public.tenant_authorization_states AS state
      ON state.tenant_id = membership.tenant_id
     AND state.initialized_at IS NOT NULL
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
    WHERE membership.tenant_id = p_tenant_id
      AND membership.user_id = p_user_id
      AND membership.status = 'active'
      AND identity.active
      AND tenant.status = 'active'
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
  SELECT p_scope <> 'platform'
     AND EXISTS (
       SELECT 1
       FROM role_paths AS role_path
       JOIN public.tenant_roles AS role
         ON role.tenant_id = p_tenant_id
        AND role.id = role_path.role_id
       JOIN public.tenant_role_permissions AS role_permission
         ON role_permission.tenant_id = role.tenant_id
        AND role_permission.role_id = role.id
       JOIN public.tenant_permissions AS permission
         ON permission.id = role_permission.permission_id
       WHERE role.principal_kind = 'human'
         AND role.archived_at IS NULL
         AND permission.key = p_permission_key
         AND role_permission.scope = p_scope
     );
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."tenant_human_can_delegate_exact_permission_v3"(
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
  WITH role_paths AS (
    SELECT direct_grant.role_id, direct_grant.expires_at
    FROM public.tenant_membership_role_grants AS direct_grant
    JOIN public.tenant_authorization_sources AS direct_source
      ON direct_source.tenant_id = direct_grant.tenant_id
     AND direct_source.id = direct_grant.source_id
    JOIN public.tenant_memberships AS membership
      ON membership.tenant_id = direct_grant.tenant_id
     AND membership.id = direct_grant.membership_id
    JOIN public.users AS identity ON identity.id = membership.user_id
    JOIN public.tenants AS tenant ON tenant.id = membership.tenant_id
    JOIN public.tenant_authorization_states AS state
      ON state.tenant_id = membership.tenant_id
     AND state.initialized_at IS NOT NULL
    WHERE membership.tenant_id = p_tenant_id
      AND membership.user_id = p_user_id
      AND membership.status = 'active'
      AND identity.active
      AND tenant.status = 'active'
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
    JOIN public.tenant_memberships AS membership
      ON membership.tenant_id = group_member.tenant_id
     AND membership.id = group_member.membership_id
    JOIN public.users AS identity ON identity.id = membership.user_id
    JOIN public.tenants AS tenant ON tenant.id = membership.tenant_id
    JOIN public.tenant_authorization_states AS state
      ON state.tenant_id = membership.tenant_id
     AND state.initialized_at IS NOT NULL
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
    WHERE membership.tenant_id = p_tenant_id
      AND membership.user_id = p_user_id
      AND membership.status = 'active'
      AND identity.active
      AND tenant.status = 'active'
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
  SELECT p_scope <> 'platform'
     AND EXISTS (
       SELECT 1
       FROM role_paths AS role_path
       JOIN public.tenant_roles AS role
         ON role.tenant_id = p_tenant_id
        AND role.id = role_path.role_id
       JOIN public.tenant_role_delegation_ceilings AS ceiling
         ON ceiling.tenant_id = role.tenant_id
        AND ceiling.role_id = role.id
       JOIN public.tenant_permissions AS permission
         ON permission.id = ceiling.permission_id
       WHERE role.principal_kind = 'human'
         AND role.archived_at IS NULL
         AND permission.key = p_permission_key
         AND ceiling.scope = p_scope
         AND (
           (p_requested_expires_at IS NULL AND role_path.expires_at IS NULL)
           OR (p_requested_expires_at IS NOT NULL
             AND (role_path.expires_at IS NULL
               OR role_path.expires_at >= p_requested_expires_at))
         )
     );
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."current_tenant_human_has_exact_permission_v3"(
  p_permission_key text,
  p_scope "public"."authorization_scope"
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT app.tenant_human_has_exact_permission_v3(
    app.context_tenant_id(), app.context_user_id(), p_permission_key, p_scope
  );
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."assert_actor_can_change_service_account_role_grant_v1"(
  p_role_id uuid,
  p_effective_expires_at timestamp with time zone
)
RETURNS integer
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_id uuid := app.context_user_id();
  consequence record;
  checked_count integer := 0;
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM public.tenant_roles AS role
    WHERE role.tenant_id = context_tenant
      AND role.id = p_role_id
      AND role.principal_kind = 'service_account'
      AND role.archived_at IS NULL
  ) THEN
    RAISE EXCEPTION 'live service-account role was not found'
      USING ERRCODE = 'P0002';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM public.tenant_role_delegation_ceilings AS ceiling
    WHERE ceiling.tenant_id = context_tenant
      AND ceiling.role_id = p_role_id
  ) THEN
    RAISE EXCEPTION 'service-account roles cannot carry delegation ceilings'
      USING ERRCODE = '55000';
  END IF;

  FOR consequence IN
    SELECT permission.key AS permission_key, policy.scope
    FROM public.tenant_role_permissions AS policy
    JOIN public.tenant_permissions AS permission
      ON permission.id = policy.permission_id
    JOIN public.tenant_permission_scopes AS permission_scope
      ON permission_scope.permission_id = policy.permission_id
     AND permission_scope.scope = policy.scope
    WHERE policy.tenant_id = context_tenant
      AND policy.role_id = p_role_id
      AND permission.service_account_allowed
      AND policy.scope <> 'platform'
    ORDER BY permission.key, policy.scope
    LIMIT 201
  LOOP
    checked_count := checked_count + 1;
    IF checked_count > 200 THEN
      RAISE EXCEPTION 'service-account role consequence limit exceeded'
        USING ERRCODE = '54000';
    END IF;
    IF NOT app.tenant_human_can_delegate_exact_permission_v3(
      context_tenant,
      actor_id,
      consequence.permission_key,
      consequence.scope,
      p_effective_expires_at
    ) THEN
      RAISE EXCEPTION 'service-account role change exceeds the exact delegation ceiling or requested_expires_at horizon'
        USING ERRCODE = '42501';
    END IF;
  END LOOP;

  IF EXISTS (
    SELECT 1
    FROM public.tenant_role_permissions AS policy
    JOIN public.tenant_permissions AS permission
      ON permission.id = policy.permission_id
    WHERE policy.tenant_id = context_tenant
      AND policy.role_id = p_role_id
      AND (
        NOT permission.service_account_allowed
        OR policy.scope = 'platform'
      )
  ) THEN
    RAISE EXCEPTION 'service-account role contains a human-only or platform permission'
      USING ERRCODE = '55000';
  END IF;

  RETURN checked_count;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."assert_tenant_api_credential_request_shape_v1"(
  p_permission_keys text[],
  p_scopes "public"."authorization_scope"[],
  p_networks cidr[]
)
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  canonical_permission_keys text[];
  canonical_scopes public.authorization_scope[];
  canonical_networks cidr[];
BEGIN
  IF p_permission_keys IS NULL OR p_scopes IS NULL
     OR cardinality(p_permission_keys) IS DISTINCT FROM cardinality(p_scopes)
     OR cardinality(p_permission_keys) NOT BETWEEN 1 AND 100 THEN
    RAISE EXCEPTION 'credential permission arrays must have equal bounded nonzero cardinality'
      USING ERRCODE = '22023';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM unnest(p_permission_keys, p_scopes)
      AS requested(permission_key, scope)
    GROUP BY requested.permission_key, requested.scope
    HAVING count(*) > 1 OR bool_or(
      requested.permission_key IS NULL OR requested.scope IS NULL
    )
  ) THEN
    RAISE EXCEPTION 'credential permission allowlist is noncanonical or contains duplicates'
      USING ERRCODE = '22023';
  END IF;

  SELECT array_agg(requested.permission_key ORDER BY requested.permission_key, requested.scope),
         array_agg(requested.scope ORDER BY requested.permission_key, requested.scope)
    INTO canonical_permission_keys, canonical_scopes
  FROM unnest(p_permission_keys, p_scopes)
    AS requested(permission_key, scope);
  IF p_permission_keys IS DISTINCT FROM canonical_permission_keys
     OR p_scopes IS DISTINCT FROM canonical_scopes THEN
    RAISE EXCEPTION 'credential permission allowlist must use canonical sorted order'
      USING ERRCODE = '22023';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM unnest(p_permission_keys, p_scopes)
      AS requested(permission_key, scope)
    WHERE NOT EXISTS (
      SELECT 1
      FROM public.tenant_permissions AS permission
      JOIN public.tenant_permission_scopes AS permission_scope
        ON permission_scope.permission_id = permission.id
       AND permission_scope.scope = requested.scope
      WHERE permission.key = requested.permission_key
        AND permission.service_account_allowed
        AND requested.scope <> 'platform'
    )
  ) THEN
    RAISE EXCEPTION 'credential allowlist contains an unsupported machine permission scope'
      USING ERRCODE = '22023';
  END IF;

  IF p_networks IS NULL OR cardinality(p_networks) > 32
     OR EXISTS (
       SELECT 1
       FROM unnest(p_networks) AS allowed_network(network)
       WHERE allowed_network.network IS NULL
     )
     OR EXISTS (
       SELECT 1
       FROM unnest(p_networks) AS allowed_network(network)
       GROUP BY allowed_network.network HAVING count(*) > 1
     ) THEN
    RAISE EXCEPTION 'credential CIDR allowlist is noncanonical or exceeds 32 networks'
      USING ERRCODE = '22023';
  END IF;

  SELECT coalesce(
           array_agg(allowed_network.network ORDER BY allowed_network.network),
           ARRAY[]::cidr[]
         )
    INTO canonical_networks
  FROM unnest(p_networks) AS allowed_network(network);
  IF p_networks IS DISTINCT FROM canonical_networks THEN
    RAISE EXCEPTION 'credential CIDR allowlist must use canonical sorted order'
      USING ERRCODE = '22023';
  END IF;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."assert_tenant_api_credential_policy_v1"(
  p_tenant_id uuid,
  p_service_account_id uuid,
  p_permission_keys text[],
  p_scopes "public"."authorization_scope"[],
  p_networks cidr[]
)
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  PERFORM app.assert_tenant_api_credential_request_shape_v1(
    p_permission_keys, p_scopes, p_networks
  );

  IF NOT EXISTS (
    SELECT 1
    FROM unnest(p_permission_keys, p_scopes)
      AS requested(permission_key, scope)
    JOIN public.tenant_permissions AS permission
      ON permission.key = requested.permission_key
     AND permission.service_account_allowed
    JOIN public.tenant_service_account_role_grants AS role_grant
      ON role_grant.tenant_id = p_tenant_id
     AND role_grant.service_account_id = p_service_account_id
     AND role_grant.revoked_at IS NULL
     AND (role_grant.expires_at IS NULL
       OR role_grant.expires_at > transaction_timestamp())
    JOIN public.tenant_authorization_sources AS source
      ON source.tenant_id = role_grant.tenant_id
     AND source.id = role_grant.source_id
     AND source.retired_at IS NULL
    JOIN public.tenant_roles AS role
      ON role.tenant_id = role_grant.tenant_id
     AND role.id = role_grant.role_id
     AND role.principal_kind = 'service_account'
     AND role.archived_at IS NULL
    JOIN public.tenant_role_permissions AS policy
      ON policy.tenant_id = role.tenant_id
     AND policy.role_id = role.id
     AND policy.permission_id = permission.id
     AND policy.scope = requested.scope
  ) THEN
    RAISE EXCEPTION 'credential allowlist has no live exact service-account authority intersection'
      USING ERRCODE = '42501';
  END IF;
END;
$function$;--> statement-breakpoint

-- This lookup obtains no row lock. Its only purpose is to discover the
-- account key from the globally unique locator after the tenant state lock;
-- authenticate_tenant_api_credential_v1 then locks account before credential.
CREATE FUNCTION "app"."private_resolve_tenant_api_credential_locator_v1"(
  p_tenant_id uuid,
  p_locator bytea
)
RETURNS TABLE (
  service_account_id uuid,
  credential_id uuid
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT credential.service_account_id, credential.id
  FROM public.tenant_api_credentials AS credential
  WHERE credential.tenant_id = p_tenant_id
    AND credential.locator = p_locator;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."authenticate_tenant_api_credential_v1"(
  p_tenant_id uuid,
  p_locator bytea,
  p_envelope_key_version integer,
  p_secret_digest bytea,
  p_client_address inet,
  p_permission_key text,
  p_scope "public"."authorization_scope"
)
RETURNS TABLE (
  service_account_id uuid,
  credential_id uuid,
  key_version integer
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  resolved record;
  locked_service_account record;
  locked_credential record;
BEGIN
  IF p_tenant_id IS NULL OR p_locator IS NULL
     OR octet_length(p_locator) <> 16
     OR p_secret_digest IS NULL OR octet_length(p_secret_digest) <> 32
     OR p_envelope_key_version IS NULL
     OR p_envelope_key_version NOT BETWEEN 1 AND 32767
     OR p_client_address IS NULL
     OR (family(p_client_address) = 4 AND masklen(p_client_address) <> 32)
     OR (family(p_client_address) = 6 AND masklen(p_client_address) <> 128)
     OR p_permission_key IS NULL OR btrim(p_permission_key) = ''
     OR p_scope IS NULL OR p_scope = 'platform' THEN
    RAISE EXCEPTION 'invalid tenant API credential proof'
      USING ERRCODE = '22023';
  END IF;

  -- Fixed lock order: authorization state, account, credential. FOR KEY SHARE
  -- conflicts with every authorization mutation's state FOR UPDATE lock.
  PERFORM 1
  FROM public.tenant_authorization_states AS authorization_state
  JOIN public.tenants AS tenant
    ON tenant.id = authorization_state.tenant_id
  WHERE authorization_state.tenant_id = p_tenant_id
    AND authorization_state.initialized_at IS NOT NULL
    AND tenant.status = 'active'
  FOR KEY SHARE OF authorization_state;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'active initialized tenant was not found'
      USING ERRCODE = '42501';
  END IF;

  SELECT locator_result.* INTO resolved
  FROM app.private_resolve_tenant_api_credential_locator_v1(
    p_tenant_id, p_locator
  ) AS locator_result;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant API credential authentication failed'
      USING ERRCODE = '28000';
  END IF;

  SELECT service_account.* INTO locked_service_account
  FROM public.tenant_service_accounts AS service_account
  WHERE service_account.tenant_id = p_tenant_id
    AND service_account.id = resolved.service_account_id
    AND service_account.archived_at IS NULL
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant API credential authentication failed'
      USING ERRCODE = '28000';
  END IF;

  SELECT credential.* INTO locked_credential
  FROM public.tenant_api_credentials AS credential
  WHERE credential.tenant_id = p_tenant_id
    AND credential.service_account_id = locked_service_account.id
    AND credential.id = resolved.credential_id
    AND credential.locator = p_locator
    AND credential.format_version = 1
    AND credential.key_version = p_envelope_key_version
    AND credential.secret_digest = p_secret_digest
    AND credential.revoked_at IS NULL
    AND credential.expires_at > transaction_timestamp()
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant API credential authentication failed'
      USING ERRCODE = '28000';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM public.tenant_api_credential_networks AS credential_network
    WHERE credential_network.tenant_id = p_tenant_id
      AND credential_network.credential_id = locked_credential.id
  ) AND NOT EXISTS (
    SELECT 1
    FROM public.tenant_api_credential_networks AS credential_network
    WHERE credential_network.tenant_id = p_tenant_id
      AND credential_network.credential_id = locked_credential.id
      AND p_client_address <<= credential_network.network
  ) THEN
    RAISE EXCEPTION 'tenant API credential source address is not allowed'
      USING ERRCODE = '28000';
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM public.tenant_api_credential_permissions AS credential_permission
    JOIN public.tenant_permissions AS permission
      ON permission.id = credential_permission.permission_id
     AND permission.service_account_allowed
     AND permission.key = p_permission_key
    JOIN public.tenant_service_account_role_grants AS role_grant
      ON role_grant.tenant_id = credential_permission.tenant_id
     AND role_grant.service_account_id = locked_service_account.id
     AND role_grant.revoked_at IS NULL
     AND (role_grant.expires_at IS NULL
       OR role_grant.expires_at > transaction_timestamp())
    JOIN public.tenant_authorization_sources AS source
      ON source.tenant_id = role_grant.tenant_id
     AND source.id = role_grant.source_id
     AND source.retired_at IS NULL
    JOIN public.tenant_roles AS role
      ON role.tenant_id = role_grant.tenant_id
     AND role.id = role_grant.role_id
     AND role.principal_kind = 'service_account'
     AND role.archived_at IS NULL
    JOIN public.tenant_role_permissions AS role_permission
      ON role_permission.tenant_id = role.tenant_id
     AND role_permission.role_id = role.id
     AND role_permission.permission_id = permission.id
     AND role_permission.scope = credential_permission.scope
    WHERE credential_permission.tenant_id = p_tenant_id
      AND credential_permission.credential_id = locked_credential.id
      AND credential_permission.permission_service_account_allowed
      AND credential_permission.scope = p_scope
  ) THEN
    RAISE EXCEPTION 'tenant API credential lacks live exact authority'
      USING ERRCODE = '42501';
  END IF;

  IF locked_credential.version >= 2147483647 THEN
    RAISE EXCEPTION 'tenant API credential version is exhausted during authentication'
      USING ERRCODE = '55000';
  END IF;

  UPDATE public.tenant_api_credentials AS used_credential
  SET last_used_at = transaction_timestamp(),
      last_used_ip = p_client_address,
      version = locked_credential.version + 1,
      updated_at = transaction_timestamp()
  WHERE used_credential.tenant_id = p_tenant_id
    AND used_credential.id = locked_credential.id;

  RETURN QUERY
  SELECT locked_service_account.id,
         locked_credential.id,
         locked_credential.key_version;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."append_tenant_service_account_audit_v1"(
  p_tenant_id uuid,
  p_service_account_id uuid,
  p_credential_id uuid,
  p_action text,
  p_resource_type text,
  p_resource_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
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
BEGIN
  IF p_action IS NULL OR btrim(p_action) = ''
     OR p_resource_type IS NULL OR btrim(p_resource_type) = ''
     OR p_ip_address IS NULL
     OR (p_user_agent IS NOT NULL AND (
       char_length(p_user_agent) > 1024
       OR p_user_agent ~ '[[:cntrl:]]'
     )) THEN
    RAISE EXCEPTION 'invalid service-account audit event'
      USING ERRCODE = '22023';
  END IF;
  IF NOT EXISTS (
    SELECT 1
    FROM public.tenant_service_accounts AS service_account
    JOIN public.tenants AS tenant ON tenant.id = service_account.tenant_id
    WHERE service_account.tenant_id = p_tenant_id
      AND service_account.id = p_service_account_id
      AND service_account.archived_at IS NULL
      AND tenant.status = 'active'
  ) THEN
    RAISE EXCEPTION 'live service-account audit actor was not found'
      USING ERRCODE = '42501';
  END IF;

  INSERT INTO public.audit_events (
    id, tenant_id, sequence, actor_type, actor_service_account_id,
    action, resource_type, resource_id, request_id, correlation_id,
    ip_address, user_agent, authentication_method, outcome,
    before, after, metadata
  ) VALUES (
    uuidv7(), p_tenant_id, 0, 'service_account', p_service_account_id,
    p_action, p_resource_type, p_resource_id, p_request_id,
    p_correlation_id, p_ip_address, p_user_agent, 'api_credential',
    'success', p_before, p_after,
    coalesce(p_metadata, '{}'::jsonb)
      || jsonb_build_object('credential_id', p_credential_id)
  );
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."resolve_tenant_service_account_authority_v1"(
  p_service_account_id uuid,
  p_limit integer
)
RETURNS TABLE (
  permission_key text,
  scope "public"."authorization_scope",
  effective_expires_at timestamp with time zone
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
  IF NOT app.current_tenant_human_has_exact_permission_v3(
    'service_account.read', 'tenant'
  ) THEN
    RAISE EXCEPTION 'service_account.read tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 201 THEN
    RAISE EXCEPTION 'service-account authority limit must be between 1 and 201'
      USING ERRCODE = '22023';
  END IF;
  IF NOT EXISTS (
    SELECT 1
    FROM public.tenant_service_accounts AS service_account
    WHERE service_account.tenant_id = context_tenant
      AND service_account.id = p_service_account_id
  ) THEN
    RAISE EXCEPTION 'tenant service account was not found'
      USING ERRCODE = 'P0002';
  END IF;

  RETURN QUERY
  SELECT permission.key,
         role_permission.scope,
         CASE
           WHEN bool_or(role_grant.expires_at IS NULL) THEN NULL
           ELSE max(role_grant.expires_at)
         END
  FROM public.tenant_service_accounts AS service_account
  JOIN public.tenants AS tenant ON tenant.id = service_account.tenant_id
  JOIN public.tenant_authorization_states AS state
    ON state.tenant_id = service_account.tenant_id
   AND state.initialized_at IS NOT NULL
  JOIN public.tenant_service_account_role_grants AS role_grant
    ON role_grant.tenant_id = service_account.tenant_id
   AND role_grant.service_account_id = service_account.id
  JOIN public.tenant_authorization_sources AS source
    ON source.tenant_id = role_grant.tenant_id
   AND source.id = role_grant.source_id
  JOIN public.tenant_roles AS role
    ON role.tenant_id = role_grant.tenant_id
   AND role.id = role_grant.role_id
  JOIN public.tenant_role_permissions AS role_permission
    ON role_permission.tenant_id = role.tenant_id
   AND role_permission.role_id = role.id
  JOIN public.tenant_permissions AS permission
    ON permission.id = role_permission.permission_id
  WHERE service_account.tenant_id = context_tenant
    AND service_account.id = p_service_account_id
    AND service_account.archived_at IS NULL
    AND tenant.status = 'active'
    AND role_grant.revoked_at IS NULL
    AND (role_grant.expires_at IS NULL
      OR role_grant.expires_at > transaction_timestamp())
    AND source.retired_at IS NULL
    AND role.principal_kind = 'service_account'
    AND role.archived_at IS NULL
    AND permission.service_account_allowed
    AND role_permission.scope <> 'platform'
  GROUP BY permission.key, role_permission.scope
  ORDER BY permission.key, role_permission.scope
  LIMIT p_limit;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."list_live_api_credential_key_versions_v1"(
  p_limit integer
)
RETURNS TABLE (
  key_version integer
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 101 THEN
    RAISE EXCEPTION 'live credential key-version limit must be between 1 and 101'
      USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  SELECT DISTINCT credential.key_version
  FROM public.tenant_api_credentials AS credential
  JOIN public.tenant_service_accounts AS service_account
    ON service_account.tenant_id = credential.tenant_id
   AND service_account.id = credential.service_account_id
  JOIN public.tenants AS tenant ON tenant.id = credential.tenant_id
  JOIN public.tenant_authorization_states AS state
    ON state.tenant_id = credential.tenant_id
   AND state.initialized_at IS NOT NULL
  WHERE credential.revoked_at IS NULL
    AND credential.expires_at > transaction_timestamp()
    AND service_account.archived_at IS NULL
    AND tenant.status = 'active'
  ORDER BY credential.key_version
  LIMIT p_limit;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."list_tenant_service_accounts_v1"(
  p_after_id uuid,
  p_include_archived boolean,
  p_limit integer
)
RETURNS TABLE (
  service_account_id uuid,
  account_key text,
  display_name text,
  description text,
  created_by_membership_id uuid,
  created_by_user_id uuid,
  archived_at timestamp with time zone,
  archived_by_membership_id uuid,
  archived_by_user_id uuid,
  archive_reason text,
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
  IF NOT app.current_tenant_human_has_exact_permission_v3(
    'service_account.read', 'tenant'
  ) THEN
    RAISE EXCEPTION 'service_account.read tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_include_archived IS NULL THEN
    RAISE EXCEPTION 'include archived must be explicit'
      USING ERRCODE = '22023';
  END IF;
  IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 101 THEN
    RAISE EXCEPTION 'service-account page limit must be between 1 and 101'
      USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  SELECT service_account.id,
         service_account.key,
         service_account.display_name,
         service_account.description,
         service_account.created_by_membership_id,
         creator.user_id,
         service_account.archived_at,
         service_account.archived_by_membership_id,
         archiver.user_id,
         service_account.archive_reason,
         service_account.version,
         service_account.created_at,
         service_account.updated_at
  FROM public.tenant_service_accounts AS service_account
  JOIN public.tenant_memberships AS creator
    ON creator.tenant_id = service_account.tenant_id
   AND creator.id = service_account.created_by_membership_id
  LEFT JOIN public.tenant_memberships AS archiver
    ON archiver.tenant_id = service_account.tenant_id
   AND archiver.id = service_account.archived_by_membership_id
  WHERE service_account.tenant_id = context_tenant
    AND (p_include_archived OR service_account.archived_at IS NULL)
    AND (p_after_id IS NULL OR service_account.id > p_after_id)
  ORDER BY service_account.id
  LIMIT p_limit;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."get_tenant_service_account_v1"(
  p_service_account_id uuid
)
RETURNS TABLE (
  service_account_id uuid,
  account_key text,
  display_name text,
  description text,
  created_by_membership_id uuid,
  created_by_user_id uuid,
  archived_at timestamp with time zone,
  archived_by_membership_id uuid,
  archived_by_user_id uuid,
  archive_reason text,
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
    app.current_tenant_human_has_exact_permission_v3(
      'service_account.read', 'tenant'
    )
    OR app.current_tenant_human_has_exact_permission_v3(
      'service_account.manage', 'tenant'
    )
  ) THEN
    RAISE EXCEPTION 'service-account read or mutation authority is required'
      USING ERRCODE = '42501';
  END IF;

  RETURN QUERY
  SELECT service_account.id,
         service_account.key,
         service_account.display_name,
         service_account.description,
         service_account.created_by_membership_id,
         creator.user_id,
         service_account.archived_at,
         service_account.archived_by_membership_id,
         archiver.user_id,
         service_account.archive_reason,
         service_account.version,
         service_account.created_at,
         service_account.updated_at
  FROM public.tenant_service_accounts AS service_account
  JOIN public.tenant_memberships AS creator
    ON creator.tenant_id = service_account.tenant_id
   AND creator.id = service_account.created_by_membership_id
  LEFT JOIN public.tenant_memberships AS archiver
    ON archiver.tenant_id = service_account.tenant_id
   AND archiver.id = service_account.archived_by_membership_id
  WHERE service_account.tenant_id = context_tenant
    AND service_account.id = p_service_account_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant service account was not found'
      USING ERRCODE = 'P0002';
  END IF;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."create_tenant_service_account_v1"(
  p_service_account_id uuid,
  p_key text,
  p_display_name text,
  p_description text,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE (
  result_resource_id uuid,
  result_version integer
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF NOT app.current_tenant_human_has_exact_permission_v3(
    'service_account.manage', 'tenant'
  ) THEN
    RAISE EXCEPTION 'service_account.manage tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_service_account_id IS NULL
     OR p_key IS NULL OR p_key !~ '^[a-z][a-z0-9_]{2,63}$'
     OR p_display_name IS NULL OR btrim(p_display_name) = ''
     OR char_length(p_display_name) > 120
     OR p_display_name ~ '[[:cntrl:]]'
     OR p_description IS NULL OR char_length(p_description) > 500
     OR p_description ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION 'service-account attributes violate the canonical contract'
      USING ERRCODE = '22023';
  END IF;

  INSERT INTO public.tenant_service_accounts (
    id, tenant_id, key, display_name, description,
    created_by_membership_id
  ) VALUES (
    p_service_account_id, context_tenant, p_key, p_display_name,
    p_description, actor_membership
  );

  PERFORM app.append_tenant_authorization_audit(
    uuidv7(),
    'tenant.service_account.created',
    'tenant_service_account',
    p_service_account_id,
    p_request_id,
    p_correlation_id,
    p_ip_address,
    p_user_agent,
    p_authentication_method,
    NULL,
    jsonb_build_object(
      'key', p_key,
      'display_name', p_display_name,
      'description', p_description,
      'version', 1
    ),
    jsonb_build_object('actor_membership_id', actor_membership)
  );

  RETURN QUERY SELECT p_service_account_id, 1::integer;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."update_tenant_service_account_v1"(
  p_service_account_id uuid,
  p_expected_version integer,
  p_display_name text,
  p_description text,
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
  target_account record;
  next_version integer;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF NOT app.current_tenant_human_has_exact_permission_v3(
    'service_account.manage', 'tenant'
  ) THEN
    RAISE EXCEPTION 'service_account.manage tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_display_name IS NULL AND p_description IS NULL THEN
    RAISE EXCEPTION 'at least one service-account metadata field is required'
      USING ERRCODE = '22023';
  END IF;
  IF p_display_name IS NOT NULL AND (
    btrim(p_display_name) = ''
    OR char_length(p_display_name) > 120
    OR p_display_name ~ '[[:cntrl:]]'
  ) THEN
    RAISE EXCEPTION 'service-account display name is invalid'
      USING ERRCODE = '22023';
  END IF;
  IF p_description IS NOT NULL AND (
    char_length(p_description) > 500
    OR p_description ~ '[[:cntrl:]]'
  ) THEN
    RAISE EXCEPTION 'service-account description is invalid'
      USING ERRCODE = '22023';
  END IF;

  SELECT service_account.* INTO target_account
  FROM public.tenant_service_accounts AS service_account
  WHERE service_account.tenant_id = context_tenant
    AND service_account.id = p_service_account_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant service account was not found'
      USING ERRCODE = 'P0002';
  END IF;
  IF target_account.version IS DISTINCT FROM p_expected_version THEN
    RAISE EXCEPTION 'tenant service-account version conflict'
      USING ERRCODE = '40001';
  END IF;
  IF target_account.archived_at IS NOT NULL THEN
    RAISE EXCEPTION 'archived service account cannot be updated'
      USING ERRCODE = '55000';
  END IF;
  IF target_account.version >= 2147483647 THEN
    RAISE EXCEPTION 'tenant service-account version is exhausted'
      USING ERRCODE = '55000';
  END IF;

  next_version := target_account.version + 1;
  UPDATE public.tenant_service_accounts AS service_account
  SET display_name = coalesce(p_display_name, service_account.display_name),
      description = coalesce(p_description, service_account.description),
      version = next_version,
      updated_at = transaction_timestamp()
  WHERE service_account.tenant_id = context_tenant
    AND service_account.id = p_service_account_id;

  PERFORM app.append_tenant_authorization_audit(
    uuidv7(),
    'tenant.service_account.metadata_updated',
    'tenant_service_account',
    p_service_account_id,
    p_request_id,
    p_correlation_id,
    p_ip_address,
    p_user_agent,
    p_authentication_method,
    jsonb_build_object(
      'display_name', target_account.display_name,
      'description', target_account.description,
      'version', target_account.version
    ),
    jsonb_build_object(
      'display_name', coalesce(p_display_name, target_account.display_name),
      'description', coalesce(p_description, target_account.description),
      'version', next_version
    ),
    jsonb_build_object('actor_membership_id', actor_membership)
  );

  RETURN next_version;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."archive_tenant_service_account_v1"(
  p_service_account_id uuid,
  p_expected_version integer,
  p_reason text,
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
  target_account record;
  next_version integer;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF NOT app.current_tenant_human_has_exact_permission_v3(
    'service_account.manage', 'tenant'
  ) THEN
    RAISE EXCEPTION 'service_account.manage tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_reason IS NULL OR btrim(p_reason) = ''
     OR char_length(p_reason) > 500 OR p_reason ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION 'service-account archive reason is invalid'
      USING ERRCODE = '22023';
  END IF;

  SELECT service_account.* INTO target_account
  FROM public.tenant_service_accounts AS service_account
  WHERE service_account.tenant_id = context_tenant
    AND service_account.id = p_service_account_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant service account was not found'
      USING ERRCODE = 'P0002';
  END IF;
  IF target_account.version IS DISTINCT FROM p_expected_version THEN
    RAISE EXCEPTION 'tenant service-account version conflict'
      USING ERRCODE = '40001';
  END IF;
  IF target_account.archived_at IS NOT NULL THEN
    RAISE EXCEPTION 'tenant service account is already archived'
      USING ERRCODE = '55000';
  END IF;
  IF target_account.version >= 2147483647 THEN
    RAISE EXCEPTION 'tenant service-account version is exhausted'
      USING ERRCODE = '55000';
  END IF;

  next_version := target_account.version + 1;
  UPDATE public.tenant_service_accounts AS service_account
  SET archived_at = transaction_timestamp(),
      archived_by_membership_id = actor_membership,
      archive_reason = p_reason,
      version = next_version,
      updated_at = transaction_timestamp()
  WHERE service_account.tenant_id = context_tenant
    AND service_account.id = p_service_account_id;

  PERFORM app.append_tenant_authorization_audit(
    uuidv7(),
    'tenant.service_account.archived',
    'tenant_service_account',
    p_service_account_id,
    p_request_id,
    p_correlation_id,
    p_ip_address,
    p_user_agent,
    p_authentication_method,
    jsonb_build_object(
      'archived_at', NULL,
      'version', target_account.version
    ),
    jsonb_build_object(
      'archived_at', transaction_timestamp(),
      'reason', p_reason,
      'version', next_version
    ),
    jsonb_build_object('actor_membership_id', actor_membership)
  );

  RETURN next_version;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."list_tenant_service_account_role_grants_v1"(
  p_service_account_id uuid,
  p_after_id uuid,
  p_include_revoked boolean,
  p_limit integer
)
RETURNS TABLE (
  grant_id uuid,
  service_account_id uuid,
  role_id uuid,
  role_key text,
  role_display_name text,
  role_system boolean,
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
  IF NOT app.current_tenant_human_has_exact_permission_v3(
    'service_account.read', 'tenant'
  ) THEN
    RAISE EXCEPTION 'service_account.read tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_include_revoked IS NULL THEN
    RAISE EXCEPTION 'include revoked must be explicit'
      USING ERRCODE = '22023';
  END IF;
  IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 101 THEN
    RAISE EXCEPTION 'service-account role-grant page limit must be between 1 and 101'
      USING ERRCODE = '22023';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM public.tenant_service_accounts AS service_account
    WHERE service_account.tenant_id = context_tenant
      AND service_account.id = p_service_account_id
  ) THEN
    RAISE EXCEPTION 'tenant service account was not found'
      USING ERRCODE = 'P0002';
  END IF;

  RETURN QUERY
  SELECT role_grant.id,
         role_grant.service_account_id,
         role.id,
         role.key,
         role.display_name,
         role.system_role,
         source.id,
         source.kind,
         source.key,
         source.authoritative,
         source.retired_at,
         role_grant.granted_by_membership_id,
         grantor.user_id,
         role_grant.grant_reason,
         role_grant.granted_at,
         role_grant.expires_at,
         role_grant.revoked_at,
         role_grant.revoked_by_membership_id,
         revoker.user_id,
         role_grant.revoke_reason,
         CASE
           WHEN role_grant.revoked_at IS NOT NULL THEN 'revoked'
           WHEN role_grant.expires_at IS NOT NULL
             AND role_grant.expires_at <= transaction_timestamp()
             THEN 'expired'
           WHEN source.retired_at IS NOT NULL
             OR role.archived_at IS NOT NULL
             OR service_account.archived_at IS NOT NULL THEN 'expired'
           ELSE 'active'
         END,
         role_grant.version,
         role_grant.updated_at
  FROM public.tenant_service_account_role_grants AS role_grant
  JOIN public.tenant_service_accounts AS service_account
    ON service_account.tenant_id = role_grant.tenant_id
   AND service_account.id = role_grant.service_account_id
  JOIN public.tenant_roles AS role
    ON role.tenant_id = role_grant.tenant_id
   AND role.id = role_grant.role_id
   AND role.principal_kind = 'service_account'
  JOIN public.tenant_authorization_sources AS source
    ON source.tenant_id = role_grant.tenant_id
   AND source.id = role_grant.source_id
  JOIN public.tenant_memberships AS grantor
    ON grantor.tenant_id = role_grant.tenant_id
   AND grantor.id = role_grant.granted_by_membership_id
  LEFT JOIN public.tenant_memberships AS revoker
    ON revoker.tenant_id = role_grant.tenant_id
   AND revoker.id = role_grant.revoked_by_membership_id
  WHERE role_grant.tenant_id = context_tenant
    AND role_grant.service_account_id = p_service_account_id
    AND (p_include_revoked OR role_grant.revoked_at IS NULL)
    AND (p_after_id IS NULL OR role_grant.id > p_after_id)
  ORDER BY role_grant.id
  LIMIT p_limit;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."get_tenant_service_account_role_grant_v1"(
  p_service_account_id uuid,
  p_grant_id uuid
)
RETURNS TABLE (
  grant_id uuid,
  service_account_id uuid,
  role_id uuid,
  role_key text,
  role_display_name text,
  role_system boolean,
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
    app.current_tenant_human_has_exact_permission_v3(
      'service_account.read', 'tenant'
    )
    OR (
      app.current_tenant_human_has_exact_permission_v3(
        'service_account.manage', 'tenant'
      )
      AND app.current_tenant_human_has_exact_permission_v3(
        'role.grant', 'tenant'
      )
    )
  ) THEN
    RAISE EXCEPTION 'service-account role-grant read or mutation authority is required'
      USING ERRCODE = '42501';
  END IF;

  RETURN QUERY
  SELECT role_grant.id,
         role_grant.service_account_id,
         role.id,
         role.key,
         role.display_name,
         role.system_role,
         source.id,
         source.kind,
         source.key,
         source.authoritative,
         source.retired_at,
         role_grant.granted_by_membership_id,
         grantor.user_id,
         role_grant.grant_reason,
         role_grant.granted_at,
         role_grant.expires_at,
         role_grant.revoked_at,
         role_grant.revoked_by_membership_id,
         revoker.user_id,
         role_grant.revoke_reason,
         CASE
           WHEN role_grant.revoked_at IS NOT NULL THEN 'revoked'
           WHEN role_grant.expires_at IS NOT NULL
             AND role_grant.expires_at <= transaction_timestamp()
             THEN 'expired'
           WHEN source.retired_at IS NOT NULL
             OR role.archived_at IS NOT NULL
             OR service_account.archived_at IS NOT NULL THEN 'expired'
           ELSE 'active'
         END,
         role_grant.version,
         role_grant.updated_at
  FROM public.tenant_service_account_role_grants AS role_grant
  JOIN public.tenant_service_accounts AS service_account
    ON service_account.tenant_id = role_grant.tenant_id
   AND service_account.id = role_grant.service_account_id
  JOIN public.tenant_roles AS role
    ON role.tenant_id = role_grant.tenant_id
   AND role.id = role_grant.role_id
   AND role.principal_kind = 'service_account'
  JOIN public.tenant_authorization_sources AS source
    ON source.tenant_id = role_grant.tenant_id
   AND source.id = role_grant.source_id
  JOIN public.tenant_memberships AS grantor
    ON grantor.tenant_id = role_grant.tenant_id
   AND grantor.id = role_grant.granted_by_membership_id
  LEFT JOIN public.tenant_memberships AS revoker
    ON revoker.tenant_id = role_grant.tenant_id
   AND revoker.id = role_grant.revoked_by_membership_id
  WHERE role_grant.tenant_id = context_tenant
    AND role_grant.service_account_id = p_service_account_id
    AND role_grant.id = p_grant_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant service-account role grant was not found'
      USING ERRCODE = 'P0002';
  END IF;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."grant_tenant_service_account_role_v1"(
  p_grant_id uuid,
  p_service_account_id uuid,
  p_role_id uuid,
  p_reason text,
  p_expires_at timestamp with time zone,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE (
  result_resource_id uuid,
  result_version integer
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
  consequences_checked integer;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF NOT app.current_tenant_human_has_exact_permission_v3(
    'service_account.manage', 'tenant'
  ) THEN
    RAISE EXCEPTION 'service_account.manage tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  IF NOT app.current_tenant_human_has_exact_permission_v3(
    'role.grant', 'tenant'
  ) THEN
    RAISE EXCEPTION 'role.grant tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_grant_id IS NULL
     OR p_reason IS NULL OR btrim(p_reason) = ''
     OR char_length(p_reason) > 500 OR p_reason ~ '[[:cntrl:]]'
     OR (p_expires_at IS NOT NULL
       AND p_expires_at <= transaction_timestamp()) THEN
    RAISE EXCEPTION 'service-account role grant attributes are invalid'
      USING ERRCODE = '22023';
  END IF;

  PERFORM 1
  FROM public.tenant_service_accounts AS service_account
  WHERE service_account.tenant_id = context_tenant
    AND service_account.id = p_service_account_id
    AND service_account.archived_at IS NULL
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'live tenant service account was not found'
      USING ERRCODE = 'P0002';
  END IF;

  PERFORM 1
  FROM public.tenant_roles AS role
  WHERE role.tenant_id = context_tenant
    AND role.id = p_role_id
    AND role.principal_kind = 'service_account'
    AND role.archived_at IS NULL
  FOR KEY SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'live service-account role was not found'
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
    FROM public.tenant_service_account_role_grants AS expired_grant
    WHERE expired_grant.tenant_id = context_tenant
      AND expired_grant.service_account_id = p_service_account_id
      AND expired_grant.role_id = p_role_id
      AND expired_grant.source_id = manual_source
      AND expired_grant.revoked_at IS NULL
      AND expired_grant.expires_at <= transaction_timestamp()
      AND expired_grant.version >= 2147483647
  ) THEN
    RAISE EXCEPTION 'expired service-account role grant version is exhausted'
      USING ERRCODE = '55000';
  END IF;

  UPDATE public.tenant_service_account_role_grants AS expired_grant
  SET revoked_at = transaction_timestamp(),
      revoked_by_membership_id = actor_membership,
      revoke_reason = 'Superseded after the prior manual service-account role grant expired.',
      version = expired_grant.version + 1,
      updated_at = transaction_timestamp()
  WHERE expired_grant.tenant_id = context_tenant
    AND expired_grant.service_account_id = p_service_account_id
    AND expired_grant.role_id = p_role_id
    AND expired_grant.source_id = manual_source
    AND expired_grant.revoked_at IS NULL
    AND expired_grant.expires_at <= transaction_timestamp();

  IF EXISTS (
    SELECT 1
    FROM public.tenant_service_account_role_grants AS existing_grant
    WHERE existing_grant.tenant_id = context_tenant
      AND existing_grant.service_account_id = p_service_account_id
      AND existing_grant.role_id = p_role_id
      AND existing_grant.source_id = manual_source
      AND existing_grant.revoked_at IS NULL
  ) THEN
    RAISE EXCEPTION 'an active manual service-account role grant already exists'
      USING ERRCODE = '23505',
            CONSTRAINT = 'tenant_service_account_role_grants_active_key';
  END IF;

  consequences_checked :=
    app.assert_actor_can_change_service_account_role_grant_v1(
      p_role_id, p_expires_at
    );

  INSERT INTO public.tenant_service_account_role_grants (
    id, tenant_id, service_account_id, role_id, role_principal_kind,
    source_id, granted_by_membership_id, grant_reason, expires_at
  ) VALUES (
    p_grant_id, context_tenant, p_service_account_id, p_role_id,
    'service_account', manual_source, actor_membership, p_reason, p_expires_at
  );

  PERFORM app.append_tenant_authorization_audit(
    uuidv7(),
    'tenant.service_account.role_granted',
    'tenant_service_account_role_grant',
    p_grant_id,
    p_request_id,
    p_correlation_id,
    p_ip_address,
    p_user_agent,
    p_authentication_method,
    NULL,
    jsonb_build_object(
      'service_account_id', p_service_account_id,
      'role_id', p_role_id,
      'source_id', manual_source,
      'reason', p_reason,
      'expires_at', p_expires_at,
      'version', 1
    ),
    jsonb_build_object(
      'actor_membership_id', actor_membership,
      'exact_consequences_checked', consequences_checked
    )
  );

  RETURN QUERY SELECT p_grant_id, 1::integer;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."revoke_tenant_service_account_role_grant_v1"(
  p_service_account_id uuid,
  p_grant_id uuid,
  p_expected_version integer,
  p_reason text,
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
  consequences_checked integer;
  next_version integer;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF NOT app.current_tenant_human_has_exact_permission_v3(
    'service_account.manage', 'tenant'
  ) THEN
    RAISE EXCEPTION 'service_account.manage tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  IF NOT app.current_tenant_human_has_exact_permission_v3(
    'role.grant', 'tenant'
  ) THEN
    RAISE EXCEPTION 'role.grant tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_reason IS NULL OR btrim(p_reason) = ''
     OR char_length(p_reason) > 500 OR p_reason ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION 'service-account role revoke reason is invalid'
      USING ERRCODE = '22023';
  END IF;

  SELECT role_grant.* INTO target_grant
  FROM public.tenant_service_account_role_grants AS role_grant
  JOIN public.tenant_service_accounts AS service_account
    ON service_account.tenant_id = role_grant.tenant_id
   AND service_account.id = role_grant.service_account_id
   AND service_account.archived_at IS NULL
  JOIN public.tenant_roles AS role
    ON role.tenant_id = role_grant.tenant_id
   AND role.id = role_grant.role_id
   AND role.principal_kind = 'service_account'
   AND role.archived_at IS NULL
  JOIN public.tenant_authorization_sources AS source
    ON source.tenant_id = role_grant.tenant_id
   AND source.id = role_grant.source_id
   AND source.key = 'manual'
   AND source.kind = 'manual'
   AND source.protected
   AND source.retired_at IS NULL
  WHERE role_grant.tenant_id = context_tenant
    AND role_grant.service_account_id = p_service_account_id
    AND role_grant.id = p_grant_id
    AND role_grant.revoked_at IS NULL
    AND (role_grant.expires_at IS NULL
      OR role_grant.expires_at > transaction_timestamp())
  FOR UPDATE OF role_grant;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'live manual service-account role grant was not found'
      USING ERRCODE = 'P0002';
  END IF;
  IF target_grant.version IS DISTINCT FROM p_expected_version THEN
    RAISE EXCEPTION 'service-account role grant version conflict'
      USING ERRCODE = '40001';
  END IF;
  IF target_grant.version >= 2147483647 THEN
    RAISE EXCEPTION 'service-account role grant version is exhausted'
      USING ERRCODE = '55000';
  END IF;

  consequences_checked :=
    app.assert_actor_can_change_service_account_role_grant_v1(
      target_grant.role_id, target_grant.expires_at
    );

  next_version := target_grant.version + 1;
  UPDATE public.tenant_service_account_role_grants AS role_grant
  SET revoked_at = transaction_timestamp(),
      revoked_by_membership_id = actor_membership,
      revoke_reason = p_reason,
      version = next_version,
      updated_at = transaction_timestamp()
  WHERE role_grant.tenant_id = context_tenant
    AND role_grant.service_account_id = p_service_account_id
    AND role_grant.id = p_grant_id;

  PERFORM app.append_tenant_authorization_audit(
    uuidv7(),
    'tenant.service_account.role_revoked',
    'tenant_service_account_role_grant',
    p_grant_id,
    p_request_id,
    p_correlation_id,
    p_ip_address,
    p_user_agent,
    p_authentication_method,
    jsonb_build_object(
      'revoked_at', NULL,
      'version', target_grant.version
    ),
    jsonb_build_object(
      'revoked_at', transaction_timestamp(),
      'reason', p_reason,
      'version', next_version
    ),
    jsonb_build_object(
      'service_account_id', p_service_account_id,
      'role_id', target_grant.role_id,
      'actor_membership_id', actor_membership,
      'exact_consequences_checked', consequences_checked
    )
  );

  RETURN next_version;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."list_tenant_api_credentials_v1"(
  p_service_account_id uuid,
  p_after_id uuid,
  p_include_revoked boolean,
  p_limit integer
)
RETURNS TABLE (
  credential_id uuid,
  service_account_id uuid,
  label text,
  format_version integer,
  key_version integer,
  issued_by_membership_id uuid,
  issued_by_user_id uuid,
  issued_at timestamp with time zone,
  expires_at timestamp with time zone,
  rotated_from_credential_id uuid,
  revoked_at timestamp with time zone,
  revoked_by_membership_id uuid,
  revoked_by_user_id uuid,
  revoke_reason text,
  last_used_at timestamp with time zone,
  last_used_ip inet,
  version integer,
  updated_at timestamp with time zone,
  permission_keys text[],
  permission_scopes "public"."authorization_scope"[],
  networks cidr[]
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
  IF NOT app.current_tenant_human_has_exact_permission_v3(
    'service_account.read', 'tenant'
  ) THEN
    RAISE EXCEPTION 'service_account.read tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_include_revoked IS NULL THEN
    RAISE EXCEPTION 'include revoked must be explicit'
      USING ERRCODE = '22023';
  END IF;
  IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 101 THEN
    RAISE EXCEPTION 'API credential page limit must be between 1 and 101'
      USING ERRCODE = '22023';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM public.tenant_service_accounts AS service_account
    WHERE service_account.tenant_id = context_tenant
      AND service_account.id = p_service_account_id
  ) THEN
    RAISE EXCEPTION 'tenant service account was not found'
      USING ERRCODE = 'P0002';
  END IF;

  RETURN QUERY
  SELECT credential.id,
         credential.service_account_id,
         credential.label,
         credential.format_version,
         credential.key_version,
         credential.issued_by_membership_id,
         issuer.user_id,
         credential.issued_at,
         credential.expires_at,
         credential.rotated_from_credential_id,
         credential.revoked_at,
         credential.revoked_by_membership_id,
         revoker.user_id,
         credential.revoke_reason,
         credential.last_used_at,
         credential.last_used_ip,
         credential.version,
         credential.updated_at,
         ARRAY(
           SELECT permission.key
           FROM public.tenant_api_credential_permissions AS allowlist
           JOIN public.tenant_permissions AS permission
             ON permission.id = allowlist.permission_id
           WHERE allowlist.tenant_id = credential.tenant_id
             AND allowlist.credential_id = credential.id
           ORDER BY permission.key, allowlist.scope
         ),
         ARRAY(
           SELECT allowlist.scope
           FROM public.tenant_api_credential_permissions AS allowlist
           JOIN public.tenant_permissions AS permission
             ON permission.id = allowlist.permission_id
           WHERE allowlist.tenant_id = credential.tenant_id
             AND allowlist.credential_id = credential.id
           ORDER BY permission.key, allowlist.scope
         )::public.authorization_scope[],
         ARRAY(
           SELECT credential_network.network
           FROM public.tenant_api_credential_networks AS credential_network
           WHERE credential_network.tenant_id = credential.tenant_id
             AND credential_network.credential_id = credential.id
           ORDER BY credential_network.network
         )::cidr[]
  FROM public.tenant_api_credentials AS credential
  JOIN public.tenant_memberships AS issuer
    ON issuer.tenant_id = credential.tenant_id
   AND issuer.id = credential.issued_by_membership_id
  LEFT JOIN public.tenant_memberships AS revoker
    ON revoker.tenant_id = credential.tenant_id
   AND revoker.id = credential.revoked_by_membership_id
  WHERE credential.tenant_id = context_tenant
    AND credential.service_account_id = p_service_account_id
    AND (p_include_revoked OR credential.revoked_at IS NULL)
    AND (p_after_id IS NULL OR credential.id > p_after_id)
  ORDER BY credential.id
  LIMIT p_limit;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."get_tenant_api_credential_v1"(
  p_service_account_id uuid,
  p_credential_id uuid
)
RETURNS TABLE (
  credential_id uuid,
  service_account_id uuid,
  label text,
  format_version integer,
  key_version integer,
  issued_by_membership_id uuid,
  issued_by_user_id uuid,
  issued_at timestamp with time zone,
  expires_at timestamp with time zone,
  rotated_from_credential_id uuid,
  revoked_at timestamp with time zone,
  revoked_by_membership_id uuid,
  revoked_by_user_id uuid,
  revoke_reason text,
  last_used_at timestamp with time zone,
  last_used_ip inet,
  version integer,
  updated_at timestamp with time zone,
  permission_keys text[],
  permission_scopes "public"."authorization_scope"[],
  networks cidr[]
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
    app.current_tenant_human_has_exact_permission_v3(
      'service_account.read', 'tenant'
    )
    OR app.current_tenant_human_has_exact_permission_v3(
      'service_account.credential.manage', 'tenant'
    )
  ) THEN
    RAISE EXCEPTION 'service-account credential read or mutation authority is required'
      USING ERRCODE = '42501';
  END IF;

  RETURN QUERY
  SELECT credential.id,
         credential.service_account_id,
         credential.label,
         credential.format_version,
         credential.key_version,
         credential.issued_by_membership_id,
         issuer.user_id,
         credential.issued_at,
         credential.expires_at,
         credential.rotated_from_credential_id,
         credential.revoked_at,
         credential.revoked_by_membership_id,
         revoker.user_id,
         credential.revoke_reason,
         credential.last_used_at,
         credential.last_used_ip,
         credential.version,
         credential.updated_at,
         ARRAY(
           SELECT permission.key
           FROM public.tenant_api_credential_permissions AS allowlist
           JOIN public.tenant_permissions AS permission
             ON permission.id = allowlist.permission_id
           WHERE allowlist.tenant_id = credential.tenant_id
             AND allowlist.credential_id = credential.id
           ORDER BY permission.key, allowlist.scope
         ),
         ARRAY(
           SELECT allowlist.scope
           FROM public.tenant_api_credential_permissions AS allowlist
           JOIN public.tenant_permissions AS permission
             ON permission.id = allowlist.permission_id
           WHERE allowlist.tenant_id = credential.tenant_id
             AND allowlist.credential_id = credential.id
           ORDER BY permission.key, allowlist.scope
         )::public.authorization_scope[],
         ARRAY(
           SELECT credential_network.network
           FROM public.tenant_api_credential_networks AS credential_network
           WHERE credential_network.tenant_id = credential.tenant_id
             AND credential_network.credential_id = credential.id
           ORDER BY credential_network.network
         )::cidr[]
  FROM public.tenant_api_credentials AS credential
  JOIN public.tenant_memberships AS issuer
    ON issuer.tenant_id = credential.tenant_id
   AND issuer.id = credential.issued_by_membership_id
  LEFT JOIN public.tenant_memberships AS revoker
    ON revoker.tenant_id = credential.tenant_id
   AND revoker.id = credential.revoked_by_membership_id
  WHERE credential.tenant_id = context_tenant
    AND credential.service_account_id = p_service_account_id
    AND credential.id = p_credential_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant API credential was not found'
      USING ERRCODE = 'P0002';
  END IF;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."issue_tenant_api_credential_v1"(
  p_credential_id uuid,
  p_service_account_id uuid,
  p_key_digest bytea,
  p_request_digest bytea,
  p_label text,
  p_format_version integer,
  p_locator bytea,
  p_key_version integer,
  p_secret_digest bytea,
  p_expires_at timestamp with time zone,
  p_permission_keys text[],
  p_scopes "public"."authorization_scope"[],
  p_networks cidr[],
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE (
  result_credential_id uuid,
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
  replay record;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF NOT app.current_tenant_human_has_exact_permission_v3(
    'service_account.credential.manage', 'tenant'
  ) THEN
    RAISE EXCEPTION 'service_account.credential.manage tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_key_digest IS NULL OR NOT (octet_length(p_key_digest) = 32)
     OR p_request_digest IS NULL
     OR NOT (octet_length(p_request_digest) = 32) THEN
    RAISE EXCEPTION 'credential idempotency and request digests must be SHA-256'
      USING ERRCODE = '22023';
  END IF;
  IF p_format_version IS DISTINCT FROM 1
     OR p_locator IS NULL OR octet_length(p_locator) <> 16
     OR p_key_version IS NULL OR p_key_version NOT BETWEEN 1 AND 32767
     OR p_secret_digest IS NULL OR octet_length(p_secret_digest) <> 32 THEN
    RAISE EXCEPTION 'API credential envelope material is invalid'
      USING ERRCODE = '22023';
  END IF;
  PERFORM app.assert_tenant_api_credential_request_shape_v1(
    p_permission_keys, p_scopes, p_networks
  );

  PERFORM 1
  FROM public.tenant_service_accounts AS service_account
  WHERE service_account.tenant_id = context_tenant
    AND service_account.id = p_service_account_id
    AND service_account.archived_at IS NULL
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'live tenant service account was not found'
      USING ERRCODE = 'P0002';
  END IF;

  SELECT command.* INTO replay
  FROM public.tenant_api_credential_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.actor_membership_id = actor_membership
    AND command.service_account_id = p_service_account_id
    AND command.operation = 'service_account.credential.issue'
    AND command.key_digest = p_key_digest
  FOR UPDATE;
  IF FOUND THEN
    IF replay.request_digest IS DISTINCT FROM p_request_digest THEN
      RAISE EXCEPTION 'credential idempotency key was already used for a different request'
        USING ERRCODE = '23505',
              CONSTRAINT = 'tenant_api_credential_commands_replay_key';
    END IF;
    RETURN QUERY
    SELECT replay.result_credential_id, replay.result_version, true;
    RETURN;
  END IF;

  IF p_credential_id IS NULL
     OR p_label IS NULL OR btrim(p_label) = ''
     OR char_length(p_label) > 120 OR p_label ~ '[[:cntrl:]]'
     OR p_expires_at IS NULL
     OR p_expires_at <= transaction_timestamp()
     OR p_expires_at > transaction_timestamp() + interval '90 days' THEN
    RAISE EXCEPTION 'API credential material or lifecycle is invalid'
      USING ERRCODE = '22023';
  END IF;

  PERFORM app.assert_tenant_api_credential_policy_v1(
    context_tenant,
    p_service_account_id,
    p_permission_keys,
    p_scopes,
    p_networks
  );

  INSERT INTO public.tenant_api_credentials (
    id, tenant_id, service_account_id, label, format_version, locator,
    key_version, secret_digest, issued_by_membership_id, issued_at,
    expires_at
  ) VALUES (
    p_credential_id, context_tenant, p_service_account_id, p_label,
    p_format_version, p_locator, p_key_version, p_secret_digest,
    actor_membership, transaction_timestamp(), p_expires_at
  );

  INSERT INTO public.tenant_api_credential_permissions (
    tenant_id, credential_id, permission_id,
    permission_service_account_allowed, scope
  )
  SELECT context_tenant, p_credential_id, permission.id, true,
         requested.scope
  FROM unnest(p_permission_keys, p_scopes)
    AS requested(permission_key, scope)
  JOIN public.tenant_permissions AS permission
    ON permission.key = requested.permission_key
   AND permission.service_account_allowed;

  INSERT INTO public.tenant_api_credential_networks (
    tenant_id, credential_id, network
  )
  SELECT context_tenant, p_credential_id, allowed_network.network
  FROM unnest(p_networks) AS allowed_network(network);

  PERFORM app.append_tenant_authorization_audit(
    uuidv7(),
    'tenant.service_account.credential_issued',
    'tenant_api_credential',
    p_credential_id,
    p_request_id,
    p_correlation_id,
    p_ip_address,
    p_user_agent,
    p_authentication_method,
    NULL,
    jsonb_build_object(
      'service_account_id', p_service_account_id,
      'label', p_label,
      'format_version', p_format_version,
      'key_version', p_key_version,
      'expires_at', p_expires_at,
      'permission_count', cardinality(p_permission_keys),
      'network_count', cardinality(p_networks),
      'version', 1
    ),
    jsonb_build_object(
      'actor_membership_id', actor_membership,
      'secret_material_archived', false
    )
  );

  -- The command is a permanent payload-bound tombstone. It contains no
  -- locator, HMAC digest, token, or recoverable secret.
  INSERT INTO public.tenant_api_credential_commands (
    tenant_id, service_account_id, actor_membership_id, operation,
    key_digest, request_digest, result_credential_id, result_version
  ) VALUES (
    context_tenant, p_service_account_id, actor_membership,
    'service_account.credential.issue', p_key_digest, p_request_digest,
    p_credential_id, 1
  );

  RETURN QUERY SELECT p_credential_id, 1::integer, false;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."rotate_tenant_api_credential_v1"(
  p_replacement_credential_id uuid,
  p_service_account_id uuid,
  p_rotated_from_credential_id uuid,
  p_expected_version integer,
  p_key_digest bytea,
  p_request_digest bytea,
  p_label text,
  p_format_version integer,
  p_locator bytea,
  p_key_version integer,
  p_secret_digest bytea,
  p_expires_at timestamp with time zone,
  p_permission_keys text[],
  p_scopes "public"."authorization_scope"[],
  p_networks cidr[],
  p_rotation_reason text,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE (
  result_credential_id uuid,
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
  replay record;
  predecessor record;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF NOT app.current_tenant_human_has_exact_permission_v3(
    'service_account.credential.manage', 'tenant'
  ) THEN
    RAISE EXCEPTION 'service_account.credential.manage tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_key_digest IS NULL OR NOT (octet_length(p_key_digest) = 32)
     OR p_request_digest IS NULL
     OR NOT (octet_length(p_request_digest) = 32) THEN
    RAISE EXCEPTION 'credential idempotency and request digests must be SHA-256'
      USING ERRCODE = '22023';
  END IF;
  IF p_format_version IS DISTINCT FROM 1
     OR p_locator IS NULL OR octet_length(p_locator) <> 16
     OR p_key_version IS NULL OR p_key_version NOT BETWEEN 1 AND 32767
     OR p_secret_digest IS NULL OR octet_length(p_secret_digest) <> 32 THEN
    RAISE EXCEPTION 'API credential rotation envelope material is invalid'
      USING ERRCODE = '22023';
  END IF;
  PERFORM app.assert_tenant_api_credential_request_shape_v1(
    p_permission_keys, p_scopes, p_networks
  );

  PERFORM 1
  FROM public.tenant_service_accounts AS service_account
  WHERE service_account.tenant_id = context_tenant
    AND service_account.id = p_service_account_id
    AND service_account.archived_at IS NULL
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'live tenant service account was not found'
      USING ERRCODE = 'P0002';
  END IF;

  SELECT command.* INTO replay
  FROM public.tenant_api_credential_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.actor_membership_id = actor_membership
    AND command.service_account_id = p_service_account_id
    AND command.operation = 'service_account.credential.rotate'
    AND command.key_digest = p_key_digest
  FOR UPDATE;
  IF FOUND THEN
    IF replay.request_digest IS DISTINCT FROM p_request_digest THEN
      RAISE EXCEPTION 'credential idempotency key was already used for a different request'
        USING ERRCODE = '23505',
              CONSTRAINT = 'tenant_api_credential_commands_replay_key';
    END IF;
    RETURN QUERY
    SELECT replay.result_credential_id, replay.result_version, true;
    RETURN;
  END IF;

  IF p_replacement_credential_id IS NULL
     OR p_rotated_from_credential_id IS NULL
     OR p_replacement_credential_id = p_rotated_from_credential_id
     OR p_label IS NULL OR btrim(p_label) = ''
     OR char_length(p_label) > 120 OR p_label ~ '[[:cntrl:]]'
     OR p_expires_at IS NULL
     OR p_expires_at <= transaction_timestamp()
     OR p_expires_at > transaction_timestamp() + interval '90 days'
     OR p_rotation_reason IS NULL OR btrim(p_rotation_reason) = ''
     OR char_length(p_rotation_reason) > 500
     OR p_rotation_reason ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION 'API credential rotation material or lifecycle is invalid'
      USING ERRCODE = '22023';
  END IF;

  SELECT credential.* INTO predecessor
  FROM public.tenant_api_credentials AS credential
  WHERE credential.tenant_id = context_tenant
    AND credential.service_account_id = p_service_account_id
    AND credential.id = p_rotated_from_credential_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'predecessor tenant API credential was not found'
      USING ERRCODE = 'P0002';
  END IF;
  IF predecessor.version IS DISTINCT FROM p_expected_version THEN
    RAISE EXCEPTION 'tenant API credential version conflict'
      USING ERRCODE = '40001';
  END IF;
  IF predecessor.revoked_at IS NOT NULL
     OR predecessor.expires_at <= transaction_timestamp() THEN
    RAISE EXCEPTION 'only a live tenant API credential can be rotated'
      USING ERRCODE = '55000';
  END IF;
  IF predecessor.version >= 2147483647 THEN
    RAISE EXCEPTION 'tenant API credential version is exhausted'
      USING ERRCODE = '55000';
  END IF;

  PERFORM app.assert_tenant_api_credential_policy_v1(
    context_tenant,
    p_service_account_id,
    p_permission_keys,
    p_scopes,
    p_networks
  );

  INSERT INTO public.tenant_api_credentials (
    id, tenant_id, service_account_id, label, format_version, locator,
    key_version, secret_digest, issued_by_membership_id, issued_at,
    expires_at, rotated_from_credential_id
  ) VALUES (
    p_replacement_credential_id, context_tenant, p_service_account_id,
    p_label, p_format_version, p_locator, p_key_version, p_secret_digest,
    actor_membership, transaction_timestamp(), p_expires_at,
    p_rotated_from_credential_id
  );

  INSERT INTO public.tenant_api_credential_permissions (
    tenant_id, credential_id, permission_id,
    permission_service_account_allowed, scope
  )
  SELECT context_tenant, p_replacement_credential_id, permission.id, true,
         requested.scope
  FROM unnest(p_permission_keys, p_scopes)
    AS requested(permission_key, scope)
  JOIN public.tenant_permissions AS permission
    ON permission.key = requested.permission_key
   AND permission.service_account_allowed;

  INSERT INTO public.tenant_api_credential_networks (
    tenant_id, credential_id, network
  )
  SELECT context_tenant, p_replacement_credential_id,
         allowed_network.network
  FROM unnest(p_networks) AS allowed_network(network);

  UPDATE public.tenant_api_credentials AS credential
  SET revoked_at = transaction_timestamp(),
      revoked_by_membership_id = actor_membership,
      revoke_reason = p_rotation_reason,
      version = predecessor.version + 1,
      updated_at = transaction_timestamp()
  WHERE credential.tenant_id = context_tenant
    AND credential.service_account_id = p_service_account_id
    AND credential.id = p_rotated_from_credential_id;

  PERFORM app.append_tenant_authorization_audit(
    uuidv7(),
    'tenant.service_account.credential_rotated',
    'tenant_api_credential',
    p_replacement_credential_id,
    p_request_id,
    p_correlation_id,
    p_ip_address,
    p_user_agent,
    p_authentication_method,
    jsonb_build_object(
      'predecessor_credential_id', p_rotated_from_credential_id,
      'predecessor_version', predecessor.version
    ),
    jsonb_build_object(
      'service_account_id', p_service_account_id,
      'replacement_credential_id', p_replacement_credential_id,
      'label', p_label,
      'format_version', p_format_version,
      'key_version', p_key_version,
      'expires_at', p_expires_at,
      'permission_count', cardinality(p_permission_keys),
      'network_count', cardinality(p_networks),
      'replacement_version', 1,
      'predecessor_result_version', predecessor.version + 1
    ),
    jsonb_build_object(
      'actor_membership_id', actor_membership,
      'secret_material_archived', false
    )
  );

  INSERT INTO public.tenant_api_credential_commands (
    tenant_id, service_account_id, actor_membership_id, operation,
    key_digest, request_digest, result_credential_id, result_version
  ) VALUES (
    context_tenant, p_service_account_id, actor_membership,
    'service_account.credential.rotate', p_key_digest, p_request_digest,
    p_replacement_credential_id, 1
  );

  RETURN QUERY SELECT p_replacement_credential_id, 1::integer, false;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."revoke_tenant_api_credential_v1"(
  p_service_account_id uuid,
  p_credential_id uuid,
  p_expected_version integer,
  p_reason text,
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
  target_credential record;
  next_version integer;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF NOT app.current_tenant_human_has_exact_permission_v3(
    'service_account.credential.manage', 'tenant'
  ) THEN
    RAISE EXCEPTION 'service_account.credential.manage tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_reason IS NULL OR btrim(p_reason) = ''
     OR char_length(p_reason) > 500 OR p_reason ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION 'API credential revoke reason is invalid'
      USING ERRCODE = '22023';
  END IF;

  PERFORM 1
  FROM public.tenant_service_accounts AS service_account
  WHERE service_account.tenant_id = context_tenant
    AND service_account.id = p_service_account_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant service account was not found'
      USING ERRCODE = 'P0002';
  END IF;

  SELECT credential.* INTO target_credential
  FROM public.tenant_api_credentials AS credential
  WHERE credential.tenant_id = context_tenant
    AND credential.service_account_id = p_service_account_id
    AND credential.id = p_credential_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant API credential was not found'
      USING ERRCODE = 'P0002';
  END IF;
  IF target_credential.version IS DISTINCT FROM p_expected_version THEN
    RAISE EXCEPTION 'tenant API credential version conflict'
      USING ERRCODE = '40001';
  END IF;
  IF target_credential.revoked_at IS NOT NULL THEN
    RAISE EXCEPTION 'tenant API credential is already revoked'
      USING ERRCODE = '55000';
  END IF;
  IF target_credential.version >= 2147483647 THEN
    RAISE EXCEPTION 'tenant API credential version is exhausted'
      USING ERRCODE = '55000';
  END IF;

  next_version := target_credential.version + 1;
  UPDATE public.tenant_api_credentials AS credential
  SET revoked_at = transaction_timestamp(),
      revoked_by_membership_id = actor_membership,
      revoke_reason = p_reason,
      version = next_version,
      updated_at = transaction_timestamp()
  WHERE credential.tenant_id = context_tenant
    AND credential.service_account_id = p_service_account_id
    AND credential.id = p_credential_id;

  PERFORM app.append_tenant_authorization_audit(
    uuidv7(),
    'tenant.service_account.credential_revoked',
    'tenant_api_credential',
    p_credential_id,
    p_request_id,
    p_correlation_id,
    p_ip_address,
    p_user_agent,
    p_authentication_method,
    jsonb_build_object(
      'revoked_at', NULL,
      'version', target_credential.version
    ),
    jsonb_build_object(
      'revoked_at', transaction_timestamp(),
      'reason', p_reason,
      'version', next_version
    ),
    jsonb_build_object(
      'service_account_id', p_service_account_id,
      'actor_membership_id', actor_membership,
      'key_version', target_credential.key_version
    )
  );

  RETURN next_version;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."create_tenant_alert_as_human_v1"(
  p_title text,
  p_description text,
  p_external_id text,
  p_severity "public"."alert_severity",
  p_key_digest bytea,
  p_request_digest bytea,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE (
  id uuid,
  external_id text,
  title text,
  description text,
  status "public"."alert_status",
  severity "public"."alert_severity",
  created_by_user_id uuid,
  created_by_membership_id uuid,
  created_by_service_account_id uuid,
  created_at timestamp with time zone,
  updated_at timestamp with time zone,
  version integer,
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
  replay record;
  created_alert_id uuid;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF NOT app.current_tenant_human_has_exact_permission_v3(
    'alert.create', 'tenant'
  ) THEN
    RAISE EXCEPTION 'alert.create tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_title IS NULL OR btrim(p_title) = ''
     OR char_length(p_title) > 240 OR p_title ~ '[[:cntrl:]]'
     OR (p_description IS NOT NULL AND (
       char_length(p_description) > 10000
       OR p_description ~ '[[:cntrl:]]'
     ))
     OR (p_external_id IS NOT NULL AND (
       btrim(p_external_id) = ''
       OR char_length(p_external_id) > 200
       OR p_external_id ~ '[[:cntrl:]]'
     ))
     OR p_severity IS NULL THEN
    RAISE EXCEPTION 'Alert payload violates the bounded canonical contract'
      USING ERRCODE = '22023';
  END IF;
  IF p_key_digest IS NULL OR NOT (octet_length(p_key_digest) = 32)
     OR p_request_digest IS NULL
     OR NOT (octet_length(p_request_digest) = 32) THEN
    RAISE EXCEPTION 'Alert idempotency and request digests must be SHA-256'
      USING ERRCODE = '22023';
  END IF;

  SELECT command.* INTO replay
  FROM public.alert_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.operation = 'alert.create'
    AND command.principal_kind = 'human'
    AND command.actor_membership_id = actor_membership
    AND command.key_digest = p_key_digest
  FOR UPDATE;
  IF FOUND THEN
    IF replay.request_digest IS DISTINCT FROM p_request_digest THEN
      RAISE EXCEPTION 'Alert idempotency key was already used for a different request'
        USING ERRCODE = '23505',
              CONSTRAINT = 'alert_commands_human_replay_key';
    END IF;
    RETURN QUERY
    SELECT alert_row.id,
           alert_row.external_id,
           alert_row.title,
           alert_row.description,
           alert_row.status,
           alert_row.severity,
           alert_row.created_by,
           alert_row.created_by_membership_id,
           alert_row.created_by_service_account_id,
           alert_row.created_at,
           alert_row.updated_at,
           alert_row.version,
           true
    FROM public.alerts AS alert_row
    WHERE alert_row.tenant_id = context_tenant
      AND alert_row.id = replay.result_alert_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'Alert command result is missing'
        USING ERRCODE = '55000';
    END IF;
    RETURN;
  END IF;

  INSERT INTO public.alerts (
    id, tenant_id, external_id, title, description, status, severity,
    created_by, created_by_membership_id, created_by_service_account_id,
    version
  ) VALUES (
    uuidv7(), context_tenant, p_external_id, p_title, p_description,
    'new', p_severity, actor_id, actor_membership, NULL, 1
  ) RETURNING alerts.id INTO created_alert_id;

  INSERT INTO public.alert_activities (
    tenant_id, alert_id, sequence, activity_type,
    actor_principal_kind, actor_membership_id,
    actor_service_account_id, metadata
  ) VALUES (
    context_tenant, created_alert_id, 1, 'alert.created',
    'human', actor_membership, NULL,
    jsonb_build_object('severity', p_severity, 'version', 1)
  );

  PERFORM app.append_tenant_authorization_audit(
    uuidv7(),
    'tenant.alert.created',
    'alert',
    created_alert_id,
    p_request_id,
    p_correlation_id,
    p_ip_address,
    p_user_agent,
    p_authentication_method,
    NULL,
    jsonb_build_object(
      'status', 'new',
      'severity', p_severity,
      'version', 1
    ),
    jsonb_build_object(
      'actor_membership_id', actor_membership,
      'content_redacted', true
    )
  );

  INSERT INTO public.outbox_events (
    tenant_id, aggregate_type, aggregate_id, event_type, schema_version,
    payload, deduplication_key, correlation_id, causation_id
  ) VALUES (
    context_tenant, 'alert', created_alert_id, 'alert.created', 1,
    jsonb_build_object(
      'alert_id', created_alert_id,
      'principal_kind', 'human',
      'version', 1
    ),
    'alert.created:' || created_alert_id::text,
    p_correlation_id,
    p_request_id
  );

  INSERT INTO public.alert_commands (
    tenant_id, operation, principal_kind, actor_membership_id,
    actor_service_account_id, key_digest, request_digest,
    result_alert_id, result_version
  ) VALUES (
    context_tenant, 'alert.create', 'human', actor_membership, NULL,
    p_key_digest, p_request_digest, created_alert_id, 1
  );

  RETURN QUERY
  SELECT alert_row.id,
         alert_row.external_id,
         alert_row.title,
         alert_row.description,
         alert_row.status,
         alert_row.severity,
         alert_row.created_by,
         alert_row.created_by_membership_id,
         alert_row.created_by_service_account_id,
         alert_row.created_at,
         alert_row.updated_at,
         alert_row.version,
         false
  FROM public.alerts AS alert_row
  WHERE alert_row.tenant_id = context_tenant
    AND alert_row.id = created_alert_id;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."create_tenant_alert_as_service_account_v1"(
  p_tenant_id uuid,
  p_locator bytea,
  p_envelope_key_version integer,
  p_secret_digest bytea,
  p_client_address inet,
  p_title text,
  p_description text,
  p_external_id text,
  p_severity "public"."alert_severity",
  p_key_digest bytea,
  p_request_digest bytea,
  p_request_id uuid,
  p_correlation_id uuid,
  p_user_agent text
)
RETURNS TABLE (
  id uuid,
  external_id text,
  title text,
  description text,
  status "public"."alert_status",
  severity "public"."alert_severity",
  created_by_user_id uuid,
  created_by_membership_id uuid,
  created_by_service_account_id uuid,
  created_at timestamp with time zone,
  updated_at timestamp with time zone,
  version integer,
  replayed boolean
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  authenticated record;
  replay record;
  created_alert_id uuid;
BEGIN
  -- This private helper validates tenant/path binding and retains the fixed
  -- authorization/account/credential locks through every side effect below.
  SELECT proof.* INTO authenticated
  FROM app.authenticate_tenant_api_credential_v1(
    p_tenant_id,
    p_locator,
    p_envelope_key_version,
    p_secret_digest,
    p_client_address,
    'alert.create',
    'tenant'
  ) AS proof;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant API credential authentication failed'
      USING ERRCODE = '28000';
  END IF;

  IF p_title IS NULL OR btrim(p_title) = ''
     OR char_length(p_title) > 240 OR p_title ~ '[[:cntrl:]]'
     OR (p_description IS NOT NULL AND (
       char_length(p_description) > 10000
       OR p_description ~ '[[:cntrl:]]'
     ))
     OR (p_external_id IS NOT NULL AND (
       btrim(p_external_id) = ''
       OR char_length(p_external_id) > 200
       OR p_external_id ~ '[[:cntrl:]]'
     ))
     OR p_severity IS NULL THEN
    RAISE EXCEPTION 'Alert payload violates the bounded canonical contract'
      USING ERRCODE = '22023';
  END IF;
  IF p_key_digest IS NULL OR NOT (octet_length(p_key_digest) = 32)
     OR p_request_digest IS NULL
     OR NOT (octet_length(p_request_digest) = 32) THEN
    RAISE EXCEPTION 'Alert idempotency and request digests must be SHA-256'
      USING ERRCODE = '22023';
  END IF;

  SELECT command.* INTO replay
  FROM public.alert_commands AS command
  WHERE command.tenant_id = p_tenant_id
    AND command.operation = 'alert.create'
    AND command.principal_kind = 'service_account'
    AND command.actor_service_account_id = authenticated.service_account_id
    AND command.key_digest = p_key_digest
  FOR UPDATE;
  IF FOUND THEN
    IF replay.request_digest IS DISTINCT FROM p_request_digest THEN
      RAISE EXCEPTION 'Alert idempotency key was already used for a different request'
        USING ERRCODE = '23505',
              CONSTRAINT = 'alert_commands_service_account_replay_key';
    END IF;
    RETURN QUERY
    SELECT alert_row.id,
           alert_row.external_id,
           alert_row.title,
           alert_row.description,
           alert_row.status,
           alert_row.severity,
           alert_row.created_by,
           alert_row.created_by_membership_id,
           alert_row.created_by_service_account_id,
           alert_row.created_at,
           alert_row.updated_at,
           alert_row.version,
           true
    FROM public.alerts AS alert_row
    WHERE alert_row.tenant_id = p_tenant_id
      AND alert_row.id = replay.result_alert_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'Alert command result is missing'
        USING ERRCODE = '55000';
    END IF;
    RETURN;
  END IF;

  INSERT INTO public.alerts (
    id, tenant_id, external_id, title, description, status, severity,
    created_by, created_by_membership_id, created_by_service_account_id,
    version
  ) VALUES (
    uuidv7(), p_tenant_id, p_external_id, p_title, p_description,
    'new', p_severity, NULL, NULL, authenticated.service_account_id, 1
  ) RETURNING alerts.id INTO created_alert_id;

  INSERT INTO public.alert_activities (
    tenant_id, alert_id, sequence, activity_type,
    actor_principal_kind, actor_membership_id,
    actor_service_account_id, metadata
  ) VALUES (
    p_tenant_id, created_alert_id, 1, 'alert.created',
    'service_account', NULL, authenticated.service_account_id,
    jsonb_build_object('severity', p_severity, 'version', 1)
  );

  PERFORM app.append_tenant_service_account_audit_v1(
    p_tenant_id,
    authenticated.service_account_id,
    authenticated.credential_id,
    'tenant.alert.created',
    'alert',
    created_alert_id,
    p_request_id,
    p_correlation_id,
    p_client_address,
    p_user_agent,
    NULL,
    jsonb_build_object(
      'status', 'new',
      'severity', p_severity,
      'version', 1
    ),
    jsonb_build_object(
      'credential_key_version', authenticated.key_version,
      'content_redacted', true
    )
  );

  INSERT INTO public.outbox_events (
    tenant_id, aggregate_type, aggregate_id, event_type, schema_version,
    payload, deduplication_key, correlation_id, causation_id
  ) VALUES (
    p_tenant_id, 'alert', created_alert_id, 'alert.created', 1,
    jsonb_build_object(
      'alert_id', created_alert_id,
      'principal_kind', 'service_account',
      'version', 1
    ),
    'alert.created:' || created_alert_id::text,
    p_correlation_id,
    p_request_id
  );

  INSERT INTO public.alert_commands (
    tenant_id, operation, principal_kind, actor_membership_id,
    actor_service_account_id, key_digest, request_digest,
    result_alert_id, result_version
  ) VALUES (
    p_tenant_id, 'alert.create', 'service_account', NULL,
    authenticated.service_account_id, p_key_digest, p_request_digest,
    created_alert_id, 1
  );

  RETURN QUERY
  SELECT alert_row.id,
         alert_row.external_id,
         alert_row.title,
         alert_row.description,
         alert_row.status,
         alert_row.severity,
         alert_row.created_by,
         alert_row.created_by_membership_id,
         alert_row.created_by_service_account_id,
         alert_row.created_at,
         alert_row.updated_at,
         alert_row.version,
         false
  FROM public.alerts AS alert_row
  WHERE alert_row.tenant_id = p_tenant_id
    AND alert_row.id = created_alert_id;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION "app"."tenant_human_has_exact_permission_v3"(uuid, uuid, text, "public"."authorization_scope") OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."tenant_human_can_delegate_exact_permission_v3"(uuid, uuid, text, "public"."authorization_scope", timestamp with time zone) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."current_tenant_human_has_exact_permission_v3"(text, "public"."authorization_scope") OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."assert_actor_can_change_service_account_role_grant_v1"(uuid, timestamp with time zone) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."assert_tenant_api_credential_request_shape_v1"(text[], "public"."authorization_scope"[], cidr[]) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."assert_tenant_api_credential_policy_v1"(uuid, uuid, text[], "public"."authorization_scope"[], cidr[]) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."private_resolve_tenant_api_credential_locator_v1"(uuid, bytea) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."authenticate_tenant_api_credential_v1"(uuid, bytea, integer, bytea, inet, text, "public"."authorization_scope") OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."append_tenant_service_account_audit_v1"(uuid, uuid, uuid, text, text, uuid, uuid, uuid, inet, text, jsonb, jsonb, jsonb) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."resolve_tenant_service_account_authority_v1"(uuid, integer) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."list_live_api_credential_key_versions_v1"(integer) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."list_tenant_service_accounts_v1"(uuid, boolean, integer) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."get_tenant_service_account_v1"(uuid) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."create_tenant_service_account_v1"(uuid, text, text, text, uuid, uuid, inet, text, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."update_tenant_service_account_v1"(uuid, integer, text, text, uuid, uuid, inet, text, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."archive_tenant_service_account_v1"(uuid, integer, text, uuid, uuid, inet, text, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."list_tenant_service_account_role_grants_v1"(uuid, uuid, boolean, integer) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."get_tenant_service_account_role_grant_v1"(uuid, uuid) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."grant_tenant_service_account_role_v1"(uuid, uuid, uuid, text, timestamp with time zone, uuid, uuid, inet, text, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."revoke_tenant_service_account_role_grant_v1"(uuid, uuid, integer, text, uuid, uuid, inet, text, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."list_tenant_api_credentials_v1"(uuid, uuid, boolean, integer) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."get_tenant_api_credential_v1"(uuid, uuid) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."issue_tenant_api_credential_v1"(uuid, uuid, bytea, bytea, text, integer, bytea, integer, bytea, timestamp with time zone, text[], "public"."authorization_scope"[], cidr[], uuid, uuid, inet, text, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."rotate_tenant_api_credential_v1"(uuid, uuid, uuid, integer, bytea, bytea, text, integer, bytea, integer, bytea, timestamp with time zone, text[], "public"."authorization_scope"[], cidr[], text, uuid, uuid, inet, text, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."revoke_tenant_api_credential_v1"(uuid, uuid, integer, text, uuid, uuid, inet, text, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."create_tenant_alert_as_human_v1"(text, text, text, "public"."alert_severity", bytea, bytea, uuid, uuid, inet, text, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."create_tenant_alert_as_service_account_v1"(uuid, bytea, integer, bytea, inet, text, text, text, "public"."alert_severity", bytea, bytea, uuid, uuid, text) OWNER TO "periapsis_migrator";--> statement-breakpoint

REVOKE ALL ON FUNCTION "app"."tenant_human_has_exact_permission_v3"(uuid, uuid, text, "public"."authorization_scope") FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."tenant_human_can_delegate_exact_permission_v3"(uuid, uuid, text, "public"."authorization_scope", timestamp with time zone) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."current_tenant_human_has_exact_permission_v3"(text, "public"."authorization_scope") FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."assert_actor_can_change_service_account_role_grant_v1"(uuid, timestamp with time zone) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."assert_tenant_api_credential_request_shape_v1"(text[], "public"."authorization_scope"[], cidr[]) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."assert_tenant_api_credential_policy_v1"(uuid, uuid, text[], "public"."authorization_scope"[], cidr[]) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."private_resolve_tenant_api_credential_locator_v1"(uuid, bytea) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."authenticate_tenant_api_credential_v1"(uuid, bytea, integer, bytea, inet, text, "public"."authorization_scope") FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."append_tenant_service_account_audit_v1"(uuid, uuid, uuid, text, text, uuid, uuid, uuid, inet, text, jsonb, jsonb, jsonb) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint

REVOKE ALL ON FUNCTION "app"."resolve_tenant_service_account_authority_v1"(uuid, integer) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."list_live_api_credential_key_versions_v1"(integer) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."list_tenant_service_accounts_v1"(uuid, boolean, integer) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."get_tenant_service_account_v1"(uuid) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."create_tenant_service_account_v1"(uuid, text, text, text, uuid, uuid, inet, text, text) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."update_tenant_service_account_v1"(uuid, integer, text, text, uuid, uuid, inet, text, text) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."archive_tenant_service_account_v1"(uuid, integer, text, uuid, uuid, inet, text, text) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."list_tenant_service_account_role_grants_v1"(uuid, uuid, boolean, integer) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."get_tenant_service_account_role_grant_v1"(uuid, uuid) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."grant_tenant_service_account_role_v1"(uuid, uuid, uuid, text, timestamp with time zone, uuid, uuid, inet, text, text) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."revoke_tenant_service_account_role_grant_v1"(uuid, uuid, integer, text, uuid, uuid, inet, text, text) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."list_tenant_api_credentials_v1"(uuid, uuid, boolean, integer) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."get_tenant_api_credential_v1"(uuid, uuid) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."issue_tenant_api_credential_v1"(uuid, uuid, bytea, bytea, text, integer, bytea, integer, bytea, timestamp with time zone, text[], "public"."authorization_scope"[], cidr[], uuid, uuid, inet, text, text) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."rotate_tenant_api_credential_v1"(uuid, uuid, uuid, integer, bytea, bytea, text, integer, bytea, integer, bytea, timestamp with time zone, text[], "public"."authorization_scope"[], cidr[], text, uuid, uuid, inet, text, text) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."revoke_tenant_api_credential_v1"(uuid, uuid, integer, text, uuid, uuid, inet, text, text) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."create_tenant_alert_as_human_v1"(text, text, text, "public"."alert_severity", bytea, bytea, uuid, uuid, inet, text, text) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."create_tenant_alert_as_service_account_v1"(uuid, bytea, integer, bytea, inet, text, text, text, "public"."alert_severity", bytea, bytea, uuid, uuid, text) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint

GRANT EXECUTE ON FUNCTION "app"."resolve_tenant_service_account_authority_v1"(uuid, integer) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."list_live_api_credential_key_versions_v1"(integer) TO "periapsis_api", "periapsis_worker";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."list_tenant_service_accounts_v1"(uuid, boolean, integer) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."get_tenant_service_account_v1"(uuid) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."create_tenant_service_account_v1"(uuid, text, text, text, uuid, uuid, inet, text, text) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."update_tenant_service_account_v1"(uuid, integer, text, text, uuid, uuid, inet, text, text) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."archive_tenant_service_account_v1"(uuid, integer, text, uuid, uuid, inet, text, text) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."list_tenant_service_account_role_grants_v1"(uuid, uuid, boolean, integer) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."get_tenant_service_account_role_grant_v1"(uuid, uuid) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."grant_tenant_service_account_role_v1"(uuid, uuid, uuid, text, timestamp with time zone, uuid, uuid, inet, text, text) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."revoke_tenant_service_account_role_grant_v1"(uuid, uuid, integer, text, uuid, uuid, inet, text, text) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."list_tenant_api_credentials_v1"(uuid, uuid, boolean, integer) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."get_tenant_api_credential_v1"(uuid, uuid) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."issue_tenant_api_credential_v1"(uuid, uuid, bytea, bytea, text, integer, bytea, integer, bytea, timestamp with time zone, text[], "public"."authorization_scope"[], cidr[], uuid, uuid, inet, text, text) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."rotate_tenant_api_credential_v1"(uuid, uuid, uuid, integer, bytea, bytea, text, integer, bytea, integer, bytea, timestamp with time zone, text[], "public"."authorization_scope"[], cidr[], text, uuid, uuid, inet, text, text) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."revoke_tenant_api_credential_v1"(uuid, uuid, integer, text, uuid, uuid, inet, text, text) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."create_tenant_alert_as_human_v1"(text, text, text, "public"."alert_severity", bytea, bytea, uuid, uuid, inet, text, text) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."create_tenant_alert_as_service_account_v1"(uuid, bytea, integer, bytea, inet, text, text, text, "public"."alert_severity", bytea, bytea, uuid, uuid, text) TO "periapsis_api";--> statement-breakpoint

DO $service_principal_security_assertions$
DECLARE
  private_relations regclass[] := ARRAY[
    'public.tenant_service_accounts'::regclass,
    'public.tenant_service_account_role_grants'::regclass,
    'public.tenant_api_credentials'::regclass,
    'public.tenant_api_credential_permissions'::regclass,
    'public.tenant_api_credential_networks'::regclass,
    'public.tenant_api_credential_commands'::regclass,
    'public.alert_activities'::regclass,
    'public.alert_commands'::regclass
  ];
  public_functions regprocedure[] := ARRAY[
    'app.resolve_tenant_service_account_authority_v1(uuid,integer)'::regprocedure,
    'app.list_live_api_credential_key_versions_v1(integer)'::regprocedure,
    'app.list_tenant_service_accounts_v1(uuid,boolean,integer)'::regprocedure,
    'app.get_tenant_service_account_v1(uuid)'::regprocedure,
    'app.create_tenant_service_account_v1(uuid,text,text,text,uuid,uuid,inet,text,text)'::regprocedure,
    'app.update_tenant_service_account_v1(uuid,integer,text,text,uuid,uuid,inet,text,text)'::regprocedure,
    'app.archive_tenant_service_account_v1(uuid,integer,text,uuid,uuid,inet,text,text)'::regprocedure,
    'app.list_tenant_service_account_role_grants_v1(uuid,uuid,boolean,integer)'::regprocedure,
    'app.get_tenant_service_account_role_grant_v1(uuid,uuid)'::regprocedure,
    'app.grant_tenant_service_account_role_v1(uuid,uuid,uuid,text,timestamp with time zone,uuid,uuid,inet,text,text)'::regprocedure,
    'app.revoke_tenant_service_account_role_grant_v1(uuid,uuid,integer,text,uuid,uuid,inet,text,text)'::regprocedure,
    'app.list_tenant_api_credentials_v1(uuid,uuid,boolean,integer)'::regprocedure,
    'app.get_tenant_api_credential_v1(uuid,uuid)'::regprocedure,
    'app.issue_tenant_api_credential_v1(uuid,uuid,bytea,bytea,text,integer,bytea,integer,bytea,timestamp with time zone,text[],public.authorization_scope[],cidr[],uuid,uuid,inet,text,text)'::regprocedure,
    'app.rotate_tenant_api_credential_v1(uuid,uuid,uuid,integer,bytea,bytea,text,integer,bytea,integer,bytea,timestamp with time zone,text[],public.authorization_scope[],cidr[],text,uuid,uuid,inet,text,text)'::regprocedure,
    'app.revoke_tenant_api_credential_v1(uuid,uuid,integer,text,uuid,uuid,inet,text,text)'::regprocedure,
    'app.create_tenant_alert_as_human_v1(text,text,text,public.alert_severity,bytea,bytea,uuid,uuid,inet,text,text)'::regprocedure,
    'app.create_tenant_alert_as_service_account_v1(uuid,bytea,integer,bytea,inet,text,text,text,public.alert_severity,bytea,bytea,uuid,uuid,text)'::regprocedure
  ];
  private_functions regprocedure[] := ARRAY[
    'app.private_seed_tenant_service_principal_authorization_v1(uuid)'::regprocedure,
    'app.seed_tenant_authorization_service_principal_compatibility_impl(uuid,uuid)'::regprocedure,
    'app.seed_tenant_authorization(uuid,uuid)'::regprocedure,
    'app.guard_service_principal_append_only_v1()'::regprocedure,
    'app.tenant_human_has_exact_permission_v3(uuid,uuid,text,public.authorization_scope)'::regprocedure,
    'app.tenant_human_can_delegate_exact_permission_v3(uuid,uuid,text,public.authorization_scope,timestamp with time zone)'::regprocedure,
    'app.current_tenant_human_has_exact_permission_v3(text,public.authorization_scope)'::regprocedure,
    'app.assert_actor_can_change_service_account_role_grant_v1(uuid,timestamp with time zone)'::regprocedure,
    'app.assert_tenant_api_credential_request_shape_v1(text[],public.authorization_scope[],cidr[])'::regprocedure,
    'app.assert_tenant_api_credential_policy_v1(uuid,uuid,text[],public.authorization_scope[],cidr[])'::regprocedure,
    'app.private_resolve_tenant_api_credential_locator_v1(uuid,bytea)'::regprocedure,
    'app.authenticate_tenant_api_credential_v1(uuid,bytea,integer,bytea,inet,text,public.authorization_scope)'::regprocedure,
    'app.append_tenant_service_account_audit_v1(uuid,uuid,uuid,text,text,uuid,uuid,uuid,inet,text,jsonb,jsonb,jsonb)'::regprocedure
  ];
  all_functions regprocedure[];
  relation_oid regclass;
  function_oid regprocedure;
  runtime_role name;
  migrator_oid oid := (
    SELECT role.oid FROM pg_catalog.pg_roles AS role
    WHERE role.rolname = 'periapsis_migrator'
  );
BEGIN
  all_functions := public_functions || private_functions;

  FOREACH relation_oid IN ARRAY private_relations LOOP
    IF EXISTS (
      SELECT 1
      FROM pg_catalog.pg_class AS relation
      WHERE relation.oid = relation_oid
        AND (
          relation.relowner <> migrator_oid
          OR NOT relation.relrowsecurity
          OR NOT relation.relforcerowsecurity
        )
    ) THEN
      RAISE EXCEPTION 'private service-principal relation lacks migrator ownership or forced RLS: %', relation_oid
        USING ERRCODE = '55000';
    END IF;

    FOREACH runtime_role IN ARRAY ARRAY[
      'periapsis_api'::name,
      'periapsis_worker'::name,
      'periapsis_notifier'::name,
      'periapsis_auditor'::name
    ] LOOP
      IF pg_catalog.has_table_privilege(
           runtime_role,
           relation_oid,
           'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER'
         )
         OR pg_catalog.has_any_column_privilege(
           runtime_role,
           relation_oid,
           'SELECT, INSERT, UPDATE, REFERENCES'
         ) THEN
        RAISE EXCEPTION 'runtime role % retains direct privilege on private relation %', runtime_role, relation_oid
          USING ERRCODE = '55000';
      END IF;
    END LOOP;
  END LOOP;

  FOREACH relation_oid IN ARRAY ARRAY[
    'public.alerts'::regclass,
    'public.audit_events'::regclass,
    'public.outbox_events'::regclass
  ] LOOP
    IF pg_catalog.has_table_privilege(
         'periapsis_api', relation_oid, 'INSERT, UPDATE, DELETE'
       )
       OR pg_catalog.has_any_column_privilege(
         'periapsis_api', relation_oid, 'INSERT, UPDATE'
       ) THEN
      RAISE EXCEPTION 'API runtime retains direct mutation privilege on %', relation_oid
        USING ERRCODE = '55000';
    END IF;
  END LOOP;

  IF EXISTS (
    SELECT 1
    FROM unnest(all_functions) AS expected(function_oid)
    JOIN pg_catalog.pg_proc AS routine
      ON routine.oid = expected.function_oid
    WHERE routine.proowner <> migrator_oid
       OR NOT routine.prosecdef
       OR NOT coalesce(
         routine.proconfig @> ARRAY['search_path=pg_catalog, public, app'],
         false
       )
  ) THEN
    RAISE EXCEPTION 'service-principal function ownership, definer mode, or search_path drifted'
      USING ERRCODE = '55000';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM unnest(all_functions) AS expected(function_oid)
    JOIN pg_catalog.pg_proc AS routine
      ON routine.oid = expected.function_oid
    CROSS JOIN LATERAL pg_catalog.aclexplode(
      coalesce(
        routine.proacl,
        pg_catalog.acldefault('f', routine.proowner)
      )
    ) AS privilege
    WHERE privilege.grantee = 0
      AND privilege.privilege_type = 'EXECUTE'
  ) THEN
    RAISE EXCEPTION 'PUBLIC retains execute on a service-principal function'
      USING ERRCODE = '55000';
  END IF;

  FOREACH function_oid IN ARRAY public_functions LOOP
    IF NOT pg_catalog.has_function_privilege(
      'periapsis_api', function_oid, 'EXECUTE'
    ) THEN
      RAISE EXCEPTION 'API runtime lacks bounded service-principal function %', function_oid
        USING ERRCODE = '55000';
    END IF;
  END LOOP;

  FOREACH function_oid IN ARRAY private_functions LOOP
    FOREACH runtime_role IN ARRAY ARRAY[
      'periapsis_api'::name,
      'periapsis_worker'::name,
      'periapsis_notifier'::name,
      'periapsis_auditor'::name
    ] LOOP
      IF pg_catalog.has_function_privilege(
        runtime_role, function_oid, 'EXECUTE'
      ) THEN
        RAISE EXCEPTION 'runtime role % can execute private service-principal function %', runtime_role, function_oid
          USING ERRCODE = '55000';
      END IF;
    END LOOP;
  END LOOP;

  IF NOT pg_catalog.has_function_privilege(
    'periapsis_worker',
    'app.list_live_api_credential_key_versions_v1(integer)'::regprocedure,
    'EXECUTE'
  ) THEN
    RAISE EXCEPTION 'worker lacks bounded live key-version inventory'
      USING ERRCODE = '55000';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_policy AS policy
    WHERE policy.polrelid = 'public.alerts'::regclass
      AND policy.polname = 'alerts_api_tenant'
  ) THEN
    RAISE EXCEPTION 'legacy unbounded Alert runtime boundary remains active'
      USING ERRCODE = '55000';
  END IF;

  IF (
    SELECT count(*)
    FROM pg_catalog.pg_trigger AS trigger
    WHERE trigger.tgname = ANY(ARRAY[
      'tenant_service_accounts_authorization_touch',
      'tenant_service_account_role_grants_authorization_touch',
      'alert_activities_immutable_guard',
      'alert_commands_immutable_guard',
      'tenant_api_credential_commands_immutable_guard'
    ]::name[])
      AND NOT trigger.tgisinternal
      AND trigger.tgenabled <> 'D'
  ) <> 5 THEN
    RAISE EXCEPTION 'service-principal authorization or append-only trigger set is incomplete'
      USING ERRCODE = '55000';
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_proc AS routine
    WHERE routine.oid = 'app.audit_event_payload(public.audit_events)'::regprocedure
      AND routine.proowner = migrator_oid
      AND coalesce(
        routine.proconfig @> ARRAY['search_path=pg_catalog, public, app'],
        false
      )
  ) THEN
    RAISE EXCEPTION 'audit payload owner or fixed search_path drifted'
      USING ERRCODE = '55000';
  END IF;
END;
$service_principal_security_assertions$;
