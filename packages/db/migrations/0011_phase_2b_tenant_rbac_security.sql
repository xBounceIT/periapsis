ALTER TABLE "tenant_authorization_commands" ADD CONSTRAINT "tenant_authorization_commands_actor_fk" FOREIGN KEY ("tenant_id","actor_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_membership_role_grants" ADD CONSTRAINT "tenant_membership_role_grants_membership_fk" FOREIGN KEY ("tenant_id","membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_membership_role_grants" ADD CONSTRAINT "tenant_membership_role_grants_grantor_fk" FOREIGN KEY ("tenant_id","granted_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_membership_role_grants" ADD CONSTRAINT "tenant_membership_role_grants_revoker_fk" FOREIGN KEY ("tenant_id","revoked_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_role_delegation_ceilings" ADD CONSTRAINT "tenant_role_delegation_creator_fk" FOREIGN KEY ("tenant_id","created_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_role_permissions" ADD CONSTRAINT "tenant_role_permissions_creator_fk" FOREIGN KEY ("tenant_id","created_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_roles" ADD CONSTRAINT "tenant_roles_creator_membership_fk" FOREIGN KEY ("tenant_id","created_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;

-- Phase 2B.1 tenant authorization hardening. Drizzle generated 0010 plus the
-- dependency-ordered composite membership FKs above. The remainder owns
-- PostgreSQL privileges, protected catalog data, definer entry points, audit
-- coupling, and concurrency invariants that Drizzle cannot express faithfully.

ALTER TABLE "public"."tenant_permissions" OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER TABLE "public"."tenant_permission_scopes" OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER TABLE "public"."tenant_authorization_commands" OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER TABLE "public"."tenant_authorization_sources" OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER TABLE "public"."tenant_authorization_states" OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER TABLE "public"."tenant_roles" OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER TABLE "public"."tenant_role_permissions" OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER TABLE "public"."tenant_role_delegation_ceilings" OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER TABLE "public"."tenant_membership_role_grants" OWNER TO "periapsis_migrator";--> statement-breakpoint

ALTER TABLE "public"."tenant_permissions" FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "public"."tenant_permission_scopes" FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "public"."tenant_authorization_commands" FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "public"."tenant_authorization_sources" FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "public"."tenant_authorization_states" FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "public"."tenant_roles" FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "public"."tenant_role_permissions" FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "public"."tenant_role_delegation_ceilings" FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "public"."tenant_membership_role_grants" FORCE ROW LEVEL SECURITY;--> statement-breakpoint

REVOKE ALL ON TABLE "public"."tenant_permissions" FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON TABLE "public"."tenant_permission_scopes" FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON TABLE "public"."tenant_authorization_commands" FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON TABLE "public"."tenant_authorization_sources" FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON TABLE "public"."tenant_authorization_states" FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON TABLE "public"."tenant_roles" FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON TABLE "public"."tenant_role_permissions" FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON TABLE "public"."tenant_role_delegation_ceilings" FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON TABLE "public"."tenant_membership_role_grants" FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint

INSERT INTO "public"."tenant_permissions" (
  "id", "key", "display_name", "description", "service_account_allowed"
)
VALUES
  (uuidv7(), 'permission.read', 'Read permissions', 'Read the tenant permission catalog.', false),
  (uuidv7(), 'role.read', 'Read roles', 'Read tenant roles, policies, and direct grants.', false),
  (uuidv7(), 'role.manage', 'Manage roles', 'Create, update, and archive tenant roles.', false),
  (uuidv7(), 'role.grant', 'Grant roles', 'Grant and revoke tenant roles within an exact delegation ceiling.', false),
  (uuidv7(), 'user.read', 'Read users', 'Read tenant user membership summaries.', false),
  (uuidv7(), 'membership.manage', 'Manage memberships', 'Change tenant membership lifecycle state within an exact delegation ceiling.', false);--> statement-breakpoint

INSERT INTO "public"."tenant_permission_scopes" (
  "permission_id", "scope"
)
SELECT permission.id, 'tenant'::"public"."authorization_scope"
FROM "public"."tenant_permissions" AS permission;--> statement-breakpoint

DO $block$
DECLARE
  actual_keys text[];
BEGIN
  SELECT array_agg(permission.key ORDER BY permission.key)
    INTO actual_keys
  FROM public.tenant_permissions AS permission;

  IF actual_keys IS DISTINCT FROM ARRAY[
    'membership.manage', 'permission.read', 'role.grant',
    'role.manage', 'role.read', 'user.read'
  ]::text[] THEN
    RAISE EXCEPTION 'tenant permission catalog drifted during Phase 2B.1 seed'
      USING ERRCODE = '55000';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM public.tenant_permissions AS permission
    LEFT JOIN public.tenant_permission_scopes AS permission_scope
      ON permission_scope.permission_id = permission.id
    WHERE permission.service_account_allowed
       OR permission_scope.scope IS DISTINCT FROM 'tenant'
  ) THEN
    RAISE EXCEPTION 'Phase 2B.1 permissions must be human-only tenant scopes'
      USING ERRCODE = '55000';
  END IF;
END;
$block$;--> statement-breakpoint

CREATE FUNCTION "app"."touch_tenant_authorization_row"()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  affected_tenant uuid;
BEGIN
  affected_tenant := CASE WHEN TG_OP = 'DELETE' THEN OLD.tenant_id ELSE NEW.tenant_id END;
  PERFORM app.bump_tenant_authorization_revision(affected_tenant);
  RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."lock_current_tenant_authorization_state"()
RETURNS bigint
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  locked_revision bigint;
BEGIN
  SELECT state.revision INTO locked_revision
  FROM public.tenant_authorization_states AS state
  WHERE state.tenant_id = context_tenant
    AND state.initialized_at IS NOT NULL
  FOR UPDATE;

  IF locked_revision IS NULL THEN
    RAISE EXCEPTION 'initialized tenant authorization state is required'
      USING ERRCODE = '42501';
  END IF;

  -- Recheck the actor after acquiring the tenant serialization row. Every
  -- authority-changing trigger takes this same row lock before changing data.
  PERFORM app.current_tenant_membership_id();
  RETURN locked_revision;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."validate_tenant_role_policy"(
  p_permission_keys text[],
  p_scopes "public"."authorization_scope"[],
  p_delegation_permission_keys text[],
  p_delegation_scopes "public"."authorization_scope"[]
)
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  PERFORM app.assert_actor_can_define_role_policy(p_permission_keys, p_scopes);

  IF p_delegation_permission_keys IS NULL OR p_delegation_scopes IS NULL
     OR cardinality(p_delegation_permission_keys)
        <> cardinality(p_delegation_scopes)
     OR cardinality(p_delegation_permission_keys) > 200 THEN
    RAISE EXCEPTION 'delegation ceiling arrays must have equal bounded cardinality'
      USING ERRCODE = '22023';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM unnest(
      p_delegation_permission_keys, p_delegation_scopes
    ) AS ceiling(permission_key, scope)
    GROUP BY ceiling.permission_key, ceiling.scope
    HAVING count(*) > 1
  ) THEN
    RAISE EXCEPTION 'delegation ceiling contains duplicate permission scopes'
      USING ERRCODE = '22023';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM unnest(
      p_delegation_permission_keys, p_delegation_scopes
    ) AS ceiling(permission_key, scope)
    WHERE NOT EXISTS (
      SELECT 1
      FROM unnest(p_permission_keys, p_scopes) AS policy(permission_key, scope)
      WHERE policy.permission_key = ceiling.permission_key
        AND policy.scope = ceiling.scope
    )
  ) THEN
    RAISE EXCEPTION 'delegation ceiling must be an exact subset of role permissions'
      USING ERRCODE = '22023';
  END IF;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."resolve_current_tenant_human_role_grants"(p_limit integer)
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
    AND role.archived_at IS NULL
  ORDER BY role_grant.id
  LIMIT p_limit;
END;
$function$;--> statement-breakpoint

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
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid;
  canonical_request_digest bytea;
  replay record;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();

  IF NOT app.current_tenant_has_exact_permission('role.manage', 'tenant') THEN
    RAISE EXCEPTION 'role.manage tenant scope is required'
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
    'description', coalesce(p_description, ''),
    'permissions', coalesce((
      SELECT jsonb_agg(
        jsonb_build_object(
          'permission_key', requested.permission_key,
          'scope', requested.scope
        ) ORDER BY requested.permission_key, requested.scope
      )
      FROM unnest(p_permission_keys, p_scopes)
        AS requested(permission_key, scope)
    ), '[]'::jsonb),
    'delegation_ceiling', coalesce((
      SELECT jsonb_agg(
        jsonb_build_object(
          'permission_key', requested.permission_key,
          'scope', requested.scope
        ) ORDER BY requested.permission_key, requested.scope
      )
      FROM unnest(p_delegation_permission_keys, p_delegation_scopes)
        AS requested(permission_key, scope)
    ), '[]'::jsonb)
  )::text, 'UTF8')) INTO canonical_request_digest;

  DELETE FROM public.tenant_authorization_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.actor_membership_id = actor_membership
    AND command.operation = 'tenant_role.create'
    AND command.key_digest = p_idempotency_key_digest
    AND command.expires_at <= transaction_timestamp();

  SELECT command.* INTO replay
  FROM public.tenant_authorization_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.actor_membership_id = actor_membership
    AND command.operation = 'tenant_role.create'
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

  IF p_name IS NULL OR btrim(p_name) = ''
     OR char_length(p_name) > 120 OR p_name ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION 'tenant role name must be nonblank, control-free, and at most 120 characters'
      USING ERRCODE = '22023';
  END IF;
  IF p_description IS NOT NULL
     AND (char_length(p_description) > 500
       OR p_description ~ '[[:cntrl:]]') THEN
    RAISE EXCEPTION 'tenant role description must be control-free and at most 500 characters'
      USING ERRCODE = '22023';
  END IF;

  PERFORM app.validate_tenant_role_policy(
    p_permission_keys, p_scopes,
    p_delegation_permission_keys, p_delegation_scopes
  );

  INSERT INTO public.tenant_roles (
    id, tenant_id, key, display_name, description,
    system_role, protected_role, created_by_membership_id
  ) VALUES (
    p_role_id, context_tenant, p_key, p_name, coalesce(p_description, ''),
    false, false, actor_membership
  );

  INSERT INTO public.tenant_role_permissions (
    tenant_id, role_id, permission_id, scope, created_by_membership_id
  )
  SELECT context_tenant, p_role_id, permission.id, requested.scope,
         actor_membership
  FROM unnest(p_permission_keys, p_scopes)
    AS requested(permission_key, scope)
  JOIN public.tenant_permissions AS permission
    ON permission.key = requested.permission_key;

  INSERT INTO public.tenant_role_delegation_ceilings (
    tenant_id, role_id, permission_id, scope, created_by_membership_id
  )
  SELECT context_tenant, p_role_id, permission.id, requested.scope,
         actor_membership
  FROM unnest(p_delegation_permission_keys, p_delegation_scopes)
    AS requested(permission_key, scope)
  JOIN public.tenant_permissions AS permission
    ON permission.key = requested.permission_key;

  PERFORM app.append_tenant_authorization_audit(
    p_audit_event_id, 'tenant.role.created', 'tenant_role', p_role_id,
    p_request_id, p_correlation_id,
    p_ip_address, p_user_agent, p_authentication_method, NULL,
    jsonb_build_object(
      'key', p_key, 'name', p_name,
      'permissions', cardinality(p_permission_keys),
      'delegation_ceiling', cardinality(p_delegation_permission_keys),
      'version', 1
    ),
    jsonb_build_object('actor_membership_id', actor_membership)
  );

  INSERT INTO public.tenant_authorization_commands (
    tenant_id, actor_membership_id, operation, key_digest, request_digest,
    result_resource_id, result_version
  ) VALUES (
    context_tenant, actor_membership, 'tenant_role.create',
    p_idempotency_key_digest, canonical_request_digest, p_role_id, 1
  );
  RETURN QUERY SELECT p_role_id, 1::integer, false;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."update_tenant_role_metadata"(
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
  IF target_role.version <> p_expected_version THEN
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

CREATE FUNCTION "app"."touch_membership_authorization"()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP = 'DELETE' OR OLD.status IS DISTINCT FROM NEW.status
     OR OLD.user_id IS DISTINCT FROM NEW.user_id
     OR OLD.tenant_id IS DISTINCT FROM NEW.tenant_id THEN
    PERFORM app.bump_tenant_authorization_revision(OLD.tenant_id);
    IF TG_OP <> 'DELETE' AND NEW.tenant_id IS DISTINCT FROM OLD.tenant_id THEN
      PERFORM app.bump_tenant_authorization_revision(NEW.tenant_id);
    END IF;
  END IF;
  RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."touch_user_authorization"()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  affected record;
BEGIN
  IF TG_OP = 'DELETE' OR OLD.active IS DISTINCT FROM NEW.active THEN
    FOR affected IN
      SELECT DISTINCT membership.tenant_id
      FROM public.tenant_memberships AS membership
      JOIN public.tenant_authorization_states AS state
        ON state.tenant_id = membership.tenant_id
      WHERE membership.user_id = OLD.id
      ORDER BY membership.tenant_id
    LOOP
      PERFORM app.bump_tenant_authorization_revision(affected.tenant_id);
    END LOOP;
  END IF;
  RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."assert_tenant_recovery_admin"(p_tenant_id uuid)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  initialized timestamp with time zone;
BEGIN
  SELECT state.initialized_at INTO initialized
  FROM public.tenant_authorization_states AS state
  WHERE state.tenant_id = p_tenant_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant authorization state is absent'
      USING ERRCODE = '55000';
  END IF;
  IF initialized IS NULL THEN
    RETURN;
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM public.tenant_membership_role_grants AS role_grant
    JOIN public.tenant_authorization_sources AS source
      ON source.tenant_id = role_grant.tenant_id
     AND source.id = role_grant.source_id
    JOIN public.tenant_roles AS role
      ON role.tenant_id = role_grant.tenant_id
     AND role.id = role_grant.role_id
    JOIN public.tenant_memberships AS membership
      ON membership.tenant_id = role_grant.tenant_id
     AND membership.id = role_grant.membership_id
    JOIN public.users AS identity ON identity.id = membership.user_id
    WHERE role_grant.tenant_id = p_tenant_id
      AND role_grant.revoked_at IS NULL
      AND role_grant.expires_at IS NULL
      AND source.retired_at IS NULL
      AND role.key = 'tenant_admin'
      AND role.system_role
      AND role.protected_role
      AND role.archived_at IS NULL
      AND membership.status = 'active'
      AND identity.active
  ) THEN
    RAISE EXCEPTION 'initialized tenant must retain a live direct non-expiring human tenant_admin grant'
      USING ERRCODE = '23514', CONSTRAINT = 'tenant_last_recovery_admin_check';
  END IF;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."assert_tenant_recovery_row"()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  affected_tenant uuid;
BEGIN
  affected_tenant := CASE WHEN TG_OP = 'DELETE' THEN OLD.tenant_id ELSE NEW.tenant_id END;
  PERFORM app.assert_tenant_recovery_admin(affected_tenant);
  IF TG_OP = 'UPDATE' AND NEW.tenant_id IS DISTINCT FROM OLD.tenant_id THEN
    PERFORM app.assert_tenant_recovery_admin(OLD.tenant_id);
  END IF;
  RETURN NULL;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."assert_user_tenant_recovery"()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  affected record;
BEGIN
  IF TG_OP = 'DELETE' OR OLD.active IS DISTINCT FROM NEW.active THEN
    FOR affected IN
      SELECT DISTINCT membership.tenant_id
      FROM public.tenant_memberships AS membership
      JOIN public.tenant_membership_role_grants AS role_grant
        ON role_grant.tenant_id = membership.tenant_id
       AND role_grant.membership_id = membership.id
      JOIN public.tenant_roles AS role
        ON role.tenant_id = role_grant.tenant_id
       AND role.id = role_grant.role_id
      WHERE membership.user_id = OLD.id
        AND role.key = 'tenant_admin'
      ORDER BY membership.tenant_id
    LOOP
      PERFORM app.assert_tenant_recovery_admin(affected.tenant_id);
    END LOOP;
  END IF;
  RETURN NULL;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."assert_authorization_initialization"()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF OLD.initialized_at IS NULL AND NEW.initialized_at IS NOT NULL THEN
    PERFORM app.assert_tenant_recovery_admin(NEW.tenant_id);
  ELSIF OLD.initialized_at IS NOT NULL AND NEW.initialized_at IS NULL THEN
    RAISE EXCEPTION 'tenant authorization cannot be de-initialized'
      USING ERRCODE = '23514';
  END IF;
  RETURN NULL;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."guard_tenant_authorization_command"()
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
      SELECT 1
      FROM public.tenant_roles AS role
      WHERE role.tenant_id = NEW.tenant_id
        AND role.id = NEW.result_resource_id
        AND role.version = NEW.result_version
    ) THEN
      RAISE EXCEPTION 'tenant role idempotency result is not a same-tenant role version'
        USING ERRCODE = '23503',
              CONSTRAINT = 'tenant_authorization_commands_result_fk';
    END IF;
  ELSIF NEW.operation = 'tenant_role_grant.create' THEN
    IF NOT EXISTS (
      SELECT 1
      FROM public.tenant_membership_role_grants AS role_grant
      WHERE role_grant.tenant_id = NEW.tenant_id
        AND role_grant.id = NEW.result_resource_id
        AND role_grant.version = NEW.result_version
    ) THEN
      RAISE EXCEPTION 'tenant role grant idempotency result is not a same-tenant grant version'
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

ALTER FUNCTION "app"."touch_tenant_authorization_row"() OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."touch_membership_authorization"() OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."touch_user_authorization"() OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."assert_tenant_recovery_admin"(uuid) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."assert_tenant_recovery_row"() OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."assert_user_tenant_recovery"() OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."assert_authorization_initialization"() OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."guard_tenant_authorization_command"() OWNER TO "periapsis_migrator";--> statement-breakpoint

REVOKE ALL ON FUNCTION "app"."touch_tenant_authorization_row"() FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."touch_membership_authorization"() FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."touch_user_authorization"() FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."assert_tenant_recovery_admin"(uuid) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."assert_tenant_recovery_row"() FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."assert_user_tenant_recovery"() FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."assert_authorization_initialization"() FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."guard_tenant_authorization_command"() FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint

CREATE TRIGGER "tenant_authorization_sources_touch"
BEFORE INSERT OR UPDATE OR DELETE ON "public"."tenant_authorization_sources"
FOR EACH ROW EXECUTE FUNCTION "app"."touch_tenant_authorization_row"();--> statement-breakpoint
CREATE TRIGGER "tenant_roles_touch"
BEFORE INSERT OR UPDATE OR DELETE ON "public"."tenant_roles"
FOR EACH ROW EXECUTE FUNCTION "app"."touch_tenant_authorization_row"();--> statement-breakpoint
CREATE TRIGGER "tenant_role_permissions_touch"
BEFORE INSERT OR UPDATE OR DELETE ON "public"."tenant_role_permissions"
FOR EACH ROW EXECUTE FUNCTION "app"."touch_tenant_authorization_row"();--> statement-breakpoint
CREATE TRIGGER "tenant_role_delegation_ceilings_touch"
BEFORE INSERT OR UPDATE OR DELETE ON "public"."tenant_role_delegation_ceilings"
FOR EACH ROW EXECUTE FUNCTION "app"."touch_tenant_authorization_row"();--> statement-breakpoint
CREATE TRIGGER "tenant_membership_role_grants_touch"
BEFORE INSERT OR UPDATE OR DELETE ON "public"."tenant_membership_role_grants"
FOR EACH ROW EXECUTE FUNCTION "app"."touch_tenant_authorization_row"();--> statement-breakpoint
CREATE TRIGGER "tenant_memberships_authorization_touch"
BEFORE UPDATE OR DELETE ON "public"."tenant_memberships"
FOR EACH ROW EXECUTE FUNCTION "app"."touch_membership_authorization"();--> statement-breakpoint
CREATE TRIGGER "users_authorization_touch"
BEFORE UPDATE OR DELETE ON "public"."users"
FOR EACH ROW EXECUTE FUNCTION "app"."touch_user_authorization"();--> statement-breakpoint
CREATE TRIGGER "tenant_authorization_commands_guard"
BEFORE INSERT OR UPDATE OR DELETE ON "public"."tenant_authorization_commands"
FOR EACH ROW EXECUTE FUNCTION "app"."guard_tenant_authorization_command"();--> statement-breakpoint

CREATE CONSTRAINT TRIGGER "tenant_role_grants_recovery_guard"
AFTER INSERT OR UPDATE OR DELETE ON "public"."tenant_membership_role_grants"
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION "app"."assert_tenant_recovery_row"();--> statement-breakpoint
CREATE CONSTRAINT TRIGGER "tenant_memberships_recovery_guard"
AFTER UPDATE OR DELETE ON "public"."tenant_memberships"
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION "app"."assert_tenant_recovery_row"();--> statement-breakpoint
CREATE CONSTRAINT TRIGGER "tenant_sources_recovery_guard"
AFTER UPDATE OR DELETE ON "public"."tenant_authorization_sources"
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION "app"."assert_tenant_recovery_row"();--> statement-breakpoint
CREATE CONSTRAINT TRIGGER "tenant_roles_recovery_guard"
AFTER UPDATE OR DELETE ON "public"."tenant_roles"
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION "app"."assert_tenant_recovery_row"();--> statement-breakpoint
CREATE CONSTRAINT TRIGGER "users_tenant_recovery_guard"
AFTER UPDATE OR DELETE ON "public"."users"
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION "app"."assert_user_tenant_recovery"();--> statement-breakpoint
CREATE CONSTRAINT TRIGGER "tenant_authorization_initialization_guard"
AFTER UPDATE ON "public"."tenant_authorization_states"
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
WHEN (OLD.initialized_at IS DISTINCT FROM NEW.initialized_at)
EXECUTE FUNCTION "app"."assert_authorization_initialization"();--> statement-breakpoint

CREATE FUNCTION "app"."context_tenant_id"()
RETURNS uuid
LANGUAGE plpgsql
STABLE
SECURITY INVOKER
SET search_path = pg_catalog
AS $function$
DECLARE
  context_tenant uuid;
BEGIN
  context_tenant := nullif(current_setting('app.tenant_id', true), '')::uuid;
  IF context_tenant IS NULL THEN
    RAISE EXCEPTION 'app.tenant_id context is required' USING ERRCODE = '42501';
  END IF;
  RETURN context_tenant;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."current_tenant_membership_id"()
RETURNS uuid
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_id uuid := app.context_user_id();
  membership_id uuid;
BEGIN
  SELECT membership.id INTO membership_id
  FROM public.tenant_memberships AS membership
  JOIN public.users AS identity ON identity.id = membership.user_id
  JOIN public.tenants AS tenant ON tenant.id = membership.tenant_id
  JOIN public.tenant_authorization_states AS state
    ON state.tenant_id = membership.tenant_id
  WHERE membership.tenant_id = context_tenant
    AND membership.user_id = actor_id
    AND membership.status = 'active'
    AND identity.active
    AND tenant.status = 'active'
    AND state.initialized_at IS NOT NULL;

  IF membership_id IS NULL THEN
    RAISE EXCEPTION 'active initialized tenant membership is required'
      USING ERRCODE = '42501';
  END IF;
  RETURN membership_id;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."bump_tenant_authorization_revision"(p_tenant_id uuid)
RETURNS bigint
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  next_revision bigint;
BEGIN
  UPDATE public.tenant_authorization_states AS state
  SET revision = state.revision + 1,
      updated_at = transaction_timestamp()
  WHERE state.tenant_id = p_tenant_id
    AND state.revision < 9223372036854775807
  RETURNING state.revision INTO next_revision;

  IF next_revision IS NULL THEN
    RAISE EXCEPTION 'tenant authorization state is absent or exhausted'
      USING ERRCODE = '55000';
  END IF;
  RETURN next_revision;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."append_tenant_authorization_audit"(
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
  -- Establish the actor's live tenant membership before emitting security audit.
  PERFORM app.current_tenant_membership_id();
  IF p_action IS NULL OR btrim(p_action) = ''
     OR p_resource_type IS NULL OR btrim(p_resource_type) = '' THEN
    RAISE EXCEPTION 'authorization audit action and resource are required'
      USING ERRCODE = '22023';
  END IF;
  IF p_user_agent IS NOT NULL
     AND length(p_user_agent) NOT BETWEEN 1 AND 1024 THEN
    RAISE EXCEPTION 'authorization audit user agent is invalid'
      USING ERRCODE = '22023';
  END IF;
  IF p_authentication_method IS NULL
     OR p_authentication_method NOT IN (
       'bootstrap_totp', 'totp', 'recovery_code'
     ) THEN
    RAISE EXCEPTION 'authorization mutation requires a live authentication method'
      USING ERRCODE = '22023';
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
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."tenant_user_has_exact_permission"(
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
       JOIN public.tenant_membership_role_grants AS role_grant
         ON role_grant.tenant_id = membership.tenant_id
        AND role_grant.membership_id = membership.id
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
       WHERE membership.tenant_id = p_tenant_id
         AND membership.user_id = p_user_id
         AND membership.status = 'active'
         AND identity.active
         AND tenant.status = 'active'
         AND state.initialized_at IS NOT NULL
         AND role_grant.revoked_at IS NULL
         AND (role_grant.expires_at IS NULL
           OR role_grant.expires_at > transaction_timestamp())
         AND source.retired_at IS NULL
         AND role.archived_at IS NULL
         AND permission.key = p_permission_key
         AND role_permission.scope = p_scope
         AND role_permission.scope <> 'platform'
     );
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."tenant_user_can_delegate_exact_permission"(
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
       JOIN public.tenant_membership_role_grants AS role_grant
         ON role_grant.tenant_id = membership.tenant_id
        AND role_grant.membership_id = membership.id
       JOIN public.tenant_authorization_sources AS source
         ON source.tenant_id = role_grant.tenant_id
        AND source.id = role_grant.source_id
       JOIN public.tenant_roles AS role
         ON role.tenant_id = role_grant.tenant_id
        AND role.id = role_grant.role_id
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
         AND role_grant.revoked_at IS NULL
         AND (role_grant.expires_at IS NULL
           OR role_grant.expires_at > transaction_timestamp())
         AND source.retired_at IS NULL
         AND role.archived_at IS NULL
         AND permission.key = p_permission_key
         AND ceiling.scope = p_scope
         AND ceiling.scope <> 'platform'
         AND (
           (p_requested_expires_at IS NULL AND role_grant.expires_at IS NULL)
           OR (p_requested_expires_at IS NOT NULL
             AND (role_grant.expires_at IS NULL
               OR role_grant.expires_at >= p_requested_expires_at))
         )
     );
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."current_tenant_has_exact_permission"(
  p_permission_key text,
  p_scope "public"."authorization_scope"
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT app.tenant_user_has_exact_permission(
    app.context_tenant_id(), app.context_user_id(), p_permission_key, p_scope
  );
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."get_current_tenant_authorization_context"()
RETURNS TABLE (
  tenant_id uuid,
  membership_id uuid,
  authorization_revision bigint,
  membership_status "public"."membership_status",
  compatibility_role "public"."membership_role",
  evaluated_at timestamp with time zone
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
  RETURN QUERY
  SELECT state.tenant_id, membership.id, state.revision,
         membership.status, membership.role, transaction_timestamp()
  FROM public.tenant_authorization_states AS state
  JOIN public.tenant_memberships AS membership
    ON membership.tenant_id = state.tenant_id
   AND membership.id = context_membership
  WHERE state.tenant_id = context_tenant
    AND state.initialized_at IS NOT NULL;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."resolve_current_tenant_human_authority"(p_limit integer)
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
  WITH effective AS (
    SELECT permission.key AS permission_key,
           role_permission.scope,
           ceiling.permission_id IS NOT NULL AS is_delegable,
           role_grant.expires_at
    FROM public.tenant_membership_role_grants AS role_grant
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
    LEFT JOIN public.tenant_role_delegation_ceilings AS ceiling
      ON ceiling.tenant_id = role_permission.tenant_id
     AND ceiling.role_id = role_permission.role_id
     AND ceiling.permission_id = role_permission.permission_id
     AND ceiling.scope = role_permission.scope
    WHERE role_grant.tenant_id = context_tenant
      AND role_grant.membership_id = context_membership
      AND role_grant.revoked_at IS NULL
      AND (role_grant.expires_at IS NULL
        OR role_grant.expires_at > transaction_timestamp())
      AND source.retired_at IS NULL
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

ALTER FUNCTION "app"."context_tenant_id"() OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."current_tenant_membership_id"() OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."bump_tenant_authorization_revision"(uuid) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."append_tenant_authorization_audit"(uuid, text, text, uuid, uuid, uuid, inet, text, text, jsonb, jsonb, jsonb) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."tenant_user_has_exact_permission"(uuid, uuid, text, "public"."authorization_scope") OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."tenant_user_can_delegate_exact_permission"(uuid, uuid, text, "public"."authorization_scope", timestamp with time zone) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."current_tenant_has_exact_permission"(text, "public"."authorization_scope") OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."get_current_tenant_authorization_context"() OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."resolve_current_tenant_human_authority"(integer) OWNER TO "periapsis_migrator";--> statement-breakpoint

REVOKE ALL ON FUNCTION "app"."context_tenant_id"() FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."current_tenant_membership_id"() FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."bump_tenant_authorization_revision"(uuid) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."append_tenant_authorization_audit"(uuid, text, text, uuid, uuid, uuid, inet, text, text, jsonb, jsonb, jsonb) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."tenant_user_has_exact_permission"(uuid, uuid, text, "public"."authorization_scope") FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."tenant_user_can_delegate_exact_permission"(uuid, uuid, text, "public"."authorization_scope", timestamp with time zone) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."current_tenant_has_exact_permission"(text, "public"."authorization_scope") FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."get_current_tenant_authorization_context"() FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."resolve_current_tenant_human_authority"(integer) FROM PUBLIC;--> statement-breakpoint

CREATE FUNCTION "app"."seed_tenant_authorization"(
  p_tenant_id uuid,
  p_initial_admin_membership_id uuid
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  admin_role_id uuid;
  tenant_creation_source_id uuid;
  role_keys text[];
  seeded_at timestamp with time zone := transaction_timestamp();
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM public.tenants AS tenant WHERE tenant.id = p_tenant_id
  ) THEN
    RAISE EXCEPTION 'tenant authorization seed requires an existing tenant'
      USING ERRCODE = '23503';
  END IF;

  INSERT INTO public.tenant_authorization_states (
    tenant_id, initialized_at, revision, updated_at
  ) VALUES (p_tenant_id, NULL, 0, seeded_at)
  ON CONFLICT (tenant_id) DO NOTHING;

  INSERT INTO public.tenant_authorization_sources (
    id, tenant_id, kind, key, authoritative, protected
  ) VALUES
    (uuidv7(), p_tenant_id, 'tenant_creation', 'tenant_creation', false, true),
    (uuidv7(), p_tenant_id, 'manual', 'manual', false, true)
  ON CONFLICT (tenant_id, key) DO NOTHING;

  INSERT INTO public.tenant_roles (
    id, tenant_id, key, display_name, description,
    system_role, protected_role
  ) VALUES
    (uuidv7(), p_tenant_id, 'tenant_admin', 'Tenant administrator', 'Protected tenant recovery and administration role.', true, true),
    (uuidv7(), p_tenant_id, 'soc_manager', 'SOC manager', 'Built-in SOC management role.', true, false),
    (uuidv7(), p_tenant_id, 'senior_analyst', 'Senior analyst', 'Built-in senior analyst role.', true, false),
    (uuidv7(), p_tenant_id, 'analyst', 'Analyst', 'Built-in analyst role.', true, false),
    (uuidv7(), p_tenant_id, 'customer_manager', 'Customer manager', 'Built-in customer manager role.', true, false),
    (uuidv7(), p_tenant_id, 'customer_user', 'Customer user', 'Built-in customer user role.', true, false),
    (uuidv7(), p_tenant_id, 'read_only', 'Read only', 'Built-in read-only role.', true, false),
    (uuidv7(), p_tenant_id, 'service_account', 'Service account', 'Built-in service-account role; it grants no human authority.', true, false)
  ON CONFLICT (tenant_id, key) DO NOTHING;

  SELECT array_agg(role.key ORDER BY role.key)
    INTO role_keys
  FROM public.tenant_roles AS role
  WHERE role.tenant_id = p_tenant_id
    AND role.system_role;

  IF role_keys IS DISTINCT FROM ARRAY[
    'analyst', 'customer_manager', 'customer_user', 'read_only',
    'senior_analyst', 'service_account', 'soc_manager', 'tenant_admin'
  ]::text[] THEN
    RAISE EXCEPTION 'tenant built-in role catalog is incomplete or contains drift'
      USING ERRCODE = '55000';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM public.tenant_roles AS role
    WHERE role.tenant_id = p_tenant_id
      AND role.system_role
      AND ((role.key = 'tenant_admin') IS DISTINCT FROM role.protected_role)
  ) THEN
    RAISE EXCEPTION 'only tenant_admin may be the protected built-in tenant role'
      USING ERRCODE = '55000';
  END IF;

  SELECT role.id INTO STRICT admin_role_id
  FROM public.tenant_roles AS role
  WHERE role.tenant_id = p_tenant_id
    AND role.key = 'tenant_admin'
    AND role.system_role
    AND role.protected_role
    AND role.archived_at IS NULL;

  INSERT INTO public.tenant_role_permissions (
    tenant_id, role_id, permission_id, scope
  )
  SELECT p_tenant_id, admin_role_id, permission_scope.permission_id,
         permission_scope.scope
  FROM public.tenant_permission_scopes AS permission_scope
  JOIN public.tenant_permissions AS permission
    ON permission.id = permission_scope.permission_id
  ON CONFLICT DO NOTHING;

  INSERT INTO public.tenant_role_delegation_ceilings (
    tenant_id, role_id, permission_id, scope
  )
  SELECT role_permission.tenant_id, role_permission.role_id,
         role_permission.permission_id, role_permission.scope
  FROM public.tenant_role_permissions AS role_permission
  WHERE role_permission.tenant_id = p_tenant_id
    AND role_permission.role_id = admin_role_id
  ON CONFLICT DO NOTHING;

  IF EXISTS (
    SELECT 1
    FROM public.tenant_role_permissions AS role_permission
    JOIN public.tenant_roles AS role
      ON role.tenant_id = role_permission.tenant_id
     AND role.id = role_permission.role_id
    WHERE role_permission.tenant_id = p_tenant_id
      AND role.key <> 'tenant_admin'
  ) THEN
    RAISE EXCEPTION 'non-admin built-in roles must remain empty in Phase 2B.1'
      USING ERRCODE = '55000';
  END IF;

  IF p_initial_admin_membership_id IS NOT NULL THEN
    IF NOT EXISTS (
      SELECT 1
      FROM public.tenant_memberships AS membership
      JOIN public.users AS identity ON identity.id = membership.user_id
      WHERE membership.tenant_id = p_tenant_id
        AND membership.id = p_initial_admin_membership_id
        AND membership.status = 'active'
        AND identity.active
    ) THEN
      RAISE EXCEPTION 'initial tenant administrator membership is not active'
        USING ERRCODE = '23514';
    END IF;

    SELECT source.id INTO STRICT tenant_creation_source_id
    FROM public.tenant_authorization_sources AS source
    WHERE source.tenant_id = p_tenant_id
      AND source.key = 'tenant_creation'
      AND source.kind = 'tenant_creation'
      AND source.protected
      AND source.retired_at IS NULL;

    INSERT INTO public.tenant_membership_role_grants (
      id, tenant_id, membership_id, role_id, source_id,
      granted_by_membership_id, grant_reason, expires_at
    ) VALUES (
      uuidv7(), p_tenant_id, p_initial_admin_membership_id, admin_role_id,
      tenant_creation_source_id, p_initial_admin_membership_id,
      'Protected tenant recovery administrator.', NULL
    )
    ON CONFLICT (tenant_id, membership_id, role_id, source_id)
      WHERE revoked_at IS NULL
    DO NOTHING;

    UPDATE public.tenant_authorization_states AS state
    SET initialized_at = coalesce(state.initialized_at, seeded_at),
        revision = state.revision + 1,
        updated_at = seeded_at
    WHERE state.tenant_id = p_tenant_id;
  END IF;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION "app"."seed_tenant_authorization"(uuid, uuid) OWNER TO "periapsis_migrator";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."seed_tenant_authorization"(uuid, uuid) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint

DO $block$
DECLARE
  tenant_record record;
  membership_record record;
BEGIN
  FOR tenant_record IN
    SELECT tenant.id
    FROM public.tenants AS tenant
    ORDER BY tenant.id
  LOOP
    PERFORM app.seed_tenant_authorization(tenant_record.id, NULL);
  END LOOP;

  -- Only an explicit, active legacy tenant_admin label is eligible for the
  -- compatibility backfill. No analyst or arbitrary oldest member is promoted.
  FOR membership_record IN
    SELECT membership.tenant_id, membership.id
    FROM public.tenant_memberships AS membership
    JOIN public.users AS identity ON identity.id = membership.user_id
    WHERE membership.role = 'tenant_admin'
      AND membership.status = 'active'
      AND identity.active
    ORDER BY membership.tenant_id, membership.id
  LOOP
    PERFORM app.seed_tenant_authorization(
      membership_record.tenant_id,
      membership_record.id
    );
  END LOOP;
END;
$block$;--> statement-breakpoint

CREATE FUNCTION "app"."assert_actor_can_define_role_policy"(
  p_permission_keys text[],
  p_scopes "public"."authorization_scope"[]
)
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_id uuid := app.context_user_id();
  requested record;
BEGIN
  IF p_permission_keys IS NULL OR p_scopes IS NULL
     OR cardinality(p_permission_keys) <> cardinality(p_scopes)
     OR cardinality(p_permission_keys) > 200 THEN
    RAISE EXCEPTION 'role permission arrays must have equal bounded cardinality'
      USING ERRCODE = '22023';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM unnest(p_permission_keys, p_scopes) AS item(permission_key, scope)
    GROUP BY item.permission_key, item.scope
    HAVING count(*) > 1
  ) THEN
    RAISE EXCEPTION 'role policy contains duplicate permission scopes'
      USING ERRCODE = '22023';
  END IF;

  FOR requested IN
    SELECT item.permission_key, item.scope
    FROM unnest(p_permission_keys, p_scopes) AS item(permission_key, scope)
  LOOP
    IF requested.scope = 'platform'
       OR NOT EXISTS (
         SELECT 1
         FROM public.tenant_permissions AS permission
         JOIN public.tenant_permission_scopes AS permission_scope
           ON permission_scope.permission_id = permission.id
         WHERE permission.key = requested.permission_key
           AND permission_scope.scope = requested.scope
       ) THEN
      RAISE EXCEPTION 'unknown or invalid tenant permission scope'
        USING ERRCODE = '22023';
    END IF;
    IF NOT app.tenant_user_can_delegate_exact_permission(
      context_tenant, actor_id, requested.permission_key, requested.scope,
      transaction_timestamp()
    ) THEN
      RAISE EXCEPTION 'requested role policy exceeds the exact delegation ceiling'
        USING ERRCODE = '42501';
    END IF;
  END LOOP;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."assert_actor_can_grant_role"(
  p_role_id uuid,
  p_expires_at timestamp with time zone
)
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_id uuid := app.context_user_id();
  role_permission record;
BEGIN
  IF p_expires_at IS NOT NULL AND p_expires_at <= transaction_timestamp() THEN
    RAISE EXCEPTION 'role grant expiry must be in the future'
      USING ERRCODE = '22023';
  END IF;
  IF NOT EXISTS (
    SELECT 1
    FROM public.tenant_roles AS role
    WHERE role.tenant_id = context_tenant
      AND role.id = p_role_id
      AND role.archived_at IS NULL
  ) THEN
    RAISE EXCEPTION 'active tenant role was not found' USING ERRCODE = 'P0002';
  END IF;

  FOR role_permission IN
    SELECT permission.key, policy.scope
    FROM public.tenant_role_permissions AS policy
    JOIN public.tenant_permissions AS permission
      ON permission.id = policy.permission_id
    WHERE policy.tenant_id = context_tenant
      AND policy.role_id = p_role_id
  LOOP
    IF NOT app.tenant_user_can_delegate_exact_permission(
      context_tenant, actor_id, role_permission.key, role_permission.scope,
      p_expires_at
    ) THEN
      RAISE EXCEPTION 'role grant exceeds the exact delegation ceiling or lifetime'
        USING ERRCODE = '42501';
    END IF;
  END LOOP;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."list_tenant_permission_catalog"(
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

CREATE FUNCTION "app"."list_tenant_roles"(
  p_after_id uuid,
  p_include_archived boolean,
  p_limit integer
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
         role.system_role, role.protected_role, role.version,
         role.archived_at, role.created_at, role.updated_at
  FROM public.tenant_roles AS role
  WHERE role.tenant_id = context_tenant
    AND (p_include_archived OR role.archived_at IS NULL)
    AND (p_after_id IS NULL OR role.id > p_after_id)
  ORDER BY role.id
  LIMIT p_limit;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."get_tenant_role"(p_role_id uuid)
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
         role.system_role, role.protected_role, role.version,
         role.archived_at, role.created_at, role.updated_at
  FROM public.tenant_roles AS role
  WHERE role.tenant_id = context_tenant
    AND role.id = p_role_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant role was not found' USING ERRCODE = 'P0002';
  END IF;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."get_tenant_role_policy"(
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

CREATE FUNCTION "app"."list_tenant_users"(
  p_after_membership_id uuid,
  p_limit integer
)
RETURNS TABLE (
  membership_id uuid,
  user_id uuid,
  email text,
  display_name text,
  membership_status "public"."membership_status",
  compatibility_role "public"."membership_role",
  user_active boolean,
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
  IF NOT app.current_tenant_has_exact_permission('user.read', 'tenant') THEN
    RAISE EXCEPTION 'user.read tenant scope is required' USING ERRCODE = '42501';
  END IF;
  IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 101 THEN
    RAISE EXCEPTION 'tenant user page limit must be between 1 and 101'
      USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  SELECT membership.id, identity.id, identity.email, identity.display_name,
         membership.status, membership.role, identity.active,
         membership.created_at, membership.updated_at
  FROM public.tenant_memberships AS membership
  JOIN public.users AS identity ON identity.id = membership.user_id
  WHERE membership.tenant_id = context_tenant
    AND (p_after_membership_id IS NULL OR membership.id > p_after_membership_id)
  ORDER BY membership.id
  LIMIT p_limit;
END;
$function$;--> statement-breakpoint

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
         role_grant.source_id, source.kind,
         'direct'::text,
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
    AND source.kind = 'manual'
    AND (p_include_revoked OR role_grant.revoked_at IS NULL)
    AND (p_after_grant_id IS NULL OR role_grant.id > p_after_grant_id)
  ORDER BY role_grant.id
  LIMIT p_limit;
END;
$function$;--> statement-breakpoint

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
         role_grant.source_id, source.kind,
         'direct'::text,
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
    AND role_grant.id = p_grant_id
    AND source.kind = 'manual';

  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant role grant was not found' USING ERRCODE = 'P0002';
  END IF;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."replace_tenant_role_policy"(
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
  SELECT context_tenant, p_role_id, permission.id, requested.scope,
         actor_membership
  FROM unnest(p_permission_keys, p_scopes)
    AS requested(permission_key, scope)
  JOIN public.tenant_permissions AS permission
    ON permission.key = requested.permission_key;

  INSERT INTO public.tenant_role_delegation_ceilings (
    tenant_id, role_id, permission_id, scope, created_by_membership_id
  )
  SELECT context_tenant, p_role_id, permission.id, requested.scope,
         actor_membership
  FROM unnest(p_delegation_permission_keys, p_delegation_scopes)
    AS requested(permission_key, scope)
  JOIN public.tenant_permissions AS permission
    ON permission.key = requested.permission_key;

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

CREATE FUNCTION "app"."archive_tenant_role"(
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
  IF target_role.version <> p_expected_version THEN
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
$function$;--> statement-breakpoint

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
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid;
  target_membership uuid;
  manual_source uuid;
  canonical_request_digest bytea;
  replay record;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
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
    RAISE EXCEPTION 'direct role grant reason is invalid'
      USING ERRCODE = '22023';
  END IF;

  SELECT sha256(convert_to(jsonb_build_object(
    'target_user_id', p_target_user_id,
    'role_id', p_role_id,
    'reason', p_reason,
    'expires_at', p_expires_at
  )::text, 'UTF8')) INTO canonical_request_digest;

  DELETE FROM public.tenant_authorization_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.actor_membership_id = actor_membership
    AND command.operation = 'tenant_role_grant.create'
    AND command.key_digest = p_idempotency_key_digest
    AND command.expires_at <= transaction_timestamp();

  SELECT command.* INTO replay
  FROM public.tenant_authorization_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.actor_membership_id = actor_membership
    AND command.operation = 'tenant_role_grant.create'
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

  PERFORM app.assert_actor_can_grant_role(p_role_id, p_expires_at);

  SELECT source.id INTO STRICT manual_source
  FROM public.tenant_authorization_sources AS source
  WHERE source.tenant_id = context_tenant
    AND source.key = 'manual'
    AND source.kind = 'manual'
    AND source.protected
    AND source.retired_at IS NULL;

  -- An expired-but-unrevoked grant is historical, not an active uniqueness
  -- claim. Close it before inserting the new provenance row.
  UPDATE public.tenant_membership_role_grants AS old_grant
  SET revoked_at = transaction_timestamp(),
      revoked_by_membership_id = actor_membership,
      revoke_reason = 'Superseded after the prior direct grant expired.',
      version = old_grant.version + 1,
      updated_at = transaction_timestamp()
  WHERE old_grant.tenant_id = context_tenant
    AND old_grant.membership_id = target_membership
    AND old_grant.role_id = p_role_id
    AND old_grant.source_id = manual_source
    AND old_grant.revoked_at IS NULL
    AND old_grant.expires_at <= transaction_timestamp()
    AND old_grant.version < 2147483647;

  IF EXISTS (
    SELECT 1
    FROM public.tenant_membership_role_grants AS existing
    WHERE existing.tenant_id = context_tenant
      AND existing.membership_id = target_membership
      AND existing.role_id = p_role_id
      AND existing.source_id = manual_source
      AND existing.revoked_at IS NULL
  ) THEN
    RAISE EXCEPTION 'an active direct role grant already exists'
      USING ERRCODE = '23505', CONSTRAINT = 'tenant_membership_role_grants_active_key';
  END IF;

  INSERT INTO public.tenant_membership_role_grants (
    id, tenant_id, membership_id, role_id, source_id,
    granted_by_membership_id, grant_reason, expires_at
  ) VALUES (
    p_grant_id, context_tenant, target_membership, p_role_id, manual_source,
    actor_membership, p_reason, p_expires_at
  );

  PERFORM app.append_tenant_authorization_audit(
    p_audit_event_id, 'tenant.role_grant.created',
    'tenant_membership_role_grant', p_grant_id,
    p_request_id, p_correlation_id,
    p_ip_address, p_user_agent, p_authentication_method, NULL,
    jsonb_build_object(
      'target_user_id', p_target_user_id,
      'target_membership_id', target_membership,
      'role_id', p_role_id,
      'source_type', 'direct',
      'reason', p_reason,
      'expires_at', p_expires_at,
      'version', 1
    ),
    jsonb_build_object('actor_membership_id', actor_membership)
  );

  INSERT INTO public.tenant_authorization_commands (
    tenant_id, actor_membership_id, operation, key_digest, request_digest,
    result_resource_id, result_version
  ) VALUES (
    context_tenant, actor_membership, 'tenant_role_grant.create',
    p_idempotency_key_digest, canonical_request_digest, p_grant_id, 1
  );
  RETURN QUERY SELECT p_grant_id, 1::integer, false;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."revoke_tenant_user_role_grant"(
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

  SELECT role_grant.* INTO target_grant
  FROM public.tenant_membership_role_grants AS role_grant
  JOIN public.tenant_authorization_sources AS source
    ON source.tenant_id = role_grant.tenant_id
   AND source.id = role_grant.source_id
  WHERE role_grant.tenant_id = context_tenant
    AND role_grant.id = p_grant_id
    AND source.kind = 'manual'
  FOR UPDATE OF role_grant;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'direct tenant role grant was not found'
      USING ERRCODE = 'P0002';
  END IF;
  IF target_grant.version <> p_expected_version THEN
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

  IF target_grant.expires_at IS NULL
     OR target_grant.expires_at > transaction_timestamp() THEN
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

CREATE FUNCTION "app"."set_tenant_user_membership_status"(
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

  -- Suspending removes, and activating restores, every live grant at once.
  -- Require exact ceiling coverage for the full remaining lifetime of each.
  FOR role_grant IN
    SELECT grant_row.role_id, grant_row.expires_at
    FROM public.tenant_membership_role_grants AS grant_row
    JOIN public.tenant_authorization_sources AS source
      ON source.tenant_id = grant_row.tenant_id
     AND source.id = grant_row.source_id
    JOIN public.tenant_roles AS role
      ON role.tenant_id = grant_row.tenant_id
     AND role.id = grant_row.role_id
    WHERE grant_row.tenant_id = context_tenant
      AND grant_row.membership_id = target_membership.id
      AND grant_row.revoked_at IS NULL
      AND (grant_row.expires_at IS NULL
        OR grant_row.expires_at > transaction_timestamp())
      AND source.retired_at IS NULL
      AND role.archived_at IS NULL
  LOOP
    PERFORM app.assert_actor_can_grant_role(
      role_grant.role_id, role_grant.expires_at
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
      'actor_membership_id', actor_membership
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

  -- Built-in roles, the exact protected administrator policy/ceiling, the
  -- creator's direct recovery grant, and initialized authorization state are
  -- committed atomically with the tenant and both audit chains.
  PERFORM app.seed_tenant_authorization(p_tenant_id, p_membership_id);

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
      'tenant_admin_permissions', 6
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
$function$;--> statement-breakpoint

ALTER FUNCTION "app"."lock_current_tenant_authorization_state"() OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."validate_tenant_role_policy"(text[], "public"."authorization_scope"[], text[], "public"."authorization_scope"[]) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."assert_actor_can_define_role_policy"(text[], "public"."authorization_scope"[]) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."assert_actor_can_grant_role"(uuid, timestamp with time zone) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."resolve_current_tenant_human_role_grants"(integer) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."list_tenant_permission_catalog"(uuid, integer) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."list_tenant_roles"(uuid, boolean, integer) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."get_tenant_role"(uuid) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."get_tenant_role_policy"(uuid, integer) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."list_tenant_users"(uuid, integer) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."list_tenant_membership_role_grants"(uuid, uuid, boolean, integer) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."get_tenant_membership_role_grant"(uuid) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."create_tenant_role"(uuid, bytea, text, text, text, text[], "public"."authorization_scope"[], text[], "public"."authorization_scope"[], uuid, uuid, uuid, inet, text, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."update_tenant_role_metadata"(uuid, integer, text, text, uuid, uuid, uuid, inet, text, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."replace_tenant_role_policy"(uuid, integer, text[], "public"."authorization_scope"[], text[], "public"."authorization_scope"[], uuid, uuid, uuid, inet, text, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."archive_tenant_role"(uuid, integer, uuid, uuid, uuid, inet, text, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."grant_tenant_user_role"(uuid, bytea, uuid, uuid, text, timestamp with time zone, uuid, uuid, uuid, inet, text, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."revoke_tenant_user_role_grant"(uuid, integer, text, uuid, uuid, uuid, inet, text, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."set_tenant_user_membership_status"(uuid, "public"."membership_status", uuid, uuid, uuid, inet, text, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."create_platform_tenant"(uuid, uuid, text, text, text, text, uuid, uuid, uuid, inet, text, text) OWNER TO "periapsis_migrator";--> statement-breakpoint

REVOKE ALL ON FUNCTION "app"."lock_current_tenant_authorization_state"() FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."validate_tenant_role_policy"(text[], "public"."authorization_scope"[], text[], "public"."authorization_scope"[]) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."assert_actor_can_define_role_policy"(text[], "public"."authorization_scope"[]) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."assert_actor_can_grant_role"(uuid, timestamp with time zone) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint

REVOKE ALL ON FUNCTION "app"."get_current_tenant_authorization_context"() FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."resolve_current_tenant_human_authority"(integer) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."resolve_current_tenant_human_role_grants"(integer) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."list_tenant_permission_catalog"(uuid, integer) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."list_tenant_roles"(uuid, boolean, integer) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."get_tenant_role"(uuid) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."get_tenant_role_policy"(uuid, integer) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."list_tenant_users"(uuid, integer) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."list_tenant_membership_role_grants"(uuid, uuid, boolean, integer) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."get_tenant_membership_role_grant"(uuid) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."create_tenant_role"(uuid, bytea, text, text, text, text[], "public"."authorization_scope"[], text[], "public"."authorization_scope"[], uuid, uuid, uuid, inet, text, text) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."update_tenant_role_metadata"(uuid, integer, text, text, uuid, uuid, uuid, inet, text, text) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."replace_tenant_role_policy"(uuid, integer, text[], "public"."authorization_scope"[], text[], "public"."authorization_scope"[], uuid, uuid, uuid, inet, text, text) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."archive_tenant_role"(uuid, integer, uuid, uuid, uuid, inet, text, text) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."grant_tenant_user_role"(uuid, bytea, uuid, uuid, text, timestamp with time zone, uuid, uuid, uuid, inet, text, text) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."revoke_tenant_user_role_grant"(uuid, integer, text, uuid, uuid, uuid, inet, text, text) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."set_tenant_user_membership_status"(uuid, "public"."membership_status", uuid, uuid, uuid, inet, text, text) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."create_platform_tenant"(uuid, uuid, text, text, text, text, uuid, uuid, uuid, inet, text, text) FROM PUBLIC;--> statement-breakpoint

GRANT USAGE ON TYPE "public"."authorization_scope", "public"."authorization_source_kind" TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."get_current_tenant_authorization_context"() TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."resolve_current_tenant_human_authority"(integer) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."resolve_current_tenant_human_role_grants"(integer) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."list_tenant_permission_catalog"(uuid, integer) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."list_tenant_roles"(uuid, boolean, integer) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."get_tenant_role"(uuid) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."get_tenant_role_policy"(uuid, integer) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."list_tenant_users"(uuid, integer) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."list_tenant_membership_role_grants"(uuid, uuid, boolean, integer) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."get_tenant_membership_role_grant"(uuid) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."create_tenant_role"(uuid, bytea, text, text, text, text[], "public"."authorization_scope"[], text[], "public"."authorization_scope"[], uuid, uuid, uuid, inet, text, text) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."update_tenant_role_metadata"(uuid, integer, text, text, uuid, uuid, uuid, inet, text, text) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."replace_tenant_role_policy"(uuid, integer, text[], "public"."authorization_scope"[], text[], "public"."authorization_scope"[], uuid, uuid, uuid, inet, text, text) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."archive_tenant_role"(uuid, integer, uuid, uuid, uuid, inet, text, text) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."grant_tenant_user_role"(uuid, bytea, uuid, uuid, text, timestamp with time zone, uuid, uuid, uuid, inet, text, text) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."revoke_tenant_user_role_grant"(uuid, integer, text, uuid, uuid, uuid, inet, text, text) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."set_tenant_user_membership_status"(uuid, "public"."membership_status", uuid, uuid, uuid, inet, text, text) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."create_platform_tenant"(uuid, uuid, text, text, text, text, uuid, uuid, uuid, inet, text, text) TO "periapsis_api";--> statement-breakpoint
