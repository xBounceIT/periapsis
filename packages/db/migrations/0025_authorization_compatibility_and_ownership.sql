-- Migration 0025 is deliberately compatible with the immediately preceding
-- application manifest. The legacy projection exposes the exact 0000-0024
-- prefix only while the real journal is the single allowlisted 25 -> 26 edge.
-- New replicas use schema_compatibility_v2() and validate the complete journal.
CREATE FUNCTION "app"."schema_compatibility_v2"()
RETURNS TABLE (
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
  RETURN QUERY EXECUTE $query$
    SELECT
      count(*)::bigint AS applied_count,
      max(created_at)::bigint AS latest_created_at,
      (
        SELECT lower(migration.hash::text)
        FROM drizzle.__drizzle_migrations AS migration
        ORDER BY migration.created_at DESC, migration.id DESC
        LIMIT 1
      ) AS latest_hash,
      string_agg(
        lower(migration.hash::text),
        ':' ORDER BY migration.created_at, migration.id
      ) AS migration_fingerprint
    FROM drizzle.__drizzle_migrations AS migration
  $query$;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION "app"."schema_compatibility_v2"() OWNER TO "periapsis_migrator";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."schema_compatibility_v2"() FROM PUBLIC;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."schema_compatibility_v2"() TO "periapsis_api", "periapsis_worker";--> statement-breakpoint

CREATE OR REPLACE FUNCTION "app"."schema_compatibility"()
RETURNS TABLE (
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
  journal_count bigint;
  journal_latest_created_at bigint;
  journal_fingerprint text;
  migration_0025_rows bigint;
BEGIN
  SELECT compatibility.applied_count,
         compatibility.latest_created_at,
         compatibility.migration_fingerprint
  INTO journal_count, journal_latest_created_at, journal_fingerprint
  FROM app.schema_compatibility_v2() AS compatibility;

  EXECUTE $query$
    SELECT count(*)::bigint
    FROM drizzle.__drizzle_migrations AS migration
    WHERE migration.created_at = 1787516694668
  $query$
  INTO migration_0025_rows;

  IF journal_count = 26
     AND journal_latest_created_at = 1787516694668
     AND migration_0025_rows = 1
     AND journal_fingerprint = current_setting(
       'app.schema_compatibility_fingerprint',
       true
     ) THEN
    RETURN QUERY EXECUTE $query$
      WITH ordered_migrations AS (
        SELECT
          migration.id,
          migration.created_at,
          lower(migration.hash::text) AS migration_hash,
          row_number() OVER (
            ORDER BY migration.created_at, migration.id
          ) AS migration_ordinal
        FROM drizzle.__drizzle_migrations AS migration
      )
      SELECT
        count(*)::bigint AS applied_count,
        max(migration.created_at)::bigint AS latest_created_at,
        (
          SELECT latest_prefix_migration.migration_hash
          FROM ordered_migrations AS latest_prefix_migration
          WHERE latest_prefix_migration.migration_ordinal = 25
        ) AS latest_hash,
        string_agg(
          migration.migration_hash,
          ':' ORDER BY migration.created_at, migration.id
        ) AS migration_fingerprint
      FROM ordered_migrations AS migration
      WHERE migration.migration_ordinal <= 25
    $query$;
    RETURN;
  END IF;

  RETURN QUERY
  SELECT compatibility.applied_count,
         compatibility.latest_created_at,
         compatibility.latest_hash,
         compatibility.migration_fingerprint
  FROM app.schema_compatibility_v2() AS compatibility;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION "app"."schema_compatibility"() OWNER TO "periapsis_migrator";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."schema_compatibility"() FROM PUBLIC;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."schema_compatibility"() TO "periapsis_api", "periapsis_worker";--> statement-breakpoint

GRANT SET ON PARAMETER app.schema_compatibility_fingerprint TO "periapsis_migrator";--> statement-breakpoint

CREATE FUNCTION "app"."seal_schema_compatibility_manifest"(
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
  actual_count bigint;
  actual_latest_created_at bigint;
  actual_latest_hash text;
  actual_migration_fingerprint text;
  fingerprint_hashes text[];
BEGIN
  fingerprint_hashes := string_to_array(
    p_expected_migration_fingerprint,
    ':'
  );
  IF p_expected_count IS NULL
     OR p_expected_count NOT BETWEEN 1 AND 2147483647
     OR p_expected_latest_created_at IS NULL
     OR p_expected_latest_created_at <= 0
     OR p_expected_latest_hash IS NULL
     OR p_expected_latest_hash !~ '^[0-9a-f]{64}$'
     OR p_expected_migration_fingerprint IS NULL
     OR p_expected_migration_fingerprint !~ '^[0-9a-f]{64}(:[0-9a-f]{64})*$'
     OR cardinality(fingerprint_hashes) IS DISTINCT FROM p_expected_count::integer
     OR fingerprint_hashes[cardinality(fingerprint_hashes)] IS DISTINCT FROM p_expected_latest_hash THEN
    RAISE EXCEPTION 'invalid schema compatibility manifest'
      USING ERRCODE = '22023';
  END IF;

  EXECUTE $query$
    SELECT
      count(*)::bigint AS applied_count,
      max(created_at)::bigint AS latest_created_at,
      (
        SELECT lower(migration.hash::text)
        FROM drizzle.__drizzle_migrations AS migration
        ORDER BY migration.created_at DESC, migration.id DESC
        LIMIT 1
      ) AS latest_hash,
      string_agg(
        lower(migration.hash::text),
        ':' ORDER BY migration.created_at, migration.id
      ) AS migration_fingerprint
    FROM drizzle.__drizzle_migrations AS migration
  $query$
  INTO actual_count,
       actual_latest_created_at,
       actual_latest_hash,
       actual_migration_fingerprint;

  IF actual_count IS DISTINCT FROM p_expected_count
     OR actual_latest_created_at IS DISTINCT FROM p_expected_latest_created_at
     OR actual_latest_hash IS DISTINCT FROM p_expected_latest_hash
     OR actual_migration_fingerprint IS DISTINCT FROM p_expected_migration_fingerprint THEN
    RAISE EXCEPTION 'schema compatibility manifest does not match the applied migration journal'
      USING ERRCODE = '55000';
  END IF;

  PERFORM set_config(
    'app.schema_compatibility_fingerprint',
    p_expected_migration_fingerprint,
    true
  );
  EXECUTE $statement$
    ALTER FUNCTION app.schema_compatibility()
      SET app.schema_compatibility_fingerprint FROM CURRENT
  $statement$;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION "app"."seal_schema_compatibility_manifest"(bigint, bigint, text, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."seal_schema_compatibility_manifest"(bigint, bigint, text, text) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint

-- Restore the Phase 2B.1 database ABI for replicas that are still running the
-- direct-only authority projection. Phase 2B.2 replicas use the role-path
-- resolver, but the old entry point must remain callable during a rolling
-- deployment.
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

ALTER FUNCTION "app"."resolve_current_tenant_human_role_grants"(integer)
  OWNER TO "periapsis_migrator";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."resolve_current_tenant_human_role_grants"(integer)
  FROM PUBLIC;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."resolve_current_tenant_human_role_grants"(integer)
  TO "periapsis_api";--> statement-breakpoint

-- Preserve the exact 0024 table-function ABI for replicas running the immediate
-- predecessor. Publish only the new mutation-ownership hint through explicitly
-- versioned v2 names.
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

CREATE FUNCTION "app"."list_tenant_membership_role_grants_v2"(
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
  managed_by_authorization_api boolean,
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
         (
           source.key = 'manual'
           AND source.kind = 'manual'
           AND source.protected
           AND source.retired_at IS NULL
         ),
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

CREATE FUNCTION "app"."get_tenant_membership_role_grant_v2"(p_grant_id uuid)
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
  managed_by_authorization_api boolean,
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
         (
           source.key = 'manual'
           AND source.kind = 'manual'
           AND source.protected
           AND source.retired_at IS NULL
         ),
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

ALTER FUNCTION "app"."list_tenant_membership_role_grants"(
  uuid, uuid, boolean, integer
) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."get_tenant_membership_role_grant"(uuid)
  OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."list_tenant_membership_role_grants_v2"(
  uuid, uuid, boolean, integer
) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."get_tenant_membership_role_grant_v2"(uuid)
  OWNER TO "periapsis_migrator";--> statement-breakpoint

REVOKE ALL ON FUNCTION "app"."list_tenant_membership_role_grants"(
  uuid, uuid, boolean, integer
) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."get_tenant_membership_role_grant"(uuid)
  FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."list_tenant_membership_role_grants_v2"(
  uuid, uuid, boolean, integer
) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."get_tenant_membership_role_grant_v2"(uuid)
  FROM PUBLIC;--> statement-breakpoint

GRANT EXECUTE ON FUNCTION "app"."list_tenant_membership_role_grants"(
  uuid, uuid, boolean, integer
) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."get_tenant_membership_role_grant"(uuid)
  TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."list_tenant_membership_role_grants_v2"(
  uuid, uuid, boolean, integer
) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."get_tenant_membership_role_grant_v2"(uuid)
  TO "periapsis_api";--> statement-breakpoint

-- Keep the four Phase 2B security-group read ABIs unchanged for old replicas.
-- New replicas use v2 wrappers which append the exact mutation-ownership fact.
CREATE FUNCTION "app"."list_tenant_security_group_memberships_v2"(
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
  updated_at timestamp with time zone,
  managed_by_authorization_api boolean
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT legacy.*,
         (
           source.key = 'manual'
           AND source.kind = 'manual'
           AND source.protected
           AND source.retired_at IS NULL
         )
  FROM app.list_tenant_security_group_memberships(
    p_group_id,
    p_after_group_membership_id,
    p_include_revoked,
    p_limit
  ) AS legacy
  JOIN public.tenant_authorization_sources AS source
    ON source.tenant_id = app.context_tenant_id()
   AND source.id = legacy.source_id;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."get_tenant_security_group_membership_v2"(
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
  updated_at timestamp with time zone,
  managed_by_authorization_api boolean
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT legacy.*,
         (
           source.key = 'manual'
           AND source.kind = 'manual'
           AND source.protected
           AND source.retired_at IS NULL
         )
  FROM app.get_tenant_security_group_membership(
    p_group_id,
    p_group_membership_id
  ) AS legacy
  JOIN public.tenant_authorization_sources AS source
    ON source.tenant_id = app.context_tenant_id()
   AND source.id = legacy.source_id;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."list_tenant_security_group_role_grants_v2"(
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
  updated_at timestamp with time zone,
  managed_by_authorization_api boolean
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT legacy.*,
         (
           source.key = 'manual'
           AND source.kind = 'manual'
           AND source.protected
           AND source.retired_at IS NULL
         )
  FROM app.list_tenant_security_group_role_grants(
    p_group_id,
    p_after_group_role_grant_id,
    p_include_revoked,
    p_limit
  ) AS legacy
  JOIN public.tenant_authorization_sources AS source
    ON source.tenant_id = app.context_tenant_id()
   AND source.id = legacy.source_id;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."get_tenant_security_group_role_grant_v2"(
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
  updated_at timestamp with time zone,
  managed_by_authorization_api boolean
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT legacy.*,
         (
           source.key = 'manual'
           AND source.kind = 'manual'
           AND source.protected
           AND source.retired_at IS NULL
         )
  FROM app.get_tenant_security_group_role_grant(
    p_group_id,
    p_group_role_grant_id
  ) AS legacy
  JOIN public.tenant_authorization_sources AS source
    ON source.tenant_id = app.context_tenant_id()
   AND source.id = legacy.source_id;
$function$;--> statement-breakpoint

ALTER FUNCTION "app"."list_tenant_security_group_memberships_v2"(
  uuid, uuid, boolean, integer
) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."get_tenant_security_group_membership_v2"(uuid, uuid)
  OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."list_tenant_security_group_role_grants_v2"(
  uuid, uuid, boolean, integer
) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."get_tenant_security_group_role_grant_v2"(uuid, uuid)
  OWNER TO "periapsis_migrator";--> statement-breakpoint

REVOKE ALL ON FUNCTION "app"."list_tenant_security_group_memberships_v2"(
  uuid, uuid, boolean, integer
) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."get_tenant_security_group_membership_v2"(
  uuid, uuid
) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."list_tenant_security_group_role_grants_v2"(
  uuid, uuid, boolean, integer
) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."get_tenant_security_group_role_grant_v2"(
  uuid, uuid
) FROM PUBLIC;--> statement-breakpoint

GRANT EXECUTE ON FUNCTION "app"."list_tenant_security_group_memberships_v2"(
  uuid, uuid, boolean, integer
) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."get_tenant_security_group_membership_v2"(
  uuid, uuid
) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."list_tenant_security_group_role_grants_v2"(
  uuid, uuid, boolean, integer
) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."get_tenant_security_group_role_grant_v2"(
  uuid, uuid
) TO "periapsis_api";--> statement-breakpoint

-- Only the protected, live source with the canonical manual key is owned by
-- the direct-grant mutation API. A second manual-kind source is a distinct
-- integration owner and must remain immutable through this entry point.
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
    AND source.key = 'manual'
    AND source.kind = 'manual'
    AND source.protected
    AND source.retired_at IS NULL
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

ALTER FUNCTION "app"."revoke_tenant_user_role_grant"(
  uuid, integer, text, uuid, uuid, uuid, inet, text, text
) OWNER TO "periapsis_migrator";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."revoke_tenant_user_role_grant"(
  uuid, integer, text, uuid, uuid, uuid, inet, text, text
) FROM PUBLIC;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."revoke_tenant_user_role_grant"(
  uuid, integer, text, uuid, uuid, uuid, inet, text, text
) TO "periapsis_api";--> statement-breakpoint

-- Phase 2B.1 bootstrapped RBAC sources, roles, and the administrator policy for
-- every pre-existing tenant before fresh platform tenant creation appended its
-- initialization audit. Some legacy tenants had no eligible recovery admin and
-- intentionally remained uninitialized, so name this as a migration backfill
-- and record only redacted state booleans. The ordinary audit trigger assigns
-- sequence/hash fields, preserving the append-only tenant chain.
INSERT INTO public.audit_events (
  id, tenant_id, sequence, actor_type, action, resource_type, resource_id,
  authentication_method, outcome, after, metadata
)
SELECT uuidv7(), state.tenant_id, 0, 'system',
       'tenant.authorization.migration_backfilled', 'tenant', state.tenant_id,
       'database_migration', 'success',
       jsonb_build_object(
         'rbac_bootstrap_backfilled', true,
         'authorization_initialized', state.initialized_at IS NOT NULL,
         'recovery_grant_initialized', EXISTS (
           SELECT 1
           FROM public.tenant_membership_role_grants AS recovery_grant
           JOIN public.tenant_authorization_sources AS recovery_source
             ON recovery_source.tenant_id = recovery_grant.tenant_id
            AND recovery_source.id = recovery_grant.source_id
           JOIN public.tenant_roles AS recovery_role
             ON recovery_role.tenant_id = recovery_grant.tenant_id
            AND recovery_role.id = recovery_grant.role_id
           WHERE recovery_grant.tenant_id = state.tenant_id
             AND recovery_source.key = 'tenant_creation'
             AND recovery_source.kind = 'tenant_creation'
             AND recovery_source.protected
             AND recovery_role.key = 'tenant_admin'
             AND recovery_role.system_role
             AND recovery_role.protected_role
             AND recovery_grant.revoked_at IS NULL
             AND recovery_grant.expires_at IS NULL
         )
       ),
       jsonb_build_object(
         'migration', '0025_authorization_compatibility_and_ownership',
         'source', 'phase_2b_1_existing_tenant_backfill'
       )
FROM public.tenant_authorization_states AS state
WHERE NOT EXISTS (
    SELECT 1
    FROM public.audit_events AS existing
    WHERE existing.tenant_id = state.tenant_id
      AND existing.action = 'tenant.authorization.initialized'
      AND existing.resource_type = 'tenant'
      AND existing.resource_id = state.tenant_id
      AND existing.outcome = 'success'
  )
  AND NOT EXISTS (
    SELECT 1
    FROM public.audit_events AS existing
    WHERE existing.tenant_id = state.tenant_id
      AND existing.action = 'tenant.authorization.migration_backfilled'
      AND existing.resource_type = 'tenant'
      AND existing.resource_id = state.tenant_id
      AND existing.outcome = 'success'
      AND existing.metadata ->> 'migration'
        = '0025_authorization_compatibility_and_ownership'
  )
ORDER BY state.tenant_id;
