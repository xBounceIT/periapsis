-- Preserve complete audit evidence when a new manual service-account role
-- grant supersedes expired-but-unrevoked predecessors. Migrations 0037 and
-- 0038 are immutable; this forward replacement also advances the v6
-- readiness manifest to the complete 40-row ADR-0008 journal.
CREATE OR REPLACE FUNCTION "app"."grant_tenant_service_account_role_v1"(
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
  superseded_role_grants jsonb := '[]'::jsonb;
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

  SELECT coalesce(jsonb_agg(jsonb_build_object(
           'role_grant_id', expired_grant.id,
           'prior_version', expired_grant.version,
           'result_version', expired_grant.version + 1
         ) ORDER BY expired_grant.id), '[]'::jsonb)
    INTO superseded_role_grants
  FROM public.tenant_service_account_role_grants AS expired_grant
  WHERE expired_grant.tenant_id = context_tenant
    AND expired_grant.service_account_id = p_service_account_id
    AND expired_grant.role_id = p_role_id
    AND expired_grant.source_id = manual_source
    AND expired_grant.revoked_at IS NULL
    AND expired_grant.expires_at <= transaction_timestamp()
    AND expired_grant.version < 2147483647;

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
    AND expired_grant.expires_at <= transaction_timestamp()
    AND expired_grant.version < 2147483647;

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
      'exact_consequences_checked', consequences_checked,
      'superseded_role_grants', superseded_role_grants
    )
  );

  RETURN QUERY SELECT p_grant_id, 1::integer;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION "app"."grant_tenant_service_account_role_v1"(uuid, uuid, uuid, text, timestamp with time zone, uuid, uuid, inet, text, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."grant_tenant_service_account_role_v1"(uuid, uuid, uuid, text, timestamp with time zone, uuid, uuid, inet, text, text) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."grant_tenant_service_account_role_v1"(uuid, uuid, uuid, text, timestamp with time zone, uuid, uuid, inet, text, text) TO "periapsis_api";--> statement-breakpoint

-- v6 remains the current ADR-0008 projection and now accepts only the exact
-- 40-row journal including this forward audit repair.
CREATE OR REPLACE FUNCTION "app"."schema_compatibility_v6"()
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
DECLARE
  journal_count bigint;
  journal_latest_created_at bigint;
  migration_0039_rows bigint;
  journal_created_at bigint[];
BEGIN
  EXECUTE $query$
    SELECT
      count(*)::bigint,
      max(migration.created_at)::bigint,
      count(*) FILTER (
        WHERE migration.created_at = 1787613749000
      )::bigint,
      array_agg(
        migration.created_at::bigint
        ORDER BY migration.created_at, migration.id
      )
    FROM drizzle.__drizzle_migrations AS migration
  $query$
  INTO
    journal_count,
    journal_latest_created_at,
    migration_0039_rows,
    journal_created_at;

  IF journal_count = 40
     AND journal_latest_created_at = 1787613749000
     AND migration_0039_rows = 1
     AND journal_created_at = ARRAY[
       1787472409685, 1787472415216, 1787473527702, 1787473536723,
       1787474082034, 1787474089267, 1787475027656, 1787475184077,
       1787488565252, 1787488569966, 1787492910536, 1787493031146,
       1787494284382, 1787495115125, 1787495293635, 1787495819997,
       1787495999394, 1787496124539, 1787496880587, 1787496982733,
       1787496987011, 1787501702276, 1787506296280, 1787507888755,
       1787508523197, 1787516694668, 1787571776845, 1787581350373,
       1787581530382, 1787582150087, 1787591930962, 1787591938733,
       1787592230466, 1787612620574, 1787613580320, 1787613592459,
       1787613744526, 1787613746038, 1787613747552, 1787613749000
     ]::bigint[] THEN
    RETURN QUERY EXECUTE $query$
      SELECT
        count(*)::bigint AS applied_count,
        max(migration.created_at)::bigint AS latest_created_at,
        (
          SELECT lower(latest_migration.hash::text)
          FROM drizzle.__drizzle_migrations AS latest_migration
          ORDER BY latest_migration.created_at DESC, latest_migration.id DESC
          LIMIT 1
        ) AS latest_hash,
        string_agg(
          migration.created_at::text || '@' || lower(migration.hash::text),
          ':' ORDER BY migration.created_at, migration.id
        ) AS migration_fingerprint
      FROM drizzle.__drizzle_migrations AS migration
    $query$;
    RETURN;
  END IF;

  RETURN QUERY
  SELECT 0::bigint,
         0::bigint,
         'UNSUPPORTED'::text,
         'UNSUPPORTED'::text;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION "app"."schema_compatibility_v6"() OWNER TO "periapsis_migrator";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."schema_compatibility_v6"() FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."schema_compatibility_v6"() TO "periapsis_api", "periapsis_worker";--> statement-breakpoint

-- Keep v5 available to the immediately preceding release only when a
-- migrator has sealed this exact 40-row v6 journal.
CREATE OR REPLACE FUNCTION "app"."schema_compatibility_v5"()
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
  migration_0032_rows bigint;
  migration_0039_rows bigint;
BEGIN
  SELECT compatibility.applied_count,
         compatibility.latest_created_at,
         compatibility.migration_fingerprint
  INTO journal_count, journal_latest_created_at, journal_fingerprint
  FROM app.schema_compatibility_v6() AS compatibility;

  EXECUTE $query$
    SELECT
      count(*) FILTER (
        WHERE migration.created_at = 1787592230466
      )::bigint,
      count(*) FILTER (
        WHERE migration.created_at = 1787613749000
      )::bigint
    FROM drizzle.__drizzle_migrations AS migration
  $query$
  INTO migration_0032_rows, migration_0039_rows;

  IF journal_count = 40
     AND journal_latest_created_at = 1787613749000
     AND migration_0032_rows = 1
     AND migration_0039_rows = 1
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
          WHERE latest_prefix_migration.migration_ordinal = 33
        ) AS latest_hash,
        string_agg(
          migration.created_at::text || '@' || migration.migration_hash,
          ':' ORDER BY migration.created_at, migration.id
        ) AS migration_fingerprint
      FROM ordered_migrations AS migration
      WHERE migration.migration_ordinal <= 33
    $query$;
    RETURN;
  END IF;

  RETURN QUERY
  SELECT 0::bigint,
         0::bigint,
         'UNSUPPORTED'::text,
         'UNSUPPORTED'::text;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION "app"."schema_compatibility_v5"() OWNER TO "periapsis_migrator";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."schema_compatibility_v5"() FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."schema_compatibility_v5"() TO "periapsis_api", "periapsis_worker";--> statement-breakpoint

-- The canonical migrator supplies the generated v6 manifest. The routine is
-- private and accepts only this exact 40-timestamp release journal.
CREATE OR REPLACE FUNCTION "app"."seal_schema_compatibility_manifest"(
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
  predecessor_count bigint;
  predecessor_latest_created_at bigint;
  predecessor_latest_hash text;
  predecessor_migration_fingerprint text;
  expected_predecessor_hash text;
  expected_predecessor_fingerprint text;
  fingerprint_entries text[];
  fingerprint_created_at bigint[];
BEGIN
  fingerprint_entries := string_to_array(
    p_expected_migration_fingerprint,
    ':'
  );
  IF p_expected_count IS DISTINCT FROM 40
     OR p_expected_latest_created_at IS DISTINCT FROM 1787613749000
     OR p_expected_latest_hash IS NULL
     OR p_expected_latest_hash !~ '^[0-9a-f]{64}$'
     OR p_expected_migration_fingerprint IS NULL
     OR p_expected_migration_fingerprint !~ '^[1-9][0-9]*@[0-9a-f]{64}(:[1-9][0-9]*@[0-9a-f]{64})*$'
     OR cardinality(fingerprint_entries) IS DISTINCT FROM 40
     OR fingerprint_entries[40] IS DISTINCT FROM (
          p_expected_latest_created_at::text || '@' || p_expected_latest_hash
        ) THEN
    RAISE EXCEPTION 'invalid schema compatibility v6 manifest'
      USING ERRCODE = '22023';
  END IF;

  SELECT array_agg(
           split_part(entry.value, '@', 1)::bigint
           ORDER BY entry.ordinality
         )
  INTO fingerprint_created_at
  FROM unnest(fingerprint_entries) WITH ORDINALITY AS entry(value, ordinality);

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
       1787613744526, 1787613746038, 1787613747552, 1787613749000
     ]::bigint[] THEN
    RAISE EXCEPTION 'invalid schema compatibility v6 timestamp sequence'
      USING ERRCODE = '22023';
  END IF;

  SELECT compatibility.applied_count,
         compatibility.latest_created_at,
         compatibility.latest_hash,
         compatibility.migration_fingerprint
  INTO actual_count,
       actual_latest_created_at,
       actual_latest_hash,
       actual_migration_fingerprint
  FROM app.schema_compatibility_v6() AS compatibility;

  IF actual_count IS DISTINCT FROM p_expected_count
     OR actual_latest_created_at IS DISTINCT FROM p_expected_latest_created_at
     OR actual_latest_hash IS DISTINCT FROM p_expected_latest_hash
     OR actual_migration_fingerprint IS DISTINCT FROM p_expected_migration_fingerprint THEN
    RAISE EXCEPTION 'schema compatibility v6 manifest does not match the applied journal'
      USING ERRCODE = '55000';
  END IF;

  PERFORM set_config(
    'app.schema_compatibility_fingerprint',
    p_expected_migration_fingerprint,
    true
  );
  EXECUTE $statement$
    ALTER FUNCTION app.schema_compatibility_v5()
      SET app.schema_compatibility_fingerprint FROM CURRENT
  $statement$;

  expected_predecessor_hash := split_part(fingerprint_entries[33], '@', 2);
  expected_predecessor_fingerprint := array_to_string(
    fingerprint_entries[1:33],
    ':'
  );
  SELECT compatibility.applied_count,
         compatibility.latest_created_at,
         compatibility.latest_hash,
         compatibility.migration_fingerprint
  INTO predecessor_count,
       predecessor_latest_created_at,
       predecessor_latest_hash,
       predecessor_migration_fingerprint
  FROM app.schema_compatibility_v5() AS compatibility;

  IF predecessor_count IS DISTINCT FROM 33
     OR predecessor_latest_created_at IS DISTINCT FROM 1787592230466
     OR predecessor_latest_hash IS DISTINCT FROM expected_predecessor_hash
     OR predecessor_migration_fingerprint IS DISTINCT FROM
          expected_predecessor_fingerprint THEN
    RAISE EXCEPTION 'sealed schema compatibility v5 prefix is not exact'
      USING ERRCODE = '55000';
  END IF;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION "app"."seal_schema_compatibility_manifest"(bigint, bigint, text, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."seal_schema_compatibility_manifest"(bigint, bigint, text, text) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";
