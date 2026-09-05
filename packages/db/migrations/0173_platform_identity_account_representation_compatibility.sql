-- V37 seals the split account-representation revisions introduced by
-- migrations 0171-0172. The v36 root cannot describe those columns, triggers,
-- or the composite retirement ABI, so it is retired fail-closed.
ALTER FUNCTION app.schema_compatibility_v36()
  SET app.schema_compatibility_fingerprint = 'RETIRED';
REVOKE ALL ON FUNCTION app.schema_compatibility_v36()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
  periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
REVOKE ALL ON FUNCTION app.platform_identity_runtime_schema_readiness_v2()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
  periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
--> statement-breakpoint

-- Derive the journal root only from the attested v36 implementation. The
-- migration count includes this compatibility checkpoint itself (0000-0173).
DO $derive_schema_compatibility_v37$
DECLARE
  predecessor_definition text;
  derived_definition text;
  predecessor_source_hash text;
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(
           pg_catalog.convert_to(function_row.prosrc,'UTF8')
         ),'hex')
    INTO STRICT predecessor_definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid = 'app.schema_compatibility_v36()'::regprocedure;
  IF predecessor_source_hash IS DISTINCT FROM
       '565cd14cde70a795cb2e4a118eed68a1585c3496255edfaea08788e42e135989' THEN
    RAISE EXCEPTION 'schema compatibility v36 predecessor drifted'
      USING ERRCODE = '55000';
  END IF;

  derived_definition := pg_catalog.replace(
    predecessor_definition,'schema_compatibility_v36','schema_compatibility_v37'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,
    'SET "app.schema_compatibility_fingerprint" TO ''RETIRED''',
    'SET "app.schema_compatibility_fingerprint" TO ''UNSEALED'''
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'1788062677386','1788067083196'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'journal_count = 170','journal_count = 174'
  );
  IF derived_definition = predecessor_definition
     OR derived_definition LIKE '%schema_compatibility_v36%'
     OR derived_definition LIKE
       '%app.schema_compatibility_fingerprint" TO ''RETIRED''%'
     OR derived_definition LIKE '%1788062677386%'
     OR derived_definition LIKE '%journal_count = 170%' THEN
    RAISE EXCEPTION 'schema compatibility v37 derivation was not exact'
      USING ERRCODE = '55000';
  END IF;
  EXECUTE derived_definition;
END;
$derive_schema_compatibility_v37$;
ALTER FUNCTION app.schema_compatibility_v37() OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.schema_compatibility_v37()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
  periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v37()
TO periapsis_api, periapsis_worker;
--> statement-breakpoint

-- The catalog transcript is forward-derived so the retired v36 roots become
-- ordinary attested dependencies and only the four v37 roots are self-excluded.
DO $derive_platform_identity_dependency_surface_v3$
DECLARE
  predecessor_definition text;
  derived_definition text;
  predecessor_source_hash text;
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(
           pg_catalog.convert_to(function_row.prosrc,'UTF8')
         ),'hex')
    INTO STRICT predecessor_definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid =
    'app.private_platform_identity_dependency_surface_hash_v2()'::regprocedure;
  IF predecessor_source_hash IS DISTINCT FROM
       '6a8c4ddd4a219c10033e60b1cdd85d4e7c72980abdc83695cfc8b3e9ffc76852' THEN
    RAISE EXCEPTION 'platform identity dependency v2 predecessor drifted'
      USING ERRCODE = '55000';
  END IF;

  derived_definition := pg_catalog.replace(
    predecessor_definition,
    'private_platform_identity_dependency_surface_hash_v2',
    'private_platform_identity_dependency_surface_hash_v3'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,
    'private_platform_identity_runtime_schema_readiness_v2',
    'private_platform_identity_runtime_schema_readiness_v3'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,
    'platform_identity_runtime_schema_readiness_v2',
    'platform_identity_runtime_schema_readiness_v3'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'schema_compatibility_v36','schema_compatibility_v37'
  );
  IF derived_definition = predecessor_definition
     OR derived_definition LIKE
       '%private_platform_identity_dependency_surface_hash_v2%'
     OR derived_definition LIKE
       '%private_platform_identity_runtime_schema_readiness_v2%'
     OR derived_definition LIKE
       '%platform_identity_runtime_schema_readiness_v2%'
     OR derived_definition LIKE '%schema_compatibility_v36%' THEN
    RAISE EXCEPTION 'platform identity dependency v3 derivation was not exact'
      USING ERRCODE = '55000';
  END IF;
  EXECUTE derived_definition;
END;
$derive_platform_identity_dependency_surface_v3$;
ALTER FUNCTION app.private_platform_identity_dependency_surface_hash_v3()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION
  app.private_platform_identity_dependency_surface_hash_v3()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
  periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
--> statement-breakpoint

-- Derive the comprehensive readiness body from v36, then make only the
-- representation-specific changes. Every replacement is checked before the
-- derived function is installed so a predecessor formatting drift fails closed.
DO $derive_platform_identity_runtime_readiness_v3$
DECLARE
  predecessor_definition text;
  derived_definition text;
  predecessor_source_hash text;
  dependency_source_hash text;
  function_entry_marker constant text :=
    '    (''app.guard_platform_identity_account_command_v1()'',';
  function_entry_replacement constant text :=
    '    (''app.retire_platform_identity_account_v1(uuid,uuid,uuid,bigint,uuid,uuid,uuid,inet,text,text,text)'',' || chr(10) ||
    '      ARRAY[''periapsis_migrator'']::text[]),' || chr(10) ||
    '    (''app.guard_platform_federated_external_identity_v3()'',' || chr(10) ||
    '      ARRAY[''periapsis_migrator'']::text[]),' || chr(10) ||
    '    (''app.guard_user_platform_identity_projection_v1()'',' || chr(10) ||
    '      ARRAY[''periapsis_migrator'']::text[]),' || chr(10) ||
    '    (''app.guard_platform_identity_account_command_v1()'',';
  catalog_marker constant text :=
    '  IF EXISTS (' || chr(10) ||
    '       SELECT 1' || chr(10) ||
    '       FROM ONLY public.platform_federated_provider_policies AS policy';
  catalog_checks constant text := $checks$
  IF NOT (
    SELECT count(*) = 2 AND coalesce(bool_and(
      column_row.atttypid = 'bigint'::pg_catalog.regtype
      AND column_row.attnotnull
      AND pg_catalog.pg_get_expr(default_row.adbin,default_row.adrelid) = '1'
    ),false)
    FROM (VALUES
      ('public.users'::regclass,'version'::name),
      ('public.platform_federated_external_identities'::regclass,
       'resource_version'::name)
    ) AS expected(relation_id,column_name)
    JOIN pg_catalog.pg_attribute AS column_row
      ON column_row.attrelid = expected.relation_id
     AND column_row.attname = expected.column_name
     AND column_row.attnum > 0 AND NOT column_row.attisdropped
    JOIN pg_catalog.pg_attrdef AS default_row
      ON default_row.adrelid = column_row.attrelid
     AND default_row.adnum = column_row.attnum
  ) OR NOT (
    SELECT count(*) = 2 AND coalesce(bool_and(
      constraint_row.contype = 'c'
      AND constraint_row.conenforced AND constraint_row.convalidated
      AND NOT constraint_row.condeferrable
      AND NOT constraint_row.condeferred
    ),false)
    FROM pg_catalog.pg_constraint AS constraint_row
    WHERE constraint_row.conname IN (
      'users_version_check',
      'platform_federated_external_identities_lifecycle_check'
    )
  ) OR NOT (
    SELECT count(*) = 3 AND coalesce(bool_and(
      trigger_row.tgenabled = 'O' AND NOT trigger_row.tgisinternal
      AND CASE trigger_row.tgname
        WHEN 'platform_federated_external_identities_guard_v3' THEN
          trigger_row.tgrelid =
            'public.platform_federated_external_identities'::regclass
          AND trigger_row.tgfoid =
            'app.guard_platform_federated_external_identity_v3()'::regprocedure
        WHEN 'users_platform_identity_projection_insert_guard_v1' THEN
          trigger_row.tgrelid = 'public.users'::regclass
          AND trigger_row.tgfoid =
            'app.guard_user_platform_identity_projection_v1()'::regprocedure
        WHEN 'users_platform_identity_projection_update_guard_v1' THEN
          trigger_row.tgrelid = 'public.users'::regclass
          AND trigger_row.tgfoid =
            'app.guard_user_platform_identity_projection_v1()'::regprocedure
        ELSE false
      END
    ),false)
    FROM pg_catalog.pg_trigger AS trigger_row
    WHERE trigger_row.tgname IN (
      'platform_federated_external_identities_guard_v3',
      'users_platform_identity_projection_insert_guard_v1',
      'users_platform_identity_projection_update_guard_v1'
    )
  ) OR EXISTS (
    SELECT 1 FROM pg_catalog.pg_trigger AS trigger_row
    WHERE trigger_row.tgrelid =
      'public.platform_federated_external_identities'::regclass
      AND NOT trigger_row.tgisinternal
      AND trigger_row.tgname <>
        'platform_federated_external_identities_guard_v3'
  ) THEN
    RETURN false;
  END IF;

$checks$;
  function_marker constant text :=
    '  SELECT pg_catalog.pg_get_functiondef(' || chr(10) ||
    '    ''app.create_platform_oidc_auth_provider_v2';
  function_checks constant text := $checks$
  SELECT pg_catalog.pg_get_functiondef(
    'app.private_platform_identity_account_document_v1(uuid,uuid)'::regprocedure
  ) INTO function_definition;
  IF function_definition NOT LIKE '%''version'', identity.resource_version%'
     OR function_definition NOT LIKE '%''version'', local_user.version%'
     OR function_definition LIKE '%''version'', identity.version%' THEN
    RETURN false;
  END IF;
  SELECT pg_catalog.pg_get_functiondef(
    'app.retire_platform_identity_account_v2(uuid,uuid,uuid,bigint,bigint,uuid,uuid,uuid,inet,text,text,text)'::regprocedure
  ) INTO function_definition;
  IF function_definition NOT LIKE '%p_expected_user_version bigint%'
     OR function_definition NOT LIKE
       '%identity_record.resource_version <> p_expected_version%'
     OR function_definition NOT LIKE
       '%user_record.version <> p_expected_user_version%'
     OR function_definition NOT LIKE
       '%resource_version = identity.resource_version + 1%'
     OR function_definition NOT LIKE
       '%last_observed_at = identity.last_observed_at%' THEN
    RETURN false;
  END IF;
  SELECT pg_catalog.pg_get_functiondef(
    'app.guard_platform_federated_external_identity_v3()'::regprocedure
  ) INTO function_definition;
  IF function_definition NOT LIKE '%NEW.version <> OLD.version%'
     OR function_definition NOT LIKE
       '%NEW.resource_version := OLD.resource_version + 1%'
     OR function_definition NOT LIKE
       '%NEW.last_observed_at := OLD.last_observed_at%' THEN
    RETURN false;
  END IF;
  SELECT pg_catalog.pg_get_functiondef(
    'app.guard_user_platform_identity_projection_v1()'::regprocedure
  ) INTO function_definition;
  IF function_definition NOT LIKE
       '%ROW(NEW.display_name, NEW.email, NEW.active)%'
     OR function_definition NOT LIKE '%NEW.version := OLD.version + 1%'
     OR function_definition LIKE '%platform_federated_external_identities%' THEN
    RETURN false;
  END IF;

$checks$;
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(
           pg_catalog.convert_to(function_row.prosrc,'UTF8')
         ),'hex')
    INTO STRICT predecessor_definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid =
    'app.private_platform_identity_runtime_schema_readiness_v2()'::regprocedure;
  IF predecessor_source_hash IS DISTINCT FROM
       '49c633206b2c8615fe4de53d61d57fdb562e9483c12a510cfbec9fc3171d4786' THEN
    RAISE EXCEPTION 'platform identity readiness v2 predecessor drifted'
      USING ERRCODE = '55000';
  END IF;
  SELECT pg_catalog.encode(pg_catalog.sha256(
           pg_catalog.convert_to(function_row.prosrc,'UTF8')
         ),'hex') INTO STRICT dependency_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid =
    'app.private_platform_identity_dependency_surface_hash_v3()'::regprocedure;

  derived_definition := pg_catalog.replace(
    predecessor_definition,
    'private_platform_identity_runtime_schema_readiness_v2',
    'private_platform_identity_runtime_schema_readiness_v3'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,
    'private_platform_identity_dependency_surface_hash_v2',
    'private_platform_identity_dependency_surface_hash_v3'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'platform_identity_runtime_schema_readiness_v2',
    'platform_identity_runtime_schema_readiness_v3'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'schema_compatibility_v36','schema_compatibility_v37'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'schema_compatibility_v35','schema_compatibility_v36'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,
    '6a8c4ddd4a219c10033e60b1cdd85d4e7c72980abdc83695cfc8b3e9ffc76852',
    dependency_source_hash
  );
  derived_definition := pg_catalog.replace(
    derived_definition,
    'dbe197debc5813ff66b9d7ad38c1cf273537f587d9d2612dea829e0709c3dfa9',
    '979433a414c409eac3080c233832c73cb34db6427fc603b7eb49dc71b5ca8473'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,
    'app.retire_platform_identity_account_v1(uuid,uuid,uuid,bigint,uuid,uuid,uuid,inet,text,text,text)',
    'app.retire_platform_identity_account_v2(uuid,uuid,uuid,bigint,bigint,uuid,uuid,uuid,inet,text,text,text)'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'SELECT count(*) = 11','SELECT count(*) = 14'
  );
  IF pg_catalog.strpos(derived_definition,function_entry_marker) = 0
     OR pg_catalog.strpos(derived_definition,catalog_marker) = 0
     OR pg_catalog.strpos(derived_definition,function_marker) = 0 THEN
    RAISE EXCEPTION 'platform identity readiness v3 markers drifted'
      USING ERRCODE = '55000';
  END IF;
  derived_definition := pg_catalog.replace(
    derived_definition,function_entry_marker,function_entry_replacement
  );
  derived_definition := pg_catalog.replace(
    derived_definition,catalog_marker,catalog_checks || catalog_marker
  );
  derived_definition := pg_catalog.replace(
    derived_definition,function_marker,function_checks || function_marker
  );
  IF derived_definition = predecessor_definition
     OR derived_definition LIKE
       '%private_platform_identity_runtime_schema_readiness_v2%'
     OR derived_definition LIKE
       '%private_platform_identity_dependency_surface_hash_v2%'
     OR derived_definition LIKE
       '%platform_identity_runtime_schema_readiness_v2%'
     OR derived_definition LIKE '%schema_compatibility_v35%'
     OR derived_definition LIKE '%SELECT count(*) = 11%'
     OR derived_definition NOT LIKE
       '%979433a414c409eac3080c233832c73cb34db6427fc603b7eb49dc71b5ca8473%' THEN
    RAISE EXCEPTION 'platform identity readiness v3 derivation was not exact'
      USING ERRCODE = '55000';
  END IF;
  EXECUTE derived_definition;
END;
$derive_platform_identity_runtime_readiness_v3$;
ALTER FUNCTION app.private_platform_identity_runtime_schema_readiness_v3()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION
  app.private_platform_identity_runtime_schema_readiness_v3()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
  periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
--> statement-breakpoint

DO $derive_platform_identity_runtime_public_readiness_v3$
DECLARE
  predecessor_definition text;
  derived_definition text;
  predecessor_source_hash text;
  private_marker constant text :=
    '    AND app.private_platform_identity_runtime_schema_readiness_v3();';
  predecessor_acl_checks constant text :=
    '    AND NOT pg_catalog.has_function_privilege(' || chr(10) ||
    '      ''periapsis_api'',' || chr(10) ||
    '      ''app.platform_identity_runtime_schema_readiness_v2()''::regprocedure,' || chr(10) ||
    '      ''EXECUTE''' || chr(10) ||
    '    )' || chr(10) ||
    '    AND NOT pg_catalog.has_function_privilege(' || chr(10) ||
    '      ''periapsis_worker'',' || chr(10) ||
    '      ''app.platform_identity_runtime_schema_readiness_v2()''::regprocedure,' || chr(10) ||
    '      ''EXECUTE''' || chr(10) ||
    '    )' || chr(10);
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(
           pg_catalog.convert_to(function_row.prosrc,'UTF8')
         ),'hex')
    INTO STRICT predecessor_definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid =
    'app.platform_identity_runtime_schema_readiness_v2()'::regprocedure;
  IF predecessor_source_hash IS DISTINCT FROM
       'a5af721101d16393a87fc9c84dce62749f73711a364c0281f6e4c709c52c8257' THEN
    RAISE EXCEPTION 'platform identity public readiness v2 predecessor drifted'
      USING ERRCODE = '55000';
  END IF;

  derived_definition := pg_catalog.replace(
    predecessor_definition,'platform_identity_runtime_schema_readiness_v2',
    'platform_identity_runtime_schema_readiness_v3'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'private_platform_identity_runtime_schema_readiness_v2',
    'private_platform_identity_runtime_schema_readiness_v3'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'schema_compatibility_v36','schema_compatibility_v37'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'schema_compatibility_v35','schema_compatibility_v36'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'current_count = 170','current_count = 174'
  );
  IF pg_catalog.strpos(derived_definition,private_marker) = 0 THEN
    RAISE EXCEPTION 'platform identity public readiness v3 marker drifted'
      USING ERRCODE = '55000';
  END IF;
  derived_definition := pg_catalog.replace(
    derived_definition,private_marker,
    predecessor_acl_checks || private_marker
  );
  IF derived_definition = predecessor_definition
     OR derived_definition LIKE
       '%private_platform_identity_runtime_schema_readiness_v2%'
     OR derived_definition LIKE
       '%platform_identity_runtime_schema_readiness_v2();%'
     OR derived_definition LIKE '%schema_compatibility_v35%'
     OR derived_definition LIKE '%current_count = 170%' THEN
    RAISE EXCEPTION 'platform identity public readiness v3 derivation was not exact'
      USING ERRCODE = '55000';
  END IF;
  EXECUTE derived_definition;
END;
$derive_platform_identity_runtime_public_readiness_v3$;
ALTER FUNCTION app.platform_identity_runtime_schema_readiness_v3()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.platform_identity_runtime_schema_readiness_v3()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
  periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION app.platform_identity_runtime_schema_readiness_v3()
TO periapsis_api, periapsis_worker;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.seal_schema_compatibility_manifest(
  p_expected_count bigint,
  p_expected_latest_created_at bigint,
  p_expected_latest_hash text,
  p_expected_migration_fingerprint text
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  journal_count bigint;
  journal_latest_created_at bigint;
  journal_latest_hash text;
  journal_fingerprint text;
  sealed_count bigint;
  sealed_latest_created_at bigint;
  sealed_latest_hash text;
  sealed_fingerprint text;
BEGIN
  IF p_expected_count IS DISTINCT FROM 174
     OR p_expected_latest_created_at IS DISTINCT FROM 1788067083196
     OR p_expected_latest_hash !~ '^[0-9a-f]{64}$'
     OR p_expected_migration_fingerprint !~
       '^[0-9]+@[0-9a-f]{64}(:[0-9]+@[0-9a-f]{64}){173}$' THEN
    RAISE EXCEPTION 'schema compatibility v37 seal input is invalid'
      USING ERRCODE = '55000';
  END IF;
  EXECUTE $query$
    SELECT count(*)::bigint,max(migration.created_at)::bigint,
           (SELECT lower(latest.hash::text)
            FROM drizzle.__drizzle_migrations AS latest
            ORDER BY latest.created_at DESC,latest.id DESC LIMIT 1),
           string_agg(
             migration.created_at::text || '@' || lower(migration.hash::text),
             ':' ORDER BY migration.created_at,migration.id
           )
    FROM drizzle.__drizzle_migrations AS migration
  $query$ INTO journal_count,journal_latest_created_at,journal_latest_hash,
                journal_fingerprint;
  IF ROW(journal_count,journal_latest_created_at,journal_latest_hash,
         journal_fingerprint) IS DISTINCT FROM
     ROW(p_expected_count,p_expected_latest_created_at,p_expected_latest_hash,
         p_expected_migration_fingerprint)
     OR NOT app.private_platform_identity_runtime_schema_readiness_v3()
     OR pg_catalog.has_function_privilege(
       'periapsis_api','app.schema_compatibility_v36()'::regprocedure,'EXECUTE'
     )
     OR pg_catalog.has_function_privilege(
       'periapsis_worker','app.schema_compatibility_v36()'::regprocedure,'EXECUTE'
     )
     OR pg_catalog.has_function_privilege(
       'periapsis_api',
       'app.platform_identity_runtime_schema_readiness_v2()'::regprocedure,
       'EXECUTE'
     )
     OR pg_catalog.has_function_privilege(
       'periapsis_worker',
       'app.platform_identity_runtime_schema_readiness_v2()'::regprocedure,
       'EXECUTE'
     ) THEN
    RAISE EXCEPTION 'schema compatibility v37 cannot be sealed'
      USING ERRCODE = '55000';
  END IF;

  EXECUTE pg_catalog.format(
    'ALTER FUNCTION app.schema_compatibility_v37() SET app.schema_compatibility_fingerprint = %L',
    p_expected_migration_fingerprint
  );
  SELECT compatibility.applied_count,compatibility.latest_created_at,
         compatibility.latest_hash,compatibility.migration_fingerprint
    INTO sealed_count,sealed_latest_created_at,sealed_latest_hash,
         sealed_fingerprint
  FROM app.schema_compatibility_v37() AS compatibility;
  IF ROW(sealed_count,sealed_latest_created_at,sealed_latest_hash,
         sealed_fingerprint) IS DISTINCT FROM
     ROW(p_expected_count,p_expected_latest_created_at,p_expected_latest_hash,
         p_expected_migration_fingerprint)
     OR NOT app.platform_identity_runtime_schema_readiness_v3() THEN
    RAISE EXCEPTION 'schema compatibility v37 seal verification failed'
      USING ERRCODE = '55000';
  END IF;
END;
$function$;
ALTER FUNCTION app.seal_schema_compatibility_manifest(
  bigint,bigint,text,text
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.seal_schema_compatibility_manifest(
  bigint,bigint,text,text
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
  periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION app.seal_schema_compatibility_manifest(
  bigint,bigint,text,text
) TO periapsis_migrator;
