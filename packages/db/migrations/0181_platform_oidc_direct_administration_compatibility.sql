-- V40 seals the administrable direct platform OIDC lifecycle through a
-- coordinated cutover. V39 remains immutable only as predecessor evidence:
-- V39 binaries reject the advanced journal, the migration-to-seal interval is
-- unsupported, and the V39 runtime roots are retired by the V40 seal.

DO $derive_schema_compatibility_v40$
DECLARE
  predecessor_definition text;
  derived_definition text;
  predecessor_source_hash text;
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8'
         )),'hex')
    INTO STRICT predecessor_definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid = 'app.schema_compatibility_v39()'::regprocedure;
  IF predecessor_source_hash IS DISTINCT FROM
       '0dc92b7ce33b94dd18fd493d07921d4da00a5877e29435f7e90d6ca15aa0d18a' THEN
    RAISE EXCEPTION 'schema compatibility v39 predecessor drifted'
      USING ERRCODE = '55000';
  END IF;
  derived_definition := pg_catalog.replace(
    predecessor_definition,'schema_compatibility_v39',
    'schema_compatibility_v40'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'1788077000000','1788085744122'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'journal_count = 180','journal_count = 182'
  );
  IF derived_definition = predecessor_definition
     OR derived_definition LIKE '%schema_compatibility_v39%'
     OR derived_definition LIKE '%1788077000000%'
     OR derived_definition LIKE '%journal_count = 180%' THEN
    RAISE EXCEPTION 'schema compatibility v40 derivation was not exact'
      USING ERRCODE = '55000';
  END IF;
  EXECUTE derived_definition;
END;
$derive_schema_compatibility_v40$;
ALTER FUNCTION app.schema_compatibility_v40() OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.schema_compatibility_v40()
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,periapsis_sla_api_owner,
  periapsis_sla_worker_owner,periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner,periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v40()
TO periapsis_api,periapsis_worker;
--> statement-breakpoint

-- Capture the released V5 public implementation before replacing that name
-- is retired at the V40 seal.
DO $derive_platform_identity_runtime_public_readiness_v6$
DECLARE
  predecessor_definition text;
  derived_definition text;
  predecessor_source_hash text;
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8'
         )),'hex')
    INTO STRICT predecessor_definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid =
    'app.platform_identity_runtime_schema_readiness_v5()'::regprocedure;
  IF predecessor_source_hash IS DISTINCT FROM
       '6e1b0cfa942596a7ae36a3d15f44e751f2d462444b9a2f5ecae1583633d1d0cb' THEN
    RAISE EXCEPTION 'platform identity public readiness v5 drifted'
      USING ERRCODE = '55000';
  END IF;
  derived_definition := pg_catalog.replace(
    predecessor_definition,'private_platform_identity_runtime_schema_readiness_v5',
    'private_platform_identity_runtime_schema_readiness_v6'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'platform_identity_runtime_schema_readiness_v5',
    'platform_identity_runtime_schema_readiness_v6'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'schema_compatibility_v39','schema_compatibility_v40'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'current_count = 180','current_count = 182'
  );
  IF derived_definition = predecessor_definition
     OR derived_definition LIKE
       '%private_platform_identity_runtime_schema_readiness_v5%'
     OR derived_definition LIKE
       '%platform_identity_runtime_schema_readiness_v5%'
     OR derived_definition LIKE '%schema_compatibility_v39%'
     OR derived_definition LIKE '%current_count = 180%' THEN
    RAISE EXCEPTION 'platform identity public readiness v6 derivation failed'
      USING ERRCODE = '55000';
  END IF;
  EXECUTE derived_definition;
END;
$derive_platform_identity_runtime_public_readiness_v6$;
ALTER FUNCTION app.platform_identity_runtime_schema_readiness_v6()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.platform_identity_runtime_schema_readiness_v6()
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,periapsis_sla_api_owner,
  periapsis_sla_worker_owner,periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner,periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION app.platform_identity_runtime_schema_readiness_v6()
TO periapsis_api,periapsis_worker;
--> statement-breakpoint

DO $derive_platform_identity_dependency_surface_v6$
DECLARE
  predecessor_definition text;
  derived_definition text;
  predecessor_source_hash text;
  exclusion_marker constant text :=
    '        ''private_platform_identity_dependency_surface_hash_v6'',' || chr(10) ||
    '        ''private_platform_identity_runtime_schema_readiness_v6'',' || chr(10) ||
    '        ''platform_identity_runtime_schema_readiness_v6'',' || chr(10) ||
    '        ''schema_compatibility_v40'',' || chr(10) ||
    '        ''private_platform_oidc_direct_dependency_surface_hash_v1'',' || chr(10) ||
    '        ''private_platform_oidc_direct_runtime_schema_readiness_v1'',' || chr(10) ||
    '        ''platform_oidc_direct_runtime_schema_readiness_v1''';
  exclusion_replacement constant text :=
    '        ''private_platform_identity_dependency_surface_hash_v6'',' || chr(10) ||
    '        ''private_platform_identity_runtime_schema_readiness_v6'',' || chr(10) ||
    '        ''platform_identity_runtime_schema_readiness_v6'',' || chr(10) ||
    '        ''schema_compatibility_v40'',' || chr(10) ||
    '        ''private_platform_identity_dependency_surface_hash_v5'',' || chr(10) ||
    '        ''private_platform_identity_runtime_schema_readiness_v5'',' || chr(10) ||
    '        ''platform_identity_runtime_schema_readiness_v5'',' || chr(10) ||
    '        ''schema_compatibility_v39'',' || chr(10) ||
    '        ''private_platform_oidc_direct_dependency_surface_hash_v1'',' || chr(10) ||
    '        ''private_platform_oidc_direct_runtime_schema_readiness_v1'',' || chr(10) ||
    '        ''platform_oidc_direct_runtime_schema_readiness_v1'',' || chr(10) ||
    '        ''private_platform_oidc_direct_dependency_surface_hash_v2'',' || chr(10) ||
    '        ''private_platform_oidc_direct_runtime_schema_readiness_v2'',' || chr(10) ||
    '        ''platform_oidc_direct_runtime_schema_readiness_v2''';
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8'
         )),'hex')
    INTO STRICT predecessor_definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid =
    'app.private_platform_identity_dependency_surface_hash_v5()'::regprocedure;
  IF predecessor_source_hash IS DISTINCT FROM
       '6a28391afdce6696eef764bf08aa3c5cd59926c3720a555548aeea080b086127' THEN
    RAISE EXCEPTION 'platform identity dependency v5 predecessor drifted'
      USING ERRCODE = '55000';
  END IF;
  derived_definition := pg_catalog.replace(
    predecessor_definition,'private_platform_identity_dependency_surface_hash_v5',
    'private_platform_identity_dependency_surface_hash_v6'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'private_platform_identity_runtime_schema_readiness_v5',
    'private_platform_identity_runtime_schema_readiness_v6'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'platform_identity_runtime_schema_readiness_v5',
    'platform_identity_runtime_schema_readiness_v6'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'schema_compatibility_v39','schema_compatibility_v40'
  );
  IF pg_catalog.strpos(derived_definition,exclusion_marker) = 0 THEN
    RAISE EXCEPTION 'platform identity dependency v6 exclusion marker drifted'
      USING ERRCODE = '55000';
  END IF;
  derived_definition := pg_catalog.replace(
    derived_definition,exclusion_marker,exclusion_replacement
  );
  IF derived_definition = predecessor_definition
     OR derived_definition LIKE
       '%private_platform_identity_dependency_surface_hash_v5%regprocedure%'
     OR derived_definition NOT LIKE '%schema_compatibility_v39%'
     OR derived_definition NOT LIKE
       '%private_platform_oidc_direct_dependency_surface_hash_v2%' THEN
    RAISE EXCEPTION 'platform identity dependency v6 derivation failed'
      USING ERRCODE = '55000';
  END IF;
  EXECUTE derived_definition;
END;
$derive_platform_identity_dependency_surface_v6$;
ALTER FUNCTION app.private_platform_identity_dependency_surface_hash_v6()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_platform_identity_dependency_surface_hash_v6()
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,periapsis_sla_api_owner,
  periapsis_sla_worker_owner,periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner,periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION app.private_platform_identity_dependency_surface_hash_v6()
TO periapsis_migrator;
--> statement-breakpoint

DO $derive_platform_oidc_direct_dependency_surface_v2$
DECLARE
  predecessor_definition text;
  derived_definition text;
  predecessor_source_hash text;
  exclusion_marker constant text :=
    '      ''private_platform_oidc_direct_dependency_surface_hash_v2'',' || chr(10) ||
    '      ''private_platform_oidc_direct_runtime_schema_readiness_v2'',' || chr(10) ||
    '      ''platform_oidc_direct_runtime_schema_readiness_v2''';
  exclusion_replacement constant text :=
    '      ''private_platform_oidc_direct_dependency_surface_hash_v2'',' || chr(10) ||
    '      ''private_platform_oidc_direct_runtime_schema_readiness_v2'',' || chr(10) ||
    '      ''platform_oidc_direct_runtime_schema_readiness_v2'',' || chr(10) ||
    '      ''private_platform_oidc_direct_dependency_surface_hash_v1'',' || chr(10) ||
    '      ''private_platform_oidc_direct_runtime_schema_readiness_v1'',' || chr(10) ||
    '      ''platform_oidc_direct_runtime_schema_readiness_v1''';
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8'
         )),'hex')
    INTO STRICT predecessor_definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid =
    'app.private_platform_oidc_direct_dependency_surface_hash_v1()'::regprocedure;
  IF predecessor_source_hash IS DISTINCT FROM
       '4d86365af67a2e98aef60473360474ae6b69d30c6548ff9605514fcb6133febe' THEN
    RAISE EXCEPTION 'direct platform OIDC dependency v1 predecessor drifted'
      USING ERRCODE = '55000';
  END IF;
  derived_definition := pg_catalog.replace(
    predecessor_definition,'private_platform_oidc_direct_dependency_surface_hash_v1',
    'private_platform_oidc_direct_dependency_surface_hash_v2'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'private_platform_oidc_direct_runtime_schema_readiness_v1',
    'private_platform_oidc_direct_runtime_schema_readiness_v2'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'platform_oidc_direct_runtime_schema_readiness_v1',
    'platform_oidc_direct_runtime_schema_readiness_v2'
  );
  IF pg_catalog.strpos(derived_definition,exclusion_marker) = 0 THEN
    RAISE EXCEPTION 'direct platform OIDC dependency v2 exclusion marker drifted'
      USING ERRCODE = '55000';
  END IF;
  derived_definition := pg_catalog.replace(
    derived_definition,exclusion_marker,exclusion_replacement
  );
  IF derived_definition = predecessor_definition
     OR derived_definition NOT LIKE
       '%private_platform_oidc_direct_dependency_surface_hash_v1%'
     OR derived_definition NOT LIKE
       '%private_platform_oidc_direct_dependency_surface_hash_v2%' THEN
    RAISE EXCEPTION 'direct platform OIDC dependency v2 derivation failed'
      USING ERRCODE = '55000';
  END IF;
  EXECUTE derived_definition;
END;
$derive_platform_oidc_direct_dependency_surface_v2$;
ALTER FUNCTION app.private_platform_oidc_direct_dependency_surface_hash_v2()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION
  app.private_platform_oidc_direct_dependency_surface_hash_v2()
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,periapsis_sla_api_owner,
  periapsis_sla_worker_owner,periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner,periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION
  app.private_platform_oidc_direct_dependency_surface_hash_v2()
TO periapsis_migrator;
--> statement-breakpoint

DO $derive_platform_oidc_direct_private_readiness_v2$
DECLARE
  predecessor_definition text;
  derived_definition text;
  predecessor_source_hash text;
  dependency_source_hash text;
  dependency_surface_hash text;
  dormant_invariant constant text := $old$
  IF EXISTS (
    SELECT 1
    FROM ONLY public.platform_federated_provider_policies AS runtime_policy
    WHERE runtime_policy.platform_login_enabled
  ) OR EXISTS (
    SELECT 1
    FROM ONLY public.platform_auth_providers AS provider
    LEFT JOIN ONLY public.platform_oidc_login_policies AS login_policy
      ON login_policy.provider_id = provider.id
    WHERE provider.kind = 'oidc' AND (
      login_policy.provider_id IS NULL
      OR login_policy.account_mode <> 'disabled'
      OR login_policy.enabled
      OR login_policy.revision <> 1
    )
  ) OR EXISTS (
    SELECT 1
    FROM ONLY public.platform_oidc_login_policies AS login_policy
    JOIN ONLY public.platform_auth_providers AS provider
      ON provider.id = login_policy.provider_id
    WHERE provider.kind <> 'oidc'
  ) THEN
    RETURN false;
  END IF;
$old$;
  lifecycle_invariant constant text := $new$
  IF EXISTS (
    SELECT 1
    FROM ONLY public.platform_federated_provider_policies AS runtime_policy
    WHERE runtime_policy.platform_login_enabled
  ) OR EXISTS (
    SELECT 1
    FROM ONLY public.platform_auth_providers AS provider
    LEFT JOIN ONLY public.platform_federated_provider_policies AS runtime_policy
      ON runtime_policy.provider_id = provider.id
     AND runtime_policy.provider_kind = 'oidc'
    LEFT JOIN ONLY public.platform_oidc_login_policies AS login_policy
      ON login_policy.provider_id = provider.id
     AND login_policy.provider_kind = 'oidc'
    WHERE provider.kind = 'oidc' AND (
      login_policy.provider_id IS NULL
      OR login_policy.revision < 1
      OR (login_policy.enabled AND login_policy.account_mode <>
        'existing_identity')
      OR (NOT login_policy.enabled AND login_policy.account_mode <> 'disabled')
      OR (login_policy.enabled AND (
        NOT provider.enabled OR provider.archived_at IS NOT NULL
        OR runtime_policy.provider_id IS NULL OR NOT runtime_policy.enabled
        OR runtime_policy.platform_login_enabled
        OR app.private_platform_oidc_direct_configuration_v1(
          provider.id,NULL
        ) IS NULL
      ))
    )
  ) OR EXISTS (
    SELECT 1
    FROM ONLY public.platform_oidc_login_policies AS login_policy
    JOIN ONLY public.platform_auth_providers AS provider
      ON provider.id = login_policy.provider_id
    WHERE provider.kind <> 'oidc'
  ) THEN
    RETURN false;
  END IF;
$new$;
  tenant_switch_entry constant text :=
    '      (''app.apply_platform_oidc_tenant_switch_v1(jsonb)''),';
  administration_entries constant text := tenant_switch_entry || chr(10) ||
    '      (''app.lookup_platform_oidc_tenant_switch_replay_v1(jsonb)''),' || chr(10) ||
    '      (''app.activate_platform_oidc_direct_login_v1(uuid,uuid,bigint,uuid,uuid,uuid,inet,text,text,text)''),' || chr(10) ||
    '      (''app.deactivate_platform_oidc_direct_login_v1(uuid,uuid,bigint,uuid,uuid,uuid,inet,text,text,text)''),';
  private_marker constant text :=
    '        ''guard_platform_oidc_login_policy_v1'',';
  private_replacement constant text := private_marker || chr(10) ||
    '        ''guard_platform_auth_provider_binding_dependency_v1'',' || chr(10) ||
    '        ''guard_platform_oidc_direct_runtime_dependency_v1'',' || chr(10) ||
    '        ''private_platform_auth_provider_document_v1'',' || chr(10) ||
    '        ''private_platform_oidc_direct_activation_available_v1'',' || chr(10) ||
    '        ''set_platform_oidc_direct_login_activation_v1'',';
  final_marker constant text :=
    '  RETURN true;' || chr(10) || 'END;';
  v40_checks constant text := $checks$
  IF NOT (
    SELECT count(*) = 2 AND coalesce(bool_and(
      NOT trigger_row.tgisinternal AND trigger_row.tgenabled = 'O'
      AND trigger_row.tgfoid = CASE trigger_row.tgname
        WHEN 'platform_oidc_login_policies_guard_v1' THEN
          'app.guard_platform_oidc_login_policy_v1()'::regprocedure
        ELSE
          'app.guard_platform_oidc_direct_runtime_dependency_v1()'::regprocedure
      END
    ),false)
    FROM pg_catalog.pg_trigger AS trigger_row
    WHERE (trigger_row.tgrelid,trigger_row.tgname) IN (
      ('public.platform_oidc_login_policies'::regclass,
       'platform_oidc_login_policies_guard_v1'),
      ('public.platform_federated_provider_policies'::regclass,
       'platform_oidc_direct_runtime_dependency_guard_v1')
    )
  ) THEN
    RETURN false;
  END IF;
  IF pg_catalog.pg_get_functiondef(
       'app.private_platform_auth_provider_document_v1(uuid)'::regprocedure
     ) NOT LIKE
       '%platform_oidc_login_policies AS login_policy%'
     OR pg_catalog.pg_get_functiondef(
       'app.private_platform_auth_provider_document_v1(uuid)'::regprocedure
     ) NOT LIKE
       '%WHEN ''oidc'' THEN coalesce(login_policy.enabled, false)%'
     OR pg_catalog.pg_get_functiondef(
       'app.private_platform_auth_provider_document_v1(uuid)'::regprocedure
     ) NOT LIKE '%ELSE false END%' THEN
    RETURN false;
  END IF;
  IF pg_catalog.pg_get_functiondef(
       'app.list_platform_auth_providers_v1(uuid,text,uuid,integer,boolean)'::regprocedure
     ) NOT LIKE
       '%platform_oidc_login_policies AS login_policy%'
     OR pg_catalog.pg_get_functiondef(
       'app.list_platform_auth_providers_v1(uuid,text,uuid,integer,boolean)'::regprocedure
     ) NOT LIKE
       '%WHEN ''oidc'' THEN coalesce(login_policy.enabled, false)%'
     OR pg_catalog.pg_get_functiondef(
       'app.list_platform_auth_providers_v1(uuid,text,uuid,integer,boolean)'::regprocedure
     ) NOT LIKE '%ELSE false END%' THEN
    RETURN false;
  END IF;

$checks$;
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8'
         )),'hex')
    INTO STRICT predecessor_definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid =
    'app.private_platform_oidc_direct_runtime_schema_readiness_v1()'::regprocedure;
  IF predecessor_source_hash IS DISTINCT FROM
       '227a05995959e439c1bd1318c0ecdcdcc61178fd3aa66e95ad9dc201ff74ff3e' THEN
    RAISE EXCEPTION 'direct platform OIDC private readiness v1 drifted'
      USING ERRCODE = '55000';
  END IF;
  SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8'
         )),'hex')
    INTO STRICT dependency_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid =
    'app.private_platform_oidc_direct_dependency_surface_hash_v2()'::regprocedure;
  dependency_surface_hash :=
    app.private_platform_oidc_direct_dependency_surface_hash_v2();
  IF dependency_surface_hash !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'direct platform OIDC dependency v2 surface is invalid'
      USING ERRCODE = '55000';
  END IF;
  derived_definition := pg_catalog.replace(
    predecessor_definition,'private_platform_oidc_direct_runtime_schema_readiness_v1',
    'private_platform_oidc_direct_runtime_schema_readiness_v2'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'private_platform_oidc_direct_dependency_surface_hash_v1',
    'private_platform_oidc_direct_dependency_surface_hash_v2'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,
    '4d86365af67a2e98aef60473360474ae6b69d30c6548ff9605514fcb6133febe',
    dependency_source_hash
  );
  derived_definition := pg_catalog.replace(
    derived_definition,
    '314be1f25c22af04d55868c1fcefa537884765d0c9083ef203aad1d8fed225df',
    dependency_surface_hash
  );
  IF pg_catalog.strpos(derived_definition,dormant_invariant) = 0
     OR pg_catalog.strpos(derived_definition,tenant_switch_entry) = 0
     OR pg_catalog.strpos(derived_definition,private_marker) = 0
     OR pg_catalog.strpos(derived_definition,final_marker) = 0 THEN
    RAISE EXCEPTION 'direct platform OIDC readiness v2 marker drifted'
      USING ERRCODE = '55000';
  END IF;
  derived_definition := pg_catalog.replace(
    derived_definition,dormant_invariant,lifecycle_invariant
  );
  derived_definition := pg_catalog.replace(
    derived_definition,tenant_switch_entry,administration_entries
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'SELECT count(*) = 21 AND coalesce(bool_and(',
    'SELECT count(*) = 24 AND coalesce(bool_and('
  );
  derived_definition := pg_catalog.replace(
    derived_definition,private_marker,private_replacement
  );
  derived_definition := pg_catalog.replace(
    derived_definition,final_marker,v40_checks || final_marker
  );
  IF derived_definition = predecessor_definition
     OR derived_definition LIKE
       '%private_platform_oidc_direct_runtime_schema_readiness_v1%regprocedure%'
     OR derived_definition NOT LIKE '%SELECT count(*) = 24%'
     OR derived_definition NOT LIKE '%' || dependency_surface_hash || '%'
     OR derived_definition NOT LIKE
       '%lookup_platform_oidc_tenant_switch_replay_v1%' THEN
    RAISE EXCEPTION 'direct platform OIDC readiness v2 derivation failed'
      USING ERRCODE = '55000';
  END IF;
  EXECUTE derived_definition;
END;
$derive_platform_oidc_direct_private_readiness_v2$;
ALTER FUNCTION app.private_platform_oidc_direct_runtime_schema_readiness_v2()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION
  app.private_platform_oidc_direct_runtime_schema_readiness_v2()
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,periapsis_sla_api_owner,
  periapsis_sla_worker_owner,periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner,periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION
  app.private_platform_oidc_direct_runtime_schema_readiness_v2()
TO periapsis_migrator;
--> statement-breakpoint

DO $derive_platform_oidc_direct_public_readiness_v2$
DECLARE
  predecessor_definition text;
  derived_definition text;
  predecessor_source_hash text;
  private_marker constant text :=
    '    AND app.private_platform_oidc_direct_runtime_schema_readiness_v2();';
  v40_checks constant text :=
    '    AND NOT pg_catalog.has_function_privilege(' || chr(10) ||
    '      ''periapsis_api'',''app.schema_compatibility_v39()''::regprocedure,' || chr(10) ||
    '      ''EXECUTE''' || chr(10) ||
    '    )' || chr(10) ||
    '    AND NOT pg_catalog.has_function_privilege(' || chr(10) ||
    '      ''periapsis_worker'',''app.schema_compatibility_v39()''::regprocedure,' || chr(10) ||
    '      ''EXECUTE''' || chr(10) ||
    '    )' || chr(10) ||
    '    AND NOT pg_catalog.has_function_privilege(' || chr(10) ||
    '      ''periapsis_api'',' || chr(10) ||
    '      ''app.platform_identity_runtime_schema_readiness_v5()''::regprocedure,' || chr(10) ||
    '      ''EXECUTE''' || chr(10) ||
    '    )' || chr(10) ||
    '    AND NOT pg_catalog.has_function_privilege(' || chr(10) ||
    '      ''periapsis_worker'',' || chr(10) ||
    '      ''app.platform_identity_runtime_schema_readiness_v5()''::regprocedure,' || chr(10) ||
    '      ''EXECUTE''' || chr(10) ||
    '    )' || chr(10) ||
    '    AND NOT pg_catalog.has_function_privilege(' || chr(10) ||
    '      ''periapsis_api'',' || chr(10) ||
    '      ''app.platform_oidc_direct_runtime_schema_readiness_v1()''::regprocedure,' || chr(10) ||
    '      ''EXECUTE''' || chr(10) ||
    '    )' || chr(10) ||
    '    AND NOT pg_catalog.has_function_privilege(' || chr(10) ||
    '      ''periapsis_worker'',' || chr(10) ||
    '      ''app.platform_oidc_direct_runtime_schema_readiness_v1()''::regprocedure,' || chr(10) ||
    '      ''EXECUTE''' || chr(10) ||
    '    )' || chr(10) ||
    '    AND app.platform_identity_runtime_schema_readiness_v6()' || chr(10);
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8'
         )),'hex')
    INTO STRICT predecessor_definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid =
    'app.platform_oidc_direct_runtime_schema_readiness_v1()'::regprocedure;
  IF predecessor_source_hash IS DISTINCT FROM
       '139387c939e4c446eec5f4e61bdd1b032e7b904daced4fcaaa02143c930ff953' THEN
    RAISE EXCEPTION 'direct platform OIDC public readiness v1 drifted'
      USING ERRCODE = '55000';
  END IF;
  derived_definition := pg_catalog.replace(
    predecessor_definition,'private_platform_oidc_direct_runtime_schema_readiness_v1',
    'private_platform_oidc_direct_runtime_schema_readiness_v2'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'platform_oidc_direct_runtime_schema_readiness_v1',
    'platform_oidc_direct_runtime_schema_readiness_v2'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'schema_compatibility_v39','schema_compatibility_v40'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'current_count = 180','current_count = 182'
  );
  IF pg_catalog.strpos(derived_definition,private_marker) = 0 THEN
    RAISE EXCEPTION 'direct platform OIDC public readiness v2 marker drifted'
      USING ERRCODE = '55000';
  END IF;
  derived_definition := pg_catalog.replace(
    derived_definition,private_marker,v40_checks || private_marker
  );
  IF derived_definition = predecessor_definition
     OR derived_definition LIKE '%current_count = 180%'
     OR derived_definition NOT LIKE
       '%platform_identity_runtime_schema_readiness_v6%' THEN
    RAISE EXCEPTION 'direct platform OIDC public readiness v2 derivation failed'
      USING ERRCODE = '55000';
  END IF;
  EXECUTE derived_definition;
END;
$derive_platform_oidc_direct_public_readiness_v2$;
ALTER FUNCTION app.platform_oidc_direct_runtime_schema_readiness_v2()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.platform_oidc_direct_runtime_schema_readiness_v2()
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,periapsis_sla_api_owner,
  periapsis_sla_worker_owner,periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner,periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION app.platform_oidc_direct_runtime_schema_readiness_v2()
TO periapsis_api,periapsis_worker;
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
  predecessor_count bigint;
BEGIN
  IF p_expected_count IS DISTINCT FROM 182
     OR p_expected_latest_created_at IS DISTINCT FROM 1788085744122
     OR p_expected_latest_hash !~ '^[0-9a-f]{64}$'
     OR p_expected_migration_fingerprint !~
       '^[0-9]+@[0-9a-f]{64}(:[0-9]+@[0-9a-f]{64}){181}$' THEN
    RAISE EXCEPTION 'schema compatibility v40 seal input is invalid'
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
     OR NOT app.private_platform_identity_runtime_schema_readiness_v6()
     OR NOT app.private_platform_oidc_direct_runtime_schema_readiness_v2()
     OR pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
       (SELECT function_row.prosrc FROM pg_catalog.pg_proc AS function_row
        WHERE function_row.oid =
          'app.schema_compatibility_v39()'::regprocedure),'UTF8'
     )),'hex') <>
       '0dc92b7ce33b94dd18fd493d07921d4da00a5877e29435f7e90d6ca15aa0d18a'
     OR pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
       (SELECT function_row.prosrc FROM pg_catalog.pg_proc AS function_row
        WHERE function_row.oid =
          'app.platform_identity_runtime_schema_readiness_v5()'::regprocedure),
       'UTF8'
     )),'hex') <>
       '6e1b0cfa942596a7ae36a3d15f44e751f2d462444b9a2f5ecae1583633d1d0cb'
     OR pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
       (SELECT function_row.prosrc FROM pg_catalog.pg_proc AS function_row
        WHERE function_row.oid =
          'app.platform_oidc_direct_runtime_schema_readiness_v1()'::regprocedure),
       'UTF8'
     )),'hex') <>
       '139387c939e4c446eec5f4e61bdd1b032e7b904daced4fcaaa02143c930ff953'
  THEN
    RAISE EXCEPTION 'schema compatibility v40 pre-seal verification failed'
      USING ERRCODE = '55000';
  END IF;

  -- The migration-to-seal interval is deliberately unsupported.  Only after
  -- all V40 private checks pass do we publish V40 and retire every V39 runtime
  -- readiness root in the same sealing transaction.
  EXECUTE pg_catalog.format(
    'ALTER FUNCTION app.schema_compatibility_v40() SET app.schema_compatibility_fingerprint = %L',
    p_expected_migration_fingerprint
  );
  EXECUTE $ddl$
    ALTER FUNCTION app.schema_compatibility_v39()
      SET app.schema_compatibility_fingerprint = 'RETIRED'
  $ddl$;
  EXECUTE $ddl$
    REVOKE ALL ON FUNCTION app.schema_compatibility_v39()
      FROM periapsis_api,periapsis_worker
  $ddl$;
  EXECUTE $ddl$
    REVOKE ALL ON FUNCTION app.platform_identity_runtime_schema_readiness_v5()
      FROM periapsis_api,periapsis_worker
  $ddl$;
  EXECUTE $ddl$
    REVOKE ALL ON FUNCTION app.platform_oidc_direct_runtime_schema_readiness_v1()
      FROM periapsis_api,periapsis_worker
  $ddl$;

  SELECT compatibility.applied_count,compatibility.latest_created_at,
         compatibility.latest_hash,compatibility.migration_fingerprint
    INTO sealed_count,sealed_latest_created_at,sealed_latest_hash,
         sealed_fingerprint
  FROM app.schema_compatibility_v40() AS compatibility;
  SELECT compatibility.applied_count INTO predecessor_count
  FROM app.schema_compatibility_v39() AS compatibility;
  IF ROW(sealed_count,sealed_latest_created_at,sealed_latest_hash,
         sealed_fingerprint) IS DISTINCT FROM
     ROW(p_expected_count,p_expected_latest_created_at,p_expected_latest_hash,
         p_expected_migration_fingerprint)
     OR predecessor_count <> 0
     OR NOT app.platform_identity_runtime_schema_readiness_v6()
     OR NOT app.platform_oidc_direct_runtime_schema_readiness_v2()
     OR pg_catalog.has_function_privilege(
       'periapsis_api','app.schema_compatibility_v39()'::regprocedure,'EXECUTE'
     )
     OR pg_catalog.has_function_privilege(
       'periapsis_worker','app.schema_compatibility_v39()'::regprocedure,'EXECUTE'
     )
     OR pg_catalog.has_function_privilege(
       'periapsis_api',
       'app.platform_identity_runtime_schema_readiness_v5()'::regprocedure,
       'EXECUTE'
     )
     OR pg_catalog.has_function_privilege(
       'periapsis_worker',
       'app.platform_identity_runtime_schema_readiness_v5()'::regprocedure,
       'EXECUTE'
     )
     OR pg_catalog.has_function_privilege(
       'periapsis_api',
       'app.platform_oidc_direct_runtime_schema_readiness_v1()'::regprocedure,
       'EXECUTE'
     )
     OR pg_catalog.has_function_privilege(
       'periapsis_worker',
       'app.platform_oidc_direct_runtime_schema_readiness_v1()'::regprocedure,
       'EXECUTE'
     ) THEN
    RAISE EXCEPTION 'schema compatibility v40 seal verification failed'
      USING ERRCODE = '55000';
  END IF;
END;
$function$;
ALTER FUNCTION app.seal_schema_compatibility_manifest(
  bigint,bigint,text,text
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.seal_schema_compatibility_manifest(
  bigint,bigint,text,text
) FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,periapsis_sla_api_owner,
  periapsis_sla_worker_owner,periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner,periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION app.seal_schema_compatibility_manifest(
  bigint,bigint,text,text
) TO periapsis_migrator;
--> statement-breakpoint

-- The identity transcript intentionally covers every non-root application
-- function, including the final sealer.  Bind the private V6 verifier only
-- after that complete catalog exists.
DO $bind_platform_identity_runtime_private_readiness_v6$
DECLARE
  predecessor_definition text;
  derived_definition text;
  predecessor_source_hash text;
  dependency_source_hash text;
  dependency_surface_hash text;
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8'
         )),'hex')
    INTO STRICT predecessor_definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid =
    'app.private_platform_identity_runtime_schema_readiness_v5()'::regprocedure;
  IF predecessor_source_hash IS DISTINCT FROM
       '3320ebf764f8562fb242f634c2f9307b3fc77c3757e25c89edd67e2183db1830' THEN
    RAISE EXCEPTION 'platform identity private readiness v5 drifted'
      USING ERRCODE = '55000';
  END IF;
  SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8'
         )),'hex')
    INTO STRICT dependency_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid =
    'app.private_platform_identity_dependency_surface_hash_v6()'::regprocedure;
  dependency_surface_hash :=
    app.private_platform_identity_dependency_surface_hash_v6();
  IF dependency_surface_hash !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'platform identity dependency v6 surface is invalid'
      USING ERRCODE = '55000';
  END IF;
  derived_definition := pg_catalog.replace(
    predecessor_definition,'private_platform_identity_runtime_schema_readiness_v5',
    'private_platform_identity_runtime_schema_readiness_v6'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'private_platform_identity_dependency_surface_hash_v5',
    'private_platform_identity_dependency_surface_hash_v6'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'platform_identity_runtime_schema_readiness_v5',
    'platform_identity_runtime_schema_readiness_v6'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'schema_compatibility_v39','schema_compatibility_v40'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,
    '6a28391afdce6696eef764bf08aa3c5cd59926c3720a555548aeea080b086127',
    dependency_source_hash
  );
  derived_definition := pg_catalog.replace(
    derived_definition,
    'a096dcc3b17fd035a87d2d52fdb4d8817f5a6c7fa666aee8fd2c2cc6d4217273',
    dependency_surface_hash
  );
  EXECUTE derived_definition;
END;
$bind_platform_identity_runtime_private_readiness_v6$;
ALTER FUNCTION app.private_platform_identity_runtime_schema_readiness_v6()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_platform_identity_runtime_schema_readiness_v6()
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,periapsis_sla_api_owner,
  periapsis_sla_worker_owner,periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner,periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION app.private_platform_identity_runtime_schema_readiness_v6()
TO periapsis_migrator;
--> statement-breakpoint
