-- V38 seals the explicit last-observation provenance introduced by 0174-0175.
-- V37 cannot describe the nullable legacy projection or the replacement ABI.
ALTER FUNCTION app.schema_compatibility_v37()
  SET app.schema_compatibility_fingerprint = 'RETIRED';
REVOKE ALL ON FUNCTION app.schema_compatibility_v37()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
  periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
REVOKE ALL ON FUNCTION app.platform_identity_runtime_schema_readiness_v3()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
  periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
--> statement-breakpoint

-- The migration count includes this checkpoint itself (0000-0176).
DO $derive_schema_compatibility_v38$
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
  WHERE function_row.oid = 'app.schema_compatibility_v37()'::regprocedure;
  IF predecessor_source_hash IS DISTINCT FROM
       'cbfac359101b7b16f12c96cbb19a6697a47f48cf1f63b342ed9d1c503265bae5' THEN
    RAISE EXCEPTION 'schema compatibility v37 predecessor drifted'
      USING ERRCODE = '55000';
  END IF;

  derived_definition := pg_catalog.replace(
    predecessor_definition,'schema_compatibility_v37','schema_compatibility_v38'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,
    'SET "app.schema_compatibility_fingerprint" TO ''RETIRED''',
    'SET "app.schema_compatibility_fingerprint" TO ''UNSEALED'''
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'1788067083196','1788069336676'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'journal_count = 174','journal_count = 177'
  );
  IF derived_definition = predecessor_definition
     OR derived_definition LIKE '%schema_compatibility_v37%'
     OR derived_definition LIKE
       '%app.schema_compatibility_fingerprint" TO ''RETIRED''%'
     OR derived_definition LIKE '%1788067083196%'
     OR derived_definition LIKE '%journal_count = 174%' THEN
    RAISE EXCEPTION 'schema compatibility v38 derivation was not exact'
      USING ERRCODE = '55000';
  END IF;
  EXECUTE derived_definition;
END;
$derive_schema_compatibility_v38$;
ALTER FUNCTION app.schema_compatibility_v38() OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.schema_compatibility_v38()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
  periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v38()
TO periapsis_api, periapsis_worker;
--> statement-breakpoint

DO $derive_platform_identity_dependency_surface_v4$
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
    'app.private_platform_identity_dependency_surface_hash_v3()'::regprocedure;
  IF predecessor_source_hash IS DISTINCT FROM
       '3b41d269386c8eb449eec630606165ab29b480d059d23423047cdeb8a6edfc04' THEN
    RAISE EXCEPTION 'platform identity dependency v3 predecessor drifted'
      USING ERRCODE = '55000';
  END IF;

  derived_definition := pg_catalog.replace(
    predecessor_definition,
    'private_platform_identity_dependency_surface_hash_v3',
    'private_platform_identity_dependency_surface_hash_v4'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,
    'private_platform_identity_runtime_schema_readiness_v3',
    'private_platform_identity_runtime_schema_readiness_v4'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,
    'platform_identity_runtime_schema_readiness_v3',
    'platform_identity_runtime_schema_readiness_v4'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'schema_compatibility_v37','schema_compatibility_v38'
  );
  IF derived_definition = predecessor_definition
     OR derived_definition LIKE
       '%private_platform_identity_dependency_surface_hash_v3%'
     OR derived_definition LIKE
       '%private_platform_identity_runtime_schema_readiness_v3%'
     OR derived_definition LIKE
       '%platform_identity_runtime_schema_readiness_v3%'
     OR derived_definition LIKE '%schema_compatibility_v37%' THEN
    RAISE EXCEPTION 'platform identity dependency v4 derivation was not exact'
      USING ERRCODE = '55000';
  END IF;
  EXECUTE derived_definition;
END;
$derive_platform_identity_dependency_surface_v4$;
ALTER FUNCTION app.private_platform_identity_dependency_surface_hash_v4()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION
  app.private_platform_identity_dependency_surface_hash_v4()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
  periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
--> statement-breakpoint

DO $derive_platform_identity_runtime_readiness_v4$
DECLARE
  predecessor_definition text;
  derived_definition text;
  predecessor_source_hash text;
  dependency_source_hash text;
  active_list_entry constant text :=
    '    (''app.list_platform_identity_accounts_v1(uuid,text,uuid,uuid,integer,boolean)'',' || chr(10) ||
    '      ARRAY[''periapsis_api'',''periapsis_migrator'']::text[]),';
  replacement_list_entries constant text :=
    '    (''app.list_platform_identity_accounts_v1(uuid,text,uuid,uuid,integer,boolean)'',' || chr(10) ||
    '      ARRAY[''periapsis_migrator'']::text[]),' || chr(10) ||
    '    (''app.list_platform_identity_accounts_v2(uuid,text,uuid,uuid,integer,boolean)'',' || chr(10) ||
    '      ARRAY[''periapsis_api'',''periapsis_migrator'']::text[]),';
  active_get_entry constant text :=
    '    (''app.get_platform_identity_account_v1(uuid,uuid,uuid,text)'',' || chr(10) ||
    '      ARRAY[''periapsis_api'',''periapsis_migrator'']::text[]),';
  replacement_get_entries constant text :=
    '    (''app.get_platform_identity_account_v1(uuid,uuid,uuid,text)'',' || chr(10) ||
    '      ARRAY[''periapsis_migrator'']::text[]),' || chr(10) ||
    '    (''app.get_platform_identity_account_v2(uuid,uuid,uuid,text)'',' || chr(10) ||
    '      ARRAY[''periapsis_api'',''periapsis_migrator'']::text[]),';
  active_prelink_entry constant text :=
    '    (''app.prelink_platform_identity_account_v1(uuid,uuid,uuid,uuid,uuid,text,public.identity_subject_format,bytea,bytea,integer,integer[],bytea[],bytea,bytea,uuid,uuid,uuid,inet,text,text,text)'',' || chr(10) ||
    '      ARRAY[''periapsis_api'',''periapsis_migrator'']::text[]),';
  replacement_prelink_entries constant text :=
    '    (''app.prelink_platform_identity_account_v1(uuid,uuid,uuid,uuid,uuid,text,public.identity_subject_format,bytea,bytea,integer,integer[],bytea[],bytea,bytea,uuid,uuid,uuid,inet,text,text,text)'',' || chr(10) ||
    '      ARRAY[''periapsis_migrator'']::text[]),' || chr(10) ||
    '    (''app.prelink_platform_identity_account_v2(uuid,uuid,uuid,uuid,uuid,text,public.identity_subject_format,bytea,bytea,integer,integer[],bytea[],bytea,bytea,uuid,uuid,uuid,inet,text,text,text)'',' || chr(10) ||
    '      ARRAY[''periapsis_api'',''periapsis_migrator'']::text[]),';
  active_retire_entry constant text :=
    '    (''app.retire_platform_identity_account_v2(uuid,uuid,uuid,bigint,bigint,uuid,uuid,uuid,inet,text,text,text)'',' || chr(10) ||
    '      ARRAY[''periapsis_api'',''periapsis_migrator'']::text[]),';
  replacement_retire_entries constant text :=
    '    (''app.retire_platform_identity_account_v2(uuid,uuid,uuid,bigint,bigint,uuid,uuid,uuid,inet,text,text,text)'',' || chr(10) ||
    '      ARRAY[''periapsis_migrator'']::text[]),' || chr(10) ||
    '    (''app.retire_platform_identity_account_v3(uuid,uuid,uuid,bigint,bigint,uuid,uuid,uuid,inet,text,text,text)'',' || chr(10) ||
    '      ARRAY[''periapsis_api'',''periapsis_migrator'']::text[]),';
  old_guard_entry constant text :=
    '    (''app.guard_platform_federated_external_identity_v3()'',' || chr(10) ||
    '      ARRAY[''periapsis_migrator'']::text[]),';
  replacement_guard_entries constant text :=
    '    (''app.guard_platform_federated_external_identity_v3()'',' || chr(10) ||
    '      ARRAY[''periapsis_migrator'']::text[]),' || chr(10) ||
    '    (''app.guard_platform_federated_external_identity_v4()'',' || chr(10) ||
    '      ARRAY[''periapsis_migrator'']::text[]),';
  new_guard_entry constant text :=
    '    (''app.guard_platform_federated_external_identity_v4()'',' || chr(10) ||
    '      ARRAY[''periapsis_migrator'']::text[]),';
  old_document_entry constant text :=
    '    (''app.private_platform_identity_account_document_v1(uuid,uuid)'',' || chr(10) ||
    '      ARRAY[''periapsis_migrator'']::text[]),';
  replacement_document_entries constant text :=
    '    (''app.private_platform_identity_account_document_v1(uuid,uuid)'',' || chr(10) ||
    '      ARRAY[''periapsis_migrator'']::text[]),' || chr(10) ||
    '    (''app.private_platform_identity_account_document_v2(uuid,uuid)'',' || chr(10) ||
    '      ARRAY[''periapsis_migrator'']::text[]),';
  new_document_entry constant text :=
    '    (''app.private_platform_identity_account_document_v2(uuid,uuid)'',' || chr(10) ||
    '      ARRAY[''periapsis_migrator'']::text[]),';
  catalog_marker constant text :=
    '  IF NOT (' || chr(10) ||
    '    SELECT count(*) = 2 AND coalesce(bool_and(';
  observation_catalog_checks constant text := $checks$
  IF NOT (
    SELECT count(*) = 1 AND coalesce(bool_and(
      column_row.atttypid = 'text'::pg_catalog.regtype
      AND column_row.attnotnull
      AND pg_catalog.pg_get_expr(default_row.adbin,default_row.adrelid) =
        '''known''::text'
    ),false)
    FROM pg_catalog.pg_attribute AS column_row
    JOIN pg_catalog.pg_attrdef AS default_row
      ON default_row.adrelid = column_row.attrelid
     AND default_row.adnum = column_row.attnum
    WHERE column_row.attrelid =
      'public.platform_federated_external_identities'::regclass
      AND column_row.attname = 'last_observation_state'
      AND column_row.attnum > 0 AND NOT column_row.attisdropped
  ) OR NOT (
    SELECT count(*) = 1 AND coalesce(bool_and(
      constraint_row.contype = 'c'
      AND constraint_row.conenforced AND constraint_row.convalidated
      AND NOT constraint_row.condeferrable
      AND NOT constraint_row.condeferred
    ),false)
    FROM pg_catalog.pg_constraint AS constraint_row
    WHERE constraint_row.conrelid =
      'public.platform_federated_external_identities'::regclass
      AND constraint_row.conname =
        'platform_federated_external_identities_observation_state_check'
  ) OR EXISTS (
    SELECT 1
    FROM ONLY public.platform_federated_external_identities AS identity
    WHERE (
      identity.retired_at IS NOT NULL
      AND identity.resource_version = 1
      AND identity.last_observed_at = identity.retired_at
      AND identity.last_observation_state <> 'legacy_unknown'
    ) OR (
      identity.last_observation_state = 'legacy_unknown'
      AND NOT (
        identity.retired_at IS NOT NULL
        AND identity.resource_version = 1
        AND identity.last_observed_at = identity.retired_at
      )
    )
  ) THEN
    RETURN false;
  END IF;

$checks$;
  function_marker constant text :=
    '  SELECT pg_catalog.pg_get_functiondef(' || chr(10) ||
    '    ''app.private_platform_identity_account_document_v2(uuid,uuid)''::regprocedure';
  observation_function_checks constant text := $checks$
  SELECT pg_catalog.pg_get_functiondef(
    'app.private_platform_identity_account_document_v2(uuid,uuid)'::regprocedure
  ) INTO function_definition;
  IF function_definition NOT LIKE
       '%''lastObservationState'', identity.last_observation_state%'
     OR function_definition NOT LIKE
       '%WHEN identity.last_observation_state = ''known''%'
     OR function_definition NOT LIKE '%ELSE NULL%'
     OR function_definition NOT LIKE
       '%''lastObservedAt'', CASE%' THEN
    RETURN false;
  END IF;
  SELECT pg_catalog.pg_get_functiondef(
    'app.guard_platform_federated_external_identity_v4()'::regprocedure
  ) INTO function_definition;
  IF function_definition NOT LIKE
       '%NEW.last_observation_state <> ''known''%'
     OR function_definition NOT LIKE
       '%NEW.last_observation_state,%'
     OR function_definition NOT LIKE
       '%OLD.last_observation_state,%'
     OR function_definition NOT LIKE
       '%NEW.last_observation_state := OLD.last_observation_state%' THEN
    RETURN false;
  END IF;
  SELECT pg_catalog.pg_get_functiondef(
    'app.prelink_platform_identity_account_v2(uuid,uuid,uuid,uuid,uuid,text,public.identity_subject_format,bytea,bytea,integer,integer[],bytea[],bytea,bytea,uuid,uuid,uuid,inet,text,text,text)'::regprocedure
  ) INTO function_definition;
  IF function_definition NOT LIKE
       '%FROM app.prelink_platform_identity_account_v1(%'
     OR function_definition NOT LIKE
       '%app.private_platform_identity_account_document_v2(%' THEN
    RETURN false;
  END IF;
  SELECT pg_catalog.pg_get_functiondef(
    'app.retire_platform_identity_account_v3(uuid,uuid,uuid,bigint,bigint,uuid,uuid,uuid,inet,text,text,text)'::regprocedure
  ) INTO function_definition;
  IF function_definition NOT LIKE
       '%FROM app.retire_platform_identity_account_v2(%'
     OR function_definition NOT LIKE
       '%app.private_platform_identity_account_document_v2(%' THEN
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
    'app.private_platform_identity_runtime_schema_readiness_v3()'::regprocedure;
  IF predecessor_source_hash IS DISTINCT FROM
       '06e01a9db32d73fa077a05b4729fb8e75178d0b2f0933e0cbdd4be4102356a4b' THEN
    RAISE EXCEPTION 'platform identity readiness v3 predecessor drifted'
      USING ERRCODE = '55000';
  END IF;
  SELECT pg_catalog.encode(pg_catalog.sha256(
           pg_catalog.convert_to(function_row.prosrc,'UTF8')
         ),'hex') INTO STRICT dependency_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid =
    'app.private_platform_identity_dependency_surface_hash_v4()'::regprocedure;

  derived_definition := pg_catalog.replace(
    predecessor_definition,
    'private_platform_identity_runtime_schema_readiness_v3',
    'private_platform_identity_runtime_schema_readiness_v4'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,
    'private_platform_identity_dependency_surface_hash_v3',
    'private_platform_identity_dependency_surface_hash_v4'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'platform_identity_runtime_schema_readiness_v3',
    'platform_identity_runtime_schema_readiness_v4'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'schema_compatibility_v37','schema_compatibility_v38'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,
    '3b41d269386c8eb449eec630606165ab29b480d059d23423047cdeb8a6edfc04',
    dependency_source_hash
  );
  derived_definition := pg_catalog.replace(
    derived_definition,
    '979433a414c409eac3080c233832c73cb34db6427fc603b7eb49dc71b5ca8473',
    'f078b26e61ed4daa2885a310118c2aacbdcdc4a9d93999fc16fbc1e639e7049f'
  );
  IF pg_catalog.strpos(derived_definition,active_list_entry) = 0
     OR pg_catalog.strpos(derived_definition,active_get_entry) = 0
     OR pg_catalog.strpos(derived_definition,active_prelink_entry) = 0
     OR pg_catalog.strpos(derived_definition,active_retire_entry) = 0
     OR pg_catalog.strpos(derived_definition,old_guard_entry) = 0
     OR pg_catalog.strpos(derived_definition,old_document_entry) = 0
     OR pg_catalog.strpos(derived_definition,catalog_marker) = 0 THEN
    RAISE EXCEPTION 'platform identity readiness v4 markers drifted'
      USING ERRCODE = '55000';
  END IF;
  derived_definition := pg_catalog.replace(
    derived_definition,active_list_entry,replacement_list_entries
  );
  derived_definition := pg_catalog.replace(
    derived_definition,active_get_entry,replacement_get_entries
  );
  derived_definition := pg_catalog.replace(
    derived_definition,active_prelink_entry,replacement_prelink_entries
  );
  derived_definition := pg_catalog.replace(
    derived_definition,active_retire_entry,replacement_retire_entries
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'SELECT count(*) = 14','SELECT count(*) = 20'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,
    'platform_federated_external_identities_guard_v3',
    'platform_federated_external_identities_guard_v4'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,
    'app.guard_platform_federated_external_identity_v3()',
    'app.guard_platform_federated_external_identity_v4()'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,
    'app.private_platform_identity_account_document_v1(uuid,uuid)',
    'app.private_platform_identity_account_document_v2(uuid,uuid)'
  );
  IF pg_catalog.strpos(derived_definition,new_guard_entry) = 0
     OR pg_catalog.strpos(derived_definition,new_document_entry) = 0 THEN
    RAISE EXCEPTION 'platform identity readiness v4 replacement entries drifted'
      USING ERRCODE = '55000';
  END IF;
  derived_definition := pg_catalog.replace(
    derived_definition,new_guard_entry,replacement_guard_entries
  );
  derived_definition := pg_catalog.replace(
    derived_definition,new_document_entry,replacement_document_entries
  );
  IF pg_catalog.strpos(derived_definition,function_marker) = 0 THEN
    RAISE EXCEPTION 'platform identity readiness v4 function marker drifted'
      USING ERRCODE = '55000';
  END IF;
  derived_definition := pg_catalog.replace(
    derived_definition,catalog_marker,
    observation_catalog_checks || catalog_marker
  );
  derived_definition := pg_catalog.replace(
    derived_definition,function_marker,
    observation_function_checks || function_marker
  );
  IF derived_definition = predecessor_definition
     OR derived_definition LIKE
       '%private_platform_identity_runtime_schema_readiness_v3%'
     OR derived_definition LIKE
       '%private_platform_identity_dependency_surface_hash_v3%'
     OR derived_definition LIKE
       '%platform_identity_runtime_schema_readiness_v3%'
     OR derived_definition LIKE '%schema_compatibility_v37%'
     OR derived_definition LIKE '%SELECT count(*) = 14%'
     OR derived_definition NOT LIKE
       '%f078b26e61ed4daa2885a310118c2aacbdcdc4a9d93999fc16fbc1e639e7049f%' THEN
    RAISE EXCEPTION 'platform identity readiness v4 derivation was not exact'
      USING ERRCODE = '55000';
  END IF;
  EXECUTE derived_definition;
END;
$derive_platform_identity_runtime_readiness_v4$;
ALTER FUNCTION app.private_platform_identity_runtime_schema_readiness_v4()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION
  app.private_platform_identity_runtime_schema_readiness_v4()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
  periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
--> statement-breakpoint

DO $derive_platform_identity_runtime_public_readiness_v4$
DECLARE
  predecessor_definition text;
  derived_definition text;
  predecessor_source_hash text;
  private_marker constant text :=
    '    AND app.private_platform_identity_runtime_schema_readiness_v4();';
  predecessor_acl_checks constant text :=
    '    AND NOT pg_catalog.has_function_privilege(' || chr(10) ||
    '      ''periapsis_api'',' || chr(10) ||
    '      ''app.schema_compatibility_v37()''::regprocedure,''EXECUTE''' || chr(10) ||
    '    )' || chr(10) ||
    '    AND NOT pg_catalog.has_function_privilege(' || chr(10) ||
    '      ''periapsis_worker'',' || chr(10) ||
    '      ''app.schema_compatibility_v37()''::regprocedure,''EXECUTE''' || chr(10) ||
    '    )' || chr(10) ||
    '    AND NOT pg_catalog.has_function_privilege(' || chr(10) ||
    '      ''periapsis_api'',' || chr(10) ||
    '      ''app.platform_identity_runtime_schema_readiness_v3()''::regprocedure,' || chr(10) ||
    '      ''EXECUTE''' || chr(10) ||
    '    )' || chr(10) ||
    '    AND NOT pg_catalog.has_function_privilege(' || chr(10) ||
    '      ''periapsis_worker'',' || chr(10) ||
    '      ''app.platform_identity_runtime_schema_readiness_v3()''::regprocedure,' || chr(10) ||
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
    'app.platform_identity_runtime_schema_readiness_v3()'::regprocedure;
  IF predecessor_source_hash IS DISTINCT FROM
       'b5a2b9da53785a7daeff1f6c0c35cc5e376d934f149ca35f8bdff27b6fd8e36a' THEN
    RAISE EXCEPTION 'platform identity public readiness v3 predecessor drifted'
      USING ERRCODE = '55000';
  END IF;

  derived_definition := pg_catalog.replace(
    predecessor_definition,'platform_identity_runtime_schema_readiness_v3',
    'platform_identity_runtime_schema_readiness_v4'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'private_platform_identity_runtime_schema_readiness_v3',
    'private_platform_identity_runtime_schema_readiness_v4'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'schema_compatibility_v37','schema_compatibility_v38'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'current_count = 174','current_count = 177'
  );
  IF pg_catalog.strpos(derived_definition,private_marker) = 0 THEN
    RAISE EXCEPTION 'platform identity public readiness v4 marker drifted'
      USING ERRCODE = '55000';
  END IF;
  derived_definition := pg_catalog.replace(
    derived_definition,private_marker,predecessor_acl_checks || private_marker
  );
  IF derived_definition = predecessor_definition
     OR derived_definition LIKE
       '%platform_identity_runtime_schema_readiness_v3();%'
     OR derived_definition LIKE '%current_count = 174%'
     OR derived_definition NOT LIKE '%schema_compatibility_v37()%' THEN
    RAISE EXCEPTION 'platform identity public readiness v4 derivation was not exact'
      USING ERRCODE = '55000';
  END IF;
  EXECUTE derived_definition;
END;
$derive_platform_identity_runtime_public_readiness_v4$;
ALTER FUNCTION app.platform_identity_runtime_schema_readiness_v4()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.platform_identity_runtime_schema_readiness_v4()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
  periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION app.platform_identity_runtime_schema_readiness_v4()
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
  IF p_expected_count IS DISTINCT FROM 177
     OR p_expected_latest_created_at IS DISTINCT FROM 1788069336676
     OR p_expected_latest_hash !~ '^[0-9a-f]{64}$'
     OR p_expected_migration_fingerprint !~
       '^[0-9]+@[0-9a-f]{64}(:[0-9]+@[0-9a-f]{64}){176}$' THEN
    RAISE EXCEPTION 'schema compatibility v38 seal input is invalid'
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
     OR NOT app.private_platform_identity_runtime_schema_readiness_v4()
     OR pg_catalog.has_function_privilege(
       'periapsis_api','app.schema_compatibility_v37()'::regprocedure,'EXECUTE'
     )
     OR pg_catalog.has_function_privilege(
       'periapsis_worker','app.schema_compatibility_v37()'::regprocedure,'EXECUTE'
     )
     OR pg_catalog.has_function_privilege(
       'periapsis_api',
       'app.platform_identity_runtime_schema_readiness_v3()'::regprocedure,
       'EXECUTE'
     )
     OR pg_catalog.has_function_privilege(
       'periapsis_worker',
       'app.platform_identity_runtime_schema_readiness_v3()'::regprocedure,
       'EXECUTE'
     ) THEN
    RAISE EXCEPTION 'schema compatibility v38 pre-seal verification failed'
      USING ERRCODE = '55000';
  END IF;
  EXECUTE pg_catalog.format(
    'ALTER FUNCTION app.schema_compatibility_v38() SET app.schema_compatibility_fingerprint = %L',
    p_expected_migration_fingerprint
  );
  SELECT compatibility.applied_count,compatibility.latest_created_at,
         compatibility.latest_hash,compatibility.migration_fingerprint
    INTO sealed_count,sealed_latest_created_at,sealed_latest_hash,
         sealed_fingerprint
  FROM app.schema_compatibility_v38() AS compatibility;
  IF ROW(sealed_count,sealed_latest_created_at,sealed_latest_hash,
         sealed_fingerprint) IS DISTINCT FROM
     ROW(p_expected_count,p_expected_latest_created_at,p_expected_latest_hash,
         p_expected_migration_fingerprint)
     OR NOT app.platform_identity_runtime_schema_readiness_v4() THEN
    RAISE EXCEPTION 'schema compatibility v38 seal verification failed'
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
