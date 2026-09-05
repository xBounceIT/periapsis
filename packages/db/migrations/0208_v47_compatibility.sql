-- Preserve the immutable V46 convergence evidence while decoupling the V47
-- journal from capability functions that the V47 cutover intentionally
-- supersedes. The attested normalized V45 fingerprint must still be the exact
-- prefix of the live migration journal.
CREATE FUNCTION app.private_v47_migration_convergence_schema_readiness_v1()
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
DECLARE
  v45_count bigint;
  v45_latest bigint;
  v_metadata_hash text;
  v_compatibility_hash text;
  v_raw_fingerprint text;
  v_normalized_fingerprint text;
BEGIN
  IF pg_catalog.to_regclass(
       'drizzle.__periapsis_migration_convergence_attestations'
     ) IS NULL
     OR NOT EXISTS (
       SELECT 1
       FROM pg_catalog.pg_class AS relation_row
       JOIN pg_catalog.pg_namespace AS namespace
         ON namespace.oid=relation_row.relnamespace
       JOIN pg_catalog.pg_roles AS owner ON owner.oid=relation_row.relowner
       WHERE relation_row.oid=
         'drizzle.__periapsis_migration_convergence_attestations'::regclass
         AND namespace.nspname='drizzle' AND relation_row.relkind='r'
         AND owner.rolname='periapsis_migrator'
         AND NOT relation_row.relrowsecurity
         AND NOT relation_row.relforcerowsecurity
         AND relation_row.relpersistence='p'
         AND (
           SELECT count(*)=8 AND coalesce(bool_and(
             privilege.grantor=relation_row.relowner
             AND privilege.grantee=relation_row.relowner
             AND privilege.privilege_type=ANY(ARRAY[
               'SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES',
               'TRIGGER','MAINTAIN'
             ]::text[])
             AND NOT privilege.is_grantable
           ),false)
           FROM pg_catalog.aclexplode(coalesce(
             relation_row.relacl,
             pg_catalog.acldefault('r',relation_row.relowner)
           )) AS privilege
         )
     )
     OR (
       SELECT count(*)<>9 OR string_agg(
         attribute.attnum::text || ':' || attribute.attname || ':' ||
         pg_catalog.format_type(attribute.atttypid,attribute.atttypmod) || ':' ||
         attribute.attnotnull::text || ':' || coalesce(
           pg_catalog.pg_get_expr(default_row.adbin,default_row.adrelid),''
         ),',' ORDER BY attribute.attnum
       ) IS DISTINCT FROM
         '1:attestation_id:uuid:true:uuidv7(),2:convergence_version:smallint:true:,3:source_variant:text:true:,4:metadata_original_hash:text:true:,5:compatibility_original_hash:text:true:,6:raw_v45_fingerprint:text:true:,7:normalized_v45_fingerprint:text:true:,8:canonical_catalog_digest:text:true:,9:attested_at:timestamp with time zone:true:'
       FROM pg_catalog.pg_attribute AS attribute
       LEFT JOIN pg_catalog.pg_attrdef AS default_row
         ON default_row.adrelid=attribute.attrelid
        AND default_row.adnum=attribute.attnum
       WHERE attribute.attrelid=
         'drizzle.__periapsis_migration_convergence_attestations'::regclass
         AND attribute.attnum>0 AND NOT attribute.attisdropped
     )
     OR (
       SELECT count(*)<>16
       FROM pg_catalog.pg_constraint AS constraint_row
       WHERE constraint_row.conrelid=
         'drizzle.__periapsis_migration_convergence_attestations'::regclass
     )
     OR EXISTS (
       SELECT 1
       FROM (VALUES
         ('__periapsis_migration_convergence_attestations_pkey','p',
          'PRIMARY KEY (attestation_id)'),
         ('migration_convergence_version_key','u',
          'UNIQUE (convergence_version)'),
         ('migration_convergence_version_check','c',
          'CHECK ((convergence_version = 46))'),
         ('migration_convergence_source_variant_check','c',
          'CHECK ((source_variant = ANY (ARRAY[''legacy-v45''::text, ''canonical-v45''::text])))'),
         ('migration_convergence_uuidv7_check','c',
          'CHECK ((uuid_extract_version(attestation_id) = 7))'),
         ('migration_convergence_hashes_check','c',
          'CHECK (((metadata_original_hash ~ ''^[0-9a-f]{64}$''::text) AND (compatibility_original_hash ~ ''^[0-9a-f]{64}$''::text) AND (canonical_catalog_digest ~ ''^[0-9a-f]{64}$''::text)))'),
         ('migration_convergence_fingerprints_check','c',
          'CHECK (((raw_v45_fingerprint ~ ''^[0-9]+@[0-9a-f]{64}(:[0-9]+@[0-9a-f]{64}){198}$''::text) AND (normalized_v45_fingerprint ~ ''^[0-9]+@[0-9a-f]{64}(:[0-9]+@[0-9a-f]{64}){198}$''::text)))')
       ) AS expected(name,type,definition)
       LEFT JOIN pg_catalog.pg_constraint AS constraint_row
         ON constraint_row.conrelid=
           'drizzle.__periapsis_migration_convergence_attestations'::regclass
        AND constraint_row.conname=expected.name
       WHERE constraint_row.oid IS NULL
          OR constraint_row.contype::text<>expected.type
          OR pg_catalog.pg_get_constraintdef(constraint_row.oid,false)<>
             expected.definition
     )
     OR (
       SELECT count(*)<>2 OR NOT coalesce(bool_and(
         index_row.indisunique AND index_row.indisvalid
         AND index_row.indisready AND index_row.indpred IS NULL
         AND index_row.indexprs IS NULL
       ),false)
       FROM pg_catalog.pg_index AS index_row
       WHERE index_row.indrelid=
         'drizzle.__periapsis_migration_convergence_attestations'::regclass
     )
     OR EXISTS (
       SELECT 1
       FROM (VALUES
         ('periapsis_api'),('periapsis_worker'),('periapsis_notifier'),
         ('periapsis_auditor')
       ) AS role_name(value)
       CROSS JOIN (VALUES
         ('SELECT'),('INSERT'),('UPDATE'),('DELETE'),('TRUNCATE'),
         ('REFERENCES'),('TRIGGER'),('MAINTAIN')
       ) AS privilege_name(value)
       WHERE pg_catalog.has_table_privilege(
         role_name.value,
         'drizzle.__periapsis_migration_convergence_attestations',
         privilege_name.value
       )
     )
     OR NOT EXISTS (
       SELECT 1
       FROM pg_catalog.pg_proc AS function_row
       JOIN pg_catalog.pg_roles AS owner ON owner.oid=function_row.proowner
       WHERE function_row.oid=
         'app.guard_migration_convergence_attestation_v1()'::regprocedure
         AND owner.rolname='periapsis_migrator'
         AND function_row.provolatile='v' AND function_row.prosecdef
         AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8'
         )),'hex')=
           'caa2b5ae2481eb1870cdef57b4c71ec72079873fbe1f320e61d412d20b16aa03'
         AND (
           SELECT count(*)=1 AND coalesce(bool_and(
             privilege.grantor=function_row.proowner
             AND privilege.grantee=function_row.proowner
             AND privilege.privilege_type='EXECUTE'
             AND NOT privilege.is_grantable
           ),false)
           FROM pg_catalog.aclexplode(coalesce(
             function_row.proacl,
             pg_catalog.acldefault('f',function_row.proowner)
           )) AS privilege
         )
     )
     OR (
       SELECT count(*)<>2 OR NOT coalesce(bool_and(
         trigger_row.oid IS NOT NULL
         AND trigger_row.tgfoid=
           'app.guard_migration_convergence_attestation_v1()'::regprocedure
         AND trigger_row.tgtype=expected.trigger_type
         AND trigger_row.tgenabled='O' AND NOT trigger_row.tgisinternal
       ),false)
       FROM (VALUES
         ('migration_convergence_immutable'::name,27::smallint),
         ('migration_convergence_truncate_immutable'::name,34::smallint)
       ) AS expected(trigger_name,trigger_type)
       LEFT JOIN pg_catalog.pg_trigger AS trigger_row
         ON trigger_row.tgrelid=
           'drizzle.__periapsis_migration_convergence_attestations'::regclass
        AND trigger_row.tgname=expected.trigger_name
     )
     OR (
       SELECT count(*)<>2
       FROM pg_catalog.pg_trigger AS trigger_row
       WHERE trigger_row.tgrelid=
         'drizzle.__periapsis_migration_convergence_attestations'::regclass
         AND NOT trigger_row.tgisinternal
     ) THEN
    RETURN false;
  END IF;

  WITH ordered_migration AS (
    SELECT migration.id,migration.created_at,lower(migration.hash::text) AS hash,
      pg_catalog.row_number() OVER (
        ORDER BY migration.created_at,migration.id
      ) AS ordinal
    FROM drizzle.__drizzle_migrations AS migration
  ), v45_prefix AS (
    SELECT * FROM ordered_migration WHERE ordinal<=199
  )
  SELECT count(*)::bigint,max(migration.created_at)::bigint,
    string_agg(
      migration.created_at::text || '@' || migration.hash,
      ':' ORDER BY migration.created_at,migration.id
    ),
    string_agg(
      migration.created_at::text || '@' || CASE
        WHEN migration.created_at=1788128074116
         AND migration.hash=
           '0edecb4d9945aeccc4d5b7c9db7dbb25c5f07c7df933ee4e208d3e4e34397d9e'
          THEN '6112ec54973db26390fa6020a050db71a6c5d28b1c45132bca10b32372109fa4'
        WHEN migration.created_at=1788128702258
         AND migration.hash=
           '0d47a74b3ecb3064766ae3a920e420f56e3cfc7e0bf95578df7fe353c2b3d72c'
          THEN 'fffd40eb9eb5800fbe63f9e62fa85f960190e2a149e2313ccb66a1d6c78293ea'
        ELSE migration.hash
      END,
      ':' ORDER BY migration.created_at,migration.id
    )
    INTO v45_count,v45_latest,v_raw_fingerprint,v_normalized_fingerprint
  FROM v45_prefix AS migration;
  SELECT lower(migration.hash::text) INTO STRICT v_metadata_hash
  FROM drizzle.__drizzle_migrations AS migration
  WHERE migration.created_at=1788128074116;
  SELECT lower(migration.hash::text) INTO STRICT v_compatibility_hash
  FROM drizzle.__drizzle_migrations AS migration
  WHERE migration.created_at=1788128702258;

  RETURN v45_count=199 AND v45_latest=1788128702258
    AND (SELECT count(*)=1
         FROM drizzle.__periapsis_migration_convergence_attestations)
    AND (
      SELECT count(*)=1
      FROM drizzle.__periapsis_migration_convergence_attestations AS attestation
      WHERE attestation.convergence_version=46
        AND attestation.source_variant=CASE
          WHEN ROW(v_metadata_hash,v_compatibility_hash) IS NOT DISTINCT FROM
            ROW(
              '0edecb4d9945aeccc4d5b7c9db7dbb25c5f07c7df933ee4e208d3e4e34397d9e',
              '0d47a74b3ecb3064766ae3a920e420f56e3cfc7e0bf95578df7fe353c2b3d72c'
            ) THEN 'legacy-v45'
          WHEN ROW(v_metadata_hash,v_compatibility_hash) IS NOT DISTINCT FROM
            ROW(
              '6112ec54973db26390fa6020a050db71a6c5d28b1c45132bca10b32372109fa4',
              'fffd40eb9eb5800fbe63f9e62fa85f960190e2a149e2313ccb66a1d6c78293ea'
            ) THEN 'canonical-v45'
          ELSE '<unsupported>' END
        AND attestation.metadata_original_hash=v_metadata_hash
        AND attestation.compatibility_original_hash=v_compatibility_hash
        AND attestation.raw_v45_fingerprint=v_raw_fingerprint
        AND attestation.normalized_v45_fingerprint=v_normalized_fingerprint
        AND attestation.canonical_catalog_digest=
          '1b1310c2a1350590629ebfb71eb58d837900d376a3bdf8c7ccbff3e9aad3d2a3'
        AND pg_catalog.uuid_extract_version(attestation.attestation_id)=7
        AND attestation.attested_at IS NOT NULL
    );
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;
ALTER FUNCTION app.private_v47_migration_convergence_schema_readiness_v1()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_v47_migration_convergence_schema_readiness_v1()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
       periapsis_auditor;
--> statement-breakpoint

CREATE FUNCTION app.private_schema_compatibility_journal_v47()
RETURNS TABLE(
  applied_count bigint,latest_created_at bigint,latest_rows bigint,
  latest_hash text,migration_fingerprint text
)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
BEGIN
  IF NOT app.private_v47_migration_convergence_schema_readiness_v1() THEN
    RETURN QUERY SELECT 0::bigint,0::bigint,0::bigint,
      'UNSUPPORTED'::text,'UNSUPPORTED'::text;
    RETURN;
  END IF;
  RETURN QUERY
  SELECT count(*)::bigint,max(migration.created_at)::bigint,
    count(*) FILTER (
      WHERE migration.created_at=max_created_at.value
    )::bigint,
    (SELECT lower(latest.hash::text)
     FROM drizzle.__drizzle_migrations AS latest
     ORDER BY latest.created_at DESC,latest.id DESC LIMIT 1),
    string_agg(
      migration.created_at::text || '@' || CASE
        WHEN migration.created_at=1788128074116
         AND lower(migration.hash::text)=
           '0edecb4d9945aeccc4d5b7c9db7dbb25c5f07c7df933ee4e208d3e4e34397d9e'
          THEN '6112ec54973db26390fa6020a050db71a6c5d28b1c45132bca10b32372109fa4'
        WHEN migration.created_at=1788128702258
         AND lower(migration.hash::text)=
           '0d47a74b3ecb3064766ae3a920e420f56e3cfc7e0bf95578df7fe353c2b3d72c'
          THEN 'fffd40eb9eb5800fbe63f9e62fa85f960190e2a149e2313ccb66a1d6c78293ea'
        ELSE lower(migration.hash::text)
      END,
      ':' ORDER BY migration.created_at,migration.id
    )
  FROM drizzle.__drizzle_migrations AS migration
  CROSS JOIN LATERAL (
    SELECT max(candidate.created_at)::bigint AS value
    FROM drizzle.__drizzle_migrations AS candidate
  ) AS max_created_at;
END;
$function$;
ALTER FUNCTION app.private_schema_compatibility_journal_v47()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_schema_compatibility_journal_v47()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
       periapsis_auditor;
--> statement-breakpoint

-- V47 ticket comments revoke one escalation entry point and broaden one
-- private notification helper only to the migrator. Rotate the two exact
-- catalog roots instead of weakening their predecessor assertions.
DO $derive_ticket_mutation_runtime_readiness_v2$
DECLARE
  definition text;
  predecessor_source_hash text;
  predecessor_entry constant text :=
    '(''app.commit_tenant_ticket_escalation_v3(uuid,uuid,boolean,jsonb,jsonb,text,text,bytea,bytea,text[],uuid,uuid,inet,text,text)'',' ||
    chr(10) || '      ''v''::"char",true,false),';
  successor_entry constant text :=
    '(''app.commit_tenant_ticket_escalation_v3(uuid,uuid,boolean,jsonb,jsonb,text,text,bytea,bytea,text[],uuid,uuid,inet,text,text)'',' ||
    chr(10) || '      ''v''::"char",false,false),';
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex')
    INTO STRICT definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.ticket_mutation_runtime_schema_readiness_v1()'::regprocedure;
  IF predecessor_source_hash<>
       '410f89f59c493c2cfe1ca17d0b43f38d74fa48235122d311922cf7da5bdd2ae3'
     OR pg_catalog.strpos(definition,predecessor_entry)=0 THEN
    RAISE EXCEPTION 'ticket mutation readiness v1 drifted'
      USING ERRCODE='55000';
  END IF;
  definition:=pg_catalog.replace(
    definition,'ticket_mutation_runtime_schema_readiness_v1',
    'ticket_mutation_runtime_schema_readiness_v2'
  );
  definition:=pg_catalog.replace(
    definition,predecessor_entry,successor_entry
  );
  IF pg_catalog.strpos(definition,predecessor_entry)<>0
     OR pg_catalog.strpos(definition,successor_entry)=0 THEN
    RAISE EXCEPTION 'ticket mutation readiness v2 derivation failed'
      USING ERRCODE='55000';
  END IF;
  EXECUTE definition;
END;
$derive_ticket_mutation_runtime_readiness_v2$;
ALTER FUNCTION app.ticket_mutation_runtime_schema_readiness_v2()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.ticket_mutation_runtime_schema_readiness_v2()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
       periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.ticket_mutation_runtime_schema_readiness_v2()
  TO periapsis_api,periapsis_worker;
REVOKE EXECUTE ON FUNCTION app.ticket_mutation_runtime_schema_readiness_v1()
  FROM periapsis_api,periapsis_worker;
--> statement-breakpoint

DO $derive_ticket_watcher_runtime_readiness_v2$
DECLARE
  definition text;
  predecessor_source_hash text;
  predecessor_entry constant text :=
    '(''app.private_notification_operator_candidates_v1(uuid,uuid)'',' ||
    chr(10) ||
    '       ''7578ee7692d7d08ab7b4dac54857737ee4da052bef7ee1d346892f06e8d08c8b'',' ||
    chr(10) || '       ''periapsis_notification_dispatch_owner'',''s'',' ||
    chr(10) ||
    '       ARRAY[''search_path=pg_catalog, public, app'']::text[],' ||
    chr(10) ||
    '       ARRAY[''periapsis_notification_dispatch_owner'']::text[]),';
  successor_entry constant text :=
    '(''app.private_notification_operator_candidates_v1(uuid,uuid)'',' ||
    chr(10) ||
    '       ''7578ee7692d7d08ab7b4dac54857737ee4da052bef7ee1d346892f06e8d08c8b'',' ||
    chr(10) || '       ''periapsis_notification_dispatch_owner'',''s'',' ||
    chr(10) ||
    '       ARRAY[''search_path=pg_catalog, public, app'']::text[],' ||
    chr(10) ||
    '       ARRAY[''periapsis_migrator'',''periapsis_notification_dispatch_owner'']::text[]),';
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex')
    INTO STRICT definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.ticket_watcher_runtime_schema_readiness_v1()'::regprocedure;
  IF predecessor_source_hash<>
       '8a870b2760c196f807a2366bfbde415e3627960f5b0191eb7e1f1b529ae4efe3'
     OR pg_catalog.strpos(definition,predecessor_entry)=0 THEN
    RAISE EXCEPTION 'ticket watcher readiness v1 drifted'
      USING ERRCODE='55000';
  END IF;
  definition:=pg_catalog.replace(
    definition,'ticket_watcher_runtime_schema_readiness_v1',
    'ticket_watcher_runtime_schema_readiness_v2'
  );
  definition:=pg_catalog.replace(
    definition,predecessor_entry,successor_entry
  );
  IF pg_catalog.strpos(definition,predecessor_entry)<>0
     OR pg_catalog.strpos(definition,successor_entry)=0 THEN
    RAISE EXCEPTION 'ticket watcher readiness v2 derivation failed'
      USING ERRCODE='55000';
  END IF;
  EXECUTE definition;
END;
$derive_ticket_watcher_runtime_readiness_v2$;
ALTER FUNCTION app.ticket_watcher_runtime_schema_readiness_v2()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.ticket_watcher_runtime_schema_readiness_v2()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
       periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.ticket_watcher_runtime_schema_readiness_v2()
  TO periapsis_api,periapsis_worker;
REVOKE EXECUTE ON FUNCTION app.ticket_watcher_runtime_schema_readiness_v1()
  FROM periapsis_api,periapsis_worker;
--> statement-breakpoint

-- V47 compatibility root and sealed dependency attestation for the complete
-- ticket-comment, SLA ingress, SMTP and interactive LDAP cutover.
CREATE FUNCTION app.schema_compatibility_v47()
RETURNS TABLE(
  applied_count bigint,latest_created_at bigint,latest_hash text,
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
  journal_latest_hash text;
  latest_rows bigint;
  journal_fingerprint text;
  self_catalog_ready boolean;
BEGIN
  SELECT journal.applied_count,journal.latest_created_at,
         journal.latest_rows,journal.latest_hash,journal.migration_fingerprint
    INTO journal_count,journal_latest_created_at,latest_rows,
         journal_latest_hash,journal_fingerprint
  FROM app.private_schema_compatibility_journal_v47() AS journal;
  SELECT count(*)=1 INTO self_catalog_ready
  FROM pg_catalog.pg_proc AS function_row
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid=function_row.pronamespace
  JOIN pg_catalog.pg_roles AS owner ON owner.oid=function_row.proowner
  JOIN pg_catalog.pg_language AS language ON language.oid=function_row.prolang
  WHERE function_row.oid='app.schema_compatibility_v47()'::regprocedure
    AND namespace.nspname='app' AND owner.rolname='periapsis_migrator'
    AND language.lanname='plpgsql' AND function_row.prokind='f'
    AND function_row.provolatile='s' AND function_row.prosecdef
    AND NOT function_row.proisstrict AND NOT function_row.proleakproof
    AND function_row.proparallel='u' AND function_row.pronargs=0
    AND function_row.proconfig IS NOT DISTINCT FROM ARRAY[
      'search_path=pg_catalog',
      'app.schema_compatibility_fingerprint=' || journal_fingerprint
    ]::text[]
    AND pg_catalog.pg_get_function_result(function_row.oid)=
      'TABLE(applied_count bigint, latest_created_at bigint, latest_hash text, migration_fingerprint text)'
    AND (
      SELECT count(*)=3 AND coalesce(bool_and(
        function_acl.grantor=function_row.proowner
        AND function_acl.grantee IN (
          function_row.proowner,
          (SELECT role.oid FROM pg_catalog.pg_roles AS role
           WHERE role.rolname='periapsis_api'),
          (SELECT role.oid FROM pg_catalog.pg_roles AS role
           WHERE role.rolname='periapsis_worker')
        ) AND function_acl.privilege_type='EXECUTE'
        AND NOT function_acl.is_grantable
      ),false)
      FROM pg_catalog.aclexplode(CASE WHEN pg_catalog.cardinality(coalesce(
        function_row.proacl,pg_catalog.acldefault('f',function_row.proowner)
      ))>0 THEN coalesce(
        function_row.proacl,pg_catalog.acldefault('f',function_row.proowner)
      ) ELSE NULL::pg_catalog.aclitem[] END) AS function_acl
    );
  IF journal_count=209 AND journal_latest_created_at=1788275200000
     AND latest_rows=1 AND self_catalog_ready
     AND journal_fingerprint=current_setting(
       'app.schema_compatibility_fingerprint',true
     ) THEN
    RETURN QUERY SELECT journal_count,journal_latest_created_at,
      journal_latest_hash,journal_fingerprint;
    RETURN;
  END IF;
  RETURN QUERY SELECT 0::bigint,0::bigint,
    'UNSUPPORTED'::text,'UNSUPPORTED'::text;
END;
$function$;
ALTER FUNCTION app.schema_compatibility_v47() OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.schema_compatibility_v47()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v47()
  TO periapsis_api,periapsis_worker;
--> statement-breakpoint

-- The SLA readiness root is deliberately owned by the isolated readiness
-- role and callable at runtime only by the worker. The NOLOGIN migration role
-- receives the narrow execute edge needed by the compatibility sealer; no
-- application login or role membership is broadened.
GRANT EXECUTE ON FUNCTION app.sla_trigger_action_runtime_schema_readiness_v1()
  TO periapsis_migrator;
--> statement-breakpoint

GRANT EXECUTE ON FUNCTION app.sla_object_event_ingress_schema_readiness_v1()
  TO periapsis_migrator;
--> statement-breakpoint

-- Install the final sealer source before deriving the v47 dependency surface,
-- so every private readiness root binds the post-seal catalog in one pass.
CREATE OR REPLACE FUNCTION app.seal_schema_compatibility_manifest(
  p_expected_count bigint,p_expected_latest_created_at bigint,
  p_expected_latest_hash text,p_expected_migration_fingerprint text
)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
DECLARE
  journal_count bigint;
  journal_latest_created_at bigint;
  journal_latest_hash text;
  journal_latest_rows bigint;
  journal_fingerprint text;
  sealed_count bigint;
BEGIN
  IF p_expected_count IS DISTINCT FROM 209
     OR p_expected_latest_created_at IS DISTINCT FROM 1788275200000
     OR p_expected_latest_hash !~ '^[0-9a-f]{64}$'
     OR p_expected_migration_fingerprint !~
       '^[0-9]+@[0-9a-f]{64}(:[0-9]+@[0-9a-f]{64}){208}$' THEN
    RAISE EXCEPTION 'schema compatibility v47 seal input is invalid'
      USING ERRCODE='55000';
  END IF;
  SELECT journal.applied_count,journal.latest_created_at,journal.latest_rows,
         journal.latest_hash,journal.migration_fingerprint
    INTO journal_count,journal_latest_created_at,journal_latest_rows,
         journal_latest_hash,journal_fingerprint
  FROM app.private_schema_compatibility_journal_v47() AS journal;
  IF ROW(journal_count,journal_latest_created_at,journal_latest_hash,
         journal_fingerprint) IS DISTINCT FROM
     ROW(p_expected_count,p_expected_latest_created_at,p_expected_latest_hash,
          p_expected_migration_fingerprint)
     OR journal_latest_rows<>1
     OR NOT app.private_v47_migration_convergence_schema_readiness_v1()
     OR NOT app.private_mfa_policy_administration_schema_readiness_v7()
     OR NOT app.private_platform_identity_runtime_schema_readiness_v13()
     OR NOT app.private_platform_oidc_direct_runtime_schema_readiness_v9()
     OR NOT app.private_platform_saml_direct_runtime_schema_readiness_v6()
     OR NOT app.ticket_mutation_runtime_schema_readiness_v2()
     OR NOT app.sla_trigger_action_runtime_schema_readiness_v1()
     OR NOT app.sla_object_event_ingress_schema_readiness_v1()
     OR NOT app.platform_local_account_runtime_schema_readiness_v1()
     OR NOT app.ticket_bulk_runtime_schema_readiness_v2()
     OR NOT app.ticket_export_runtime_schema_readiness_v2()
     OR NOT app.alert_dfir_runtime_schema_readiness_v1()
     OR NOT app.ticket_metadata_runtime_schema_readiness_v1()
     OR NOT app.ticket_watcher_runtime_schema_readiness_v2()
     OR NOT app.contacts_portal_schema_readiness_v2()
     OR NOT app.notification_schema_readiness_v4()
     OR NOT app.tenant_ldap_interactive_auth_schema_readiness_v1()
     OR pg_catalog.has_function_privilege(
       'periapsis_api','app.ticket_mutation_runtime_schema_readiness_v1()'::regprocedure,'EXECUTE')
     OR pg_catalog.has_function_privilege(
       'periapsis_worker','app.ticket_mutation_runtime_schema_readiness_v1()'::regprocedure,'EXECUTE')
     OR pg_catalog.has_function_privilege(
       'periapsis_api','app.ticket_watcher_runtime_schema_readiness_v1()'::regprocedure,'EXECUTE')
     OR pg_catalog.has_function_privilege(
       'periapsis_worker','app.ticket_watcher_runtime_schema_readiness_v1()'::regprocedure,'EXECUTE') THEN
    RAISE EXCEPTION 'schema compatibility v47 pre-seal verification failed'
      USING ERRCODE='55000';
  END IF;
  EXECUTE pg_catalog.format(
    'ALTER FUNCTION app.schema_compatibility_v47() SET app.schema_compatibility_fingerprint = %L',
    p_expected_migration_fingerprint
  );
  ALTER FUNCTION app.schema_compatibility_v46()
    SET app.schema_compatibility_fingerprint='RETIRED';
  REVOKE ALL ON FUNCTION app.schema_compatibility_v46()
    FROM periapsis_api,periapsis_worker;
  REVOKE ALL ON FUNCTION app.platform_identity_runtime_schema_readiness_v12()
    FROM periapsis_api,periapsis_worker;
  REVOKE ALL ON FUNCTION app.platform_oidc_direct_runtime_schema_readiness_v8()
    FROM periapsis_api,periapsis_worker;
  REVOKE ALL ON FUNCTION app.platform_saml_direct_runtime_schema_readiness_v5()
    FROM periapsis_api,periapsis_worker;
  REVOKE ALL ON FUNCTION app.mfa_policy_administration_schema_readiness_v6()
    FROM periapsis_api,periapsis_worker;
  SELECT compatibility.applied_count INTO sealed_count
  FROM app.schema_compatibility_v47() AS compatibility;
  IF sealed_count<>209
     OR NOT app.private_v47_migration_convergence_schema_readiness_v1()
     OR NOT app.mfa_policy_administration_schema_readiness_v7()
     OR NOT app.platform_identity_runtime_schema_readiness_v13()
     OR NOT app.platform_oidc_direct_runtime_schema_readiness_v9()
     OR NOT app.platform_saml_direct_runtime_schema_readiness_v6()
     OR NOT app.ticket_mutation_runtime_schema_readiness_v2()
     OR NOT app.sla_trigger_action_runtime_schema_readiness_v1()
     OR NOT app.sla_object_event_ingress_schema_readiness_v1()
     OR NOT app.platform_local_account_runtime_schema_readiness_v1()
     OR NOT app.ticket_bulk_runtime_schema_readiness_v2()
     OR NOT app.ticket_export_runtime_schema_readiness_v2()
     OR NOT app.alert_dfir_runtime_schema_readiness_v1()
     OR NOT app.ticket_metadata_runtime_schema_readiness_v1()
     OR NOT app.ticket_watcher_runtime_schema_readiness_v2()
     OR NOT app.contacts_portal_schema_readiness_v2()
     OR NOT app.notification_schema_readiness_v4()
     OR NOT app.tenant_ldap_interactive_auth_schema_readiness_v1()
     OR pg_catalog.has_function_privilege(
       'periapsis_api','app.ticket_mutation_runtime_schema_readiness_v1()'::regprocedure,'EXECUTE')
     OR pg_catalog.has_function_privilege(
       'periapsis_worker','app.ticket_mutation_runtime_schema_readiness_v1()'::regprocedure,'EXECUTE')
     OR pg_catalog.has_function_privilege(
       'periapsis_api','app.ticket_watcher_runtime_schema_readiness_v1()'::regprocedure,'EXECUTE')
     OR pg_catalog.has_function_privilege(
       'periapsis_worker','app.ticket_watcher_runtime_schema_readiness_v1()'::regprocedure,'EXECUTE')
     OR pg_catalog.has_function_privilege(
       'periapsis_api','app.schema_compatibility_v46()'::regprocedure,'EXECUTE')
     OR pg_catalog.has_function_privilege(
       'periapsis_worker','app.schema_compatibility_v46()'::regprocedure,'EXECUTE')
     OR pg_catalog.has_function_privilege(
       'periapsis_api','app.platform_identity_runtime_schema_readiness_v12()'::regprocedure,'EXECUTE')
     OR pg_catalog.has_function_privilege(
       'periapsis_worker','app.platform_identity_runtime_schema_readiness_v12()'::regprocedure,'EXECUTE')
     OR pg_catalog.has_function_privilege(
       'periapsis_api','app.platform_oidc_direct_runtime_schema_readiness_v8()'::regprocedure,'EXECUTE')
     OR pg_catalog.has_function_privilege(
       'periapsis_worker','app.platform_oidc_direct_runtime_schema_readiness_v8()'::regprocedure,'EXECUTE')
     OR pg_catalog.has_function_privilege(
       'periapsis_api','app.platform_saml_direct_runtime_schema_readiness_v5()'::regprocedure,'EXECUTE')
     OR pg_catalog.has_function_privilege(
       'periapsis_worker','app.platform_saml_direct_runtime_schema_readiness_v5()'::regprocedure,'EXECUTE')
     OR pg_catalog.has_function_privilege(
       'periapsis_api','app.mfa_policy_administration_schema_readiness_v6()'::regprocedure,'EXECUTE')
     OR pg_catalog.has_function_privilege(
       'periapsis_worker','app.mfa_policy_administration_schema_readiness_v6()'::regprocedure,'EXECUTE') THEN
    RAISE EXCEPTION 'schema compatibility v47 seal verification failed'
      USING ERRCODE='55000';
  END IF;
END;
$function$;
ALTER FUNCTION app.seal_schema_compatibility_manifest(bigint,bigint,text,text)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.seal_schema_compatibility_manifest(bigint,bigint,text,text)
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
GRANT EXECUTE ON FUNCTION app.seal_schema_compatibility_manifest(bigint,bigint,text,text)
  TO periapsis_migrator;
--> statement-breakpoint

DO $derive_platform_identity_dependency_surface_v13$
DECLARE
  predecessor_definition text;
  predecessor_source_hash text;
  derived_definition text;
  marker constant text := '        ''schema_compatibility_v47'',';
  exclusions constant text :=
    '        ''private_platform_identity_dependency_surface_hash_v12'',' || chr(10) ||
    '        ''private_platform_identity_runtime_schema_readiness_v12'',' || chr(10) ||
    '        ''platform_identity_runtime_schema_readiness_v12'',' || chr(10) ||
    '        ''schema_compatibility_v46'',' || chr(10) ||
    '        ''private_platform_oidc_direct_dependency_surface_hash_v9'',' || chr(10) ||
    '        ''private_platform_oidc_direct_runtime_schema_readiness_v9'',' || chr(10) ||
    '        ''platform_oidc_direct_runtime_schema_readiness_v9'',' || chr(10) ||
    '        ''private_platform_saml_direct_dependency_surface_hash_v6'',' || chr(10) ||
    '        ''private_platform_saml_direct_runtime_schema_readiness_v6'',' || chr(10) ||
    '        ''platform_saml_direct_runtime_schema_readiness_v6'',' || chr(10) ||
    '        ''private_mfa_policy_administration_dependency_surface_hash_v7'',' || chr(10) ||
    '        ''private_mfa_policy_administration_schema_readiness_v7'',' || chr(10) ||
    '        ''mfa_policy_administration_schema_readiness_v7'',';
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex')
    INTO STRICT predecessor_definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_platform_identity_dependency_surface_hash_v12()'::regprocedure;
  IF predecessor_source_hash<>
    '2d33728110b9e5828cb86ad15dbc066a69242ff3611f2793e9408b0838da35e7' THEN
    RAISE EXCEPTION 'platform identity dependency v12 drifted'
      USING ERRCODE='55000';
  END IF;
  derived_definition:=pg_catalog.replace(
    predecessor_definition,
    'private_platform_identity_dependency_surface_hash_v12',
    'private_platform_identity_dependency_surface_hash_v13'
  );
  derived_definition:=pg_catalog.replace(
    derived_definition,'private_platform_identity_runtime_schema_readiness_v12',
    'private_platform_identity_runtime_schema_readiness_v13'
  );
  derived_definition:=pg_catalog.replace(
    derived_definition,'platform_identity_runtime_schema_readiness_v12',
    'platform_identity_runtime_schema_readiness_v13'
  );
  derived_definition:=pg_catalog.replace(
    derived_definition,'schema_compatibility_v46','schema_compatibility_v47'
  );
  IF pg_catalog.strpos(derived_definition,marker)=0 THEN
    RAISE EXCEPTION 'platform identity dependency v12 marker drifted'
      USING ERRCODE='55000';
  END IF;
  derived_definition:=pg_catalog.replace(
    derived_definition,marker,marker || chr(10) || exclusions
  );
  EXECUTE derived_definition;
END;
$derive_platform_identity_dependency_surface_v13$;
ALTER FUNCTION app.private_platform_identity_dependency_surface_hash_v13()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_platform_identity_dependency_surface_hash_v13()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
--> statement-breakpoint

CREATE FUNCTION app.private_platform_oidc_direct_dependency_surface_hash_v9()
RETURNS text LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app
SET quote_all_identifiers=off SET TimeZone='UTC' SET DateStyle='ISO, YMD'
SET IntervalStyle='postgres' SET extra_float_digits=3 SET bytea_output='hex'
SET standard_conforming_strings=on SET lc_numeric='C'
AS $function$
  SELECT app.private_platform_identity_dependency_surface_hash_v13();
$function$;
CREATE FUNCTION app.private_platform_saml_direct_dependency_surface_hash_v6()
RETURNS text LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app
SET quote_all_identifiers=off SET TimeZone='UTC' SET DateStyle='ISO, YMD'
SET IntervalStyle='postgres' SET extra_float_digits=3 SET bytea_output='hex'
SET standard_conforming_strings=on SET lc_numeric='C'
AS $function$
  SELECT app.private_platform_identity_dependency_surface_hash_v13();
$function$;
CREATE FUNCTION app.private_mfa_policy_administration_dependency_surface_hash_v7()
RETURNS text LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app
SET quote_all_identifiers=off SET TimeZone='UTC' SET DateStyle='ISO, YMD'
SET IntervalStyle='postgres' SET extra_float_digits=3 SET bytea_output='hex'
SET standard_conforming_strings=on SET lc_numeric='C'
AS $function$
  SELECT app.private_platform_identity_dependency_surface_hash_v13();
$function$;
ALTER FUNCTION app.private_platform_oidc_direct_dependency_surface_hash_v9()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_platform_saml_direct_dependency_surface_hash_v6()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_mfa_policy_administration_dependency_surface_hash_v7()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_platform_oidc_direct_dependency_surface_hash_v9()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
REVOKE ALL ON FUNCTION app.private_platform_saml_direct_dependency_surface_hash_v6()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
REVOKE ALL ON FUNCTION app.private_mfa_policy_administration_dependency_surface_hash_v7()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
--> statement-breakpoint

DO $derive_mfa_policy_private_readiness_v7$
DECLARE
  definition text;
  predecessor_hash text;
  dependency_source_hash text;
  dependency_result_hash text;
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex')
    INTO STRICT definition,predecessor_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_mfa_policy_administration_schema_readiness_v6()'::regprocedure;
  IF predecessor_hash<>
    'e2e054209aed0eeb65634f78465955efef0631e34615212738b3d7b9d121b8c9' THEN
    RAISE EXCEPTION 'MFA policy private readiness v6 drifted'
      USING ERRCODE='55000';
  END IF;
  SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex'),
         app.private_mfa_policy_administration_dependency_surface_hash_v7()
    INTO STRICT dependency_source_hash,dependency_result_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_mfa_policy_administration_dependency_surface_hash_v7()'::regprocedure;
  definition:=pg_catalog.replace(definition,
    'private_mfa_policy_administration_dependency_surface_hash_v6',
    'private_mfa_policy_administration_dependency_surface_hash_v7');
  definition:=pg_catalog.replace(definition,
    'private_mfa_policy_administration_schema_readiness_v6',
    'private_mfa_policy_administration_schema_readiness_v7');
  definition:=pg_catalog.replace(definition,
    '''app.mfa_policy_administration_schema_readiness_v6()''::regprocedure',
    '''app.mfa_policy_administration_schema_readiness_v6()''::regprocedure,' ||
    chr(10) ||
    '        ''app.mfa_policy_administration_schema_readiness_v7()''::regprocedure'
  );
  definition:=pg_catalog.replace(definition,
    'fcb03a39cf3d71343c4d5b475aa78a9f2528d63ccc4540132cfff5b1e776a1a7',
    dependency_source_hash);
  definition:=pg_catalog.replace(definition,
    'b99402c521e1a59047f2bb6fe3b912e8189b587b43a61140874516493ac40e36',
    dependency_result_hash);
  EXECUTE definition;
END;
$derive_mfa_policy_private_readiness_v7$;
ALTER FUNCTION app.private_mfa_policy_administration_schema_readiness_v7()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_mfa_policy_administration_schema_readiness_v7()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
--> statement-breakpoint

DO $derive_platform_identity_private_readiness_v13$
DECLARE
  definition text;
  predecessor_hash text;
  dependency_source_hash text;
  dependency_result_hash text;
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex')
    INTO STRICT definition,predecessor_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_platform_identity_runtime_schema_readiness_v12()'::regprocedure;
  IF predecessor_hash<>
    'f144de3c10a170e3bedf6c40a428ede8813322366fc944e32b84a44e0becf9a3' THEN
    RAISE EXCEPTION 'platform identity private readiness v12 drifted'
      USING ERRCODE='55000';
  END IF;
  SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex'),
         app.private_platform_identity_dependency_surface_hash_v13()
    INTO STRICT dependency_source_hash,dependency_result_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_platform_identity_dependency_surface_hash_v13()'::regprocedure;
  definition:=pg_catalog.replace(definition,
    'private_platform_identity_dependency_surface_hash_v12',
    'private_platform_identity_dependency_surface_hash_v13');
  definition:=pg_catalog.replace(definition,
    'private_platform_identity_runtime_schema_readiness_v12',
    'private_platform_identity_runtime_schema_readiness_v13');
  definition:=pg_catalog.replace(definition,
    'platform_identity_runtime_schema_readiness_v12',
    'platform_identity_runtime_schema_readiness_v13');
  definition:=pg_catalog.replace(definition,
    'schema_compatibility_v46','schema_compatibility_v47');
  definition:=pg_catalog.replace(definition,
    'private_platform_oidc_direct_dependency_surface_hash_v8',
    'private_platform_oidc_direct_dependency_surface_hash_v9');
  definition:=pg_catalog.replace(definition,
    'private_platform_oidc_direct_runtime_schema_readiness_v8',
    'private_platform_oidc_direct_runtime_schema_readiness_v9');
  definition:=pg_catalog.replace(definition,
    'platform_oidc_direct_runtime_schema_readiness_v8',
    'platform_oidc_direct_runtime_schema_readiness_v9');
  definition:=pg_catalog.replace(definition,
    'private_platform_saml_direct_dependency_surface_hash_v5',
    'private_platform_saml_direct_dependency_surface_hash_v6');
  definition:=pg_catalog.replace(definition,
    'private_platform_saml_direct_runtime_schema_readiness_v5',
    'private_platform_saml_direct_runtime_schema_readiness_v6');
  definition:=pg_catalog.replace(definition,
    'platform_saml_direct_runtime_schema_readiness_v5',
    'platform_saml_direct_runtime_schema_readiness_v6');
  definition:=pg_catalog.replace(definition,
    'private_mfa_policy_administration_dependency_surface_hash_v6',
    'private_mfa_policy_administration_dependency_surface_hash_v7');
  definition:=pg_catalog.replace(definition,
    'private_mfa_policy_administration_schema_readiness_v6',
    'private_mfa_policy_administration_schema_readiness_v7');
  definition:=pg_catalog.replace(definition,
    'mfa_policy_administration_schema_readiness_v6',
    'mfa_policy_administration_schema_readiness_v7');
  definition:=pg_catalog.replace(definition,
    '2d33728110b9e5828cb86ad15dbc066a69242ff3611f2793e9408b0838da35e7',
    dependency_source_hash);
  definition:=pg_catalog.replace(definition,
    'b99402c521e1a59047f2bb6fe3b912e8189b587b43a61140874516493ac40e36',
    dependency_result_hash);
  EXECUTE definition;
END;
$derive_platform_identity_private_readiness_v13$;
ALTER FUNCTION app.private_platform_identity_runtime_schema_readiness_v13()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_platform_identity_runtime_schema_readiness_v13()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
--> statement-breakpoint

DO $derive_platform_oidc_private_readiness_v9$
DECLARE
  definition text;
  predecessor_hash text;
  dependency_source_hash text;
  dependency_result_hash text;
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex')
    INTO STRICT definition,predecessor_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_platform_oidc_direct_runtime_schema_readiness_v8()'::regprocedure;
  IF predecessor_hash<>
    '1c8e651bd145350b4788c9f74e12651aa729e112975f1bb1721f7d5fa8763764' THEN
    RAISE EXCEPTION 'direct platform OIDC private readiness v8 drifted'
      USING ERRCODE='55000';
  END IF;
  SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex'),
         app.private_platform_oidc_direct_dependency_surface_hash_v9()
    INTO STRICT dependency_source_hash,dependency_result_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_platform_oidc_direct_dependency_surface_hash_v9()'::regprocedure;
  definition:=pg_catalog.replace(definition,
    'private_platform_oidc_direct_dependency_surface_hash_v8',
    'private_platform_oidc_direct_dependency_surface_hash_v9');
  definition:=pg_catalog.replace(definition,
    'private_platform_oidc_direct_runtime_schema_readiness_v8',
    'private_platform_oidc_direct_runtime_schema_readiness_v9');
  definition:=pg_catalog.replace(definition,
    'platform_oidc_direct_runtime_schema_readiness_v8',
    'platform_oidc_direct_runtime_schema_readiness_v9');
  definition:=pg_catalog.replace(definition,
    'private_platform_identity_dependency_surface_hash_v12',
    'private_platform_identity_dependency_surface_hash_v13');
  definition:=pg_catalog.replace(definition,
    'private_platform_identity_runtime_schema_readiness_v12',
    'private_platform_identity_runtime_schema_readiness_v13');
  definition:=pg_catalog.replace(definition,
    'platform_identity_runtime_schema_readiness_v12',
    'platform_identity_runtime_schema_readiness_v13');
  definition:=pg_catalog.replace(definition,
    'private_mfa_policy_administration_schema_readiness_v6',
    'private_mfa_policy_administration_schema_readiness_v7');
  definition:=pg_catalog.replace(definition,
    'schema_compatibility_v46','schema_compatibility_v47');
  definition:=pg_catalog.replace(definition,
    'fcb03a39cf3d71343c4d5b475aa78a9f2528d63ccc4540132cfff5b1e776a1a7',
    dependency_source_hash);
  definition:=pg_catalog.replace(definition,
    'b99402c521e1a59047f2bb6fe3b912e8189b587b43a61140874516493ac40e36',
    dependency_result_hash);
  EXECUTE definition;
END;
$derive_platform_oidc_private_readiness_v9$;
ALTER FUNCTION app.private_platform_oidc_direct_runtime_schema_readiness_v9()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_platform_oidc_direct_runtime_schema_readiness_v9()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
--> statement-breakpoint

DO $derive_platform_saml_private_readiness_v6$
DECLARE
  definition text;
  predecessor_hash text;
  dependency_source_hash text;
  dependency_result_hash text;
  metadata_source_hash text;
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex')
    INTO STRICT definition,predecessor_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_platform_saml_direct_runtime_schema_readiness_v5()'::regprocedure;
  IF predecessor_hash<>
    '6c48a1da606dcfd1d06fa351ec505ee4de5f71c9e86b06cc7c47e66b184d25f0' THEN
    RAISE EXCEPTION 'direct platform SAML private readiness v5 drifted'
      USING ERRCODE='55000';
  END IF;
  SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex'),
         app.private_platform_saml_direct_dependency_surface_hash_v6()
    INTO STRICT dependency_source_hash,dependency_result_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_platform_saml_direct_dependency_surface_hash_v6()'::regprocedure;
  SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex')
    INTO STRICT metadata_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.load_platform_saml_metadata_projection_v1(text)'::regprocedure;
  IF metadata_source_hash<>
    'f3af6d609094cbd7a563b8465bc2560bc6bec1926e7b43945e122da3152db989' THEN
    RAISE EXCEPTION 'platform SAML metadata projection v1 drifted'
      USING ERRCODE='55000';
  END IF;
  definition:=pg_catalog.replace(definition,
    'private_platform_saml_direct_dependency_surface_hash_v5',
    'private_platform_saml_direct_dependency_surface_hash_v6');
  definition:=pg_catalog.replace(definition,
    'private_platform_saml_direct_runtime_schema_readiness_v5',
    'private_platform_saml_direct_runtime_schema_readiness_v6');
  definition:=pg_catalog.replace(definition,
    'platform_saml_direct_runtime_schema_readiness_v5',
    'platform_saml_direct_runtime_schema_readiness_v6');
  definition:=pg_catalog.replace(definition,
    'fcb03a39cf3d71343c4d5b475aa78a9f2528d63ccc4540132cfff5b1e776a1a7',
    dependency_source_hash);
  definition:=pg_catalog.replace(definition,
    'b99402c521e1a59047f2bb6fe3b912e8189b587b43a61140874516493ac40e36',
    dependency_result_hash);
  definition:=pg_catalog.replace(definition,
    'f3af6d609094cbd7a563b8465bc2560bc6bec1926e7b43945e122da3152db989',
    metadata_source_hash);
  EXECUTE definition;
END;
$derive_platform_saml_private_readiness_v6$;
ALTER FUNCTION app.private_platform_saml_direct_runtime_schema_readiness_v6()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_platform_saml_direct_runtime_schema_readiness_v6()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
--> statement-breakpoint

CREATE FUNCTION app.mfa_policy_administration_schema_readiness_v7()
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
DECLARE current_count bigint;
BEGIN
  SELECT compatibility.applied_count INTO current_count
  FROM app.schema_compatibility_v47() AS compatibility;
  RETURN current_count=209
    AND app.private_mfa_policy_administration_schema_readiness_v7();
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;
CREATE FUNCTION app.platform_identity_runtime_schema_readiness_v13()
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
DECLARE current_count bigint;
BEGIN
  SELECT compatibility.applied_count INTO current_count
  FROM app.schema_compatibility_v47() AS compatibility;
  RETURN current_count=209
    AND app.mfa_policy_administration_schema_readiness_v7()
    AND app.private_platform_identity_runtime_schema_readiness_v13();
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;
CREATE FUNCTION app.platform_oidc_direct_runtime_schema_readiness_v9()
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
DECLARE current_count bigint;
BEGIN
  SELECT compatibility.applied_count INTO current_count
  FROM app.schema_compatibility_v47() AS compatibility;
  RETURN current_count=209
    AND app.platform_identity_runtime_schema_readiness_v13()
    AND app.private_platform_oidc_direct_runtime_schema_readiness_v9()
    AND NOT pg_catalog.has_function_privilege(
      'periapsis_api','app.platform_oidc_direct_runtime_schema_readiness_v8()'::regprocedure,'EXECUTE');
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;
CREATE FUNCTION app.platform_saml_direct_runtime_schema_readiness_v6()
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
DECLARE current_count bigint;
BEGIN
  SELECT compatibility.applied_count INTO current_count
  FROM app.schema_compatibility_v47() AS compatibility;
  RETURN current_count=209
    AND app.platform_identity_runtime_schema_readiness_v13()
    AND app.private_platform_saml_direct_runtime_schema_readiness_v6()
    AND NOT pg_catalog.has_function_privilege(
      'periapsis_api','app.platform_saml_direct_runtime_schema_readiness_v5()'::regprocedure,'EXECUTE');
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;
ALTER FUNCTION app.mfa_policy_administration_schema_readiness_v7()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.platform_identity_runtime_schema_readiness_v13()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.platform_oidc_direct_runtime_schema_readiness_v9()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.platform_saml_direct_runtime_schema_readiness_v6()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.mfa_policy_administration_schema_readiness_v7()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
REVOKE ALL ON FUNCTION app.platform_identity_runtime_schema_readiness_v13()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
REVOKE ALL ON FUNCTION app.platform_oidc_direct_runtime_schema_readiness_v9()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
REVOKE ALL ON FUNCTION app.platform_saml_direct_runtime_schema_readiness_v6()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
GRANT EXECUTE ON FUNCTION app.mfa_policy_administration_schema_readiness_v7()
  TO periapsis_api,periapsis_worker;
GRANT EXECUTE ON FUNCTION app.platform_identity_runtime_schema_readiness_v13()
  TO periapsis_api,periapsis_worker;
GRANT EXECUTE ON FUNCTION app.platform_oidc_direct_runtime_schema_readiness_v9()
  TO periapsis_api,periapsis_worker;
GRANT EXECUTE ON FUNCTION app.platform_saml_direct_runtime_schema_readiness_v6()
  TO periapsis_api,periapsis_worker;
