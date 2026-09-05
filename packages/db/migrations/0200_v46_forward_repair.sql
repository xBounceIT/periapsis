-- Converge the distributed V45 catalog and a clean LF rebuild before
-- deriving the single V46 compatibility root. Every supported predecessor and
-- every canonical result is pinned by function identity and source digest.
-- Drizzle creates this journal schema before applying the bundle. Keep the
-- idempotent declaration here as well so the canonical DDL is independently
-- consumable by schema analyzers such as sqlc.
CREATE SCHEMA IF NOT EXISTS drizzle;
--> statement-breakpoint

CREATE TABLE IF NOT EXISTS drizzle.__periapsis_migration_convergence_attestations (
  attestation_id uuid PRIMARY KEY DEFAULT uuidv7(),
  convergence_version smallint NOT NULL,
  source_variant text NOT NULL,
  metadata_original_hash text NOT NULL,
  compatibility_original_hash text NOT NULL,
  raw_v45_fingerprint text NOT NULL,
  normalized_v45_fingerprint text NOT NULL,
  canonical_catalog_digest text NOT NULL,
  attested_at timestamp with time zone NOT NULL,
  CONSTRAINT migration_convergence_version_check
    CHECK (convergence_version=46),
  CONSTRAINT migration_convergence_version_key
    UNIQUE (convergence_version),
  CONSTRAINT migration_convergence_source_variant_check
    CHECK (source_variant IN ('legacy-v45','canonical-v45')),
  CONSTRAINT migration_convergence_uuidv7_check
    CHECK (uuid_extract_version(attestation_id)=7),
  CONSTRAINT migration_convergence_hashes_check CHECK (
    metadata_original_hash ~ '^[0-9a-f]{64}$'
    AND compatibility_original_hash ~ '^[0-9a-f]{64}$'
    AND canonical_catalog_digest ~ '^[0-9a-f]{64}$'
  ),
  CONSTRAINT migration_convergence_fingerprints_check CHECK (
    raw_v45_fingerprint ~
      '^[0-9]+@[0-9a-f]{64}(:[0-9]+@[0-9a-f]{64}){198}$'
    AND normalized_v45_fingerprint ~
      '^[0-9]+@[0-9a-f]{64}(:[0-9]+@[0-9a-f]{64}){198}$'
  )
);
ALTER TABLE drizzle.__periapsis_migration_convergence_attestations
  OWNER TO periapsis_migrator;
REVOKE ALL ON TABLE drizzle.__periapsis_migration_convergence_attestations
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
       periapsis_auditor;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.guard_migration_convergence_attestation_v1()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog AS $function$
BEGIN
  RAISE EXCEPTION 'migration convergence attestations are immutable'
    USING ERRCODE='55000';
END;
$function$;
ALTER FUNCTION app.guard_migration_convergence_attestation_v1()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.guard_migration_convergence_attestation_v1()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
       periapsis_auditor;
DO $create_migration_convergence_guard$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_trigger AS trigger_row
    WHERE trigger_row.tgrelid=
      'drizzle.__periapsis_migration_convergence_attestations'::regclass
      AND trigger_row.tgname='migration_convergence_immutable'
      AND NOT trigger_row.tgisinternal
  ) THEN
    CREATE TRIGGER migration_convergence_immutable
    BEFORE UPDATE OR DELETE
    ON drizzle.__periapsis_migration_convergence_attestations
    FOR EACH ROW EXECUTE FUNCTION
      app.guard_migration_convergence_attestation_v1();
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_trigger AS trigger_row
    WHERE trigger_row.tgrelid=
      'drizzle.__periapsis_migration_convergence_attestations'::regclass
      AND trigger_row.tgname='migration_convergence_truncate_immutable'
      AND NOT trigger_row.tgisinternal
  ) THEN
    CREATE TRIGGER migration_convergence_truncate_immutable
    BEFORE TRUNCATE
    ON drizzle.__periapsis_migration_convergence_attestations
    FOR EACH STATEMENT EXECUTE FUNCTION
      app.guard_migration_convergence_attestation_v1();
  END IF;
END;
$create_migration_convergence_guard$;
--> statement-breakpoint

-- V45 accepted Unicode bidi formatting controls and non-ASCII
-- strings.TrimSpace whitespace at profile display-name edges.
-- Keep 0199 as immutable predecessor evidence and converge the live catalog
-- here before V46 is attested. The helper is deliberately exact and private;
-- both the constraint and convergence readiness bind its catalog definition.
CREATE OR REPLACE FUNCTION app.private_ticket_watcher_display_name_valid_v1(
  p_value text
)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
SET search_path=pg_catalog
AS $function$
  SELECT btrim(p_value)<>''
    AND btrim(p_value)=p_value
    AND char_length(p_value)<=160
    AND p_value !~ '[[:cntrl:]]'
    AND p_value !~ U&'[\200E\200F\202A-\202E\2066-\2069]'
    -- Go strings.TrimSpace uses exactly Unicode White_Space at either edge.
    -- Spell the set out so database locale and regex shorthands cannot widen it.
    AND p_value !~ U&'^[\0009-\000D\0020\0085\00A0\1680\2000-\200A\2028\2029\202F\205F\3000]|[\0009-\000D\0020\0085\00A0\1680\2000-\200A\2028\2029\202F\205F\3000]$';
$function$;
ALTER FUNCTION app.private_ticket_watcher_display_name_valid_v1(text)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_watcher_display_name_valid_v1(text)
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
       periapsis_auditor,periapsis_ticket_runtime_owner;
GRANT EXECUTE ON FUNCTION app.private_ticket_watcher_display_name_valid_v1(text)
  TO periapsis_ticket_runtime_owner;
ALTER TABLE public.ticket_watcher_events
  DROP CONSTRAINT IF EXISTS ticket_watcher_events_display_name_check;
ALTER TABLE public.ticket_watcher_events
  ADD CONSTRAINT ticket_watcher_events_display_name_check CHECK (
    app.private_ticket_watcher_display_name_valid_v1(display_name_snapshot)
  );
--> statement-breakpoint

DO $v46_forward_repair$
DECLARE
  legacy_ready boolean;
  canonical_ready boolean;
  v_source_variant text;
  v_metadata_original_hash text;
  v_compatibility_original_hash text;
  v_raw_v45_fingerprint text;
  v_normalized_v45_fingerprint text;
  v_canonical_catalog_digest text;
  v45_count bigint;
  v45_latest bigint;
BEGIN
  WITH expected(identity,source_hash) AS (
    VALUES
      ('app.apply_tenant_ticket_mutation_v1(public.ticket_aggregate_kind,uuid,text,integer,integer,uuid,integer,text,text,text,boolean,uuid,uuid,uuid,text,text,text,jsonb,bytea,bytea,uuid,uuid,inet,text,text)','dd6faddd70c6155af88c610679ca69305e073cb8a2dce5adb982293f08de5202')
      ,('app.apply_ticket_bulk_target_v1(jsonb)','3bfb09f886577a72d24b77b21dd3643a60aba6ef543050b34722e6214e618e80')
      ,('app.execute_sla_trigger_action_v1(uuid,uuid,uuid,bigint,bytea,public.sla_trigger_action_kind,timestamp with time zone)','af1c513f046bb3a5c096e70283cdbdcd08ad81d68304be8e1ecf32b6148310bf')
      ,('app.private_append_sla_action_audit_v1(uuid,uuid,text,timestamp with time zone,jsonb)','0ebbaba464790c09ca7a2f7abb0f27b58c54a73081b00fcda3b09984fa448763')
      ,('app.private_ticket_export_requester_live_v1(public.ticket_export_jobs)','b6e60a4d7947834e13ce543b4c2f3c0e439c43942a124f8cc78ba04867897ac8')
      ,('app.private_ticket_runtime_append_human_effects_v1(uuid,jsonb,jsonb,text,text,uuid,bigint,timestamp with time zone,jsonb)','04b98c297f6b032640b7fe8e3f20eddc397204409e03ef24f802c665a636f7a7')
      ,('app.private_ticket_runtime_append_system_effects_v1(uuid,text,text,uuid,bigint,timestamp with time zone,text,jsonb)','b7fbd12df80d522fcbf7fc699fc7f10e47e849b57f4b72654fad1a3692ad8375')
      ,('app.private_ticket_runtime_catalog_digest_v1(text)','7a22822bfed67da318ee4e6f5cc497648ddb4778c24641e2f208321808b5b869')
      ,('app.replace_tenant_ticket_metadata_v1(public.ticket_aggregate_kind,uuid,bigint,text,text,text,text,text,text,text,boolean,text[],bytea,bytea,uuid,uuid,inet,text,text)','f96503a56446664ed96c51370ae165ee9103509f3d61b543fa56b03e21cd985b')
      ,('app.sla_trigger_action_runtime_schema_readiness_v1()','718a00b46945270c0cede9d1684daf22fd72b290bd485106a901f4f0a062576d')
      ,('app.ticket_bulk_runtime_schema_readiness_v1()','934430d5c3711a8959cac382ae6626b97c32418cf0b53a75e1a48ee603d8a5c6')
      ,('app.ticket_export_runtime_schema_readiness_v1()','d490814bd4c9e1ecef70fc9abaddd8205ce45e27df6cf49174e7d1f816e49c26')
  ), actual AS (
    SELECT expected.identity,expected.source_hash,
      pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
        function_row.prosrc,'UTF8')),'hex') AS actual_hash
    FROM expected
    LEFT JOIN pg_catalog.pg_proc AS function_row
      ON function_row.oid=pg_catalog.to_regprocedure(expected.identity)
  )
  SELECT count(*)=12
         AND coalesce(bool_and(actual_hash=source_hash),false)
    INTO legacy_ready FROM actual;
  legacy_ready:=legacy_ready
    AND pg_catalog.to_regprocedure(
      'app.private_append_ticket_bulk_mutation_effects_v1(public.ticket_aggregate_kind,uuid,text,integer,text[],uuid,uuid,inet,text,text,jsonb,jsonb,jsonb)'
    ) IS NULL
    AND pg_catalog.to_regprocedure(
      'app.private_apply_ticket_bulk_mutation_v1(public.ticket_aggregate_kind,uuid,text,integer,integer,uuid,integer,text,text,text,boolean,uuid,uuid,uuid,text,text,text,jsonb,bytea,bytea,uuid,uuid,inet,text,text)'
    ) IS NULL
    AND pg_catalog.to_regprocedure(
      'app.private_v45_sla_action_repairs_ready()'
    ) IS NULL
    AND pg_catalog.to_regprocedure(
      'app.private_v45_ticket_runtime_repairs_ready(text)'
    ) IS NULL;

  WITH expected(identity,source_hash) AS (
    VALUES
      ('app.apply_tenant_ticket_mutation_v1(public.ticket_aggregate_kind,uuid,text,integer,integer,uuid,integer,text,text,text,boolean,uuid,uuid,uuid,text,text,text,jsonb,bytea,bytea,uuid,uuid,inet,text,text)','5e14daab242f4d66ac6193cfce0e7ff1653eb8d0bed956ebba730403ff100e15')
      ,('app.apply_ticket_bulk_target_v1(jsonb)','2b0ce5ef907aed6ee53fe8bf3f23a8fae939304185752d80a526b22ccac487f6')
      ,('app.execute_sla_trigger_action_v1(uuid,uuid,uuid,bigint,bytea,public.sla_trigger_action_kind,timestamp with time zone)','a40dc874f364e73b9602bdae04a3c2ee714839b8b1cadfc873fa8ad03e61fd3c')
      ,('app.private_append_sla_action_audit_v1(uuid,uuid,text,timestamp with time zone,jsonb)','f9e4e780e13e39d191e7f5068c6e3b8272d7df2f1c4e57c4dec5fb1813f2bbbb')
      ,('app.private_append_ticket_bulk_mutation_effects_v1(public.ticket_aggregate_kind,uuid,text,integer,text[],uuid,uuid,inet,text,text,jsonb,jsonb,jsonb)','e1a56ad722b603d2a0c6c67b2350bf99069f1fa60267f6a1c17132c32e1d9f1a')
      ,('app.private_apply_ticket_bulk_mutation_v1(public.ticket_aggregate_kind,uuid,text,integer,integer,uuid,integer,text,text,text,boolean,uuid,uuid,uuid,text,text,text,jsonb,bytea,bytea,uuid,uuid,inet,text,text)','5fef80c1851843719bdfbe83f61feed2eebf5e31156ec3a929d70420f60b9fb2')
      ,('app.private_ticket_export_requester_live_v1(public.ticket_export_jobs)','d36935995ea90ca8150dde407eae130096b1aa30a5ab89fd6364cbaea4877f41')
      ,('app.private_ticket_runtime_append_human_effects_v1(uuid,jsonb,jsonb,text,text,uuid,bigint,timestamp with time zone,jsonb)','c171f2fc279b6e6deae34a258d58ac45e1f63421f8c6e896987a870d8a2e0695')
      ,('app.private_ticket_runtime_append_system_effects_v1(uuid,text,text,uuid,bigint,timestamp with time zone,text,jsonb)','43dbd715c96c3ce908a980bb96c1840ce69edd5c2cffa11e1287b43c565eb941')
      ,('app.private_ticket_runtime_catalog_digest_v1(text)','ca5fcd0dd6313ae9c087fd9374a21912fc4b39039e6b196076bc278f2411db23')
      ,('app.private_ticket_watcher_display_name_valid_v1(text)','b69b7003f5bd8c1df0677280cada79eba38c7c061e1024ae3711f1d6d39b83b7')
      ,('app.private_v45_sla_action_repairs_ready()','16a8f24a57c37700e9f104d47a467cafb4e0ae54f9b1c76e0e305b4c644cfe00')
      ,('app.private_v45_ticket_runtime_repairs_ready(text)','ad0ed7a40341483fd04a45efddb83d4f2523ba295dc80d8abaf90da4d38c304a')
      ,('app.replace_tenant_ticket_metadata_v1(public.ticket_aggregate_kind,uuid,bigint,text,text,text,text,text,text,text,boolean,text[],bytea,bytea,uuid,uuid,inet,text,text)','dd84a141e54a23d097fbb6a35f2dc9e8321262ac9decc5fb78ad927975374e33')
      ,('app.sla_trigger_action_runtime_schema_readiness_v1()','de66e722783bb54c663e5fbfce40a99374cf5cedafbe936ee61af0dc7e21d72f')
      ,('app.ticket_bulk_runtime_schema_readiness_v1()','720ac628734386423164c9fe9b57b29d73b5d0c8604d99123a46c8b731ff0cab')
      ,('app.ticket_export_runtime_schema_readiness_v1()','c1d7f730e15a54271d2a3ec324ab55557ff1d4bd8e6922392cee1648f334281d')
  ), actual AS (
    SELECT expected.identity,expected.source_hash,
      pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
        function_row.prosrc,'UTF8')),'hex') AS actual_hash
    FROM expected
    LEFT JOIN pg_catalog.pg_proc AS function_row
      ON function_row.oid=pg_catalog.to_regprocedure(expected.identity)
  )
  SELECT count(*)=17
         AND coalesce(bool_and(actual_hash=source_hash),false)
    INTO canonical_ready FROM actual;

  IF legacy_ready IS NOT DISTINCT FROM canonical_ready THEN
    RAISE EXCEPTION
      'V45 catalog is neither one exact supported predecessor nor one canonical catalog'
      USING ERRCODE='55000';
  END IF;

  IF legacy_ready THEN
    EXECUTE $v46_forward_statement_01$
-- V45 is a coordinated fail-closed cutover. V44 remains immutable predecessor
-- evidence, but it does not attest the v45 ticket metadata, ticket mutation, SLA action,
-- local-account, bulk/export, and Alert DFIR runtime surfaces. Old binaries
-- reject the advanced journal before any v45 writer becomes admissible.
-- The SLA action definer traverses forced-RLS policies that resolve the tenant
-- through this helper. Keep the edge on the isolated NOLOGIN owner rather than
-- broadening the worker login or making the policy helper public.
GRANT EXECUTE ON FUNCTION app.context_tenant_id()
  TO periapsis_sla_worker_owner;
$v46_forward_statement_01$;

    EXECUTE $v46_forward_statement_02$
-- Repair two latent branches that could not complete a successful SLA action:
-- pgcrypto is intentionally absent, chr(0) is invalid PostgreSQL text, and an
-- uncast CASE expression cannot target the audit_outcome enum. Both functions
-- are derived from attested predecessors so unexpected drift fails migration.
DO $repair_sla_trigger_action_audit_v1$
DECLARE
  predecessor_definition text;
  predecessor_source_hash text;
  repaired_definition text;
  old_expression constant text :=
    'CASE WHEN p_action = ''executed'' THEN ''success'' ELSE ''failure'' END,';
  new_expression constant text :=
    '(CASE WHEN p_action = ''executed'' THEN ''success'' ELSE ''failure'' END)::public.audit_outcome,';
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex')
    INTO STRICT predecessor_definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_append_sla_action_audit_v1(uuid,uuid,text,timestamp with time zone,jsonb)'::regprocedure;
  IF predecessor_source_hash<>
    '0ebbaba464790c09ca7a2f7abb0f27b58c54a73081b00fcda3b09984fa448763' THEN
    RAISE EXCEPTION 'SLA trigger action audit v1 drifted'
      USING ERRCODE='55000';
  END IF;
  IF pg_catalog.strpos(predecessor_definition,old_expression)=0 THEN
    RAISE EXCEPTION 'SLA trigger action audit v1 marker drifted'
      USING ERRCODE='55000';
  END IF;
  repaired_definition:=pg_catalog.replace(
    predecessor_definition,old_expression,new_expression
  );
  EXECUTE repaired_definition;
END;
$repair_sla_trigger_action_audit_v1$;
$v46_forward_statement_02$;

    EXECUTE $v46_forward_statement_03$
DO $repair_sla_trigger_action_execution_v1$
DECLARE
  predecessor_definition text;
  predecessor_source_hash text;
  repaired_definition text;
  old_digest constant text := $old_digest$
    effect_digest := digest(convert_to(
      'periapsis/sla-action/effect/v1' || chr(0)
      || occurrence.id::text || chr(0) || occurrence.action_kind::text
      || chr(0) || effect_kind || chr(0)
      || coalesce(effect_id::text, '') || chr(0)
      || coalesce(effect_version::text, ''), 'UTF8'), 'sha256');
$old_digest$;
  new_digest constant text := $new_digest$
    effect_digest := pg_catalog.sha256(
      pg_catalog.convert_to('periapsis/sla-action/effect/v1', 'UTF8')
      || '\x00'::bytea
      || pg_catalog.convert_to(occurrence.id::text, 'UTF8')
      || '\x00'::bytea
      || pg_catalog.convert_to(occurrence.action_kind::text, 'UTF8')
      || '\x00'::bytea
      || pg_catalog.convert_to(effect_kind, 'UTF8')
      || '\x00'::bytea
      || pg_catalog.convert_to(coalesce(effect_id::text, ''), 'UTF8')
      || '\x00'::bytea
      || pg_catalog.convert_to(coalesce(effect_version::text, ''), 'UTF8')
    );
$new_digest$;
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex')
    INTO STRICT predecessor_definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.execute_sla_trigger_action_v1(uuid,uuid,uuid,bigint,bytea,public.sla_trigger_action_kind,timestamp with time zone)'::regprocedure;
  IF predecessor_source_hash<>
    'af1c513f046bb3a5c096e70283cdbdcd08ad81d68304be8e1ecf32b6148310bf' THEN
    RAISE EXCEPTION 'SLA trigger action execution v1 drifted'
      USING ERRCODE='55000';
  END IF;
  IF pg_catalog.strpos(predecessor_definition,old_digest)=0 THEN
    RAISE EXCEPTION 'SLA trigger action execution v1 marker drifted'
      USING ERRCODE='55000';
  END IF;
  repaired_definition:=pg_catalog.replace(
    predecessor_definition,old_digest,new_digest
  );
  EXECUTE repaired_definition;
END;
$repair_sla_trigger_action_execution_v1$;
$v46_forward_statement_03$;

    EXECUTE $v46_forward_statement_04$
CREATE FUNCTION app.private_v45_sla_action_repairs_ready()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path=pg_catalog
AS $function$
DECLARE
  function_row record;
BEGIN
  IF NOT pg_catalog.has_function_privilege(
    'periapsis_sla_worker_owner','app.context_tenant_id()','EXECUTE'
  ) THEN
    RETURN false;
  END IF;
  FOR function_row IN
    SELECT expected.identity,expected.source_hash
    FROM (VALUES
      ('app.execute_sla_trigger_action_v1(uuid,uuid,uuid,bigint,bytea,public.sla_trigger_action_kind,timestamp with time zone)',
       'a40dc874f364e73b9602bdae04a3c2ee714839b8b1cadfc873fa8ad03e61fd3c'),
      ('app.private_append_sla_action_audit_v1(uuid,uuid,text,timestamp with time zone,jsonb)',
       'f9e4e780e13e39d191e7f5068c6e3b8272d7df2f1c4e57c4dec5fb1813f2bbbb')
    ) AS expected(identity,source_hash)
  LOOP
    IF pg_catalog.to_regprocedure(function_row.identity) IS NULL
       OR NOT EXISTS (
         SELECT 1 FROM pg_catalog.pg_proc AS procedure
         JOIN pg_catalog.pg_roles AS owner ON owner.oid=procedure.proowner
         WHERE procedure.oid=pg_catalog.to_regprocedure(function_row.identity)
           AND owner.rolname='periapsis_sla_worker_owner'
           AND procedure.prosecdef AND procedure.provolatile='v'
           AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
             procedure.prosrc,'UTF8')),'hex')=function_row.source_hash
       ) THEN
      RETURN false;
    END IF;
  END LOOP;
  RETURN (
    SELECT count(*)=1 AND coalesce(bool_and(
      privilege.grantor=procedure.proowner
      AND privilege.grantee=procedure.proowner
      AND privilege.privilege_type='EXECUTE'
      AND NOT privilege.is_grantable
    ),false)
    FROM pg_catalog.pg_proc AS procedure
    CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(
      procedure.proacl,pg_catalog.acldefault('f',procedure.proowner)
    )) AS privilege
    WHERE procedure.oid=
      'app.private_append_sla_action_audit_v1(uuid,uuid,text,timestamp with time zone,jsonb)'::regprocedure
  );
END;
$function$;
ALTER FUNCTION app.private_v45_sla_action_repairs_ready()
  OWNER TO periapsis_sla_readiness_owner;
REVOKE ALL ON FUNCTION app.private_v45_sla_action_repairs_ready()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_migrator,periapsis_sla_api_owner,
  periapsis_sla_worker_owner;
$v46_forward_statement_04$;

    EXECUTE $v46_forward_statement_05$
-- Harden the existing readiness root so a catalog can no longer seal while
-- action execution is guaranteed to fail behind forced RLS. Derive from the
-- attested predecessor instead of duplicating its large catalog contract.
DO $harden_sla_trigger_action_readiness_v1$
DECLARE
  predecessor_definition text;
  predecessor_source_hash text;
  hardened_definition text;
  marker constant text := '  RETURN EXISTS (';
  prerequisite constant text :=
    '  IF NOT EXISTS (' || chr(10) ||
    '    SELECT 1 FROM pg_catalog.pg_proc AS procedure' || chr(10) ||
    '    JOIN pg_catalog.pg_roles AS owner' || chr(10) ||
    '      ON owner.oid=procedure.proowner' || chr(10) ||
    '    WHERE procedure.oid=' || chr(10) ||
    '      ''app.private_v45_sla_action_repairs_ready()''::regprocedure' ||
    chr(10) ||
    '      AND owner.rolname=''periapsis_sla_readiness_owner''' || chr(10) ||
    '      AND procedure.prosecdef AND procedure.provolatile=''s''' ||
    chr(10) ||
    '      AND pg_catalog.encode(pg_catalog.sha256(' || chr(10) ||
    '        pg_catalog.convert_to(procedure.prosrc,''UTF8'')' || chr(10) ||
    '      ),''hex'')=' || chr(10) ||
    '        ''16a8f24a57c37700e9f104d47a467cafb4e0ae54f9b1c76e0e305b4c644cfe00''' ||
    chr(10) ||
    '      AND (SELECT count(*)=1 AND coalesce(bool_and(' || chr(10) ||
    '        privilege.grantor=procedure.proowner' || chr(10) ||
    '        AND privilege.grantee=procedure.proowner' || chr(10) ||
    '        AND privilege.privilege_type=''EXECUTE''' || chr(10) ||
    '        AND NOT privilege.is_grantable' || chr(10) ||
    '      ),false) FROM pg_catalog.aclexplode(coalesce(' || chr(10) ||
    '        procedure.proacl,pg_catalog.acldefault(''f'',procedure.proowner)' ||
    chr(10) || '      )) AS privilege)' || chr(10) ||
    '  ) OR NOT app.private_v45_sla_action_repairs_ready() THEN' || chr(10) ||
    '    RETURN false;' || chr(10) ||
    '  END IF;' || chr(10) || chr(10);
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex')
    INTO STRICT predecessor_definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.sla_trigger_action_runtime_schema_readiness_v1()'::regprocedure;
  IF predecessor_source_hash<>
    '718a00b46945270c0cede9d1684daf22fd72b290bd485106a901f4f0a062576d' THEN
    RAISE EXCEPTION 'SLA trigger action readiness v1 drifted'
      USING ERRCODE='55000';
  END IF;
  IF pg_catalog.strpos(predecessor_definition,marker)=0 THEN
    RAISE EXCEPTION 'SLA trigger action readiness v1 marker drifted'
      USING ERRCODE='55000';
  END IF;
  hardened_definition:=pg_catalog.replace(
    predecessor_definition,marker,prerequisite || marker
  );
  EXECUTE hardened_definition;
END;
$harden_sla_trigger_action_readiness_v1$;
$v46_forward_statement_05$;

    EXECUTE $v46_forward_statement_06$
-- Human ticket-runtime effects must use the ticket principal enum's canonical
-- `human` value; `operator` is an audience, not a principal kind.
DO $repair_ticket_runtime_human_effects_v1$
DECLARE
  predecessor_definition text;
  predecessor_source_hash text;
  repaired_definition text;
  old_expression constant text :=
    '''operator'', actor_id, ''ticket-runtime'', ''operator'',';
  new_expression constant text :=
    '''human'', actor_id, ''ticket-runtime'', ''operator'',';
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex')
    INTO STRICT predecessor_definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_ticket_runtime_append_human_effects_v1(uuid,jsonb,jsonb,text,text,uuid,bigint,timestamp with time zone,jsonb)'::regprocedure;
  IF predecessor_source_hash<>
    '04b98c297f6b032640b7fe8e3f20eddc397204409e03ef24f802c665a636f7a7' THEN
    RAISE EXCEPTION 'ticket runtime human effects v1 drifted'
      USING ERRCODE='55000';
  END IF;
  IF pg_catalog.strpos(predecessor_definition,old_expression)=0 THEN
    RAISE EXCEPTION 'ticket runtime human effects v1 marker drifted'
      USING ERRCODE='55000';
  END IF;
  repaired_definition:=pg_catalog.replace(
    predecessor_definition,old_expression,new_expression
  );
  EXECUTE repaired_definition;
END;
$repair_ticket_runtime_human_effects_v1$;
$v46_forward_statement_06$;

    EXECUTE $v46_forward_statement_07$
-- COLLATE binds more tightly than the jsonb extraction operator. Parenthesize
-- both DISTINCT ON and ORDER BY expressions so PostgreSQL accepts the pinned,
-- deterministic catalog projection.
DO $repair_ticket_runtime_catalog_digest_v1$
DECLARE
  predecessor_definition text;
  predecessor_source_hash text;
  repaired_definition text;
  old_distinct constant text :=
    'SELECT DISTINCT ON (source, definition ->> ''id'')';
  new_distinct constant text :=
    'SELECT DISTINCT ON (source COLLATE "C", (definition ->> ''id'') COLLATE "C")';
  old_order constant text :=
    'ORDER BY source COLLATE "C", definition ->> ''id'' COLLATE "C"';
  new_order constant text :=
    'ORDER BY source COLLATE "C", (definition ->> ''id'') COLLATE "C"';
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex')
    INTO STRICT predecessor_definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_ticket_runtime_catalog_digest_v1(text)'::regprocedure;
  IF predecessor_source_hash<>
    '7a22822bfed67da318ee4e6f5cc497648ddb4778c24641e2f208321808b5b869' THEN
    RAISE EXCEPTION 'ticket runtime catalog digest v1 drifted'
      USING ERRCODE='55000';
  END IF;
  IF pg_catalog.strpos(predecessor_definition,old_distinct)=0
     OR pg_catalog.strpos(predecessor_definition,old_order)=0 THEN
    RAISE EXCEPTION 'ticket runtime catalog digest v1 marker drifted'
      USING ERRCODE='55000';
  END IF;
  repaired_definition:=pg_catalog.replace(
    predecessor_definition,old_distinct,new_distinct
  );
  repaired_definition:=pg_catalog.replace(
    repaired_definition,old_order,new_order
  );
  EXECUTE repaired_definition;
END;
$repair_ticket_runtime_catalog_digest_v1$;
$v46_forward_statement_07$;

    EXECUTE $v46_forward_statement_08$
-- Bulk execution is an isolated system actor operating a previously authorized
-- immutable target set. It must not forge a live human authentication method
-- merely to reuse the synchronous side-effect writer.
CREATE FUNCTION app.private_append_ticket_bulk_mutation_effects_v1(
  p_aggregate_kind public.ticket_aggregate_kind,
  p_aggregate_id uuid,
  p_action text,
  p_version integer,
  p_effects text[],
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
  event_type text := p_aggregate_kind::text || '.' || p_action;
  activity_id uuid := uuidv7();
  activity_sequence bigint;
  notification_type public.notification_event_type;
  routing_creator_user_id uuid;
  routing_assignee_user_id uuid;
  routing_previous_assignee_user_id uuid;
  routing_operator_team_id uuid;
  routing_operator_team_epoch_id uuid;
BEGIN
  PERFORM app.private_validate_ticket_effects_v1(p_effects);
  IF context_tenant IS NULL
     OR p_aggregate_id IS NULL
     OR p_version NOT BETWEEN 1 AND 2147483647
     OR p_action IS NULL OR p_action !~ '^[a-z][a-z0-9_]{1,63}$'
     OR p_request_id IS NULL OR p_correlation_id IS NULL
     OR p_ip_address IS NOT NULL
     OR p_user_agent IS DISTINCT FROM 'ticket-bulk-worker'
     OR p_authentication_method IS DISTINCT FROM 'system'
     OR p_before IS NOT NULL AND jsonb_typeof(p_before) <> 'object'
     OR p_after IS NOT NULL AND jsonb_typeof(p_after) <> 'object'
     OR p_metadata IS NULL OR jsonb_typeof(p_metadata) <> 'object'
     OR pg_column_size(p_metadata) > 16384 THEN
    RAISE EXCEPTION 'ticket bulk mutation effects are invalid'
      USING ERRCODE='22023';
  END IF;

  SELECT coalesce(max(activity.sequence),0)+1 INTO activity_sequence
  FROM public.ticket_activities AS activity
  WHERE activity.tenant_id=context_tenant
    AND (p_aggregate_kind='alert' AND activity.alert_id=p_aggregate_id
      OR p_aggregate_kind='case' AND activity.case_id=p_aggregate_id);
  IF activity_sequence NOT BETWEEN 1 AND 2147483647 THEN
    RAISE EXCEPTION 'ticket bulk activity sequence is exhausted'
      USING ERRCODE='54000';
  END IF;

  INSERT INTO public.ticket_activities(
    id,tenant_id,alert_id,case_id,sequence,kind,summary,
    actor_principal_kind,origin,details,occurred_at
  ) VALUES (
    activity_id,context_tenant,
    CASE WHEN p_aggregate_kind='alert' THEN p_aggregate_id END,
    CASE WHEN p_aggregate_kind='case' THEN p_aggregate_id END,
    activity_sequence,event_type,
    initcap(p_aggregate_kind::text) || ' ' || replace(p_action,'_',' '),
    'system','system',p_metadata || jsonb_build_object(
      'version',p_version,'contentRedacted',true
    ),transaction_timestamp()
  );

  INSERT INTO public.audit_events(
    id,tenant_id,sequence,occurred_at,actor_type,action,
    resource_type,resource_id,request_id,correlation_id,
    authentication_method,outcome,before,after,metadata
  ) VALUES (
    uuidv7(),context_tenant,0,transaction_timestamp(),'system',
    'tenant.' || event_type,p_aggregate_kind::text,p_aggregate_id,
    p_request_id,p_correlation_id,'system','success',p_before,p_after,
    p_metadata || jsonb_build_object('contentRedacted',true)
  );

  INSERT INTO public.outbox_events(
    id,tenant_id,aggregate_type,aggregate_id,aggregate_version,event_type,
    schema_version,payload,deduplication_key,correlation_id,causation_id,
    actor_kind,producer,maximum_audience,occurred_at,available_at
  ) VALUES (
    uuidv7(),context_tenant,p_aggregate_kind::text,p_aggregate_id,p_version,
    event_type,1,jsonb_build_object(
      p_aggregate_kind::text || '_id',p_aggregate_id,
      'version',p_version,'contentRedacted',true
    ),event_type || ':' || activity_id::text,p_correlation_id,p_request_id,
    'system','ticket-bulk-worker','operator',
    transaction_timestamp(),transaction_timestamp()
  );

  IF p_effects @> ARRAY['sla']::text[] THEN
    INSERT INTO public.outbox_events(
      id,tenant_id,aggregate_type,aggregate_id,aggregate_version,event_type,
      schema_version,payload,deduplication_key,correlation_id,causation_id,
      actor_kind,producer,maximum_audience,occurred_at,available_at
    ) VALUES (
      uuidv7(),context_tenant,p_aggregate_kind::text,p_aggregate_id,p_version,
      'sla.' || event_type,1,jsonb_build_object(
        p_aggregate_kind::text || '_id',p_aggregate_id,
        'version',p_version,'action',p_action,'contentRedacted',true
      ),'sla.' || event_type || ':' || activity_id::text,
      p_correlation_id,p_request_id,'system','ticket-bulk-worker','operator',
      transaction_timestamp(),transaction_timestamp()
    );
  END IF;
  IF p_effects @> ARRAY['notification']::text[] THEN
    notification_type:=CASE
      WHEN p_aggregate_kind='alert' AND p_action='created'
        THEN 'alert.created'::public.notification_event_type
      WHEN p_aggregate_kind='alert' AND p_action='assigned'
        THEN 'alert.assigned'::public.notification_event_type
      WHEN p_aggregate_kind='alert' AND p_action='claimed'
        THEN 'alert.claimed'::public.notification_event_type
      WHEN p_aggregate_kind='alert' AND p_action='transitioned'
        THEN 'alert.status_changed'::public.notification_event_type
      WHEN p_aggregate_kind='alert' AND p_action='escalated'
        THEN 'alert.escalated'::public.notification_event_type
      WHEN p_aggregate_kind='case' AND p_action='created'
        THEN 'case.created'::public.notification_event_type
      WHEN p_aggregate_kind='case' AND p_action='assigned'
        THEN 'case.assigned'::public.notification_event_type
      WHEN p_aggregate_kind='case' AND p_action='claimed'
        THEN 'case.claimed'::public.notification_event_type
      WHEN p_aggregate_kind='case' AND p_action='transferred'
        THEN 'case.transferred'::public.notification_event_type
      WHEN p_aggregate_kind='case' AND p_action='transitioned'
        THEN 'case.status_changed'::public.notification_event_type
      ELSE NULL
    END;
    IF notification_type IS NOT NULL THEN
      routing_previous_assignee_user_id:=nullif(
        p_before ->> 'assignee_user_id',''
      )::uuid;
      IF p_aggregate_kind='alert' THEN
        SELECT alert.created_by,alert.assignee_user_id,
               alert.assigned_team_id,alert.assigned_team_epoch_id
        INTO STRICT routing_creator_user_id,routing_assignee_user_id,
             routing_operator_team_id,routing_operator_team_epoch_id
        FROM public.alerts AS alert
        WHERE alert.tenant_id=context_tenant AND alert.id=p_aggregate_id;
      ELSE
        SELECT case_row.created_by_user_id,case_row.assignee_user_id,
               case_row.assigned_team_id,case_row.assigned_team_epoch_id
        INTO STRICT routing_creator_user_id,routing_assignee_user_id,
             routing_operator_team_id,routing_operator_team_epoch_id
        FROM public.cases AS case_row
        WHERE case_row.tenant_id=context_tenant AND case_row.id=p_aggregate_id;
      END IF;
      PERFORM app.private_append_tenant_notification_event_v2(
        uuidv7(),notification_type,
        p_aggregate_kind::text::public.notification_object_type,
        p_aggregate_id,p_version,transaction_timestamp(),
        'system',NULL,'ticket-bulk-worker','operator',
        jsonb_build_object(
          p_aggregate_kind::text,jsonb_build_object(
            'id',p_aggregate_id,'version',p_version
          ),
          'actor',jsonb_build_object('kind','system'),
          'action',p_action,
          'metadata',p_metadata || jsonb_build_object(
            'content_redacted',true
          ),
          'routing',jsonb_strip_nulls(jsonb_build_object(
            'creatorUserId',routing_creator_user_id,
            'assigneeUserId',routing_assignee_user_id,
            'previousAssigneeUserId',routing_previous_assignee_user_id,
            'operatorTeamId',routing_operator_team_id,
            'operatorTeamEpochId',routing_operator_team_epoch_id
          ))
        ),
        NULL,
        'notification:v2:' || p_aggregate_kind::text || ':' ||
          p_aggregate_id::text || ':' || p_version::text || ':' ||
          notification_type::text,
        p_correlation_id,p_request_id
      );
    END IF;
  END IF;
END;
$function$;
ALTER FUNCTION app.private_append_ticket_bulk_mutation_effects_v1(
  public.ticket_aggregate_kind,uuid,text,integer,text[],uuid,uuid,inet,text,
  text,jsonb,jsonb,jsonb
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_append_ticket_bulk_mutation_effects_v1(
  public.ticket_aggregate_kind,uuid,text,integer,text[],uuid,uuid,inet,text,
  text,jsonb,jsonb,jsonb
) FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_ticket_runtime_owner;
$v46_forward_statement_08$;

    EXECUTE $v46_forward_statement_09$
-- Repair the synchronous mutation implementation for PostgreSQL's strict
-- variable/column resolution and heterogeneous alert/case row descriptors,
-- then derive a private bulk-only copy with system-attributed side effects.
DO $repair_and_derive_ticket_mutation_v1$
DECLARE
  predecessor_definition text;
  predecessor_source_hash text;
  repaired_definition text;
  bulk_definition text;
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex')
    INTO STRICT predecessor_definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.apply_tenant_ticket_mutation_v1(public.ticket_aggregate_kind,uuid,text,integer,integer,uuid,integer,text,text,text,boolean,uuid,uuid,uuid,text,text,text,jsonb,bytea,bytea,uuid,uuid,inet,text,text)'::regprocedure;
  IF predecessor_source_hash<>
    'dd6faddd70c6155af88c610679ca69305e073cb8a2dce5adb982293f08de5202' THEN
    RAISE EXCEPTION 'tenant ticket mutation v1 drifted'
      USING ERRCODE='55000';
  END IF;
  repaired_definition:=pg_catalog.replace(
    predecessor_definition,'operation text :=','operation_name text :='
  );
  repaired_definition:=pg_catalog.replace(
    repaired_definition,'|| operation ||','|| operation_name ||'
  );
  repaired_definition:=pg_catalog.replace(
    repaired_definition,'command.operation = operation',
    'command.operation = operation_name'
  );
  repaired_definition:=pg_catalog.replace(
    repaired_definition,'context_tenant, operation, actor_membership',
    'context_tenant, operation_name, actor_membership'
  );
  repaired_definition:=pg_catalog.replace(
    repaired_definition,'SELECT alert.* INTO locked',
    'SELECT alert.*, alert.created_by AS creator_user_id INTO locked'
  );
  repaired_definition:=pg_catalog.replace(
    repaired_definition,'SELECT case_row.* INTO locked',
    'SELECT case_row.*, case_row.created_by_user_id AS creator_user_id INTO locked'
  );
  repaired_definition:=pg_catalog.regexp_replace(
    repaired_definition,
    'CASE WHEN p_aggregate_kind = ''alert'' THEN locked[.]created_by[[:space:]]+ELSE locked[.]created_by_user_id END',
    'locked.creator_user_id','g'
  );
  IF pg_catalog.strpos(repaired_definition,'operation text :=')<>0
     OR pg_catalog.strpos(repaired_definition,'locked.created_by_user_id')<>0
     OR pg_catalog.strpos(repaired_definition,'locked.creator_user_id')=0 THEN
    RAISE EXCEPTION 'tenant ticket mutation v1 repair markers drifted'
      USING ERRCODE='55000';
  END IF;
  EXECUTE repaired_definition;

  bulk_definition:=pg_catalog.replace(
    repaired_definition,'apply_tenant_ticket_mutation_v1',
    'private_apply_ticket_bulk_mutation_v1'
  );
  bulk_definition:=pg_catalog.replace(
    bulk_definition,'private_append_ticket_side_effects_v1',
    'private_append_ticket_bulk_mutation_effects_v1'
  );
  IF bulk_definition IS NOT DISTINCT FROM repaired_definition THEN
    RAISE EXCEPTION 'private ticket bulk mutation v1 derivation drifted'
      USING ERRCODE='55000';
  END IF;
  EXECUTE bulk_definition;
END;
$repair_and_derive_ticket_mutation_v1$;
ALTER FUNCTION app.private_apply_ticket_bulk_mutation_v1(
  public.ticket_aggregate_kind,uuid,text,integer,integer,uuid,integer,text,
  text,text,boolean,uuid,uuid,uuid,text,text,text,jsonb,bytea,bytea,uuid,uuid,
  inet,text,text
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_apply_ticket_bulk_mutation_v1(
  public.ticket_aggregate_kind,uuid,text,integer,integer,uuid,integer,text,
  text,text,boolean,uuid,uuid,uuid,text,text,text,jsonb,bytea,bytea,uuid,uuid,
  inet,text,text
) FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_ticket_runtime_owner;
$v46_forward_statement_09$;

    EXECUTE $v46_forward_statement_10$
DO $repair_ticket_bulk_target_apply_v1$
DECLARE
  predecessor_definition text;
  predecessor_source_hash text;
  repaired_definition text;
  old_call constant text := 'FROM app.apply_tenant_ticket_mutation_v1(';
  new_call constant text :=
    'FROM app.private_apply_ticket_bulk_mutation_v1(';
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex')
    INTO STRICT predecessor_definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid='app.apply_ticket_bulk_target_v1(jsonb)'::regprocedure;
  IF predecessor_source_hash<>
    '3bfb09f886577a72d24b77b21dd3643a60aba6ef543050b34722e6214e618e80' THEN
    RAISE EXCEPTION 'ticket bulk target apply v1 drifted'
      USING ERRCODE='55000';
  END IF;
  IF pg_catalog.strpos(predecessor_definition,old_call)=0 THEN
    RAISE EXCEPTION 'ticket bulk target apply v1 marker drifted'
      USING ERRCODE='55000';
  END IF;
  repaired_definition:=pg_catalog.replace(
    predecessor_definition,old_call,new_call
  );
  EXECUTE repaired_definition;
END;
$repair_ticket_bulk_target_apply_v1$;
$v46_forward_statement_10$;

    EXECUTE $v46_forward_statement_11$
DO $repair_ticket_runtime_system_effects_v1$
DECLARE
  predecessor_definition text;
  predecessor_source_hash text;
  repaired_definition text;
  old_expression constant text :=
    'p_resource_type, p_resource_id, ''system'', p_outcome,';
  new_expression constant text :=
    'p_resource_type, p_resource_id, ''system'', p_outcome::public.audit_outcome,';
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex')
    INTO STRICT predecessor_definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_ticket_runtime_append_system_effects_v1(uuid,text,text,uuid,bigint,timestamp with time zone,text,jsonb)'::regprocedure;
  IF predecessor_source_hash<>
    'b7fbd12df80d522fcbf7fc699fc7f10e47e849b57f4b72654fad1a3692ad8375' THEN
    RAISE EXCEPTION 'ticket runtime system effects v1 drifted'
      USING ERRCODE='55000';
  END IF;
  IF pg_catalog.strpos(predecessor_definition,old_expression)=0 THEN
    RAISE EXCEPTION 'ticket runtime system effects v1 marker drifted'
      USING ERRCODE='55000';
  END IF;
  repaired_definition:=pg_catalog.replace(
    predecessor_definition,old_expression,new_expression
  );
  EXECUTE repaired_definition;
END;
$repair_ticket_runtime_system_effects_v1$;
$v46_forward_statement_11$;

    EXECUTE $v46_forward_statement_12$
DO $repair_ticket_export_requester_live_v1$
DECLARE
  predecessor_definition text;
  predecessor_source_hash text;
  repaired_definition text;
  old_expression constant text :=
    'membership.status = ''active'' AND account.status = ''active''';
  new_expression constant text :=
    'membership.status = ''active'' AND account.active';
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex')
    INTO STRICT predecessor_definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_ticket_export_requester_live_v1(public.ticket_export_jobs)'::regprocedure;
  IF predecessor_source_hash<>
    'b6e60a4d7947834e13ce543b4c2f3c0e439c43942a124f8cc78ba04867897ac8' THEN
    RAISE EXCEPTION 'ticket export requester liveness v1 drifted'
      USING ERRCODE='55000';
  END IF;
  IF pg_catalog.strpos(predecessor_definition,old_expression)=0 THEN
    RAISE EXCEPTION 'ticket export requester liveness v1 marker drifted'
      USING ERRCODE='55000';
  END IF;
  repaired_definition:=pg_catalog.replace(
    predecessor_definition,old_expression,new_expression
  );
  EXECUTE repaired_definition;
END;
$repair_ticket_export_requester_live_v1$;
$v46_forward_statement_12$;

    EXECUTE $v46_forward_statement_13$
-- The original bulk/export readiness roots predate the v45 forward repairs.
-- Bind them to every repaired/private dependency and its exact executable ACL,
-- otherwise a latent mutation/audit/export defect could still report ready.
CREATE FUNCTION app.private_v45_ticket_runtime_repairs_ready(p_surface text)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path=pg_catalog
AS $function$
DECLARE
  expected_function record;
BEGIN
  IF p_surface IS NULL OR p_surface NOT IN ('bulk','export') THEN
    RETURN false;
  END IF;
  FOR expected_function IN
    SELECT expected.identity,expected.source_hash,
           expected.security_definer,expected.volatility,
           expected.execute_roles
    FROM (VALUES
      (ARRAY['bulk']::text[],
       'app.apply_tenant_ticket_mutation_v1(public.ticket_aggregate_kind,uuid,text,integer,integer,uuid,integer,text,text,text,boolean,uuid,uuid,uuid,text,text,text,jsonb,bytea,bytea,uuid,uuid,inet,text,text)',
       '5e14daab242f4d66ac6193cfce0e7ff1653eb8d0bed956ebba730403ff100e15',
       true,'v',ARRAY['periapsis_api','periapsis_migrator']::text[]),
      (ARRAY['bulk']::text[],
       'app.apply_ticket_bulk_target_v1(jsonb)',
       '2b0ce5ef907aed6ee53fe8bf3f23a8fae939304185752d80a526b22ccac487f6',
       true,'v',ARRAY['periapsis_migrator','periapsis_worker']::text[]),
      (ARRAY['bulk']::text[],
       'app.private_apply_ticket_bulk_mutation_v1(public.ticket_aggregate_kind,uuid,text,integer,integer,uuid,integer,text,text,text,boolean,uuid,uuid,uuid,text,text,text,jsonb,bytea,bytea,uuid,uuid,inet,text,text)',
       '5fef80c1851843719bdfbe83f61feed2eebf5e31156ec3a929d70420f60b9fb2',
       true,'v',ARRAY['periapsis_migrator']::text[]),
      (ARRAY['bulk']::text[],
       'app.private_append_ticket_bulk_mutation_effects_v1(public.ticket_aggregate_kind,uuid,text,integer,text[],uuid,uuid,inet,text,text,jsonb,jsonb,jsonb)',
       'e1a56ad722b603d2a0c6c67b2350bf99069f1fa60267f6a1c17132c32e1d9f1a',
       true,'v',ARRAY['periapsis_migrator']::text[]),
      (ARRAY['bulk','export']::text[],
       'app.private_ticket_runtime_append_human_effects_v1(uuid,jsonb,jsonb,text,text,uuid,bigint,timestamp with time zone,jsonb)',
       'c171f2fc279b6e6deae34a258d58ac45e1f63421f8c6e896987a870d8a2e0695',
       true,'v',ARRAY['periapsis_migrator']::text[]),
      (ARRAY['bulk','export']::text[],
       'app.private_ticket_runtime_catalog_digest_v1(text)',
       'ca5fcd0dd6313ae9c087fd9374a21912fc4b39039e6b196076bc278f2411db23',
       false,'i',ARRAY['periapsis_migrator']::text[]),
      (ARRAY['bulk','export']::text[],
       'app.private_ticket_runtime_append_system_effects_v1(uuid,text,text,uuid,bigint,timestamp with time zone,text,jsonb)',
       '43dbd715c96c3ce908a980bb96c1840ce69edd5c2cffa11e1287b43c565eb941',
       true,'v',ARRAY['periapsis_migrator']::text[]),
      (ARRAY['export']::text[],
       'app.private_ticket_export_requester_live_v1(public.ticket_export_jobs)',
       'd36935995ea90ca8150dde407eae130096b1aa30a5ab89fd6364cbaea4877f41',
       true,'v',ARRAY['periapsis_migrator']::text[])
    ) AS expected(
      surfaces,identity,source_hash,security_definer,volatility,execute_roles
    )
    WHERE p_surface=ANY(expected.surfaces)
  LOOP
    IF pg_catalog.to_regprocedure(expected_function.identity) IS NULL
       OR NOT EXISTS (
         SELECT 1
         FROM pg_catalog.pg_proc AS procedure
         JOIN pg_catalog.pg_roles AS owner ON owner.oid=procedure.proowner
         WHERE procedure.oid=
           pg_catalog.to_regprocedure(expected_function.identity)
           AND owner.rolname='periapsis_migrator'
           AND procedure.prosecdef=expected_function.security_definer
           AND procedure.provolatile=expected_function.volatility
           AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
             procedure.prosrc,'UTF8')),'hex')=expected_function.source_hash
           AND (
             SELECT pg_catalog.array_agg(
                      grantee.rolname::text ORDER BY grantee.rolname
                    )=expected_function.execute_roles
                    AND pg_catalog.bool_and(
                      privilege.grantor=procedure.proowner
                      AND privilege.privilege_type='EXECUTE'
                      AND NOT privilege.is_grantable
                    )
             FROM pg_catalog.aclexplode(coalesce(
               procedure.proacl,
               pg_catalog.acldefault('f',procedure.proowner)
             )) AS privilege
             LEFT JOIN pg_catalog.pg_roles AS grantee
               ON grantee.oid=privilege.grantee
           )
       ) THEN
      RETURN false;
    END IF;
  END LOOP;
  RETURN true;
END;
$function$;
ALTER FUNCTION app.private_v45_ticket_runtime_repairs_ready(text)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_v45_ticket_runtime_repairs_ready(text)
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_ticket_runtime_owner;
$v46_forward_statement_13$;

    EXECUTE $v46_forward_statement_14$
DO $harden_ticket_bulk_runtime_readiness_v1$
DECLARE
  predecessor_definition text;
  predecessor_source_hash text;
  hardened_definition text;
  marker constant text := '  RETURN EXISTS (';
  prerequisite constant text :=
    '  IF NOT EXISTS (' || chr(10) ||
    '    SELECT 1 FROM pg_catalog.pg_proc AS procedure' || chr(10) ||
    '    JOIN pg_catalog.pg_roles AS owner' || chr(10) ||
    '      ON owner.oid=procedure.proowner' || chr(10) ||
    '    WHERE procedure.oid=' || chr(10) ||
    '      ''app.private_v45_ticket_runtime_repairs_ready(text)''::regprocedure' ||
    chr(10) ||
    '      AND owner.rolname=''periapsis_migrator''' || chr(10) ||
    '      AND procedure.prosecdef AND procedure.provolatile=''s''' ||
    chr(10) ||
    '      AND pg_catalog.encode(pg_catalog.sha256(' || chr(10) ||
    '        pg_catalog.convert_to(procedure.prosrc,''UTF8'')' || chr(10) ||
    '      ),''hex'')=' || chr(10) ||
    '        ''ad0ed7a40341483fd04a45efddb83d4f2523ba295dc80d8abaf90da4d38c304a''' ||
    chr(10) ||
    '      AND (SELECT count(*)=1 AND coalesce(bool_and(' || chr(10) ||
    '        privilege.grantor=procedure.proowner' || chr(10) ||
    '        AND privilege.grantee=procedure.proowner' || chr(10) ||
    '        AND privilege.privilege_type=''EXECUTE''' || chr(10) ||
    '        AND NOT privilege.is_grantable' || chr(10) ||
    '      ),false) FROM pg_catalog.aclexplode(coalesce(' || chr(10) ||
    '        procedure.proacl,pg_catalog.acldefault(''f'',procedure.proowner)' ||
    chr(10) || '      )) AS privilege)' || chr(10) ||
    '  ) OR NOT app.private_v45_ticket_runtime_repairs_ready(''bulk'') THEN' ||
    chr(10) || '    RETURN false;' || chr(10) || '  END IF;' ||
    chr(10) || chr(10);
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex')
    INTO STRICT predecessor_definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.ticket_bulk_runtime_schema_readiness_v1()'::regprocedure;
  IF predecessor_source_hash<>
    '934430d5c3711a8959cac382ae6626b97c32418cf0b53a75e1a48ee603d8a5c6' THEN
    RAISE EXCEPTION 'ticket bulk runtime readiness v1 drifted'
      USING ERRCODE='55000';
  END IF;
  IF pg_catalog.strpos(predecessor_definition,marker)=0 THEN
    RAISE EXCEPTION 'ticket bulk runtime readiness v1 marker drifted'
      USING ERRCODE='55000';
  END IF;
  hardened_definition:=pg_catalog.replace(
    predecessor_definition,marker,prerequisite || marker
  );
  EXECUTE hardened_definition;
END;
$harden_ticket_bulk_runtime_readiness_v1$;
$v46_forward_statement_14$;

    EXECUTE $v46_forward_statement_15$
DO $harden_ticket_export_runtime_readiness_v1$
DECLARE
  predecessor_definition text;
  predecessor_source_hash text;
  hardened_definition text;
  marker constant text := '  RETURN EXISTS (';
  prerequisite constant text :=
    '  IF NOT EXISTS (' || chr(10) ||
    '    SELECT 1 FROM pg_catalog.pg_proc AS procedure' || chr(10) ||
    '    JOIN pg_catalog.pg_roles AS owner' || chr(10) ||
    '      ON owner.oid=procedure.proowner' || chr(10) ||
    '    WHERE procedure.oid=' || chr(10) ||
    '      ''app.private_v45_ticket_runtime_repairs_ready(text)''::regprocedure' ||
    chr(10) ||
    '      AND owner.rolname=''periapsis_migrator''' || chr(10) ||
    '      AND procedure.prosecdef AND procedure.provolatile=''s''' ||
    chr(10) ||
    '      AND pg_catalog.encode(pg_catalog.sha256(' || chr(10) ||
    '        pg_catalog.convert_to(procedure.prosrc,''UTF8'')' || chr(10) ||
    '      ),''hex'')=' || chr(10) ||
    '        ''ad0ed7a40341483fd04a45efddb83d4f2523ba295dc80d8abaf90da4d38c304a''' ||
    chr(10) ||
    '      AND (SELECT count(*)=1 AND coalesce(bool_and(' || chr(10) ||
    '        privilege.grantor=procedure.proowner' || chr(10) ||
    '        AND privilege.grantee=procedure.proowner' || chr(10) ||
    '        AND privilege.privilege_type=''EXECUTE''' || chr(10) ||
    '        AND NOT privilege.is_grantable' || chr(10) ||
    '      ),false) FROM pg_catalog.aclexplode(coalesce(' || chr(10) ||
    '        procedure.proacl,pg_catalog.acldefault(''f'',procedure.proowner)' ||
    chr(10) || '      )) AS privilege)' || chr(10) ||
    '  ) OR NOT app.private_v45_ticket_runtime_repairs_ready(''export'') THEN' ||
    chr(10) || '    RETURN false;' || chr(10) || '  END IF;' ||
    chr(10) || chr(10);
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex')
    INTO STRICT predecessor_definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.ticket_export_runtime_schema_readiness_v1()'::regprocedure;
  IF predecessor_source_hash<>
    'd490814bd4c9e1ecef70fc9abaddd8205ce45e27df6cf49174e7d1f816e49c26' THEN
    RAISE EXCEPTION 'ticket export runtime readiness v1 drifted'
      USING ERRCODE='55000';
  END IF;
  IF pg_catalog.strpos(predecessor_definition,marker)=0 THEN
    RAISE EXCEPTION 'ticket export runtime readiness v1 marker drifted'
      USING ERRCODE='55000';
  END IF;
  hardened_definition:=pg_catalog.replace(
    predecessor_definition,marker,prerequisite || marker
  );
  EXECUTE hardened_definition;
END;
$harden_ticket_export_runtime_readiness_v1$;
$v46_forward_statement_15$;

    EXECUTE $v46_forward_metadata$
-- A single human-only ABI owns mutable Alert/Case metadata. The immutable
-- ticket_commands receipt binds actor, aggregate kind/id, expected version,
-- canonical payload, and the historical post-commit projection.
CREATE OR REPLACE FUNCTION app.replace_tenant_ticket_metadata_v1(
  p_aggregate_kind public.ticket_aggregate_kind,
  p_ticket_id uuid,
  p_expected_version bigint,
  p_title text,
  p_description text,
  p_summary text,
  p_severity text,
  p_priority text,
  p_category text,
  p_classification text,
  p_customer_visible boolean,
  p_tags text[],
  p_key_digest bytea,
  p_request_digest bytea,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE(
  result_version bigint,
  result_updated_at timestamp with time zone,
  result_metadata jsonb,
  replayed boolean
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
#variable_conflict use_variable
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid;
  actor_user uuid;
  operation text := p_aggregate_kind::text || '.metadata.replace';
  permission_key text := p_aggregate_kind::text || '.update';
  command_record public.ticket_commands%ROWTYPE;
  command_found boolean;
  current_version integer;
  current_title text;
  current_description text;
  current_summary text;
  current_severity text;
  current_priority text;
  current_category text;
  current_classification text;
  current_customer_visible boolean;
  current_tags text[];
  current_assigned_team uuid;
  current_owner_user uuid;
  current_assignee_user uuid;
  current_claimant_user uuid;
  operation_at timestamp with time zone := transaction_timestamp();
  committed_version integer;
  committed_updated_at timestamp with time zone;
  canonical_summary text := coalesce(p_summary,'');
  canonical_result jsonb;
  changed_fields text[];
  edge_whitespace constant text := E' \t\n\r\v\f'
    || U&'\0085\00A0\1680\2000\2001\2002\2003\2004\2005\2006\2007\2008\2009\200A\2028\2029\202F\205F\3000';
BEGIN
  IF p_aggregate_kind IS NULL
     OR p_ticket_id IS NULL OR uuid_extract_version(p_ticket_id)<>7
     OR p_expected_version IS NULL
        OR p_expected_version NOT BETWEEN 1 AND 2147483646
     OR p_title IS NULL OR btrim(p_title,edge_whitespace)=''
     OR p_title<>btrim(p_title,edge_whitespace)
     OR char_length(p_title)>240
     OR p_title ~ '[[:cntrl:]]'
     OR p_description IS NULL
     OR p_aggregate_kind='alert' AND (
       char_length(p_description)>10000
        OR p_description<>btrim(p_description,edge_whitespace)
       OR regexp_replace(p_description,E'[\t\n\r]','','g') ~ '[[:cntrl:]]'
     )
     OR p_aggregate_kind='case' AND (
       char_length(p_description)>20000
        OR p_description<>btrim(p_description,edge_whitespace)
       OR regexp_replace(p_description,E'[\t\n\r]','','g') ~ '[[:cntrl:]]'
     )
     OR p_aggregate_kind='alert' AND p_summary IS NOT NULL
     OR p_aggregate_kind='case' AND (
       p_summary IS NULL OR char_length(p_summary)>2000
        OR p_summary<>btrim(p_summary,edge_whitespace)
       OR regexp_replace(p_summary,E'[\t\n\r]','','g') ~ '[[:cntrl:]]'
     )
     OR p_severity IS NULL OR p_severity NOT IN (
       'informational','low','medium','high','critical'
     )
     OR p_priority IS NULL
        OR p_priority NOT IN ('low','medium','high','urgent','critical')
     OR p_category IS NULL OR btrim(p_category,edge_whitespace)=''
     OR p_category<>btrim(p_category,edge_whitespace)
     OR char_length(p_category)>120 OR p_category ~ '[[:cntrl:]]'
     OR p_classification IS NOT NULL AND (
        btrim(p_classification,edge_whitespace)=''
        OR p_classification<>btrim(p_classification,edge_whitespace)
       OR char_length(p_classification)>120
       OR p_classification ~ '[[:cntrl:]]'
     )
     OR p_customer_visible IS NULL
     OR p_tags IS NULL OR cardinality(p_tags)>100
     OR EXISTS (
       SELECT 1 FROM unnest(p_tags) AS tag(value)
       WHERE tag.value IS NULL
          OR tag.value !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$'
     )
     OR p_tags IS DISTINCT FROM ARRAY(
       SELECT DISTINCT tag.value COLLATE "C"
       FROM unnest(p_tags) AS tag(value)
       ORDER BY tag.value COLLATE "C"
     )
     OR p_key_digest IS NULL OR octet_length(p_key_digest)<>32
     OR p_key_digest=decode(repeat('00',32),'hex')
     OR p_request_digest IS NULL OR octet_length(p_request_digest)<>32
     OR p_request_digest=decode(repeat('00',32),'hex')
     OR p_request_id IS NULL OR uuid_extract_version(p_request_id)<>7
     OR p_correlation_id IS NULL
        OR uuid_extract_version(p_correlation_id)<>7
     OR p_ip_address IS NULL
     OR p_user_agent IS NULL OR btrim(p_user_agent)=''
     OR char_length(p_user_agent)>1024 OR p_user_agent ~ '[[:cntrl:]]'
     OR p_authentication_method IS NULL
        OR p_authentication_method NOT IN (
       'bootstrap_totp','totp','recovery_code','ldap','oidc','saml','passkey'
     ) THEN
    RAISE EXCEPTION 'ticket metadata replacement input is invalid'
      USING ERRCODE='22023';
  END IF;

  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership:=app.current_tenant_membership_id();
  actor_user:=app.context_user_id();

  IF p_aggregate_kind='alert' THEN
    SELECT alert.version,alert.title,coalesce(alert.description,''),''::text,
           alert.severity::text,alert.priority,alert.category,
           alert.classification,alert.customer_visible,alert.tags,
           alert.assigned_team_id,alert.created_by,alert.assignee_user_id,
           alert.claimed_by_user_id
      INTO current_version,current_title,current_description,current_summary,
           current_severity,current_priority,current_category,
           current_classification,current_customer_visible,current_tags,
           current_assigned_team,current_owner_user,current_assignee_user,
           current_claimant_user
    FROM public.alerts AS alert
    WHERE alert.tenant_id=context_tenant AND alert.id=p_ticket_id
      AND alert.deleted_at IS NULL
    FOR UPDATE;
  ELSE
    SELECT case_record.version,case_record.title,case_record.description,
           case_record.summary,case_record.severity::text,
           case_record.priority,case_record.category,
           case_record.classification,case_record.customer_visible,
           case_record.tags,case_record.assigned_team_id,
           case_record.created_by_user_id,case_record.assignee_user_id,
           case_record.claimed_by_user_id
      INTO current_version,current_title,current_description,current_summary,
           current_severity,current_priority,current_category,
           current_classification,current_customer_visible,current_tags,
           current_assigned_team,current_owner_user,current_assignee_user,
           current_claimant_user
    FROM public.cases AS case_record
    WHERE case_record.tenant_id=context_tenant
      AND case_record.id=p_ticket_id
    FOR UPDATE;
  END IF;
  IF NOT FOUND OR NOT app.private_current_ticket_scope_allows_v1(
    permission_key,current_assigned_team,current_owner_user,
    current_assignee_user,current_claimant_user
  ) THEN
    RAISE EXCEPTION 'ticket metadata replacement is unauthorized'
      USING ERRCODE='42501';
  END IF;

  -- Resolve idempotency only after the ticket lock and live authorization.
  -- A concurrent identical writer can commit while this call is waiting;
  -- the post-lock statement snapshot must observe and replay that receipt.
  SELECT command.* INTO command_record
  FROM public.ticket_commands AS command
  WHERE command.tenant_id=context_tenant
    AND command.actor_membership_id=actor_membership
    AND command.operation=operation
    AND command.key_digest=p_key_digest;
  command_found:=FOUND;

  IF command_found THEN
    canonical_result:=jsonb_build_object(
      'schema_version',1,
      'tenant_id',context_tenant,
      'ticket_id',p_ticket_id,
      'aggregate_kind',p_aggregate_kind::text,
      'title',p_title,
      'description',p_description,
      'summary',canonical_summary,
      'severity',p_severity,
      'priority',p_priority,
      'category',p_category,
      'classification',p_classification,
      'customer_visible',p_customer_visible,
      'tags',to_jsonb(p_tags),
      'version',command_record.result_version,
      'updated_at',command_record.created_at
    );
    IF command_record.request_digest IS DISTINCT FROM p_request_digest
       OR command_record.actor_user_id IS DISTINCT FROM actor_user
       OR command_record.result_version IS DISTINCT FROM
          (p_expected_version+1)::integer
       OR p_aggregate_kind='alert' AND (
         command_record.result_alert_id IS DISTINCT FROM p_ticket_id
         OR command_record.result_case_id IS NOT NULL
       )
       OR p_aggregate_kind='case' AND (
         command_record.result_case_id IS DISTINCT FROM p_ticket_id
         OR command_record.result_alert_id IS NOT NULL
       )
       OR command_record.result_metadata IS DISTINCT FROM canonical_result THEN
      RAISE EXCEPTION 'ticket metadata idempotency key conflicts'
        USING ERRCODE='23505',CONSTRAINT='ticket_commands_replay_key';
    END IF;
    RETURN QUERY SELECT command_record.result_version::bigint,
      command_record.created_at,command_record.result_metadata,true;
    RETURN;
  END IF;

  IF current_version IS DISTINCT FROM p_expected_version::integer THEN
    RAISE EXCEPTION 'ticket metadata version conflict'
      USING ERRCODE='40001';
  END IF;

  SELECT ARRAY(
    SELECT changed.name
    FROM (VALUES
      (1,'title',current_title IS DISTINCT FROM p_title),
      (2,'description',current_description IS DISTINCT FROM p_description),
      (3,'summary',p_aggregate_kind='case'
        AND current_summary IS DISTINCT FROM canonical_summary),
      (4,'severity',current_severity IS DISTINCT FROM p_severity),
      (5,'priority',current_priority IS DISTINCT FROM p_priority),
      (6,'category',current_category IS DISTINCT FROM p_category),
      (7,'classification',current_classification IS DISTINCT FROM
        p_classification),
      (8,'customer_visible',current_customer_visible IS DISTINCT FROM
        p_customer_visible),
      (9,'tags',current_tags IS DISTINCT FROM p_tags)
    ) AS changed(ordinal,name,is_changed)
    WHERE changed.is_changed
    ORDER BY changed.ordinal
  ) INTO changed_fields;
  IF cardinality(changed_fields)=0 THEN
    RAISE EXCEPTION 'ticket metadata replacement is a no-op'
      USING ERRCODE='23514';
  END IF;

  IF p_aggregate_kind='alert' THEN
    UPDATE public.alerts AS alert
    SET title=p_title,
        description=p_description,
        severity=p_severity::public.alert_severity,
        priority=p_priority,
        category=p_category,
        classification=p_classification,
        customer_visible=p_customer_visible,
        tags=p_tags,
        updated_at=operation_at,
        version=alert.version+1
    WHERE alert.tenant_id=context_tenant AND alert.id=p_ticket_id
      AND alert.deleted_at IS NULL AND alert.version=p_expected_version
      AND alert.version<2147483647
    RETURNING alert.version,alert.updated_at
      INTO committed_version,committed_updated_at;
  ELSE
    UPDATE public.cases AS case_record
    SET title=p_title,
        description=p_description,
        summary=canonical_summary,
        severity=p_severity::public.alert_severity,
        priority=p_priority,
        category=p_category,
        classification=p_classification,
        customer_visible=p_customer_visible,
        tags=p_tags,
        updated_at=operation_at,
        version=case_record.version+1
    WHERE case_record.tenant_id=context_tenant
      AND case_record.id=p_ticket_id
      AND case_record.version=p_expected_version
      AND case_record.version<2147483647
    RETURNING case_record.version,case_record.updated_at
      INTO committed_version,committed_updated_at;
  END IF;
  IF committed_version IS NULL THEN
    RAISE EXCEPTION 'ticket metadata version conflict'
      USING ERRCODE='40001';
  END IF;

  canonical_result:=jsonb_build_object(
    'schema_version',1,
    'tenant_id',context_tenant,
    'ticket_id',p_ticket_id,
    'aggregate_kind',p_aggregate_kind::text,
    'title',p_title,
    'description',p_description,
    'summary',canonical_summary,
    'severity',p_severity,
    'priority',p_priority,
    'category',p_category,
    'classification',p_classification,
    'customer_visible',p_customer_visible,
    'tags',to_jsonb(p_tags),
    'version',committed_version,
    'updated_at',committed_updated_at
  );

  INSERT INTO public.ticket_commands(
    id,tenant_id,operation,actor_membership_id,actor_user_id,
    key_digest,request_digest,result_alert_id,result_case_id,
    result_version,result_metadata,created_at
  ) VALUES (
    uuidv7(),context_tenant,operation,actor_membership,actor_user,
    p_key_digest,p_request_digest,
    CASE WHEN p_aggregate_kind='alert' THEN p_ticket_id END,
    CASE WHEN p_aggregate_kind='case' THEN p_ticket_id END,
    committed_version,canonical_result,committed_updated_at
  );

  PERFORM app.private_append_ticket_side_effects_v1(
    p_aggregate_kind,p_ticket_id,'metadata_updated',committed_version,
    ARRAY['activity','audit']::text[],p_request_id,p_correlation_id,
    p_ip_address,p_user_agent,p_authentication_method,
    jsonb_build_object(
      'version',current_version,'content_redacted',true
    ),
    jsonb_build_object(
      'version',committed_version,'content_redacted',true
    ),
    jsonb_build_object('changed_fields',to_jsonb(changed_fields))
  );

  RETURN QUERY SELECT committed_version::bigint,committed_updated_at,
    canonical_result,false;
END;
$function$;
ALTER FUNCTION app.replace_tenant_ticket_metadata_v1(
  public.ticket_aggregate_kind,uuid,bigint,text,text,text,text,text,text,text,
  boolean,text[],bytea,bytea,uuid,uuid,inet,text,text
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.replace_tenant_ticket_metadata_v1(
  public.ticket_aggregate_kind,uuid,bigint,text,text,text,text,text,text,text,
  boolean,text[],bytea,bytea,uuid,uuid,inet,text,text
) FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
       periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.replace_tenant_ticket_metadata_v1(
  public.ticket_aggregate_kind,uuid,bigint,text,text,text,text,text,text,text,
  boolean,text[],bytea,bytea,uuid,uuid,inet,text,text
) TO periapsis_api;
$v46_forward_metadata$;
  END IF;

  WITH expected(identity,source_hash) AS (
    VALUES
      ('app.apply_tenant_ticket_mutation_v1(public.ticket_aggregate_kind,uuid,text,integer,integer,uuid,integer,text,text,text,boolean,uuid,uuid,uuid,text,text,text,jsonb,bytea,bytea,uuid,uuid,inet,text,text)','5e14daab242f4d66ac6193cfce0e7ff1653eb8d0bed956ebba730403ff100e15')
      ,('app.apply_ticket_bulk_target_v1(jsonb)','2b0ce5ef907aed6ee53fe8bf3f23a8fae939304185752d80a526b22ccac487f6')
      ,('app.execute_sla_trigger_action_v1(uuid,uuid,uuid,bigint,bytea,public.sla_trigger_action_kind,timestamp with time zone)','a40dc874f364e73b9602bdae04a3c2ee714839b8b1cadfc873fa8ad03e61fd3c')
      ,('app.private_append_sla_action_audit_v1(uuid,uuid,text,timestamp with time zone,jsonb)','f9e4e780e13e39d191e7f5068c6e3b8272d7df2f1c4e57c4dec5fb1813f2bbbb')
      ,('app.private_append_ticket_bulk_mutation_effects_v1(public.ticket_aggregate_kind,uuid,text,integer,text[],uuid,uuid,inet,text,text,jsonb,jsonb,jsonb)','e1a56ad722b603d2a0c6c67b2350bf99069f1fa60267f6a1c17132c32e1d9f1a')
      ,('app.private_apply_ticket_bulk_mutation_v1(public.ticket_aggregate_kind,uuid,text,integer,integer,uuid,integer,text,text,text,boolean,uuid,uuid,uuid,text,text,text,jsonb,bytea,bytea,uuid,uuid,inet,text,text)','5fef80c1851843719bdfbe83f61feed2eebf5e31156ec3a929d70420f60b9fb2')
      ,('app.private_ticket_export_requester_live_v1(public.ticket_export_jobs)','d36935995ea90ca8150dde407eae130096b1aa30a5ab89fd6364cbaea4877f41')
      ,('app.private_ticket_runtime_append_human_effects_v1(uuid,jsonb,jsonb,text,text,uuid,bigint,timestamp with time zone,jsonb)','c171f2fc279b6e6deae34a258d58ac45e1f63421f8c6e896987a870d8a2e0695')
      ,('app.private_ticket_runtime_append_system_effects_v1(uuid,text,text,uuid,bigint,timestamp with time zone,text,jsonb)','43dbd715c96c3ce908a980bb96c1840ce69edd5c2cffa11e1287b43c565eb941')
      ,('app.private_ticket_runtime_catalog_digest_v1(text)','ca5fcd0dd6313ae9c087fd9374a21912fc4b39039e6b196076bc278f2411db23')
      ,('app.private_ticket_watcher_display_name_valid_v1(text)','b69b7003f5bd8c1df0677280cada79eba38c7c061e1024ae3711f1d6d39b83b7')
      ,('app.private_v45_sla_action_repairs_ready()','16a8f24a57c37700e9f104d47a467cafb4e0ae54f9b1c76e0e305b4c644cfe00')
      ,('app.private_v45_ticket_runtime_repairs_ready(text)','ad0ed7a40341483fd04a45efddb83d4f2523ba295dc80d8abaf90da4d38c304a')
      ,('app.replace_tenant_ticket_metadata_v1(public.ticket_aggregate_kind,uuid,bigint,text,text,text,text,text,text,text,boolean,text[],bytea,bytea,uuid,uuid,inet,text,text)','dd84a141e54a23d097fbb6a35f2dc9e8321262ac9decc5fb78ad927975374e33')
      ,('app.sla_trigger_action_runtime_schema_readiness_v1()','de66e722783bb54c663e5fbfce40a99374cf5cedafbe936ee61af0dc7e21d72f')
      ,('app.ticket_bulk_runtime_schema_readiness_v1()','720ac628734386423164c9fe9b57b29d73b5d0c8604d99123a46c8b731ff0cab')
      ,('app.ticket_export_runtime_schema_readiness_v1()','c1d7f730e15a54271d2a3ec324ab55557ff1d4bd8e6922392cee1648f334281d')
  ), actual AS (
    SELECT expected.identity,expected.source_hash,
      pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
        function_row.prosrc,'UTF8')),'hex') AS actual_hash
    FROM expected
    LEFT JOIN pg_catalog.pg_proc AS function_row
      ON function_row.oid=pg_catalog.to_regprocedure(expected.identity)
  )
  SELECT count(*)=17
         AND coalesce(bool_and(actual_hash=source_hash),false)
    INTO canonical_ready FROM actual;

  IF NOT canonical_ready
     OR NOT app.sla_trigger_action_runtime_schema_readiness_v1()
     OR NOT app.ticket_bulk_runtime_schema_readiness_v1()
     OR NOT app.ticket_export_runtime_schema_readiness_v1()
     OR NOT app.private_v45_ticket_runtime_repairs_ready('bulk')
     OR NOT app.private_v45_ticket_runtime_repairs_ready('export')
     OR EXISTS (
       SELECT 1
       FROM (VALUES
         ('app.private_append_ticket_bulk_mutation_effects_v1(public.ticket_aggregate_kind,uuid,text,integer,text[],uuid,uuid,inet,text,text,jsonb,jsonb,jsonb)','periapsis_migrator'),
         ('app.private_apply_ticket_bulk_mutation_v1(public.ticket_aggregate_kind,uuid,text,integer,integer,uuid,integer,text,text,text,boolean,uuid,uuid,uuid,text,text,text,jsonb,bytea,bytea,uuid,uuid,inet,text,text)','periapsis_migrator'),
         ('app.private_v45_sla_action_repairs_ready()','periapsis_sla_readiness_owner'),
         ('app.private_v45_ticket_runtime_repairs_ready(text)','periapsis_migrator')
       ) AS expected(identity,owner_name)
       JOIN pg_catalog.pg_proc AS function_row
         ON function_row.oid=pg_catalog.to_regprocedure(expected.identity)
       JOIN pg_catalog.pg_roles AS owner ON owner.oid=function_row.proowner
       WHERE owner.rolname<>expected.owner_name
          OR (
            SELECT count(*)<>1 OR NOT coalesce(bool_and(
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
     ) THEN
    RAISE EXCEPTION 'V45 forward repair did not converge to the canonical catalog'
      USING ERRCODE='55000';
  END IF;

  SELECT count(*)::bigint,max(migration.created_at)::bigint,
         string_agg(
           migration.created_at::text || '@' || lower(migration.hash::text),
           ':' ORDER BY migration.created_at,migration.id
         ),
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
    INTO v45_count,v45_latest,v_raw_v45_fingerprint,
         v_normalized_v45_fingerprint
  FROM drizzle.__drizzle_migrations AS migration
  WHERE migration.created_at<=1788128702258;
  SELECT lower(migration.hash::text) INTO STRICT v_metadata_original_hash
  FROM drizzle.__drizzle_migrations AS migration
  WHERE migration.created_at=1788128074116;
  SELECT lower(migration.hash::text) INTO STRICT v_compatibility_original_hash
  FROM drizzle.__drizzle_migrations AS migration
  WHERE migration.created_at=1788128702258;
  v_source_variant:=CASE
    WHEN ROW(v_metadata_original_hash,v_compatibility_original_hash)
      IS NOT DISTINCT FROM ROW(
        '0edecb4d9945aeccc4d5b7c9db7dbb25c5f07c7df933ee4e208d3e4e34397d9e',
        '0d47a74b3ecb3064766ae3a920e420f56e3cfc7e0bf95578df7fe353c2b3d72c'
      ) THEN 'legacy-v45'
    WHEN ROW(v_metadata_original_hash,v_compatibility_original_hash)
      IS NOT DISTINCT FROM ROW(
        '6112ec54973db26390fa6020a050db71a6c5d28b1c45132bca10b32372109fa4',
        'fffd40eb9eb5800fbe63f9e62fa85f960190e2a149e2313ccb66a1d6c78293ea'
      ) THEN 'canonical-v45'
    ELSE NULL
  END;
  v_canonical_catalog_digest:=
    '1b1310c2a1350590629ebfb71eb58d837900d376a3bdf8c7ccbff3e9aad3d2a3';
  IF v45_count<>199 OR v45_latest<>1788128702258
     OR v_source_variant IS NULL THEN
    RAISE EXCEPTION 'V45 journal is not the exact source catalog predecessor'
      USING ERRCODE='55000';
  END IF;

  INSERT INTO drizzle.__periapsis_migration_convergence_attestations (
    attestation_id,convergence_version,source_variant,
    metadata_original_hash,compatibility_original_hash,
    raw_v45_fingerprint,normalized_v45_fingerprint,
    canonical_catalog_digest,attested_at
  ) VALUES (
    uuidv7(),46,v_source_variant,v_metadata_original_hash,
    v_compatibility_original_hash,v_raw_v45_fingerprint,
    v_normalized_v45_fingerprint,v_canonical_catalog_digest,
    transaction_timestamp()
  ) ON CONFLICT (convergence_version) DO NOTHING;
  IF NOT EXISTS (
    SELECT 1
    FROM drizzle.__periapsis_migration_convergence_attestations AS attestation
    WHERE attestation.convergence_version=46
      AND attestation.source_variant=v_source_variant
      AND attestation.metadata_original_hash=v_metadata_original_hash
      AND attestation.compatibility_original_hash=v_compatibility_original_hash
      AND attestation.raw_v45_fingerprint=v_raw_v45_fingerprint
      AND attestation.normalized_v45_fingerprint=v_normalized_v45_fingerprint
      AND attestation.canonical_catalog_digest=v_canonical_catalog_digest
  ) THEN
    RAISE EXCEPTION 'V45 convergence attestation conflicts with prior evidence'
      USING ERRCODE='55000';
  END IF;

END;
$v46_forward_repair$;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.private_v46_migration_convergence_schema_readiness_v1()
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
         AND namespace.nspname='drizzle'
          AND relation_row.relkind='r'
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
     OR NOT EXISTS (
       SELECT 1
       FROM pg_catalog.pg_trigger AS trigger_row
       WHERE trigger_row.tgrelid=
         'drizzle.__periapsis_migration_convergence_attestations'::regclass
         AND trigger_row.tgname='migration_convergence_immutable'
         AND trigger_row.tgfoid=
           'app.guard_migration_convergence_attestation_v1()'::regprocedure
          AND trigger_row.tgtype=27
         AND trigger_row.tgenabled='O'
          AND NOT trigger_row.tgisinternal
      )
     OR NOT EXISTS (
       SELECT 1
       FROM pg_catalog.pg_trigger AS trigger_row
       WHERE trigger_row.tgrelid=
         'drizzle.__periapsis_migration_convergence_attestations'::regclass
         AND trigger_row.tgname='migration_convergence_truncate_immutable'
         AND trigger_row.tgfoid=
           'app.guard_migration_convergence_attestation_v1()'::regprocedure
         AND trigger_row.tgtype=34
         AND trigger_row.tgenabled='O'
         AND NOT trigger_row.tgisinternal
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

  IF NOT EXISTS (
       SELECT 1
       FROM pg_catalog.pg_proc AS function_row
       JOIN pg_catalog.pg_roles AS owner ON owner.oid=function_row.proowner
       JOIN pg_catalog.pg_language AS language
         ON language.oid=function_row.prolang
       WHERE function_row.oid=
         'app.private_ticket_watcher_display_name_valid_v1(text)'::regprocedure
         AND owner.rolname='periapsis_migrator'
         AND language.lanname='sql'
         AND function_row.prokind='f' AND function_row.provolatile='i'
         AND NOT function_row.prosecdef AND function_row.proisstrict
         AND NOT function_row.proleakproof AND function_row.proparallel='s'
         AND function_row.pronargs=1 AND function_row.pronargdefaults=0
         AND function_row.proconfig IS NOT DISTINCT FROM
           ARRAY['search_path=pg_catalog']::text[]
         AND pg_catalog.pg_get_function_result(function_row.oid)='boolean'
         AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8'
         )),'hex')='b69b7003f5bd8c1df0677280cada79eba38c7c061e1024ae3711f1d6d39b83b7'
         AND (
           SELECT count(*)=2 AND coalesce(bool_and(
             privilege.grantor=function_row.proowner
             AND privilege.grantee IN (
               function_row.proowner,
               (SELECT role.oid FROM pg_catalog.pg_roles AS role
                WHERE role.rolname='periapsis_ticket_runtime_owner')
             )
             AND privilege.privilege_type='EXECUTE'
             AND NOT privilege.is_grantable
           ),false)
           FROM pg_catalog.aclexplode(coalesce(
             function_row.proacl,
             pg_catalog.acldefault('f',function_row.proowner)
           )) AS privilege
         )
     )
     OR NOT EXISTS (
       SELECT 1
       FROM pg_catalog.pg_constraint AS constraint_row
       WHERE constraint_row.conrelid=
         'public.ticket_watcher_events'::regclass
         AND constraint_row.conname=
           'ticket_watcher_events_display_name_check'
         AND constraint_row.contype='c'
         AND constraint_row.convalidated
         AND NOT constraint_row.condeferrable
         AND NOT constraint_row.condeferred
         AND constraint_row.coninhcount=0
         AND pg_catalog.pg_get_expr(
           constraint_row.conbin,constraint_row.conrelid,false
         )=
           'private_ticket_watcher_display_name_valid_v1(display_name_snapshot)'
     ) THEN
    RETURN false;
  END IF;

  IF EXISTS (
    WITH expected(identity,source_hash) AS (
    VALUES
      ('app.apply_tenant_ticket_mutation_v1(public.ticket_aggregate_kind,uuid,text,integer,integer,uuid,integer,text,text,text,boolean,uuid,uuid,uuid,text,text,text,jsonb,bytea,bytea,uuid,uuid,inet,text,text)','5e14daab242f4d66ac6193cfce0e7ff1653eb8d0bed956ebba730403ff100e15'),
      ('app.apply_ticket_bulk_target_v1(jsonb)','2b0ce5ef907aed6ee53fe8bf3f23a8fae939304185752d80a526b22ccac487f6'),
      ('app.execute_sla_trigger_action_v1(uuid,uuid,uuid,bigint,bytea,public.sla_trigger_action_kind,timestamp with time zone)','a40dc874f364e73b9602bdae04a3c2ee714839b8b1cadfc873fa8ad03e61fd3c'),
      ('app.private_append_sla_action_audit_v1(uuid,uuid,text,timestamp with time zone,jsonb)','f9e4e780e13e39d191e7f5068c6e3b8272d7df2f1c4e57c4dec5fb1813f2bbbb'),
      ('app.private_append_ticket_bulk_mutation_effects_v1(public.ticket_aggregate_kind,uuid,text,integer,text[],uuid,uuid,inet,text,text,jsonb,jsonb,jsonb)','e1a56ad722b603d2a0c6c67b2350bf99069f1fa60267f6a1c17132c32e1d9f1a'),
      ('app.private_apply_ticket_bulk_mutation_v1(public.ticket_aggregate_kind,uuid,text,integer,integer,uuid,integer,text,text,text,boolean,uuid,uuid,uuid,text,text,text,jsonb,bytea,bytea,uuid,uuid,inet,text,text)','5fef80c1851843719bdfbe83f61feed2eebf5e31156ec3a929d70420f60b9fb2'),
      ('app.private_ticket_export_requester_live_v1(public.ticket_export_jobs)','d36935995ea90ca8150dde407eae130096b1aa30a5ab89fd6364cbaea4877f41'),
      ('app.private_ticket_runtime_append_human_effects_v1(uuid,jsonb,jsonb,text,text,uuid,bigint,timestamp with time zone,jsonb)','c171f2fc279b6e6deae34a258d58ac45e1f63421f8c6e896987a870d8a2e0695'),
      ('app.private_ticket_runtime_append_system_effects_v1(uuid,text,text,uuid,bigint,timestamp with time zone,text,jsonb)','43dbd715c96c3ce908a980bb96c1840ce69edd5c2cffa11e1287b43c565eb941'),
      ('app.private_ticket_runtime_catalog_digest_v1(text)','ca5fcd0dd6313ae9c087fd9374a21912fc4b39039e6b196076bc278f2411db23'),
      ('app.private_v45_sla_action_repairs_ready()','16a8f24a57c37700e9f104d47a467cafb4e0ae54f9b1c76e0e305b4c644cfe00'),
      ('app.private_v45_ticket_runtime_repairs_ready(text)','ad0ed7a40341483fd04a45efddb83d4f2523ba295dc80d8abaf90da4d38c304a'),
      ('app.replace_tenant_ticket_metadata_v1(public.ticket_aggregate_kind,uuid,bigint,text,text,text,text,text,text,text,boolean,text[],bytea,bytea,uuid,uuid,inet,text,text)','dd84a141e54a23d097fbb6a35f2dc9e8321262ac9decc5fb78ad927975374e33'),
      ('app.sla_trigger_action_runtime_schema_readiness_v1()','de66e722783bb54c663e5fbfce40a99374cf5cedafbe936ee61af0dc7e21d72f'),
      ('app.ticket_bulk_runtime_schema_readiness_v1()','720ac628734386423164c9fe9b57b29d73b5d0c8604d99123a46c8b731ff0cab'),
      ('app.ticket_export_runtime_schema_readiness_v1()','c1d7f730e15a54271d2a3ec324ab55557ff1d4bd8e6922392cee1648f334281d')
    )
    SELECT 1
    FROM expected
    LEFT JOIN pg_catalog.pg_proc AS function_row
      ON function_row.oid=pg_catalog.to_regprocedure(expected.identity)
    WHERE function_row.oid IS NULL
       OR pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
            function_row.prosrc,'UTF8'
          )),'hex')<>expected.source_hash
  ) THEN
    RETURN false;
  END IF;

  IF EXISTS (
    SELECT 1
    FROM (VALUES
      ('app.private_mfa_policy_administration_schema_readiness_v5()',
       ARRAY['ad1c5aa88277c11782e7ad20abf4509e5343ec8f62c47c12062176fa797d1032','5348f7c36837a65fa5a41443177acd6820d41f0a1fa5b8b473c1024b070383de']::text[],
       'd74624090df589f4d2d65414f5dd8b65b88b873ef06120a74f3c53076444024e'),
      ('app.private_platform_identity_runtime_schema_readiness_v11()',
       ARRAY['81395c7f999f2ab28be82fcc2854e536f8548285ab741661889fb41be09d5f7b','e6b1ab3503731aa6b664f075fcbb3f74431d9d600ca01254a408b232f17a5171']::text[],
       '097a9a1845d40f2b107a2aa274af3ee4e9139cfafe43c9aecdc26d91ea0c8156'),
      ('app.private_platform_oidc_direct_runtime_schema_readiness_v7()',
       ARRAY['588689bdf29011aba884ba70bcf330f09951895b7680c5181196648c4537f2ce','7c0d03aa7dd74f8c72ad867023e324ef49fccbe28b77a6c8d10eb4c8069ecbf0']::text[],
       '2cfbb916bb418bdb5ae78f8db51e996a61e5025c8eba0e8b8991397e5e6d2b4c'),
      ('app.private_platform_saml_direct_runtime_schema_readiness_v4()',
       ARRAY['bbc299650d5f4bc8e3616d4e19a64af11494a2f9156c79a3b37a3b702f3cf03c','541eb8770ec4b1981f8b114c034077a89a617afb792c9912afaa1ed3d4ada471']::text[],
       '7be522d05c97d26db08150c95eec97c7b1a2ee661a992ae1f40a7b3565115b85')
    ) AS expected(identity,source_hashes,normalized_hash)
    JOIN pg_catalog.pg_proc AS function_row
      ON function_row.oid=pg_catalog.to_regprocedure(expected.identity)
    WHERE NOT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
            function_row.prosrc,'UTF8'
          )),'hex')=ANY(expected.source_hashes)
       OR pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
            pg_catalog.replace(pg_catalog.replace(
              function_row.prosrc,
              '3e0cf8fc6faa5eac5f542c3b3cb739d80303d563cdec289b8bf8309d9ec278b6',
              '<DEPENDENCY_RESULT>'
            ),
              'ac33cd232816dc2108e3af8aef01f938dfef2f5650b9426829cf14cef9d5c3bb',
              '<DEPENDENCY_RESULT>'
            ),'UTF8'
          )),'hex')<>expected.normalized_hash
  ) THEN
    RETURN false;
  END IF;

  SELECT count(*)::bigint,max(migration.created_at)::bigint,
    string_agg(
      migration.created_at::text || '@' || lower(migration.hash::text),
      ':' ORDER BY migration.created_at,migration.id
    ),
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
    INTO v45_count,v45_latest,v_raw_fingerprint,v_normalized_fingerprint
  FROM drizzle.__drizzle_migrations AS migration
  WHERE migration.created_at<=1788128702258;
  SELECT lower(migration.hash::text) INTO STRICT v_metadata_hash
  FROM drizzle.__drizzle_migrations AS migration
  WHERE migration.created_at=1788128074116;
  SELECT lower(migration.hash::text) INTO STRICT v_compatibility_hash
  FROM drizzle.__drizzle_migrations AS migration
  WHERE migration.created_at=1788128702258;
  RETURN v45_count=199 AND v45_latest=1788128702258
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
        AND uuid_extract_version(attestation.attestation_id)=7
        AND attestation.attested_at IS NOT NULL
    );
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;
ALTER FUNCTION app.private_v46_migration_convergence_schema_readiness_v1()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_v46_migration_convergence_schema_readiness_v1()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
       periapsis_auditor;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.private_schema_compatibility_journal_v46()
RETURNS TABLE(
  applied_count bigint,latest_created_at bigint,latest_rows bigint,
  latest_hash text,migration_fingerprint text
)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
BEGIN
  IF NOT app.private_v46_migration_convergence_schema_readiness_v1() THEN
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
ALTER FUNCTION app.private_schema_compatibility_journal_v46()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_schema_compatibility_journal_v46()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
       periapsis_auditor;
--> statement-breakpoint

DO $verify_v46_forward_repair$
BEGIN
  IF NOT app.private_v46_migration_convergence_schema_readiness_v1() THEN
    RAISE EXCEPTION 'V46 forward-repair attestation is not ready'
      USING ERRCODE='55000';
  END IF;
END;
$verify_v46_forward_repair$;
--> statement-breakpoint
