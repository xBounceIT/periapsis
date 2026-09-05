-- Seal the compatibility and security boundary before publishing the v6
-- journal projection. SHA-256 source hashes cover normalized function bodies
-- so line-ending or formatting-only differences cannot weaken the
-- exact implementation contract.
DO $service_principal_readiness_assertions$
DECLARE
  expected record;
  function_oid oid;
  actual_source_hash text;
  actual_volatility "char";
  actual_security_definer boolean;
  actual_owner text;
  actual_configuration text[];
  public_can_execute boolean;
  api_can_execute boolean;
  worker_can_execute boolean;
  notifier_can_execute boolean;
  auditor_can_execute boolean;
  actual_all_argument_types oid[];
  actual_argument_modes "char"[];
  actual_argument_names text[];
  relation_name text;
  relation_oid oid;
  relation_has_rls boolean;
  relation_forces_rls boolean;
  relation_owner text;
  runtime_role text;
  table_privilege text;
  actual_public_surface text[];
BEGIN
  FOR expected IN
    SELECT *
    FROM (VALUES
      (
        'app.tenant_user_has_exact_permission(uuid,uuid,text,public.authorization_scope)',
        'b0f5e7e5e04629017c1f3f62878ac40e8de7b6594510df6db6a4ef54cf71d5e3', 's'::"char", true,
        false, false, false, false
      ),
      (
        'app.tenant_user_can_delegate_exact_permission(uuid,uuid,text,public.authorization_scope,timestamp with time zone)',
        'c97e63da4b8ead8e6c85988e84a771bc4ad7cc1104aa2012293c5f3d7d449019', 's'::"char", true,
        false, false, false, false
      ),
      (
        'app.resolve_current_tenant_human_authority_v2(integer)',
        'a8b2520c11105da040b2819a3c587afb6905dcab1c7d5e04c349f26b092ba7c7', 's'::"char", true,
        true, false, false, false
      ),
      (
        'app.list_tenant_permission_catalog_v2(uuid,integer)',
        '7312ae1e37d7c3cdec4c1be706d2e63c45bb0d5bd630c3399ed8d32ab2242713', 's'::"char", true,
        true, false, false, false
      ),
      (
        'app.get_tenant_role_policy_v2(uuid,integer)',
        'dea44eee34aaebe0da37be5849d197cfacaea00372c1acc425aa6b580c9294c6', 's'::"char", true,
        true, false, false, false
      ),
      (
        'app.resolve_current_tenant_human_authority_v3(integer)',
        '43c161aaf168473fe7575af53e6729e1335d946bc28964e64a1d2029143857c3', 's'::"char", true,
        true, false, false, false
      ),
      (
        'app.list_tenant_permission_catalog_v3(uuid,integer)',
        'a868e17a86444dd22168c7ac735f136acecdc15deadd2129d43c7210d5c46563', 's'::"char", true,
        true, false, false, false
      ),
      (
        'app.list_tenant_roles_v3(uuid,boolean,integer)',
        '7bfde8a21ccf3da260cce777a3dbb6860404e2f31be0d9b25ca139c4d75b5be1', 's'::"char", true,
        true, false, false, false
      ),
      (
        'app.get_tenant_role_v3(uuid)',
        'fae83de528b525709d7a716dbc350f98e608df02232e7afcebc424d297b657b6', 's'::"char", true,
        true, false, false, false
      ),
      (
        'app.get_tenant_role_policy_v3(uuid)',
        '7aaedcf69918db5299a898e74c98f3ad59936704c2826369b2b0f6144f785849', 's'::"char", true,
        true, false, false, false
      ),
      (
        'app.assert_legacy_human_role_projection(uuid,text[],text[])',
        '90e0364561c52bb50fb5e6962fd871161f613aee4f5614b0ac13c5cc5e909180', 's'::"char", true,
        false, false, false, false
      ),
      (
        'app.create_tenant_role(uuid,bytea,text,text,text,text[],public.authorization_scope[],text[],public.authorization_scope[],uuid,uuid,uuid,inet,text,text)',
        '74b42feb948c0b75cc528ac6ff849884c4c5087b0513256f9bebbe6a261054b9', 'v'::"char", true,
        true, false, false, false
      ),
      (
        'app.replace_tenant_role_policy_v2(uuid,integer,text[],public.authorization_scope[],text[],public.authorization_scope[],uuid,uuid,uuid,inet,text,text)',
        '85b9af48003e83f86056b84f5b1d3ad31f9c2611ec853983faa45833afcdcb9f', 'v'::"char", true,
        true, false, false, false
      ),
      (
        'app.grant_tenant_user_role(uuid,bytea,uuid,uuid,text,timestamp with time zone,uuid,uuid,uuid,inet,text,text)',
        '11806557ef6e90cbd34af9c9f5fa958ed99a5c6b584652bff05d5e6a33ab2805', 'v'::"char", true,
        true, false, false, false
      ),
      (
        'app.grant_tenant_security_group_role(uuid,bytea,uuid,uuid,text,timestamp with time zone,uuid,uuid,uuid,inet,text,text)',
        'd3b5634d69459fae972e1d68ca9e745c66cede5acead3d959fbce5f475ca9e66', 'v'::"char", true,
        true, false, false, false
      ),
      (
        'app.guard_service_principal_append_only_v1()',
        '87c84bd1f564f41973c5a0b2c1b0863c201c3c96a8d06698c743ed7efdf63e5f', 'v'::"char", true,
        false, false, false, false
      ),
      (
        'app.tenant_human_has_exact_permission_v3(uuid,uuid,text,public.authorization_scope)',
        '886c91a5246fb64f75343930a592e3c0b68265b53e5ea6804268ed6dd83b728c', 's'::"char", true,
        false, false, false, false
      ),
      (
        'app.tenant_human_can_delegate_exact_permission_v3(uuid,uuid,text,public.authorization_scope,timestamp with time zone)',
        '392bc1779eaa17d90631df549882757b35acbbd27b133d14143161939beec36d', 's'::"char", true,
        false, false, false, false
      ),
      (
        'app.current_tenant_human_has_exact_permission_v3(text,public.authorization_scope)',
        'c0e0e79bc6121de381bae7e5bc435e8d0c20a246466aae8ef787f1ad916d85ef', 's'::"char", true,
        false, false, false, false
      ),
      (
        'app.assert_actor_can_change_service_account_role_grant_v1(uuid,timestamp with time zone)',
        '489d7a52fdb8bbe551ee6e58862326367f6fd266d3f85933ca918f6b8b894951', 's'::"char", true,
        false, false, false, false
      ),
      (
        'app.assert_tenant_api_credential_request_shape_v1(text[],public.authorization_scope[],cidr[])',
        '8ec73a63c433e851ad489601cdd483c776f7f0f9d78970e6bbe9c78ea7650518', 's'::"char", true,
        false, false, false, false
      ),
      (
        'app.assert_tenant_api_credential_policy_v1(uuid,uuid,text[],public.authorization_scope[],cidr[])',
        '131abc3c8dad94e3d1b1a436ad8a3fb9be57dc216947d59b6fe3888911a1177e', 's'::"char", true,
        false, false, false, false
      ),
      (
        'app.private_resolve_tenant_api_credential_locator_v1(uuid,bytea)',
        'd490b6198ab7987296908cb8f26b79953d813a50e464511ad80c6760b9a8cc95', 's'::"char", true,
        false, false, false, false
      ),
      (
        'app.authenticate_tenant_api_credential_v1(uuid,bytea,integer,bytea,inet,text,public.authorization_scope)',
        '7f6a56aee6417470c8a31d3e9e0cbb9552a0fcb13682de3626c6ec69cf4b7b3e', 'v'::"char", true,
        false, false, false, false
      ),
      (
        'app.append_tenant_service_account_audit_v1(uuid,uuid,uuid,text,text,uuid,uuid,uuid,inet,text,jsonb,jsonb,jsonb)',
        '23f5e8a4e8afc02768aab37a9a9aa5de1130fca8bfa47ac848031a83ee27dc4b', 'v'::"char", true,
        false, false, false, false
      ),
      (
        'app.resolve_tenant_service_account_authority_v1(uuid,integer)',
        '4753647e807e6690907e0f757ef4feadd190fb5a0a588680c28e23fb03c5cbda', 's'::"char", true,
        true, false, false, false
      ),
      (
        'app.list_live_api_credential_key_versions_v1(integer)',
        'fd7cd2919efa7404d5df5152c66e4146b7a114c633cb5189226e6e0277673b1b', 's'::"char", true,
        true, true, false, false
      ),
      (
        'app.create_tenant_alert_as_human_v1(text,text,text,public.alert_severity,bytea,bytea,uuid,uuid,inet,text,text)',
        '96d4819b1732097c09f5dc9cce0a30b44b304af07d5ce5583d27715fda2103f0', 'v'::"char", true,
        true, false, false, false
      ),
      (
        'app.create_tenant_alert_as_service_account_v1(uuid,bytea,integer,bytea,inet,text,text,text,public.alert_severity,bytea,bytea,uuid,uuid,text)',
        'd7915d07a33800c66aa10ed93ff5f6fc003d6a0b33bc9134d23f4570b259d507', 'v'::"char", true,
        true, false, false, false
      ),
      (
        'app.audit_event_payload(public.audit_events)',
        'b539596ea7e991967aacb996f3ed22116f21451dc9b74717bdcfe14745f7cd80', 's'::"char", false,
        true, false, false, true
      )
    ) AS manifest(
      signature, source_hash, volatility, security_definer,
      api_execute, worker_execute, notifier_execute, auditor_execute
    )
  LOOP
    function_oid := pg_catalog.to_regprocedure(expected.signature);
    IF function_oid IS NULL THEN
      RAISE EXCEPTION 'readiness ABI function % is missing', expected.signature
        USING ERRCODE = '55000';
    END IF;

    SELECT
      pg_catalog.encode(
        pg_catalog.sha256(
          pg_catalog.convert_to(
            pg_catalog.btrim(
              pg_catalog.regexp_replace(
                procedure.prosrc,
                '[[:space:]]+',
                ' ',
                'g'
              )
            ),
            'UTF8'
          )
        ),
        'hex'
      ),
      procedure.provolatile,
      procedure.prosecdef,
      pg_catalog.pg_get_userbyid(procedure.proowner),
      procedure.proconfig,
      EXISTS (
        SELECT 1
        FROM pg_catalog.aclexplode(
          coalesce(
            procedure.proacl,
            pg_catalog.acldefault('f', procedure.proowner)
          )
        ) AS privilege
        WHERE privilege.grantee = 0
          AND privilege.privilege_type = 'EXECUTE'
      ),
      pg_catalog.has_function_privilege(
        'periapsis_api', procedure.oid, 'EXECUTE'
      ),
      pg_catalog.has_function_privilege(
        'periapsis_worker', procedure.oid, 'EXECUTE'
      ),
      pg_catalog.has_function_privilege(
        'periapsis_notifier', procedure.oid, 'EXECUTE'
      ),
      pg_catalog.has_function_privilege(
        'periapsis_auditor', procedure.oid, 'EXECUTE'
      )
    INTO
      actual_source_hash,
      actual_volatility,
      actual_security_definer,
      actual_owner,
      actual_configuration,
      public_can_execute,
      api_can_execute,
      worker_can_execute,
      notifier_can_execute,
      auditor_can_execute
    FROM pg_catalog.pg_proc AS procedure
    WHERE procedure.oid = function_oid;

    IF actual_source_hash IS DISTINCT FROM expected.source_hash
       OR actual_volatility IS DISTINCT FROM expected.volatility
       OR actual_security_definer IS DISTINCT FROM expected.security_definer
       OR actual_owner IS DISTINCT FROM 'periapsis_migrator'
       OR actual_configuration IS DISTINCT FROM
            ARRAY['search_path=pg_catalog, public, app']::text[]
       OR public_can_execute
       OR api_can_execute IS DISTINCT FROM expected.api_execute
       OR worker_can_execute IS DISTINCT FROM expected.worker_execute
       OR notifier_can_execute IS DISTINCT FROM expected.notifier_execute
       OR auditor_can_execute IS DISTINCT FROM expected.auditor_execute THEN
      RAISE EXCEPTION 'readiness ABI function % does not match its sealed contract',
        expected.signature
        USING ERRCODE = '55000';
    END IF;
  END LOOP;

  function_oid := pg_catalog.to_regprocedure(
    'app.audit_event_payload(public.audit_events)'
  );
  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_proc AS procedure
    JOIN pg_catalog.pg_language AS language
      ON language.oid = procedure.prolang
    WHERE procedure.oid = function_oid
      AND (
        procedure.prorettype IS DISTINCT FROM
          'jsonb'::pg_catalog.regtype::oid
        OR procedure.proretset
        OR NOT procedure.proisstrict
        OR procedure.proparallel IS DISTINCT FROM 's'::"char"
        OR language.lanname IS DISTINCT FROM 'sql'
      )
  ) THEN
    RAISE EXCEPTION 'audit payload compatibility attributes are not exact'
      USING ERRCODE = '55000';
  END IF;

  -- Freeze the input/output order as well as the implementation of every
  -- predecessor read ABI. This avoids a compatible-looking overload from
  -- silently changing a rolling replica's row decoder.
  FOR expected IN
    SELECT *
    FROM (VALUES
      (
        'app.resolve_current_tenant_human_authority_v2(integer)',
        ARRAY[
          'integer'::pg_catalog.regtype::oid,
          'text'::pg_catalog.regtype::oid,
          'public.authorization_scope'::pg_catalog.regtype::oid,
          'boolean'::pg_catalog.regtype::oid,
          'timestamp with time zone'::pg_catalog.regtype::oid
        ]::oid[],
        ARRAY['i', 't', 't', 't', 't']::"char"[],
        ARRAY[
          'p_limit', 'permission_key', 'scope', 'delegable',
          'delegation_expires_at'
        ]::text[]
      ),
      (
        'app.list_tenant_permission_catalog_v2(uuid,integer)',
        ARRAY[
          'uuid'::pg_catalog.regtype::oid,
          'integer'::pg_catalog.regtype::oid,
          'uuid'::pg_catalog.regtype::oid,
          'text'::pg_catalog.regtype::oid,
          'text'::pg_catalog.regtype::oid,
          'text'::pg_catalog.regtype::oid,
          'public.authorization_scope[]'::pg_catalog.regtype::oid,
          'text[]'::pg_catalog.regtype::oid
        ]::oid[],
        ARRAY['i', 'i', 't', 't', 't', 't', 't', 't']::"char"[],
        ARRAY[
          'p_after_id', 'p_limit', 'permission_id', 'permission_key',
          'display_name', 'description', 'allowed_scopes', 'principal_kinds'
        ]::text[]
      ),
      (
        'app.get_tenant_role_policy_v2(uuid,integer)',
        ARRAY[
          'uuid'::pg_catalog.regtype::oid,
          'integer'::pg_catalog.regtype::oid,
          'text'::pg_catalog.regtype::oid,
          'public.authorization_scope'::pg_catalog.regtype::oid,
          'boolean'::pg_catalog.regtype::oid
        ]::oid[],
        ARRAY['i', 'i', 't', 't', 't']::"char"[],
        ARRAY[
          'p_role_id', 'p_limit', 'permission_key', 'scope', 'delegable'
        ]::text[]
      ),
      (
        'app.resolve_current_tenant_human_authority_v3(integer)',
        ARRAY[
          'integer'::pg_catalog.regtype::oid,
          'text'::pg_catalog.regtype::oid,
          'public.authorization_scope'::pg_catalog.regtype::oid,
          'boolean'::pg_catalog.regtype::oid,
          'timestamp with time zone'::pg_catalog.regtype::oid
        ]::oid[],
        ARRAY['i', 't', 't', 't', 't']::"char"[],
        ARRAY[
          'p_limit', 'permission_key', 'scope', 'delegable',
          'delegation_expires_at'
        ]::text[]
      ),
      (
        'app.list_tenant_permission_catalog_v3(uuid,integer)',
        ARRAY[
          'uuid'::pg_catalog.regtype::oid,
          'integer'::pg_catalog.regtype::oid,
          'uuid'::pg_catalog.regtype::oid,
          'text'::pg_catalog.regtype::oid,
          'text'::pg_catalog.regtype::oid,
          'text'::pg_catalog.regtype::oid,
          'public.authorization_scope[]'::pg_catalog.regtype::oid,
          'text[]'::pg_catalog.regtype::oid
        ]::oid[],
        ARRAY['i', 'i', 't', 't', 't', 't', 't', 't']::"char"[],
        ARRAY[
          'p_after_id', 'p_limit', 'permission_id', 'permission_key',
          'display_name', 'description', 'allowed_scopes', 'principal_kinds'
        ]::text[]
      ),
      (
        'app.list_tenant_roles_v3(uuid,boolean,integer)',
        ARRAY[
          'uuid'::pg_catalog.regtype::oid,
          'boolean'::pg_catalog.regtype::oid,
          'integer'::pg_catalog.regtype::oid,
          'uuid'::pg_catalog.regtype::oid,
          'text'::pg_catalog.regtype::oid,
          'text'::pg_catalog.regtype::oid,
          'text'::pg_catalog.regtype::oid,
          'text'::pg_catalog.regtype::oid,
          'boolean'::pg_catalog.regtype::oid,
          'boolean'::pg_catalog.regtype::oid,
          'integer'::pg_catalog.regtype::oid,
          'timestamp with time zone'::pg_catalog.regtype::oid,
          'timestamp with time zone'::pg_catalog.regtype::oid,
          'timestamp with time zone'::pg_catalog.regtype::oid
        ]::oid[],
        ARRAY[
          'i', 'i', 'i', 't', 't', 't', 't', 't', 't', 't', 't', 't',
          't', 't'
        ]::"char"[],
        ARRAY[
          'p_after_id', 'p_include_archived', 'p_limit', 'role_id',
          'role_key', 'display_name', 'description', 'principal_kind',
          'system_role', 'protected_role', 'version', 'archived_at',
          'created_at', 'updated_at'
        ]::text[]
      ),
      (
        'app.get_tenant_role_v3(uuid)',
        ARRAY[
          'uuid'::pg_catalog.regtype::oid,
          'uuid'::pg_catalog.regtype::oid,
          'text'::pg_catalog.regtype::oid,
          'text'::pg_catalog.regtype::oid,
          'text'::pg_catalog.regtype::oid,
          'text'::pg_catalog.regtype::oid,
          'boolean'::pg_catalog.regtype::oid,
          'boolean'::pg_catalog.regtype::oid,
          'integer'::pg_catalog.regtype::oid,
          'timestamp with time zone'::pg_catalog.regtype::oid,
          'timestamp with time zone'::pg_catalog.regtype::oid,
          'timestamp with time zone'::pg_catalog.regtype::oid
        ]::oid[],
        ARRAY[
          'i', 't', 't', 't', 't', 't', 't', 't', 't', 't', 't', 't'
        ]::"char"[],
        ARRAY[
          'p_role_id', 'role_id', 'role_key', 'display_name', 'description',
          'principal_kind', 'system_role', 'protected_role', 'version',
          'archived_at', 'created_at', 'updated_at'
        ]::text[]
      ),
      (
        'app.get_tenant_role_policy_v3(uuid)',
        ARRAY[
          'uuid'::pg_catalog.regtype::oid,
          'text'::pg_catalog.regtype::oid,
          'public.authorization_scope'::pg_catalog.regtype::oid,
          'boolean'::pg_catalog.regtype::oid
        ]::oid[],
        ARRAY['i', 't', 't', 't']::"char"[],
        ARRAY['p_role_id', 'permission_key', 'scope', 'delegable']::text[]
      ),
      (
        'app.authenticate_tenant_api_credential_v1(uuid,bytea,integer,bytea,inet,text,public.authorization_scope)',
        ARRAY[
          'uuid'::pg_catalog.regtype::oid,
          'bytea'::pg_catalog.regtype::oid,
          'integer'::pg_catalog.regtype::oid,
          'bytea'::pg_catalog.regtype::oid,
          'inet'::pg_catalog.regtype::oid,
          'text'::pg_catalog.regtype::oid,
          'public.authorization_scope'::pg_catalog.regtype::oid,
          'uuid'::pg_catalog.regtype::oid,
          'uuid'::pg_catalog.regtype::oid,
          'integer'::pg_catalog.regtype::oid
        ]::oid[],
        ARRAY[
          'i', 'i', 'i', 'i', 'i', 'i', 'i', 't', 't', 't'
        ]::"char"[],
        ARRAY[
          'p_tenant_id', 'p_locator', 'p_envelope_key_version',
          'p_secret_digest', 'p_client_address', 'p_permission_key',
          'p_scope', 'service_account_id', 'credential_id', 'key_version'
        ]::text[]
      ),
      (
        'app.resolve_tenant_service_account_authority_v1(uuid,integer)',
        ARRAY[
          'uuid'::pg_catalog.regtype::oid,
          'integer'::pg_catalog.regtype::oid,
          'text'::pg_catalog.regtype::oid,
          'public.authorization_scope'::pg_catalog.regtype::oid,
          'timestamp with time zone'::pg_catalog.regtype::oid
        ]::oid[],
        ARRAY['i', 'i', 't', 't', 't']::"char"[],
        ARRAY[
          'p_service_account_id', 'p_limit', 'permission_key', 'scope',
          'effective_expires_at'
        ]::text[]
      ),
      (
        'app.list_live_api_credential_key_versions_v1(integer)',
        ARRAY[
          'integer'::pg_catalog.regtype::oid,
          'integer'::pg_catalog.regtype::oid
        ]::oid[],
        ARRAY['i', 't']::"char"[],
        ARRAY['p_limit', 'key_version']::text[]
      ),
      (
        'app.create_tenant_alert_as_human_v1(text,text,text,public.alert_severity,bytea,bytea,uuid,uuid,inet,text,text)',
        ARRAY[
          'text'::pg_catalog.regtype::oid,
          'text'::pg_catalog.regtype::oid,
          'text'::pg_catalog.regtype::oid,
          'public.alert_severity'::pg_catalog.regtype::oid,
          'bytea'::pg_catalog.regtype::oid,
          'bytea'::pg_catalog.regtype::oid,
          'uuid'::pg_catalog.regtype::oid,
          'uuid'::pg_catalog.regtype::oid,
          'inet'::pg_catalog.regtype::oid,
          'text'::pg_catalog.regtype::oid,
          'text'::pg_catalog.regtype::oid,
          'uuid'::pg_catalog.regtype::oid,
          'text'::pg_catalog.regtype::oid,
          'text'::pg_catalog.regtype::oid,
          'text'::pg_catalog.regtype::oid,
          'public.alert_status'::pg_catalog.regtype::oid,
          'public.alert_severity'::pg_catalog.regtype::oid,
          'uuid'::pg_catalog.regtype::oid,
          'uuid'::pg_catalog.regtype::oid,
          'uuid'::pg_catalog.regtype::oid,
          'timestamp with time zone'::pg_catalog.regtype::oid,
          'timestamp with time zone'::pg_catalog.regtype::oid,
          'integer'::pg_catalog.regtype::oid,
          'boolean'::pg_catalog.regtype::oid
        ]::oid[],
        ARRAY[
          'i', 'i', 'i', 'i', 'i', 'i', 'i', 'i', 'i', 'i', 'i', 't',
          't', 't', 't', 't', 't', 't', 't', 't', 't', 't', 't', 't'
        ]::"char"[],
        ARRAY[
          'p_title', 'p_description', 'p_external_id', 'p_severity',
          'p_key_digest', 'p_request_digest', 'p_request_id',
          'p_correlation_id', 'p_ip_address', 'p_user_agent',
          'p_authentication_method', 'id', 'external_id', 'title',
          'description', 'status', 'severity', 'created_by_user_id',
          'created_by_membership_id', 'created_by_service_account_id',
          'created_at', 'updated_at', 'version', 'replayed'
        ]::text[]
      ),
      (
        'app.create_tenant_alert_as_service_account_v1(uuid,bytea,integer,bytea,inet,text,text,text,public.alert_severity,bytea,bytea,uuid,uuid,text)',
        ARRAY[
          'uuid'::pg_catalog.regtype::oid,
          'bytea'::pg_catalog.regtype::oid,
          'integer'::pg_catalog.regtype::oid,
          'bytea'::pg_catalog.regtype::oid,
          'inet'::pg_catalog.regtype::oid,
          'text'::pg_catalog.regtype::oid,
          'text'::pg_catalog.regtype::oid,
          'text'::pg_catalog.regtype::oid,
          'public.alert_severity'::pg_catalog.regtype::oid,
          'bytea'::pg_catalog.regtype::oid,
          'bytea'::pg_catalog.regtype::oid,
          'uuid'::pg_catalog.regtype::oid,
          'uuid'::pg_catalog.regtype::oid,
          'text'::pg_catalog.regtype::oid,
          'uuid'::pg_catalog.regtype::oid,
          'text'::pg_catalog.regtype::oid,
          'text'::pg_catalog.regtype::oid,
          'text'::pg_catalog.regtype::oid,
          'public.alert_status'::pg_catalog.regtype::oid,
          'public.alert_severity'::pg_catalog.regtype::oid,
          'uuid'::pg_catalog.regtype::oid,
          'uuid'::pg_catalog.regtype::oid,
          'uuid'::pg_catalog.regtype::oid,
          'timestamp with time zone'::pg_catalog.regtype::oid,
          'timestamp with time zone'::pg_catalog.regtype::oid,
          'integer'::pg_catalog.regtype::oid,
          'boolean'::pg_catalog.regtype::oid
        ]::oid[],
        ARRAY[
          'i', 'i', 'i', 'i', 'i', 'i', 'i', 'i', 'i', 'i', 'i', 'i',
          'i', 'i', 't', 't', 't', 't', 't', 't', 't', 't', 't', 't',
          't', 't', 't'
        ]::"char"[],
        ARRAY[
          'p_tenant_id', 'p_locator', 'p_envelope_key_version',
          'p_secret_digest', 'p_client_address', 'p_title', 'p_description',
          'p_external_id', 'p_severity', 'p_key_digest', 'p_request_digest',
          'p_request_id', 'p_correlation_id', 'p_user_agent',
          'id', 'external_id', 'title', 'description', 'status', 'severity',
          'created_by_user_id', 'created_by_membership_id',
          'created_by_service_account_id', 'created_at', 'updated_at',
          'version', 'replayed'
        ]::text[]
      )
    ) AS abi(signature, all_argument_types, argument_modes, argument_names)
  LOOP
    function_oid := pg_catalog.to_regprocedure(expected.signature);
    SELECT
      procedure.proallargtypes,
      procedure.proargmodes,
      procedure.proargnames
    INTO
      actual_all_argument_types,
      actual_argument_modes,
      actual_argument_names
    FROM pg_catalog.pg_proc AS procedure
    WHERE procedure.oid = function_oid;

    IF actual_all_argument_types IS DISTINCT FROM expected.all_argument_types
       OR actual_argument_modes IS DISTINCT FROM expected.argument_modes
       OR actual_argument_names IS DISTINCT FROM expected.argument_names THEN
      RAISE EXCEPTION 'readiness ABI shape % does not match its sealed contract',
        expected.signature
        USING ERRCODE = '55000';
    END IF;
  END LOOP;

  SELECT array_agg(
           procedure.proname::text
           ORDER BY procedure.proname::text COLLATE "C"
         )
  INTO actual_public_surface
  FROM pg_catalog.pg_proc AS procedure
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid = procedure.pronamespace
  WHERE namespace.nspname = 'app'
    AND (
      procedure.proname LIKE '%service_account%'
      OR procedure.proname LIKE '%service_principal%'
      OR procedure.proname LIKE '%api_credential%'
      OR procedure.proname IN (
        'create_tenant_alert_as_human_v1',
        'create_tenant_alert_as_service_account_v1'
      )
    )
    AND pg_catalog.has_function_privilege(
      'periapsis_api', procedure.oid, 'EXECUTE'
    );

  IF actual_public_surface IS DISTINCT FROM ARRAY[
    'archive_tenant_service_account_v1',
    'create_tenant_alert_as_human_v1',
    'create_tenant_alert_as_service_account_v1',
    'create_tenant_service_account_v1',
    'get_tenant_api_credential_v1',
    'get_tenant_service_account_role_grant_v1',
    'get_tenant_service_account_v1',
    'grant_tenant_service_account_role_v1',
    'issue_tenant_api_credential_v1',
    'list_live_api_credential_key_versions_v1',
    'list_tenant_api_credentials_v1',
    'list_tenant_service_account_role_grants_v1',
    'list_tenant_service_accounts_v1',
    'resolve_tenant_service_account_authority_v1',
    'revoke_tenant_api_credential_v1',
    'revoke_tenant_service_account_role_grant_v1',
    'rotate_tenant_api_credential_v1',
    'update_tenant_service_account_v1'
  ]::text[] THEN
    RAISE EXCEPTION 'service-principal public function surface is not exact'
      USING ERRCODE = '55000';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_proc AS procedure
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = procedure.pronamespace
    WHERE namespace.nspname = 'app'
      AND (
        procedure.proname LIKE '%service_account%'
        OR procedure.proname LIKE '%service_principal%'
        OR procedure.proname LIKE '%api_credential%'
        OR procedure.proname IN (
          'create_tenant_alert_as_human_v1',
          'create_tenant_alert_as_service_account_v1'
        )
      )
      AND (
        NOT procedure.prosecdef
        OR pg_catalog.pg_get_userbyid(procedure.proowner)
             IS DISTINCT FROM 'periapsis_migrator'
        OR procedure.proconfig IS DISTINCT FROM
             ARRAY['search_path=pg_catalog, public, app']::text[]
        OR EXISTS (
          SELECT 1
          FROM pg_catalog.aclexplode(
            coalesce(
              procedure.proacl,
              pg_catalog.acldefault('f', procedure.proowner)
            )
          ) AS privilege
          WHERE privilege.grantee = 0
            AND privilege.privilege_type = 'EXECUTE'
        )
        OR (
          pg_catalog.has_function_privilege(
            'periapsis_worker', procedure.oid, 'EXECUTE'
          )
          AND procedure.proname <>
            'list_live_api_credential_key_versions_v1'
        )
        OR pg_catalog.has_function_privilege(
          'periapsis_notifier', procedure.oid, 'EXECUTE'
        )
        OR pg_catalog.has_function_privilege(
          'periapsis_auditor', procedure.oid, 'EXECUTE'
        )
      )
  ) THEN
    RAISE EXCEPTION 'service-principal function hardening is not exact'
      USING ERRCODE = '55000';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_proc AS procedure
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = procedure.pronamespace
    WHERE namespace.nspname = 'app'
      AND procedure.proname LIKE 'list\_%' ESCAPE '\'
      AND procedure.proname::text = ANY(actual_public_surface)
      AND (
        pg_catalog.strpos(procedure.prosrc, 'p_limit') = 0
        OR pg_catalog.strpos(procedure.prosrc, 'LIMIT p_limit') = 0
        OR pg_catalog.strpos(procedure.prosrc, 'NOT BETWEEN 1 AND') = 0
      )
  ) THEN
    RAISE EXCEPTION 'service-principal list surface is not bounded'
      USING ERRCODE = '55000';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_proc AS procedure
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = procedure.pronamespace
    WHERE namespace.nspname = 'app'
      AND procedure.proname IN (
        'create_tenant_role_legacy_human_impl',
        'replace_tenant_role_policy_v2_legacy_human_impl',
        'grant_tenant_user_role_legacy_human_impl',
        'grant_tenant_security_group_role_legacy_human_impl',
        'seed_tenant_authorization_legacy_impl'
      )
      AND (
        pg_catalog.has_function_privilege(
          'periapsis_api', procedure.oid, 'EXECUTE'
        )
        OR pg_catalog.has_function_privilege(
          'periapsis_worker', procedure.oid, 'EXECUTE'
        )
        OR pg_catalog.has_function_privilege(
          'periapsis_notifier', procedure.oid, 'EXECUTE'
        )
        OR pg_catalog.has_function_privilege(
          'periapsis_auditor', procedure.oid, 'EXECUTE'
        )
      )
  ) THEN
    RAISE EXCEPTION 'legacy human implementation is runtime-executable'
      USING ERRCODE = '55000';
  END IF;

  FOREACH relation_name IN ARRAY ARRAY[
    'alert_activities',
    'alert_commands',
    'tenant_api_credential_commands',
    'tenant_api_credential_networks',
    'tenant_api_credential_permissions',
    'tenant_api_credentials',
    'tenant_service_account_role_grants',
    'tenant_service_accounts'
  ]::text[] LOOP
    SELECT
      relation.oid,
      relation.relrowsecurity,
      relation.relforcerowsecurity,
      pg_catalog.pg_get_userbyid(relation.relowner)
    INTO
      relation_oid,
      relation_has_rls,
      relation_forces_rls,
      relation_owner
    FROM pg_catalog.pg_class AS relation
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'public'
      AND relation.relname = relation_name
      AND relation.relkind = 'r';

    IF relation_oid IS NULL
       OR NOT relation_has_rls
       OR NOT relation_forces_rls
       OR relation_owner IS DISTINCT FROM 'periapsis_migrator' THEN
      RAISE EXCEPTION 'private relation public.% is not owned and FORCE RLS sealed',
        relation_name
        USING ERRCODE = '55000';
    END IF;

    FOREACH runtime_role IN ARRAY ARRAY[
      'periapsis_api',
      'periapsis_worker',
      'periapsis_notifier',
      'periapsis_auditor'
    ]::text[] LOOP
      FOREACH table_privilege IN ARRAY ARRAY[
        'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES',
        'TRIGGER'
      ]::text[] LOOP
        IF pg_catalog.has_table_privilege(
          runtime_role::pg_catalog.name, relation_oid, table_privilege
        ) THEN
          RAISE EXCEPTION 'runtime role % has % on private relation public.%',
            runtime_role, table_privilege, relation_name
            USING ERRCODE = '55000';
        END IF;
      END LOOP;
      FOREACH table_privilege IN ARRAY ARRAY[
        'SELECT', 'INSERT', 'UPDATE', 'REFERENCES'
      ]::text[] LOOP
        IF pg_catalog.has_any_column_privilege(
          runtime_role::pg_catalog.name, relation_oid, table_privilege
        ) THEN
          RAISE EXCEPTION 'runtime role % has column % on private relation public.%',
            runtime_role, table_privilege, relation_name
            USING ERRCODE = '55000';
        END IF;
      END LOOP;
    END LOOP;
  END LOOP;

  IF NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_roles AS role
    WHERE role.rolname = 'periapsis_migrator'
      AND role.rolbypassrls
  ) OR EXISTS (
    SELECT 1
    FROM pg_catalog.pg_roles AS role
    WHERE role.rolname IN (
      'periapsis_api',
      'periapsis_worker',
      'periapsis_notifier',
      'periapsis_auditor'
    )
      AND role.rolbypassrls
  ) THEN
    RAISE EXCEPTION 'readiness role BYPASSRLS boundary is not exact'
      USING ERRCODE = '55000';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM (VALUES
      ('alerts', 'alerts_creator_attribution_check'),
      ('alert_activities', 'alert_activities_actor_check'),
      ('alert_commands', 'alert_commands_actor_check'),
      ('audit_events', 'audit_events_actor_consistency_check')
    ) AS required_constraint(relation_name, constraint_name)
    WHERE NOT EXISTS (
      SELECT 1
      FROM pg_catalog.pg_constraint AS catalog_constraint
      WHERE catalog_constraint.conrelid = pg_catalog.to_regclass(
              'public.' || required_constraint.relation_name
            )
        AND catalog_constraint.conname = required_constraint.constraint_name
        AND catalog_constraint.contype = 'c'
        AND catalog_constraint.convalidated
    )
  ) THEN
    RAISE EXCEPTION 'Alert or audit actor XOR constraint is not validated'
      USING ERRCODE = '55000';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM (VALUES
      ('alert_activities', 'alert_activities_immutable_guard'),
      ('alert_commands', 'alert_commands_immutable_guard'),
      (
        'tenant_api_credential_commands',
        'tenant_api_credential_commands_immutable_guard'
      )
    ) AS required_trigger(relation_name, trigger_name)
    WHERE NOT EXISTS (
      SELECT 1
      FROM pg_catalog.pg_trigger AS catalog_trigger
      WHERE catalog_trigger.tgrelid = pg_catalog.to_regclass(
              'public.' || required_trigger.relation_name
            )
        AND catalog_trigger.tgname = required_trigger.trigger_name
        AND NOT catalog_trigger.tgisinternal
        AND catalog_trigger.tgenabled = 'O'
        AND catalog_trigger.tgtype = 27
        AND catalog_trigger.tgfoid = pg_catalog.to_regprocedure(
              'app.guard_service_principal_append_only_v1()'
            )
    )
  ) THEN
    RAISE EXCEPTION 'service-principal tombstone trigger is not enabled'
      USING ERRCODE = '55000';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM (VALUES
      (
        'tenant_service_accounts',
        'tenant_service_accounts_authorization_touch'
      ),
      (
        'tenant_service_account_role_grants',
        'tenant_service_account_role_grants_authorization_touch'
      )
    ) AS required_trigger(relation_name, trigger_name)
    WHERE NOT EXISTS (
      SELECT 1
      FROM pg_catalog.pg_trigger AS catalog_trigger
      WHERE catalog_trigger.tgrelid = pg_catalog.to_regclass(
              'public.' || required_trigger.relation_name
            )
        AND catalog_trigger.tgname = required_trigger.trigger_name
        AND NOT catalog_trigger.tgisinternal
        AND catalog_trigger.tgenabled = 'O'
        AND catalog_trigger.tgtype = 31
        AND catalog_trigger.tgfoid = pg_catalog.to_regprocedure(
              'app.touch_tenant_authorization_row()'
            )
    )
  ) THEN
    RAISE EXCEPTION 'service-principal authorization touch trigger is not exact'
      USING ERRCODE = '55000';
  END IF;

  FOREACH relation_name IN ARRAY ARRAY[
    'alerts', 'alert_activities', 'audit_events', 'outbox_events'
  ]::text[] LOOP
    relation_oid := pg_catalog.to_regclass('public.' || relation_name);
    IF relation_oid IS NULL THEN
      RAISE EXCEPTION 'Alert side-effect relation public.% is missing',
        relation_name
        USING ERRCODE = '55000';
    END IF;
    SELECT relation.relrowsecurity,
           relation.relforcerowsecurity,
           pg_catalog.pg_get_userbyid(relation.relowner)
    INTO relation_has_rls, relation_forces_rls, relation_owner
    FROM pg_catalog.pg_class AS relation
    WHERE relation.oid = relation_oid;
    IF NOT relation_has_rls
       OR NOT relation_forces_rls
       OR relation_owner IS DISTINCT FROM 'periapsis_migrator' THEN
      RAISE EXCEPTION 'Alert side-effect relation public.% is not FORCE RLS sealed',
        relation_name
        USING ERRCODE = '55000';
    END IF;
    FOREACH table_privilege IN ARRAY ARRAY[
      'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE'
    ]::text[] LOOP
      IF pg_catalog.has_table_privilege(
        'periapsis_api', relation_oid, table_privilege
      ) THEN
        RAISE EXCEPTION 'API has % on Alert side-effect relation public.%',
          table_privilege, relation_name
          USING ERRCODE = '55000';
      END IF;
    END LOOP;
    FOREACH table_privilege IN ARRAY ARRAY['INSERT', 'UPDATE']::text[] LOOP
      IF pg_catalog.has_any_column_privilege(
        'periapsis_api', relation_oid, table_privilege
      ) THEN
        RAISE EXCEPTION 'API has column % on Alert side-effect relation public.%',
          table_privilege, relation_name
          USING ERRCODE = '55000';
      END IF;
    END LOOP;
  END LOOP;
END;
$service_principal_readiness_assertions$;--> statement-breakpoint

-- v6 is the only unsealed projection. It fails closed unless the journal has
-- the exact 39 timestamp sequence committed for this release.
CREATE FUNCTION "app"."schema_compatibility_v6"()
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
  migration_0038_rows bigint;
  journal_created_at bigint[];
BEGIN
  EXECUTE $query$
    SELECT
      count(*)::bigint,
      max(migration.created_at)::bigint,
      count(*) FILTER (
        WHERE migration.created_at = 1787613747552
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
    migration_0038_rows,
    journal_created_at;

  IF journal_count = 39
     AND journal_latest_created_at = 1787613747552
     AND migration_0038_rows = 1
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
       1787613744526, 1787613746038, 1787613747552
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
-- migrator has sealed the exact v6 journal. Its result is the original 33-row
-- predecessor prefix and therefore retains the previous fingerprint.
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
  migration_0038_rows bigint;
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
        WHERE migration.created_at = 1787613747552
      )::bigint
    FROM drizzle.__drizzle_migrations AS migration
  $query$
  INTO migration_0032_rows, migration_0038_rows;

  IF journal_count = 39
     AND journal_latest_created_at = 1787613747552
     AND migration_0032_rows = 1
     AND migration_0038_rows = 1
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

-- v4 is outside the supported two-release rolling window.
CREATE OR REPLACE FUNCTION "app"."schema_compatibility_v4"()
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
  RETURN QUERY
  SELECT 0::bigint,
         0::bigint,
         'UNSUPPORTED'::text,
         'UNSUPPORTED'::text;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION "app"."schema_compatibility_v4"() OWNER TO "periapsis_migrator";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."schema_compatibility_v4"() FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."schema_compatibility_v4"() TO "periapsis_api", "periapsis_worker";--> statement-breakpoint

-- The canonical migrator supplies the generated v6 manifest. The routine is
-- intentionally private, accepts only the exact 39 timestamp sequence, and
-- verifies both v6 and the sealed v5 predecessor before returning.
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
  IF p_expected_count IS DISTINCT FROM 39
     OR p_expected_latest_created_at IS DISTINCT FROM 1787613747552
     OR p_expected_latest_hash IS NULL
     OR p_expected_latest_hash !~ '^[0-9a-f]{64}$'
     OR p_expected_migration_fingerprint IS NULL
     OR p_expected_migration_fingerprint !~ '^[1-9][0-9]*@[0-9a-f]{64}(:[1-9][0-9]*@[0-9a-f]{64})*$'
     OR cardinality(fingerprint_entries) IS DISTINCT FROM 39
     OR fingerprint_entries[39] IS DISTINCT FROM (
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
       1787613744526, 1787613746038, 1787613747552
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
