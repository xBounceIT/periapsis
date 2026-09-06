-- V51 forward SAML admission and typed tenant-platform provenance repair.
-- Subject-index alias key versions are distinct from identity ciphertext keys.
-- Planning preserves the exact 0188 variable-conflict directive already applied.
-- Current 0228 authority/revalidation helpers remain source-identical. Planning,
-- typed-primary validation, alias creation and session lookup are repaired. Revoked SAML rows
-- retain their exact historical graph, while live sessions require current authority.
-- Every runtime writer and inherited login must be NOLOGIN and drained.
DO $v51_saml_provenance_quiesced_cutover$
BEGIN
  IF EXISTS (
    WITH RECURSIVE writer_principal(role_oid) AS (
      SELECT role.oid
      FROM pg_catalog.pg_roles AS role
      WHERE role.rolname IN (
        'periapsis_api','periapsis_worker','periapsis_notifier',
        'periapsis_api_login','periapsis_worker_login',
        'periapsis_notifier_login'
      )
      UNION
      SELECT membership.member
      FROM pg_catalog.pg_auth_members AS membership
      JOIN writer_principal AS granted
        ON granted.role_oid = membership.roleid
    )
    SELECT 1
    FROM writer_principal AS principal
    JOIN pg_catalog.pg_roles AS role ON role.oid = principal.role_oid
    WHERE role.rolcanlogin
  ) THEN
    RAISE EXCEPTION
      'v51 SAML provenance cutover requires every runtime writer login to be NOLOGIN'
      USING ERRCODE = '55000';
  END IF;
  IF EXISTS (
    WITH RECURSIVE writer_principal(role_oid) AS (
      SELECT role.oid
      FROM pg_catalog.pg_roles AS role
      WHERE role.rolname IN (
        'periapsis_api','periapsis_worker','periapsis_notifier',
        'periapsis_api_login','periapsis_worker_login',
        'periapsis_notifier_login'
      )
      UNION
      SELECT membership.member
      FROM pg_catalog.pg_auth_members AS membership
      JOIN writer_principal AS granted
        ON granted.role_oid = membership.roleid
    )
    SELECT 1
    FROM pg_catalog.pg_stat_activity AS activity
    JOIN writer_principal AS principal
      ON principal.role_oid = activity.usesysid
    WHERE activity.pid <> pg_backend_pid()
  ) THEN
    RAISE EXCEPTION
      'v51 SAML provenance cutover requires every runtime writer session to be drained'
      USING ERRCODE = '55000';
  END IF;
END;
$v51_saml_provenance_quiesced_cutover$;
--> statement-breakpoint
DO $assert_v51_authority_predecessor$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_proc AS routine
    JOIN pg_catalog.pg_roles AS owner ON owner.oid=routine.proowner
    JOIN pg_catalog.pg_language AS language ON language.oid=routine.prolang
    WHERE routine.oid='app.private_tenant_platform_session_authority_live_v1(uuid,uuid,timestamp with time zone)'::pg_catalog.regprocedure
      AND owner.rolname='periapsis_migrator' AND language.lanname='sql'
      AND routine.prokind='f' AND routine.provolatile='s' AND routine.prosecdef
      AND NOT routine.proisstrict AND NOT routine.proleakproof
      AND routine.proparallel='u' AND routine.pronargs=3
      AND routine.pronargdefaults=0 AND routine.prorettype='pg_catalog.bool'::pg_catalog.regtype
      AND NOT routine.proretset AND routine.proallargtypes IS NULL AND routine.proargmodes IS NULL
      AND routine.proargnames IS NOT DISTINCT FROM ARRAY['p_tenant_id','p_session_id','p_observed_at']::pg_catalog.text[]
      AND routine.proconfig IS NOT DISTINCT FROM ARRAY['search_path=pg_catalog, public, app']::pg_catalog.text[]
      AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(routine.prosrc,'UTF8')),'hex')='9ed40684de93fcfb7a92725f02a3201ef8e600ece5623a6597845a4c6b9e9afa'
      AND (
        SELECT count(*)=1 AND coalesce(bool_and(
          acl.grantor=routine.proowner AND acl.grantee=routine.proowner
          AND acl.privilege_type='EXECUTE' AND NOT acl.is_grantable
        ),false)
        FROM pg_catalog.aclexplode(coalesce(routine.proacl,
          pg_catalog.acldefault('f',routine.proowner))) AS acl
      )
  ) THEN
    RAISE EXCEPTION 'SAML authority predecessor source/catalog mismatch' USING ERRCODE='55000';
  END IF;
END;
$assert_v51_authority_predecessor$;
--> statement-breakpoint
DO $assert_v51_load_predecessor$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_proc AS routine
    JOIN pg_catalog.pg_roles AS owner ON owner.oid=routine.proowner
    JOIN pg_catalog.pg_language AS language ON language.oid=routine.prolang
    WHERE routine.oid='app.load_tenant_platform_federated_session_revalidation_v1(jsonb)'::pg_catalog.regprocedure
      AND owner.rolname='periapsis_migrator' AND language.lanname='plpgsql'
      AND routine.prokind='f' AND routine.provolatile='s' AND routine.prosecdef
      AND NOT routine.proisstrict AND NOT routine.proleakproof
      AND routine.proparallel='u' AND routine.pronargs=1
      AND routine.pronargdefaults=0 AND routine.prorettype='pg_catalog.jsonb'::pg_catalog.regtype
      AND NOT routine.proretset AND routine.proallargtypes IS NULL AND routine.proargmodes IS NULL
      AND routine.proargnames IS NOT DISTINCT FROM ARRAY['p_lookup']::pg_catalog.text[]
      AND routine.proconfig IS NOT DISTINCT FROM ARRAY['search_path=pg_catalog, public, app']::pg_catalog.text[]
      AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(routine.prosrc,'UTF8')),'hex')='e8e9d3a466b8bbc17160b5b41ca5f6ab2ee378aefb6290a6e41e41066b7db80d'
      AND (
        SELECT count(*)=1 AND coalesce(bool_and(
          acl.grantor=routine.proowner AND acl.grantee=routine.proowner
          AND acl.privilege_type='EXECUTE' AND NOT acl.is_grantable
        ),false)
        FROM pg_catalog.aclexplode(coalesce(routine.proacl,
          pg_catalog.acldefault('f',routine.proowner))) AS acl
      )
  ) THEN
    RAISE EXCEPTION 'SAML load predecessor source/catalog mismatch' USING ERRCODE='55000';
  END IF;
END;
$assert_v51_load_predecessor$;
--> statement-breakpoint
DO $assert_v51_apply_predecessor$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_proc AS routine
    JOIN pg_catalog.pg_roles AS owner ON owner.oid=routine.proowner
    JOIN pg_catalog.pg_language AS language ON language.oid=routine.prolang
    WHERE routine.oid='app.apply_tenant_platform_federated_session_revalidation_v1(jsonb)'::pg_catalog.regprocedure
      AND owner.rolname='periapsis_migrator' AND language.lanname='plpgsql'
      AND routine.prokind='f' AND routine.provolatile='v' AND routine.prosecdef
      AND NOT routine.proisstrict AND NOT routine.proleakproof
      AND routine.proparallel='u' AND routine.pronargs=1
      AND routine.pronargdefaults=0 AND routine.prorettype='pg_catalog.jsonb'::pg_catalog.regtype
      AND NOT routine.proretset AND routine.proallargtypes IS NULL AND routine.proargmodes IS NULL
      AND routine.proargnames IS NOT DISTINCT FROM ARRAY['p_mutation']::pg_catalog.text[]
      AND routine.proconfig IS NOT DISTINCT FROM ARRAY['search_path=pg_catalog, public, app']::pg_catalog.text[]
      AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(routine.prosrc,'UTF8')),'hex')='d2a81b178c1769e2018ac22281799731e96a9ac450c3bd7be2d2f965aa582227'
      AND (
        SELECT count(*)=1 AND coalesce(bool_and(
          acl.grantor=routine.proowner AND acl.grantee=routine.proowner
          AND acl.privilege_type='EXECUTE' AND NOT acl.is_grantable
        ),false)
        FROM pg_catalog.aclexplode(coalesce(routine.proacl,
          pg_catalog.acldefault('f',routine.proowner))) AS acl
      )
  ) THEN
    RAISE EXCEPTION 'SAML apply predecessor source/catalog mismatch' USING ERRCODE='55000';
  END IF;
END;
$assert_v51_apply_predecessor$;
--> statement-breakpoint
DO $assert_v51_wrapper_predecessor$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_proc AS routine
    JOIN pg_catalog.pg_roles AS owner ON owner.oid=routine.proowner
    JOIN pg_catalog.pg_language AS language ON language.oid=routine.prolang
    WHERE routine.oid='app.assert_auth_session_mfa_provenance_v1(uuid,uuid)'::pg_catalog.regprocedure
      AND owner.rolname='periapsis_migrator' AND language.lanname='plpgsql'
      AND routine.prokind='f' AND routine.provolatile='v' AND routine.prosecdef
      AND NOT routine.proisstrict AND NOT routine.proleakproof
      AND routine.proparallel='u' AND routine.pronargs=2
      AND routine.pronargdefaults=0 AND routine.prorettype='pg_catalog.void'::pg_catalog.regtype
      AND NOT routine.proretset AND routine.proallargtypes IS NULL AND routine.proargmodes IS NULL
      AND routine.proargnames IS NOT DISTINCT FROM ARRAY['p_tenant_id','p_session_id']::pg_catalog.text[]
      AND routine.proconfig IS NOT DISTINCT FROM ARRAY['search_path=pg_catalog, public, app']::pg_catalog.text[]
      AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(routine.prosrc,'UTF8')),'hex')='af0dc8cb0913052a8688a614c5931f21c82b76cd8871ac89767d7e2f99ed65ec'
      AND (
        SELECT count(*)=1 AND coalesce(bool_and(
          acl.grantor=routine.proowner AND acl.grantee=routine.proowner
          AND acl.privilege_type='EXECUTE' AND NOT acl.is_grantable
        ),false)
        FROM pg_catalog.aclexplode(coalesce(routine.proacl,
          pg_catalog.acldefault('f',routine.proowner))) AS acl
      )
  ) THEN
    RAISE EXCEPTION 'SAML wrapper predecessor source/catalog mismatch' USING ERRCODE='55000';
  END IF;
END;
$assert_v51_wrapper_predecessor$;
--> statement-breakpoint
CREATE OR REPLACE FUNCTION app.assert_auth_session_mfa_provenance_v1(
  p_tenant_id uuid,p_session_id uuid
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_state public.auth_session_mfa_states%ROWTYPE;
  v_lookup record;
  v_method text;
  v_ldap_count integer;
  v_other_count integer;
  v_saml_count integer;
  v_saml_revoked boolean;
BEGIN
  IF EXISTS (
    SELECT 1
    FROM ONLY public.auth_session_mfa_states AS state
    JOIN ONLY public.auth_sessions AS session ON session.id=state.session_id
    WHERE state.session_id=p_session_id
      AND state.primary_kind='tenant_platform_provider'
      AND session.authentication_method='saml'
  ) OR EXISTS (
    SELECT 1
    FROM ONLY public.auth_session_tenant_platform_federated_provenance AS provenance
    LEFT JOIN ONLY public.platform_auth_providers AS provider
      ON provider.id=provenance.platform_provider_id
    LEFT JOIN ONLY public.platform_federated_provider_policies AS policy
      ON policy.provider_id=provenance.platform_provider_id
    LEFT JOIN ONLY public.platform_federated_external_identities AS identity
      ON identity.id=provenance.external_identity_id
    WHERE provenance.session_id=p_session_id
      AND (provenance.authentication_method='saml'
        OR provider.kind::text='saml' OR policy.provider_kind::text='saml'
        OR identity.provider_kind::text='saml')
  ) THEN
    SELECT state.* INTO v_state
    FROM ONLY public.auth_session_mfa_states AS state
    JOIN ONLY public.auth_sessions AS session
      ON session.id=state.session_id AND session.user_id=state.user_id
     AND session.active_tenant_id=state.tenant_id
    WHERE state.tenant_id=p_tenant_id AND state.session_id=p_session_id;
    IF NOT FOUND OR v_state.primary_kind<>'tenant_platform_provider' THEN
      RAISE EXCEPTION 'SAML session has invalid typed primary provenance'
        USING ERRCODE='23514';
    END IF;

    -- Count raw rows before joins: malformed competing families cannot vanish
    -- because their provider/credential or lifecycle is no longer valid.
    SELECT count(*)::integer INTO v_saml_count
    FROM ONLY public.auth_session_tenant_platform_federated_provenance
    WHERE session_id=p_session_id;
    SELECT
      (SELECT count(*) FROM ONLY public.auth_session_local_credential_provenance
        WHERE session_id=p_session_id)
      +(SELECT count(*) FROM ONLY public.auth_session_passkey_provenance
        WHERE session_id=p_session_id)
      +(SELECT count(*) FROM ONLY public.auth_session_federated_provenance
        WHERE session_id=p_session_id)
      +(SELECT count(*) FROM ONLY public.auth_session_ldap_provenance
        WHERE session_id=p_session_id)
      +(SELECT count(*) FROM ONLY public.auth_session_platform_oidc_provenance
        WHERE session_id=p_session_id)
      +(SELECT count(*) FROM ONLY public.auth_session_platform_saml_provenance
        WHERE session_id=p_session_id)
      INTO v_other_count;
    IF v_saml_count<>1 OR v_other_count<>0 THEN
      RAISE EXCEPTION 'SAML session has invalid typed primary provenance'
        USING ERRCODE='23514';
    END IF;

    -- This graph is structural for BOTH live and revoked sessions. Immutable
    -- pins stay bounded but are not rewritten to current revisions on revoke.
    SELECT count(*)::integer INTO v_saml_count
    FROM ONLY public.auth_session_tenant_platform_federated_provenance AS provenance
    JOIN ONLY public.auth_sessions AS session
      ON session.id=provenance.session_id AND session.user_id=provenance.user_id
     AND session.active_tenant_id=provenance.tenant_id
     AND session.authentication_method=provenance.authentication_method
    JOIN ONLY public.platform_auth_providers AS provider
      ON provider.id=provenance.platform_provider_id
     AND provider.kind::text=provenance.authentication_method
    JOIN ONLY public.platform_federated_provider_policies AS policy
      ON policy.provider_id=provenance.platform_provider_id
     AND policy.provider_kind::text=provenance.authentication_method
    JOIN ONLY public.platform_federated_external_identities AS identity
      ON identity.platform_provider_id=provenance.platform_provider_id
     AND identity.id=provenance.external_identity_id
     AND identity.user_id=provenance.user_id
     AND identity.provider_kind::text=provenance.authentication_method
    JOIN ONLY public.tenant_platform_auth_provider_bindings AS binding
      ON binding.tenant_id=provenance.tenant_id AND binding.id=provenance.binding_id
     AND binding.platform_provider_id=provenance.platform_provider_id
    JOIN ONLY public.tenant_platform_identity_provider_access_epochs AS epoch
      ON epoch.tenant_id=provenance.tenant_id AND epoch.id=provenance.access_epoch_id
     AND epoch.binding_id=provenance.binding_id
     AND epoch.platform_provider_id=provenance.platform_provider_id
     AND epoch.source_id=provenance.access_source_id
    JOIN ONLY public.tenant_authorization_sources AS source
      ON source.tenant_id=epoch.tenant_id AND source.id=epoch.source_id
     AND source.kind='identity_provider_access'
     AND source.key=format('identity_provider_access:%s:%s',epoch.binding_id,epoch.sequence)
    JOIN ONLY public.tenant_memberships AS membership
      ON membership.tenant_id=provenance.tenant_id AND membership.id=provenance.membership_id
     AND membership.user_id=provenance.user_id
    JOIN ONLY public.tenant_platform_federated_provider_access_grants AS grant_record
      ON grant_record.tenant_id=provenance.tenant_id AND grant_record.id=provenance.access_grant_id
     AND grant_record.platform_provider_id=provenance.platform_provider_id
     AND grant_record.binding_id=provenance.binding_id
     AND grant_record.access_epoch_id=provenance.access_epoch_id
     AND grant_record.source_id=provenance.access_source_id
     AND grant_record.external_identity_id=provenance.external_identity_id
     AND grant_record.membership_id=provenance.membership_id
     AND grant_record.user_id=provenance.user_id
    WHERE provenance.tenant_id=p_tenant_id AND provenance.session_id=p_session_id
      AND provenance.user_id=v_state.user_id
      AND provenance.primary_kind='tenant_platform_provider'
      AND provenance.authentication_method='saml'
      AND provenance.external_identity_revision BETWEEN 1 AND 2147483647
      AND provenance.provider_revision BETWEEN 1 AND 2147483647
      AND provenance.binding_revision BETWEEN 1 AND 2147483647
      AND provenance.security_revision BETWEEN 1 AND 9007199254740991
      AND provenance.mapping_revision BETWEEN 1 AND 9007199254740991
      AND provenance.authorization_revision BETWEEN 1 AND 9007199254740991
      AND provenance.subject_alias_key_version BETWEEN 1 AND 32767
      AND provenance.trust_rule_revision BETWEEN 1 AND 9007199254740991;
    IF v_saml_count<>1 THEN
      RAISE EXCEPTION 'SAML session has invalid typed primary provenance'
        USING ERRCODE='23514';
    END IF;
    SELECT session.revoked_at IS NOT NULL INTO STRICT v_saml_revoked
    FROM ONLY public.auth_sessions AS session WHERE session.id=p_session_id;
    IF NOT v_saml_revoked AND NOT
       app.private_tenant_platform_session_authority_live_v1(
         p_tenant_id,p_session_id,transaction_timestamp()
       ) THEN
      RAISE EXCEPTION 'SAML session has no live primary authority'
        USING ERRCODE='23514';
    END IF;
    RETURN;
  END IF;
  SELECT state AS mfa_state,session.authentication_method AS method
    INTO v_lookup
  FROM public.auth_session_mfa_states AS state
  JOIN public.auth_sessions AS session
    ON session.id=state.session_id AND session.user_id=state.user_id
   AND session.active_tenant_id=state.tenant_id
  WHERE state.tenant_id=p_tenant_id AND state.session_id=p_session_id;
  IF NOT FOUND THEN RETURN; END IF;
  v_state:=v_lookup.mfa_state;
  v_method:=v_lookup.method;
  IF v_state.primary_kind='tenant_provider' AND v_method='ldap' THEN
    SELECT count(*)::integer INTO v_ldap_count
    FROM public.auth_session_ldap_provenance AS provenance
    WHERE provenance.tenant_id=p_tenant_id
      AND provenance.session_id=p_session_id
      AND provenance.user_id=v_state.user_id
      AND provenance.primary_kind='tenant_provider'
      AND provenance.authentication_method='ldap';
    SELECT
      (SELECT count(*) FROM public.auth_session_local_credential_provenance
        WHERE tenant_id=p_tenant_id AND session_id=p_session_id)
      +(SELECT count(*) FROM public.auth_session_passkey_provenance
        WHERE tenant_id=p_tenant_id AND session_id=p_session_id)
      +(SELECT count(*) FROM public.auth_session_federated_provenance
        WHERE tenant_id=p_tenant_id AND session_id=p_session_id)
      +(SELECT count(*)
        FROM public.auth_session_tenant_platform_federated_provenance
        WHERE tenant_id=p_tenant_id AND session_id=p_session_id)
      INTO v_other_count;
    IF v_ldap_count<>1 OR v_other_count<>0 THEN
      RAISE EXCEPTION 'LDAP session has invalid typed primary provenance'
        USING ERRCODE='23514';
    END IF;
    RETURN;
  END IF;
  PERFORM app.assert_auth_session_mfa_provenance_pre_ldap_v1(
    p_tenant_id,p_session_id
  );
END;
$function$;
--> statement-breakpoint
DO $assert_v51_authority_successor$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_proc AS routine
    JOIN pg_catalog.pg_roles AS owner ON owner.oid=routine.proowner
    JOIN pg_catalog.pg_language AS language ON language.oid=routine.prolang
    WHERE routine.oid='app.private_tenant_platform_session_authority_live_v1(uuid,uuid,timestamp with time zone)'::pg_catalog.regprocedure
      AND owner.rolname='periapsis_migrator' AND language.lanname='sql'
      AND routine.prokind='f' AND routine.provolatile='s' AND routine.prosecdef
      AND NOT routine.proisstrict AND NOT routine.proleakproof
      AND routine.proparallel='u' AND routine.pronargs=3
      AND routine.pronargdefaults=0 AND routine.prorettype='pg_catalog.bool'::pg_catalog.regtype
      AND NOT routine.proretset AND routine.proallargtypes IS NULL AND routine.proargmodes IS NULL
      AND routine.proargnames IS NOT DISTINCT FROM ARRAY['p_tenant_id','p_session_id','p_observed_at']::pg_catalog.text[]
      AND routine.proconfig IS NOT DISTINCT FROM ARRAY['search_path=pg_catalog, public, app']::pg_catalog.text[]
      AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(routine.prosrc,'UTF8')),'hex')='9ed40684de93fcfb7a92725f02a3201ef8e600ece5623a6597845a4c6b9e9afa'
      AND (
        SELECT count(*)=1 AND coalesce(bool_and(
          acl.grantor=routine.proowner AND acl.grantee=routine.proowner
          AND acl.privilege_type='EXECUTE' AND NOT acl.is_grantable
        ),false)
        FROM pg_catalog.aclexplode(coalesce(routine.proacl,
          pg_catalog.acldefault('f',routine.proowner))) AS acl
      )
  ) THEN
    RAISE EXCEPTION 'SAML authority successor source/catalog mismatch' USING ERRCODE='55000';
  END IF;
END;
$assert_v51_authority_successor$;
--> statement-breakpoint
DO $assert_v51_load_successor$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_proc AS routine
    JOIN pg_catalog.pg_roles AS owner ON owner.oid=routine.proowner
    JOIN pg_catalog.pg_language AS language ON language.oid=routine.prolang
    WHERE routine.oid='app.load_tenant_platform_federated_session_revalidation_v1(jsonb)'::pg_catalog.regprocedure
      AND owner.rolname='periapsis_migrator' AND language.lanname='plpgsql'
      AND routine.prokind='f' AND routine.provolatile='s' AND routine.prosecdef
      AND NOT routine.proisstrict AND NOT routine.proleakproof
      AND routine.proparallel='u' AND routine.pronargs=1
      AND routine.pronargdefaults=0 AND routine.prorettype='pg_catalog.jsonb'::pg_catalog.regtype
      AND NOT routine.proretset AND routine.proallargtypes IS NULL AND routine.proargmodes IS NULL
      AND routine.proargnames IS NOT DISTINCT FROM ARRAY['p_lookup']::pg_catalog.text[]
      AND routine.proconfig IS NOT DISTINCT FROM ARRAY['search_path=pg_catalog, public, app']::pg_catalog.text[]
      AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(routine.prosrc,'UTF8')),'hex')='e8e9d3a466b8bbc17160b5b41ca5f6ab2ee378aefb6290a6e41e41066b7db80d'
      AND (
        SELECT count(*)=1 AND coalesce(bool_and(
          acl.grantor=routine.proowner AND acl.grantee=routine.proowner
          AND acl.privilege_type='EXECUTE' AND NOT acl.is_grantable
        ),false)
        FROM pg_catalog.aclexplode(coalesce(routine.proacl,
          pg_catalog.acldefault('f',routine.proowner))) AS acl
      )
  ) THEN
    RAISE EXCEPTION 'SAML load successor source/catalog mismatch' USING ERRCODE='55000';
  END IF;
END;
$assert_v51_load_successor$;
--> statement-breakpoint
DO $assert_v51_apply_successor$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_proc AS routine
    JOIN pg_catalog.pg_roles AS owner ON owner.oid=routine.proowner
    JOIN pg_catalog.pg_language AS language ON language.oid=routine.prolang
    WHERE routine.oid='app.apply_tenant_platform_federated_session_revalidation_v1(jsonb)'::pg_catalog.regprocedure
      AND owner.rolname='periapsis_migrator' AND language.lanname='plpgsql'
      AND routine.prokind='f' AND routine.provolatile='v' AND routine.prosecdef
      AND NOT routine.proisstrict AND NOT routine.proleakproof
      AND routine.proparallel='u' AND routine.pronargs=1
      AND routine.pronargdefaults=0 AND routine.prorettype='pg_catalog.jsonb'::pg_catalog.regtype
      AND NOT routine.proretset AND routine.proallargtypes IS NULL AND routine.proargmodes IS NULL
      AND routine.proargnames IS NOT DISTINCT FROM ARRAY['p_mutation']::pg_catalog.text[]
      AND routine.proconfig IS NOT DISTINCT FROM ARRAY['search_path=pg_catalog, public, app']::pg_catalog.text[]
      AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(routine.prosrc,'UTF8')),'hex')='d2a81b178c1769e2018ac22281799731e96a9ac450c3bd7be2d2f965aa582227'
      AND (
        SELECT count(*)=1 AND coalesce(bool_and(
          acl.grantor=routine.proowner AND acl.grantee=routine.proowner
          AND acl.privilege_type='EXECUTE' AND NOT acl.is_grantable
        ),false)
        FROM pg_catalog.aclexplode(coalesce(routine.proacl,
          pg_catalog.acldefault('f',routine.proowner))) AS acl
      )
  ) THEN
    RAISE EXCEPTION 'SAML apply successor source/catalog mismatch' USING ERRCODE='55000';
  END IF;
END;
$assert_v51_apply_successor$;
--> statement-breakpoint
DO $assert_v51_wrapper_successor$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_proc AS routine
    JOIN pg_catalog.pg_roles AS owner ON owner.oid=routine.proowner
    JOIN pg_catalog.pg_language AS language ON language.oid=routine.prolang
    WHERE routine.oid='app.assert_auth_session_mfa_provenance_v1(uuid,uuid)'::pg_catalog.regprocedure
      AND owner.rolname='periapsis_migrator' AND language.lanname='plpgsql'
      AND routine.prokind='f' AND routine.provolatile='v' AND routine.prosecdef
      AND NOT routine.proisstrict AND NOT routine.proleakproof
      AND routine.proparallel='u' AND routine.pronargs=2
      AND routine.pronargdefaults=0 AND routine.prorettype='pg_catalog.void'::pg_catalog.regtype
      AND NOT routine.proretset AND routine.proallargtypes IS NULL AND routine.proargmodes IS NULL
      AND routine.proargnames IS NOT DISTINCT FROM ARRAY['p_tenant_id','p_session_id']::pg_catalog.text[]
      AND routine.proconfig IS NOT DISTINCT FROM ARRAY['search_path=pg_catalog, public, app']::pg_catalog.text[]
      AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(routine.prosrc,'UTF8')),'hex')='71c6155df39b10327a247a04143e302f298996e930a7e5f852cacc8f646199e3'
      AND (
        SELECT count(*)=1 AND coalesce(bool_and(
          acl.grantor=routine.proowner AND acl.grantee=routine.proowner
          AND acl.privilege_type='EXECUTE' AND NOT acl.is_grantable
        ),false)
        FROM pg_catalog.aclexplode(coalesce(routine.proacl,
          pg_catalog.acldefault('f',routine.proowner))) AS acl
      )
  ) THEN
    RAISE EXCEPTION 'SAML wrapper successor source/catalog mismatch' USING ERRCODE='55000';
  END IF;
END;
$assert_v51_wrapper_successor$;
--> statement-breakpoint
DO $assert_v51_saml_planning_predecessor$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_proc AS routine
    JOIN pg_catalog.pg_roles AS owner ON owner.oid=routine.proowner
    JOIN pg_catalog.pg_language AS language ON language.oid=routine.prolang
    WHERE routine.oid='app.load_platform_saml_planning_state_v1(jsonb)'::pg_catalog.regprocedure
      AND owner.rolname='periapsis_migrator' AND language.lanname='plpgsql'
      AND routine.prokind='f' AND routine.provolatile='s' AND routine.prosecdef
      AND NOT routine.proisstrict AND NOT routine.proleakproof
      AND routine.proparallel='u' AND routine.pronargs=1
      AND routine.pronargdefaults=0 AND routine.proargtypes='3802'::pg_catalog.oidvector
      AND routine.prorettype='pg_catalog.jsonb'::pg_catalog.regtype
      AND NOT routine.proretset AND routine.proallargtypes IS NULL AND routine.proargmodes IS NULL
      AND routine.proargnames IS NOT DISTINCT FROM ARRAY['p_lookup']::pg_catalog.text[]
      AND routine.proconfig IS NOT DISTINCT FROM ARRAY['search_path=pg_catalog, public, app']::pg_catalog.text[]
      AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(routine.prosrc,'UTF8')),'hex')='7c278fe227151c76f58f8f08c8b302819da295f2663f54e3a0b4453c7e4901d2'
      AND (
        SELECT count(*)=2 AND coalesce(bool_and(
          acl.grantor=routine.proowner
          AND acl.grantee IN (routine.proowner,'periapsis_api'::pg_catalog.regrole)
          AND acl.privilege_type='EXECUTE' AND NOT acl.is_grantable
        ),false)
        FROM pg_catalog.aclexplode(coalesce(routine.proacl,
          pg_catalog.acldefault('f',routine.proowner))) AS acl
      )
  ) THEN
    RAISE EXCEPTION 'SAML planning predecessor source/catalog mismatch' USING ERRCODE='55000';
  END IF;
END;
$assert_v51_saml_planning_predecessor$;
--> statement-breakpoint
CREATE OR REPLACE FUNCTION app.load_platform_saml_planning_state_v1(p_lookup jsonb)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  transaction_id bytea;
  observed_at timestamptz;
  pins jsonb;
  protocol_pins jsonb;
  aliases jsonb;
  matching_identity_count integer;
  result jsonb;
BEGIN
  PERFORM app.private_platform_saml_direct_json_v1(
    p_lookup,ARRAY['transactionId','observedAt','pins','subjectFormat','subjectAliases'],
    ARRAY['transactionId','observedAt','pins','subjectFormat','subjectAliases'],131072
  );
  transaction_id := app.private_mfa_decode_base64_v1(p_lookup ->> 'transactionId',32,32);
  observed_at := (p_lookup ->> 'observedAt')::timestamptz;
  pins := p_lookup -> 'pins';
  protocol_pins := pins -> 'protocol';
  aliases := p_lookup -> 'subjectAliases';
  IF (p_lookup ->> 'subjectFormat')::integer <> 3
     OR jsonb_typeof(aliases) <> 'array'
     OR jsonb_array_length(aliases) NOT BETWEEN 1 AND 16
     OR observed_at NOT BETWEEN statement_timestamp()-interval '5 minutes'
                            AND statement_timestamp()+interval '30 seconds'
     OR EXISTS (
       SELECT 1 FROM jsonb_array_elements(aliases) AS alias(value)
       WHERE jsonb_typeof(alias.value) <> 'object'
          OR (alias.value ->> 'keyVersion')::integer NOT BETWEEN 1 AND 32767
          OR octet_length(app.private_mfa_decode_base64_v1(alias.value ->> 'digest',32,32)) <> 32
     ) THEN
    RAISE EXCEPTION 'invalid direct platform SAML planning lookup'
      USING ERRCODE='22023';
  END IF;
  SELECT count(DISTINCT identity.id)::integer INTO matching_identity_count
  FROM ONLY public.platform_saml_authentication_transactions AS transaction
  JOIN ONLY public.platform_federated_external_identity_aliases AS identity_alias
    ON identity_alias.platform_provider_id=transaction.platform_provider_id
   AND identity_alias.retired_at IS NULL
  JOIN ONLY public.platform_federated_external_identities AS identity
    ON identity.platform_provider_id=identity_alias.platform_provider_id
   AND identity.id=identity_alias.external_identity_id
   AND identity.provider_kind='saml' AND identity.retired_at IS NULL
  JOIN LATERAL jsonb_array_elements(aliases) AS supplied(value)
    ON identity_alias.key_version=(supplied.value ->> 'keyVersion')::integer
   AND identity_alias.subject_digest=app.private_mfa_decode_base64_v1(supplied.value ->> 'digest',32,32)
  WHERE transaction.transaction_id=transaction_id
    AND transaction.state='pending' AND transaction.expires_at>observed_at
    AND app.private_platform_saml_transaction_pins_v1(transaction) IS NOT DISTINCT FROM pins;
  IF matching_identity_count <> 1 THEN RETURN NULL; END IF;

  WITH transaction_record AS (
    SELECT transaction.*
    FROM ONLY public.platform_saml_authentication_transactions AS transaction
    WHERE transaction.transaction_id=transaction_id
      AND transaction.state='pending' AND transaction.expires_at>observed_at
      AND app.private_platform_saml_transaction_pins_v1(transaction) IS NOT DISTINCT FROM pins
  ), matched AS (
    SELECT identity.*,identity_alias.key_version AS subject_alias_key_version,identity_alias.subject_digest,
      row_number() OVER (ORDER BY identity_alias.key_version DESC) AS rank
    FROM transaction_record AS transaction
    JOIN ONLY public.platform_federated_external_identity_aliases AS identity_alias
      ON identity_alias.platform_provider_id=transaction.platform_provider_id
     AND identity_alias.retired_at IS NULL
    JOIN ONLY public.platform_federated_external_identities AS identity
      ON identity.platform_provider_id=identity_alias.platform_provider_id
     AND identity.id=identity_alias.external_identity_id
     AND identity.provider_kind='saml' AND identity.retired_at IS NULL
    JOIN LATERAL jsonb_array_elements(aliases) AS supplied(value)
      ON identity_alias.key_version=(supplied.value ->> 'keyVersion')::integer
     AND identity_alias.subject_digest=app.private_mfa_decode_base64_v1(supplied.value ->> 'digest',32,32)
  )
  SELECT jsonb_build_object(
    'pins',pins,'providerKind','saml','providerEnabled',provider.enabled,
    'platformLoginLive',login_policy.enabled AND login_policy.account_mode='existing_identity',
    'configurationLive',configuration.version=runtime_policy.configuration_revision,
    'assurancePolicyLive',runtime_policy.assurance_policy_revision=transaction.assurance_policy_revision,
    'matches',jsonb_build_array(jsonb_build_object(
      'providerId',provider.id::text,'externalIdentityId',matched.id::text,
      'userId',local_user.id::text,
      'alias',jsonb_build_object(
        'keyVersion',matched.subject_alias_key_version,
        'digest',replace(encode(matched.subject_digest,'base64'),E'\n','')
      ),
      'identityRevision',matched.version,
      'userAuthenticationRevision',local_user.authentication_revision,
      'platformAuthorityId',role_grant.id::text,'platformAuthorityRevision',1,
      'identityLive',matched.retired_at IS NULL,'aliasLive',true,
      'userActive',local_user.active,'protectedPlatformAuthorityLive',role_grant.revoked_at IS NULL
    )),
    'trustRules',coalesce((
      SELECT jsonb_agg(jsonb_build_object(
        'ruleId',rule.id::text,'revision',rule.revision,'enabled',rule.enabled,
        'classRef',rule.exact_value,'level',rule.level,
        'maximumAuthenticationAgeSeconds',rule.maximum_authentication_age_seconds
      ) ORDER BY rule.exact_value,rule.id,rule.revision)
      FROM ONLY public.platform_federated_trust_rules AS rule
      WHERE rule.provider_id=provider.id AND rule.provider_kind='saml'
        AND rule.enabled AND rule.retired_at IS NULL
    ),'[]'::jsonb),
    'platformFloor',jsonb_build_object(
      'level',platform_floor.level,'localRequired',platform_floor.local_required,
      'freshnessNanoseconds',platform_floor.freshness_nanoseconds,
      'enrollmentDeadline',to_jsonb(platform_floor.enrollment_deadline),
      'policyRevisions',jsonb_build_array(jsonb_build_object(
        'policyId',platform_floor.id::text,'revision',platform_floor.revision
      ))
    ),
    'liveConfirmedTotpFactors',coalesce((
      SELECT jsonb_agg(jsonb_build_object(
        'factorId',factor.id::text,'userId',factor.user_id::text,
        'revision',factor.security_revision,'active',true,
        'confirmedAt',to_jsonb(factor.confirmed_at)
      ) ORDER BY factor.id)
      FROM ONLY public.totp_credentials AS factor
      WHERE factor.user_id=local_user.id AND factor.confirmed_at IS NOT NULL
        AND factor.disabled_at IS NULL
    ),'[]'::jsonb)
  ) INTO result
  FROM transaction_record AS transaction
  JOIN matched ON matched.rank=1
  JOIN ONLY public.platform_auth_providers AS provider
    ON provider.id=transaction.platform_provider_id
   AND provider.kind='saml' AND provider.enabled AND provider.archived_at IS NULL
  JOIN ONLY public.platform_federated_provider_policies AS runtime_policy
    ON runtime_policy.provider_id=provider.id AND runtime_policy.provider_kind='saml'
   AND runtime_policy.enabled AND NOT runtime_policy.platform_login_enabled
  JOIN ONLY public.platform_saml_login_policies AS login_policy
    ON login_policy.provider_id=provider.id
   AND login_policy.revision=transaction.login_policy_revision
  JOIN ONLY public.platform_saml_provider_configurations AS configuration
    ON configuration.provider_id=provider.id
  JOIN ONLY public.users AS local_user
    ON local_user.id=matched.user_id AND local_user.active
  JOIN ONLY public.user_platform_roles AS role_grant
    ON role_grant.user_id=local_user.id AND role_grant.revoked_at IS NULL
  JOIN ONLY public.platform_roles AS platform_role
    ON platform_role.id=role_grant.role_id AND platform_role.key='platform_super_admin'
  JOIN ONLY public.mfa_policy_revisions AS platform_floor
    ON platform_floor.id=transaction.platform_floor_policy_id
   AND platform_floor.revision=transaction.platform_floor_policy_revision
   AND platform_floor.scope='platform_floor' AND platform_floor.tenant_id IS NULL
   AND platform_floor.retired_at IS NULL
  WHERE transaction.provider_revision=provider.version
    AND transaction.configuration_revision=runtime_policy.configuration_revision
    AND transaction.security_revision=runtime_policy.security_revision
    AND transaction.plan_revision=runtime_policy.plan_revision
    AND transaction.assurance_policy_revision=runtime_policy.assurance_policy_revision;
  RETURN result;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid direct platform SAML planning lookup'
    USING ERRCODE='22023';
END;
$function$;
--> statement-breakpoint
DO $assert_v51_saml_planning_successor$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_proc AS routine
    JOIN pg_catalog.pg_roles AS owner ON owner.oid=routine.proowner
    JOIN pg_catalog.pg_language AS language ON language.oid=routine.prolang
    WHERE routine.oid='app.load_platform_saml_planning_state_v1(jsonb)'::pg_catalog.regprocedure
      AND owner.rolname='periapsis_migrator' AND language.lanname='plpgsql'
      AND routine.prokind='f' AND routine.provolatile='s' AND routine.prosecdef
      AND NOT routine.proisstrict AND NOT routine.proleakproof
      AND routine.proparallel='u' AND routine.pronargs=1
      AND routine.pronargdefaults=0 AND routine.proargtypes='3802'::pg_catalog.oidvector
      AND routine.prorettype='pg_catalog.jsonb'::pg_catalog.regtype
      AND NOT routine.proretset AND routine.proallargtypes IS NULL AND routine.proargmodes IS NULL
      AND routine.proargnames IS NOT DISTINCT FROM ARRAY['p_lookup']::pg_catalog.text[]
      AND routine.proconfig IS NOT DISTINCT FROM ARRAY['search_path=pg_catalog, public, app']::pg_catalog.text[]
      AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(routine.prosrc,'UTF8')),'hex')='fa533493ecf308ff8ead14bf98c7fd8aa04f5d30947b8c8fe433140871412936'
      AND (
        SELECT count(*)=2 AND coalesce(bool_and(
          acl.grantor=routine.proowner
          AND acl.grantee IN (routine.proowner,'periapsis_api'::pg_catalog.regrole)
          AND acl.privilege_type='EXECUTE' AND NOT acl.is_grantable
        ),false)
        FROM pg_catalog.aclexplode(coalesce(routine.proacl,
          pg_catalog.acldefault('f',routine.proowner))) AS acl
      )
  ) THEN
    RAISE EXCEPTION 'SAML planning successor source/catalog mismatch' USING ERRCODE='55000';
  END IF;
END;
$assert_v51_saml_planning_successor$;

--> statement-breakpoint
-- Alias creation uses the database transaction clock, not the assertion observation clock.
-- Preserve the effective 0184 + 0188 + 0228 apply, including logout configuration.
DO $assert_v51_saml_alias_guard_predecessor$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_proc AS routine
    JOIN pg_catalog.pg_roles AS owner ON owner.oid=routine.proowner
    JOIN pg_catalog.pg_language AS language ON language.oid=routine.prolang
    WHERE routine.oid='app.guard_platform_federated_alias_v1()'::pg_catalog.regprocedure
      AND owner.rolname='periapsis_migrator' AND language.lanname='plpgsql'
      AND routine.prokind='f' AND routine.provolatile='v' AND routine.prosecdef
      AND NOT routine.proisstrict AND NOT routine.proleakproof
      AND routine.proparallel='u' AND routine.pronargs=0
      AND routine.pronargdefaults=0
      AND routine.proargtypes=''::pg_catalog.oidvector
      AND routine.prorettype='pg_catalog.trigger'::pg_catalog.regtype
      AND NOT routine.proretset AND routine.proallargtypes IS NULL
      AND routine.proargmodes IS NULL
      AND routine.proargnames IS NULL
      AND routine.provariadic=0 AND routine.prosupport=0
      AND routine.protrftypes IS NULL AND routine.proargdefaults IS NULL
      AND routine.probin IS NULL AND routine.prosqlbody IS NULL
      AND routine.proconfig IS NOT DISTINCT FROM ARRAY['search_path=pg_catalog, public, app']::pg_catalog.text[]
      AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(routine.prosrc,'UTF8')),'hex')='002acc80cdaedd5198d01bb2370b709fa88ed19bde5b0fc2aa8bef9bbf4f2309'
      AND (
        SELECT count(*)=1 AND coalesce(bool_and(
          acl.grantor=routine.proowner
          AND acl.grantee=routine.proowner
          AND acl.privilege_type='EXECUTE' AND NOT acl.is_grantable
        ),false)
        FROM pg_catalog.aclexplode(coalesce(routine.proacl,
          pg_catalog.acldefault('f',routine.proowner))) AS acl
      )
  ) THEN
    RAISE EXCEPTION 'SAML alias guard predecessor source/catalog mismatch' USING ERRCODE='55000';
  END IF;
END;
$assert_v51_saml_alias_guard_predecessor$;
--> statement-breakpoint
DO $assert_v51_saml_apply_predecessor$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_proc AS routine
    JOIN pg_catalog.pg_roles AS owner ON owner.oid=routine.proowner
    JOIN pg_catalog.pg_language AS language ON language.oid=routine.prolang
    WHERE routine.oid='app.apply_platform_saml_authentication_v1(jsonb)'::pg_catalog.regprocedure
      AND owner.rolname='periapsis_migrator' AND language.lanname='plpgsql'
      AND routine.prokind='f' AND routine.provolatile='v' AND routine.prosecdef
      AND NOT routine.proisstrict AND NOT routine.proleakproof
      AND routine.proparallel='u' AND routine.pronargs=1
      AND routine.pronargdefaults=0
      AND routine.proargtypes='3802'::pg_catalog.oidvector
      AND routine.prorettype='pg_catalog.jsonb'::pg_catalog.regtype
      AND NOT routine.proretset AND routine.proallargtypes IS NULL
      AND routine.proargmodes IS NULL
      AND routine.proargnames IS NOT DISTINCT FROM ARRAY['p_command']::pg_catalog.text[]
      AND routine.provariadic=0 AND routine.prosupport=0
      AND routine.protrftypes IS NULL AND routine.proargdefaults IS NULL
      AND routine.probin IS NULL AND routine.prosqlbody IS NULL
      AND routine.proconfig IS NOT DISTINCT FROM ARRAY['search_path=pg_catalog, public, app']::pg_catalog.text[]
      AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(routine.prosrc,'UTF8')),'hex')='5d12a306bc233d65a032459fe26aef4797ef123e8e81723d34243c8d57295109'
      AND (
        SELECT count(*)=2 AND coalesce(bool_and(
          acl.grantor=routine.proowner
          AND acl.grantee IN (routine.proowner,'periapsis_api'::pg_catalog.regrole)
          AND acl.privilege_type='EXECUTE' AND NOT acl.is_grantable
        ),false)
        FROM pg_catalog.aclexplode(coalesce(routine.proacl,
          pg_catalog.acldefault('f',routine.proowner))) AS acl
      )
  ) THEN
    RAISE EXCEPTION 'SAML apply predecessor source/catalog mismatch' USING ERRCODE='55000';
  END IF;
END;
$assert_v51_saml_apply_predecessor$;
--> statement-breakpoint
CREATE OR REPLACE FUNCTION app.apply_platform_saml_authentication_v1(p_command jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  semantic jsonb;
  authority jsonb;
  plan jsonb;
  provenance jsonb;
  subject jsonb;
  transaction_id bytea;
  proof_digest bytea;
  response_digest bytea;
  assertion_digest bytea;
  session_index_digest bytea;
  observed_at timestamptz;
  expected_version bigint;
  provider_id uuid;
  user_id uuid;
  identity_id uuid;
  session_id uuid;
  continuation_id uuid;
  material_id uuid;
  disposition text;
  result jsonb;
  transaction_record public.platform_saml_authentication_transactions%ROWTYPE;
  application_record public.platform_saml_authentication_applications%ROWTYPE;
  alias_value jsonb;
  trust_id uuid;
  trust_revision bigint;
BEGIN
  PERFORM app.private_platform_saml_direct_json_v1(
    p_command,ARRAY['authority','plan','session','continuation','sessionAudience',
      'recoveryRestricted','protectedSessionMaterial','appliedAt','audit','proofDigest'],
    ARRAY['authority','plan','sessionAudience','recoveryRestricted','appliedAt','audit','proofDigest'],2097152
  );
  semantic := p_command-'audit';
  authority := p_command->'authority';
  plan := p_command->'plan';
  provenance := plan->'provenance';
  subject := plan->'subject';
  PERFORM app.private_platform_saml_direct_json_v1(
    authority,ARRAY['transactionId','materialId','expectedVersion','pins',
      'responseIdDigest','assertionIdDigest','sessionIndexDigest','hasSessionIndex',
      'hasSessionMaterial','consumedAt','returnPath'],
    ARRAY['transactionId','materialId','expectedVersion','pins','responseIdDigest',
      'assertionIdDigest','hasSessionIndex','hasSessionMaterial','consumedAt','returnPath'],65536
  );
  transaction_id:=app.private_mfa_decode_base64_v1(authority->>'transactionId',32,32);
  proof_digest:=app.private_mfa_decode_base64_v1(p_command->>'proofDigest',32,32);
  response_digest:=app.private_mfa_decode_base64_v1(authority->>'responseIdDigest',32,32);
  assertion_digest:=app.private_mfa_decode_base64_v1(authority->>'assertionIdDigest',32,32);
  IF (authority->>'hasSessionIndex')::boolean THEN
    session_index_digest:=app.private_mfa_decode_base64_v1(authority->>'sessionIndexDigest',32,32);
  ELSIF authority ? 'sessionIndexDigest' THEN
    RAISE EXCEPTION 'invalid direct platform SAML apply authority' USING ERRCODE='22023';
  END IF;
  observed_at:=(p_command->>'appliedAt')::timestamptz;
  expected_version:=(authority->>'expectedVersion')::bigint;
  material_id:=app.private_mfa_require_uuidv7_v1(authority->>'materialId');
  provider_id:=app.private_mfa_require_uuidv7_v1(provenance#>>'{provider,providerId}');
  user_id:=app.private_mfa_require_uuidv7_v1(provenance->>'userId');
  identity_id:=app.private_mfa_require_uuidv7_v1(provenance->>'externalIdentityId');
  disposition:=plan->>'disposition';
  IF disposition NOT IN ('immediate_session','totp_continuation')
     OR p_command->>'sessionAudience'<>'api'
     OR (p_command->>'recoveryRestricted')::boolean
     OR response_digest=assertion_digest
     OR encode(proof_digest,'hex')=repeat('00',32)
     OR observed_at NOT BETWEEN statement_timestamp()-interval '5 minutes'
                              AND statement_timestamp()+interval '30 seconds'
     OR authority->>'returnPath' !~ '^/[^[:cntrl:]\\]*$'
     OR left(authority->>'returnPath',2)='//'
     OR (disposition='immediate_session')<>(p_command ? 'session')
     OR (disposition='totp_continuation')<>(p_command ? 'continuation') THEN
    RAISE EXCEPTION 'invalid direct platform SAML apply command' USING ERRCODE='22023';
  END IF;
  IF disposition='immediate_session' THEN
    session_id:=app.private_mfa_require_uuidv7_v1(p_command#>>'{session,id}');
  ELSE
    continuation_id:=app.private_mfa_require_uuidv7_v1(p_command#>>'{continuation,id}');
  END IF;
  result:=jsonb_strip_nulls(jsonb_build_object(
    'category','stale','transactionId',authority->'transactionId',
    'proofDigest',p_command->'proofDigest','userId',user_id::text,
    'sessionId',CASE WHEN session_id IS NULL THEN NULL ELSE session_id::text END,
    'continuationId',CASE WHEN continuation_id IS NULL THEN NULL ELSE continuation_id::text END,
    'returnPath',authority->>'returnPath','appliedAt',to_jsonb(observed_at)
  ));
  SELECT application.* INTO application_record
  FROM ONLY public.platform_saml_authentication_applications AS application
  WHERE application.transaction_id=transaction_id
  FOR UPDATE;
  IF FOUND THEN
    IF application_record.proof_digest<>proof_digest
       OR application_record.request_snapshot IS DISTINCT FROM semantic THEN
      RAISE EXCEPTION 'direct platform SAML apply replay collision' USING ERRCODE='23505';
    END IF;
    RETURN jsonb_set(application_record.result_snapshot,'{category}','"already_applied"'::jsonb);
  END IF;
  IF EXISTS (
    SELECT 1 FROM ONLY public.platform_saml_authentication_applications AS replay
    WHERE replay.platform_provider_id=provider_id AND (
      replay.response_id_digest=response_digest OR replay.assertion_id_digest=assertion_digest
      OR (session_index_digest IS NOT NULL AND replay.session_index_digest=session_index_digest)
    )
  ) THEN
    RETURN jsonb_set(result,'{category}','"protocol_replay"'::jsonb);
  END IF;
  SELECT transaction.* INTO STRICT transaction_record
  FROM ONLY public.platform_saml_authentication_transactions AS transaction
  WHERE transaction.transaction_id=transaction_id FOR UPDATE;
  IF transaction_record.state<>'pending' OR transaction_record.version<>expected_version
     OR transaction_record.expires_at<=observed_at
     OR transaction_record.platform_provider_id<>provider_id
     OR app.private_platform_saml_transaction_pins_v1(transaction_record)->'protocol'
          IS DISTINCT FROM authority->'pins'
     OR app.private_platform_saml_transaction_pins_v1(transaction_record)
          IS DISTINCT FROM plan->'pins'
     OR authority->>'returnPath'<>transaction_record.return_path
     OR app.private_platform_saml_direct_configuration_v1(provider_id,authority->'pins') IS NULL THEN
    RETURN result;
  END IF;
  -- Recheck the complete prelinked authority under row locks.  No assertion
  -- claim can create an account or grant a platform role.
  PERFORM 1
  FROM ONLY public.platform_auth_providers AS provider
  JOIN ONLY public.platform_federated_provider_policies AS runtime_policy
    ON runtime_policy.provider_id=provider.id AND runtime_policy.provider_kind='saml'
  JOIN ONLY public.platform_saml_login_policies AS login_policy
    ON login_policy.provider_id=provider.id
  JOIN ONLY public.platform_federated_external_identities AS identity
    ON identity.id=identity_id AND identity.platform_provider_id=provider.id
   AND identity.provider_kind='saml' AND identity.user_id=user_id AND identity.retired_at IS NULL
  JOIN ONLY public.users AS local_user
    ON local_user.id=user_id AND local_user.active
  JOIN ONLY public.user_platform_roles AS grant_record
    ON grant_record.id=app.private_mfa_require_uuidv7_v1(provenance->>'platformAuthorityId')
   AND grant_record.user_id=user_id AND grant_record.revoked_at IS NULL
  JOIN ONLY public.platform_roles AS platform_role
    ON platform_role.id=grant_record.role_id AND platform_role.key='platform_super_admin'
  WHERE provider.id=provider_id AND provider.kind='saml' AND provider.enabled
    AND provider.archived_at IS NULL AND provider.version=transaction_record.provider_revision
    AND runtime_policy.enabled AND NOT runtime_policy.platform_login_enabled
    AND runtime_policy.configuration_revision=transaction_record.configuration_revision
    AND runtime_policy.security_revision=transaction_record.security_revision
    AND runtime_policy.plan_revision=transaction_record.plan_revision
    AND runtime_policy.assurance_policy_revision=transaction_record.assurance_policy_revision
    AND login_policy.enabled AND login_policy.account_mode='existing_identity'
    AND login_policy.revision=transaction_record.login_policy_revision
    AND identity.version=(provenance->>'identityRevision')::bigint
    AND local_user.authentication_revision=(provenance->>'userAuthenticationRevision')::bigint
  FOR UPDATE OF provider,runtime_policy,login_policy,identity,local_user,grant_record;
  IF NOT FOUND THEN RETURN result; END IF;
  IF NOT EXISTS (
    SELECT 1 FROM ONLY public.platform_federated_external_identity_aliases AS alias
    JOIN LATERAL jsonb_array_elements(subject->'aliases') AS supplied(value)
      ON alias.key_version=(supplied.value->>'keyVersion')::integer
     AND alias.subject_digest=app.private_mfa_decode_base64_v1(supplied.value->>'digest',32,32)
    WHERE alias.platform_provider_id=provider_id
      AND alias.external_identity_id=identity_id AND alias.retired_at IS NULL
      AND alias.key_version=(provenance->>'matchedAliasKeyVersion')::integer
  ) THEN RETURN jsonb_set(result,'{category}','"collision"'::jsonb); END IF;
  IF jsonb_array_length(subject->'aliases') NOT BETWEEN 1 AND 16
     OR subject->>'subjectFormat'<>'utf8_exact'
     OR subject#>>'{envelope,format}'<>'utf8_exact' THEN
    RAISE EXCEPTION 'invalid direct platform SAML subject observation' USING ERRCODE='22023';
  END IF;
  IF provenance#>>'{selectedAssurance,trustRuleId}' IS NOT NULL THEN
    trust_id:=app.private_mfa_require_uuidv7_v1(provenance#>>'{selectedAssurance,trustRuleId}');
    trust_revision:=(provenance#>>'{selectedAssurance,trustRuleRevision}')::bigint;
    IF NOT EXISTS (
      SELECT 1 FROM ONLY public.platform_federated_trust_rules AS trust
      WHERE trust.id=trust_id AND trust.provider_id=provider_id
        AND trust.provider_kind='saml' AND trust.revision=trust_revision
        AND trust.enabled AND trust.retired_at IS NULL
      FOR SHARE
    ) THEN RETURN result; END IF;
  END IF;
  IF disposition='totp_continuation' AND NOT EXISTS (
    SELECT 1 FROM ONLY public.totp_credentials AS factor
    WHERE factor.id=app.private_mfa_require_uuidv7_v1(plan#>>'{totp,factorId}')
      AND factor.user_id=user_id
      AND factor.security_revision=(plan#>>'{totp,revision}')::bigint
      AND factor.confirmed_at IS NOT NULL AND factor.disabled_at IS NULL
    FOR UPDATE
  ) THEN RETURN result; END IF;
  PERFORM set_config('app.platform_saml_direct_runtime_write_v1','on',true);
  IF disposition='immediate_session' THEN
    PERFORM app.private_platform_saml_create_session_v1(
      p_command->'session',plan,p_command->>'sessionAudience',observed_at
    );
  ELSE
    INSERT INTO public.platform_saml_post_primary_continuations (
      id,user_id,receipt_digest,authority,authentication_method,action,audience,
      platform_provider_id,external_identity_id,provider_revision,
      login_policy_revision,configuration_revision,security_revision,plan_revision,
      assurance_policy_revision,metadata_revision,metadata_digest,sp_key_revision,
      configuration_digest,user_authentication_revision,identity_version,
      alias_key_version,platform_authority_id,platform_authority_revision,
      platform_floor_policy_id,platform_floor_policy_revision,
      selected_totp_credential_id,selected_totp_security_revision,
      trust_rule_id,trust_rule_revision,state,version,created_at,expires_at
    ) VALUES (
      continuation_id,user_id,
      app.private_mfa_decode_base64_v1(p_command#>>'{continuation,receiptDigest}',32,32),
      'direct_platform_saml','saml','session.create',p_command->>'sessionAudience',
      provider_id,identity_id,transaction_record.provider_revision,
      transaction_record.login_policy_revision,transaction_record.configuration_revision,
      transaction_record.security_revision,transaction_record.plan_revision,
      transaction_record.assurance_policy_revision,transaction_record.metadata_revision,
      transaction_record.metadata_digest,transaction_record.sp_key_revision,
      transaction_record.configuration_digest,
      (provenance->>'userAuthenticationRevision')::bigint,
      (provenance->>'identityRevision')::bigint,
      (provenance->>'matchedAliasKeyVersion')::integer,
      app.private_mfa_require_uuidv7_v1(provenance->>'platformAuthorityId'),
      (provenance->>'platformAuthorityRevision')::bigint,
      transaction_record.platform_floor_policy_id,transaction_record.platform_floor_policy_revision,
      app.private_mfa_require_uuidv7_v1(plan#>>'{totp,factorId}'),
      (plan#>>'{totp,revision}')::bigint,trust_id,trust_revision,
      'pending',1,observed_at,(p_command#>>'{continuation,expiresAt}')::timestamptz
    );
    INSERT INTO public.platform_saml_post_primary_continuation_evidence (
      id,continuation_id,user_id,kind,level,platform_provider_id,
      external_identity_id,trust_rule_id,trust_rule_revision,authenticated_at,expires_at
    ) VALUES (
      uuidv7(),continuation_id,user_id,'platform_provider',
      provenance#>>'{selectedAssurance,level}',provider_id,identity_id,
      trust_id,trust_revision,(provenance#>>'{selectedAssurance,authenticatedAt}')::timestamptz,
      (provenance->>'validUntil')::timestamptz
    );
    INSERT INTO public.platform_saml_post_primary_continuation_policy_pins (
      continuation_id,policy_kind,policy_id,policy_revision
    ) VALUES
      (continuation_id,'login',provider_id,transaction_record.login_policy_revision),
      (continuation_id,'assurance',provider_id,transaction_record.assurance_policy_revision),
      (continuation_id,'platform_floor',transaction_record.platform_floor_policy_id,
        transaction_record.platform_floor_policy_revision);
  END IF;
  FOR alias_value IN SELECT value FROM jsonb_array_elements(subject->'aliases') LOOP
    INSERT INTO public.platform_federated_external_identity_aliases (
      id,platform_provider_id,external_identity_id,key_version,subject_digest,created_at
    ) SELECT uuidv7(),provider_id,identity_id,(alias_value->>'keyVersion')::integer,
      app.private_mfa_decode_base64_v1(alias_value->>'digest',32,32),transaction_timestamp()
    WHERE NOT EXISTS (
      SELECT 1 FROM ONLY public.platform_federated_external_identity_aliases AS alias
      WHERE alias.platform_provider_id=provider_id AND alias.external_identity_id=identity_id
        AND alias.key_version=(alias_value->>'keyVersion')::integer
        AND alias.subject_digest=app.private_mfa_decode_base64_v1(alias_value->>'digest',32,32)
        AND alias.retired_at IS NULL
    );
  END LOOP;
  UPDATE ONLY public.platform_federated_external_identities AS identity
  SET subject_format='utf8_exact',
      subject_ciphertext=app.private_mfa_decode_base64_v1(subject#>>'{envelope,ciphertext}',17,4112),
      subject_nonce=app.private_mfa_decode_base64_v1(subject#>>'{envelope,nonce}',12,12),
      key_version=(subject#>>'{envelope,keyVersion}')::integer,
      last_observed_at=transaction_timestamp(),last_observation_state='known',updated_at=transaction_timestamp()
  WHERE identity.id=identity_id AND identity.platform_provider_id=provider_id
    AND identity.user_id=user_id AND identity.version=(provenance->>'identityRevision')::bigint
    AND identity.retired_at IS NULL;
  IF NOT FOUND THEN RAISE EXCEPTION 'direct platform SAML identity CAS lost' USING ERRCODE='40001'; END IF;
  IF (authority->>'hasSessionMaterial')::boolean THEN
    INSERT INTO public.platform_saml_session_materials (
      id,session_id,continuation_id,user_id,platform_provider_id,external_identity_id,
      login_policy_revision,session_index_digest,key_version,nonce,ciphertext,
      logout_configuration,created_at
    ) VALUES (
      material_id,session_id,continuation_id,user_id,provider_id,identity_id,
      transaction_record.login_policy_revision,session_index_digest,
      (p_command#>>'{protectedSessionMaterial,keyVersion}')::integer,
      app.private_mfa_decode_base64_v1(p_command#>>'{protectedSessionMaterial,nonce}',12,12),
      app.private_mfa_decode_base64_v1(p_command#>>'{protectedSessionMaterial,ciphertext}',17,16384),
      app.private_platform_saml_direct_configuration_v1(provider_id,authority->'pins'),
      observed_at
    );
  ELSIF p_command ? 'protectedSessionMaterial' THEN
    RAISE EXCEPTION 'unexpected direct platform SAML session material' USING ERRCODE='22023';
  END IF;
  result:=jsonb_strip_nulls(jsonb_build_object(
    'category','success','transactionId',authority->'transactionId',
    'proofDigest',p_command->'proofDigest','userId',user_id::text,
    'sessionId',CASE WHEN session_id IS NULL THEN NULL ELSE session_id::text END,
    'continuationId',CASE WHEN continuation_id IS NULL THEN NULL ELSE continuation_id::text END,
    'returnPath',authority->>'returnPath','appliedAt',to_jsonb(observed_at)
  ));
  UPDATE ONLY public.platform_saml_authentication_transactions AS transaction
  SET state='completed',version=transaction.version+1,completed_at=observed_at,failure_reason=NULL
  WHERE transaction.transaction_id=transaction_id AND transaction.state='pending'
    AND transaction.version=expected_version;
  IF NOT FOUND THEN RAISE EXCEPTION 'direct platform SAML apply CAS lost' USING ERRCODE='40001'; END IF;
  INSERT INTO public.platform_saml_authentication_applications (
    id,transaction_id,proof_digest,platform_provider_id,response_id_digest,
    assertion_id_digest,session_index_digest,category,user_id,external_identity_id,
    session_id,continuation_id,request_snapshot,result_snapshot,applied_at
  ) VALUES (
    uuidv7(),transaction_id,proof_digest,provider_id,response_digest,
    assertion_digest,session_index_digest,'success',user_id,identity_id,
    session_id,continuation_id,semantic,result,observed_at
  );
  PERFORM app.private_platform_saml_direct_audit_v1(
    p_command->'audit',uuidv7(),'platform.saml.login.succeeded',
    'platform_identity_account',identity_id,'success',jsonb_build_object(
      'providerId',provider_id,'userId',user_id,'disposition',disposition,
      'providerRevision',transaction_record.provider_revision,
      'loginPolicyRevision',transaction_record.login_policy_revision
    )
  );
  RETURN result;
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RETURN result;
WHEN invalid_text_representation OR numeric_value_out_of_range OR data_exception THEN
  RAISE EXCEPTION 'invalid direct platform SAML apply command' USING ERRCODE='22023';
END;
$function$;
--> statement-breakpoint
DO $assert_v51_saml_apply_successor$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_proc AS routine
    JOIN pg_catalog.pg_roles AS owner ON owner.oid=routine.proowner
    JOIN pg_catalog.pg_language AS language ON language.oid=routine.prolang
    WHERE routine.oid='app.apply_platform_saml_authentication_v1(jsonb)'::pg_catalog.regprocedure
      AND owner.rolname='periapsis_migrator' AND language.lanname='plpgsql'
      AND routine.prokind='f' AND routine.provolatile='v' AND routine.prosecdef
      AND NOT routine.proisstrict AND NOT routine.proleakproof
      AND routine.proparallel='u' AND routine.pronargs=1
      AND routine.pronargdefaults=0
      AND routine.proargtypes='3802'::pg_catalog.oidvector
      AND routine.prorettype='pg_catalog.jsonb'::pg_catalog.regtype
      AND NOT routine.proretset AND routine.proallargtypes IS NULL
      AND routine.proargmodes IS NULL
      AND routine.proargnames IS NOT DISTINCT FROM ARRAY['p_command']::pg_catalog.text[]
      AND routine.provariadic=0 AND routine.prosupport=0
      AND routine.protrftypes IS NULL AND routine.proargdefaults IS NULL
      AND routine.probin IS NULL AND routine.prosqlbody IS NULL
      AND routine.proconfig IS NOT DISTINCT FROM ARRAY['search_path=pg_catalog, public, app']::pg_catalog.text[]
      AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(routine.prosrc,'UTF8')),'hex')='0a283b3ab1a520a5daff1f57ac5038ac0f014bc71ef847d41b7cdab8f94fa40a'
      AND (
        SELECT count(*)=2 AND coalesce(bool_and(
          acl.grantor=routine.proowner
          AND acl.grantee IN (routine.proowner,'periapsis_api'::pg_catalog.regrole)
          AND acl.privilege_type='EXECUTE' AND NOT acl.is_grantable
        ),false)
        FROM pg_catalog.aclexplode(coalesce(routine.proacl,
          pg_catalog.acldefault('f',routine.proowner))) AS acl
      )
  ) THEN
    RAISE EXCEPTION 'SAML apply successor source/catalog mismatch' USING ERRCODE='55000';
  END IF;
END;
$assert_v51_saml_apply_successor$;
--> statement-breakpoint
DO $assert_v51_saml_alias_guard_successor$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_proc AS routine
    JOIN pg_catalog.pg_roles AS owner ON owner.oid=routine.proowner
    JOIN pg_catalog.pg_language AS language ON language.oid=routine.prolang
    WHERE routine.oid='app.guard_platform_federated_alias_v1()'::pg_catalog.regprocedure
      AND owner.rolname='periapsis_migrator' AND language.lanname='plpgsql'
      AND routine.prokind='f' AND routine.provolatile='v' AND routine.prosecdef
      AND NOT routine.proisstrict AND NOT routine.proleakproof
      AND routine.proparallel='u' AND routine.pronargs=0
      AND routine.pronargdefaults=0
      AND routine.proargtypes=''::pg_catalog.oidvector
      AND routine.prorettype='pg_catalog.trigger'::pg_catalog.regtype
      AND NOT routine.proretset AND routine.proallargtypes IS NULL
      AND routine.proargmodes IS NULL
      AND routine.proargnames IS NULL
      AND routine.provariadic=0 AND routine.prosupport=0
      AND routine.protrftypes IS NULL AND routine.proargdefaults IS NULL
      AND routine.probin IS NULL AND routine.prosqlbody IS NULL
      AND routine.proconfig IS NOT DISTINCT FROM ARRAY['search_path=pg_catalog, public, app']::pg_catalog.text[]
      AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(routine.prosrc,'UTF8')),'hex')='002acc80cdaedd5198d01bb2370b709fa88ed19bde5b0fc2aa8bef9bbf4f2309'
      AND (
        SELECT count(*)=1 AND coalesce(bool_and(
          acl.grantor=routine.proowner
          AND acl.grantee=routine.proowner
          AND acl.privilege_type='EXECUTE' AND NOT acl.is_grantable
        ),false)
        FROM pg_catalog.aclexplode(coalesce(routine.proacl,
          pg_catalog.acldefault('f',routine.proowner))) AS acl
      )
  ) THEN
    RAISE EXCEPTION 'SAML alias guard successor source/catalog mismatch' USING ERRCODE='55000';
  END IF;
END;
$assert_v51_saml_alias_guard_successor$;

--> statement-breakpoint
-- Bind only the requested session variable to an explicit local block label.
-- All other SQL keeps the existing ambiguity policy and exact authority checks.
DO $assert_v51_saml_session_lookup_predecessor$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_proc AS routine
    JOIN pg_catalog.pg_roles AS owner ON owner.oid=routine.proowner
    JOIN pg_catalog.pg_language AS language ON language.oid=routine.prolang
    WHERE routine.oid='app.load_platform_saml_session_revalidation_v1(jsonb)'::pg_catalog.regprocedure
      AND owner.rolname='periapsis_migrator' AND language.lanname='plpgsql'
      AND routine.prokind='f' AND routine.provolatile='s' AND routine.prosecdef
      AND NOT routine.proisstrict AND NOT routine.proleakproof
      AND routine.proparallel='u' AND routine.pronargs=1
      AND routine.pronargdefaults=0
      AND routine.proargtypes='3802'::pg_catalog.oidvector
      AND routine.prorettype='pg_catalog.jsonb'::pg_catalog.regtype
      AND NOT routine.proretset AND routine.proallargtypes IS NULL
      AND routine.proargmodes IS NULL
      AND routine.proargnames IS NOT DISTINCT FROM ARRAY['p_lookup']::pg_catalog.text[]
      AND routine.provariadic=0 AND routine.prosupport=0
      AND routine.protrftypes IS NULL AND routine.proargdefaults IS NULL
      AND routine.probin IS NULL AND routine.prosqlbody IS NULL
      AND routine.proconfig IS NOT DISTINCT FROM ARRAY['search_path=pg_catalog, public, app']::pg_catalog.text[]
      AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(routine.prosrc,'UTF8')),'hex')='124dc03bc7c1d21f6c50db1f09daa7c68aefdce030d86c73994f516576421d5b'
      AND (
        SELECT count(*)=2 AND coalesce(bool_and(
          acl.grantor=routine.proowner
          AND acl.grantee IN (routine.proowner,'periapsis_api'::pg_catalog.regrole)
          AND acl.privilege_type='EXECUTE' AND NOT acl.is_grantable
        ),false)
        FROM pg_catalog.aclexplode(coalesce(routine.proacl,
          pg_catalog.acldefault('f',routine.proowner))) AS acl
      )
  ) THEN
    RAISE EXCEPTION 'SAML session lookup predecessor source/catalog mismatch' USING ERRCODE='55000';
  END IF;
END;
$assert_v51_saml_session_lookup_predecessor$;
--> statement-breakpoint
CREATE OR REPLACE FUNCTION app.load_platform_saml_session_revalidation_v1(p_lookup jsonb)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
<<saml_session_lookup>>
DECLARE session_id uuid;
DECLARE observed_at timestamptz;
DECLARE result jsonb;
BEGIN
  PERFORM app.private_platform_saml_direct_json_v1(
    p_lookup,ARRAY['sessionId','observedAt'],ARRAY['sessionId','observedAt'],8192
  );
  session_id:=app.private_mfa_require_uuidv7_v1(p_lookup->>'sessionId');
  observed_at:=(p_lookup->>'observedAt')::timestamptz;
  IF observed_at NOT BETWEEN statement_timestamp()-interval '5 minutes'
                         AND statement_timestamp()+interval '30 seconds'
     OR date_trunc('microseconds',observed_at)<>observed_at THEN
    RAISE EXCEPTION 'invalid direct platform SAML session revalidation lookup'
      USING ERRCODE='22023';
  END IF;
  WITH source AS (
    SELECT session.id,session.rotation_family_id,session.user_id,
      session.active_tenant_id,session.idle_expires_at,session.absolute_expires_at,
      session.revoked_at,state.authority,state.authentication_method,state.audience,
      state.primary_kind,state.session_version,state.user_authentication_revision,
      state.recovery_restricted,state.issued_at,
      provenance.platform_provider_id,provenance.external_identity_id,
      provenance.provider_revision,provenance.login_policy_revision,
      provenance.configuration_revision,provenance.security_revision,
      provenance.plan_revision,provenance.assurance_policy_revision,
      provenance.metadata_revision,provenance.metadata_digest,
      provenance.sp_key_revision,provenance.configuration_digest,
      provenance.identity_version,provenance.alias_key_version,
      provenance.platform_authority_id,provenance.platform_authority_revision,
      provenance.platform_floor_policy_id,provenance.platform_floor_policy_revision
    FROM ONLY public.auth_sessions AS session
    JOIN ONLY public.auth_session_platform_saml_states AS state
      ON state.session_id=session.id
    JOIN ONLY public.auth_session_platform_saml_provenance AS provenance
      ON provenance.session_id=session.id
    WHERE session.id=saml_session_lookup.session_id
  ), current_floor_candidates AS (
    SELECT floor.*
    FROM ONLY public.mfa_policy_revisions AS floor
    WHERE floor.scope='platform_floor' AND floor.tenant_id IS NULL
      AND floor.retired_at IS NULL
    ORDER BY floor.id,floor.revision
  ), current_floor AS (
    SELECT floor.* FROM current_floor_candidates AS floor
    ORDER BY floor.id,floor.revision LIMIT 1
  )
  SELECT jsonb_build_object(
    'session',jsonb_build_object(
      'sessionId',source.id::text,'rotationFamilyId',source.rotation_family_id::text,
      'userId',source.user_id::text,'activeTenantId',source.active_tenant_id,
      'authority',source.authority,'authenticationMethod',source.authentication_method,
      'audience',source.audience,'primaryKind',source.primary_kind,
      'samlStateCount',(SELECT count(*) FROM ONLY public.auth_session_platform_saml_states AS s WHERE s.session_id=source.id),
      'samlProvenanceCount',(SELECT count(*) FROM ONLY public.auth_session_platform_saml_provenance AS p WHERE p.session_id=source.id),
      'oidcStateCount',(SELECT count(*) FROM ONLY public.auth_session_platform_oidc_states AS s WHERE s.session_id=source.id),
      'tenantProvenanceCount',(SELECT count(*) FROM ONLY public.auth_session_federated_provenance AS p WHERE p.session_id=source.id),
      'providerEvidenceCount',(SELECT count(*) FROM ONLY public.auth_session_platform_saml_evidence AS e WHERE e.session_id=source.id AND e.kind='platform_provider'),
      'totpEvidenceCount',(SELECT count(*) FROM ONLY public.auth_session_platform_saml_evidence AS e WHERE e.session_id=source.id AND e.kind='totp'),
      'currentVersion',source.session_version,
      'userAuthenticationRevision',source.user_authentication_revision,
      'recoveryRestricted',source.recovery_restricted,
      'issuedAt',to_jsonb(source.issued_at),'idleExpiresAt',to_jsonb(source.idle_expires_at),
      'absoluteExpiresAt',to_jsonb(source.absolute_expires_at),
      'active',source.revoked_at IS NULL AND source.idle_expires_at>observed_at
        AND source.absolute_expires_at>observed_at,
      'rotationFamilyLive',NOT EXISTS (
        SELECT 1 FROM ONLY public.auth_sessions AS family
        WHERE family.user_id=source.user_id AND family.rotation_family_id=source.rotation_family_id
          AND family.revoked_at IS NOT NULL AND family.id=source.id
      )
    ),
    'authority',(jsonb_build_object(
      'providerId',source.platform_provider_id::text,
      'externalIdentityId',source.external_identity_id::text,'providerKind','saml',
      'accountMode',coalesce(login_policy.account_mode,'disabled'),
      'pinnedProviderRevision',source.provider_revision,'currentProviderRevision',provider.version,
      'pinnedLoginPolicyRevision',source.login_policy_revision,'currentLoginPolicyRevision',login_policy.revision,
      'pinnedConfigurationRevision',source.configuration_revision,'currentConfigurationRevision',runtime_policy.configuration_revision,
      'pinnedSecurityRevision',source.security_revision,'currentSecurityRevision',runtime_policy.security_revision,
      'pinnedPlanRevision',source.plan_revision,'currentPlanRevision',runtime_policy.plan_revision,
      'pinnedAssurancePolicyRevision',source.assurance_policy_revision,'currentAssurancePolicyRevision',runtime_policy.assurance_policy_revision,
      'pinnedMetadataRevision',source.metadata_revision,'currentMetadataRevision',configuration.metadata_revision,
      'pinnedSpKeyRevision',source.sp_key_revision,'currentSpKeyRevision',configuration.sp_key_revision,
      'pinnedUserAuthenticationRevision',source.user_authentication_revision,
      'currentUserAuthenticationRevision',local_user.authentication_revision,
      'pinnedIdentityRevision',source.identity_version,'currentIdentityRevision',identity_record.version,
      'pinnedAliasKeyVersion',source.alias_key_version,
      'currentAliasKeyVersion',coalesce(current_alias.key_version,source.alias_key_version),
      'pinnedMetadataDigest',replace(encode(source.metadata_digest,'base64'),E'\n',''),
      'currentMetadataDigest',replace(encode(metadata.document_digest,'base64'),E'\n',''),
      'pinnedConfigurationDigest',replace(encode(source.configuration_digest,'base64'),E'\n',''),
      'currentConfigurationDigest',replace(encode(
        CASE WHEN source.configuration_revision=runtime_policy.configuration_revision
          AND source.security_revision=runtime_policy.security_revision
          AND source.plan_revision=runtime_policy.plan_revision
          AND source.metadata_revision=configuration.metadata_revision
          AND source.sp_key_revision=configuration.sp_key_revision
        THEN source.configuration_digest
        ELSE sha256(source.configuration_digest || int8send(runtime_policy.configuration_revision)
          || int8send(runtime_policy.security_revision) || int8send(runtime_policy.plan_revision)
          || int8send(configuration.metadata_revision) || int8send(configuration.sp_key_revision)) END,
        'base64'),E'\n',''),
      'identityCurrentProviderId',identity_record.platform_provider_id::text,
      'identityCurrentUserId',identity_record.user_id::text,
      'aliasCurrentProviderId',coalesce(current_alias.platform_provider_id,source.platform_provider_id)::text,
      'aliasCurrentIdentityId',coalesce(current_alias.external_identity_id,source.external_identity_id)::text,
      'pinnedPlatformAuthorityId',source.platform_authority_id::text,
      'currentPlatformAuthorityId',coalesce(current_grant.id,source.platform_authority_id)::text,
      'pinnedPlatformAuthorityRevision',source.platform_authority_revision,
      'currentPlatformAuthorityRevision',1,
      'pinnedPlatformFloorId',source.platform_floor_policy_id::text,
      'currentPlatformFloorId',coalesce(floor.id,pinned_floor.id)::text,
      'pinnedPlatformFloorRevision',source.platform_floor_policy_revision,
      'currentPlatformFloorRevision',coalesce(floor.revision,pinned_floor.revision)) || jsonb_build_object(
      'providerEnabled',provider.enabled AND provider.archived_at IS NULL,
      'platformLoginLive',login_policy.enabled AND login_policy.account_mode='existing_identity',
      'userActive',local_user.active,
      'identityLive',identity_record.provider_kind='saml' AND identity_record.retired_at IS NULL,
      'subjectAliasLive',current_alias.id IS NOT NULL,
      'factorEvidenceLive',NOT EXISTS (
        SELECT 1 FROM ONLY public.auth_session_platform_saml_evidence AS evidence
        LEFT JOIN ONLY public.totp_credentials AS factor
          ON factor.id=evidence.totp_credential_id AND factor.user_id=evidence.user_id
        WHERE evidence.session_id=source.id AND evidence.kind='totp'
          AND (factor.id IS NULL OR factor.security_revision<>evidence.factor_revision
            OR factor.confirmed_at IS NULL OR factor.disabled_at IS NOT NULL)
      ),
      'evidenceFresh',coalesce((
        SELECT bool_and(evidence.authenticated_at<=observed_at
          AND (evidence.expires_at IS NULL OR evidence.expires_at>observed_at))
        FROM ONLY public.auth_session_platform_saml_evidence AS evidence
        WHERE evidence.session_id=source.id
      ),false),
      'policyPinsExact',(SELECT count(*)=3 AND bool_and(
          (pin.policy_kind='login' AND pin.policy_id=source.platform_provider_id AND pin.policy_revision=source.login_policy_revision)
          OR (pin.policy_kind='assurance' AND pin.policy_id=source.platform_provider_id AND pin.policy_revision=source.assurance_policy_revision)
          OR (pin.policy_kind='platform_floor' AND pin.policy_id=source.platform_floor_policy_id AND pin.policy_revision=source.platform_floor_policy_revision)
        ) FROM ONLY public.auth_session_platform_saml_policy_pins AS pin WHERE pin.session_id=source.id),
      'trustEvidenceLive',NOT EXISTS (
        SELECT 1 FROM ONLY public.auth_session_platform_saml_evidence AS evidence
        LEFT JOIN ONLY public.platform_federated_trust_rules AS trust
          ON trust.id=evidence.trust_rule_id AND trust.revision=evidence.trust_rule_revision
        WHERE evidence.session_id=source.id AND evidence.kind='platform_provider'
          AND evidence.trust_rule_id IS NOT NULL
          AND (trust.id IS NULL OR trust.provider_id<>source.platform_provider_id
            OR trust.provider_kind<>'saml' OR NOT trust.enabled OR trust.retired_at IS NOT NULL
            OR trust.level<>evidence.level)
      ),
      'configurationLive',configuration.provider_kind='saml'
        AND configuration.encryption_policy='disabled'
        AND cardinality(configuration.decryption_key_versions)=0,
      'metadataLive',metadata.document_digest=sha256(metadata.document)
        AND metadata.maximum_valid_until>observed_at,
      'spKeyLive',active_key.id IS NOT NULL,
      'platformAuthorityLive',current_grant.id IS NOT NULL,
      'platformFloorLive',floor.id IS NOT NULL AND (SELECT count(*) FROM current_floor_candidates)=1,
      'platformFloor',jsonb_build_object(
        'level',coalesce(floor.level,pinned_floor.level),
        'localRequired',coalesce(floor.local_required,pinned_floor.local_required),
        'freshnessNanoseconds',coalesce(floor.freshness_nanoseconds,pinned_floor.freshness_nanoseconds),
        'enrollmentDeadline',to_jsonb(coalesce(floor.enrollment_deadline,pinned_floor.enrollment_deadline)),
        'policyRevisions',jsonb_build_array(jsonb_build_object(
          'policyId',coalesce(floor.id,pinned_floor.id)::text,
          'revision',coalesce(floor.revision,pinned_floor.revision)
        ))
      ),
      'stepUpTotp',CASE WHEN factor_choice.factor_count=1 THEN jsonb_build_object(
        'factorId',factor_choice.factor_id::text,'revision',factor_choice.security_revision
      ) ELSE NULL END
    )),
    'evidence',coalesce((
      SELECT jsonb_agg(jsonb_strip_nulls(jsonb_build_object(
        'id',evidence.id::text,'userId',evidence.user_id::text,'kind',evidence.kind,
        'level',evidence.level,'platformProviderId',evidence.platform_provider_id,
        'externalIdentityId',evidence.external_identity_id,
        'totpCredentialId',evidence.totp_credential_id,'factorRevision',evidence.factor_revision,
        'trustRuleId',evidence.trust_rule_id,'trustRuleRevision',evidence.trust_rule_revision,
        'authenticatedAt',to_jsonb(evidence.authenticated_at),'expiresAt',to_jsonb(evidence.expires_at)
      )) ORDER BY evidence.kind,evidence.id)
      FROM ONLY public.auth_session_platform_saml_evidence AS evidence
      WHERE evidence.session_id=source.id
    ),'[]'::jsonb),
    'factorAuthorities',coalesce((
      SELECT jsonb_agg(jsonb_build_object(
        'evidenceId',evidence.id::text,'evidenceUserId',evidence.user_id::text,
        'totpCredentialId',evidence.totp_credential_id::text,
        'pinnedSecurityRevision',evidence.factor_revision,
        'currentUserId',factor.user_id::text,'currentSecurityRevision',factor.security_revision,
        'confirmedAt',to_jsonb(factor.confirmed_at),'disabledAt',to_jsonb(factor.disabled_at)
      ) ORDER BY evidence.id)
      FROM ONLY public.auth_session_platform_saml_evidence AS evidence
      JOIN ONLY public.totp_credentials AS factor ON factor.id=evidence.totp_credential_id
      WHERE evidence.session_id=source.id AND evidence.kind='totp'
    ),'[]'::jsonb),
    'trustAuthorities',coalesce((
      SELECT jsonb_agg(jsonb_build_object(
        'evidenceId',evidence.id::text,'trustRuleId',evidence.trust_rule_id::text,
        'pinnedRevision',evidence.trust_rule_revision,
        'currentProviderId',coalesce(trust.provider_id,source.platform_provider_id)::text,
        'currentProviderKind',coalesce(trust.provider_kind,'saml'),
        'currentRevision',coalesce(trust.revision,evidence.trust_rule_revision),
        'currentLevel',coalesce(trust.level,evidence.level),
        'enabled',coalesce(trust.enabled,false),'retiredAt',to_jsonb(trust.retired_at)
      ) ORDER BY evidence.id)
      FROM ONLY public.auth_session_platform_saml_evidence AS evidence
      LEFT JOIN ONLY public.platform_federated_trust_rules AS trust
        ON trust.id=evidence.trust_rule_id AND trust.revision=evidence.trust_rule_revision
      WHERE evidence.session_id=source.id AND evidence.kind='platform_provider'
        AND evidence.trust_rule_id IS NOT NULL
    ),'[]'::jsonb),
    'policyPins',coalesce((
      SELECT jsonb_agg(jsonb_build_object(
        'kind',pin.policy_kind,'id',pin.policy_id::text,'revision',pin.policy_revision
      ) ORDER BY CASE pin.policy_kind WHEN 'login' THEN 1 WHEN 'assurance' THEN 2 ELSE 3 END,pin.policy_id)
      FROM ONLY public.auth_session_platform_saml_policy_pins AS pin
      WHERE pin.session_id=source.id
    ),'[]'::jsonb)
  ) INTO result
  FROM source
  JOIN ONLY public.platform_auth_providers AS provider ON provider.id=source.platform_provider_id
  JOIN ONLY public.platform_federated_provider_policies AS runtime_policy
    ON runtime_policy.provider_id=provider.id AND runtime_policy.provider_kind='saml'
  JOIN ONLY public.platform_saml_login_policies AS login_policy ON login_policy.provider_id=provider.id
  JOIN ONLY public.platform_saml_provider_configurations AS configuration ON configuration.provider_id=provider.id
  JOIN ONLY public.platform_saml_metadata_snapshots AS metadata
    ON metadata.provider_id=provider.id AND metadata.revision=configuration.metadata_revision
  JOIN ONLY public.platform_federated_external_identities AS identity_record
    ON identity_record.id=source.external_identity_id AND identity_record.platform_provider_id=provider.id
  JOIN ONLY public.users AS local_user ON local_user.id=source.user_id
  JOIN ONLY public.mfa_policy_revisions AS pinned_floor
    ON pinned_floor.id=source.platform_floor_policy_id AND pinned_floor.revision=source.platform_floor_policy_revision
  LEFT JOIN current_floor AS floor ON true
  LEFT JOIN LATERAL (
    SELECT alias.* FROM ONLY public.platform_federated_external_identity_aliases AS alias
    WHERE alias.platform_provider_id=provider.id AND alias.external_identity_id=identity_record.id
      AND alias.retired_at IS NULL ORDER BY alias.key_version DESC LIMIT 1
  ) AS current_alias ON true
  LEFT JOIN LATERAL (
    SELECT role_grant.* FROM ONLY public.user_platform_roles AS role_grant
    JOIN ONLY public.platform_roles AS role ON role.id=role_grant.role_id
    WHERE role_grant.user_id=source.user_id AND role_grant.revoked_at IS NULL
      AND role.key='platform_super_admin' ORDER BY role_grant.id LIMIT 1
  ) AS current_grant ON true
  LEFT JOIN LATERAL (
    SELECT sp_key.id
    FROM ONLY public.platform_saml_sp_keys AS sp_key
    JOIN ONLY public.identity_keyring_versions AS root
      ON root.key_version=sp_key.key_version AND root.is_active AND root.retired_at IS NULL
    WHERE sp_key.provider_id=provider.id AND sp_key.revision=configuration.sp_key_revision
      AND sp_key.retired_at IS NULL
      AND (SELECT count(*) FROM ONLY public.platform_saml_sp_certificates AS certificate
           WHERE certificate.key_id=sp_key.id) BETWEEN 1 AND 8
  ) AS active_key ON true
  LEFT JOIN LATERAL (
    SELECT count(*)::integer AS factor_count,
      (array_agg(factor.id ORDER BY factor.id))[1] AS factor_id,
      (array_agg(factor.security_revision ORDER BY factor.id))[1] AS security_revision
    FROM ONLY public.totp_credentials AS factor
    WHERE factor.user_id=source.user_id AND factor.confirmed_at IS NOT NULL
      AND factor.disabled_at IS NULL
  ) AS factor_choice ON true;
  RETURN result;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid direct platform SAML session revalidation lookup'
    USING ERRCODE='22023';
END;
$function$;
--> statement-breakpoint
DO $assert_v51_saml_session_lookup_successor$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_proc AS routine
    JOIN pg_catalog.pg_roles AS owner ON owner.oid=routine.proowner
    JOIN pg_catalog.pg_language AS language ON language.oid=routine.prolang
    WHERE routine.oid='app.load_platform_saml_session_revalidation_v1(jsonb)'::pg_catalog.regprocedure
      AND owner.rolname='periapsis_migrator' AND language.lanname='plpgsql'
      AND routine.prokind='f' AND routine.provolatile='s' AND routine.prosecdef
      AND NOT routine.proisstrict AND NOT routine.proleakproof
      AND routine.proparallel='u' AND routine.pronargs=1
      AND routine.pronargdefaults=0
      AND routine.proargtypes='3802'::pg_catalog.oidvector
      AND routine.prorettype='pg_catalog.jsonb'::pg_catalog.regtype
      AND NOT routine.proretset AND routine.proallargtypes IS NULL
      AND routine.proargmodes IS NULL
      AND routine.proargnames IS NOT DISTINCT FROM ARRAY['p_lookup']::pg_catalog.text[]
      AND routine.provariadic=0 AND routine.prosupport=0
      AND routine.protrftypes IS NULL AND routine.proargdefaults IS NULL
      AND routine.probin IS NULL AND routine.prosqlbody IS NULL
      AND routine.proconfig IS NOT DISTINCT FROM ARRAY['search_path=pg_catalog, public, app']::pg_catalog.text[]
      AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(routine.prosrc,'UTF8')),'hex')='b2c5075c04f6cf2238f710c273ebece45b9c00968f9c444e7e2eb1bac19d4077'
      AND (
        SELECT count(*)=2 AND coalesce(bool_and(
          acl.grantor=routine.proowner
          AND acl.grantee IN (routine.proowner,'periapsis_api'::pg_catalog.regrole)
          AND acl.privilege_type='EXECUTE' AND NOT acl.is_grantable
        ),false)
        FROM pg_catalog.aclexplode(coalesce(routine.proacl,
          pg_catalog.acldefault('f',routine.proowner))) AS acl
      )
  ) THEN
    RAISE EXCEPTION 'SAML session lookup successor source/catalog mismatch' USING ERRCODE='55000';
  END IF;
END;
$assert_v51_saml_session_lookup_successor$;
