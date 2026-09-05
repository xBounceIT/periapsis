-- The sealed v42 metadata projection used an unqualified PL/pgSQL variable
-- named provider_id. PostgreSQL correctly treated `provider.id=provider_id`
-- as ambiguous, so the public metadata endpoint failed closed for every live
-- SAML provider. Keep the predecessor immutable and replace only the affected
-- definition in this append-only successor.
DO $verify_platform_saml_metadata_projection_v42$
DECLARE
  predecessor_ready boolean;
BEGIN
  SELECT count(*)=1 AND coalesce(bool_and(
    function_row.proowner='periapsis_migrator'::regrole
    AND function_row.prosecdef AND function_row.provolatile='s'
    AND function_row.proconfig=ARRAY[
      'search_path=pg_catalog, public, app'
    ]::text[]
    AND pg_catalog.pg_get_function_result(function_row.oid)='jsonb'
    AND pg_catalog.pg_get_function_arguments(function_row.oid)=
      'p_provider_key text'
    AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
      function_row.prosrc,'UTF8'
    )),'hex')=
      'c4562f984383ee7ad2116b4a66c1ec5401b8a19ccd79bc63264c184e81608c4a'
    AND (
      SELECT count(*)=2 AND coalesce(bool_and(
        function_acl.grantor=function_row.proowner
        AND function_acl.grantee IN (
          function_row.proowner,
          (SELECT role.oid FROM pg_catalog.pg_roles AS role
           WHERE role.rolname='periapsis_api')
        )
        AND function_acl.privilege_type='EXECUTE'
        AND NOT function_acl.is_grantable
      ),false)
      FROM pg_catalog.aclexplode(coalesce(
        function_row.proacl,
        pg_catalog.acldefault('f',function_row.proowner)
      )) AS function_acl
    )
  ),false) INTO predecessor_ready
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.load_platform_saml_metadata_projection_v1(text)'::regprocedure;
  IF NOT predecessor_ready THEN
    RAISE EXCEPTION 'direct platform SAML metadata predecessor drifted'
      USING ERRCODE='55000';
  END IF;
END;
$verify_platform_saml_metadata_projection_v42$;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.load_platform_saml_metadata_projection_v1(
  p_provider_key text
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  selected_provider_id uuid;
  protocol_pins jsonb;
  configuration_record jsonb;
BEGIN
  IF p_provider_key IS NULL OR p_provider_key <> lower(btrim(p_provider_key))
     OR p_provider_key !~ '^[a-z][a-z0-9_-]{2,63}$' THEN
    RAISE EXCEPTION 'invalid direct platform SAML metadata provider key'
      USING ERRCODE='22023';
  END IF;
  SELECT provider.id INTO STRICT selected_provider_id
  FROM ONLY public.platform_auth_providers AS provider
  JOIN ONLY public.platform_saml_login_policies AS login_policy
    ON login_policy.provider_id=provider.id
  WHERE provider.key=p_provider_key AND provider.kind='saml'
    AND provider.enabled AND provider.archived_at IS NULL;

  -- Metadata remains available while login is disabled so an administrator can
  -- configure the IdP before the guarded activation. Construct the same safe
  -- projection but never expose the SP private-key envelope.
  SELECT app.private_platform_saml_direct_pins_v1(
      provider.id,provider.version,login_policy.revision,
      runtime_policy.configuration_revision,runtime_policy.security_revision,
      runtime_policy.plan_revision,runtime_policy.assurance_policy_revision,
      configuration.metadata_revision,metadata.document_digest,
      configuration.sp_key_revision,NULL
    ),
    jsonb_build_object(
      'providerKey',provider.key,
      'observedAt',to_jsonb(statement_timestamp()),
      'authentication',jsonb_build_object(
        'provider',jsonb_build_object('scope','platform','providerId',provider.id::text),
        'providerRevision',provider.version,'platformLoginRevision',login_policy.revision,
        'configurationRevision',runtime_policy.configuration_revision,
        'securityRevision',runtime_policy.security_revision,
        'planRevision',runtime_policy.plan_revision,
        'assurancePolicyRevision',runtime_policy.assurance_policy_revision,
        'spEntityId',configuration.sp_entity_id,'acsUrl',configuration.acs_url,
        'spKeyRevision',configuration.sp_key_revision,
        'redirectSignatureAlgorithm',configuration.redirect_signature_algorithm,
        'signaturePolicy',configuration.signature_policy,
        'encryptionPolicy',configuration.encryption_policy,
        'directPlatformDecryptionKeyRevisions','[]'::jsonb,
        'requestedAuthnContexts',to_jsonb(configuration.requested_authn_contexts),
        'subject',jsonb_build_object(
          'source',configuration.subject_source,
          'attributeName',coalesce(configuration.subject_attribute_name,''),
          'attributeNameFormat',coalesce(configuration.subject_attribute_name_format,'')
        ),
        'mapping',jsonb_build_object('scalars','[]'::jsonb,'profiles','[]'::jsonb),
        'trustRules',coalesce((
          SELECT jsonb_agg(jsonb_build_object(
            'id',rule.id::text,'classRef',rule.exact_value,'level',rule.level,
            'revision',rule.revision,
            'maximumAuthenticationAgeSeconds',rule.maximum_authentication_age_seconds
          ) ORDER BY rule.exact_value,rule.id,rule.revision)
          FROM ONLY public.platform_federated_trust_rules AS rule
          WHERE rule.provider_id=provider.id AND rule.provider_kind='saml'
            AND rule.enabled AND rule.retired_at IS NULL
        ),'[]'::jsonb),
        'clockSkewNanoseconds',configuration.clock_skew_nanoseconds,
        'maxAuthenticationAgeNanoseconds',configuration.max_authentication_age_nanoseconds
      ),
      'metadata',jsonb_build_object(
        'expectedEntityId',configuration.expected_entity_id,
        'revision',metadata.revision,
        'document',replace(encode(metadata.document,'base64'),E'\n',''),
        'digest',replace(encode(metadata.document_digest,'base64'),E'\n',''),
        'retrievedAt',to_jsonb(metadata.retrieved_at),
        'maximumValidUntil',to_jsonb(metadata.maximum_valid_until)
      ),
      'platformFloor',jsonb_build_object(
        'id',platform_floor.id::text,'revision',platform_floor.revision,
        'level',platform_floor.level,'localRequired',platform_floor.local_required,
        'freshnessNanoseconds',platform_floor.freshness_nanoseconds,
        'enrollmentDeadline',to_jsonb(platform_floor.enrollment_deadline)
      ),
      'certificates',(
        SELECT coalesce(jsonb_agg(jsonb_build_object(
          'keyId',sp_key.id::text,'keyRevision',sp_key.revision,
          'platformLoginRevision',login_policy.revision,
          'signing',true,'encryption',false,
          'certificateDer',replace(encode(certificate.certificate_der,'base64'),E'\n','')
        ) ORDER BY sp_key.revision,sp_key.id,certificate.sequence),'[]'::jsonb)
        FROM ONLY public.platform_saml_sp_keys AS sp_key
        JOIN ONLY public.platform_saml_sp_certificates AS certificate
          ON certificate.key_id=sp_key.id
        WHERE sp_key.provider_id=provider.id AND sp_key.retired_at IS NULL
          AND sp_key.revision=configuration.sp_key_revision
      )
    )
  INTO protocol_pins,configuration_record
  FROM ONLY public.platform_auth_providers AS provider
  JOIN ONLY public.platform_federated_provider_policies AS runtime_policy
    ON runtime_policy.provider_id=provider.id AND runtime_policy.provider_kind='saml'
  JOIN ONLY public.platform_saml_login_policies AS login_policy
    ON login_policy.provider_id=provider.id
  JOIN ONLY public.platform_saml_provider_configurations AS configuration
    ON configuration.provider_id=provider.id
   AND configuration.version=runtime_policy.configuration_revision
   AND configuration.encryption_policy='disabled'
   AND cardinality(configuration.decryption_key_versions)=0
  JOIN ONLY public.platform_saml_metadata_snapshots AS metadata
    ON metadata.provider_id=provider.id AND metadata.revision=configuration.metadata_revision
   AND metadata.document_digest=sha256(metadata.document)
   AND metadata.maximum_valid_until>statement_timestamp()
  JOIN ONLY public.platform_saml_sp_keys AS selected_key
    ON selected_key.provider_id=provider.id
   AND selected_key.revision=configuration.sp_key_revision
   AND selected_key.retired_at IS NULL
  JOIN ONLY public.identity_keyring_versions AS root_key
    ON root_key.key_version=selected_key.key_version
   AND root_key.is_active AND root_key.retired_at IS NULL
  JOIN ONLY public.mfa_policy_revisions AS platform_floor
    ON platform_floor.scope='platform_floor' AND platform_floor.tenant_id IS NULL
   AND platform_floor.retired_at IS NULL
  WHERE provider.id=selected_provider_id
    AND configuration.sp_entity_id ~ ('/api/v1/auth/platform/saml/' || provider.key || '/metadata$')
    AND configuration.acs_url ~ '/api/v1/auth/platform/saml/acs$'
    AND NOT EXISTS (SELECT 1 FROM ONLY public.platform_saml_attribute_rules AS rule
                    WHERE rule.provider_id=provider.id)
    AND (SELECT count(*) FROM ONLY public.platform_saml_sp_certificates AS certificate
         WHERE certificate.key_id=selected_key.id) BETWEEN 1 AND 8
    AND (SELECT count(*) FROM ONLY public.mfa_policy_revisions AS counted_floor
         WHERE counted_floor.scope='platform_floor' AND counted_floor.tenant_id IS NULL
           AND counted_floor.retired_at IS NULL)=1;
  IF configuration_record IS NULL THEN RETURN NULL; END IF;
  RETURN configuration_record || jsonb_build_object('pins',protocol_pins);
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RETURN NULL;
END;
$function$;
--> statement-breakpoint

ALTER FUNCTION app.load_platform_saml_metadata_projection_v1(text)
  OWNER TO periapsis_migrator;
REVOKE ALL PRIVILEGES ON FUNCTION
  app.load_platform_saml_metadata_projection_v1(text)
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
GRANT EXECUTE ON FUNCTION app.load_platform_saml_metadata_projection_v1(text)
  TO periapsis_api;
--> statement-breakpoint

-- PostgreSQL's default PL/pgSQL variable-conflict mode rejects several v42
-- SAML paths only when their SQL statements are first reached. Each source is
-- pinned before adding the explicit `use_variable` directive, so an upgrade
-- cannot bless a tampered predecessor body through this mechanical repair.
DO $repair_platform_saml_variable_conflicts_v1$
DECLARE
  object_record record;
  definition text;
  source_hash text;
  marker constant text := 'AS $function$' || chr(10) || 'DECLARE';
BEGIN
  FOR object_record IN
    SELECT * FROM (VALUES
      ('app.abort_platform_saml_authentication_transaction_v1(jsonb)',
       '0c2a2bc3587fa15f9217579288981cf435dd35a5cd3c01cb02e0fcdca1450d31',true),
      ('app.begin_platform_saml_post_primary_totp_v1(jsonb)',
       'dca1a855a402dafe1671a3e0270e08fd990b7d786dce9a0dda7348ef2efc4c27',true),
      ('app.load_platform_saml_planning_state_v1(jsonb)',
       '45ec5dc233a75d8e9b048b1a8045e07f9be093981227ee0cf0d9da0d0fd0c424',true),
      ('app.lookup_platform_saml_authentication_transaction_v1(jsonb)',
       'f5b964fedde6a8d32aa19e18cf7803eac99e2fd23e1b54e844a12f07a8b74ec0',true),
      ('app.private_platform_saml_create_session_v1(jsonb,jsonb,text,timestamp with time zone,uuid,bigint,timestamp with time zone,uuid)',
       '7e20a911aec0036f11533e46c7f3c3006bea6289eb1f3a5d3b132b4d8ab66a5d',false),
      ('app.recover_platform_saml_authentication_transaction_create_v1(jsonb)',
       '3567332fa3a0f1bbff56dadefa4d64f8b2caa1b6734e6649914d596117bda331',true),
      ('app.resolve_platform_saml_authentication_configuration_v1(jsonb)',
       '0971759519ea7b70bac52efbe81e15845968a620b11f1c1572710cf7d79097c8',true)
    ) AS expected(signature,source_hash,api_callable)
  LOOP
    SELECT pg_catalog.pg_get_functiondef(function_row.oid),
           pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
             function_row.prosrc,'UTF8')),'hex')
      INTO STRICT definition,source_hash
    FROM pg_catalog.pg_proc AS function_row
    WHERE function_row.oid=object_record.signature::regprocedure;
    IF source_hash<>object_record.source_hash
       OR pg_catalog.strpos(definition,marker)=0
       OR pg_catalog.strpos(definition,'#variable_conflict')<>0 THEN
      RAISE EXCEPTION 'direct platform SAML predecessor % drifted',
        object_record.signature USING ERRCODE='55000';
    END IF;
    definition:=pg_catalog.replace(
      definition,marker,
      'AS $function$' || chr(10) || '#variable_conflict use_variable' ||
      chr(10) || 'DECLARE'
    );
    EXECUTE definition;
    EXECUTE pg_catalog.format(
      'ALTER FUNCTION %s OWNER TO periapsis_migrator',
      object_record.signature::regprocedure
    );
    EXECUTE pg_catalog.format(
      'REVOKE ALL PRIVILEGES ON FUNCTION %s FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier',
      object_record.signature::regprocedure
    );
    IF object_record.api_callable THEN
      EXECUTE pg_catalog.format(
        'GRANT EXECUTE ON FUNCTION %s TO periapsis_api',
        object_record.signature::regprocedure
      );
    END IF;
  END LOOP;
END;
$repair_platform_saml_variable_conflicts_v1$;
--> statement-breakpoint

DO $repair_platform_saml_identity_observation_v1$
DECLARE
  definition text;
  source_hash text;
  predecessor_fragment constant text :=
    'last_observed_at=observed_at,last_observation_state=''known'',updated_at=observed_at';
  successor_fragment constant text :=
    'last_observed_at=transaction_timestamp(),last_observation_state=''known'',' ||
    'updated_at=transaction_timestamp()';
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex')
    INTO STRICT definition,source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.apply_platform_saml_authentication_v1(jsonb)'::regprocedure;
  IF source_hash<>
       '007e4feec0a6caf9995c5a6e0621eeb6566ae875fbfc604725c3f57c28fc9113'
     OR pg_catalog.strpos(definition,predecessor_fragment)=0 THEN
    RAISE EXCEPTION 'direct platform SAML apply predecessor drifted'
      USING ERRCODE='55000';
  END IF;
  definition:=pg_catalog.replace(
    definition,predecessor_fragment,successor_fragment
  );
  EXECUTE definition;
END;
$repair_platform_saml_identity_observation_v1$;
ALTER FUNCTION app.apply_platform_saml_authentication_v1(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL PRIVILEGES ON FUNCTION app.apply_platform_saml_authentication_v1(jsonb)
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
GRANT EXECUTE ON FUNCTION app.apply_platform_saml_authentication_v1(jsonb)
  TO periapsis_api;
