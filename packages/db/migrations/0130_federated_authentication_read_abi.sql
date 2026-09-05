-- Tenant-owned OIDC/SAML configuration, planning and secret read ABI.
-- Every entry point re-authorizes the live provider/binding/policy tuple and
-- returns only operation-shaped JSON.  Raw protocol claims never cross this
-- boundary and encrypted material is exposed only by the two narrow envelope
-- readers.

CREATE FUNCTION app.private_federated_assert_begin_lookup_v1(p_lookup jsonb)
RETURNS void
LANGUAGE plpgsql
IMMUTABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_begin jsonb;
  v_digest_name text;
  v_digest bytea;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_lookup,
    ARRAY['begin','tenantSlug','loginKey'],
    ARRAY['begin','tenantSlug','loginKey'],
    32768
  );
  IF jsonb_typeof(p_lookup -> 'begin') <> 'object'
     OR jsonb_typeof(p_lookup -> 'tenantSlug') <> 'string'
     OR jsonb_typeof(p_lookup -> 'loginKey') <> 'string'
     OR p_lookup ->> 'tenantSlug' <> lower(btrim(p_lookup ->> 'tenantSlug'))
     OR p_lookup ->> 'tenantSlug'
          !~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'
     OR p_lookup ->> 'loginKey' <> lower(btrim(p_lookup ->> 'loginKey'))
     OR p_lookup ->> 'loginKey' !~ '^[a-z][a-z0-9_-]{2,63}$' THEN
    RAISE EXCEPTION 'invalid federated authentication lookup'
      USING ERRCODE = '22023';
  END IF;
  v_begin := p_lookup -> 'begin';
  PERFORM app.private_mfa_assert_json_object_v1(
    v_begin,
    ARRAY['operationRunId','receiptDigest','networkDigest','accountDigest','providerDigest'],
    ARRAY['operationRunId','receiptDigest','networkDigest','accountDigest','providerDigest'],
    16384
  );
  IF jsonb_typeof(v_begin -> 'operationRunId') <> 'string'
     OR app.private_mfa_require_uuidv7_v1(v_begin ->> 'operationRunId') IS NULL THEN
    RAISE EXCEPTION 'invalid federated authentication lookup'
      USING ERRCODE = '22023';
  END IF;
  FOREACH v_digest_name IN ARRAY ARRAY[
    'receiptDigest','networkDigest','accountDigest','providerDigest'
  ] LOOP
    IF jsonb_typeof(v_begin -> v_digest_name) <> 'string' THEN
      RAISE EXCEPTION 'invalid federated authentication lookup'
        USING ERRCODE = '22023';
    END IF;
    v_digest := app.private_mfa_decode_base64_v1(
      v_begin ->> v_digest_name, 32, 32
    );
    IF encode(v_digest, 'hex') = repeat('00', 32) THEN
      RAISE EXCEPTION 'invalid federated authentication lookup'
        USING ERRCODE = '22023';
    END IF;
  END LOOP;
  IF (v_begin ->> 'receiptDigest') IN (
       v_begin ->> 'networkDigest', v_begin ->> 'accountDigest',
       v_begin ->> 'providerDigest'
     ) OR (v_begin ->> 'networkDigest') IN (
       v_begin ->> 'accountDigest', v_begin ->> 'providerDigest'
     ) OR v_begin ->> 'accountDigest' = v_begin ->> 'providerDigest' THEN
    RAISE EXCEPTION 'invalid federated authentication lookup'
      USING ERRCODE = '22023';
  END IF;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_tenant_oidc_configuration_record_v1(
  p_tenant_id uuid,
  p_provider_id uuid,
  p_binding_id uuid,
  p_expected_pins jsonb DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_record jsonb;
  v_live_pins jsonb;
BEGIN
  SELECT jsonb_build_object(
    'authorization', jsonb_build_object(
      'provider', jsonb_build_object(
        'scope','tenant','tenantId',provider.tenant_id::text,
        'providerId',provider.id::text,'bindingId',binding.id::text
      ),
      'providerRevision',provider.version,
      'bindingRevision',binding.version,
      'configurationRevision',policy.configuration_revision,
      'securityRevision',policy.security_revision,
      'mappingRevision',binding.mapping_revision,
      'authorizationRevision',binding.auth_revision,
      'assurancePolicyRevision',policy.assurance_policy_revision,
      'clientSecretRevision',configuration.client_secret_revision,
      'clientId',configuration.client_id,
      'redirectUri',configuration.redirect_uri,
      'postLogoutRedirectUri',configuration.post_logout_redirect_uri,
      'extraScopes',to_jsonb(configuration.extra_scopes),
      'allowRefreshToken',configuration.allow_refresh_token,
      'useUserInfo',configuration.use_user_info
    ),
    'issuer',configuration.issuer,
    'discoveryRevision',discovery.revision,
    'discoveryDocument',replace(encode(discovery.document,'base64'), E'\n',''),
    'discoveryDigest',replace(encode(discovery.document_digest,'base64'), E'\n',''),
    'discoveryCache',jsonb_build_object(
      'retrievedAt',to_jsonb(discovery.retrieved_at),
      'freshUntil',to_jsonb(discovery.fresh_until),
      'cacheable',discovery.cacheable,
      'mustRevalidate',discovery.must_revalidate
    ),
    'discoveryPolicy',jsonb_build_object(
      'clientAuthentication',discovery.client_authentication,
      'signingAlgorithms',to_jsonb(discovery.signing_algorithms)
    ),
    'jwksDocument',replace(encode(jwks.document,'base64'), E'\n',''),
    'jwksDigest',replace(encode(jwks.document_digest,'base64'), E'\n',''),
    'jwksRevision',jwks.revision,
    'jwksCache',jsonb_build_object(
      'retrievedAt',to_jsonb(jwks.retrieved_at),
      'freshUntil',to_jsonb(jwks.fresh_until),
      'cacheable',jwks.cacheable,
      'mustRevalidate',jwks.must_revalidate
    ),
    'idTokenClaims',app.private_tenant_oidc_claim_policy_v1(
      provider.tenant_id, provider.id, 'id_token'
    ),
    'userInfoClaims',app.private_tenant_oidc_claim_policy_v1(
      provider.tenant_id, provider.id, 'userinfo'
    )
  ), jsonb_build_object(
    'provider',jsonb_build_object(
      'scope','tenant','tenantId',provider.tenant_id::text,
      'providerId',provider.id::text,'bindingId',binding.id::text
    ),
    'providerRevision',provider.version,
    'bindingRevision',binding.version,
    'configurationRevision',policy.configuration_revision,
    'securityRevision',policy.security_revision,
    'mappingRevision',binding.mapping_revision,
    'authorizationRevision',binding.auth_revision,
    'assurancePolicyRevision',policy.assurance_policy_revision,
    'clientSecretRevision',configuration.client_secret_revision,
    'discoveryRevision',discovery.revision,
    'discoveryDigest',replace(encode(discovery.document_digest,'base64'), E'\n',''),
    'jwksRevision',jwks.revision,
    'jwksDigest',replace(encode(jwks.document_digest,'base64'), E'\n','')
  )
  INTO v_record, v_live_pins
  FROM public.tenant_auth_providers AS provider
  JOIN public.tenants AS tenant
    ON tenant.id = provider.tenant_id AND tenant.status = 'active'
  JOIN public.tenant_auth_provider_bindings AS binding
    ON binding.tenant_id = provider.tenant_id
   AND binding.provider_id = provider.id
   AND binding.id = p_binding_id
   AND binding.enabled AND binding.archived_at IS NULL
   AND binding.current_access_epoch_id IS NOT NULL
  JOIN public.tenant_federated_provider_policies AS policy
    ON policy.tenant_id = provider.tenant_id
   AND policy.provider_id = provider.id
   AND policy.binding_id = binding.id
   AND policy.provider_kind = 'oidc'
   AND policy.enabled
  JOIN public.tenant_oidc_provider_configurations AS configuration
    ON configuration.tenant_id = provider.tenant_id
   AND configuration.provider_id = provider.id
   AND configuration.version = policy.configuration_revision
  JOIN public.tenant_oidc_discovery_snapshots AS discovery
    ON discovery.tenant_id = configuration.tenant_id
   AND discovery.provider_id = configuration.provider_id
   AND discovery.revision = configuration.discovery_revision
  JOIN public.tenant_oidc_jwks_snapshots AS jwks
    ON jwks.tenant_id = configuration.tenant_id
   AND jwks.provider_id = configuration.provider_id
   AND jwks.revision = configuration.jwks_revision
  JOIN public.tenant_oidc_client_secrets AS secret
    ON secret.tenant_id = configuration.tenant_id
   AND secret.provider_id = configuration.provider_id
   AND secret.revision = configuration.client_secret_revision
   AND secret.retired_at IS NULL
  JOIN public.identity_keyring_versions AS keyring
    ON keyring.key_version = secret.key_version
   AND keyring.retired_at IS NULL
  JOIN public.tenant_identity_provider_access_epochs AS access_epoch
    ON access_epoch.tenant_id = binding.tenant_id
   AND access_epoch.id = binding.current_access_epoch_id
   AND access_epoch.binding_id = binding.id
   AND access_epoch.provider_id = provider.id
   AND access_epoch.ended_at IS NULL
  WHERE provider.tenant_id = p_tenant_id
    AND provider.id = p_provider_id
    AND provider.kind = 'oidc'
    AND provider.enabled AND provider.archived_at IS NULL;

  IF v_record IS NULL
     OR (p_expected_pins IS NOT NULL AND p_expected_pins IS DISTINCT FROM v_live_pins) THEN
    RETURN NULL;
  END IF;
  RETURN v_record;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_tenant_oidc_claim_policy_v1(
  p_tenant_id uuid,
  p_provider_id uuid,
  p_source text
)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT jsonb_build_object(
    'Scalars',coalesce((
      SELECT jsonb_agg(jsonb_build_object(
        'Claim',rule.claim_name,'Required',rule.required
      ) ORDER BY rule.sequence)
      FROM public.tenant_oidc_claim_rules AS rule
      WHERE rule.tenant_id = p_tenant_id AND rule.provider_id = p_provider_id
        AND rule.source = p_source AND rule.kind = 'scalar'
    ),'[]'::jsonb),
    'Profiles',coalesce((
      SELECT jsonb_agg(jsonb_build_object(
        'Claim',rule.claim_name,'Field',rule.profile_field,
        'Required',rule.required
      ) ORDER BY rule.sequence)
      FROM public.tenant_oidc_claim_rules AS rule
      WHERE rule.tenant_id = p_tenant_id AND rule.provider_id = p_provider_id
        AND rule.source = p_source AND rule.kind = 'profile'
    ),'[]'::jsonb),
    'Groups',(
      SELECT jsonb_build_object('Claim',rule.claim_name,'Required',rule.required)
      FROM public.tenant_oidc_claim_rules AS rule
      WHERE rule.tenant_id = p_tenant_id AND rule.provider_id = p_provider_id
        AND rule.source = p_source AND rule.kind = 'groups'
    ),
    'ACR',(
      SELECT jsonb_build_object('Claim',rule.claim_name,'Required',rule.required)
      FROM public.tenant_oidc_claim_rules AS rule
      WHERE rule.tenant_id = p_tenant_id AND rule.provider_id = p_provider_id
        AND rule.source = p_source AND rule.kind = 'acr'
    ),
    'AMR',(
      SELECT jsonb_build_object('Claim',rule.claim_name,'Required',rule.required)
      FROM public.tenant_oidc_claim_rules AS rule
      WHERE rule.tenant_id = p_tenant_id AND rule.provider_id = p_provider_id
        AND rule.source = p_source AND rule.kind = 'amr'
    )
  )
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_tenant_saml_attribute_policy_v1(
  p_tenant_id uuid,
  p_provider_id uuid
)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT jsonb_build_object(
    'Scalars',coalesce((
      SELECT jsonb_agg(jsonb_build_object(
        'Name',rule.attribute_name,'NameFormat',rule.attribute_name_format,
        'Required',rule.required
      ) ORDER BY rule.sequence)
      FROM public.tenant_saml_attribute_rules AS rule
      WHERE rule.tenant_id = p_tenant_id AND rule.provider_id = p_provider_id
        AND rule.kind = 'scalar'
    ),'[]'::jsonb),
    'Profiles',coalesce((
      SELECT jsonb_agg(jsonb_build_object(
        'Name',rule.attribute_name,'NameFormat',rule.attribute_name_format,
        'Field',rule.profile_field,'Required',rule.required
      ) ORDER BY rule.sequence)
      FROM public.tenant_saml_attribute_rules AS rule
      WHERE rule.tenant_id = p_tenant_id AND rule.provider_id = p_provider_id
        AND rule.kind = 'profile'
    ),'[]'::jsonb),
    'Groups',(
      SELECT jsonb_build_object(
        'Name',rule.attribute_name,'NameFormat',rule.attribute_name_format,
        'Required',rule.required
      )
      FROM public.tenant_saml_attribute_rules AS rule
      WHERE rule.tenant_id = p_tenant_id AND rule.provider_id = p_provider_id
        AND rule.kind = 'groups'
    )
  )
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_tenant_saml_configuration_record_v1(
  p_tenant_id uuid,
  p_provider_id uuid,
  p_binding_id uuid,
  p_expected_pins jsonb DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_record jsonb;
  v_live_pins jsonb;
BEGIN
  SELECT jsonb_build_object(
    'authentication',jsonb_build_object(
      'provider',jsonb_build_object(
        'scope','tenant','tenantId',provider.tenant_id::text,
        'providerId',provider.id::text,'bindingId',binding.id::text
      ),
      'providerRevision',provider.version,
      'bindingRevision',binding.version,
      'configurationRevision',policy.configuration_revision,
      'securityRevision',policy.security_revision,
      'mappingRevision',binding.mapping_revision,
      'authorizationRevision',binding.auth_revision,
      'assurancePolicyRevision',policy.assurance_policy_revision,
      'spEntityId',configuration.sp_entity_id,
      'acsUrl',configuration.acs_url,
      'spKeyRevision',configuration.sp_key_revision,
      'redirectSignatureAlgorithm',configuration.redirect_signature_algorithm,
      'signaturePolicy',configuration.signature_policy,
      'encryptionPolicy',configuration.encryption_policy,
      'decryptionKeyVersions',to_jsonb(configuration.decryption_key_versions),
      'requestedAuthnContexts',to_jsonb(configuration.requested_authn_contexts),
      'subject',jsonb_build_object(
        'Source',configuration.subject_source,
        'AttributeName',coalesce(configuration.subject_attribute_name,''),
        'AttributeNameFormat',coalesce(configuration.subject_attribute_name_format,'')
      ),
      'mapping',app.private_tenant_saml_attribute_policy_v1(
        provider.tenant_id,provider.id
      ),
      'trustRules',coalesce((
        SELECT jsonb_agg(jsonb_build_object(
          'ClassRef',rule.exact_value,'Level',rule.level,
          'Revision',rule.revision,
          'MaxAge',(rule.maximum_authentication_age_seconds::bigint * 1000000000)
        ) ORDER BY rule.exact_value,rule.id)
        FROM public.tenant_federated_trust_rules AS rule
        WHERE rule.tenant_id = provider.tenant_id
          AND rule.provider_id = provider.id
          AND rule.binding_id = binding.id
          AND rule.provider_kind = 'saml'
          AND rule.enabled AND rule.retired_at IS NULL
      ),'[]'::jsonb),
      'clockSkewNanoseconds',configuration.clock_skew_nanoseconds,
      'maxAuthenticationAgeNanoseconds',configuration.max_authentication_age_nanoseconds
    ),
    'expectedEntityId',configuration.expected_entity_id,
    'metadataRevision',metadata.revision,
    'metadataDocument',replace(encode(metadata.document,'base64'), E'\n',''),
    'metadataDigest',replace(encode(metadata.document_digest,'base64'), E'\n',''),
    'metadataRetrievedAt',to_jsonb(metadata.retrieved_at),
    'metadataMaximumValidUntil',to_jsonb(metadata.maximum_valid_until)
  ), jsonb_build_object(
    'provider',jsonb_build_object(
      'scope','tenant','tenantId',provider.tenant_id::text,
      'providerId',provider.id::text,'bindingId',binding.id::text
    ),
    'providerRevision',provider.version,
    'bindingRevision',binding.version,
    'configurationRevision',policy.configuration_revision,
    'securityRevision',policy.security_revision,
    'mappingRevision',binding.mapping_revision,
    'authorizationRevision',binding.auth_revision,
    'assurancePolicyRevision',policy.assurance_policy_revision,
    'metadataRevision',metadata.revision,
    'metadataDigest',replace(encode(metadata.document_digest,'base64'), E'\n',''),
    'spKeyRevision',sp_key.revision,
    'configurationDigest',p_expected_pins ->> 'configurationDigest'
  )
  INTO v_record, v_live_pins
  FROM public.tenant_auth_providers AS provider
  JOIN public.tenants AS tenant
    ON tenant.id = provider.tenant_id AND tenant.status = 'active'
  JOIN public.tenant_auth_provider_bindings AS binding
    ON binding.tenant_id = provider.tenant_id
   AND binding.provider_id = provider.id
   AND binding.id = p_binding_id
   AND binding.enabled AND binding.archived_at IS NULL
   AND binding.current_access_epoch_id IS NOT NULL
  JOIN public.tenant_federated_provider_policies AS policy
    ON policy.tenant_id = provider.tenant_id
   AND policy.provider_id = provider.id
   AND policy.binding_id = binding.id
   AND policy.provider_kind = 'saml'
   AND policy.enabled
  JOIN public.tenant_saml_provider_configurations AS configuration
    ON configuration.tenant_id = provider.tenant_id
   AND configuration.provider_id = provider.id
   AND configuration.version = policy.configuration_revision
  JOIN public.tenant_saml_metadata_snapshots AS metadata
    ON metadata.tenant_id = configuration.tenant_id
   AND metadata.provider_id = configuration.provider_id
   AND metadata.revision = configuration.metadata_revision
  JOIN public.tenant_saml_sp_keys AS sp_key
    ON sp_key.tenant_id = configuration.tenant_id
   AND sp_key.provider_id = configuration.provider_id
   AND sp_key.revision = configuration.sp_key_revision
   AND sp_key.retired_at IS NULL
  JOIN public.identity_keyring_versions AS keyring
    ON keyring.key_version = sp_key.key_version
   AND keyring.retired_at IS NULL
  JOIN public.tenant_identity_provider_access_epochs AS access_epoch
    ON access_epoch.tenant_id = binding.tenant_id
   AND access_epoch.id = binding.current_access_epoch_id
   AND access_epoch.binding_id = binding.id
   AND access_epoch.provider_id = provider.id
   AND access_epoch.ended_at IS NULL
  WHERE provider.tenant_id = p_tenant_id
    AND provider.id = p_provider_id
    AND provider.kind = 'saml'
    AND provider.enabled AND provider.archived_at IS NULL;

  IF v_record IS NULL THEN
    RETURN NULL;
  END IF;
  IF p_expected_pins IS NOT NULL THEN
    -- configurationDigest is a protocol canonicalization digest computed by
    -- the Go kernel; the database binds it to the transaction but cannot
    -- recompute it from semantically equivalent administrator input.
    IF (v_live_pins - 'configurationDigest') IS DISTINCT FROM
       (p_expected_pins - 'configurationDigest') THEN
      RETURN NULL;
    END IF;
  END IF;
  RETURN v_record;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.begin_tenant_oidc_authentication_v1(p_lookup jsonb)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_result jsonb;
BEGIN
  PERFORM app.private_federated_assert_begin_lookup_v1(p_lookup);
  SELECT app.private_tenant_oidc_configuration_record_v1(
           tenant.id,provider.id,binding.id,NULL
         )
    INTO v_result
  FROM public.tenants AS tenant
  JOIN public.tenant_auth_provider_bindings AS binding
    ON binding.tenant_id = tenant.id
   AND binding.key = p_lookup ->> 'loginKey'
  JOIN public.tenant_auth_providers AS provider
    ON provider.tenant_id = binding.tenant_id
   AND provider.id = binding.provider_id
   AND provider.kind = 'oidc'
  WHERE tenant.slug = p_lookup ->> 'tenantSlug'
    AND tenant.status = 'active';
  RETURN v_result;
EXCEPTION WHEN invalid_text_representation OR data_exception THEN
  RAISE EXCEPTION 'invalid federated authentication lookup'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.begin_tenant_saml_authentication_v1(p_lookup jsonb)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_result jsonb;
BEGIN
  PERFORM app.private_federated_assert_begin_lookup_v1(p_lookup);
  SELECT app.private_tenant_saml_configuration_record_v1(
           tenant.id,provider.id,binding.id,NULL
         )
    INTO v_result
  FROM public.tenants AS tenant
  JOIN public.tenant_auth_provider_bindings AS binding
    ON binding.tenant_id = tenant.id
   AND binding.key = p_lookup ->> 'loginKey'
  JOIN public.tenant_auth_providers AS provider
    ON provider.tenant_id = binding.tenant_id
   AND provider.id = binding.provider_id
   AND provider.kind = 'saml'
  WHERE tenant.slug = p_lookup ->> 'tenantSlug'
    AND tenant.status = 'active';
  RETURN v_result;
EXCEPTION WHEN invalid_text_representation OR data_exception THEN
  RAISE EXCEPTION 'invalid federated authentication lookup'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.resolve_tenant_oidc_authentication_v1(p_lookup jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_transaction_id bytea;
  v_expected_version bigint;
  v_transaction public.tenant_federated_authentication_transactions%ROWTYPE;
  v_expected_pins jsonb;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_lookup,ARRAY['transactionId','expectedVersion','pins'],
    ARRAY['transactionId','expectedVersion','pins'],65536
  );
  IF jsonb_typeof(p_lookup -> 'transactionId') <> 'string'
     OR jsonb_typeof(p_lookup -> 'expectedVersion') <> 'number'
     OR jsonb_typeof(p_lookup -> 'pins') <> 'object' THEN
    RAISE EXCEPTION 'invalid OIDC callback configuration lookup'
      USING ERRCODE = '22023';
  END IF;
  v_transaction_id := app.private_mfa_decode_base64_v1(
    p_lookup ->> 'transactionId',32,32
  );
  v_expected_version := (p_lookup ->> 'expectedVersion')::bigint;
  IF encode(v_transaction_id,'hex') = repeat('00',32)
     OR v_expected_version <= 0 THEN
    RAISE EXCEPTION 'invalid OIDC callback configuration lookup'
      USING ERRCODE = '22023';
  END IF;

  SELECT transaction_row.* INTO v_transaction
  FROM public.tenant_federated_authentication_transactions AS transaction_row
  WHERE transaction_row.transaction_id = v_transaction_id
    AND transaction_row.protocol = 'oidc'
    AND transaction_row.version = v_expected_version
    AND transaction_row.state = 'claimed'
    AND transaction_row.expires_at > transaction_timestamp();
  IF NOT FOUND THEN RETURN NULL; END IF;

  v_expected_pins := jsonb_build_object(
    'provider',jsonb_build_object(
      'scope','tenant','tenantId',v_transaction.tenant_id::text,
      'providerId',v_transaction.provider_id::text,
      'bindingId',v_transaction.binding_id::text
    ),
    'providerRevision',v_transaction.provider_revision,
    'bindingRevision',v_transaction.binding_revision,
    'configurationRevision',v_transaction.configuration_revision,
    'securityRevision',v_transaction.security_revision,
    'mappingRevision',v_transaction.mapping_revision,
    'authorizationRevision',v_transaction.authorization_revision,
    'assurancePolicyRevision',v_transaction.assurance_policy_revision,
    'clientSecretRevision',v_transaction.client_secret_revision,
    'discoveryRevision',v_transaction.discovery_revision,
    'discoveryDigest',replace(encode(v_transaction.discovery_digest,'base64'),E'\n',''),
    'jwksRevision',v_transaction.jwks_revision,
    'jwksDigest',replace(encode(v_transaction.jwks_digest,'base64'),E'\n','')
  );
  IF p_lookup -> 'pins' IS DISTINCT FROM v_expected_pins THEN RETURN NULL; END IF;
  RETURN app.private_tenant_oidc_configuration_record_v1(
    v_transaction.tenant_id,v_transaction.provider_id,
    v_transaction.binding_id,v_expected_pins
  );
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid OIDC callback configuration lookup'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.resolve_tenant_saml_authentication_v1(p_lookup jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_transaction_id bytea;
  v_expected_version bigint;
  v_transaction public.tenant_federated_authentication_transactions%ROWTYPE;
  v_expected_pins jsonb;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_lookup,ARRAY['transactionId','expectedVersion','pins'],
    ARRAY['transactionId','expectedVersion','pins'],65536
  );
  IF jsonb_typeof(p_lookup -> 'transactionId') <> 'string'
     OR jsonb_typeof(p_lookup -> 'expectedVersion') <> 'number'
     OR jsonb_typeof(p_lookup -> 'pins') <> 'object' THEN
    RAISE EXCEPTION 'invalid SAML callback configuration lookup'
      USING ERRCODE = '22023';
  END IF;
  v_transaction_id := app.private_mfa_decode_base64_v1(
    p_lookup ->> 'transactionId',32,32
  );
  v_expected_version := (p_lookup ->> 'expectedVersion')::bigint;
  IF encode(v_transaction_id,'hex') = repeat('00',32)
     OR v_expected_version <= 0 THEN
    RAISE EXCEPTION 'invalid SAML callback configuration lookup'
      USING ERRCODE = '22023';
  END IF;

  SELECT transaction_row.* INTO v_transaction
  FROM public.tenant_federated_authentication_transactions AS transaction_row
  WHERE transaction_row.transaction_id = v_transaction_id
    AND transaction_row.protocol = 'saml'
    AND transaction_row.version = v_expected_version
    AND transaction_row.state = 'pending'
    AND transaction_row.expires_at > transaction_timestamp();
  IF NOT FOUND THEN RETURN NULL; END IF;

  v_expected_pins := jsonb_build_object(
    'provider',jsonb_build_object(
      'scope','tenant','tenantId',v_transaction.tenant_id::text,
      'providerId',v_transaction.provider_id::text,
      'bindingId',v_transaction.binding_id::text
    ),
    'providerRevision',v_transaction.provider_revision,
    'bindingRevision',v_transaction.binding_revision,
    'configurationRevision',v_transaction.configuration_revision,
    'securityRevision',v_transaction.security_revision,
    'mappingRevision',v_transaction.mapping_revision,
    'authorizationRevision',v_transaction.authorization_revision,
    'assurancePolicyRevision',v_transaction.assurance_policy_revision,
    'metadataRevision',v_transaction.metadata_revision,
    'metadataDigest',replace(encode(v_transaction.metadata_digest,'base64'),E'\n',''),
    'spKeyRevision',v_transaction.sp_key_revision,
    'configurationDigest',replace(encode(v_transaction.configuration_digest,'base64'),E'\n','')
  );
  IF p_lookup -> 'pins' IS DISTINCT FROM v_expected_pins THEN RETURN NULL; END IF;
  RETURN app.private_tenant_saml_configuration_record_v1(
    v_transaction.tenant_id,v_transaction.provider_id,
    v_transaction.binding_id,v_expected_pins
  );
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid SAML callback configuration lookup'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.load_oidc_trust_snapshot_v1(p_lookup jsonb)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_tenant_id uuid;
  v_provider_id uuid;
  v_binding_id uuid;
  v_result jsonb;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_lookup,
    ARRAY['tenantId','provider','providerRevision','bindingRevision',
      'securityRevision','assurancePolicyRevision'],
    ARRAY['tenantId','provider','providerRevision','bindingRevision',
      'securityRevision','assurancePolicyRevision'],32768
  );
  PERFORM app.private_mfa_assert_json_object_v1(
    p_lookup -> 'provider',ARRAY['scope','tenantId','providerId','bindingId'],
    ARRAY['scope','tenantId','providerId','bindingId'],8192
  );
  IF p_lookup #>> '{provider,scope}' <> 'tenant'
     OR p_lookup ->> 'tenantId' IS DISTINCT FROM p_lookup #>> '{provider,tenantId}' THEN
    RAISE EXCEPTION 'invalid OIDC trust lookup' USING ERRCODE = '22023';
  END IF;
  v_tenant_id := app.private_mfa_require_uuidv7_v1(p_lookup ->> 'tenantId');
  v_provider_id := app.private_mfa_require_uuidv7_v1(p_lookup #>> '{provider,providerId}');
  v_binding_id := app.private_mfa_require_uuidv7_v1(p_lookup #>> '{provider,bindingId}');

  WITH live AS (
    SELECT provider.version AS provider_revision,
           binding.version AS binding_revision,
           policy.security_revision,policy.assurance_policy_revision
    FROM public.tenant_auth_providers AS provider
    JOIN public.tenants AS tenant
      ON tenant.id = provider.tenant_id AND tenant.status = 'active'
    JOIN public.tenant_auth_provider_bindings AS binding
      ON binding.tenant_id = provider.tenant_id
     AND binding.provider_id = provider.id AND binding.id = v_binding_id
     AND binding.enabled AND binding.archived_at IS NULL
     AND binding.current_access_epoch_id IS NOT NULL
    JOIN public.tenant_federated_provider_policies AS policy
      ON policy.tenant_id = provider.tenant_id
     AND policy.provider_id = provider.id
     AND policy.binding_id = binding.id
     AND policy.provider_kind = 'oidc' AND policy.enabled
    WHERE provider.tenant_id = v_tenant_id AND provider.id = v_provider_id
      AND provider.kind = 'oidc' AND provider.enabled
      AND provider.archived_at IS NULL
      AND provider.version = (p_lookup ->> 'providerRevision')::bigint
      AND binding.version = (p_lookup ->> 'bindingRevision')::bigint
      AND policy.security_revision = (p_lookup ->> 'securityRevision')::bigint
      AND policy.assurance_policy_revision =
          (p_lookup ->> 'assurancePolicyRevision')::bigint
  )
  SELECT jsonb_build_object(
    'lookup',p_lookup,
    'rules',coalesce((
      SELECT jsonb_agg(jsonb_build_object(
        'ruleId',rule.id::text,'revision',rule.revision,
        'enabled',rule.enabled,'level',rule.level,
        'acr',CASE WHEN rule.exact_value IS NULL THEN 'null'::jsonb
                   ELSE to_jsonb(rule.exact_value) END,
        'requiredAmr',to_jsonb(rule.required_values),
        'maximumAuthenticationAgeSeconds',
          rule.maximum_authentication_age_seconds
      ) ORDER BY rule.id,rule.revision)
      FROM public.tenant_federated_trust_rules AS rule
      WHERE rule.tenant_id = v_tenant_id AND rule.provider_id = v_provider_id
        AND rule.binding_id = v_binding_id AND rule.provider_kind = 'oidc'
        AND rule.retired_at IS NULL
    ),'[]'::jsonb)
  ) INTO v_result FROM live;
  RETURN v_result;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid OIDC trust lookup' USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.load_oidc_client_secret_envelope_v1(p_lookup jsonb)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_tenant_id uuid;
  v_provider_id uuid;
  v_binding_id uuid;
  v_revision bigint;
  v_result jsonb;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_lookup,ARRAY['provider','revision'],ARRAY['provider','revision'],16384
  );
  PERFORM app.private_mfa_assert_json_object_v1(
    p_lookup -> 'provider',ARRAY['scope','tenantId','providerId','bindingId'],
    ARRAY['scope','tenantId','providerId','bindingId'],8192
  );
  IF p_lookup #>> '{provider,scope}' <> 'tenant' THEN
    RAISE EXCEPTION 'invalid OIDC client secret lookup' USING ERRCODE = '22023';
  END IF;
  v_tenant_id := app.private_mfa_require_uuidv7_v1(p_lookup #>> '{provider,tenantId}');
  v_provider_id := app.private_mfa_require_uuidv7_v1(p_lookup #>> '{provider,providerId}');
  v_binding_id := app.private_mfa_require_uuidv7_v1(p_lookup #>> '{provider,bindingId}');
  v_revision := (p_lookup ->> 'revision')::bigint;
  IF v_revision <= 0 THEN
    RAISE EXCEPTION 'invalid OIDC client secret lookup' USING ERRCODE = '22023';
  END IF;

  SELECT jsonb_build_object(
    'lookup',p_lookup,'secretId',secret.id::text,
    'keyVersion',secret.key_version,
    'nonce',replace(encode(secret.nonce,'base64'),E'\n',''),
    'ciphertext',replace(encode(secret.ciphertext,'base64'),E'\n','')
  ) INTO v_result
  FROM public.tenant_auth_providers AS provider
  JOIN public.tenants AS tenant
    ON tenant.id = provider.tenant_id AND tenant.status = 'active'
  JOIN public.tenant_auth_provider_bindings AS binding
    ON binding.tenant_id = provider.tenant_id
   AND binding.provider_id = provider.id AND binding.id = v_binding_id
   AND binding.enabled AND binding.archived_at IS NULL
   AND binding.current_access_epoch_id IS NOT NULL
  JOIN public.tenant_federated_provider_policies AS policy
    ON policy.tenant_id = provider.tenant_id
   AND policy.provider_id = provider.id AND policy.binding_id = binding.id
   AND policy.provider_kind = 'oidc' AND policy.enabled
  JOIN public.tenant_oidc_provider_configurations AS configuration
    ON configuration.tenant_id = provider.tenant_id
   AND configuration.provider_id = provider.id
   AND configuration.version = policy.configuration_revision
   AND configuration.client_secret_revision = v_revision
  JOIN public.tenant_oidc_client_secrets AS secret
    ON secret.tenant_id = configuration.tenant_id
   AND secret.provider_id = configuration.provider_id
   AND secret.revision = v_revision AND secret.retired_at IS NULL
  JOIN public.identity_keyring_versions AS keyring
    ON keyring.key_version = secret.key_version AND keyring.retired_at IS NULL
  WHERE provider.tenant_id = v_tenant_id AND provider.id = v_provider_id
    AND provider.kind = 'oidc' AND provider.enabled
    AND provider.archived_at IS NULL;
  RETURN v_result;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid OIDC client secret lookup' USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.load_saml_sp_key_envelope_v1(p_lookup jsonb)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_tenant_id uuid;
  v_provider_id uuid;
  v_binding_id uuid;
  v_revision bigint;
  v_result jsonb;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_lookup,ARRAY['provider','revision'],ARRAY['provider','revision'],16384
  );
  PERFORM app.private_mfa_assert_json_object_v1(
    p_lookup -> 'provider',ARRAY['scope','tenantId','providerId','bindingId'],
    ARRAY['scope','tenantId','providerId','bindingId'],8192
  );
  IF p_lookup #>> '{provider,scope}' <> 'tenant' THEN
    RAISE EXCEPTION 'invalid SAML SP key lookup' USING ERRCODE = '22023';
  END IF;
  v_tenant_id := app.private_mfa_require_uuidv7_v1(p_lookup #>> '{provider,tenantId}');
  v_provider_id := app.private_mfa_require_uuidv7_v1(p_lookup #>> '{provider,providerId}');
  v_binding_id := app.private_mfa_require_uuidv7_v1(p_lookup #>> '{provider,bindingId}');
  v_revision := (p_lookup ->> 'revision')::bigint;
  IF v_revision <= 0 OR v_revision > 4294967295 THEN
    RAISE EXCEPTION 'invalid SAML SP key lookup' USING ERRCODE = '22023';
  END IF;

  SELECT jsonb_build_object(
    'lookup',p_lookup,'keyId',sp_key.id::text,
    'envelopeKeyVersion',sp_key.key_version,
    'envelopeCiphertext',replace(encode(sp_key.ciphertext,'base64'),E'\n',''),
    'certificateDer',coalesce((
      SELECT jsonb_agg(
        replace(encode(certificate.certificate_der,'base64'),E'\n','')
        ORDER BY certificate.sequence
      )
      FROM public.tenant_saml_sp_certificates AS certificate
      WHERE certificate.tenant_id = sp_key.tenant_id
        AND certificate.key_id = sp_key.id
    ),'[]'::jsonb)
  ) INTO v_result
  FROM public.tenant_auth_providers AS provider
  JOIN public.tenants AS tenant
    ON tenant.id = provider.tenant_id AND tenant.status = 'active'
  JOIN public.tenant_auth_provider_bindings AS binding
    ON binding.tenant_id = provider.tenant_id
   AND binding.provider_id = provider.id AND binding.id = v_binding_id
   AND binding.enabled AND binding.archived_at IS NULL
   AND binding.current_access_epoch_id IS NOT NULL
  JOIN public.tenant_federated_provider_policies AS policy
    ON policy.tenant_id = provider.tenant_id
   AND policy.provider_id = provider.id AND policy.binding_id = binding.id
   AND policy.provider_kind = 'saml' AND policy.enabled
  JOIN public.tenant_saml_provider_configurations AS configuration
    ON configuration.tenant_id = provider.tenant_id
   AND configuration.provider_id = provider.id
   AND configuration.version = policy.configuration_revision
   AND configuration.sp_key_revision = v_revision
  JOIN public.tenant_saml_sp_keys AS sp_key
    ON sp_key.tenant_id = configuration.tenant_id
   AND sp_key.provider_id = configuration.provider_id
   AND sp_key.revision = v_revision AND sp_key.retired_at IS NULL
  JOIN public.identity_keyring_versions AS keyring
    ON keyring.key_version = sp_key.key_version AND keyring.retired_at IS NULL
  WHERE provider.tenant_id = v_tenant_id AND provider.id = v_provider_id
    AND provider.kind = 'saml' AND provider.enabled
    AND provider.archived_at IS NULL
    AND EXISTS (
      SELECT 1 FROM public.tenant_saml_sp_certificates AS certificate
      WHERE certificate.tenant_id = sp_key.tenant_id
        AND certificate.key_id = sp_key.id
    );
  RETURN v_result;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid SAML SP key lookup' USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.load_federated_authentication_planning_state_v1(p_lookup jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_protocol text;
  v_tenant_id uuid;
  v_provider_id uuid;
  v_binding_id uuid;
  v_provider_kind text;
  v_provider_revision bigint;
  v_binding_revision bigint;
  v_configuration_revision bigint;
  v_security_revision bigint;
  v_mapping_revision bigint;
  v_authorization_revision bigint;
  v_assurance_policy_revision bigint;
  v_plan_revision bigint;
  v_jit_mode text;
  v_no_match_policy text;
  v_access_epoch_id uuid;
  v_access_source_id uuid;
  v_alias_count integer;
  v_alias_index integer;
  v_alias jsonb;
  v_alias_key_versions integer[] := ARRAY[]::integer[];
  v_alias_digests bytea[] := ARRAY[]::bytea[];
  v_digest bytea;
  v_identity_ids uuid[];
  v_user_ids uuid[];
  v_external_identity_id uuid;
  v_user_id uuid;
  v_identity_epoch bigint := 0;
  v_subject_match jsonb := 'null'::jsonb;
  v_membership_id uuid;
  v_user_active boolean := false;
  v_membership_active boolean := false;
  v_access_live boolean := false;
  v_mapping jsonb;
  v_requirement jsonb;
  v_has_factor boolean := false;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_lookup,
    ARRAY['protocol','tenantId','provider','subjectFormat','subjectAliases',
      'providerRevision','bindingRevision','configurationRevision',
      'securityRevision','mappingRevision','authorizationRevision',
      'assurancePolicyRevision'],
    ARRAY['protocol','tenantId','provider','subjectFormat','subjectAliases',
      'providerRevision','bindingRevision','configurationRevision',
      'securityRevision','mappingRevision','authorizationRevision',
      'assurancePolicyRevision'],262144
  );
  PERFORM app.private_mfa_assert_json_object_v1(
    p_lookup -> 'provider',ARRAY['scope','tenantId','providerId','bindingId'],
    ARRAY['scope','tenantId','providerId','bindingId'],8192
  );
  v_protocol := p_lookup ->> 'protocol';
  IF v_protocol NOT IN ('oidc','saml')
     OR p_lookup ->> 'subjectFormat' <> 'utf8_exact'
     OR p_lookup #>> '{provider,scope}' <> 'tenant'
     OR p_lookup ->> 'tenantId' IS DISTINCT FROM p_lookup #>> '{provider,tenantId}'
     OR jsonb_typeof(p_lookup -> 'subjectAliases') <> 'array' THEN
    RAISE EXCEPTION 'invalid federated authentication planning lookup'
      USING ERRCODE = '22023';
  END IF;
  v_tenant_id := app.private_mfa_require_uuidv7_v1(p_lookup ->> 'tenantId');
  v_provider_id := app.private_mfa_require_uuidv7_v1(p_lookup #>> '{provider,providerId}');
  v_binding_id := app.private_mfa_require_uuidv7_v1(p_lookup #>> '{provider,bindingId}');
  v_provider_revision := (p_lookup ->> 'providerRevision')::bigint;
  v_binding_revision := (p_lookup ->> 'bindingRevision')::bigint;
  v_configuration_revision := (p_lookup ->> 'configurationRevision')::bigint;
  v_security_revision := (p_lookup ->> 'securityRevision')::bigint;
  v_mapping_revision := (p_lookup ->> 'mappingRevision')::bigint;
  v_authorization_revision := (p_lookup ->> 'authorizationRevision')::bigint;
  v_assurance_policy_revision := (p_lookup ->> 'assurancePolicyRevision')::bigint;
  IF least(v_provider_revision,v_binding_revision,v_configuration_revision,
       v_security_revision,v_mapping_revision,v_authorization_revision,
       v_assurance_policy_revision) <= 0 THEN
    RAISE EXCEPTION 'invalid federated authentication planning lookup'
      USING ERRCODE = '22023';
  END IF;

  v_alias_count := jsonb_array_length(p_lookup -> 'subjectAliases');
  IF v_alias_count NOT BETWEEN 1 AND 16 THEN
    RAISE EXCEPTION 'invalid federated subject aliases' USING ERRCODE = '22023';
  END IF;
  FOR v_alias_index IN 0..v_alias_count - 1 LOOP
    v_alias := p_lookup -> 'subjectAliases' -> v_alias_index;
    PERFORM app.private_mfa_assert_json_object_v1(
      v_alias,ARRAY['keyVersion','digest'],ARRAY['keyVersion','digest'],4096
    );
    IF jsonb_typeof(v_alias -> 'keyVersion') <> 'number'
       OR jsonb_typeof(v_alias -> 'digest') <> 'string'
       OR (v_alias ->> 'keyVersion')::integer NOT BETWEEN 1 AND 32767
       OR (v_alias_index > 0 AND
          v_alias_key_versions[v_alias_index] >=
            (v_alias ->> 'keyVersion')::integer) THEN
      RAISE EXCEPTION 'invalid federated subject aliases' USING ERRCODE = '22023';
    END IF;
    v_digest := app.private_mfa_decode_base64_v1(v_alias ->> 'digest',32,32);
    IF encode(v_digest,'hex') = repeat('00',32)
       OR NOT EXISTS (
         SELECT 1 FROM public.identity_keyring_versions AS keyring
         WHERE keyring.key_version = (v_alias ->> 'keyVersion')::integer
           AND keyring.retired_at IS NULL
       ) THEN
      RAISE EXCEPTION 'invalid federated subject aliases' USING ERRCODE = '22023';
    END IF;
    v_alias_key_versions := array_append(
      v_alias_key_versions,(v_alias ->> 'keyVersion')::integer
    );
    v_alias_digests := array_append(v_alias_digests,v_digest);
  END LOOP;

  SELECT provider.kind::text,policy.plan_revision,policy.jit_mode,
         policy.no_match_policy,binding.current_access_epoch_id,access_epoch.source_id
    INTO STRICT v_provider_kind,v_plan_revision,v_jit_mode,v_no_match_policy,
         v_access_epoch_id,v_access_source_id
  FROM public.tenant_auth_providers AS provider
  JOIN public.tenants AS tenant
    ON tenant.id = provider.tenant_id AND tenant.status = 'active'
  JOIN public.tenant_auth_provider_bindings AS binding
    ON binding.tenant_id = provider.tenant_id
   AND binding.provider_id = provider.id AND binding.id = v_binding_id
   AND binding.enabled AND binding.archived_at IS NULL
   AND binding.current_access_epoch_id IS NOT NULL
  JOIN public.tenant_identity_provider_access_epochs AS access_epoch
    ON access_epoch.tenant_id = binding.tenant_id
   AND access_epoch.id = binding.current_access_epoch_id
   AND access_epoch.binding_id = binding.id
   AND access_epoch.provider_id = provider.id
   AND access_epoch.ended_at IS NULL
  JOIN public.tenant_federated_provider_policies AS policy
    ON policy.tenant_id = provider.tenant_id
   AND policy.provider_id = provider.id AND policy.binding_id = binding.id
   AND policy.provider_kind = provider.kind AND policy.enabled
  WHERE provider.tenant_id = v_tenant_id AND provider.id = v_provider_id
    AND provider.kind::text = v_protocol AND provider.enabled
    AND provider.archived_at IS NULL
    AND provider.version = v_provider_revision
    AND binding.version = v_binding_revision
    AND binding.mapping_revision = v_mapping_revision
    AND binding.auth_revision::bigint = v_authorization_revision
    AND policy.configuration_revision = v_configuration_revision
    AND policy.security_revision = v_security_revision
    AND policy.assurance_policy_revision = v_assurance_policy_revision
    AND ((v_protocol = 'oidc' AND EXISTS (
      SELECT 1 FROM public.tenant_oidc_provider_configurations AS configuration
      WHERE configuration.tenant_id = provider.tenant_id
        AND configuration.provider_id = provider.id
        AND configuration.version = v_configuration_revision
    )) OR (v_protocol = 'saml' AND EXISTS (
      SELECT 1 FROM public.tenant_saml_provider_configurations AS configuration
      WHERE configuration.tenant_id = provider.tenant_id
        AND configuration.provider_id = provider.id
        AND configuration.version = v_configuration_revision
    )));

  WITH wanted AS (
    SELECT aliases.key_version,aliases.digest
    FROM unnest(v_alias_key_versions,v_alias_digests)
      AS aliases(key_version,digest)
  ), matches AS (
    SELECT DISTINCT identity.id,identity.user_id
    FROM wanted
    JOIN public.tenant_federated_external_identity_aliases AS alias
      ON alias.tenant_id = v_tenant_id AND alias.provider_id = v_provider_id
     AND alias.key_version = wanted.key_version
     AND alias.subject_digest = wanted.digest AND alias.retired_at IS NULL
    JOIN public.tenant_federated_external_identities AS identity
      ON identity.tenant_id = alias.tenant_id
     AND identity.provider_id = alias.provider_id
     AND identity.id = alias.external_identity_id
     AND identity.binding_id = v_binding_id AND identity.retired_at IS NULL
  )
  SELECT array_agg(DISTINCT id ORDER BY id),array_agg(DISTINCT user_id ORDER BY user_id)
    INTO v_identity_ids,v_user_ids FROM matches;
  IF coalesce(cardinality(v_identity_ids),0) > 1
     OR coalesce(cardinality(v_user_ids),0) > 1 THEN
    RAISE EXCEPTION 'federated subject aliases disagree' USING ERRCODE = '23505';
  END IF;
  v_external_identity_id := v_identity_ids[1];
  v_user_id := v_user_ids[1];
  IF v_external_identity_id IS NULL THEN
    v_external_identity_id := uuidv7();
  ELSE
    SELECT subject.identity_epoch INTO STRICT v_identity_epoch
    FROM public.tenant_federated_external_identities AS identity
    JOIN public.tenant_mfa_subjects AS subject
      ON subject.tenant_id = identity.tenant_id
     AND subject.user_id = identity.user_id
    WHERE identity.tenant_id = v_tenant_id
      AND identity.provider_id = v_provider_id
      AND identity.id = v_external_identity_id
      AND identity.user_id = v_user_id
      AND identity.binding_id = v_binding_id
      AND identity.retired_at IS NULL;
    SELECT jsonb_build_object(
      'externalIdentityId',v_external_identity_id::text,
      'alias',jsonb_build_object(
        'keyVersion',alias.key_version,
        'digest',replace(encode(alias.subject_digest,'base64'),E'\n','')
      )
    ) INTO STRICT v_subject_match
    FROM public.tenant_federated_external_identity_aliases AS alias
    JOIN unnest(v_alias_key_versions,v_alias_digests)
      WITH ORDINALITY AS wanted(key_version,digest,ordinality)
      ON wanted.key_version = alias.key_version
     AND wanted.digest = alias.subject_digest
    WHERE alias.tenant_id = v_tenant_id
      AND alias.provider_id = v_provider_id
      AND alias.external_identity_id = v_external_identity_id
      AND alias.retired_at IS NULL
    ORDER BY wanted.ordinality DESC LIMIT 1;
  END IF;

  IF v_user_id IS NOT NULL THEN
    SELECT local_user.active,membership.id,membership.status = 'active'
      INTO STRICT v_user_active,v_membership_id,v_membership_active
    FROM public.users AS local_user
    LEFT JOIN public.tenant_memberships AS membership
      ON membership.tenant_id = v_tenant_id
     AND membership.user_id = local_user.id
    WHERE local_user.id = v_user_id;
    SELECT EXISTS (
      SELECT 1 FROM public.tenant_federated_provider_access_grants AS access_grant
      JOIN public.tenant_authorization_sources AS source
        ON source.tenant_id = access_grant.tenant_id
       AND source.id = access_grant.source_id AND source.retired_at IS NULL
      WHERE access_grant.tenant_id = v_tenant_id
        AND access_grant.provider_id = v_provider_id
        AND access_grant.binding_id = v_binding_id
        AND access_grant.access_epoch_id = v_access_epoch_id
        AND access_grant.source_id = v_access_source_id
        AND access_grant.external_identity_id = v_external_identity_id
        AND access_grant.user_id = v_user_id
        AND access_grant.membership_id = v_membership_id
        AND access_grant.ended_at IS NULL
    ) INTO v_access_live;
  END IF;

  WITH rules AS (
    SELECT epoch.*,
      coalesce((
        SELECT jsonb_agg(target.role_id::text ORDER BY target.role_id)
        FROM public.tenant_federated_mapping_rule_role_targets AS target
        JOIN public.tenant_roles AS role ON role.tenant_id = target.tenant_id
          AND role.id = target.role_id AND role.principal_kind = 'human'
          AND role.archived_at IS NULL AND role.key <> 'platform_super_admin'
        WHERE target.tenant_id = epoch.tenant_id
          AND target.rule_epoch_id = epoch.id
          AND NOT EXISTS (
            SELECT 1 FROM public.tenant_role_permissions AS forbidden
            WHERE forbidden.tenant_id = role.tenant_id
              AND forbidden.role_id = role.id AND forbidden.scope = 'platform'
          )
      ),'[]'::jsonb) AS role_ids
    FROM public.tenant_federated_mapping_rule_epochs AS epoch
    JOIN public.tenant_authorization_sources AS epoch_source
      ON epoch_source.tenant_id = epoch.tenant_id
     AND epoch_source.id = epoch.source_id
     AND epoch_source.retired_at IS NULL
    WHERE epoch.tenant_id = v_tenant_id
      AND epoch.provider_id = v_provider_id
      AND epoch.binding_id = v_binding_id
      AND epoch.provider_kind::text = v_protocol
      AND epoch.mapping_revision = v_mapping_revision
      AND epoch.enabled AND epoch.ended_at IS NULL
  ), groups AS (
    SELECT DISTINCT security_group.id AS group_id
    FROM rules AS rule
    JOIN public.tenant_security_groups AS security_group
      ON security_group.tenant_id = rule.tenant_id
     AND security_group.id = rule.tenant_security_group_id
     AND security_group.archived_at IS NULL
  ), group_projection AS (
    SELECT groups.group_id,coalesce(jsonb_agg(DISTINCT role.id::text
      ORDER BY role.id::text) FILTER (
        WHERE grant_source.id IS NOT NULL AND role.id IS NOT NULL
      ),
      '[]'::jsonb) AS role_ids
    FROM groups
    LEFT JOIN public.tenant_security_group_role_grants AS grant_row
      ON grant_row.tenant_id = v_tenant_id AND grant_row.group_id = groups.group_id
     AND grant_row.revoked_at IS NULL
     AND (grant_row.expires_at IS NULL OR grant_row.expires_at > transaction_timestamp())
    LEFT JOIN public.tenant_authorization_sources AS grant_source
      ON grant_source.tenant_id = grant_row.tenant_id
     AND grant_source.id = grant_row.source_id AND grant_source.retired_at IS NULL
    LEFT JOIN public.tenant_roles AS role
      ON role.tenant_id = grant_row.tenant_id
     AND role.id = grant_row.role_id
     AND role.principal_kind = 'human'
     AND role.archived_at IS NULL
     AND role.key <> 'platform_super_admin'
     AND NOT EXISTS (
       SELECT 1 FROM public.tenant_role_permissions AS forbidden
       WHERE forbidden.tenant_id = role.tenant_id
         AND forbidden.role_id = role.id AND forbidden.scope = 'platform'
     )
    GROUP BY groups.group_id
  ), effective_roles AS (
    SELECT direct.role_id
    FROM public.tenant_membership_role_grants AS direct
    JOIN public.tenant_authorization_sources AS source
     ON source.tenant_id = direct.tenant_id AND source.id = direct.source_id
     AND source.retired_at IS NULL
    JOIN public.tenant_roles AS direct_role
      ON direct_role.tenant_id = direct.tenant_id
     AND direct_role.id = direct.role_id
     AND direct_role.principal_kind = 'human'
     AND direct_role.archived_at IS NULL
     AND direct_role.key <> 'platform_super_admin'
    WHERE direct.tenant_id = v_tenant_id
      AND direct.membership_id = v_membership_id
      AND direct.revoked_at IS NULL
      AND (direct.expires_at IS NULL OR direct.expires_at > transaction_timestamp())
      AND NOT EXISTS (
        SELECT 1 FROM public.tenant_role_permissions AS forbidden
        WHERE forbidden.tenant_id = direct_role.tenant_id
          AND forbidden.role_id = direct_role.id
          AND forbidden.scope = 'platform'
      )
    UNION
    SELECT group_grant.role_id
    FROM public.tenant_security_group_memberships AS group_member
    JOIN public.tenant_authorization_sources AS member_source
      ON member_source.tenant_id = group_member.tenant_id
     AND member_source.id = group_member.source_id
     AND member_source.retired_at IS NULL
    JOIN public.tenant_security_group_role_grants AS group_grant
      ON group_grant.tenant_id = group_member.tenant_id
     AND group_grant.group_id = group_member.group_id
     AND group_grant.revoked_at IS NULL
     AND (group_grant.expires_at IS NULL OR group_grant.expires_at > transaction_timestamp())
    JOIN public.tenant_authorization_sources AS grant_source
      ON grant_source.tenant_id = group_grant.tenant_id
     AND grant_source.id = group_grant.source_id
     AND grant_source.retired_at IS NULL
    JOIN public.tenant_roles AS group_role
      ON group_role.tenant_id = group_grant.tenant_id
     AND group_role.id = group_grant.role_id
     AND group_role.principal_kind = 'human'
     AND group_role.archived_at IS NULL
     AND group_role.key <> 'platform_super_admin'
    WHERE group_member.tenant_id = v_tenant_id
      AND group_member.membership_id = v_membership_id
      AND group_member.revoked_at IS NULL
      AND (group_member.expires_at IS NULL OR group_member.expires_at > transaction_timestamp())
      AND NOT EXISTS (
        SELECT 1 FROM public.tenant_role_permissions AS forbidden
        WHERE forbidden.tenant_id = group_role.tenant_id
          AND forbidden.role_id = group_role.id
          AND forbidden.scope = 'platform'
      )
  ), needed_roles AS (
    SELECT target.role_id FROM rules
      JOIN public.tenant_federated_mapping_rule_role_targets AS target
        ON target.tenant_id = rules.tenant_id AND target.rule_epoch_id = rules.id
    UNION SELECT grant_row.role_id
      FROM groups JOIN public.tenant_security_group_role_grants AS grant_row
        ON grant_row.tenant_id = v_tenant_id AND grant_row.group_id = groups.group_id
       AND grant_row.revoked_at IS NULL
       AND (grant_row.expires_at IS NULL OR grant_row.expires_at > transaction_timestamp())
      JOIN public.tenant_authorization_sources AS grant_source
        ON grant_source.tenant_id = grant_row.tenant_id
       AND grant_source.id = grant_row.source_id
       AND grant_source.retired_at IS NULL
    UNION SELECT role_id FROM effective_roles
  ), role_policies AS (
    SELECT role.id AS role_id,coalesce(jsonb_agg(jsonb_build_object(
      'permission',permission.key,'scope',policy.scope
    ) ORDER BY permission.key,policy.scope)
      FILTER (WHERE permission.id IS NOT NULL),'[]'::jsonb) AS policies
    FROM needed_roles
    JOIN public.tenant_roles AS role ON role.tenant_id = v_tenant_id
      AND role.id = needed_roles.role_id AND role.principal_kind = 'human'
      AND role.archived_at IS NULL AND role.key <> 'platform_super_admin'
    LEFT JOIN public.tenant_role_permissions AS policy
      ON policy.tenant_id = role.tenant_id AND policy.role_id = role.id
     AND policy.scope <> 'platform'
    LEFT JOIN public.tenant_permissions AS permission
      ON permission.id = policy.permission_id
    GROUP BY role.id
  ), owned_edges AS (
    SELECT rule.source_id,rule.id AS rule_epoch_id,
      'security_group_membership'::text AS kind,
      membership.group_id AS primary_id,NULL::uuid AS secondary_id
    FROM rules AS rule
    JOIN public.tenant_security_group_memberships AS membership
      ON membership.tenant_id = rule.tenant_id
     AND membership.source_id = rule.source_id
     AND membership.membership_id = v_membership_id
     AND membership.revoked_at IS NULL
     AND (membership.expires_at IS NULL
       OR membership.expires_at > transaction_timestamp())
    UNION ALL
    SELECT rule.source_id,rule.id,'security_group_role_grant',
      grant_row.group_id,grant_row.role_id
    FROM rules AS rule
    JOIN public.tenant_security_group_role_grants AS grant_row
      ON grant_row.tenant_id = rule.tenant_id
     AND grant_row.source_id = rule.source_id
     AND grant_row.revoked_at IS NULL
     AND (grant_row.expires_at IS NULL
       OR grant_row.expires_at > transaction_timestamp())
    UNION ALL
    SELECT rule.source_id,rule.id,'operator_team_roster',
      assignment.operator_team_id,roster.assignment_epoch_id
    FROM rules AS rule
    JOIN public.operator_team_roster_entries AS roster
      ON roster.tenant_id = rule.tenant_id
     AND roster.source_id = rule.source_id
     AND roster.membership_id = v_membership_id
     AND roster.revoked_at IS NULL
     AND (roster.expires_at IS NULL OR roster.expires_at > transaction_timestamp())
    JOIN public.operator_team_assignment_epochs AS assignment
     ON assignment.tenant_id = roster.tenant_id
     AND assignment.id = roster.assignment_epoch_id
     AND assignment.ended_at IS NULL
  )
  SELECT jsonb_build_object(
    'tenantId',v_tenant_id::text,
    'provider',p_lookup -> 'provider',
    'configurationRevision',v_configuration_revision,
    'ruleSetRevision',v_mapping_revision,
    'authorizationRevision',v_authorization_revision,
    'jitMode',v_jit_mode,'noMatchPolicy',v_no_match_policy,
    'effectiveUntil','null'::jsonb,
    'providerAccess',jsonb_build_object(
      'sourceId',v_access_source_id::text,'accessEpochId',v_access_epoch_id::text,
      'externalIdentityExists',v_user_id IS NOT NULL,
      'userActive',v_user_active,
      'tenantMembershipExists',v_membership_id IS NOT NULL,
      'tenantMembershipActive',v_membership_active,
      'accessGrantLive',v_access_live
    ),
    'rules',coalesce((SELECT jsonb_agg(jsonb_build_object(
      'ruleId',rule.rule_id::text,'ruleEpochId',rule.id::text,
      'sourceId',rule.source_id::text,'revision',rule.revision,
      'priority',rule.priority,'enabled',rule.enabled,
      'matcher',jsonb_strip_nulls(jsonb_build_object(
        'kind',rule.matcher_kind,'claimName',rule.claim_name,
        'value',rule.matcher_value
      )),
      'reconciliationMode',rule.reconciliation_mode,
      'securityGroupId',rule.tenant_security_group_id::text,
      'roleIds',rule.role_ids,
      'operatorTeamId',CASE WHEN rule.operator_team_id IS NULL THEN 'null'::jsonb
        ELSE to_jsonb(rule.operator_team_id::text) END,
      'operatorTeamAssignmentEpochId',CASE
        WHEN rule.operator_team_assignment_epoch_id IS NULL THEN 'null'::jsonb
        ELSE to_jsonb(rule.operator_team_assignment_epoch_id::text) END
    ) ORDER BY rule.priority,rule.rule_id) FROM rules AS rule),'[]'::jsonb),
    'securityGroups',coalesce((SELECT jsonb_agg(jsonb_build_object(
      'securityGroupId',group_projection.group_id::text,
      'activeRoleIds',group_projection.role_ids
    ) ORDER BY group_projection.group_id) FROM group_projection),'[]'::jsonb),
    'liveAssignments',coalesce((SELECT jsonb_agg(jsonb_build_object(
      'operatorTeamId',rule.operator_team_id::text,
      'assignmentEpochId',rule.operator_team_assignment_epoch_id::text,
      'live',EXISTS (
        SELECT 1 FROM public.operator_team_assignment_epochs AS assignment
        JOIN public.operator_teams AS team
          ON team.tenant_id = assignment.tenant_id
         AND team.id = assignment.operator_team_id
        WHERE assignment.tenant_id = v_tenant_id
          AND assignment.id = rule.operator_team_assignment_epoch_id
          AND assignment.operator_team_id = rule.operator_team_id
          AND assignment.ended_at IS NULL AND team.archived_at IS NULL
      )
    ) ORDER BY rule.operator_team_id,rule.operator_team_assignment_epoch_id)
      FROM rules AS rule WHERE rule.operator_team_id IS NOT NULL),'[]'::jsonb),
    'rolePolicies',coalesce((SELECT jsonb_agg(jsonb_build_object(
      'roleId',role_policies.role_id::text,'policy',role_policies.policies
    ) ORDER BY role_policies.role_id) FROM role_policies),'[]'::jsonb),
    'existingEffectiveRoleIds',coalesce((SELECT jsonb_agg(role_id::text ORDER BY role_id)
      FROM effective_roles),'[]'::jsonb),
    'delegation','[]'::jsonb,
    'liveOwnedEdges',coalesce((SELECT jsonb_agg(jsonb_strip_nulls(jsonb_build_object(
      'sourceId',edge.source_id::text,'ruleEpochId',edge.rule_epoch_id::text,
      'kind',edge.kind,'primaryId',edge.primary_id::text,
      'secondaryId',CASE WHEN edge.secondary_id IS NULL THEN NULL
        ELSE edge.secondary_id::text END
    )) ORDER BY edge.source_id,edge.kind,edge.primary_id,edge.secondary_id NULLS FIRST)
      FROM owned_edges AS edge),'[]'::jsonb)
  ) INTO v_mapping;

  v_requirement := app.private_federated_assurance_requirement_v1(
    v_tenant_id,v_user_id,v_binding_id,v_mapping_revision,
    'tenant.authentication.login',transaction_timestamp()
  );
  IF v_user_id IS NOT NULL THEN
    SELECT EXISTS (
      SELECT 1 FROM public.tenant_totp_factors AS factor
      WHERE factor.tenant_id = v_tenant_id AND factor.user_id = v_user_id
        AND factor.status = 'active'
      UNION ALL
      SELECT 1 FROM public.tenant_webauthn_credentials AS credential
      WHERE credential.tenant_id = v_tenant_id AND credential.user_id = v_user_id
        AND credential.status = 'active'
    ) INTO v_has_factor;
  END IF;

  RETURN jsonb_build_object(
    'lookup',p_lookup,'planRevision',v_plan_revision,
    'userId',CASE WHEN v_user_id IS NULL THEN 'null'::jsonb
      ELSE to_jsonb(v_user_id::text) END,
    'identityEpoch',v_identity_epoch,
    'externalIdentityId',v_external_identity_id::text,
    'subjectMatch',v_subject_match,
    'providerRevision',v_provider_revision,
    'bindingRevision',v_binding_revision,
    'securityRevision',v_security_revision,
    'assurancePolicyRevision',v_assurance_policy_revision,
    'mapping',v_mapping,'requirement',v_requirement,
    'hasEnrollableFactor',v_has_factor
  );
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RETURN NULL;
WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid federated authentication planning lookup'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

DO $acl$
DECLARE
  v_signature regprocedure;
BEGIN
  FOREACH v_signature IN ARRAY ARRAY[
    'app.private_federated_assert_begin_lookup_v1(jsonb)'::regprocedure,
    'app.private_tenant_oidc_configuration_record_v1(uuid,uuid,uuid,jsonb)'::regprocedure,
    'app.private_tenant_oidc_claim_policy_v1(uuid,uuid,text)'::regprocedure,
    'app.private_tenant_saml_attribute_policy_v1(uuid,uuid)'::regprocedure,
    'app.private_tenant_saml_configuration_record_v1(uuid,uuid,uuid,jsonb)'::regprocedure,
    'app.begin_tenant_oidc_authentication_v1(jsonb)'::regprocedure,
    'app.begin_tenant_saml_authentication_v1(jsonb)'::regprocedure,
    'app.resolve_tenant_oidc_authentication_v1(jsonb)'::regprocedure,
    'app.resolve_tenant_saml_authentication_v1(jsonb)'::regprocedure,
    'app.load_oidc_trust_snapshot_v1(jsonb)'::regprocedure,
    'app.load_oidc_client_secret_envelope_v1(jsonb)'::regprocedure,
    'app.load_saml_sp_key_envelope_v1(jsonb)'::regprocedure,
    'app.load_federated_authentication_planning_state_v1(jsonb)'::regprocedure
  ] LOOP
    EXECUTE format('ALTER FUNCTION %s OWNER TO periapsis_migrator',v_signature);
    EXECUTE format(
      'REVOKE ALL ON FUNCTION %s FROM PUBLIC, periapsis_api, periapsis_worker, '
      || 'periapsis_notifier, periapsis_auditor, periapsis_audit_reader_owner, '
      || 'periapsis_notification_dispatch_owner, periapsis_sla_api_owner, '
      || 'periapsis_sla_worker_owner, periapsis_sla_readiness_owner',
      v_signature
    );
  END LOOP;
END;
$acl$;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.begin_tenant_oidc_authentication_v1(jsonb),
  app.begin_tenant_saml_authentication_v1(jsonb),
  app.resolve_tenant_oidc_authentication_v1(jsonb),
  app.resolve_tenant_saml_authentication_v1(jsonb),
  app.load_oidc_trust_snapshot_v1(jsonb),
  app.load_oidc_client_secret_envelope_v1(jsonb),
  app.load_saml_sp_key_envelope_v1(jsonb),
  app.load_federated_authentication_planning_state_v1(jsonb)
TO periapsis_api;
--> statement-breakpoint
