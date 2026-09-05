-- Browser transaction persistence is exposed only as a bounded JSON ABI. Raw
-- state, RelayState, nonce, browser handles, PKCE verifiers, and start locators
-- never cross this boundary or enter PostgreSQL.
CREATE FUNCTION app.create_oidc_authentication_transaction_v1(p_request jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_begin jsonb;
  v_current jsonb;
  v_pins jsonb;
  v_provider jsonb;
  v_operation_run_id uuid;
  v_operation_digest bytea;
  v_receipt_digest bytea;
  v_network_digest bytea;
  v_account_digest bytea;
  v_provider_digest bytea;
  v_transaction_id bytea;
  v_state_digest bytea;
  v_browser_digest bytea;
  v_previous_browser_digest bytea;
  v_nonce_digest bytea;
  v_verifier_ciphertext bytea;
  v_discovery_digest bytea;
  v_jwks_digest bytea;
  v_tenant_id uuid;
  v_provider_id uuid;
  v_binding_id uuid;
  v_provider_revision bigint;
  v_binding_revision bigint;
  v_configuration_revision bigint;
  v_security_revision bigint;
  v_mapping_revision bigint;
  v_authorization_revision bigint;
  v_assurance_policy_revision bigint;
  v_client_secret_revision bigint;
  v_discovery_revision bigint;
  v_jwks_revision bigint;
  v_verifier_key_version integer;
  v_client_id text;
  v_redirect_uri text;
  v_post_logout_redirect_uri text;
  v_return_path text;
  v_scopes text[];
  v_allow_refresh_token boolean;
  v_use_user_info boolean;
  v_created_at timestamptz;
  v_expires_at timestamptz;
  v_operation_lock bigint;
  v_receipt_lock bigint;
  v_state_lock bigint;
  v_current_browser_lock bigint;
  v_previous_browser_lock bigint;
  v_transaction_lock bigint;
  v_existing public.tenant_federated_authentication_transactions%ROWTYPE;
  v_replay boolean := false;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_request,
    ARRAY['begin','current','previousBrowserDigest'],
    ARRAY['begin','current'],
    65536
  );
  v_begin := p_request -> 'begin';
  v_current := p_request -> 'current';
  PERFORM app.private_mfa_assert_json_object_v1(
    v_begin,
    ARRAY['operationRunId','receiptDigest','networkDigest','accountDigest','providerDigest'],
    ARRAY['operationRunId','receiptDigest','networkDigest','accountDigest','providerDigest'],
    4096
  );
  PERFORM app.private_mfa_assert_json_object_v1(
    v_current,
    ARRAY['id','stateDigest','browserDigest','nonceDigest','verifierKeyVersion',
      'verifierCiphertext','pins','clientId','redirectUri','postLogoutRedirectUri',
      'returnPath','scopes','allowRefreshToken','useUserInfo','createdAt','expiresAt',
      'state','version'],
    ARRAY['id','stateDigest','browserDigest','nonceDigest','verifierKeyVersion',
      'verifierCiphertext','pins','clientId','redirectUri','postLogoutRedirectUri',
      'returnPath','scopes','allowRefreshToken','useUserInfo','createdAt','expiresAt',
      'state','version'],
    65536
  );
  v_pins := v_current -> 'pins';
  PERFORM app.private_mfa_assert_json_object_v1(
    v_pins,
    ARRAY['provider','providerRevision','bindingRevision','configurationRevision',
      'securityRevision','mappingRevision','authorizationRevision',
      'assurancePolicyRevision','clientSecretRevision','discoveryRevision',
      'discoveryDigest','jwksRevision','jwksDigest'],
    ARRAY['provider','providerRevision','bindingRevision','configurationRevision',
      'securityRevision','mappingRevision','authorizationRevision',
      'assurancePolicyRevision','clientSecretRevision','discoveryRevision',
      'discoveryDigest','jwksRevision','jwksDigest'],
    16384
  );
  v_provider := v_pins -> 'provider';
  PERFORM app.private_mfa_assert_json_object_v1(
    v_provider,
    ARRAY['scope','tenantId','providerId','bindingId'],
    ARRAY['scope','tenantId','providerId','bindingId'],
    4096
  );

  IF jsonb_typeof(v_begin -> 'operationRunId') <> 'string'
     OR jsonb_typeof(v_begin -> 'receiptDigest') <> 'string'
     OR jsonb_typeof(v_begin -> 'networkDigest') <> 'string'
     OR jsonb_typeof(v_begin -> 'accountDigest') <> 'string'
     OR jsonb_typeof(v_begin -> 'providerDigest') <> 'string'
     OR jsonb_typeof(v_current -> 'id') <> 'string'
     OR jsonb_typeof(v_current -> 'stateDigest') <> 'string'
     OR jsonb_typeof(v_current -> 'browserDigest') <> 'string'
     OR jsonb_typeof(v_current -> 'nonceDigest') <> 'string'
     OR jsonb_typeof(v_current -> 'verifierKeyVersion') <> 'number'
     OR jsonb_typeof(v_current -> 'verifierCiphertext') <> 'string'
     OR jsonb_typeof(v_current -> 'clientId') <> 'string'
     OR jsonb_typeof(v_current -> 'redirectUri') <> 'string'
     OR jsonb_typeof(v_current -> 'postLogoutRedirectUri') <> 'string'
     OR jsonb_typeof(v_current -> 'returnPath') <> 'string'
     OR jsonb_typeof(v_current -> 'scopes') <> 'array'
     OR jsonb_typeof(v_current -> 'allowRefreshToken') <> 'boolean'
     OR jsonb_typeof(v_current -> 'useUserInfo') <> 'boolean'
     OR jsonb_typeof(v_current -> 'createdAt') <> 'string'
     OR jsonb_typeof(v_current -> 'expiresAt') <> 'string'
     OR jsonb_typeof(v_current -> 'state') <> 'string'
     OR jsonb_typeof(v_current -> 'version') <> 'number'
     OR jsonb_typeof(v_provider -> 'scope') <> 'string'
     OR jsonb_typeof(v_provider -> 'tenantId') <> 'string'
     OR jsonb_typeof(v_provider -> 'providerId') <> 'string'
     OR jsonb_typeof(v_provider -> 'bindingId') <> 'string'
     OR EXISTS (
       SELECT 1
       FROM unnest(ARRAY['providerRevision','bindingRevision','configurationRevision',
         'securityRevision','mappingRevision','authorizationRevision',
         'assurancePolicyRevision','clientSecretRevision','discoveryRevision','jwksRevision']) AS key(value)
       WHERE jsonb_typeof(v_pins -> key.value) <> 'number'
     )
     OR jsonb_typeof(v_pins -> 'discoveryDigest') <> 'string'
     OR jsonb_typeof(v_pins -> 'jwksDigest') <> 'string'
     OR (p_request ? 'previousBrowserDigest'
       AND jsonb_typeof(p_request -> 'previousBrowserDigest') <> 'string') THEN
    RAISE EXCEPTION 'invalid federated authentication transaction request'
      USING ERRCODE = '22023';
  END IF;
  IF EXISTS (
       SELECT 1 FROM jsonb_array_elements(v_current -> 'scopes') AS item(value)
       WHERE jsonb_typeof(item.value) <> 'string'
     )
     OR EXISTS (
       SELECT 1
       FROM unnest(ARRAY['verifierKeyVersion','version']) AS key(value)
       WHERE v_current ->> key.value !~ '^[1-9][0-9]{0,18}$'
     )
     OR v_current ->> 'version' <> '1'
     OR (v_current ->> 'verifierKeyVersion')::numeric NOT BETWEEN 1 AND 32767
     OR EXISTS (
       SELECT 1
       FROM unnest(ARRAY['providerRevision','bindingRevision','configurationRevision',
         'securityRevision','mappingRevision','authorizationRevision',
         'assurancePolicyRevision','clientSecretRevision','discoveryRevision','jwksRevision']) AS key(value)
       WHERE v_pins ->> key.value !~ '^[1-9][0-9]{0,18}$'
          OR (v_pins ->> key.value)::numeric > 9223372036854775807::numeric
     ) THEN
    RAISE EXCEPTION 'invalid federated authentication transaction request'
      USING ERRCODE = '22023';
  END IF;

  v_operation_run_id := app.private_mfa_require_uuidv7_v1(v_begin ->> 'operationRunId');
  v_tenant_id := app.private_mfa_require_uuidv7_v1(v_provider ->> 'tenantId');
  v_provider_id := app.private_mfa_require_uuidv7_v1(v_provider ->> 'providerId');
  v_binding_id := app.private_mfa_require_uuidv7_v1(v_provider ->> 'bindingId');
  IF v_begin ->> 'operationRunId' <> v_operation_run_id::text
     OR v_provider ->> 'tenantId' <> v_tenant_id::text
     OR v_provider ->> 'providerId' <> v_provider_id::text
     OR v_provider ->> 'bindingId' <> v_binding_id::text
     OR substring(v_operation_run_id::text, 20, 1) NOT IN ('8','9','a','b')
     OR substring(v_tenant_id::text, 20, 1) NOT IN ('8','9','a','b')
     OR substring(v_provider_id::text, 20, 1) NOT IN ('8','9','a','b')
     OR substring(v_binding_id::text, 20, 1) NOT IN ('8','9','a','b')
     OR v_provider ->> 'scope' <> 'tenant' THEN
    RAISE EXCEPTION 'invalid federated authentication transaction request'
      USING ERRCODE = '22023';
  END IF;

  v_receipt_digest := app.private_mfa_decode_base64_v1(v_begin ->> 'receiptDigest', 32, 32);
  v_network_digest := app.private_mfa_decode_base64_v1(v_begin ->> 'networkDigest', 32, 32);
  v_account_digest := app.private_mfa_decode_base64_v1(v_begin ->> 'accountDigest', 32, 32);
  v_provider_digest := app.private_mfa_decode_base64_v1(v_begin ->> 'providerDigest', 32, 32);
  v_transaction_id := app.private_mfa_decode_base64_v1(v_current ->> 'id', 32, 32);
  v_state_digest := app.private_mfa_decode_base64_v1(v_current ->> 'stateDigest', 32, 32);
  v_browser_digest := app.private_mfa_decode_base64_v1(v_current ->> 'browserDigest', 32, 32);
  v_nonce_digest := app.private_mfa_decode_base64_v1(v_current ->> 'nonceDigest', 32, 32);
  v_verifier_ciphertext := app.private_mfa_decode_base64_v1(
    v_current ->> 'verifierCiphertext', 16, 4096
  );
  v_discovery_digest := app.private_mfa_decode_base64_v1(v_pins ->> 'discoveryDigest', 32, 32);
  v_jwks_digest := app.private_mfa_decode_base64_v1(v_pins ->> 'jwksDigest', 32, 32);
  IF p_request ? 'previousBrowserDigest' THEN
    v_previous_browser_digest := app.private_mfa_decode_base64_v1(
      p_request ->> 'previousBrowserDigest', 32, 32
    );
  END IF;
  IF encode(v_receipt_digest, 'hex') = repeat('00', 32)
     OR encode(v_network_digest, 'hex') = repeat('00', 32)
     OR encode(v_account_digest, 'hex') = repeat('00', 32)
     OR encode(v_provider_digest, 'hex') = repeat('00', 32)
     OR encode(v_transaction_id, 'hex') = repeat('00', 32)
     OR encode(v_state_digest, 'hex') = repeat('00', 32)
     OR encode(v_browser_digest, 'hex') = repeat('00', 32)
     OR encode(v_nonce_digest, 'hex') = repeat('00', 32)
     OR encode(v_discovery_digest, 'hex') = repeat('00', 32)
     OR encode(v_jwks_digest, 'hex') = repeat('00', 32)
     OR (v_previous_browser_digest IS NOT NULL
       AND encode(v_previous_browser_digest, 'hex') = repeat('00', 32))
     OR v_receipt_digest IN (v_network_digest, v_account_digest, v_provider_digest)
     OR v_network_digest IN (v_account_digest, v_provider_digest)
     OR v_account_digest = v_provider_digest
     OR v_state_digest IN (v_browser_digest, v_nonce_digest)
     OR v_browser_digest = v_nonce_digest THEN
    RAISE EXCEPTION 'invalid federated authentication transaction request'
      USING ERRCODE = '22023';
  END IF;

  v_provider_revision := (v_pins ->> 'providerRevision')::bigint;
  v_binding_revision := (v_pins ->> 'bindingRevision')::bigint;
  v_configuration_revision := (v_pins ->> 'configurationRevision')::bigint;
  v_security_revision := (v_pins ->> 'securityRevision')::bigint;
  v_mapping_revision := (v_pins ->> 'mappingRevision')::bigint;
  v_authorization_revision := (v_pins ->> 'authorizationRevision')::bigint;
  v_assurance_policy_revision := (v_pins ->> 'assurancePolicyRevision')::bigint;
  v_client_secret_revision := (v_pins ->> 'clientSecretRevision')::bigint;
  v_discovery_revision := (v_pins ->> 'discoveryRevision')::bigint;
  v_jwks_revision := (v_pins ->> 'jwksRevision')::bigint;
  v_verifier_key_version := (v_current ->> 'verifierKeyVersion')::integer;
  v_client_id := v_current ->> 'clientId';
  v_redirect_uri := v_current ->> 'redirectUri';
  v_post_logout_redirect_uri := v_current ->> 'postLogoutRedirectUri';
  v_return_path := v_current ->> 'returnPath';
  v_allow_refresh_token := (v_current ->> 'allowRefreshToken')::boolean;
  v_use_user_info := (v_current ->> 'useUserInfo')::boolean;
  SELECT coalesce(array_agg(item.value #>> '{}' ORDER BY item.ordinality), ARRAY[]::text[])
    INTO v_scopes
  FROM jsonb_array_elements(v_current -> 'scopes') WITH ORDINALITY AS item(value, ordinality);
  BEGIN
    v_created_at := (v_current ->> 'createdAt')::timestamptz;
    v_expires_at := (v_current ->> 'expiresAt')::timestamptz;
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'invalid federated authentication transaction request'
      USING ERRCODE = '22023';
  END;
  IF right(v_current ->> 'createdAt', 1) <> 'Z'
     OR right(v_current ->> 'expiresAt', 1) <> 'Z'
     OR NOT isfinite(v_created_at) OR NOT isfinite(v_expires_at)
     OR v_created_at NOT BETWEEN statement_timestamp() - interval '5 minutes'
                              AND statement_timestamp() + interval '30 seconds'
     OR v_expires_at - v_created_at NOT BETWEEN interval '1 minute' AND interval '15 minutes'
     OR v_current ->> 'state' <> 'pending'
     OR (v_current ->> 'version')::bigint <> 1
     OR v_verifier_key_version NOT BETWEEN 1 AND 32767
     OR octet_length(convert_to(v_client_id, 'UTF8')) NOT BETWEEN 1 AND 512
     OR btrim(v_client_id) <> v_client_id OR v_client_id ~ '[[:cntrl:]]'
     OR octet_length(convert_to(v_redirect_uri, 'UTF8')) NOT BETWEEN 1 AND 4096
     OR btrim(v_redirect_uri) <> v_redirect_uri OR v_redirect_uri ~ '[[:cntrl:]]'
     OR octet_length(convert_to(v_post_logout_redirect_uri, 'UTF8')) NOT BETWEEN 1 AND 4096
     OR btrim(v_post_logout_redirect_uri) <> v_post_logout_redirect_uri
     OR v_post_logout_redirect_uri ~ '[[:cntrl:]]'
     OR octet_length(convert_to(v_return_path, 'UTF8')) NOT BETWEEN 1 AND 2048
     OR left(v_return_path, 1) <> '/' OR left(v_return_path, 2) = '//'
     OR position(E'\\' IN v_return_path) > 0 OR v_return_path ~ '[[:cntrl:]]'
     OR cardinality(v_scopes) NOT BETWEEN 1 AND 32
     OR v_scopes[1] <> 'openid'
     OR cardinality(v_scopes) <> (SELECT count(DISTINCT value) FROM unnest(v_scopes) AS scope(value))
     OR v_scopes IS DISTINCT FROM (
       SELECT array_agg(value ORDER BY CASE WHEN value = 'openid' THEN 0 ELSE 1 END, value COLLATE "C")
       FROM unnest(v_scopes) AS scope(value)
     )
     OR EXISTS (
       SELECT 1
       FROM unnest(v_scopes) AS scope(value)
       WHERE octet_length(convert_to(scope.value, 'UTF8')) NOT BETWEEN 1 AND 128
          OR EXISTS (
            SELECT 1
            FROM generate_series(0, octet_length(convert_to(scope.value, 'UTF8')) - 1) AS position(value)
            WHERE get_byte(convert_to(scope.value, 'UTF8'), position.value) <> 33
              AND get_byte(convert_to(scope.value, 'UTF8'), position.value) NOT BETWEEN 35 AND 91
              AND get_byte(convert_to(scope.value, 'UTF8'), position.value) NOT BETWEEN 93 AND 126
          )
     ) THEN
    RAISE EXCEPTION 'invalid federated authentication transaction request'
      USING ERRCODE = '22023';
  END IF;

  v_operation_digest := sha256(convert_to(p_request::text, 'UTF8'));
  v_operation_lock := hashtextextended(
    'federated-transaction:oidc:operation:' || v_operation_run_id::text, 17283101
  );
  PERFORM pg_advisory_xact_lock(v_operation_lock);
  SELECT transaction.* INTO v_existing
  FROM public.tenant_federated_authentication_transactions AS transaction
  WHERE transaction.protocol = 'oidc'
    AND transaction.operation_run_id = v_operation_run_id
  FOR UPDATE;
  IF FOUND THEN
    IF v_existing.operation_digest IS DISTINCT FROM v_operation_digest THEN
      RETURN NULL;
    END IF;
    v_replay := true;
  END IF;
  IF v_expires_at <= clock_timestamp() THEN
    RETURN NULL;
  END IF;

  -- The start projection must still be the exact enabled tenant authority
  -- that produced it. Holding SHARE locks closes the configuration-update
  -- race until the immutable transaction is inserted.
  PERFORM 1
  FROM public.tenant_auth_providers AS provider
  JOIN public.tenant_auth_provider_bindings AS binding
    ON binding.tenant_id = provider.tenant_id
   AND binding.provider_id = provider.id
  JOIN public.tenant_federated_provider_policies AS policy
    ON policy.tenant_id = binding.tenant_id
   AND policy.provider_id = binding.provider_id
   AND policy.binding_id = binding.id
   AND policy.provider_kind = provider.kind
  JOIN public.tenant_oidc_provider_configurations AS configuration
    ON configuration.tenant_id = provider.tenant_id
   AND configuration.provider_id = provider.id
  JOIN public.tenant_oidc_client_secrets AS secret
    ON secret.tenant_id = configuration.tenant_id
   AND secret.provider_id = configuration.provider_id
   AND secret.revision = configuration.client_secret_revision
  JOIN public.tenant_oidc_discovery_snapshots AS discovery
    ON discovery.tenant_id = configuration.tenant_id
   AND discovery.provider_id = configuration.provider_id
   AND discovery.revision = configuration.discovery_revision
  JOIN public.tenant_oidc_jwks_snapshots AS jwks
    ON jwks.tenant_id = configuration.tenant_id
   AND jwks.provider_id = configuration.provider_id
   AND jwks.revision = configuration.jwks_revision
  JOIN public.identity_keyring_versions AS verifier_key
    ON verifier_key.key_version = v_verifier_key_version
  WHERE provider.tenant_id = v_tenant_id
    AND provider.id = v_provider_id
    AND provider.kind = 'oidc'
    AND provider.version::bigint = v_provider_revision
    AND provider.enabled AND provider.archived_at IS NULL
    AND binding.id = v_binding_id
    AND binding.version::bigint = v_binding_revision
    AND binding.mapping_revision = v_mapping_revision
    AND binding.auth_revision::bigint = v_authorization_revision
    AND binding.enabled AND binding.archived_at IS NULL
    AND policy.enabled
    AND policy.configuration_revision = v_configuration_revision
    AND policy.security_revision = v_security_revision
    AND policy.assurance_policy_revision = v_assurance_policy_revision
    AND configuration.version = v_configuration_revision
    AND configuration.client_secret_revision = v_client_secret_revision
    AND configuration.discovery_revision = v_discovery_revision
    AND configuration.jwks_revision = v_jwks_revision
    AND configuration.client_id = v_client_id
    AND configuration.redirect_uri = v_redirect_uri
    AND configuration.post_logout_redirect_uri = v_post_logout_redirect_uri
    AND ARRAY['openid']::text[] || configuration.extra_scopes = v_scopes
    AND configuration.allow_refresh_token = v_allow_refresh_token
    AND configuration.use_user_info = v_use_user_info
    AND secret.revision = v_client_secret_revision AND secret.retired_at IS NULL
    AND discovery.document_digest = v_discovery_digest
    AND discovery.revision = v_discovery_revision
    AND jwks.document_digest = v_jwks_digest
    AND jwks.revision = v_jwks_revision
    AND verifier_key.is_active AND verifier_key.retired_at IS NULL
  FOR SHARE;
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;
  IF v_replay THEN
    RETURN jsonb_build_object(
      'transactionId', replace(encode(v_existing.transaction_id, 'base64'), E'\n', ''),
      'version', 1,
      'state', 'pending',
      'replayed', true
    );
  END IF;

  v_receipt_lock := hashtextextended(
    'federated-transaction:receipt:' || encode(v_receipt_digest, 'hex'), 17283101
  );
  v_state_lock := hashtextextended(
    'federated-transaction:oidc:state:' || encode(v_state_digest, 'hex'), 17283101
  );
  v_current_browser_lock := hashtextextended(
    'federated-transaction:oidc:browser:' || encode(v_browser_digest, 'hex'), 17283101
  );
  v_transaction_lock := hashtextextended(
    'federated-transaction:oidc:id:' || encode(v_transaction_id, 'hex'), 17283101
  );
  PERFORM pg_advisory_xact_lock(v_receipt_lock);
  PERFORM pg_advisory_xact_lock(v_state_lock);
  IF v_previous_browser_digest IS NULL THEN
    PERFORM pg_advisory_xact_lock(v_current_browser_lock);
  ELSE
    v_previous_browser_lock := hashtextextended(
      'federated-transaction:oidc:browser:' || encode(v_previous_browser_digest, 'hex'), 17283101
    );
    PERFORM pg_advisory_xact_lock(least(v_current_browser_lock, v_previous_browser_lock));
    IF v_current_browser_lock <> v_previous_browser_lock THEN
      PERFORM pg_advisory_xact_lock(greatest(v_current_browser_lock, v_previous_browser_lock));
    END IF;
  END IF;
  PERFORM pg_advisory_xact_lock(v_transaction_lock);
  IF EXISTS (
       SELECT 1 FROM public.tenant_federated_authentication_transactions AS transaction
       WHERE transaction.receipt_digest = v_receipt_digest
     )
     OR EXISTS (
       SELECT 1 FROM public.tenant_federated_authentication_transactions AS transaction
       WHERE transaction.protocol = 'oidc' AND transaction.transaction_id = v_transaction_id
     )
     OR EXISTS (
       SELECT 1 FROM public.tenant_federated_authentication_transactions AS transaction
       WHERE transaction.protocol = 'oidc' AND transaction.state_digest = v_state_digest
     )
     OR ((v_previous_browser_digest IS NULL
          OR v_previous_browser_digest <> v_browser_digest)
       AND EXISTS (
         SELECT 1 FROM public.tenant_federated_authentication_transactions AS transaction
         WHERE transaction.protocol = 'oidc'
           AND transaction.browser_digest = v_browser_digest
           AND transaction.state IN ('pending','claimed')
       )) THEN
    RETURN NULL;
  END IF;
  IF v_expires_at <= clock_timestamp() THEN
    RETURN NULL;
  END IF;

  IF v_previous_browser_digest IS NOT NULL THEN
    UPDATE public.tenant_federated_authentication_transactions AS transaction
    SET state = 'expired',
        version = transaction.version + 1,
        completed_at = greatest(
          v_created_at, transaction.created_at,
          coalesce(transaction.claimed_at, transaction.created_at)
        ),
        failure_reason = 'expired'
    WHERE transaction.protocol = 'oidc'
      AND transaction.browser_digest = v_previous_browser_digest
      AND transaction.state IN ('pending','claimed');
  END IF;

  INSERT INTO public.tenant_federated_authentication_transactions (
    transaction_id, tenant_id, provider_id, binding_id, provider_kind, protocol,
    operation_run_id, operation_digest, receipt_digest, network_digest,
    account_digest, provider_digest, state_digest, relay_state_digest,
    browser_digest, nonce_digest, provider_revision, binding_revision,
    configuration_revision, security_revision, mapping_revision,
    authorization_revision, assurance_policy_revision, client_secret_revision,
    discovery_revision, discovery_digest, jwks_revision, jwks_digest,
    verifier_key_version, verifier_ciphertext, client_id, redirect_uri,
    post_logout_redirect_uri, scopes, allow_refresh_token, use_user_info,
    metadata_revision, metadata_digest, sp_key_revision, configuration_digest,
    request_id, return_path, state, version, claim_attempt_id, created_at,
    expires_at, claimed_at, completed_at, failure_reason
  ) VALUES (
    v_transaction_id, v_tenant_id, v_provider_id, v_binding_id, 'oidc', 'oidc',
    v_operation_run_id, v_operation_digest, v_receipt_digest, v_network_digest,
    v_account_digest, v_provider_digest, v_state_digest, NULL,
    v_browser_digest, v_nonce_digest, v_provider_revision, v_binding_revision,
    v_configuration_revision, v_security_revision, v_mapping_revision,
    v_authorization_revision, v_assurance_policy_revision, v_client_secret_revision,
    v_discovery_revision, v_discovery_digest, v_jwks_revision, v_jwks_digest,
    v_verifier_key_version, v_verifier_ciphertext, v_client_id, v_redirect_uri,
    v_post_logout_redirect_uri, v_scopes, v_allow_refresh_token, v_use_user_info,
    NULL, NULL, NULL, NULL, NULL, v_return_path, 'pending', 1, NULL,
    v_created_at, v_expires_at, NULL, NULL, NULL
  );
  RETURN jsonb_build_object(
    'transactionId', replace(encode(v_transaction_id, 'base64'), E'\n', ''),
    'version', 1,
    'state', 'pending',
    'replayed', false
  );
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.create_oidc_authentication_transaction_v1(jsonb)
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.create_oidc_authentication_transaction_v1(jsonb)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor, periapsis_audit_reader_owner,
       periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
       periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.create_oidc_authentication_transaction_v1(jsonb)
  TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.claim_oidc_authentication_transaction_v1(p_request jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_attempt_id bytea;
  v_state_digest bytea;
  v_browser_digest bytea;
  v_claimed_at timestamptz;
  v_transaction public.tenant_federated_authentication_transactions%ROWTYPE;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_request,
    ARRAY['attemptId','stateDigest','browserDigest','claimedAt'],
    ARRAY['attemptId','stateDigest','browserDigest','claimedAt'],
    16384
  );
  IF jsonb_typeof(p_request -> 'attemptId') <> 'string'
     OR jsonb_typeof(p_request -> 'stateDigest') <> 'string'
     OR jsonb_typeof(p_request -> 'browserDigest') <> 'string'
     OR jsonb_typeof(p_request -> 'claimedAt') <> 'string' THEN
    RAISE EXCEPTION 'invalid federated authentication transaction claim'
      USING ERRCODE = '22023';
  END IF;
  v_attempt_id := app.private_mfa_decode_base64_v1(p_request ->> 'attemptId', 32, 32);
  v_state_digest := app.private_mfa_decode_base64_v1(p_request ->> 'stateDigest', 32, 32);
  v_browser_digest := app.private_mfa_decode_base64_v1(p_request ->> 'browserDigest', 32, 32);
  BEGIN
    v_claimed_at := (p_request ->> 'claimedAt')::timestamptz;
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'invalid federated authentication transaction claim'
      USING ERRCODE = '22023';
  END;
  IF encode(v_attempt_id, 'hex') = repeat('00', 32)
     OR encode(v_state_digest, 'hex') = repeat('00', 32)
     OR encode(v_browser_digest, 'hex') = repeat('00', 32)
     OR v_state_digest = v_browser_digest
     OR right(p_request ->> 'claimedAt', 1) <> 'Z'
     OR NOT isfinite(v_claimed_at)
     OR v_claimed_at NOT BETWEEN statement_timestamp() - interval '5 minutes'
                              AND statement_timestamp() + interval '30 seconds' THEN
    RAISE EXCEPTION 'invalid federated authentication transaction claim'
      USING ERRCODE = '22023';
  END IF;

  SELECT transaction.* INTO v_transaction
  FROM public.tenant_federated_authentication_transactions AS transaction
  WHERE transaction.protocol = 'oidc'
    AND transaction.state_digest = v_state_digest
    AND transaction.browser_digest = v_browser_digest
  FOR UPDATE;
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;
  IF v_transaction.expires_at <= statement_timestamp() THEN
    UPDATE public.tenant_federated_authentication_transactions AS transaction
    SET state = 'expired',
        version = transaction.version + 1,
        completed_at = statement_timestamp(),
        failure_reason = 'expired'
    WHERE transaction.tenant_id = v_transaction.tenant_id
      AND transaction.transaction_id = v_transaction.transaction_id
      AND transaction.protocol = 'oidc'
      AND transaction.state IN ('pending','claimed')
      AND transaction.version = v_transaction.version;
    RETURN NULL;
  END IF;
  IF v_transaction.state = 'claimed' THEN
    IF v_transaction.version <> 2
       OR v_transaction.claim_attempt_id IS DISTINCT FROM v_attempt_id
       OR v_transaction.claimed_at IS DISTINCT FROM v_claimed_at THEN
      RETURN NULL;
    END IF;
  ELSIF v_transaction.state = 'pending' THEN
    IF v_transaction.version <> 1 OR v_claimed_at < v_transaction.created_at THEN
      RETURN NULL;
    END IF;
    IF v_claimed_at >= v_transaction.expires_at THEN
      UPDATE public.tenant_federated_authentication_transactions AS transaction
      SET state = 'expired',
          version = transaction.version + 1,
          completed_at = v_claimed_at,
          failure_reason = 'expired'
      WHERE transaction.tenant_id = v_transaction.tenant_id
        AND transaction.transaction_id = v_transaction.transaction_id
        AND transaction.protocol = 'oidc'
        AND transaction.state = 'pending'
        AND transaction.version = 1;
      RETURN NULL;
    END IF;
    UPDATE public.tenant_federated_authentication_transactions AS transaction
    SET state = 'claimed',
        version = transaction.version + 1,
        claim_attempt_id = v_attempt_id,
        claimed_at = v_claimed_at
    WHERE transaction.tenant_id = v_transaction.tenant_id
      AND transaction.transaction_id = v_transaction.transaction_id
      AND transaction.protocol = 'oidc'
      AND transaction.state = 'pending'
      AND transaction.version = 1
      AND transaction.state_digest = v_state_digest
      AND transaction.browser_digest = v_browser_digest
    RETURNING transaction.* INTO v_transaction;
    IF NOT FOUND THEN
      RETURN NULL;
    END IF;
  ELSE
    RETURN NULL;
  END IF;

  RETURN jsonb_build_object(
    'id', replace(encode(v_transaction.transaction_id, 'base64'), E'\n', ''),
    'stateDigest', replace(encode(v_transaction.state_digest, 'base64'), E'\n', ''),
    'browserDigest', replace(encode(v_transaction.browser_digest, 'base64'), E'\n', ''),
    'nonceDigest', replace(encode(v_transaction.nonce_digest, 'base64'), E'\n', ''),
    'verifierKeyVersion', v_transaction.verifier_key_version,
    'verifierCiphertext', replace(encode(v_transaction.verifier_ciphertext, 'base64'), E'\n', ''),
    'pins', jsonb_build_object(
      'provider', jsonb_build_object(
        'scope', 'tenant',
        'tenantId', v_transaction.tenant_id::text,
        'providerId', v_transaction.provider_id::text,
        'bindingId', v_transaction.binding_id::text
      ),
      'providerRevision', v_transaction.provider_revision,
      'bindingRevision', v_transaction.binding_revision,
      'configurationRevision', v_transaction.configuration_revision,
      'securityRevision', v_transaction.security_revision,
      'mappingRevision', v_transaction.mapping_revision,
      'authorizationRevision', v_transaction.authorization_revision,
      'assurancePolicyRevision', v_transaction.assurance_policy_revision,
      'clientSecretRevision', v_transaction.client_secret_revision,
      'discoveryRevision', v_transaction.discovery_revision,
      'discoveryDigest', replace(encode(v_transaction.discovery_digest, 'base64'), E'\n', ''),
      'jwksRevision', v_transaction.jwks_revision,
      'jwksDigest', replace(encode(v_transaction.jwks_digest, 'base64'), E'\n', '')
    ),
    'clientId', v_transaction.client_id,
    'redirectUri', v_transaction.redirect_uri,
    'postLogoutRedirectUri', v_transaction.post_logout_redirect_uri,
    'returnPath', v_transaction.return_path,
    'scopes', to_jsonb(v_transaction.scopes),
    'allowRefreshToken', v_transaction.allow_refresh_token,
    'useUserInfo', v_transaction.use_user_info,
    'createdAt', to_jsonb(v_transaction.created_at),
    'expiresAt', to_jsonb(v_transaction.expires_at),
    'state', v_transaction.state,
    'version', v_transaction.version,
    'claimAttemptId', replace(encode(v_transaction.claim_attempt_id, 'base64'), E'\n', ''),
    'claimedAt', to_jsonb(v_transaction.claimed_at)
  );
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.claim_oidc_authentication_transaction_v1(jsonb)
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.claim_oidc_authentication_transaction_v1(jsonb)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor, periapsis_audit_reader_owner,
       periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
       periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.claim_oidc_authentication_transaction_v1(jsonb)
  TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.fail_oidc_authentication_transaction_v1(p_request jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_transaction_id bytea;
  v_expected_version bigint;
  v_failed_at timestamptz;
  v_reason text;
  v_state text;
  v_transaction_lock bigint;
  v_match_count integer;
  v_transaction public.tenant_federated_authentication_transactions%ROWTYPE;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_request,
    ARRAY['id','expectedVersion','failedAt','reason','state'],
    ARRAY['id','expectedVersion','failedAt','reason','state'],
    16384
  );
  IF jsonb_typeof(p_request -> 'id') <> 'string'
     OR jsonb_typeof(p_request -> 'expectedVersion') <> 'number'
     OR jsonb_typeof(p_request -> 'failedAt') <> 'string'
     OR jsonb_typeof(p_request -> 'reason') <> 'string'
     OR jsonb_typeof(p_request -> 'state') <> 'string'
     OR p_request ->> 'expectedVersion' <> '2' THEN
    RAISE EXCEPTION 'invalid federated authentication transaction failure'
      USING ERRCODE = '22023';
  END IF;
  v_transaction_id := app.private_mfa_decode_base64_v1(p_request ->> 'id', 32, 32);
  v_expected_version := (p_request ->> 'expectedVersion')::bigint;
  v_reason := p_request ->> 'reason';
  v_state := p_request ->> 'state';
  BEGIN
    v_failed_at := (p_request ->> 'failedAt')::timestamptz;
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'invalid federated authentication transaction failure'
      USING ERRCODE = '22023';
  END;
  IF encode(v_transaction_id, 'hex') = repeat('00', 32)
     OR right(p_request ->> 'failedAt', 1) <> 'Z'
     OR NOT isfinite(v_failed_at)
     OR v_reason NOT IN ('provider_response','stale_configuration','expired',
       'token_exchange','token_validation','identity_application')
     OR v_state NOT IN ('failed','expired')
     OR (v_reason = 'expired') <> (v_state = 'expired') THEN
    RAISE EXCEPTION 'invalid federated authentication transaction failure'
      USING ERRCODE = '22023';
  END IF;

  v_transaction_lock := hashtextextended(
    'federated-transaction:oidc:id:' || encode(v_transaction_id, 'hex'), 17283101
  );
  PERFORM pg_advisory_xact_lock(v_transaction_lock);
  SELECT count(*)::integer INTO v_match_count
  FROM public.tenant_federated_authentication_transactions AS transaction
  WHERE transaction.protocol = 'oidc'
    AND transaction.transaction_id = v_transaction_id;
  IF v_match_count <> 1 THEN
    RETURN NULL;
  END IF;
  SELECT transaction.* INTO v_transaction
  FROM public.tenant_federated_authentication_transactions AS transaction
  WHERE transaction.protocol = 'oidc'
    AND transaction.transaction_id = v_transaction_id
  FOR UPDATE;

  IF v_transaction.state = v_state
     AND v_transaction.version = v_expected_version + 1
     AND v_transaction.completed_at IS NOT DISTINCT FROM v_failed_at
     AND v_transaction.failure_reason IS NOT DISTINCT FROM v_reason THEN
    RETURN jsonb_build_object(
      'transactionId', replace(encode(v_transaction.transaction_id, 'base64'), E'\n', ''),
      'version', v_transaction.version,
      'state', v_transaction.state,
      'replayed', true
    );
  END IF;
  IF v_failed_at NOT BETWEEN statement_timestamp() - interval '5 minutes'
                         AND statement_timestamp() + interval '30 seconds' THEN
    RETURN NULL;
  END IF;
  IF v_transaction.state <> 'claimed'
     OR v_transaction.version <> v_expected_version
     OR v_transaction.claimed_at IS NULL
     OR v_failed_at < v_transaction.claimed_at THEN
    RETURN NULL;
  END IF;
  UPDATE public.tenant_federated_authentication_transactions AS transaction
  SET state = v_state,
      version = transaction.version + 1,
      completed_at = v_failed_at,
      failure_reason = v_reason
  WHERE transaction.tenant_id = v_transaction.tenant_id
    AND transaction.transaction_id = v_transaction.transaction_id
    AND transaction.protocol = 'oidc'
    AND transaction.state = 'claimed'
    AND transaction.version = v_expected_version
    AND transaction.claim_attempt_id = v_transaction.claim_attempt_id
    AND transaction.claimed_at = v_transaction.claimed_at
  RETURNING transaction.* INTO v_transaction;
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;
  RETURN jsonb_build_object(
    'transactionId', replace(encode(v_transaction.transaction_id, 'base64'), E'\n', ''),
    'version', v_transaction.version,
    'state', v_transaction.state,
    'replayed', false
  );
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.fail_oidc_authentication_transaction_v1(jsonb)
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.fail_oidc_authentication_transaction_v1(jsonb)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor, periapsis_audit_reader_owner,
       periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
       periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.fail_oidc_authentication_transaction_v1(jsonb)
  TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.create_saml_authentication_transaction_v1(p_request jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_begin jsonb;
  v_current jsonb;
  v_pins jsonb;
  v_provider jsonb;
  v_operation_run_id uuid;
  v_operation_digest bytea;
  v_receipt_digest bytea;
  v_network_digest bytea;
  v_account_digest bytea;
  v_provider_digest bytea;
  v_transaction_id bytea;
  v_relay_state_digest bytea;
  v_browser_digest bytea;
  v_previous_browser_digest bytea;
  v_metadata_digest bytea;
  v_configuration_digest bytea;
  v_tenant_id uuid;
  v_provider_id uuid;
  v_binding_id uuid;
  v_provider_revision bigint;
  v_binding_revision bigint;
  v_configuration_revision bigint;
  v_security_revision bigint;
  v_mapping_revision bigint;
  v_authorization_revision bigint;
  v_assurance_policy_revision bigint;
  v_metadata_revision bigint;
  v_sp_key_revision bigint;
  v_request_id text;
  v_return_path text;
  v_created_at timestamptz;
  v_expires_at timestamptz;
  v_operation_lock bigint;
  v_receipt_lock bigint;
  v_relay_state_lock bigint;
  v_current_browser_lock bigint;
  v_previous_browser_lock bigint;
  v_transaction_lock bigint;
  v_existing public.tenant_federated_authentication_transactions%ROWTYPE;
  v_replay boolean := false;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_request,
    ARRAY['begin','current','previousBrowserDigest'],
    ARRAY['begin','current'],
    65536
  );
  v_begin := p_request -> 'begin';
  v_current := p_request -> 'current';
  PERFORM app.private_mfa_assert_json_object_v1(
    v_begin,
    ARRAY['operationRunId','receiptDigest','networkDigest','accountDigest','providerDigest'],
    ARRAY['operationRunId','receiptDigest','networkDigest','accountDigest','providerDigest'],
    4096
  );
  PERFORM app.private_mfa_assert_json_object_v1(
    v_current,
    ARRAY['id','requestId','relayStateDigest','browserDigest','pins','createdAt',
      'expiresAt','returnPath','state','version'],
    ARRAY['id','requestId','relayStateDigest','browserDigest','pins','createdAt',
      'expiresAt','returnPath','state','version'],
    65536
  );
  v_pins := v_current -> 'pins';
  PERFORM app.private_mfa_assert_json_object_v1(
    v_pins,
    ARRAY['provider','providerRevision','bindingRevision','configurationRevision',
      'securityRevision','mappingRevision','authorizationRevision',
      'assurancePolicyRevision','metadataRevision','metadataDigest','spKeyRevision',
      'configurationDigest'],
    ARRAY['provider','providerRevision','bindingRevision','configurationRevision',
      'securityRevision','mappingRevision','authorizationRevision',
      'assurancePolicyRevision','metadataRevision','metadataDigest','spKeyRevision',
      'configurationDigest'],
    16384
  );
  v_provider := v_pins -> 'provider';
  PERFORM app.private_mfa_assert_json_object_v1(
    v_provider,
    ARRAY['scope','tenantId','providerId','bindingId'],
    ARRAY['scope','tenantId','providerId','bindingId'],
    4096
  );

  IF jsonb_typeof(v_begin -> 'operationRunId') <> 'string'
     OR jsonb_typeof(v_begin -> 'receiptDigest') <> 'string'
     OR jsonb_typeof(v_begin -> 'networkDigest') <> 'string'
     OR jsonb_typeof(v_begin -> 'accountDigest') <> 'string'
     OR jsonb_typeof(v_begin -> 'providerDigest') <> 'string'
     OR jsonb_typeof(v_current -> 'id') <> 'string'
     OR jsonb_typeof(v_current -> 'requestId') <> 'string'
     OR jsonb_typeof(v_current -> 'relayStateDigest') <> 'string'
     OR jsonb_typeof(v_current -> 'browserDigest') <> 'string'
     OR jsonb_typeof(v_current -> 'createdAt') <> 'string'
     OR jsonb_typeof(v_current -> 'expiresAt') <> 'string'
     OR jsonb_typeof(v_current -> 'returnPath') <> 'string'
     OR jsonb_typeof(v_current -> 'state') <> 'string'
     OR jsonb_typeof(v_current -> 'version') <> 'number'
     OR jsonb_typeof(v_provider -> 'scope') <> 'string'
     OR jsonb_typeof(v_provider -> 'tenantId') <> 'string'
     OR jsonb_typeof(v_provider -> 'providerId') <> 'string'
     OR jsonb_typeof(v_provider -> 'bindingId') <> 'string'
     OR EXISTS (
       SELECT 1
       FROM unnest(ARRAY['providerRevision','bindingRevision','configurationRevision',
         'securityRevision','mappingRevision','authorizationRevision',
         'assurancePolicyRevision','metadataRevision','spKeyRevision']) AS key(value)
       WHERE jsonb_typeof(v_pins -> key.value) <> 'number'
     )
     OR jsonb_typeof(v_pins -> 'metadataDigest') <> 'string'
     OR jsonb_typeof(v_pins -> 'configurationDigest') <> 'string'
     OR (p_request ? 'previousBrowserDigest'
       AND jsonb_typeof(p_request -> 'previousBrowserDigest') <> 'string')
     OR v_current ->> 'version' !~ '^[1-9][0-9]{0,18}$'
     OR v_current ->> 'version' <> '1'
     OR EXISTS (
       SELECT 1
       FROM unnest(ARRAY['providerRevision','bindingRevision','configurationRevision',
         'securityRevision','mappingRevision','authorizationRevision',
         'assurancePolicyRevision','metadataRevision','spKeyRevision']) AS key(value)
       WHERE v_pins ->> key.value !~ '^[1-9][0-9]{0,18}$'
          OR (v_pins ->> key.value)::numeric > 9223372036854775807::numeric
     ) THEN
    RAISE EXCEPTION 'invalid federated authentication transaction request'
      USING ERRCODE = '22023';
  END IF;

  v_operation_run_id := app.private_mfa_require_uuidv7_v1(v_begin ->> 'operationRunId');
  v_tenant_id := app.private_mfa_require_uuidv7_v1(v_provider ->> 'tenantId');
  v_provider_id := app.private_mfa_require_uuidv7_v1(v_provider ->> 'providerId');
  v_binding_id := app.private_mfa_require_uuidv7_v1(v_provider ->> 'bindingId');
  IF v_begin ->> 'operationRunId' <> v_operation_run_id::text
     OR v_provider ->> 'tenantId' <> v_tenant_id::text
     OR v_provider ->> 'providerId' <> v_provider_id::text
     OR v_provider ->> 'bindingId' <> v_binding_id::text
     OR substring(v_operation_run_id::text, 20, 1) NOT IN ('8','9','a','b')
     OR substring(v_tenant_id::text, 20, 1) NOT IN ('8','9','a','b')
     OR substring(v_provider_id::text, 20, 1) NOT IN ('8','9','a','b')
     OR substring(v_binding_id::text, 20, 1) NOT IN ('8','9','a','b')
     OR v_provider ->> 'scope' <> 'tenant' THEN
    RAISE EXCEPTION 'invalid federated authentication transaction request'
      USING ERRCODE = '22023';
  END IF;

  v_receipt_digest := app.private_mfa_decode_base64_v1(v_begin ->> 'receiptDigest', 32, 32);
  v_network_digest := app.private_mfa_decode_base64_v1(v_begin ->> 'networkDigest', 32, 32);
  v_account_digest := app.private_mfa_decode_base64_v1(v_begin ->> 'accountDigest', 32, 32);
  v_provider_digest := app.private_mfa_decode_base64_v1(v_begin ->> 'providerDigest', 32, 32);
  v_transaction_id := app.private_mfa_decode_base64_v1(v_current ->> 'id', 32, 32);
  v_relay_state_digest := app.private_mfa_decode_base64_v1(v_current ->> 'relayStateDigest', 32, 32);
  v_browser_digest := app.private_mfa_decode_base64_v1(v_current ->> 'browserDigest', 32, 32);
  v_metadata_digest := app.private_mfa_decode_base64_v1(v_pins ->> 'metadataDigest', 32, 32);
  v_configuration_digest := app.private_mfa_decode_base64_v1(
    v_pins ->> 'configurationDigest', 32, 32
  );
  IF p_request ? 'previousBrowserDigest' THEN
    v_previous_browser_digest := app.private_mfa_decode_base64_v1(
      p_request ->> 'previousBrowserDigest', 32, 32
    );
  END IF;
  IF encode(v_receipt_digest, 'hex') = repeat('00', 32)
     OR encode(v_network_digest, 'hex') = repeat('00', 32)
     OR encode(v_account_digest, 'hex') = repeat('00', 32)
     OR encode(v_provider_digest, 'hex') = repeat('00', 32)
     OR encode(v_transaction_id, 'hex') = repeat('00', 32)
     OR encode(v_relay_state_digest, 'hex') = repeat('00', 32)
     OR encode(v_browser_digest, 'hex') = repeat('00', 32)
     OR encode(v_metadata_digest, 'hex') = repeat('00', 32)
     OR encode(v_configuration_digest, 'hex') = repeat('00', 32)
     OR (v_previous_browser_digest IS NOT NULL
       AND encode(v_previous_browser_digest, 'hex') = repeat('00', 32))
     OR v_receipt_digest IN (v_network_digest, v_account_digest, v_provider_digest)
     OR v_network_digest IN (v_account_digest, v_provider_digest)
     OR v_account_digest = v_provider_digest
     OR v_relay_state_digest = v_browser_digest THEN
    RAISE EXCEPTION 'invalid federated authentication transaction request'
      USING ERRCODE = '22023';
  END IF;

  v_provider_revision := (v_pins ->> 'providerRevision')::bigint;
  v_binding_revision := (v_pins ->> 'bindingRevision')::bigint;
  v_configuration_revision := (v_pins ->> 'configurationRevision')::bigint;
  v_security_revision := (v_pins ->> 'securityRevision')::bigint;
  v_mapping_revision := (v_pins ->> 'mappingRevision')::bigint;
  v_authorization_revision := (v_pins ->> 'authorizationRevision')::bigint;
  v_assurance_policy_revision := (v_pins ->> 'assurancePolicyRevision')::bigint;
  v_metadata_revision := (v_pins ->> 'metadataRevision')::bigint;
  v_sp_key_revision := (v_pins ->> 'spKeyRevision')::bigint;
  v_request_id := v_current ->> 'requestId';
  v_return_path := v_current ->> 'returnPath';
  BEGIN
    v_created_at := (v_current ->> 'createdAt')::timestamptz;
    v_expires_at := (v_current ->> 'expiresAt')::timestamptz;
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'invalid federated authentication transaction request'
      USING ERRCODE = '22023';
  END;
  IF right(v_current ->> 'createdAt', 1) <> 'Z'
     OR right(v_current ->> 'expiresAt', 1) <> 'Z'
     OR NOT isfinite(v_created_at) OR NOT isfinite(v_expires_at)
     OR v_created_at NOT BETWEEN statement_timestamp() - interval '5 minutes'
                              AND statement_timestamp() + interval '30 seconds'
     OR v_expires_at - v_created_at NOT BETWEEN interval '1 minute' AND interval '15 minutes'
     OR v_current ->> 'state' <> 'pending'
     OR (v_current ->> 'version')::bigint <> 1
     OR octet_length(convert_to(v_request_id, 'UTF8')) NOT BETWEEN 1 AND 1024
     OR btrim(v_request_id) <> v_request_id OR v_request_id ~ '[[:cntrl:]]'
     OR octet_length(convert_to(v_return_path, 'UTF8')) NOT BETWEEN 1 AND 2048
     OR left(v_return_path, 1) <> '/' OR left(v_return_path, 2) = '//'
     OR position(E'\\' IN v_return_path) > 0 OR v_return_path ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION 'invalid federated authentication transaction request'
      USING ERRCODE = '22023';
  END IF;

  v_operation_digest := sha256(convert_to(p_request::text, 'UTF8'));
  v_operation_lock := hashtextextended(
    'federated-transaction:saml:operation:' || v_operation_run_id::text, 17283101
  );
  PERFORM pg_advisory_xact_lock(v_operation_lock);
  SELECT transaction.* INTO v_existing
  FROM public.tenant_federated_authentication_transactions AS transaction
  WHERE transaction.protocol = 'saml'
    AND transaction.operation_run_id = v_operation_run_id
  FOR UPDATE;
  IF FOUND THEN
    IF v_existing.operation_digest IS DISTINCT FROM v_operation_digest THEN
      RETURN NULL;
    END IF;
    v_replay := true;
  END IF;
  IF v_expires_at <= clock_timestamp() THEN
    RETURN NULL;
  END IF;

  PERFORM 1
  FROM public.tenant_auth_providers AS provider
  JOIN public.tenant_auth_provider_bindings AS binding
    ON binding.tenant_id = provider.tenant_id
   AND binding.provider_id = provider.id
  JOIN public.tenant_federated_provider_policies AS policy
    ON policy.tenant_id = binding.tenant_id
   AND policy.provider_id = binding.provider_id
   AND policy.binding_id = binding.id
   AND policy.provider_kind = provider.kind
  JOIN public.tenant_saml_provider_configurations AS configuration
    ON configuration.tenant_id = provider.tenant_id
   AND configuration.provider_id = provider.id
  JOIN public.tenant_saml_metadata_snapshots AS metadata
    ON metadata.tenant_id = configuration.tenant_id
   AND metadata.provider_id = configuration.provider_id
   AND metadata.revision = configuration.metadata_revision
  JOIN public.tenant_saml_sp_keys AS sp_key
    ON sp_key.tenant_id = configuration.tenant_id
   AND sp_key.provider_id = configuration.provider_id
   AND sp_key.revision = configuration.sp_key_revision
  WHERE provider.tenant_id = v_tenant_id
    AND provider.id = v_provider_id
    AND provider.kind = 'saml'
    AND provider.version::bigint = v_provider_revision
    AND provider.enabled AND provider.archived_at IS NULL
    AND binding.id = v_binding_id
    AND binding.version::bigint = v_binding_revision
    AND binding.mapping_revision = v_mapping_revision
    AND binding.auth_revision::bigint = v_authorization_revision
    AND binding.enabled AND binding.archived_at IS NULL
    AND policy.enabled
    AND policy.configuration_revision = v_configuration_revision
    AND policy.security_revision = v_security_revision
    AND policy.assurance_policy_revision = v_assurance_policy_revision
    AND configuration.version = v_configuration_revision
    AND configuration.metadata_revision = v_metadata_revision
    AND configuration.sp_key_revision = v_sp_key_revision
    AND metadata.revision = v_metadata_revision
    AND metadata.document_digest = v_metadata_digest
    AND sp_key.revision = v_sp_key_revision
    AND sp_key.retired_at IS NULL
  FOR SHARE;
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;
  IF v_replay THEN
    RETURN jsonb_build_object(
      'transactionId', replace(encode(v_existing.transaction_id, 'base64'), E'\n', ''),
      'version', 1,
      'state', 'pending',
      'replayed', true
    );
  END IF;

  v_receipt_lock := hashtextextended(
    'federated-transaction:receipt:' || encode(v_receipt_digest, 'hex'), 17283101
  );
  v_relay_state_lock := hashtextextended(
    'federated-transaction:saml:relay:' || encode(v_relay_state_digest, 'hex'), 17283101
  );
  v_current_browser_lock := hashtextextended(
    'federated-transaction:saml:browser:' || encode(v_browser_digest, 'hex'), 17283101
  );
  v_transaction_lock := hashtextextended(
    'federated-transaction:saml:id:' || encode(v_transaction_id, 'hex'), 17283101
  );
  PERFORM pg_advisory_xact_lock(v_receipt_lock);
  PERFORM pg_advisory_xact_lock(v_relay_state_lock);
  IF v_previous_browser_digest IS NULL THEN
    PERFORM pg_advisory_xact_lock(v_current_browser_lock);
  ELSE
    v_previous_browser_lock := hashtextextended(
      'federated-transaction:saml:browser:' || encode(v_previous_browser_digest, 'hex'), 17283101
    );
    PERFORM pg_advisory_xact_lock(least(v_current_browser_lock, v_previous_browser_lock));
    IF v_current_browser_lock <> v_previous_browser_lock THEN
      PERFORM pg_advisory_xact_lock(greatest(v_current_browser_lock, v_previous_browser_lock));
    END IF;
  END IF;
  PERFORM pg_advisory_xact_lock(v_transaction_lock);
  IF EXISTS (
       SELECT 1 FROM public.tenant_federated_authentication_transactions AS transaction
       WHERE transaction.receipt_digest = v_receipt_digest
     )
     OR EXISTS (
       SELECT 1 FROM public.tenant_federated_authentication_transactions AS transaction
       WHERE transaction.protocol = 'saml' AND transaction.transaction_id = v_transaction_id
     )
     OR EXISTS (
       SELECT 1 FROM public.tenant_federated_authentication_transactions AS transaction
       WHERE transaction.protocol = 'saml' AND transaction.relay_state_digest = v_relay_state_digest
     )
     OR ((v_previous_browser_digest IS NULL
          OR v_previous_browser_digest <> v_browser_digest)
       AND EXISTS (
         SELECT 1 FROM public.tenant_federated_authentication_transactions AS transaction
         WHERE transaction.protocol = 'saml'
           AND transaction.browser_digest = v_browser_digest
           AND transaction.state IN ('pending','claimed')
       )) THEN
    RETURN NULL;
  END IF;
  IF v_expires_at <= clock_timestamp() THEN
    RETURN NULL;
  END IF;

  IF v_previous_browser_digest IS NOT NULL THEN
    UPDATE public.tenant_federated_authentication_transactions AS transaction
    SET state = 'expired',
        version = transaction.version + 1,
        completed_at = greatest(v_created_at, transaction.created_at),
        failure_reason = 'expired'
    WHERE transaction.protocol = 'saml'
      AND transaction.browser_digest = v_previous_browser_digest
      AND transaction.state = 'pending';
  END IF;

  INSERT INTO public.tenant_federated_authentication_transactions (
    transaction_id, tenant_id, provider_id, binding_id, provider_kind, protocol,
    operation_run_id, operation_digest, receipt_digest, network_digest,
    account_digest, provider_digest, state_digest, relay_state_digest,
    browser_digest, nonce_digest, provider_revision, binding_revision,
    configuration_revision, security_revision, mapping_revision,
    authorization_revision, assurance_policy_revision, client_secret_revision,
    discovery_revision, discovery_digest, jwks_revision, jwks_digest,
    verifier_key_version, verifier_ciphertext, client_id, redirect_uri,
    post_logout_redirect_uri, scopes, allow_refresh_token, use_user_info,
    metadata_revision, metadata_digest, sp_key_revision, configuration_digest,
    request_id, return_path, state, version, claim_attempt_id, created_at,
    expires_at, claimed_at, completed_at, failure_reason
  ) VALUES (
    v_transaction_id, v_tenant_id, v_provider_id, v_binding_id, 'saml', 'saml',
    v_operation_run_id, v_operation_digest, v_receipt_digest, v_network_digest,
    v_account_digest, v_provider_digest, NULL, v_relay_state_digest,
    v_browser_digest, NULL, v_provider_revision, v_binding_revision,
    v_configuration_revision, v_security_revision, v_mapping_revision,
    v_authorization_revision, v_assurance_policy_revision, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    v_metadata_revision, v_metadata_digest, v_sp_key_revision,
    v_configuration_digest, v_request_id, v_return_path, 'pending', 1, NULL,
    v_created_at, v_expires_at, NULL, NULL, NULL
  );
  RETURN jsonb_build_object(
    'transactionId', replace(encode(v_transaction_id, 'base64'), E'\n', ''),
    'version', 1,
    'state', 'pending',
    'replayed', false
  );
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.create_saml_authentication_transaction_v1(jsonb)
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.create_saml_authentication_transaction_v1(jsonb)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor, periapsis_audit_reader_owner,
       periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
       periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.create_saml_authentication_transaction_v1(jsonb)
  TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.lookup_saml_authentication_transaction_v1(p_request jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_relay_state_digest bytea;
  v_browser_digest bytea;
  v_observed_at timestamptz;
  v_transaction public.tenant_federated_authentication_transactions%ROWTYPE;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_request,
    ARRAY['relayStateDigest','browserDigest','observedAt'],
    ARRAY['relayStateDigest','browserDigest','observedAt'],
    16384
  );
  IF jsonb_typeof(p_request -> 'relayStateDigest') <> 'string'
     OR jsonb_typeof(p_request -> 'browserDigest') <> 'string'
     OR jsonb_typeof(p_request -> 'observedAt') <> 'string' THEN
    RAISE EXCEPTION 'invalid federated authentication transaction lookup'
      USING ERRCODE = '22023';
  END IF;
  v_relay_state_digest := app.private_mfa_decode_base64_v1(
    p_request ->> 'relayStateDigest', 32, 32
  );
  v_browser_digest := app.private_mfa_decode_base64_v1(
    p_request ->> 'browserDigest', 32, 32
  );
  BEGIN
    v_observed_at := (p_request ->> 'observedAt')::timestamptz;
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'invalid federated authentication transaction lookup'
      USING ERRCODE = '22023';
  END;
  IF encode(v_relay_state_digest, 'hex') = repeat('00', 32)
     OR encode(v_browser_digest, 'hex') = repeat('00', 32)
     OR v_relay_state_digest = v_browser_digest
     OR right(p_request ->> 'observedAt', 1) <> 'Z'
     OR NOT isfinite(v_observed_at)
     OR v_observed_at NOT BETWEEN statement_timestamp() - interval '5 minutes'
                               AND statement_timestamp() + interval '30 seconds' THEN
    RAISE EXCEPTION 'invalid federated authentication transaction lookup'
      USING ERRCODE = '22023';
  END IF;

  SELECT transaction.* INTO v_transaction
  FROM public.tenant_federated_authentication_transactions AS transaction
  WHERE transaction.protocol = 'saml'
    AND transaction.relay_state_digest = v_relay_state_digest
    AND transaction.browser_digest = v_browser_digest
  FOR UPDATE;
  IF NOT FOUND OR v_transaction.state <> 'pending'
     OR v_transaction.version <> 1 OR v_observed_at < v_transaction.created_at THEN
    RETURN NULL;
  END IF;
  IF v_observed_at >= v_transaction.expires_at
     OR statement_timestamp() >= v_transaction.expires_at THEN
    UPDATE public.tenant_federated_authentication_transactions AS transaction
    SET state = 'expired',
        version = transaction.version + 1,
        completed_at = greatest(v_observed_at, statement_timestamp()),
        failure_reason = 'expired'
    WHERE transaction.tenant_id = v_transaction.tenant_id
      AND transaction.transaction_id = v_transaction.transaction_id
      AND transaction.protocol = 'saml'
      AND transaction.state = 'pending'
      AND transaction.version = 1
      AND transaction.relay_state_digest = v_relay_state_digest
      AND transaction.browser_digest = v_browser_digest;
    RETURN NULL;
  END IF;

  RETURN jsonb_build_object(
    'id', replace(encode(v_transaction.transaction_id, 'base64'), E'\n', ''),
    'requestId', v_transaction.request_id,
    'relayStateDigest', replace(encode(v_transaction.relay_state_digest, 'base64'), E'\n', ''),
    'browserDigest', replace(encode(v_transaction.browser_digest, 'base64'), E'\n', ''),
    'pins', jsonb_build_object(
      'provider', jsonb_build_object(
        'scope', 'tenant',
        'tenantId', v_transaction.tenant_id::text,
        'providerId', v_transaction.provider_id::text,
        'bindingId', v_transaction.binding_id::text
      ),
      'providerRevision', v_transaction.provider_revision,
      'bindingRevision', v_transaction.binding_revision,
      'configurationRevision', v_transaction.configuration_revision,
      'securityRevision', v_transaction.security_revision,
      'mappingRevision', v_transaction.mapping_revision,
      'authorizationRevision', v_transaction.authorization_revision,
      'assurancePolicyRevision', v_transaction.assurance_policy_revision,
      'metadataRevision', v_transaction.metadata_revision,
      'metadataDigest', replace(encode(v_transaction.metadata_digest, 'base64'), E'\n', ''),
      'spKeyRevision', v_transaction.sp_key_revision,
      'configurationDigest', replace(encode(v_transaction.configuration_digest, 'base64'), E'\n', '')
    ),
    'createdAt', to_jsonb(v_transaction.created_at),
    'expiresAt', to_jsonb(v_transaction.expires_at),
    'returnPath', v_transaction.return_path,
    'state', v_transaction.state,
    'version', v_transaction.version
  );
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.lookup_saml_authentication_transaction_v1(jsonb)
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.lookup_saml_authentication_transaction_v1(jsonb)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor, periapsis_audit_reader_owner,
       periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
       periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.lookup_saml_authentication_transaction_v1(jsonb)
  TO periapsis_api;
--> statement-breakpoint
