-- Retire every live predecessor SAML authority. A predecessor may have an
-- aad_version=1 envelope bound to a mutable owner or no material row at all;
-- neither state can be upgraded safely. PostgreSQL cannot decrypt/re-encrypt
-- the envelope, so the upgrade revokes the authority atomically and retains
-- any legacy row only as non-usable evidence.
LOCK TABLE public.tenant_saml_session_materials,
  public.auth_sessions,
  public.auth_session_federated_provenance,
  public.tenant_post_primary_continuations IN SHARE ROW EXCLUSIVE MODE;
--> statement-breakpoint

INSERT INTO public.audit_events (
  id, tenant_id, sequence, occurred_at, actor_type, actor_user_id,
  action, resource_type, resource_id, authentication_method,
  outcome, metadata
)
SELECT uuidv7(), source_session.active_tenant_id, 0, transaction_timestamp(),
  'system', NULL,
  'tenant.identity.saml_legacy_material_retired', 'auth_session',
  source_session.id, 'saml', 'success', jsonb_build_object(
    'legacy_material_state', CASE WHEN EXISTS (
      SELECT 1 FROM public.tenant_saml_session_materials AS material
      WHERE material.tenant_id = source_session.active_tenant_id
        AND material.session_id = source_session.id
        AND material.aad_version = 1
    ) THEN 'aad_v1' ELSE 'absent' END,
    'authority_revoked', true,
    'material_disclosed', false
  )
FROM public.auth_sessions AS source_session
JOIN public.auth_session_federated_provenance AS provenance
  ON provenance.tenant_id = source_session.active_tenant_id
 AND provenance.session_id = source_session.id
 AND provenance.user_id = source_session.user_id
 AND provenance.primary_kind = 'tenant_provider'
 AND provenance.authentication_method = 'saml'
 AND provenance.provider_kind = 'saml'
WHERE source_session.authentication_method = 'saml'
  AND source_session.revoked_at IS NULL;
--> statement-breakpoint

UPDATE public.auth_sessions AS family
SET revoked_at = transaction_timestamp(),
    revoke_reason = 'saml_legacy_material_retired'
FROM public.auth_sessions AS source_session
JOIN public.auth_session_federated_provenance AS provenance
  ON provenance.tenant_id = source_session.active_tenant_id
 AND provenance.session_id = source_session.id
 AND provenance.user_id = source_session.user_id
 AND provenance.primary_kind = 'tenant_provider'
 AND provenance.authentication_method = 'saml'
 AND provenance.provider_kind = 'saml'
WHERE source_session.authentication_method = 'saml'
  AND source_session.revoked_at IS NULL
  AND family.user_id = source_session.user_id
  AND family.rotation_family_id = source_session.rotation_family_id
  AND family.revoked_at IS NULL;
--> statement-breakpoint

INSERT INTO public.audit_events (
  id, tenant_id, sequence, occurred_at, actor_type, actor_user_id,
  action, resource_type, resource_id, authentication_method,
  outcome, metadata
)
SELECT uuidv7(), continuation.tenant_id, 0, transaction_timestamp(),
  'system', NULL,
  'tenant.identity.saml_legacy_material_retired',
  'post_primary_continuation', continuation.id, 'saml', 'success',
  jsonb_build_object(
    'legacy_material_state', CASE WHEN EXISTS (
      SELECT 1 FROM public.tenant_saml_session_materials AS material
      WHERE material.tenant_id = continuation.tenant_id
        AND material.continuation_id = continuation.id
        AND material.aad_version = 1
    ) THEN 'aad_v1' ELSE 'absent' END,
    'authority_revoked', true,
    'material_disclosed', false
  )
FROM public.tenant_post_primary_continuations AS continuation
WHERE continuation.primary_kind = 'tenant_provider'
  AND continuation.provider_kind = 'saml'
  AND continuation.state = 'pending';
--> statement-breakpoint

-- A predecessor continuation can remain pending after its live provider or
-- access provenance has already been retired. Such an authority must still be
-- revoked during the cutover, but the canonical provenance trigger correctly
-- rejects ordinary writes to that drifted row. Verify the exact trigger before
-- suspending it under the table lock acquired above, and restore it immediately
-- after the one-way revocation. Any failure rolls the whole migration back,
-- including the trigger state.
DO $migration$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_trigger AS trigger
    WHERE trigger.tgname =
            'tenant_post_primary_continuations_federated_provenance_v1'
      AND trigger.tgrelid =
            'public.tenant_post_primary_continuations'::regclass
      AND trigger.tgfoid =
            'app.validate_federated_continuation_provenance_v1()'::regprocedure
      AND trigger.tgtype = 23
      AND trigger.tgqual IS NULL
      AND trigger.tgnargs = 0
      AND NOT trigger.tgisinternal
      AND trigger.tgenabled = 'O'
  ) THEN
    RAISE EXCEPTION 'canonical continuation provenance trigger is unavailable'
      USING ERRCODE = '55000';
  END IF;
END;
$migration$;
--> statement-breakpoint
ALTER TABLE public.tenant_post_primary_continuations
  DISABLE TRIGGER tenant_post_primary_continuations_federated_provenance_v1;
--> statement-breakpoint
UPDATE public.tenant_post_primary_continuations AS continuation
SET state = 'revoked',
    version = continuation.version + 1,
    revoked_at = transaction_timestamp(),
    revoke_reason = 'saml_legacy_material_retired'
WHERE continuation.primary_kind = 'tenant_provider'
  AND continuation.provider_kind = 'saml'
  AND continuation.state = 'pending';
--> statement-breakpoint
ALTER TABLE public.tenant_post_primary_continuations
  ENABLE TRIGGER tenant_post_primary_continuations_federated_provenance_v1;
--> statement-breakpoint

ALTER TABLE public.tenant_saml_logout_commands OWNER TO periapsis_migrator;
--> statement-breakpoint
ALTER TABLE public.tenant_saml_logout_commands FORCE ROW LEVEL SECURITY;
--> statement-breakpoint
REVOKE ALL ON TABLE public.tenant_saml_logout_commands
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor, periapsis_audit_reader_owner,
       periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
       periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
--> statement-breakpoint

CREATE TRIGGER tenant_saml_logout_commands_immutable_v1
BEFORE UPDATE OR DELETE ON public.tenant_saml_logout_commands
FOR EACH ROW EXECUTE FUNCTION app.guard_federated_immutable_ledger_v1();
--> statement-breakpoint

CREATE FUNCTION app.guard_saml_session_material_v2()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.aad_version <> 2 OR NOT EXISTS (
      SELECT 1
      FROM public.tenant_federated_authentication_transactions AS transaction
      WHERE transaction.tenant_id = NEW.tenant_id
        AND transaction.operation_run_id = NEW.id
        AND transaction.protocol = 'saml'
        AND transaction.provider_id = NEW.provider_id
        AND transaction.binding_id = NEW.binding_id
        AND transaction.provider_kind = 'saml'
        AND transaction.state = 'pending'
    ) THEN
      RAISE EXCEPTION 'SAML material identity is unavailable'
        USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
  END IF;

  IF OLD.aad_version <> 2 OR NEW.aad_version <> 2
     OR NEW.id IS DISTINCT FROM OLD.id
     OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.user_id IS DISTINCT FROM OLD.user_id
     OR NEW.provider_id IS DISTINCT FROM OLD.provider_id
     OR NEW.binding_id IS DISTINCT FROM OLD.binding_id
     OR NEW.provider_kind IS DISTINCT FROM OLD.provider_kind
     OR NEW.external_identity_id IS DISTINCT FROM OLD.external_identity_id
     OR NEW.session_index_digest IS DISTINCT FROM OLD.session_index_digest
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'SAML material immutable identity changed'
      USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.guard_saml_session_material_v2()
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_saml_session_material_v2()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor, periapsis_audit_reader_owner,
       periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
       periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
--> statement-breakpoint
CREATE TRIGGER tenant_saml_session_materials_v2_guard
BEFORE INSERT OR UPDATE ON public.tenant_saml_session_materials
FOR EACH ROW EXECUTE FUNCTION app.guard_saml_session_material_v2();
--> statement-breakpoint

-- Preserve the predecessor implementations as private implementation details.
-- Only the stable wrappers below remain executable by the API runtime role.
ALTER FUNCTION app.lookup_saml_authentication_transaction_v1(jsonb)
  RENAME TO private_lookup_saml_authentication_transaction_v30;
--> statement-breakpoint
ALTER FUNCTION app.apply_federated_authentication_v1(jsonb)
  RENAME TO private_apply_federated_authentication_v30;
--> statement-breakpoint
ALTER FUNCTION app.private_federated_issue_authority_v1(
  jsonb,uuid,uuid,uuid,bigint,bigint,bigint,uuid,uuid,
  public.auth_provider_kind,bigint,timestamptz,bytea
) RENAME TO private_federated_issue_authority_v30;
--> statement-breakpoint

-- sqlc does not update its disposable migration catalog for ALTER FUNCTION
-- ... RENAME. PostgreSQL sees these drops as no-ops after the renames; sqlc
-- uses them to discard only the three stale predecessor symbols before the
-- stable wrappers below are created with the same signatures.
DROP FUNCTION IF EXISTS app.lookup_saml_authentication_transaction_v1(jsonb);
--> statement-breakpoint
DROP FUNCTION IF EXISTS app.apply_federated_authentication_v1(jsonb);
--> statement-breakpoint
DROP FUNCTION IF EXISTS app.private_federated_issue_authority_v1(
  jsonb,uuid,uuid,uuid,bigint,bigint,bigint,uuid,uuid,
  public.auth_provider_kind,bigint,timestamptz,bytea
);
--> statement-breakpoint

REVOKE ALL ON FUNCTION
  app.private_lookup_saml_authentication_transaction_v30(jsonb),
  app.private_apply_federated_authentication_v30(jsonb),
  app.private_federated_issue_authority_v30(
    jsonb,uuid,uuid,uuid,bigint,bigint,bigint,uuid,uuid,
    public.auth_provider_kind,bigint,timestamptz,bytea
  )
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
--> statement-breakpoint

CREATE FUNCTION app.lookup_saml_authentication_transaction_v1(p_request jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_result jsonb;
  v_relay_state_digest bytea;
  v_browser_digest bytea;
  v_operation_run_id uuid;
BEGIN
  v_result := app.private_lookup_saml_authentication_transaction_v30(p_request);
  IF v_result IS NULL THEN
    RETURN NULL;
  END IF;
  v_relay_state_digest := app.private_mfa_decode_base64_v1(
    p_request ->> 'relayStateDigest', 32, 32
  );
  v_browser_digest := app.private_mfa_decode_base64_v1(
    p_request ->> 'browserDigest', 32, 32
  );
  SELECT transaction.operation_run_id INTO v_operation_run_id
  FROM public.tenant_federated_authentication_transactions AS transaction
  WHERE transaction.protocol = 'saml'
    AND transaction.relay_state_digest = v_relay_state_digest
    AND transaction.browser_digest = v_browser_digest
    AND replace(encode(transaction.transaction_id, 'base64'), E'\n', '')
      = v_result ->> 'id'
    AND transaction.state = 'pending'
    AND transaction.version = 1;
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;
  RETURN jsonb_set(
    v_result, '{materialId}', to_jsonb(v_operation_run_id::text), true
  );
EXCEPTION WHEN invalid_text_representation OR data_exception THEN
  RAISE EXCEPTION 'invalid federated authentication transaction lookup'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_federated_issue_authority_v1(
  p_apply jsonb,
  p_tenant_id uuid,
  p_user_id uuid,
  p_external_identity_id uuid,
  p_external_identity_revision bigint,
  p_identity_epoch bigint,
  p_session_invalidation_epoch bigint,
  p_provider_id uuid,
  p_binding_id uuid,
  p_provider_kind public.auth_provider_kind,
  p_security_revision bigint,
  p_applied_at timestamptz,
  p_session_index_digest bytea
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_material jsonb := p_apply -> 'samlSession';
  v_result jsonb;
  v_material_id uuid;
  v_transaction_id bytea;
  v_session_id uuid;
  v_continuation_id uuid;
  v_key_version integer;
  v_ciphertext bytea;
BEGIN
  IF p_provider_kind <> 'saml'
     OR v_material IS NULL OR v_material = 'null'::jsonb THEN
    RETURN app.private_federated_issue_authority_v30(
      p_apply, p_tenant_id, p_user_id, p_external_identity_id,
      p_external_identity_revision, p_identity_epoch,
      p_session_invalidation_epoch, p_provider_id, p_binding_id,
      p_provider_kind, p_security_revision, p_applied_at,
      p_session_index_digest
    );
  END IF;

  PERFORM app.private_mfa_assert_json_object_v1(
    v_material,
    ARRAY['materialId','keyVersion','ciphertext'],
    ARRAY['materialId'],
    32768
  );
  v_material_id := app.private_mfa_require_uuidv7_v1(
    v_material ->> 'materialId'
  );
  v_transaction_id := app.private_mfa_decode_base64_v1(
    p_apply -> 'authentication' -> 'saml' ->> 'transactionId', 32, 32
  );
  IF (v_material ? 'keyVersion') <> (v_material ? 'ciphertext') THEN
    RAISE EXCEPTION 'SAML session material is non-canonical'
      USING ERRCODE = '22023';
  END IF;
  IF NOT EXISTS (
       SELECT 1
       FROM public.tenant_federated_authentication_transactions AS transaction
       WHERE transaction.tenant_id = p_tenant_id
         AND transaction.protocol = 'saml'
         AND transaction.transaction_id = v_transaction_id
         AND transaction.operation_run_id = v_material_id
         AND transaction.provider_id = p_provider_id
         AND transaction.binding_id = p_binding_id
         AND transaction.provider_kind = 'saml'
         AND transaction.state = 'pending'
     ) THEN
    RAISE EXCEPTION 'SAML session material identity is stale'
      USING ERRCODE = '40001';
  END IF;

  IF v_material ? 'keyVersion' THEN
    BEGIN
      v_key_version := (v_material ->> 'keyVersion')::integer;
    EXCEPTION WHEN OTHERS THEN
      RAISE EXCEPTION 'SAML session material is invalid'
        USING ERRCODE = '22023';
    END;
    v_ciphertext := app.private_mfa_decode_base64_v1(
      v_material ->> 'ciphertext', 16, 16384
    );
    IF v_key_version NOT BETWEEN 1 AND 32767
       OR NOT EXISTS (
         SELECT 1 FROM public.identity_keyring_versions AS keyring
         WHERE keyring.key_version = v_key_version
           AND keyring.is_active AND keyring.retired_at IS NULL
       ) THEN
      RAISE EXCEPTION 'SAML session material key is unavailable'
        USING ERRCODE = '40001';
    END IF;
  END IF;

  v_result := app.private_federated_issue_authority_v30(
    p_apply - 'samlSession', p_tenant_id, p_user_id,
    p_external_identity_id, p_external_identity_revision,
    p_identity_epoch, p_session_invalidation_epoch, p_provider_id,
    p_binding_id, p_provider_kind, p_security_revision, p_applied_at,
    p_session_index_digest
  );
  BEGIN
    v_session_id := nullif(v_result ->> 'sessionId', '')::uuid;
    v_continuation_id := nullif(v_result ->> 'continuationId', '')::uuid;
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'SAML authority result is invalid'
      USING ERRCODE = '40001';
  END;
  IF (v_session_id IS NULL) = (v_continuation_id IS NULL)
     OR v_material_id = coalesce(v_session_id, v_continuation_id)
     OR (p_apply ->> 'disposition' = 'session') <> (v_session_id IS NOT NULL)
     OR (p_apply ->> 'disposition' = 'continuation')
        <> (v_continuation_id IS NOT NULL) THEN
    RAISE EXCEPTION 'SAML authority material owner is invalid'
      USING ERRCODE = '40001';
  END IF;

  INSERT INTO public.tenant_saml_session_materials (
    id, tenant_id, session_id, continuation_id, user_id,
    provider_id, binding_id, provider_kind, external_identity_id,
    session_index_digest, aad_version, key_version, ciphertext, created_at
  ) VALUES (
    v_material_id, p_tenant_id, v_session_id, v_continuation_id,
    p_user_id, p_provider_id, p_binding_id, 'saml',
    p_external_identity_id, p_session_index_digest, 2,
    v_key_version, v_ciphertext, p_applied_at
  );
  RETURN v_result;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.apply_federated_authentication_v1(p_command jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_apply jsonb;
  v_auth jsonb;
  v_protocol_document jsonb;
  v_incoming_semantic jsonb;
  v_existing_semantic jsonb;
  v_legacy_apply jsonb;
  v_material jsonb;
  v_operation_digest bytea;
  v_transaction_id bytea;
  v_tenant_id uuid;
  v_material_id uuid;
  v_owner_id uuid;
  v_disposition text;
  v_transaction record;
  v_existing record;
BEGIN
  IF jsonb_typeof(p_command) <> 'object'
     OR jsonb_typeof(p_command -> 'apply') <> 'object'
     OR p_command -> 'apply' -> 'authentication' ->> 'protocol' <> 'saml' THEN
    RETURN app.private_apply_federated_authentication_v30(p_command);
  END IF;

  PERFORM app.private_mfa_assert_json_object_v1(
    p_command, ARRAY['operationDigest','apply'],
    ARRAY['operationDigest','apply'], 2162688
  );
  v_operation_digest := app.private_mfa_decode_base64_v1(
    p_command ->> 'operationDigest', 32, 32
  );
  v_apply := p_command -> 'apply';
  v_auth := v_apply -> 'authentication';
  v_protocol_document := v_auth -> 'saml';
  v_disposition := v_apply ->> 'disposition';
  PERFORM app.private_mfa_assert_json_object_v1(
    v_protocol_document,
    ARRAY['transactionId','expectedVersion','pins','responseId','assertionId',
      'sessionIndexDigest','hasSessionIndex','consumedAt','returnPath',
      'materialId'],
    ARRAY['transactionId','expectedVersion','pins','responseId','assertionId',
      'hasSessionIndex','consumedAt','returnPath','materialId'],
    262144
  );
  BEGIN
    v_tenant_id := app.private_mfa_require_uuidv7_v1(v_auth ->> 'tenantId');
    v_material_id := app.private_mfa_require_uuidv7_v1(
      v_protocol_document ->> 'materialId'
    );
    v_transaction_id := app.private_mfa_decode_base64_v1(
      v_protocol_document ->> 'transactionId', 32, 32
    );
    v_owner_id := CASE v_disposition
      WHEN 'session' THEN app.private_mfa_require_uuidv7_v1(
        v_apply -> 'session' ->> 'sessionId'
      )
      WHEN 'continuation' THEN app.private_mfa_require_uuidv7_v1(
        v_apply -> 'continuation' ->> 'continuationId'
      )
      ELSE NULL
    END;
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'SAML material identity is invalid'
      USING ERRCODE = '22023';
  END;
  IF v_owner_id IS NULL OR v_owner_id = v_material_id THEN
    RAISE EXCEPTION 'SAML material owner is invalid'
      USING ERRCODE = '22023';
  END IF;

  SELECT transaction.operation_run_id, transaction.state,
         transaction.provider_id, transaction.binding_id
    INTO v_transaction
  FROM public.tenant_federated_authentication_transactions AS transaction
  WHERE transaction.tenant_id = v_tenant_id
    AND transaction.protocol = 'saml'
    AND transaction.transaction_id = v_transaction_id
    AND transaction.operation_run_id = v_material_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RETURN app.private_federated_apply_response_v1(
      v_operation_digest, 'saml', v_tenant_id, v_disposition, 'denied'
    );
  END IF;

  v_material := v_apply -> 'samlSession';
  IF v_material IS NOT NULL AND v_material <> 'null'::jsonb THEN
    PERFORM app.private_mfa_assert_json_object_v1(
      v_material,
      ARRAY['materialId','keyVersion','ciphertext'],
      ARRAY['materialId','keyVersion','ciphertext'],
      32768
    );
    IF app.private_mfa_require_uuidv7_v1(v_material ->> 'materialId')
       IS DISTINCT FROM v_material_id THEN
      RAISE EXCEPTION 'SAML material identity is inconsistent'
        USING ERRCODE = '22023';
    END IF;
  END IF;

  -- The v30 parser knows no protocol-document materialId. Store an explicit
  -- top-level material marker even when no logout envelope exists, so a v2
  -- application is distinguishable from every predecessor snapshot.
  v_legacy_apply := jsonb_set(
    v_apply,
    '{authentication,saml}',
    v_protocol_document - 'materialId',
    true
  );
  IF v_material IS NULL OR v_material = 'null'::jsonb THEN
    v_legacy_apply := jsonb_set(
      v_legacy_apply, '{samlSession}',
      jsonb_build_object('materialId', v_material_id::text), true
    );
  END IF;

  SELECT application.* INTO v_existing
  FROM public.tenant_federated_authentication_applications AS application
  WHERE application.tenant_id = v_tenant_id
    AND application.protocol = 'saml'
    AND application.transaction_id = v_transaction_id;
  IF FOUND THEN
    IF v_existing.operation_digest IS DISTINCT FROM v_operation_digest
       OR v_existing.request_snapshot -> 'samlSession' ->> 'materialId'
          IS DISTINCT FROM v_material_id::text THEN
      RETURN app.private_federated_apply_response_v1(
        v_operation_digest, 'saml', v_tenant_id, v_disposition, 'replay'
      );
    END IF;

    v_incoming_semantic := v_apply;
    IF v_incoming_semantic ? 'samlSession' THEN
      v_incoming_semantic := v_incoming_semantic
        #- '{samlSession,keyVersion}' #- '{samlSession,ciphertext}';
    END IF;
    v_existing_semantic := jsonb_set(
      v_existing.request_snapshot,
      '{authentication,saml,materialId}',
      to_jsonb(v_material_id::text), true
    );
    IF v_existing_semantic -> 'samlSession'
       = jsonb_build_object('materialId', v_material_id::text) THEN
      v_existing_semantic := v_existing_semantic - 'samlSession';
    ELSE
      v_existing_semantic := v_existing_semantic
        #- '{samlSession,keyVersion}' #- '{samlSession,ciphertext}';
    END IF;
    IF v_existing_semantic IS DISTINCT FROM v_incoming_semantic
       OR NOT EXISTS (
         SELECT 1
         FROM public.tenant_saml_session_materials AS material
         WHERE material.tenant_id = v_tenant_id
           AND material.id = v_material_id
           AND material.aad_version = 2
           AND material.provider_id = v_existing.provider_id
           AND material.binding_id = v_existing.binding_id
           AND material.user_id = v_existing.user_id
           AND material.session_id IS NOT DISTINCT FROM v_existing.session_id
           AND material.continuation_id IS NOT DISTINCT FROM
             v_existing.continuation_id
           AND (
             (
               (v_existing.request_snapshot -> 'samlSession' ? 'keyVersion')
               AND material.key_version IS NOT NULL
               AND material.ciphertext IS NOT NULL
             ) OR (
               NOT (v_existing.request_snapshot -> 'samlSession' ? 'keyVersion')
               AND material.key_version IS NULL
               AND material.ciphertext IS NULL
             )
           )
       ) THEN
      RETURN app.private_federated_apply_response_v1(
        v_operation_digest, 'saml', v_tenant_id, v_disposition, 'replay'
      );
    END IF;
    -- The legacy implementation performs all live policy, resource and
    -- relationship checks, then sees its exact committed snapshot. The new
    -- randomized envelope is deliberately neither compared nor persisted.
    v_legacy_apply := v_existing.request_snapshot;
  END IF;

  RETURN app.private_apply_federated_authentication_v30(
    jsonb_set(p_command, '{apply}', v_legacy_apply, true)
  );
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid SAML federated apply command'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

-- Promotion and rotation already update a material row in place. Replace the
-- predecessor step-up clone with the same immutable-row ownership transfer.
DO $migration$
DECLARE
  v_definition text;
  v_old text := $old$
    INSERT INTO public.tenant_saml_session_materials (
      id,tenant_id,continuation_id,user_id,provider_id,binding_id,
      provider_kind,external_identity_id,session_index_digest,
      key_version,ciphertext,created_at
    ) SELECT uuidv7(),material.tenant_id,v_continuation_id,material.user_id,
      material.provider_id,material.binding_id,material.provider_kind,
      material.external_identity_id,NULL,material.key_version,
      material.ciphertext,v_observed_at
    FROM public.tenant_saml_session_materials AS material
    WHERE material.tenant_id = v_tenant_id AND material.session_id = v_session_id;$old$;
  v_new text := $new$
    UPDATE public.tenant_saml_session_materials AS material
    SET session_id = NULL, continuation_id = v_continuation_id
    WHERE material.tenant_id = v_tenant_id
      AND material.session_id = v_session_id
      AND material.aad_version = 2;
    IF v_provenance.provider_kind = 'saml' AND NOT FOUND THEN
      RAISE EXCEPTION 'SAML session material ownership is stale'
        USING ERRCODE = '40001';
    END IF;$new$;
BEGIN
  SELECT pg_get_functiondef(
    'app.apply_federated_session_revalidation_v1(jsonb)'::regprocedure
  ) INTO STRICT v_definition;
  IF strpos(v_definition, v_old) = 0
     OR strpos(substr(v_definition, strpos(v_definition, v_old) + length(v_old)), v_old) > 0 THEN
    RAISE EXCEPTION 'unexpected SAML step-up predecessor definition';
  END IF;
  EXECUTE replace(v_definition, v_old, v_new);
END;
$migration$;
--> statement-breakpoint

-- Every SAML promotion and rotation must transfer the one immutable material
-- row. A missing row is provenance drift, never an OIDC-style no-op.
DO $migration$
DECLARE
  v_definition text;
  v_old text := $old$
  IF v_anchor.flow = 'session' THEN
    UPDATE public.tenant_saml_session_materials AS material
    SET session_id = v_new_session_id
    WHERE material.tenant_id = v_tenant_id
      AND material.session_id = v_anchor.session_id
      AND material.user_id = v_user_id
      AND material.provider_id = v_provider_id
      AND material.binding_id = v_binding_id
      AND material.external_identity_id = v_external_identity_id;
  ELSE
    UPDATE public.tenant_saml_session_materials AS material
    SET session_id = v_new_session_id,continuation_id = NULL
    WHERE material.tenant_id = v_tenant_id
      AND material.continuation_id = v_anchor.continuation_id
      AND material.user_id = v_user_id
      AND material.provider_id = v_provider_id
      AND material.binding_id = v_binding_id
      AND material.external_identity_id = v_external_identity_id;
  END IF;$old$;
  v_new text := $new$
  IF v_anchor.flow = 'session' THEN
    UPDATE public.tenant_saml_session_materials AS material
    SET session_id = v_new_session_id
    WHERE material.tenant_id = v_tenant_id
      AND material.session_id = v_anchor.session_id
      AND material.user_id = v_user_id
      AND material.provider_id = v_provider_id
      AND material.binding_id = v_binding_id
      AND material.external_identity_id = v_external_identity_id
      AND material.aad_version = 2;
  ELSE
    UPDATE public.tenant_saml_session_materials AS material
    SET session_id = v_new_session_id,continuation_id = NULL
    WHERE material.tenant_id = v_tenant_id
      AND material.continuation_id = v_anchor.continuation_id
      AND material.user_id = v_user_id
      AND material.provider_id = v_provider_id
      AND material.binding_id = v_binding_id
      AND material.external_identity_id = v_external_identity_id
      AND material.aad_version = 2;
  END IF;
  IF v_provider_kind = 'saml' AND NOT FOUND THEN
    RAISE EXCEPTION 'SAML session material ownership is stale'
      USING ERRCODE = '40001';
  END IF;$new$;
BEGIN
  SELECT pg_get_functiondef(
    'app.private_mfa_apply_federated_session_v1(jsonb,uuid,text,uuid,bigint,timestamp with time zone)'::regprocedure
  ) INTO STRICT v_definition;
  IF strpos(v_definition, v_old) = 0
     OR strpos(substr(v_definition, strpos(v_definition, v_old) + length(v_old)), v_old) > 0 THEN
    RAISE EXCEPTION 'unexpected federated MFA material transfer definition';
  END IF;
  EXECUTE replace(v_definition, v_old, v_new);
END;
$migration$;
--> statement-breakpoint

DO $migration$
DECLARE
  v_definition text;
  v_old text := $old$
    UPDATE public.tenant_saml_session_materials AS material
    SET session_id = v_new_session_id
    WHERE material.tenant_id = v_tenant_id AND material.session_id = v_session_id;$old$;
  v_new text := $new$
    UPDATE public.tenant_saml_session_materials AS material
    SET session_id = v_new_session_id
    WHERE material.tenant_id = v_tenant_id
      AND material.session_id = v_session_id
      AND material.aad_version = 2;
    IF v_provenance.provider_kind = 'saml' AND NOT FOUND THEN
      RAISE EXCEPTION 'SAML session material ownership is stale'
        USING ERRCODE = '40001';
    END IF;$new$;
BEGIN
  SELECT pg_get_functiondef(
    'app.apply_federated_session_revalidation_v1(jsonb)'::regprocedure
  ) INTO STRICT v_definition;
  IF strpos(v_definition, v_old) = 0
     OR strpos(substr(v_definition, strpos(v_definition, v_old) + length(v_old)), v_old) > 0 THEN
    RAISE EXCEPTION 'unexpected SAML rotation predecessor definition';
  END IF;
  EXECUTE replace(v_definition, v_old, v_new);
END;
$migration$;
--> statement-breakpoint

-- Logout is local-first and must not depend on the provider still being
-- enabled. This projection is deliberately provenance-addressed and returns
-- only the bounded configuration needed to build an optional upstream SLO.
CREATE FUNCTION app.private_saml_logout_configuration_record_v1(
  p_tenant_id uuid,
  p_provider_id uuid,
  p_binding_id uuid
)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT jsonb_build_object(
    'authentication', jsonb_build_object(
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
  )
  FROM public.tenant_auth_providers AS provider
  JOIN public.tenant_auth_provider_bindings AS binding
    ON binding.tenant_id = provider.tenant_id
   AND binding.provider_id = provider.id
   AND binding.id = p_binding_id
  JOIN public.tenant_federated_provider_policies AS policy
    ON policy.tenant_id = provider.tenant_id
   AND policy.provider_id = provider.id
   AND policy.binding_id = binding.id
   AND policy.provider_kind = 'saml'
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
  JOIN public.identity_keyring_versions AS keyring
    ON keyring.key_version = sp_key.key_version
  WHERE provider.tenant_id = p_tenant_id
    AND provider.id = p_provider_id
    AND provider.kind = 'saml';
$function$;
--> statement-breakpoint

CREATE FUNCTION app.revoke_local_saml_session_v1(
  p_user_id uuid,
  p_command jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_operation_run_id uuid;
  v_tenant_id uuid;
  v_authenticated_user_id uuid;
  v_session_id uuid;
  v_expected_version bigint;
  v_request_upstream boolean;
  v_request_digest bytea;
  v_request_snapshot jsonb;
  v_configuration jsonb;
  v_result jsonb;
  v_revoked_at timestamptz := transaction_timestamp();
  v_session public.auth_sessions%ROWTYPE;
  v_state public.auth_session_mfa_states%ROWTYPE;
  v_provenance public.auth_session_federated_provenance%ROWTYPE;
  v_material public.tenant_saml_session_materials%ROWTYPE;
  v_transaction public.tenant_federated_authentication_transactions%ROWTYPE;
  v_existing public.tenant_saml_logout_commands%ROWTYPE;
  v_membership_id uuid;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_command,
    ARRAY['operationRunId','tenantId','authenticatedUserId','sessionId','expectedVersion',
      'requestUpstream','requestDigest'],
    ARRAY['operationRunId','tenantId','authenticatedUserId','sessionId','expectedVersion',
      'requestUpstream','requestDigest'],
    16384
  );
  BEGIN
    v_operation_run_id := app.private_mfa_require_uuidv7_v1(
      p_command ->> 'operationRunId'
    );
    v_tenant_id := app.private_mfa_require_uuidv7_v1(
      p_command ->> 'tenantId'
    );
    v_authenticated_user_id := app.private_mfa_require_uuidv7_v1(
      p_command ->> 'authenticatedUserId'
    );
    v_session_id := app.private_mfa_require_uuidv7_v1(
      p_command ->> 'sessionId'
    );
    v_expected_version := (p_command ->> 'expectedVersion')::bigint;
    v_request_upstream := (p_command ->> 'requestUpstream')::boolean;
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'invalid local SAML logout command'
      USING ERRCODE = '22023';
  END;
  v_request_digest := app.private_mfa_decode_base64_v1(
    p_command ->> 'requestDigest', 32, 32
  );
  v_request_snapshot := p_command - 'requestDigest';
  IF p_user_id IS NULL
     OR uuid_extract_version(p_user_id) IS DISTINCT FROM 7
     OR p_user_id IS DISTINCT FROM v_authenticated_user_id
     OR v_expected_version < 1
     OR v_operation_run_id = v_session_id
     OR v_operation_run_id = v_authenticated_user_id
     OR v_tenant_id = v_authenticated_user_id
     OR v_session_id = v_authenticated_user_id
     OR encode(v_request_digest,'hex') = repeat('00',32)
     OR jsonb_typeof(p_command -> 'requestUpstream') <> 'boolean'
     OR pg_column_size(v_request_snapshot) NOT BETWEEN 2 AND 16384 THEN
    RAISE EXCEPTION 'invalid local SAML logout command'
      USING ERRCODE = '22023';
  END IF;
  IF current_setting('app.tenant_id', true) IS DISTINCT FROM v_tenant_id::text
     OR current_setting('app.user_id', true) IS DISTINCT FROM p_user_id::text THEN
    RAISE EXCEPTION 'local SAML logout authority rejected'
      USING ERRCODE = '42501';
  END IF;

  PERFORM pg_advisory_xact_lock(hashtextextended(
    v_operation_run_id::text, 73419021
  ));
  SELECT membership.id INTO v_membership_id
  FROM public.tenant_memberships AS membership
  WHERE membership.tenant_id = v_tenant_id
    AND membership.user_id = p_user_id
    AND membership.status = 'active'
  FOR SHARE;
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;
  SELECT command.* INTO v_existing
  FROM public.tenant_saml_logout_commands AS command
  WHERE command.operation_run_id = v_operation_run_id;
  IF FOUND THEN
    IF v_existing.tenant_id IS DISTINCT FROM v_tenant_id
       OR v_existing.session_id IS DISTINCT FROM v_session_id
       OR v_existing.expected_version IS DISTINCT FROM v_expected_version
       OR v_existing.request_upstream IS DISTINCT FROM v_request_upstream
       OR v_existing.request_digest IS DISTINCT FROM v_request_digest
       OR v_existing.request_snapshot IS DISTINCT FROM v_request_snapshot THEN
      RETURN NULL;
    END IF;
    PERFORM 1
    FROM public.auth_sessions AS session
    JOIN public.auth_session_federated_provenance AS provenance
      ON provenance.tenant_id = v_tenant_id
     AND provenance.session_id = session.id
     AND provenance.user_id = session.user_id
     AND provenance.primary_kind = 'tenant_provider'
     AND provenance.authentication_method = 'saml'
     AND provenance.provider_kind = 'saml'
    JOIN public.tenant_saml_session_materials AS material
      ON material.tenant_id = v_tenant_id
     AND material.id = v_existing.material_id
     AND material.session_id = session.id
     AND material.continuation_id IS NULL
     AND material.user_id = session.user_id
     AND material.provider_id = provenance.provider_id
     AND material.binding_id = provenance.binding_id
     AND material.external_identity_id = provenance.external_identity_id
     AND material.aad_version = 2
    WHERE session.id = v_session_id
      AND session.active_tenant_id = v_tenant_id
      AND session.user_id = p_user_id
      AND session.authentication_method = 'saml'
    FOR SHARE OF material;
    IF NOT FOUND THEN
      RETURN NULL;
    END IF;
    RETURN v_existing.result_snapshot;
  END IF;

  SELECT session.* INTO STRICT v_session
  FROM public.auth_sessions AS session
  WHERE session.id = v_session_id
    AND session.active_tenant_id = v_tenant_id
    AND session.user_id = p_user_id
    AND session.authentication_method = 'saml'
    AND session.revoked_at IS NULL
  FOR UPDATE;
  SELECT state.* INTO STRICT v_state
  FROM public.auth_session_mfa_states AS state
  WHERE state.tenant_id = v_tenant_id
    AND state.session_id = v_session_id
    AND state.user_id = v_session.user_id
    AND state.primary_kind = 'tenant_provider'
    AND state.session_version = v_expected_version
  FOR UPDATE;
  SELECT provenance.* INTO STRICT v_provenance
  FROM public.auth_session_federated_provenance AS provenance
  WHERE provenance.tenant_id = v_tenant_id
    AND provenance.session_id = v_session_id
    AND provenance.user_id = v_session.user_id
    AND provenance.primary_kind = 'tenant_provider'
    AND provenance.authentication_method = 'saml'
    AND provenance.provider_kind = 'saml';
  SELECT material.* INTO STRICT v_material
  FROM public.tenant_saml_session_materials AS material
  WHERE material.tenant_id = v_tenant_id
    AND material.session_id = v_session_id
    AND material.continuation_id IS NULL
    AND material.user_id = v_session.user_id
    AND material.provider_id = v_provenance.provider_id
    AND material.binding_id = v_provenance.binding_id
    AND material.provider_kind = 'saml'
    AND material.external_identity_id = v_provenance.external_identity_id
    AND material.aad_version = 2
  FOR SHARE;
  SELECT transaction.* INTO STRICT v_transaction
  FROM public.tenant_federated_authentication_transactions AS transaction
  WHERE transaction.tenant_id = v_tenant_id
    AND transaction.operation_run_id = v_material.id
    AND transaction.protocol = 'saml'
    AND transaction.provider_id = v_provenance.provider_id
    AND transaction.binding_id = v_provenance.binding_id
    AND transaction.provider_kind = 'saml'
    AND transaction.state = 'completed';
  IF v_operation_run_id = v_material.id THEN
    RETURN NULL;
  END IF;
  IF NOT EXISTS (
    SELECT 1
    FROM public.tenant_federated_authentication_applications AS application
    WHERE application.tenant_id = v_tenant_id
      AND application.protocol = 'saml'
      AND application.transaction_id = v_transaction.transaction_id
      AND application.category = 'success'
      AND application.user_id = v_session.user_id
      AND application.provider_id = v_provenance.provider_id
      AND application.binding_id = v_provenance.binding_id
  ) THEN
    RETURN NULL;
  END IF;
  UPDATE public.auth_sessions AS family
  SET revoked_at = v_revoked_at,
      revoke_reason = 'saml_local_logout'
  WHERE family.user_id = v_session.user_id
    AND family.rotation_family_id = v_session.rotation_family_id
    AND family.revoked_at IS NULL;
  UPDATE public.auth_session_mfa_states AS state
  SET session_version = state.session_version + 1
  WHERE state.tenant_id = v_tenant_id
    AND state.session_id = v_session_id
    AND state.session_version = v_expected_version;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'local SAML logout lost CAS'
      USING ERRCODE = '40001';
  END IF;

  -- Local revocation is authoritative. Optional upstream configuration is
  -- projected only afterwards and cannot roll back the local security action.
  IF v_request_upstream AND v_material.key_version IS NOT NULL THEN
    BEGIN
      v_configuration := app.private_saml_logout_configuration_record_v1(
        v_tenant_id, v_provenance.provider_id, v_provenance.binding_id
      );
    EXCEPTION WHEN OTHERS THEN
      v_configuration := NULL;
    END;
  END IF;

  v_result := jsonb_build_object(
    'operationRunId',v_operation_run_id::text,
    'tenantId',v_tenant_id::text,
    'authenticatedUserId',p_user_id::text,
    'sessionId',v_session_id::text,
    'previousVersion',v_expected_version,
    'provider',jsonb_build_object(
      'scope','tenant','tenantId',v_tenant_id::text,
      'providerId',v_provenance.provider_id::text,
      'bindingId',v_provenance.binding_id::text
    ),
    'bindingId',v_provenance.binding_id::text,
    'materialId',v_material.id::text,
    'configuration',v_configuration,
    'protectedMaterial',CASE
      WHEN NOT v_request_upstream OR v_material.key_version IS NULL THEN NULL
      ELSE jsonb_build_object(
        'keyVersion',v_material.key_version,
        'ciphertext',replace(encode(v_material.ciphertext,'base64'), E'\n','')
      )
    END,
    'revokedAt',to_jsonb(v_revoked_at)
  );
  IF pg_column_size(v_result) NOT BETWEEN 2 AND 6291456 THEN
    RAISE EXCEPTION 'local SAML logout snapshot exceeds bound'
      USING ERRCODE = '54000';
  END IF;
  INSERT INTO public.tenant_saml_logout_commands (
    tenant_id, operation_run_id, session_id, expected_version,
    request_upstream, material_id, request_digest, request_snapshot,
    result_snapshot, applied_at
  ) VALUES (
    v_tenant_id, v_operation_run_id, v_session_id, v_expected_version,
    v_request_upstream, v_material.id, v_request_digest,
    v_request_snapshot, v_result, v_revoked_at
  );
  INSERT INTO public.audit_events (
    id, tenant_id, sequence, occurred_at, actor_type, actor_user_id,
    action, resource_type, resource_id, authentication_method,
    outcome, metadata
  ) VALUES (
    uuidv7(), v_tenant_id, 0, v_revoked_at, 'user', v_session.user_id,
    'tenant.identity.saml_local_logout', 'auth_session', v_session_id,
    'saml', 'success', jsonb_build_object(
      'upstream_requested',v_request_upstream,
      'material_id_bound',true,
      'material_disclosed',false
    )
  );
  RETURN v_result;
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RETURN NULL;
WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid local SAML logout command'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

ALTER FUNCTION app.lookup_saml_authentication_transaction_v1(jsonb)
  OWNER TO periapsis_migrator;
--> statement-breakpoint
ALTER FUNCTION app.private_federated_issue_authority_v1(
  jsonb,uuid,uuid,uuid,bigint,bigint,bigint,uuid,uuid,
  public.auth_provider_kind,bigint,timestamptz,bytea
) OWNER TO periapsis_migrator;
--> statement-breakpoint
ALTER FUNCTION app.apply_federated_authentication_v1(jsonb)
  OWNER TO periapsis_migrator;
--> statement-breakpoint
ALTER FUNCTION app.private_saml_logout_configuration_record_v1(uuid,uuid,uuid)
  OWNER TO periapsis_migrator;
--> statement-breakpoint
ALTER FUNCTION app.revoke_local_saml_session_v1(uuid,jsonb)
  OWNER TO periapsis_migrator;
--> statement-breakpoint

REVOKE ALL ON FUNCTION
  app.lookup_saml_authentication_transaction_v1(jsonb),
  app.private_federated_issue_authority_v1(
    jsonb,uuid,uuid,uuid,bigint,bigint,bigint,uuid,uuid,
    public.auth_provider_kind,bigint,timestamptz,bytea
  ),
  app.apply_federated_authentication_v1(jsonb),
  app.private_saml_logout_configuration_record_v1(uuid,uuid,uuid),
  app.revoke_local_saml_session_v1(uuid,jsonb)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION
  app.lookup_saml_authentication_transaction_v1(jsonb),
  app.apply_federated_authentication_v1(jsonb),
  app.revoke_local_saml_session_v1(uuid,jsonb)
TO periapsis_api;
--> statement-breakpoint
