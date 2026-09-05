-- Platform identity-account administration is exposed only through the
-- reviewed security-definer ABI below.  The command ledger is deliberately
-- private and has no permissive RLS policy.
ALTER TABLE public.platform_identity_account_commands
  OWNER TO periapsis_migrator;
ALTER TABLE public.platform_identity_account_commands
  FORCE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.platform_identity_account_commands
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
    periapsis_auditor, periapsis_audit_reader_owner,
    periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
    periapsis_sla_worker_owner, periapsis_sla_readiness_owner,
    periapsis_ticket_saved_view_owner, periapsis_ticket_attribution_owner,
    periapsis_ticket_sla_projection_owner;
--> statement-breakpoint

CREATE FUNCTION app.guard_platform_identity_account_command_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    RAISE EXCEPTION 'platform identity account commands are immutable'
      USING ERRCODE = '55000';
  END IF;
  IF TG_OP = 'DELETE' THEN
    IF OLD.expires_at > transaction_timestamp() THEN
      RAISE EXCEPTION 'live platform identity account command cannot be deleted'
        USING ERRCODE = '55000';
    END IF;
    RETURN OLD;
  END IF;
  IF NEW.operation <> 'account.prelink'
     OR NEW.actor_user_id IS DISTINCT FROM app.context_user_id()
     OR NEW.result_version <> 1
     OR NEW.created_at IS DISTINCT FROM transaction_timestamp()
     OR NEW.expires_at IS DISTINCT FROM
        transaction_timestamp() + interval '24 hours' THEN
    RAISE EXCEPTION 'platform identity account command envelope is invalid'
      USING ERRCODE = '23514';
  END IF;
  IF NOT EXISTS (
    SELECT 1
    FROM ONLY public.platform_federated_external_identities AS identity
    WHERE identity.platform_provider_id = NEW.platform_provider_id
      AND identity.id = NEW.result_account_id
      AND identity.version = NEW.result_version
      AND identity.retired_at IS NULL
  ) THEN
    RAISE EXCEPTION 'platform identity account command result is invalid'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$function$;
CREATE TRIGGER platform_identity_account_commands_guard_v1
BEFORE INSERT OR UPDATE OR DELETE
ON public.platform_identity_account_commands
FOR EACH ROW EXECUTE FUNCTION app.guard_platform_identity_account_command_v1();
--> statement-breakpoint

-- Fixed-width comparison prevents an idempotency replay oracle over the
-- normalized public request digest.  Confidential subject equality is proved
-- independently through provider-scoped keyed aliases.
CREATE FUNCTION app.private_platform_identity_digest_equal_v1(
  p_left bytea,
  p_right bytea
)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
DECLARE
  difference integer := 0;
  position_index integer;
BEGIN
  IF p_left IS NULL OR p_right IS NULL
     OR octet_length(p_left) <> 32 OR octet_length(p_right) <> 32 THEN
    RETURN false;
  END IF;
  FOR position_index IN 0..31 LOOP
    difference := difference |
      (get_byte(p_left, position_index) # get_byte(p_right, position_index));
  END LOOP;
  RETURN difference = 0;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_append_platform_identity_account_tenant_audit_v1(
  p_tenant_id uuid,
  p_platform_actor_user_id uuid,
  p_platform_audit_event_id uuid,
  p_platform_provider_id uuid,
  p_account_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text,
  p_reason text,
  p_ended_access_grant_count integer
)
RETURNS uuid
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  event_id uuid := uuidv7();
BEGIN
  IF p_tenant_id IS NULL OR uuid_extract_version(p_tenant_id) IS DISTINCT FROM 7
     OR p_platform_actor_user_id IS NULL
     OR uuid_extract_version(p_platform_actor_user_id) IS DISTINCT FROM 7
     OR p_platform_audit_event_id IS NULL
     OR uuid_extract_version(p_platform_audit_event_id) IS DISTINCT FROM 7
     OR p_platform_provider_id IS NULL
     OR uuid_extract_version(p_platform_provider_id) IS DISTINCT FROM 7
     OR p_account_id IS NULL
     OR uuid_extract_version(p_account_id) IS DISTINCT FROM 7
     OR p_ended_access_grant_count IS NULL
     OR p_ended_access_grant_count < 0
     OR p_reason IS NULL
     OR NOT app.private_platform_lifecycle_reason_is_valid_v1(p_reason) THEN
    RAISE EXCEPTION 'tenant platform identity account audit envelope is invalid'
      USING ERRCODE = '22023';
  END IF;
  INSERT INTO public.audit_events (
    id, tenant_id, sequence, actor_type, actor_user_id, action,
    resource_type, resource_id, request_id, correlation_id, ip_address,
    user_agent, authentication_method, outcome, reason, before, after, metadata
  ) VALUES (
    event_id, p_tenant_id, 0, 'system', NULL,
    'tenant.platform_identity_account.retired',
    'platform_identity_account', p_account_id, p_request_id,
    p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method, 'success', p_reason,
    jsonb_build_object(
      'account_id', p_account_id,
      'provider_id', p_platform_provider_id,
      'state', 'active'
    ),
    jsonb_build_object(
      'account_id', p_account_id,
      'provider_id', p_platform_provider_id,
      'state', 'retired',
      'ended_access_grant_count', p_ended_access_grant_count
    ),
    jsonb_build_object(
      'platform_actor_user_id', p_platform_actor_user_id,
      'platform_audit_event_id', p_platform_audit_event_id,
      'platform_provider_id', p_platform_provider_id
    )
  );
  RETURN event_id;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_platform_identity_account_document_v1(
  p_provider_id uuid,
  p_account_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  result jsonb;
BEGIN
  SELECT jsonb_build_object(
    'id', identity.id,
    'providerId', identity.platform_provider_id,
    'user', jsonb_build_object(
      'id', local_user.id,
      'displayName', local_user.display_name,
      'email', local_user.email,
      'active', local_user.active
    ),
    'state', CASE WHEN identity.retired_at IS NULL
      THEN 'active' ELSE 'retired' END,
    'admittedConfigurationRevision',
      identity.admitted_configuration_revision,
    'admittedSecurityRevision', identity.admitted_security_revision,
    'lastObservedAt', identity.last_observed_at,
    'retiredAt', identity.retired_at,
    'version', identity.version,
    'createdAt', identity.created_at,
    'updatedAt', identity.updated_at
  ) INTO result
  FROM ONLY public.platform_federated_external_identities AS identity
  JOIN ONLY public.users AS local_user ON local_user.id = identity.user_id
  WHERE identity.platform_provider_id = p_provider_id
    AND identity.id = p_account_id;
  IF result IS NULL THEN
    RAISE EXCEPTION 'platform identity account does not exist'
      USING ERRCODE = 'P0002';
  END IF;
  RETURN result;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.list_platform_identity_accounts_v1(
  p_session_id uuid,
  p_authentication_method text,
  p_provider_id uuid,
  p_after uuid DEFAULT NULL,
  p_page_size integer DEFAULT 50,
  p_include_retired boolean DEFAULT false
)
RETURNS TABLE (document jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_provider_id IS NULL
     OR uuid_extract_version(p_provider_id) IS DISTINCT FROM 7
     OR p_page_size IS NULL OR p_page_size NOT BETWEEN 1 AND 101
     OR p_include_retired IS NULL
     OR (p_after IS NOT NULL
       AND uuid_extract_version(p_after) IS DISTINCT FROM 7) THEN
    RAISE EXCEPTION 'invalid platform identity account list request'
      USING ERRCODE = '22023';
  END IF;
  PERFORM app.private_require_platform_identity_permission_v1(
    p_session_id, 'platform.identity_account.read', p_authentication_method
  );
  RETURN QUERY
  SELECT app.private_platform_identity_account_document_v1(
    identity.platform_provider_id, identity.id
  )
  FROM ONLY public.platform_federated_external_identities AS identity
  WHERE identity.platform_provider_id = p_provider_id
    AND (p_after IS NULL OR identity.id > p_after)
    AND (p_include_retired OR identity.retired_at IS NULL)
  ORDER BY identity.id
  LIMIT p_page_size;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.get_platform_identity_account_v1(
  p_session_id uuid,
  p_provider_id uuid,
  p_account_id uuid,
  p_authentication_method text
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_provider_id IS NULL
     OR uuid_extract_version(p_provider_id) IS DISTINCT FROM 7
     OR p_account_id IS NULL
     OR uuid_extract_version(p_account_id) IS DISTINCT FROM 7 THEN
    RAISE EXCEPTION 'invalid platform identity account read request'
      USING ERRCODE = '22023';
  END IF;
  PERFORM app.private_require_platform_identity_permission_v1(
    p_session_id, 'platform.identity_account.read', p_authentication_method
  );
  RETURN app.private_platform_identity_account_document_v1(
    p_provider_id, p_account_id
  );
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.prelink_platform_identity_account_v1(
  p_session_id uuid,
  p_command_id uuid,
  p_account_id uuid,
  p_provider_id uuid,
  p_user_id uuid,
  p_issuer text,
  p_subject_format public.identity_subject_format,
  p_subject_ciphertext bytea,
  p_subject_nonce bytea,
  p_key_version integer,
  p_alias_key_versions integer[],
  p_alias_subject_digests bytea[],
  p_key_digest bytea,
  p_public_request_digest bytea,
  p_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text,
  p_reason text
)
RETURNS TABLE (
  account_id uuid,
  version bigint,
  replayed boolean,
  document jsonb
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  actor_id uuid;
  read_actor_id uuid;
  alias_count integer;
  alias_index integer;
  replay_record public.platform_identity_account_commands%ROWTYPE;
  provider_record public.platform_auth_providers%ROWTYPE;
  policy_record public.platform_federated_provider_policies%ROWTYPE;
  configuration_record public.platform_oidc_provider_configurations%ROWTYPE;
  matched_alias_count integer;
  matched_account_count integer;
  divergent_alias_count integer;
  malformed_alias_count integer;
  account_document jsonb;
BEGIN
  alias_count := cardinality(p_alias_key_versions);
  IF p_command_id IS NULL
     OR uuid_extract_version(p_command_id) IS DISTINCT FROM 7
     OR p_account_id IS NULL
     OR uuid_extract_version(p_account_id) IS DISTINCT FROM 7
     OR p_provider_id IS NULL
     OR uuid_extract_version(p_provider_id) IS DISTINCT FROM 7
     OR p_user_id IS NULL OR uuid_extract_version(p_user_id) IS DISTINCT FROM 7
     OR p_issuer IS NULL OR octet_length(p_issuer) NOT BETWEEN 9 AND 2048
     OR NOT app.private_platform_identity_uri_is_canonical_v1(
       p_issuer, true, false, 2048
     )
     OR p_subject_format IS DISTINCT FROM 'utf8_exact'
     OR p_subject_ciphertext IS NULL
     OR octet_length(p_subject_ciphertext) NOT BETWEEN 17 AND 4112
     OR p_subject_nonce IS NULL OR octet_length(p_subject_nonce) <> 12
     OR encode(p_subject_nonce, 'hex') = repeat('00', 12)
     OR p_key_version IS NULL OR p_key_version NOT BETWEEN 1 AND 32767
     OR coalesce(array_ndims(p_alias_key_versions), 0) <> 1
     OR coalesce(array_ndims(p_alias_subject_digests), 0) <> 1
     OR coalesce(array_lower(p_alias_key_versions, 1), 0) <> 1
     OR coalesce(array_lower(p_alias_subject_digests, 1), 0) <> 1
     OR alias_count NOT BETWEEN 1 AND 16
     OR cardinality(p_alias_subject_digests) <> alias_count
     OR p_key_digest IS NULL OR octet_length(p_key_digest) <> 32
     OR encode(p_key_digest, 'hex') = repeat('00', 32)
     OR p_public_request_digest IS NULL
     OR octet_length(p_public_request_digest) <> 32
     OR encode(p_public_request_digest, 'hex') = repeat('00', 32)
     OR p_audit_event_id IS NULL
     OR uuid_extract_version(p_audit_event_id) IS DISTINCT FROM 7
     OR p_request_id IS NULL
     OR uuid_extract_version(p_request_id) IS DISTINCT FROM 7
     OR p_correlation_id IS NULL
     OR uuid_extract_version(p_correlation_id) IS DISTINCT FROM 7
     OR p_ip_address IS NULL
     OR p_user_agent IS NULL
     OR octet_length(p_user_agent) NOT BETWEEN 1 AND 512
     OR NOT app.private_platform_identity_text_is_safe_v1(p_user_agent, false)
     OR p_reason IS NULL
     OR NOT app.private_platform_lifecycle_reason_is_valid_v1(p_reason) THEN
    RAISE EXCEPTION 'invalid platform identity account prelink command'
      USING ERRCODE = '22023';
  END IF;
  FOR alias_index IN 1..alias_count LOOP
    IF p_alias_key_versions[alias_index] NOT BETWEEN 1 AND 32767
       OR (alias_index > 1 AND
         p_alias_key_versions[alias_index - 1] >=
           p_alias_key_versions[alias_index])
       OR p_alias_subject_digests[alias_index] IS NULL
       OR octet_length(p_alias_subject_digests[alias_index]) <> 32
       OR encode(p_alias_subject_digests[alias_index], 'hex') =
          repeat('00', 32) THEN
      RAISE EXCEPTION 'invalid platform identity account subject aliases'
        USING ERRCODE = '22023';
    END IF;
  END LOOP;
  IF NOT p_key_version = ANY(p_alias_key_versions) THEN
    RAISE EXCEPTION 'platform identity account envelope key has no alias'
      USING ERRCODE = '22023';
  END IF;

  actor_id := app.private_require_platform_identity_permission_v1(
    p_session_id, 'platform.identity_account.manage', p_authentication_method
  );
  read_actor_id := app.private_require_platform_identity_permission_v1(
    p_session_id, 'platform.identity_account.read', p_authentication_method
  );
  IF read_actor_id IS DISTINCT FROM actor_id THEN
    RAISE EXCEPTION 'live platform identity account read authority is required'
      USING ERRCODE = '42501';
  END IF;

  PERFORM pg_advisory_xact_lock(hashtextextended(
    actor_id::text || ':account.prelink:' || p_provider_id::text || ':' ||
      encode(p_key_digest, 'hex'), 81460321
  ));
  DELETE FROM ONLY public.platform_identity_account_commands AS command
  WHERE command.actor_user_id = actor_id
    AND command.operation = 'account.prelink'
    AND command.platform_provider_id = p_provider_id
    AND command.key_digest = p_key_digest
    AND command.expires_at <= transaction_timestamp();
  IF pg_try_advisory_xact_lock(hashtextextended(
       'platform_identity_account_commands:expiry-cleanup:v1', 81460321
     )) THEN
    WITH expired_command AS (
      SELECT command.id
      FROM ONLY public.platform_identity_account_commands AS command
      WHERE command.expires_at <= transaction_timestamp()
      ORDER BY command.expires_at, command.id
      LIMIT 64
      FOR UPDATE SKIP LOCKED
    )
    DELETE FROM ONLY public.platform_identity_account_commands AS command
    USING expired_command
    WHERE command.id = expired_command.id;
  END IF;

  -- Resolve an unexpired command before consulting mutable provider or keyring
  -- state.  The replay guarantee is bound to the original public payload and
  -- protected alias vector, so a later provider archive/configuration change
  -- or key retirement must not invalidate an exact replay.
  SELECT command.* INTO replay_record
  FROM ONLY public.platform_identity_account_commands AS command
  WHERE command.actor_user_id = actor_id
    AND command.operation = 'account.prelink'
    AND command.platform_provider_id = p_provider_id
    AND command.key_digest = p_key_digest
    AND command.expires_at > transaction_timestamp()
  FOR UPDATE;
  IF FOUND THEN
    IF NOT app.private_platform_identity_digest_equal_v1(
      replay_record.public_request_digest, p_public_request_digest
    ) THEN
      RAISE EXCEPTION 'platform identity account idempotency conflict'
        USING ERRCODE = '23505';
    END IF;

    -- Retirement takes provider then identity FOR UPDATE.  A replay needs no
    -- provider lock: pinning the immutable result identity FOR SHARE keeps its
    -- aliases and current safe projection coherent while allowing archived
    -- providers and retired account tombstones to replay.
    PERFORM 1
    FROM ONLY public.platform_federated_external_identities AS identity
    WHERE identity.platform_provider_id = p_provider_id
      AND identity.id = replay_record.result_account_id
    FOR SHARE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'platform identity account replay result is unavailable'
        USING ERRCODE = 'XX000';
    END IF;
    FOR alias_index IN 1..alias_count LOOP
      PERFORM pg_advisory_xact_lock(hashtextextended(
        p_provider_id::text || ':' || p_alias_key_versions[alias_index]::text ||
          ':' || encode(p_alias_subject_digests[alias_index], 'hex'),
        81460322
      ));
    END LOOP;
    WITH wanted AS (
      SELECT alias.key_version, alias.subject_digest
      FROM unnest(p_alias_key_versions, p_alias_subject_digests)
        AS alias(key_version, subject_digest)
    ), matches AS (
      SELECT alias.external_identity_id, identity.id AS live_record_id
      FROM wanted
      JOIN ONLY public.platform_federated_external_identity_aliases AS alias
        ON alias.platform_provider_id = p_provider_id
       AND alias.key_version = wanted.key_version
       AND alias.subject_digest = wanted.subject_digest
      LEFT JOIN ONLY public.platform_federated_external_identities AS identity
        ON identity.platform_provider_id = alias.platform_provider_id
       AND identity.id = alias.external_identity_id
    )
    SELECT count(*)::integer,
           count(DISTINCT external_identity_id)::integer,
           count(*) FILTER (
             WHERE external_identity_id <> replay_record.result_account_id
           )::integer,
           count(*) FILTER (WHERE live_record_id IS NULL)::integer
      INTO matched_alias_count, matched_account_count,
           divergent_alias_count, malformed_alias_count
    FROM matches;
    IF malformed_alias_count > 0 OR matched_account_count > 1 THEN
      RAISE EXCEPTION 'platform identity account alias state is unavailable'
        USING ERRCODE = 'XX000';
    END IF;
    IF matched_alias_count <> alias_count OR matched_account_count <> 1
       OR divergent_alias_count > 0 THEN
      RAISE EXCEPTION 'platform identity account subject replay conflict'
        USING ERRCODE = '23505';
    END IF;
    account_document := app.private_platform_identity_account_document_v1(
      p_provider_id, replay_record.result_account_id
    );
    RETURN QUERY SELECT replay_record.result_account_id,
      replay_record.result_version, true, account_document;
    RETURN;
  END IF;

  SELECT provider.* INTO provider_record
  FROM ONLY public.platform_auth_providers AS provider
  WHERE provider.id = p_provider_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'platform identity provider does not exist'
      USING ERRCODE = 'P0002';
  END IF;
  IF provider_record.kind <> 'oidc'
     OR provider_record.archived_at IS NOT NULL THEN
    RAISE EXCEPTION 'platform identity account requires a live OIDC provider'
      USING ERRCODE = '55000';
  END IF;
  SELECT policy.* INTO policy_record
  FROM ONLY public.platform_federated_provider_policies AS policy
  WHERE policy.provider_id = p_provider_id
    AND policy.provider_kind = 'oidc'
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'platform identity provider policy is unavailable'
      USING ERRCODE = '55000';
  END IF;
  SELECT configuration.* INTO configuration_record
  FROM ONLY public.platform_oidc_provider_configurations AS configuration
  WHERE configuration.provider_id = p_provider_id
  FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'platform OIDC configuration is unavailable'
      USING ERRCODE = '55000';
  END IF;
  IF configuration_record.issuer IS DISTINCT FROM p_issuer THEN
    RAISE EXCEPTION 'platform identity account issuer does not match provider'
      USING ERRCODE = '22023';
  END IF;

  -- Lock every subject namespace in canonical key-version order before
  -- resolving aliases. Advisory hash collisions only serialize extra work.
  FOR alias_index IN 1..alias_count LOOP
    PERFORM pg_advisory_xact_lock(hashtextextended(
      p_provider_id::text || ':' || p_alias_key_versions[alias_index]::text ||
        ':' || encode(p_alias_subject_digests[alias_index], 'hex'),
      81460322
    ));
  END LOOP;
  -- Match the V3 keyring verifier's dependency-before-keyring lock order.
  LOCK TABLE ONLY public.platform_federated_external_identities,
    public.platform_federated_external_identity_aliases
    IN ROW EXCLUSIVE MODE;
  PERFORM 1
  FROM ONLY public.identity_keyring_versions AS keyring
  WHERE keyring.key_version = ANY(p_alias_key_versions)
    AND keyring.retired_at IS NULL
  ORDER BY keyring.key_version
  FOR SHARE;
  IF (SELECT count(*)
      FROM ONLY public.identity_keyring_versions AS keyring
      WHERE keyring.key_version = ANY(p_alias_key_versions)
        AND keyring.retired_at IS NULL) <> alias_count
     OR NOT EXISTS (
       SELECT 1
       FROM ONLY public.identity_keyring_versions AS keyring
       WHERE keyring.key_version = p_key_version
         AND keyring.is_active AND keyring.retired_at IS NULL
     ) THEN
    RAISE EXCEPTION 'platform identity account keyring is unavailable'
      USING ERRCODE = '55000';
  END IF;

  PERFORM 1
  FROM ONLY public.users AS local_user
  WHERE local_user.id = p_user_id AND local_user.active
  FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'platform identity account user does not exist'
      USING ERRCODE = 'P0002';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM ONLY public.platform_federated_external_identities AS identity
    WHERE identity.id = p_account_id
  ) OR EXISTS (
    SELECT 1
    FROM unnest(p_alias_key_versions, p_alias_subject_digests)
      AS wanted(key_version, subject_digest)
    JOIN ONLY public.platform_federated_external_identity_aliases AS alias
      ON alias.platform_provider_id = p_provider_id
     AND alias.key_version = wanted.key_version
     AND alias.subject_digest = wanted.subject_digest
  ) THEN
    RAISE EXCEPTION 'platform identity account subject is already reserved'
      USING ERRCODE = '23505';
  END IF;

  INSERT INTO public.platform_federated_external_identities (
    id, platform_provider_id, provider_kind, user_id, subject_format,
    subject_ciphertext, subject_nonce, key_version,
    admitted_configuration_revision, admitted_security_revision,
    last_observed_at, version, created_at, updated_at
  ) VALUES (
    p_account_id, p_provider_id, 'oidc', p_user_id, p_subject_format,
    p_subject_ciphertext, p_subject_nonce, p_key_version,
    policy_record.configuration_revision, policy_record.security_revision,
    transaction_timestamp(), 1, transaction_timestamp(),
    transaction_timestamp()
  );
  FOR alias_index IN 1..alias_count LOOP
    INSERT INTO public.platform_federated_external_identity_aliases (
      id, platform_provider_id, external_identity_id, key_version,
      subject_digest, created_at
    ) VALUES (
      uuidv7(), p_provider_id, p_account_id,
      p_alias_key_versions[alias_index],
      p_alias_subject_digests[alias_index], transaction_timestamp()
    );
  END LOOP;
  INSERT INTO public.platform_identity_account_commands (
    id, actor_user_id, operation, platform_provider_id,
    key_digest, public_request_digest, result_account_id, result_version,
    created_at, expires_at
  ) VALUES (
    p_command_id, actor_id, 'account.prelink', p_provider_id,
    p_key_digest, p_public_request_digest, p_account_id, 1,
    transaction_timestamp(), transaction_timestamp() + interval '24 hours'
  );
  PERFORM app.append_platform_audit_event(
    p_audit_event_id, 'user', actor_id,
    'platform.identity_account.prelinked', 'platform_identity_account',
    p_account_id, p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method, 'success', p_reason,
    jsonb_build_object(
      'provider_id', p_provider_id,
      'user_id', p_user_id,
      'version', 1,
      'admitted_configuration_revision',
        policy_record.configuration_revision,
      'admitted_security_revision', policy_record.security_revision,
      'subject_material_included', false,
      'replayed', false
    )
  );
  account_document := app.private_platform_identity_account_document_v1(
    p_provider_id, p_account_id
  );
  RETURN QUERY SELECT p_account_id, 1::bigint, false, account_document;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.retire_platform_identity_account_v1(
  p_session_id uuid,
  p_provider_id uuid,
  p_account_id uuid,
  p_expected_version bigint,
  p_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text,
  p_reason text
)
RETURNS TABLE (
  account_id uuid,
  version bigint,
  document jsonb
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor_id uuid;
  read_actor_id uuid;
  provider_record public.platform_auth_providers%ROWTYPE;
  identity_record public.platform_federated_external_identities%ROWTYPE;
  changed_at timestamptz := transaction_timestamp();
  affected_tenant_ids uuid[] := ARRAY[]::uuid[];
  affected_membership_ids uuid[] := ARRAY[]::uuid[];
  owned_membership_ids uuid[] := ARRAY[]::uuid[];
  affected_membership_id uuid;
  affected_tenant_id uuid;
  affected_tenant_grant_count integer;
  revoked_session_count integer := 0;
  revoked_continuation_count integer := 0;
  ended_grant_count integer := 0;
  account_document jsonb;
BEGIN
  IF p_provider_id IS NULL
     OR uuid_extract_version(p_provider_id) IS DISTINCT FROM 7
     OR p_account_id IS NULL
     OR uuid_extract_version(p_account_id) IS DISTINCT FROM 7
     OR p_expected_version IS NULL
     OR p_expected_version NOT BETWEEN 1 AND 2147483646
     OR p_audit_event_id IS NULL
     OR uuid_extract_version(p_audit_event_id) IS DISTINCT FROM 7
     OR p_request_id IS NULL
     OR uuid_extract_version(p_request_id) IS DISTINCT FROM 7
     OR p_correlation_id IS NULL
     OR uuid_extract_version(p_correlation_id) IS DISTINCT FROM 7
     OR p_ip_address IS NULL
     OR p_user_agent IS NULL
     OR octet_length(p_user_agent) NOT BETWEEN 1 AND 512
     OR NOT app.private_platform_identity_text_is_safe_v1(p_user_agent, false)
     OR p_reason IS NULL
     OR NOT app.private_platform_lifecycle_reason_is_valid_v1(p_reason) THEN
    RAISE EXCEPTION 'invalid platform identity account retirement command'
      USING ERRCODE = '22023';
  END IF;
  actor_id := app.private_require_platform_identity_permission_v1(
    p_session_id, 'platform.identity_account.manage', p_authentication_method
  );
  read_actor_id := app.private_require_platform_identity_permission_v1(
    p_session_id, 'platform.identity_account.read', p_authentication_method
  );
  IF read_actor_id IS DISTINCT FROM actor_id THEN
    RAISE EXCEPTION 'live platform identity account read authority is required'
      USING ERRCODE = '42501';
  END IF;

  SELECT provider.* INTO provider_record
  FROM ONLY public.platform_auth_providers AS provider
  WHERE provider.id = p_provider_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'platform identity provider does not exist'
      USING ERRCODE = 'P0002';
  END IF;
  SELECT identity.* INTO identity_record
  FROM ONLY public.platform_federated_external_identities AS identity
  WHERE identity.platform_provider_id = p_provider_id
    AND identity.id = p_account_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'platform identity account does not exist'
      USING ERRCODE = 'P0002';
  END IF;
  IF identity_record.version <> p_expected_version THEN
    RAISE EXCEPTION 'platform identity account revision conflict'
      USING ERRCODE = '40001';
  END IF;
  IF identity_record.retired_at IS NOT NULL THEN
    RAISE EXCEPTION 'platform identity account is already retired'
      USING ERRCODE = '55000';
  END IF;

  -- Lock all tenant admission paths before changing any of them. Provider
  -- authentication takes the provider lock first, so this order cannot invert
  -- the login/apply path.
  PERFORM 1
  FROM ONLY public.tenant_platform_federated_provider_access_grants AS grant_row
  WHERE grant_row.platform_provider_id = p_provider_id
    AND grant_row.external_identity_id = p_account_id
    AND grant_row.ended_at IS NULL
  ORDER BY grant_row.tenant_id, grant_row.id
  FOR UPDATE;
  SELECT coalesce(array_agg(DISTINCT grant_row.tenant_id
             ORDER BY grant_row.tenant_id), ARRAY[]::uuid[]),
         coalesce(array_agg(DISTINCT grant_row.membership_id
             ORDER BY grant_row.membership_id), ARRAY[]::uuid[]),
         coalesce(array_agg(DISTINCT grant_row.membership_id
             ORDER BY grant_row.membership_id)
           FILTER (WHERE grant_row.owns_membership), ARRAY[]::uuid[])
    INTO affected_tenant_ids, affected_membership_ids, owned_membership_ids
  FROM ONLY public.tenant_platform_federated_provider_access_grants AS grant_row
  WHERE grant_row.platform_provider_id = p_provider_id
    AND grant_row.external_identity_id = p_account_id
    AND grant_row.ended_at IS NULL;
  PERFORM 1
  FROM ONLY public.tenant_authorization_states AS authorization_state
  WHERE authorization_state.tenant_id = ANY(affected_tenant_ids)
  ORDER BY authorization_state.tenant_id
  FOR UPDATE;
  -- Profile materialization and every admission/apply path acquire membership
  -- before MFA subject.  Pre-lock the full affected set in that same canonical
  -- order so two provider retirements cannot form a membership/subject cycle,
  -- and keep the revision-headroom check stable through the updates below.
  PERFORM 1
  FROM ONLY public.tenant_memberships AS membership
  WHERE membership.id = ANY(affected_membership_ids)
    AND membership.user_id = identity_record.user_id
  ORDER BY membership.tenant_id, membership.id
  FOR UPDATE;
  PERFORM 1
  FROM ONLY public.tenant_mfa_subjects AS subject
  WHERE subject.tenant_id = ANY(affected_tenant_ids)
    AND subject.user_id = identity_record.user_id
  ORDER BY subject.tenant_id, subject.user_id
  FOR UPDATE;
  IF EXISTS (
    SELECT 1
    FROM ONLY public.tenant_mfa_subjects AS subject
    WHERE subject.tenant_id = ANY(affected_tenant_ids)
      AND subject.user_id = identity_record.user_id
      AND (subject.identity_epoch >= 9007199254740991
        OR subject.session_invalidation_epoch >= 9007199254740991
        OR subject.version >= 2147483647)
  ) THEN
    RAISE EXCEPTION 'platform identity account invalidation revision is exhausted'
      USING ERRCODE = '55000';
  END IF;

  UPDATE ONLY public.tenant_post_primary_continuations AS continuation
  SET state = 'revoked', version = continuation.version + 1,
      revoked_at = changed_at,
      revoke_reason = 'platform_identity_account_retired'
  WHERE continuation.platform_provider_id = p_provider_id
    AND continuation.external_identity_id = p_account_id
    AND continuation.user_id = identity_record.user_id
    AND continuation.primary_kind = 'tenant_platform_provider'
    AND continuation.state = 'pending';
  GET DIAGNOSTICS revoked_continuation_count = ROW_COUNT;

  WITH affected_families AS (
    SELECT DISTINCT source_session.rotation_family_id
    FROM ONLY public.auth_session_tenant_platform_federated_provenance
      AS provenance
    JOIN ONLY public.auth_sessions AS source_session
      ON source_session.id = provenance.session_id
     AND source_session.user_id = provenance.user_id
    WHERE provenance.platform_provider_id = p_provider_id
      AND provenance.external_identity_id = p_account_id
      AND provenance.user_id = identity_record.user_id
  )
  UPDATE ONLY public.auth_sessions AS session
  SET revoked_at = greatest(changed_at, session.created_at),
      revoke_reason = 'platform_identity_account_retired'
  FROM affected_families
  WHERE session.rotation_family_id = affected_families.rotation_family_id
    AND session.user_id = identity_record.user_id
    AND session.revoked_at IS NULL;
  GET DIAGNOSTICS revoked_session_count = ROW_COUNT;

  UPDATE ONLY public.tenant_platform_federated_provider_profile_contributions
    AS contribution
  SET retired_at = changed_at, version = contribution.version + 1
  FROM ONLY public.tenant_platform_federated_provider_access_grants AS grant_row
  WHERE grant_row.platform_provider_id = p_provider_id
    AND grant_row.external_identity_id = p_account_id
    AND grant_row.ended_at IS NULL
    AND contribution.tenant_id = grant_row.tenant_id
    AND contribution.access_grant_id = grant_row.id
    AND contribution.retired_at IS NULL;
  UPDATE ONLY public.tenant_platform_federated_provider_access_grants AS grant_row
  SET ended_at = changed_at, version = grant_row.version + 1
  WHERE grant_row.platform_provider_id = p_provider_id
    AND grant_row.external_identity_id = p_account_id
    AND grant_row.ended_at IS NULL;
  GET DIAGNOSTICS ended_grant_count = ROW_COUNT;

  UPDATE ONLY public.tenant_mfa_subjects AS subject
  SET identity_epoch = subject.identity_epoch + 1,
      session_invalidation_epoch = subject.session_invalidation_epoch + 1,
      version = subject.version + 1,
      updated_at = changed_at
  WHERE subject.tenant_id = ANY(affected_tenant_ids)
    AND subject.user_id = identity_record.user_id;

  FOREACH affected_membership_id IN ARRAY affected_membership_ids LOOP
    SELECT grant_row.tenant_id INTO affected_tenant_id
    FROM ONLY public.tenant_platform_federated_provider_access_grants AS grant_row
    WHERE grant_row.platform_provider_id = p_provider_id
      AND grant_row.external_identity_id = p_account_id
      AND grant_row.membership_id = affected_membership_id
    ORDER BY grant_row.tenant_id
    LIMIT 1;
    IF affected_tenant_id IS NOT NULL THEN
      PERFORM app.private_materialize_tenant_user_profile_v1(
        affected_tenant_id, affected_membership_id
      );
    END IF;
  END LOOP;

  -- A membership created solely by this admission must not survive the last
  -- live identity source. Additive/manual memberships remain untouched.
  UPDATE ONLY public.tenant_memberships AS membership
  SET status = 'suspended', updated_at = changed_at
  WHERE membership.id = ANY(owned_membership_ids)
    AND membership.user_id = identity_record.user_id
    AND membership.status = 'active'
    AND NOT EXISTS (
      SELECT 1
      FROM ONLY public.tenant_platform_federated_provider_access_grants AS other
      WHERE other.tenant_id = membership.tenant_id
        AND other.membership_id = membership.id
        AND other.ended_at IS NULL
    )
    AND NOT EXISTS (
      SELECT 1
      FROM ONLY public.tenant_ldap_provider_access_grants AS other
      WHERE other.tenant_id = membership.tenant_id
        AND other.membership_id = membership.id
        AND other.ended_at IS NULL
    )
    AND NOT EXISTS (
      SELECT 1
      FROM ONLY public.tenant_federated_provider_access_grants AS other
      WHERE other.tenant_id = membership.tenant_id
        AND other.membership_id = membership.id
        AND other.ended_at IS NULL
    )
    AND NOT EXISTS (
      SELECT 1
      FROM ONLY public.user_login_identifiers AS identifier
      WHERE identifier.user_id = membership.user_id
        AND identifier.retired_at IS NULL
    );

  UPDATE ONLY public.platform_federated_external_identity_aliases AS alias
  SET retired_at = changed_at
  WHERE alias.platform_provider_id = p_provider_id
    AND alias.external_identity_id = p_account_id
    AND alias.retired_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'platform identity account aliases are unavailable'
      USING ERRCODE = '55000';
  END IF;
  UPDATE ONLY public.platform_federated_external_identities AS identity
  SET retired_at = changed_at,
      last_observed_at = changed_at,
      version = identity.version + 1,
      updated_at = changed_at
  WHERE identity.platform_provider_id = p_provider_id
    AND identity.id = p_account_id
    AND identity.version = p_expected_version
    AND identity.retired_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'platform identity account revision conflict'
      USING ERRCODE = '40001';
  END IF;

  FOREACH affected_tenant_id IN ARRAY affected_tenant_ids LOOP
    SELECT count(*)::integer INTO affected_tenant_grant_count
    FROM ONLY public.tenant_platform_federated_provider_access_grants AS grant_row
    WHERE grant_row.tenant_id = affected_tenant_id
      AND grant_row.platform_provider_id = p_provider_id
      AND grant_row.external_identity_id = p_account_id
      AND grant_row.ended_at = changed_at;
    PERFORM app.private_append_platform_identity_account_tenant_audit_v1(
      affected_tenant_id, actor_id, p_audit_event_id, p_provider_id,
      p_account_id, p_request_id, p_correlation_id, p_ip_address,
      p_user_agent, p_authentication_method, p_reason,
      affected_tenant_grant_count
    );
  END LOOP;

  PERFORM app.append_platform_audit_event(
    p_audit_event_id, 'user', actor_id,
    'platform.identity_account.retired', 'platform_identity_account',
    p_account_id, p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method, 'success', p_reason,
    jsonb_build_object(
      'provider_id', p_provider_id,
      'user_id', identity_record.user_id,
      'previous_version', identity_record.version,
      'version', identity_record.version + 1,
      'affected_tenant_count', cardinality(affected_tenant_ids),
      'ended_access_grant_count', ended_grant_count,
      'revoked_session_count', revoked_session_count,
      'revoked_continuation_count', revoked_continuation_count,
      'subject_material_included', false
    )
  );
  account_document := app.private_platform_identity_account_document_v1(
    p_provider_id, p_account_id
  );
  RETURN QUERY SELECT p_account_id, identity_record.version + 1,
    account_document;
END;
$function$;
--> statement-breakpoint

-- The generic V1 create ABI accepts a caller-selected provider kind and is not
-- a runtime capability.  This wrapper fixes the kind to SAML, matching the
-- existing OIDC-specific V2 boundary.
CREATE FUNCTION app.create_platform_saml_auth_provider_v2(
  p_session_id uuid,
  p_command_id uuid,
  p_provider_id uuid,
  p_key text,
  p_display_name text,
  p_description text,
  p_configuration jsonb,
  p_key_digest bytea,
  p_request_digest bytea,
  p_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text,
  p_reason text
)
RETURNS TABLE (
  provider_id uuid,
  version bigint,
  replayed boolean,
  document jsonb
)
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT created.provider_id, created.version, created.replayed,
         created.document
  FROM app.create_platform_auth_provider_v1(
    p_session_id, p_command_id, p_provider_id, 'saml', p_key,
    p_display_name, p_description, p_configuration, p_key_digest,
    p_request_digest, p_audit_event_id, p_request_id, p_correlation_id,
    p_ip_address, p_user_agent, p_authentication_method, p_reason
  ) AS created;
$function$;
--> statement-breakpoint

-- Forward-only repair of two frozen V35 bodies.  Both replacements are
-- guarded by their exact predecessor fragments so drift fails the migration
-- instead of silently weakening either invariant.
DO $ldap_completion_audit_fix$
DECLARE
  definition text;
  fixed_definition text;
  opening_fragment constant text := E'    jsonb_build_object(\n      ''provider_id'', locked_run.provider_id,';
  closing_fragment constant text := E'      ''authorization_revision'', locked_run.authorization_revision\n    ),\n    jsonb_build_object(';
BEGIN
  SELECT pg_get_functiondef(
    'app.complete_tenant_ldap_directory_operation_v1(uuid,public.ldap_provider_test_outcome,public.ldap_provider_test_category,integer,integer,integer,boolean,uuid,uuid,uuid,inet,text,text)'::regprocedure
  ) INTO STRICT definition;
  IF position(opening_fragment IN definition) = 0
     OR position(closing_fragment IN definition) = 0
     OR position('jsonb_strip_nulls(jsonb_build_object(' IN definition) > 0 THEN
    RAISE EXCEPTION 'unexpected LDAP completion audit predecessor';
  END IF;
  fixed_definition := replace(
    definition, opening_fragment,
    E'    jsonb_strip_nulls(jsonb_build_object(\n      ''provider_id'', locked_run.provider_id,'
  );
  fixed_definition := replace(
    fixed_definition, closing_fragment,
    E'      ''authorization_revision'', locked_run.authorization_revision\n    )),\n    jsonb_build_object('
  );
  IF fixed_definition = definition
     OR position(opening_fragment IN fixed_definition) > 0
     OR position(closing_fragment IN fixed_definition) > 0 THEN
    RAISE EXCEPTION 'LDAP completion audit repair was not exact';
  END IF;
  EXECUTE fixed_definition;
END;
$ldap_completion_audit_fix$;
--> statement-breakpoint

DO $local_primary_passkey_step_up_fix$
DECLARE
  definition text;
  fixed_definition text;
  strict_fragment constant text :=
    'SELECT provenance.credential_id INTO STRICT v_primary_credential_id';
  branch_fragment constant text :=
    'IF v_primary_credential_id = v_credential_id THEN';
BEGIN
  SELECT pg_get_functiondef(
    'app.complete_mfa_passkey_authentication_v1(jsonb)'::regprocedure
  ) INTO STRICT definition;
  IF position(strict_fragment IN definition) = 0
     OR position(branch_fragment IN definition) = 0
     OR position('INTO v_primary_credential_id' IN definition) > 0
     OR position('IF FOUND AND v_primary_credential_id' IN definition) > 0 THEN
    RAISE EXCEPTION 'unexpected passkey completion predecessor';
  END IF;
  fixed_definition := replace(
    definition, strict_fragment,
    'SELECT provenance.credential_id INTO v_primary_credential_id'
  );
  fixed_definition := replace(
    fixed_definition, branch_fragment,
    'IF FOUND AND v_primary_credential_id = v_credential_id THEN'
  );
  IF fixed_definition = definition
     OR position(strict_fragment IN fixed_definition) > 0
     OR position(branch_fragment IN fixed_definition) > 0 THEN
    RAISE EXCEPTION 'passkey completion repair was not exact';
  END IF;
  EXECUTE fixed_definition;
END;
$local_primary_passkey_step_up_fix$;
--> statement-breakpoint

ALTER FUNCTION app.guard_platform_identity_account_command_v1()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_platform_identity_digest_equal_v1(bytea, bytea)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_append_platform_identity_account_tenant_audit_v1(
  uuid, uuid, uuid, uuid, uuid, uuid, uuid, inet, text, text, text, integer
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_platform_identity_account_document_v1(uuid, uuid)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.list_platform_identity_accounts_v1(
  uuid, text, uuid, uuid, integer, boolean
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.get_platform_identity_account_v1(uuid, uuid, uuid, text)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.prelink_platform_identity_account_v1(
  uuid, uuid, uuid, uuid, uuid, text, public.identity_subject_format,
  bytea, bytea, integer, integer[], bytea[], bytea, bytea, uuid, uuid,
  uuid, inet, text, text, text
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.retire_platform_identity_account_v1(
  uuid, uuid, uuid, bigint, uuid, uuid, uuid, inet, text, text, text
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.create_platform_saml_auth_provider_v2(
  uuid, uuid, uuid, text, text, text, jsonb, bytea, bytea, uuid, uuid,
  uuid, inet, text, text, text
) OWNER TO periapsis_migrator;
--> statement-breakpoint

REVOKE ALL ON FUNCTION app.guard_platform_identity_account_command_v1(),
  app.private_platform_identity_digest_equal_v1(bytea, bytea),
  app.private_append_platform_identity_account_tenant_audit_v1(
    uuid, uuid, uuid, uuid, uuid, uuid, uuid, inet, text, text, text, integer
  ),
  app.private_platform_identity_account_document_v1(uuid, uuid),
  app.list_platform_identity_accounts_v1(uuid, text, uuid, uuid, integer, boolean),
  app.get_platform_identity_account_v1(uuid, uuid, uuid, text),
  app.prelink_platform_identity_account_v1(
    uuid, uuid, uuid, uuid, uuid, text, public.identity_subject_format,
    bytea, bytea, integer, integer[], bytea[], bytea, bytea, uuid, uuid,
    uuid, inet, text, text, text
  ),
  app.retire_platform_identity_account_v1(
    uuid, uuid, uuid, bigint, uuid, uuid, uuid, inet, text, text, text
  ),
  app.create_platform_saml_auth_provider_v2(
    uuid, uuid, uuid, text, text, text, jsonb, bytea, bytea, uuid, uuid,
    uuid, inet, text, text, text
  )
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner, periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
--> statement-breakpoint

GRANT EXECUTE ON FUNCTION
  app.list_platform_identity_accounts_v1(uuid, text, uuid, uuid, integer, boolean),
  app.get_platform_identity_account_v1(uuid, uuid, uuid, text),
  app.prelink_platform_identity_account_v1(
    uuid, uuid, uuid, uuid, uuid, text, public.identity_subject_format,
    bytea, bytea, integer, integer[], bytea[], bytea, bytea, uuid, uuid,
    uuid, inet, text, text, text
  ),
  app.retire_platform_identity_account_v1(
    uuid, uuid, uuid, bigint, uuid, uuid, uuid, inet, text, text, text
  ),
  app.create_platform_saml_auth_provider_v2(
    uuid, uuid, uuid, text, text, text, jsonb, bytea, bytea, uuid, uuid,
    uuid, inet, text, text, text
  )
TO periapsis_api;
--> statement-breakpoint

-- The caller-selected V1 provider-kind boundary remains migrator-only.
REVOKE ALL ON FUNCTION app.create_platform_auth_provider_v1(
  uuid, uuid, uuid, public.auth_provider_kind, text, text, text, jsonb,
  bytea, bytea, uuid, uuid, uuid, inet, text, text, text
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner, periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
