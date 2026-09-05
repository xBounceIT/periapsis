-- V36 retirement overwrote last_observed_at with the retirement timestamp.
-- Resource-version one on a retired row is a durable discriminator for a row
-- retired before the v37 guard existed: every retirement protected by v37
-- advances resource_version to at least two. Equality is also required so a
-- malformed/tampered predecessor row is never silently reclassified.
ALTER TABLE ONLY public.platform_federated_external_identities
  DISABLE TRIGGER platform_federated_external_identities_guard_v3;
UPDATE ONLY public.platform_federated_external_identities AS identity
SET last_observation_state = 'legacy_unknown'
WHERE identity.retired_at IS NOT NULL
  AND identity.resource_version = 1
  AND identity.last_observed_at = identity.retired_at;
ALTER TABLE ONLY public.platform_federated_external_identities
  ENABLE TRIGGER platform_federated_external_identities_guard_v3;
--> statement-breakpoint

DO $verify_legacy_observation_classification$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM ONLY public.platform_federated_external_identities AS identity
    WHERE identity.retired_at IS NOT NULL
      AND identity.resource_version = 1
      AND identity.last_observed_at = identity.retired_at
      AND identity.last_observation_state <> 'legacy_unknown'
  ) OR EXISTS (
    SELECT 1
    FROM ONLY public.platform_federated_external_identities AS identity
    WHERE identity.last_observation_state = 'legacy_unknown'
      AND NOT (
        identity.retired_at IS NOT NULL
        AND identity.resource_version = 1
        AND identity.last_observed_at = identity.retired_at
      )
  ) THEN
    RAISE EXCEPTION 'platform identity legacy observation classification failed'
      USING ERRCODE = '55000';
  END IF;
END;
$verify_legacy_observation_classification$;
--> statement-breakpoint

COMMENT ON COLUMN
  public.platform_federated_external_identities.last_observation_state IS
  'known when last_observed_at is a successful provider observation; legacy_unknown marks an irrecoverable v36 retirement overwrite and projects the timestamp as null.';
--> statement-breakpoint

CREATE FUNCTION app.guard_platform_federated_external_identity_v4()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'platform federated identities are archival records'
      USING ERRCODE = '55000';
  END IF;
  IF TG_OP = 'INSERT' THEN
    IF NEW.version <> 1 OR NEW.resource_version <> 1
       OR NEW.last_observation_state <> 'known'
       OR NEW.retired_at IS NOT NULL
       OR NEW.created_at IS DISTINCT FROM transaction_timestamp()
       OR NEW.updated_at IS DISTINCT FROM transaction_timestamp()
       OR NEW.last_observed_at IS DISTINCT FROM transaction_timestamp() THEN
      RAISE EXCEPTION 'platform federated identity create envelope is invalid'
        USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
  END IF;

  IF ROW(NEW.id, NEW.platform_provider_id, NEW.provider_kind, NEW.user_id,
         NEW.subject_format, NEW.subject_ciphertext, NEW.subject_nonce,
         NEW.key_version, NEW.admitted_configuration_revision,
         NEW.admitted_security_revision, NEW.last_observation_state,
         NEW.created_at)
     IS DISTINCT FROM
     ROW(OLD.id, OLD.platform_provider_id, OLD.provider_kind, OLD.user_id,
         OLD.subject_format, OLD.subject_ciphertext, OLD.subject_nonce,
         OLD.key_version, OLD.admitted_configuration_revision,
         OLD.admitted_security_revision, OLD.last_observation_state,
         OLD.created_at)
     OR NEW.updated_at IS DISTINCT FROM transaction_timestamp()
     OR NEW.last_observed_at < OLD.last_observed_at
     OR OLD.retired_at IS NOT NULL
     OR OLD.resource_version >= 2147483647
     OR NEW.resource_version NOT IN (
       OLD.resource_version, OLD.resource_version + 1
     ) THEN
    RAISE EXCEPTION 'platform federated identity transition is invalid'
      USING ERRCODE = '23514';
  END IF;

  IF NEW.retired_at IS NULL THEN
    IF NEW.version <> OLD.version
       OR NEW.last_observed_at IS DISTINCT FROM transaction_timestamp() THEN
      RAISE EXCEPTION 'platform federated identity observation is invalid'
        USING ERRCODE = '23514';
    END IF;
  ELSE
    IF OLD.version >= 2147483647
       OR NEW.version <> OLD.version + 1
       OR NEW.retired_at IS DISTINCT FROM transaction_timestamp()
       OR (
         NEW.last_observed_at IS DISTINCT FROM OLD.last_observed_at
         AND NEW.last_observed_at IS DISTINCT FROM transaction_timestamp()
       ) THEN
      RAISE EXCEPTION 'platform federated identity retirement is invalid'
        USING ERRCODE = '23514';
    END IF;
    NEW.last_observed_at := OLD.last_observed_at;
    NEW.last_observation_state := OLD.last_observation_state;
  END IF;
  NEW.resource_version := OLD.resource_version + 1;
  RETURN NEW;
END;
$function$;
--> statement-breakpoint

DROP TRIGGER platform_federated_external_identities_guard_v3
  ON public.platform_federated_external_identities;
CREATE TRIGGER platform_federated_external_identities_guard_v4
BEFORE INSERT OR UPDATE OR DELETE
ON public.platform_federated_external_identities
FOR EACH ROW
EXECUTE FUNCTION app.guard_platform_federated_external_identity_v4();
--> statement-breakpoint

CREATE FUNCTION app.private_platform_identity_account_document_v2(
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
      'active', local_user.active,
      'version', local_user.version
    ),
    'state', CASE WHEN identity.retired_at IS NULL
      THEN 'active' ELSE 'retired' END,
    'admittedConfigurationRevision',
      identity.admitted_configuration_revision,
    'admittedSecurityRevision', identity.admitted_security_revision,
    'lastObservationState', identity.last_observation_state,
    'lastObservedAt', CASE
      WHEN identity.last_observation_state = 'known'
        THEN identity.last_observed_at
      ELSE NULL
    END,
    'retiredAt', identity.retired_at,
    'version', identity.resource_version,
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

CREATE FUNCTION app.list_platform_identity_accounts_v2(
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
  SELECT app.private_platform_identity_account_document_v2(
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

CREATE FUNCTION app.get_platform_identity_account_v2(
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
  RETURN app.private_platform_identity_account_document_v2(
    p_provider_id, p_account_id
  );
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.prelink_platform_identity_account_v2(
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
DECLARE
  previous_result record;
BEGIN
  SELECT result.account_id, result.version, result.replayed
    INTO STRICT previous_result
  FROM app.prelink_platform_identity_account_v1(
    p_session_id, p_command_id, p_account_id, p_provider_id, p_user_id,
    p_issuer, p_subject_format, p_subject_ciphertext, p_subject_nonce,
    p_key_version, p_alias_key_versions, p_alias_subject_digests,
    p_key_digest, p_public_request_digest, p_audit_event_id, p_request_id,
    p_correlation_id, p_ip_address, p_user_agent, p_authentication_method,
    p_reason
  ) AS result;
  RETURN QUERY SELECT previous_result.account_id, previous_result.version,
    previous_result.replayed,
    app.private_platform_identity_account_document_v2(
      p_provider_id, previous_result.account_id
    );
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.retire_platform_identity_account_v3(
  p_session_id uuid,
  p_provider_id uuid,
  p_account_id uuid,
  p_expected_version bigint,
  p_expected_user_version bigint,
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
  previous_result record;
BEGIN
  SELECT result.account_id, result.version
    INTO STRICT previous_result
  FROM app.retire_platform_identity_account_v2(
    p_session_id, p_provider_id, p_account_id, p_expected_version,
    p_expected_user_version, p_audit_event_id, p_request_id,
    p_correlation_id, p_ip_address, p_user_agent, p_authentication_method,
    p_reason
  ) AS result;
  RETURN QUERY SELECT previous_result.account_id, previous_result.version,
    app.private_platform_identity_account_document_v2(
      p_provider_id, previous_result.account_id
    );
END;
$function$;
--> statement-breakpoint

ALTER FUNCTION app.guard_platform_federated_external_identity_v4()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_platform_identity_account_document_v2(uuid, uuid)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.list_platform_identity_accounts_v2(
  uuid, text, uuid, uuid, integer, boolean
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.get_platform_identity_account_v2(uuid, uuid, uuid, text)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.prelink_platform_identity_account_v2(
  uuid, uuid, uuid, uuid, uuid, text, public.identity_subject_format,
  bytea, bytea, integer, integer[], bytea[], bytea, bytea, uuid, uuid,
  uuid, inet, text, text, text
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.retire_platform_identity_account_v3(
  uuid, uuid, uuid, bigint, bigint, uuid, uuid, uuid, inet, text, text, text
) OWNER TO periapsis_migrator;
--> statement-breakpoint

REVOKE ALL ON FUNCTION
  app.guard_platform_federated_external_identity_v3(),
  app.guard_platform_federated_external_identity_v4(),
  app.private_platform_identity_account_document_v1(uuid, uuid),
  app.private_platform_identity_account_document_v2(uuid, uuid),
  app.list_platform_identity_accounts_v1(uuid, text, uuid, uuid, integer, boolean),
  app.list_platform_identity_accounts_v2(uuid, text, uuid, uuid, integer, boolean),
  app.get_platform_identity_account_v1(uuid, uuid, uuid, text),
  app.get_platform_identity_account_v2(uuid, uuid, uuid, text),
  app.prelink_platform_identity_account_v1(
    uuid, uuid, uuid, uuid, uuid, text, public.identity_subject_format,
    bytea, bytea, integer, integer[], bytea[], bytea, bytea, uuid, uuid,
    uuid, inet, text, text, text
  ),
  app.prelink_platform_identity_account_v2(
    uuid, uuid, uuid, uuid, uuid, text, public.identity_subject_format,
    bytea, bytea, integer, integer[], bytea[], bytea, bytea, uuid, uuid,
    uuid, inet, text, text, text
  ),
  app.retire_platform_identity_account_v1(
    uuid, uuid, uuid, bigint, uuid, uuid, uuid, inet, text, text, text
  ),
  app.retire_platform_identity_account_v2(
    uuid, uuid, uuid, bigint, bigint, uuid, uuid, uuid, inet, text, text, text
  ),
  app.retire_platform_identity_account_v3(
    uuid, uuid, uuid, bigint, bigint, uuid, uuid, uuid, inet, text, text, text
  )
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner, periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
--> statement-breakpoint

GRANT EXECUTE ON FUNCTION
  app.list_platform_identity_accounts_v2(uuid, text, uuid, uuid, integer, boolean),
  app.get_platform_identity_account_v2(uuid, uuid, uuid, text),
  app.prelink_platform_identity_account_v2(
    uuid, uuid, uuid, uuid, uuid, text, public.identity_subject_format,
    bytea, bytea, integer, integer[], bytea[], bytea, bytea, uuid, uuid,
    uuid, inet, text, text, text
  ),
  app.retire_platform_identity_account_v3(
    uuid, uuid, uuid, bigint, bigint, uuid, uuid, uuid, inet, text, text, text
  )
TO periapsis_api;
