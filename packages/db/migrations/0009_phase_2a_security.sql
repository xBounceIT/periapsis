-- Custom SQL migration file: Phase 2A security controls.
-- Phase 2A controls intentionally outside the Drizzle schema DSL: object
-- ownership, forced RLS, least-privilege function entry points, atomic bootstrap,
-- and the independent tamper-evident platform audit stream.

ALTER TYPE "public"."auth_challenge_purpose" OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER TYPE "public"."auth_rate_limit_scope" OWNER TO "periapsis_migrator";--> statement-breakpoint

ALTER TABLE "public"."auth_challenges" OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER TABLE "public"."auth_rate_limits" OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER TABLE "public"."auth_sessions" OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER TABLE "public"."local_break_glass_credentials" OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER TABLE "public"."recovery_codes" OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER TABLE "public"."totp_credentials" OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER TABLE "public"."platform_audit_chain_head" OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER TABLE "public"."platform_audit_events" OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER TABLE "public"."platform_bootstrap_enrollments" OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER TABLE "public"."platform_bootstrap_state" OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER TABLE "public"."platform_permissions" OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER TABLE "public"."platform_role_permissions" OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER TABLE "public"."platform_roles" OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER TABLE "public"."user_platform_roles" OWNER TO "periapsis_migrator";--> statement-breakpoint

ALTER TABLE "public"."auth_challenges" FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "public"."auth_rate_limits" FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "public"."auth_sessions" FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "public"."local_break_glass_credentials" FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "public"."recovery_codes" FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "public"."totp_credentials" FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "public"."platform_audit_chain_head" FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "public"."platform_audit_events" FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "public"."platform_bootstrap_enrollments" FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "public"."platform_bootstrap_state" FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "public"."platform_permissions" FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "public"."platform_role_permissions" FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "public"."platform_roles" FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "public"."user_platform_roles" FORCE ROW LEVEL SECURITY;--> statement-breakpoint

REVOKE ALL ON TABLE "public"."auth_challenges" FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON TABLE "public"."auth_rate_limits" FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON TABLE "public"."auth_sessions" FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON TABLE "public"."local_break_glass_credentials" FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON TABLE "public"."recovery_codes" FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON TABLE "public"."totp_credentials" FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON TABLE "public"."platform_audit_chain_head" FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON TABLE "public"."platform_audit_events" FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON TABLE "public"."platform_bootstrap_enrollments" FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON TABLE "public"."platform_bootstrap_state" FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON TABLE "public"."platform_permissions" FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON TABLE "public"."platform_role_permissions" FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON TABLE "public"."platform_roles" FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON TABLE "public"."user_platform_roles" FROM PUBLIC;--> statement-breakpoint

CREATE POLICY "platform_audit_events_auditor_select"
ON "public"."platform_audit_events"
AS PERMISSIVE
FOR SELECT
TO "periapsis_auditor"
USING (true);--> statement-breakpoint
GRANT SELECT ON TABLE "public"."platform_audit_events" TO "periapsis_auditor";--> statement-breakpoint

INSERT INTO "public"."platform_bootstrap_state" ("singleton")
VALUES (true);--> statement-breakpoint
INSERT INTO "public"."platform_audit_chain_head" ("singleton")
VALUES (true);--> statement-breakpoint

INSERT INTO "public"."platform_permissions" ("id", "key", "description")
VALUES
  ('019c0000-0000-7000-8000-000000000001', 'platform.tenant.read', 'List platform tenants'),
  ('019c0000-0000-7000-8000-000000000002', 'platform.tenant.create', 'Create a tenant and its initial administrator membership');--> statement-breakpoint

INSERT INTO "public"."platform_roles" ("id", "key", "display_name", "system")
VALUES
  ('019c0000-0000-7000-8000-000000000101', 'platform_super_admin', 'Platform super administrator', true);--> statement-breakpoint

INSERT INTO "public"."platform_role_permissions" ("role_id", "permission_id")
SELECT '019c0000-0000-7000-8000-000000000101'::uuid, permission.id
FROM "public"."platform_permissions" AS permission;--> statement-breakpoint

CREATE FUNCTION "app"."platform_audit_event_payload"(p_event "public"."platform_audit_events")
RETURNS jsonb
LANGUAGE sql
STABLE
STRICT
PARALLEL SAFE
SET search_path = pg_catalog, public, app
AS $function$
  SELECT
    (to_jsonb(p_event) - 'previous_hash' - 'event_hash' - 'occurred_at')
    || jsonb_build_object(
      'occurred_at',
      to_char(p_event.occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
    );
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."calculate_platform_audit_event_hash"(
  p_event "public"."platform_audit_events",
  p_previous_hash character(64)
)
RETURNS character(64)
LANGUAGE sql
STABLE
STRICT
PARALLEL SAFE
SET search_path = pg_catalog, public, app
AS $function$
  SELECT encode(
    sha256(convert_to(p_previous_hash::text || app.platform_audit_event_payload(p_event)::text, 'UTF8')),
    'hex'
  )::character(64);
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."seal_platform_audit_event"()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  prior_hash character(64);
  prior_sequence bigint;
BEGIN
  SELECT last_event_hash, last_sequence
    INTO STRICT prior_hash, prior_sequence
    FROM public.platform_audit_chain_head
    WHERE singleton = true
    FOR UPDATE;

  NEW.sequence := prior_sequence + 1;
  NEW.previous_hash := prior_hash;
  NEW.event_hash := app.calculate_platform_audit_event_hash(NEW, prior_hash);

  UPDATE public.platform_audit_chain_head
  SET last_sequence = NEW.sequence,
      last_event_hash = NEW.event_hash,
      updated_at = transaction_timestamp()
  WHERE singleton = true;

  RETURN NEW;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."reject_platform_audit_event_mutation"()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  RAISE EXCEPTION 'platform audit events are append-only'
    USING ERRCODE = '55000';
END;
$function$;--> statement-breakpoint

ALTER FUNCTION "app"."platform_audit_event_payload"("public"."platform_audit_events") OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."calculate_platform_audit_event_hash"("public"."platform_audit_events", character) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."seal_platform_audit_event"() OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."reject_platform_audit_event_mutation"() OWNER TO "periapsis_migrator";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."platform_audit_event_payload"("public"."platform_audit_events") FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."calculate_platform_audit_event_hash"("public"."platform_audit_events", character) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."seal_platform_audit_event"() FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."reject_platform_audit_event_mutation"() FROM PUBLIC;--> statement-breakpoint

CREATE TRIGGER "platform_audit_events_seal_before_insert"
BEFORE INSERT ON "public"."platform_audit_events"
FOR EACH ROW
EXECUTE FUNCTION "app"."seal_platform_audit_event"();--> statement-breakpoint

CREATE TRIGGER "platform_audit_events_reject_update_delete"
BEFORE UPDATE OR DELETE ON "public"."platform_audit_events"
FOR EACH ROW
EXECUTE FUNCTION "app"."reject_platform_audit_event_mutation"();--> statement-breakpoint

CREATE FUNCTION "app"."append_platform_audit_event"(
  p_id uuid,
  p_actor_type "public"."audit_actor_type",
  p_actor_user_id uuid,
  p_action text,
  p_resource_type text,
  p_resource_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text,
  p_outcome "public"."audit_outcome",
  p_reason text,
  p_metadata jsonb
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_user_agent IS NOT NULL AND length(p_user_agent) NOT BETWEEN 1 AND 1024 THEN
    RAISE EXCEPTION 'platform audit user agent exceeds 1024 characters'
      USING ERRCODE = '22023';
  END IF;
  IF p_authentication_method IS NOT NULL
     AND p_authentication_method !~ '^[a-z][a-z0-9_]{0,63}$' THEN
    RAISE EXCEPTION 'platform audit authentication method is invalid'
      USING ERRCODE = '22023';
  END IF;
  IF p_reason IS NOT NULL AND length(p_reason) NOT BETWEEN 1 AND 1024 THEN
    RAISE EXCEPTION 'platform audit reason is invalid' USING ERRCODE = '22023';
  END IF;
  IF pg_column_size(coalesce(p_metadata, '{}'::jsonb)) > 8192 THEN
    RAISE EXCEPTION 'platform audit metadata exceeds 8192 bytes' USING ERRCODE = '22023';
  END IF;
  IF coalesce(p_metadata, '{}'::jsonb) ?| ARRAY[
    'password', 'password_phc', 'token', 'token_digest', 'csrf_token',
    'totp_secret', 'recovery_code', 'assertion'
  ] THEN
    RAISE EXCEPTION 'platform audit metadata contains a prohibited credential field'
      USING ERRCODE = '22023';
  END IF;
  INSERT INTO public.platform_audit_events (
    id, sequence, actor_type, actor_user_id, action, resource_type, resource_id,
    request_id, correlation_id, ip_address, user_agent, authentication_method,
    outcome, reason, metadata
  )
  VALUES (
    p_id, 1, p_actor_type, p_actor_user_id, p_action, p_resource_type, p_resource_id,
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method, p_outcome, p_reason, coalesce(p_metadata, '{}'::jsonb)
  );
  RETURN p_id;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION "app"."append_platform_audit_event"(uuid, "public"."audit_actor_type", uuid, text, text, uuid, uuid, uuid, inet, text, text, "public"."audit_outcome", text, jsonb) OWNER TO "periapsis_migrator";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."append_platform_audit_event"(uuid, "public"."audit_actor_type", uuid, text, text, uuid, uuid, uuid, inet, text, text, "public"."audit_outcome", text, jsonb) FROM PUBLIC;--> statement-breakpoint

CREATE FUNCTION "app"."verify_platform_audit_chain"()
RETURNS TABLE (
  sequence bigint,
  event_id uuid,
  expected_previous_hash character(64),
  stored_previous_hash character(64),
  stored_event_hash character(64),
  valid boolean
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  WITH ordered AS (
    SELECT
      event AS event_record,
      event.sequence,
      event.id,
      event.previous_hash,
      event.event_hash,
      lag(event.event_hash, 1, repeat('0', 64)::character(64))
        OVER (ORDER BY event.sequence) AS expected_previous_hash
    FROM public.platform_audit_events AS event
  ),
  checked AS (
    SELECT
      ordered.sequence,
      ordered.id,
      ordered.expected_previous_hash,
      ordered.previous_hash,
      ordered.event_hash,
      (
        ordered.previous_hash = ordered.expected_previous_hash
        AND ordered.event_hash = app.calculate_platform_audit_event_hash(
          ordered.event_record,
          ordered.expected_previous_hash
        )
      ) IS TRUE AS valid
    FROM ordered
  ),
  latest_event AS (
    SELECT * FROM checked ORDER BY sequence DESC LIMIT 1
  ),
  visible_head AS (
    SELECT last_sequence, last_event_hash
    FROM public.platform_audit_chain_head
    WHERE singleton = true
  )
  SELECT checked.sequence, checked.id, checked.expected_previous_hash,
         checked.previous_hash, checked.event_hash, checked.valid
  FROM checked
  UNION ALL
  SELECT coalesce(latest.sequence, head.last_sequence), latest.id,
         latest.expected_previous_hash, latest.previous_hash, latest.event_hash, false
  FROM visible_head AS head
  FULL JOIN latest_event AS latest ON true
  WHERE NOT (
    (
      latest.sequence IS NULL
      AND head.last_sequence = 0
      AND head.last_event_hash = repeat('0', 64)::character(64)
    )
    OR (
      latest.sequence IS NOT NULL
      AND head.last_sequence = latest.sequence
      AND head.last_event_hash = latest.event_hash
    )
  )
  UNION ALL
  SELECT latest.sequence, latest.id, latest.expected_previous_hash,
         latest.previous_hash, latest.event_hash, false
  FROM latest_event AS latest
  WHERE NOT EXISTS (SELECT 1 FROM visible_head)
  UNION ALL
  SELECT 0, NULL::uuid, NULL::character(64), NULL::character(64),
         NULL::character(64), false
  WHERE NOT EXISTS (SELECT 1 FROM visible_head)
    AND NOT EXISTS (SELECT 1 FROM latest_event)
  ORDER BY sequence;
$function$;--> statement-breakpoint

ALTER FUNCTION "app"."verify_platform_audit_chain"() OWNER TO "periapsis_migrator";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."verify_platform_audit_chain"() FROM PUBLIC;
--> statement-breakpoint

CREATE FUNCTION "app"."platform_user_has_permission"(
  p_user_id uuid,
  p_permission_key text
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT EXISTS (
    SELECT 1
    FROM public.user_platform_roles AS user_role
    JOIN public.platform_role_permissions AS role_permission
      ON role_permission.role_id = user_role.role_id
    JOIN public.platform_permissions AS permission
      ON permission.id = role_permission.permission_id
    JOIN public.users AS actor ON actor.id = user_role.user_id
    WHERE user_role.user_id = p_user_id
      AND user_role.revoked_at IS NULL
      AND permission.key = p_permission_key
      AND actor.active = true
  );
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."context_user_id"()
RETURNS uuid
LANGUAGE plpgsql
STABLE
SECURITY INVOKER
SET search_path = pg_catalog
AS $function$
DECLARE
  context_user uuid;
BEGIN
  context_user := nullif(current_setting('app.user_id', true), '')::uuid;
  IF context_user IS NULL THEN
    RAISE EXCEPTION 'app.user_id context is required' USING ERRCODE = '42501';
  END IF;
  RETURN context_user;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."has_platform_permission"(p_permission_key text)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT app.platform_user_has_permission(app.context_user_id(), p_permission_key);
$function$;--> statement-breakpoint

ALTER FUNCTION "app"."platform_user_has_permission"(uuid, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."context_user_id"() OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."has_platform_permission"(text) OWNER TO "periapsis_migrator";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."platform_user_has_permission"(uuid, text) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."context_user_id"() FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."has_platform_permission"(text) FROM PUBLIC;--> statement-breakpoint

CREATE FUNCTION "app"."verify_protected_configuration"(
  p_authority_token_digest bytea,
  p_master_key_verifier bytea
)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  state_record public.platform_bootstrap_state%ROWTYPE;
BEGIN
  IF p_authority_token_digest IS NULL
     OR octet_length(p_authority_token_digest) <> 32
     OR p_master_key_verifier IS NULL
     OR octet_length(p_master_key_verifier) <> 32 THEN
    RAISE EXCEPTION 'bootstrap authority and master-key verifier must be 32 bytes'
      USING ERRCODE = '22023';
  END IF;

  SELECT * INTO STRICT state_record
  FROM public.platform_bootstrap_state
  WHERE singleton = true
  FOR UPDATE;

  IF (
    state_record.authority_token_digest IS NULL
    AND state_record.authority_configured_at IS NULL
    AND state_record.master_key_verifier IS NULL
    AND state_record.master_key_verifier_bound_at IS NULL
  ) THEN
    -- Establish both independent protected-configuration bindings in the same
    -- locked transaction. A crash or rollback cannot leave authority-only state.
    IF state_record.completed_at IS NOT NULL THEN
      RAISE EXCEPTION 'completed bootstrap has no protected configuration'
        USING ERRCODE = '55000';
    END IF;

    UPDATE public.platform_bootstrap_state
    SET authority_token_digest = p_authority_token_digest,
        authority_configured_at = transaction_timestamp(),
        master_key_verifier = p_master_key_verifier,
        master_key_verifier_bound_at = transaction_timestamp()
    WHERE singleton = true;

    RETURN true;
  END IF;

  IF state_record.authority_token_digest IS NULL
     OR state_record.authority_configured_at IS NULL
     OR state_record.master_key_verifier IS NULL
     OR state_record.master_key_verifier_bound_at IS NULL
     OR octet_length(state_record.authority_token_digest) <> 32
     OR octet_length(state_record.master_key_verifier) <> 32 THEN
    RAISE EXCEPTION 'protected configuration binding is incomplete'
      USING ERRCODE = '55000';
  END IF;

  IF state_record.authority_token_digest <> p_authority_token_digest
     OR state_record.master_key_verifier <> p_master_key_verifier THEN
    RAISE EXCEPTION 'invalid protected configuration' USING ERRCODE = '42501';
  END IF;

  RETURN state_record.completed_at IS NULL;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."reserve_platform_bootstrap"(
  p_enrollment_id uuid,
  p_authority_token_digest bytea,
  p_enrollment_token_digest bytea,
  p_enrollment_rate_key_digest bytea,
  p_canonical_email text,
  p_totp_secret_ciphertext bytea,
  p_totp_secret_nonce bytea,
  p_totp_secret_aad bytea,
  p_totp_key_version integer,
  p_expires_at timestamp with time zone,
  p_max_attempts integer,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  state_record public.platform_bootstrap_state%ROWTYPE;
BEGIN
  IF octet_length(p_authority_token_digest) <> 32
     OR octet_length(p_enrollment_token_digest) <> 32
     OR octet_length(p_enrollment_rate_key_digest) <> 32 THEN
    RAISE EXCEPTION 'bootstrap token digests must be SHA-256' USING ERRCODE = '22023';
  END IF;
  IF p_canonical_email IS DISTINCT FROM lower(btrim(p_canonical_email))
     OR position('@' in p_canonical_email) <= 1
     OR char_length(p_canonical_email) > 320
     OR p_canonical_email ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION 'bootstrap email must be canonical' USING ERRCODE = '22023';
  END IF;
  IF octet_length(p_totp_secret_ciphertext) <= 16
     OR octet_length(p_totp_secret_nonce) < 12
     OR p_totp_key_version <= 0 THEN
    RAISE EXCEPTION 'invalid bootstrap TOTP encryption parameters'
      USING ERRCODE = '22023';
  END IF;
  IF p_totp_secret_aad IS DISTINCT FROM convert_to(
    'bootstrap_enrollment:' || p_enrollment_id::text || ':email:' || p_canonical_email,
    'UTF8'
  ) THEN
    RAISE EXCEPTION 'bootstrap TOTP AAD must bind enrollment and email'
      USING ERRCODE = '22023';
  END IF;
  IF p_expires_at <= transaction_timestamp()
     OR p_expires_at > transaction_timestamp() + interval '15 minutes' THEN
    RAISE EXCEPTION 'bootstrap enrollment expiry must be within 15 minutes'
      USING ERRCODE = '22023';
  END IF;
  IF p_max_attempts NOT BETWEEN 1 AND 10 THEN
    RAISE EXCEPTION 'bootstrap proof max attempts must be between 1 and 10'
      USING ERRCODE = '22023';
  END IF;

  SELECT * INTO STRICT state_record
  FROM public.platform_bootstrap_state
  WHERE singleton = true
  FOR UPDATE;

  IF state_record.authority_token_digest IS NULL
     OR state_record.authority_token_digest <> p_authority_token_digest THEN
    RAISE EXCEPTION 'invalid bootstrap authority' USING ERRCODE = '42501';
  END IF;
  IF state_record.completed_at IS NOT NULL THEN
    RAISE EXCEPTION 'platform bootstrap is already complete' USING ERRCODE = '55000';
  END IF;
  IF state_record.master_key_verifier IS NULL THEN
    RAISE EXCEPTION 'master-key verifier must be bound before bootstrap enrollment'
      USING ERRCODE = '55000';
  END IF;

  UPDATE public.platform_bootstrap_enrollments
  SET invalidated_at = transaction_timestamp()
  WHERE consumed_at IS NULL
    AND invalidated_at IS NULL
    AND expires_at <= transaction_timestamp();

  IF EXISTS (
    SELECT 1 FROM public.platform_bootstrap_enrollments
    WHERE consumed_at IS NULL AND invalidated_at IS NULL
  ) THEN
    RAISE EXCEPTION 'an active bootstrap enrollment already exists' USING ERRCODE = '55000';
  END IF;

  INSERT INTO public.platform_bootstrap_enrollments (
    id, canonical_email, token_digest, enrollment_rate_key_digest,
    totp_secret_ciphertext,
    totp_secret_nonce, totp_secret_aad, totp_key_version, expires_at,
    max_attempts
  )
  VALUES (
    p_enrollment_id, p_canonical_email, p_enrollment_token_digest,
    p_enrollment_rate_key_digest,
    p_totp_secret_ciphertext, p_totp_secret_nonce, p_totp_secret_aad,
    p_totp_key_version, p_expires_at, p_max_attempts
  );

  PERFORM app.append_platform_audit_event(
    p_enrollment_id, 'system', NULL, 'platform.bootstrap.enrollment_started',
    'bootstrap_enrollment', p_enrollment_id, p_request_id, p_correlation_id,
    p_ip_address, p_user_agent, 'bootstrap_token', 'success', NULL, '{}'::jsonb
  );

  RETURN p_enrollment_id;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."get_platform_bootstrap_enrollment"(
  p_authority_token_digest bytea,
  p_enrollment_token_digest bytea
)
RETURNS TABLE (
  enrollment_id uuid,
  canonical_email text,
  totp_secret_ciphertext bytea,
  totp_secret_nonce bytea,
  totp_secret_aad bytea,
  totp_key_version integer,
  expires_at timestamp with time zone,
  attempts integer,
  max_attempts integer
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
  configured_digest bytea;
  completed_at timestamp with time zone;
BEGIN
  SELECT state.authority_token_digest, state.completed_at
    INTO configured_digest, completed_at
  FROM public.platform_bootstrap_state AS state
  WHERE state.singleton = true;
  IF configured_digest IS NULL OR configured_digest <> p_authority_token_digest THEN
    RAISE EXCEPTION 'invalid bootstrap authority' USING ERRCODE = '42501';
  END IF;
  IF completed_at IS NOT NULL THEN
    RAISE EXCEPTION 'platform bootstrap is already complete' USING ERRCODE = '55000';
  END IF;

  RETURN QUERY
  SELECT enrollment.id, enrollment.canonical_email,
         enrollment.totp_secret_ciphertext, enrollment.totp_secret_nonce,
         enrollment.totp_secret_aad, enrollment.totp_key_version,
         enrollment.expires_at, enrollment.attempts, enrollment.max_attempts
  FROM public.platform_bootstrap_enrollments AS enrollment
  WHERE enrollment.token_digest = p_enrollment_token_digest
    AND enrollment.consumed_at IS NULL
    AND enrollment.invalidated_at IS NULL
    AND enrollment.expires_at > statement_timestamp()
    AND enrollment.attempts < enrollment.max_attempts;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."confirm_platform_bootstrap"(
  p_authority_token_digest bytea,
  p_enrollment_token_digest bytea,
  p_user_id uuid,
  p_credential_id uuid,
  p_totp_credential_id uuid,
  p_final_totp_secret_ciphertext bytea,
  p_final_totp_secret_nonce bytea,
  p_final_totp_secret_aad bytea,
  p_final_totp_key_version integer,
  p_platform_role_grant_id uuid,
  p_canonical_email text,
  p_display_name text,
  p_password_phc text,
  p_password_version integer,
  p_initial_totp_counter bigint,
  p_recovery_code_ids uuid[],
  p_recovery_code_digests bytea[],
  p_recovery_code_key_version integer,
  p_session_id uuid,
  p_rotation_family_id uuid,
  p_session_token_digest bytea,
  p_csrf_secret_digest bytea,
  p_idle_expires_at timestamp with time zone,
  p_absolute_expires_at timestamp with time zone,
  p_platform_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  state_record public.platform_bootstrap_state%ROWTYPE;
  enrollment public.platform_bootstrap_enrollments%ROWTYPE;
  recovery_count integer;
BEGIN
  IF octet_length(p_authority_token_digest) <> 32
     OR octet_length(p_enrollment_token_digest) <> 32
     OR octet_length(p_session_token_digest) <> 32
     OR octet_length(p_csrf_secret_digest) <> 32 THEN
    RAISE EXCEPTION 'token and session digests must be SHA-256' USING ERRCODE = '22023';
  END IF;
  IF p_canonical_email IS DISTINCT FROM lower(btrim(p_canonical_email))
     OR position('@' in p_canonical_email) <= 1
     OR char_length(p_canonical_email) > 320
     OR p_canonical_email ~ '[[:cntrl:]]'
     OR p_display_name IS NULL OR btrim(p_display_name) = ''
     OR char_length(p_display_name) > 160
     OR p_display_name ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION 'bootstrap email must be canonical' USING ERRCODE = '22023';
  END IF;
  IF octet_length(p_final_totp_secret_ciphertext) <= 16
     OR octet_length(p_final_totp_secret_nonce) < 12
     OR p_final_totp_key_version <= 0
     OR p_final_totp_secret_aad IS DISTINCT FROM convert_to(
       'totp_credential:' || p_totp_credential_id::text || ':user:' || p_user_id::text,
       'UTF8'
     ) THEN
    RAISE EXCEPTION 'final TOTP encryption must bind credential and user identity'
      USING ERRCODE = '22023';
  END IF;
  recovery_count := coalesce(cardinality(p_recovery_code_ids), 0);
  IF recovery_count <> 10
     OR recovery_count <> coalesce(cardinality(p_recovery_code_digests), 0) THEN
    RAISE EXCEPTION 'exactly ten paired recovery codes are required' USING ERRCODE = '22023';
  END IF;
  IF EXISTS (
    SELECT 1 FROM unnest(p_recovery_code_digests) AS digest(value)
    WHERE octet_length(digest.value) <> 32
  ) THEN
    RAISE EXCEPTION 'recovery code digests must be SHA-256 HMAC values' USING ERRCODE = '22023';
  END IF;
  IF p_initial_totp_counter < 0 THEN
    RAISE EXCEPTION 'a validated TOTP counter is required' USING ERRCODE = '22023';
  END IF;
  IF p_idle_expires_at <= transaction_timestamp()
     OR p_absolute_expires_at < p_idle_expires_at THEN
    RAISE EXCEPTION 'invalid initial session expiry' USING ERRCODE = '22023';
  END IF;

  SELECT * INTO STRICT state_record
  FROM public.platform_bootstrap_state
  WHERE singleton = true
  FOR UPDATE;

  IF state_record.authority_token_digest IS NULL
     OR state_record.authority_token_digest <> p_authority_token_digest THEN
    RAISE EXCEPTION 'invalid bootstrap authority' USING ERRCODE = '42501';
  END IF;
  IF state_record.completed_at IS NOT NULL THEN
    RAISE EXCEPTION 'platform bootstrap is already complete' USING ERRCODE = '55000';
  END IF;
  IF EXISTS (SELECT 1 FROM public.user_platform_roles) THEN
    RAISE EXCEPTION 'platform role grants already exist before bootstrap'
      USING ERRCODE = '55000';
  END IF;

  SELECT * INTO STRICT enrollment
  FROM public.platform_bootstrap_enrollments
  WHERE token_digest = p_enrollment_token_digest
  FOR UPDATE;

  IF enrollment.consumed_at IS NOT NULL
     OR enrollment.invalidated_at IS NOT NULL
     OR enrollment.expires_at <= transaction_timestamp()
     OR enrollment.attempts >= enrollment.max_attempts THEN
    RAISE EXCEPTION 'bootstrap enrollment is consumed, invalidated, expired, or exhausted'
      USING ERRCODE = '55000';
  END IF;
  IF enrollment.canonical_email IS DISTINCT FROM p_canonical_email THEN
    RAISE EXCEPTION 'confirmed email does not match the bootstrap enrollment'
      USING ERRCODE = '23514';
  END IF;

  INSERT INTO public.users (id, email, display_name)
  VALUES (p_user_id, p_canonical_email, p_display_name);

  INSERT INTO public.local_break_glass_credentials (
    id, user_id, password_phc, password_algorithm, password_version
  )
  VALUES (p_credential_id, p_user_id, p_password_phc, 'argon2id', p_password_version);

  INSERT INTO public.totp_credentials (
    id, user_id, secret_ciphertext, secret_nonce, secret_aad, key_version,
    confirmed_at, last_accepted_counter
  )
  VALUES (
    p_totp_credential_id, p_user_id, p_final_totp_secret_ciphertext,
    p_final_totp_secret_nonce, p_final_totp_secret_aad,
    p_final_totp_key_version, transaction_timestamp(), p_initial_totp_counter
  );

  INSERT INTO public.recovery_codes (
    id, user_id, totp_credential_id, code_digest, key_version
  )
  SELECT code.id, p_user_id, p_totp_credential_id, code.digest, p_recovery_code_key_version
  FROM unnest(p_recovery_code_ids, p_recovery_code_digests) AS code(id, digest);

  INSERT INTO public.user_platform_roles (
    id, user_id, role_id, granted_by_user_id
  )
  VALUES (
    p_platform_role_grant_id, p_user_id,
    '019c0000-0000-7000-8000-000000000101', p_user_id
  );

  INSERT INTO public.auth_sessions (
    id, user_id, rotation_family_id, token_digest, csrf_secret_digest,
    authentication_method, mfa_satisfied_at, idle_expires_at, absolute_expires_at
  )
  VALUES (
    p_session_id, p_user_id, p_rotation_family_id, p_session_token_digest,
    p_csrf_secret_digest, 'bootstrap_totp', transaction_timestamp(),
    p_idle_expires_at, p_absolute_expires_at
  );

  UPDATE public.platform_bootstrap_enrollments
  SET consumed_at = transaction_timestamp(), consumed_by_user_id = p_user_id
  WHERE id = enrollment.id;

  -- The enrollment-scoped proof meter is bound at reservation time. A valid
  -- confirmation clears only that key; the shared source-network meter is not
  -- stored here and cannot be erased by bootstrap success.
  DELETE FROM public.auth_rate_limits
  WHERE scope = 'bootstrap_totp'
    AND key_digest = enrollment.enrollment_rate_key_digest;

  UPDATE public.platform_bootstrap_state
  SET completed_at = transaction_timestamp(), completed_by_user_id = p_user_id,
      enrollment_id = enrollment.id
  WHERE singleton = true;

  PERFORM app.append_platform_audit_event(
    p_platform_audit_event_id, 'user', p_user_id, 'platform.bootstrap.confirmed',
    'user', p_user_id, p_request_id, p_correlation_id,
    p_ip_address, p_user_agent, 'bootstrap_totp', 'success', NULL,
    jsonb_build_object('credential_kind', 'local_break_glass')
  );

  RETURN p_session_id;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION "app"."verify_protected_configuration"(bytea, bytea) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."reserve_platform_bootstrap"(uuid, bytea, bytea, bytea, text, bytea, bytea, bytea, integer, timestamp with time zone, integer, uuid, uuid, inet, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."get_platform_bootstrap_enrollment"(bytea, bytea) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."confirm_platform_bootstrap"(bytea, bytea, uuid, uuid, uuid, bytea, bytea, bytea, integer, uuid, text, text, text, integer, bigint, uuid[], bytea[], integer, uuid, uuid, bytea, bytea, timestamp with time zone, timestamp with time zone, uuid, uuid, uuid, inet, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."verify_protected_configuration"(bytea, bytea) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."reserve_platform_bootstrap"(uuid, bytea, bytea, bytea, text, bytea, bytea, bytea, integer, timestamp with time zone, integer, uuid, uuid, inet, text) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."get_platform_bootstrap_enrollment"(bytea, bytea) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."confirm_platform_bootstrap"(bytea, bytea, uuid, uuid, uuid, bytea, bytea, bytea, integer, uuid, text, text, text, integer, bigint, uuid[], bytea[], integer, uuid, uuid, bytea, bytea, timestamp with time zone, timestamp with time zone, uuid, uuid, uuid, inet, text) FROM PUBLIC;
--> statement-breakpoint

CREATE FUNCTION "app"."get_local_break_glass_credential"(p_email text)
RETURNS TABLE (
  user_id uuid,
  password_phc text,
  password_algorithm text,
  password_version integer,
  must_rotate boolean
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT credential.user_id, credential.password_phc,
         credential.password_algorithm, credential.password_version,
         credential.must_rotate
  FROM public.users AS identity
  JOIN public.local_break_glass_credentials AS credential
    ON credential.user_id = identity.id
  WHERE identity.email = lower(btrim(p_email))
    AND identity.active = true
    AND credential.disabled_at IS NULL;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."get_totp_credential"(p_user_id uuid)
RETURNS TABLE (
  credential_id uuid,
  secret_ciphertext bytea,
  secret_nonce bytea,
  secret_aad bytea,
  key_version integer,
  encryption_algorithm text,
  otp_algorithm text,
  digits integer,
  period_seconds integer,
  last_accepted_counter bigint
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT credential.id, credential.secret_ciphertext, credential.secret_nonce,
         credential.secret_aad, credential.key_version,
         credential.encryption_algorithm, credential.otp_algorithm,
         credential.digits, credential.period_seconds,
         credential.last_accepted_counter
  FROM public.totp_credentials AS credential
  JOIN public.users AS identity ON identity.id = credential.user_id
  WHERE credential.user_id = p_user_id
    AND credential.confirmed_at IS NOT NULL
    AND credential.disabled_at IS NULL
    AND identity.active = true;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."advance_totp_counter"(p_user_id uuid, p_counter bigint)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_counter < 0 THEN
    RAISE EXCEPTION 'TOTP counter must be nonnegative' USING ERRCODE = '22023';
  END IF;

  UPDATE public.totp_credentials
  SET last_accepted_counter = p_counter,
      updated_at = transaction_timestamp()
  WHERE user_id = p_user_id
    AND confirmed_at IS NOT NULL
    AND disabled_at IS NULL
    AND (last_accepted_counter IS NULL OR last_accepted_counter < p_counter);

  RETURN FOUND;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."consume_recovery_code"(p_user_id uuid, p_code_digest bytea)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  consumed_id uuid;
BEGIN
  IF octet_length(p_code_digest) <> 32 THEN
    RAISE EXCEPTION 'recovery code digest must be a SHA-256 HMAC value' USING ERRCODE = '22023';
  END IF;

  UPDATE public.recovery_codes
  SET consumed_at = transaction_timestamp()
  WHERE user_id = p_user_id
    AND code_digest = p_code_digest
    AND consumed_at IS NULL
  RETURNING id INTO consumed_id;

  RETURN consumed_id;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."create_auth_challenge"(
  p_challenge_id uuid,
  p_user_id uuid,
  p_challenge_rate_key_digest bytea,
  p_mfa_rate_key_digest bytea,
  p_login_account_rate_key_digest bytea,
  p_token_digest bytea,
  p_purpose "public"."auth_challenge_purpose",
  p_expires_at timestamp with time zone,
  p_max_attempts integer,
  p_platform_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  replaced_unconsumed_challenges integer := 0;
BEGIN
  IF octet_length(p_token_digest) <> 32
     OR octet_length(p_challenge_rate_key_digest) <> 32
     OR octet_length(p_mfa_rate_key_digest) <> 32
     OR octet_length(p_login_account_rate_key_digest) <> 32
     OR p_expires_at <= transaction_timestamp()
     OR p_expires_at > transaction_timestamp() + interval '15 minutes'
     OR p_max_attempts NOT BETWEEN 1 AND 20 THEN
    RAISE EXCEPTION 'invalid authentication challenge parameters' USING ERRCODE = '22023';
  END IF;

  IF EXISTS (
    SELECT 1 FROM public.auth_rate_limits AS rate
    WHERE rate.scope = 'mfa_challenge'
      AND rate.key_digest = p_mfa_rate_key_digest
      AND rate.blocked_until > transaction_timestamp()
  ) THEN
    RAISE EXCEPTION 'MFA account rate limit is blocked' USING ERRCODE = '53300';
  END IF;

  -- Serialize challenge issuance per principal and re-check every credential
  -- state that made the password proof eligible. A password credential or
  -- TOTP factor revoked concurrently with issuance must win before a new
  -- challenge can become usable.
  PERFORM 1
  FROM public.users AS identity
  JOIN public.local_break_glass_credentials AS local_credential
    ON local_credential.user_id = identity.id
  JOIN public.totp_credentials AS totp_credential
    ON totp_credential.user_id = identity.id
  WHERE identity.id = p_user_id
    AND identity.active = true
    AND local_credential.disabled_at IS NULL
    AND totp_credential.confirmed_at IS NOT NULL
    AND totp_credential.disabled_at IS NULL
  FOR UPDATE OF identity
  FOR SHARE OF local_credential, totp_credential;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'authentication challenge requires active credentials'
      USING ERRCODE = '42501';
  END IF;

  IF p_purpose = 'mfa_login' THEN
    UPDATE public.auth_challenges
    SET consumed_at = transaction_timestamp()
    WHERE user_id = p_user_id
      AND purpose = p_purpose
      AND consumed_at IS NULL;
    GET DIAGNOSTICS replaced_unconsumed_challenges = ROW_COUNT;
  END IF;

  INSERT INTO public.auth_challenges (
    id, user_id, challenge_rate_key_digest, mfa_rate_key_digest,
    login_account_rate_key_digest,
    token_digest, purpose, expires_at, max_attempts
  ) VALUES (
    p_challenge_id, p_user_id, p_challenge_rate_key_digest,
    p_mfa_rate_key_digest,
    p_login_account_rate_key_digest, p_token_digest, p_purpose,
    p_expires_at, p_max_attempts
  );
  PERFORM app.append_platform_audit_event(
    p_platform_audit_event_id, 'system', NULL,
    'authentication.mfa_challenge.created', 'authentication_challenge',
    p_challenge_id, p_request_id, p_correlation_id, p_ip_address,
    p_user_agent, p_authentication_method, 'success', NULL,
    jsonb_build_object(
      'user_id', p_user_id,
      'replaced_unconsumed_challenge', replaced_unconsumed_challenges > 0
    )
  );
  RETURN p_challenge_id;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."record_auth_challenge_failure"(
  p_token_digest bytea,
  p_purpose "public"."auth_challenge_purpose"
)
RETURNS TABLE (attempts integer, exhausted boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  RETURN QUERY
  UPDATE public.auth_challenges AS challenge
  SET attempts = least(challenge.attempts + 1, challenge.max_attempts),
      last_attempt_at = transaction_timestamp(),
      consumed_at = CASE
        WHEN challenge.attempts + 1 >= challenge.max_attempts
          THEN transaction_timestamp()
        ELSE challenge.consumed_at
      END
  WHERE challenge.token_digest = p_token_digest
    AND challenge.purpose = p_purpose
    AND challenge.consumed_at IS NULL
    AND challenge.expires_at > transaction_timestamp()
  RETURNING challenge.attempts, challenge.attempts >= challenge.max_attempts;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."get_auth_challenge"(
  p_token_digest bytea,
  p_purpose "public"."auth_challenge_purpose"
)
RETURNS TABLE (
  challenge_id uuid,
  user_id uuid,
  purpose "public"."auth_challenge_purpose",
  attempts integer,
  max_attempts integer,
  expires_at timestamp with time zone
)
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
  SELECT challenge.id, challenge.user_id, challenge.purpose,
         challenge.attempts, challenge.max_attempts, challenge.expires_at
  FROM public.auth_challenges AS challenge
  WHERE challenge.token_digest = p_token_digest
    AND challenge.purpose = p_purpose
    AND challenge.consumed_at IS NULL
    AND challenge.expires_at > statement_timestamp()
    AND challenge.attempts < challenge.max_attempts;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."consume_auth_challenge"(
  p_token_digest bytea,
  p_purpose "public"."auth_challenge_purpose"
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  challenge_user_id uuid;
BEGIN
  IF octet_length(p_token_digest) <> 32 THEN
    RETURN NULL;
  END IF;

  UPDATE public.auth_challenges
  SET consumed_at = transaction_timestamp(),
      last_attempt_at = transaction_timestamp()
  WHERE token_digest = p_token_digest
    AND purpose = p_purpose
    AND consumed_at IS NULL
    AND expires_at > transaction_timestamp()
    AND attempts < max_attempts
  RETURNING user_id INTO challenge_user_id;

  RETURN challenge_user_id;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."session_tenant_allowed"(p_user_id uuid, p_tenant_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
  SELECT p_tenant_id IS NULL OR EXISTS (
    SELECT 1
    FROM public.tenant_memberships AS membership
    JOIN public.tenants AS tenant ON tenant.id = membership.tenant_id
    WHERE membership.user_id = p_user_id
      AND membership.tenant_id = p_tenant_id
      AND membership.status = 'active'
      AND tenant.status = 'active'
  );
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."create_auth_session"(
  p_session_id uuid,
  p_user_id uuid,
  p_rotation_family_id uuid,
  p_active_tenant_id uuid,
  p_token_digest bytea,
  p_csrf_secret_digest bytea,
  p_authentication_method text,
  p_mfa_satisfied_at timestamp with time zone,
  p_idle_expires_at timestamp with time zone,
  p_absolute_expires_at timestamp with time zone
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF octet_length(p_token_digest) <> 32 OR octet_length(p_csrf_secret_digest) <> 32
     OR btrim(p_authentication_method) = ''
     OR p_authentication_method NOT IN ('totp', 'recovery_code')
     OR p_idle_expires_at <= transaction_timestamp()
     OR p_absolute_expires_at < p_idle_expires_at THEN
    RAISE EXCEPTION 'invalid authentication session parameters' USING ERRCODE = '22023';
  END IF;
  IF NOT app.session_tenant_allowed(p_user_id, p_active_tenant_id) THEN
    RAISE EXCEPTION 'session tenant requires an active user membership' USING ERRCODE = '42501';
  END IF;

  INSERT INTO public.auth_sessions (
    id, user_id, rotation_family_id, active_tenant_id, token_digest,
    csrf_secret_digest, authentication_method, mfa_satisfied_at,
    idle_expires_at, absolute_expires_at
  ) VALUES (
    p_session_id, p_user_id, p_rotation_family_id, p_active_tenant_id,
    p_token_digest, p_csrf_secret_digest, p_authentication_method,
    p_mfa_satisfied_at, p_idle_expires_at, p_absolute_expires_at
  );
  RETURN p_session_id;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."get_auth_session"(p_token_digest bytea)
RETURNS TABLE (
  session_id uuid,
  user_id uuid,
  rotation_family_id uuid,
  email text,
  display_name text,
  active_tenant_id uuid,
  csrf_secret_digest bytea,
  authentication_method text,
  mfa_satisfied_at timestamp with time zone,
  created_at timestamp with time zone,
  last_seen_at timestamp with time zone,
  idle_expires_at timestamp with time zone,
  absolute_expires_at timestamp with time zone,
  platform_permissions text[]
)
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT session.id, session.user_id, session.rotation_family_id,
         identity.email, identity.display_name, session.active_tenant_id,
         session.csrf_secret_digest, session.authentication_method,
         session.mfa_satisfied_at, session.created_at, session.last_seen_at,
         session.idle_expires_at,
         session.absolute_expires_at,
         ARRAY(
           SELECT DISTINCT permission.key
           FROM public.user_platform_roles AS user_role
           JOIN public.platform_role_permissions AS role_permission
             ON role_permission.role_id = user_role.role_id
           JOIN public.platform_permissions AS permission
             ON permission.id = role_permission.permission_id
           WHERE user_role.user_id = session.user_id
             AND user_role.revoked_at IS NULL
           ORDER BY permission.key
         )
  FROM public.auth_sessions AS session
  JOIN public.users AS identity ON identity.id = session.user_id
  WHERE session.token_digest = p_token_digest
    AND octet_length(p_token_digest) = 32
    AND session.revoked_at IS NULL
    AND session.idle_expires_at > statement_timestamp()
    AND session.absolute_expires_at > statement_timestamp()
    AND identity.active = true
    AND app.session_tenant_allowed(session.user_id, session.active_tenant_id);
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."touch_auth_session"(
  p_token_digest bytea,
  p_new_idle_expires_at timestamp with time zone
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  UPDATE public.auth_sessions
  SET last_seen_at = greatest(last_seen_at, transaction_timestamp()),
      idle_expires_at = least(
        absolute_expires_at,
        greatest(idle_expires_at, p_new_idle_expires_at)
      )
  WHERE token_digest = p_token_digest
    AND revoked_at IS NULL
    AND idle_expires_at > transaction_timestamp()
    AND absolute_expires_at > transaction_timestamp()
    AND p_new_idle_expires_at > transaction_timestamp();
  RETURN FOUND;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."revoke_auth_session"(p_token_digest bytea, p_reason text)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF btrim(p_reason) = '' THEN
    RAISE EXCEPTION 'session revocation reason is required' USING ERRCODE = '22023';
  END IF;
  UPDATE public.auth_sessions
  SET revoked_at = transaction_timestamp(), revoke_reason = p_reason
  WHERE token_digest = p_token_digest AND revoked_at IS NULL;
  RETURN FOUND;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."rotate_auth_session"(
  p_old_token_digest bytea,
  p_new_session_id uuid,
  p_new_token_digest bytea,
  p_new_csrf_secret_digest bytea,
  p_new_idle_expires_at timestamp with time zone,
  p_new_absolute_expires_at timestamp with time zone,
  p_platform_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  old_session public.auth_sessions%ROWTYPE;
BEGIN
  IF octet_length(p_old_token_digest) <> 32
     OR octet_length(p_new_token_digest) <> 32
     OR octet_length(p_new_csrf_secret_digest) <> 32 THEN
    RAISE EXCEPTION 'session digests must be SHA-256' USING ERRCODE = '22023';
  END IF;

  SELECT * INTO old_session
  FROM public.auth_sessions
  WHERE token_digest = p_old_token_digest
    AND revoked_at IS NULL
    AND idle_expires_at > transaction_timestamp()
    AND absolute_expires_at > transaction_timestamp()
  FOR UPDATE;

  IF NOT FOUND THEN
    RETURN NULL;
  END IF;
  IF p_new_idle_expires_at <= transaction_timestamp()
     OR p_new_absolute_expires_at < p_new_idle_expires_at
     OR p_new_absolute_expires_at > old_session.absolute_expires_at THEN
    RAISE EXCEPTION 'rotated session cannot extend the original absolute expiry'
      USING ERRCODE = '22023';
  END IF;
  IF NOT app.session_tenant_allowed(old_session.user_id, old_session.active_tenant_id) THEN
    RAISE EXCEPTION 'session tenant membership is no longer active' USING ERRCODE = '42501';
  END IF;

  UPDATE public.auth_sessions
  SET revoked_at = transaction_timestamp(), revoke_reason = 'rotated'
  WHERE id = old_session.id;

  INSERT INTO public.auth_sessions (
    id, user_id, rotation_family_id, active_tenant_id, token_digest,
    csrf_secret_digest, authentication_method, mfa_satisfied_at,
    idle_expires_at, absolute_expires_at, rotated_from_session_id
  ) VALUES (
    p_new_session_id, old_session.user_id, old_session.rotation_family_id,
    old_session.active_tenant_id, p_new_token_digest,
    p_new_csrf_secret_digest, old_session.authentication_method,
    old_session.mfa_satisfied_at, p_new_idle_expires_at,
    p_new_absolute_expires_at, old_session.id
  );

  PERFORM app.append_platform_audit_event(
    p_platform_audit_event_id, 'user', old_session.user_id,
    'authentication.session.rotated', 'session', p_new_session_id,
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    old_session.authentication_method, 'success', NULL,
    jsonb_build_object('rotated_from_session_id', old_session.id)
  );
  RETURN p_new_session_id;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."complete_mfa_login"(
  p_challenge_token_digest bytea,
  p_authentication_method text,
  p_totp_counter bigint,
  p_recovery_code_digest bytea,
  p_session_id uuid,
  p_rotation_family_id uuid,
  p_active_tenant_id uuid,
  p_session_token_digest bytea,
  p_csrf_secret_digest bytea,
  p_idle_expires_at timestamp with time zone,
  p_absolute_expires_at timestamp with time zone,
  p_failure_scopes "public"."auth_rate_limit_scope"[],
  p_failure_key_digests bytea[],
  p_failure_window_seconds integer[],
  p_failure_max_attempts integer[],
  p_failure_block_seconds integer[],
  p_clear_scopes "public"."auth_rate_limit_scope"[],
  p_clear_key_digests bytea[],
  p_platform_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text
)
RETURNS TABLE (
  session_id uuid,
  failure_recorded boolean,
  blocked_until timestamp with time zone
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  challenge public.auth_challenges%ROWTYPE;
  expected_clear_count integer;
  failure_blocked_until timestamp with time zone;
BEGIN
  IF p_authentication_method NOT IN ('totp', 'recovery_code') THEN
    RAISE EXCEPTION 'MFA completion method must be totp or recovery_code'
      USING ERRCODE = '22023';
  END IF;
  IF (p_authentication_method = 'totp'
      AND (p_totp_counter IS NULL OR p_recovery_code_digest IS NOT NULL))
     OR (p_authentication_method = 'recovery_code'
      AND (p_totp_counter IS NOT NULL OR octet_length(p_recovery_code_digest) <> 32)) THEN
    RAISE EXCEPTION 'MFA proof does not match the authentication method'
      USING ERRCODE = '22023';
  END IF;

  SELECT * INTO challenge
  FROM public.auth_challenges
  WHERE token_digest = p_challenge_token_digest
    AND purpose = 'mfa_login'
    AND consumed_at IS NULL
    AND expires_at > transaction_timestamp()
    AND attempts < max_attempts
  FOR UPDATE;

  IF NOT FOUND THEN
    RETURN QUERY SELECT NULL::uuid, false, NULL::timestamp with time zone;
    RETURN;
  END IF;

  expected_clear_count := CASE
    WHEN challenge.challenge_rate_key_digest = challenge.mfa_rate_key_digest THEN 1
    ELSE 2
  END;
  IF coalesce(cardinality(p_clear_scopes), 0) <> expected_clear_count
     OR array_ndims(p_clear_scopes) <> 1
     OR array_ndims(p_clear_key_digests) <> 1
     OR cardinality(p_clear_key_digests) IS DISTINCT FROM expected_clear_count
     OR EXISTS (
       SELECT 1
       FROM unnest(p_clear_scopes, p_clear_key_digests) AS clear_key(scope, key_digest)
       WHERE clear_key.scope IS DISTINCT FROM 'mfa_challenge'::public.auth_rate_limit_scope
          OR octet_length(clear_key.key_digest) <> 32
          OR clear_key.key_digest NOT IN (
            challenge.challenge_rate_key_digest,
            challenge.mfa_rate_key_digest
          )
     )
     OR EXISTS (
       SELECT 1
       FROM unnest(p_clear_scopes, p_clear_key_digests) AS clear_key(scope, key_digest)
       GROUP BY clear_key.scope, clear_key.key_digest
       HAVING count(*) > 1
     )
     OR NOT EXISTS (
       SELECT 1 FROM unnest(p_clear_key_digests) AS clear_key(key_digest)
       WHERE clear_key.key_digest = challenge.challenge_rate_key_digest
     )
     OR NOT EXISTS (
       SELECT 1 FROM unnest(p_clear_key_digests) AS clear_key(key_digest)
       WHERE clear_key.key_digest = challenge.mfa_rate_key_digest
     ) THEN
    RAISE EXCEPTION 'MFA success clear keys do not match the locked challenge'
      USING ERRCODE = '22023';
  END IF;

  -- The challenge is only a short-lived continuation of the verified local
  -- password flow. Re-check and lock the identity, password credential, and
  -- factor so deactivation/revocation cannot race session creation.
  PERFORM 1
  FROM public.users AS identity
  JOIN public.local_break_glass_credentials AS local_credential
    ON local_credential.user_id = identity.id
  JOIN public.totp_credentials AS totp_credential
    ON totp_credential.user_id = identity.id
  WHERE identity.id = challenge.user_id
    AND identity.active = true
    AND local_credential.disabled_at IS NULL
    AND totp_credential.confirmed_at IS NOT NULL
    AND totp_credential.disabled_at IS NULL
  FOR SHARE OF identity, local_credential, totp_credential;
  IF NOT FOUND THEN
    SELECT failure.blocked_until INTO failure_blocked_until
    FROM app.record_mfa_challenge_failure(
      p_challenge_token_digest, p_failure_scopes, p_failure_key_digests,
      p_failure_window_seconds, p_failure_max_attempts, p_failure_block_seconds,
      p_platform_audit_event_id, 'invalid_mfa_proof', p_request_id,
      p_correlation_id, p_ip_address, p_user_agent, p_authentication_method
    ) AS failure;
    RETURN QUERY SELECT NULL::uuid, true, failure_blocked_until;
    RETURN;
  END IF;

  IF p_authentication_method = 'totp' THEN
    UPDATE public.totp_credentials
    SET last_accepted_counter = p_totp_counter,
        updated_at = transaction_timestamp()
    WHERE user_id = challenge.user_id
      AND confirmed_at IS NOT NULL
      AND disabled_at IS NULL
       AND (last_accepted_counter IS NULL OR last_accepted_counter < p_totp_counter);
    IF NOT FOUND THEN
      SELECT failure.blocked_until INTO failure_blocked_until
      FROM app.record_mfa_challenge_failure(
        p_challenge_token_digest, p_failure_scopes, p_failure_key_digests,
        p_failure_window_seconds, p_failure_max_attempts, p_failure_block_seconds,
        p_platform_audit_event_id, 'invalid_mfa_proof', p_request_id,
        p_correlation_id, p_ip_address, p_user_agent, p_authentication_method
      ) AS failure;
      RETURN QUERY SELECT NULL::uuid, true, failure_blocked_until;
      RETURN;
    END IF;
  ELSE
    UPDATE public.recovery_codes AS recovery
    SET consumed_at = transaction_timestamp()
    FROM public.totp_credentials AS credential,
         public.users AS identity
    WHERE recovery.user_id = challenge.user_id
      AND recovery.code_digest = p_recovery_code_digest
      AND recovery.consumed_at IS NULL
      AND credential.id = recovery.totp_credential_id
      AND credential.user_id = recovery.user_id
      AND credential.confirmed_at IS NOT NULL
      AND credential.disabled_at IS NULL
      AND identity.id = recovery.user_id
      AND identity.active = true;
    IF NOT FOUND THEN
      SELECT failure.blocked_until INTO failure_blocked_until
      FROM app.record_mfa_challenge_failure(
        p_challenge_token_digest, p_failure_scopes, p_failure_key_digests,
        p_failure_window_seconds, p_failure_max_attempts, p_failure_block_seconds,
        p_platform_audit_event_id, 'invalid_mfa_proof', p_request_id,
        p_correlation_id, p_ip_address, p_user_agent, p_authentication_method
      ) AS failure;
      RETURN QUERY SELECT NULL::uuid, true, failure_blocked_until;
      RETURN;
    END IF;
  END IF;

  UPDATE public.auth_challenges
  SET consumed_at = transaction_timestamp(), last_attempt_at = transaction_timestamp()
  WHERE id = challenge.id;

  -- Clear only the three proof-bound meters persisted on the locked challenge:
  -- raw challenge-HMAC, MFA user, and password-login account. Shared network
  -- meters are neither persisted here nor accepted in p_clear_key_digests.
  DELETE FROM public.auth_rate_limits
  WHERE (scope = 'mfa_challenge' AND key_digest IN (
           challenge.challenge_rate_key_digest,
           challenge.mfa_rate_key_digest
         ))
     OR (scope = 'local_login'
         AND key_digest = challenge.login_account_rate_key_digest);

  PERFORM app.create_auth_session(
    p_session_id, challenge.user_id, p_rotation_family_id,
    p_active_tenant_id, p_session_token_digest, p_csrf_secret_digest,
    p_authentication_method, transaction_timestamp(), p_idle_expires_at,
    p_absolute_expires_at
  );

  PERFORM app.append_platform_audit_event(
    p_platform_audit_event_id, 'user', challenge.user_id,
    'authentication.login.succeeded', 'session', p_session_id,
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method, 'success', NULL,
    jsonb_build_object('authentication_method', p_authentication_method)
  );

  RETURN QUERY SELECT p_session_id, false, NULL::timestamp with time zone;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."list_user_sessions"(
  p_current_session_id uuid,
  p_after_session_id uuid,
  p_limit integer
)
RETURNS TABLE (
  session_id uuid,
  current boolean,
  active_tenant_id uuid,
  authentication_method text,
  mfa_satisfied_at timestamp with time zone,
  last_seen_at timestamp with time zone,
  idle_expires_at timestamp with time zone,
  absolute_expires_at timestamp with time zone,
  revoked_at timestamp with time zone,
  revoke_reason text,
  created_at timestamp with time zone
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor_id uuid;
  cursor_created_at timestamp with time zone;
  cursor_is_current boolean;
BEGIN
  IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 101 THEN
    RAISE EXCEPTION 'session page limit must be between 1 and 101'
      USING ERRCODE = '22023';
  END IF;

  actor_id := app.context_user_id();
  IF NOT EXISTS (
    SELECT 1
    FROM public.auth_sessions AS current_session
    WHERE current_session.id = p_current_session_id
      AND current_session.user_id = actor_id
      AND current_session.revoked_at IS NULL
      AND current_session.idle_expires_at > statement_timestamp()
      AND current_session.absolute_expires_at > statement_timestamp()
  ) THEN
    RAISE EXCEPTION 'a live current session is required' USING ERRCODE = '42501';
  END IF;

  IF p_after_session_id IS NOT NULL THEN
    SELECT cursor_session.created_at,
           cursor_session.id = p_current_session_id
      INTO cursor_created_at, cursor_is_current
    FROM public.auth_sessions AS cursor_session
    WHERE cursor_session.id = p_after_session_id
      AND cursor_session.user_id = actor_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'invalid session page cursor'
        USING ERRCODE = '22023';
    END IF;
  END IF;

  -- The authenticated session is always the first row of the first page. All
  -- following pages exclude it and use the immutable (created_at, id) tuple as
  -- a descending keyset, so every historical or still-live session remains
  -- reachable without duplicates.
  RETURN QUERY
  SELECT session.id, session.id = p_current_session_id,
         session.active_tenant_id, session.authentication_method,
         session.mfa_satisfied_at, session.last_seen_at,
         session.idle_expires_at, session.absolute_expires_at,
         session.revoked_at, session.revoke_reason, session.created_at
  FROM public.auth_sessions AS session
  WHERE session.user_id = actor_id
    AND (
      p_after_session_id IS NULL
      OR (
        cursor_is_current
        AND session.id <> p_current_session_id
      )
      OR (
        NOT cursor_is_current
        AND session.id <> p_current_session_id
        AND (session.created_at, session.id)
          < (cursor_created_at, p_after_session_id)
      )
    )
  ORDER BY (session.id = p_current_session_id) DESC,
           session.created_at DESC,
           session.id DESC
  LIMIT p_limit;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."list_user_tenant_memberships"(
  p_after_membership_id uuid,
  p_limit integer
)
RETURNS TABLE (
  membership_id uuid,
  tenant_id uuid,
  tenant_slug text,
  tenant_name text,
  membership_role "public"."membership_role",
  membership_status "public"."membership_status",
  tenant_status "public"."tenant_status",
  timezone text,
  locale text,
  created_at timestamp with time zone,
  updated_at timestamp with time zone
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor_id uuid;
BEGIN
  IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 101 THEN
    RAISE EXCEPTION 'membership page limit must be between 1 and 101'
      USING ERRCODE = '22023';
  END IF;

  actor_id := app.context_user_id();
  IF p_after_membership_id IS NOT NULL
     AND NOT EXISTS (
       SELECT 1
       FROM public.tenant_memberships AS cursor_membership
       WHERE cursor_membership.id = p_after_membership_id
         AND cursor_membership.user_id = actor_id
     ) THEN
    RAISE EXCEPTION 'invalid membership page cursor'
      USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  SELECT membership.id, membership.tenant_id, tenant.slug, tenant.name,
         membership.role, membership.status, tenant.status, tenant.timezone,
         tenant.locale, membership.created_at, membership.updated_at
  FROM public.tenant_memberships AS membership
  JOIN public.tenants AS tenant ON tenant.id = membership.tenant_id
  WHERE membership.user_id = actor_id
    AND membership.status = 'active'
    AND tenant.status = 'active'
    AND (
      p_after_membership_id IS NULL
      OR membership.id > p_after_membership_id
    )
  ORDER BY membership.id
  LIMIT p_limit;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."switch_auth_session_tenant"(
  p_session_token_digest bytea,
  p_tenant_id uuid
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor_id uuid;
BEGIN
  actor_id := app.context_user_id();
  IF NOT app.session_tenant_allowed(actor_id, p_tenant_id) THEN
    RAISE EXCEPTION 'active tenant requires an active membership' USING ERRCODE = '42501';
  END IF;
  UPDATE public.auth_sessions
  SET active_tenant_id = p_tenant_id,
      last_seen_at = transaction_timestamp()
  WHERE token_digest = p_session_token_digest
    AND user_id = actor_id
    AND active_tenant_id IS DISTINCT FROM p_tenant_id
    AND revoked_at IS NULL
    AND idle_expires_at > transaction_timestamp()
    AND absolute_expires_at > transaction_timestamp();
  RETURN FOUND;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."revoke_user_session"(
  p_session_id uuid,
  p_reason text,
  p_platform_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  session_record public.auth_sessions%ROWTYPE;
  actor_id uuid;
  audit_action text;
BEGIN
  IF p_reason IS NULL OR p_reason !~ '^[a-z][a-z0-9_]{0,63}$' THEN
    RAISE EXCEPTION 'session revocation reason is required' USING ERRCODE = '22023';
  END IF;
  actor_id := app.context_user_id();
  SELECT * INTO session_record
  FROM public.auth_sessions
  WHERE id = p_session_id AND user_id = actor_id AND revoked_at IS NULL
  FOR UPDATE;
  IF NOT FOUND THEN
    RETURN false;
  END IF;

  UPDATE public.auth_sessions
  SET revoked_at = transaction_timestamp(), revoke_reason = p_reason
  WHERE id = session_record.id;

  audit_action := CASE p_reason
    WHEN 'user_logout' THEN 'authentication.logout.succeeded'
    ELSE 'authentication.session.revoked'
  END;

  PERFORM app.append_platform_audit_event(
    p_platform_audit_event_id, 'user', actor_id,
    audit_action, 'session', p_session_id,
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    session_record.authentication_method, 'success', p_reason, '{}'::jsonb
  );
  RETURN true;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."rotate_auth_session_tenant"(
  p_old_token_digest bytea,
  p_new_session_id uuid,
  p_new_token_digest bytea,
  p_new_csrf_secret_digest bytea,
  p_tenant_id uuid,
  p_new_idle_expires_at timestamp with time zone,
  p_new_absolute_expires_at timestamp with time zone,
  p_platform_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  old_session public.auth_sessions%ROWTYPE;
  actor_id uuid;
BEGIN
  actor_id := app.context_user_id();
  IF p_tenant_id IS NULL THEN
    RAISE EXCEPTION 'active tenant is required' USING ERRCODE = '22023';
  END IF;
  SELECT * INTO old_session
  FROM public.auth_sessions
  WHERE token_digest = p_old_token_digest
    AND user_id = actor_id
    AND revoked_at IS NULL
    AND idle_expires_at > transaction_timestamp()
    AND absolute_expires_at > transaction_timestamp()
  FOR UPDATE;
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;
  IF old_session.active_tenant_id IS NOT DISTINCT FROM p_tenant_id THEN
    RAISE EXCEPTION 'requested tenant is already active' USING ERRCODE = '22023';
  END IF;
  IF NOT app.session_tenant_allowed(actor_id, p_tenant_id) THEN
    RAISE EXCEPTION 'active tenant requires an active membership' USING ERRCODE = '42501';
  END IF;
  IF octet_length(p_new_token_digest) <> 32
     OR octet_length(p_new_csrf_secret_digest) <> 32
     OR p_new_idle_expires_at <= transaction_timestamp()
     OR p_new_absolute_expires_at < p_new_idle_expires_at
     OR p_new_absolute_expires_at > old_session.absolute_expires_at THEN
    RAISE EXCEPTION 'invalid rotated session parameters' USING ERRCODE = '22023';
  END IF;

  UPDATE public.auth_sessions
  SET revoked_at = transaction_timestamp(), revoke_reason = 'rotated_tenant'
  WHERE id = old_session.id;

  INSERT INTO public.auth_sessions (
    id, user_id, rotation_family_id, active_tenant_id, token_digest,
    csrf_secret_digest, authentication_method, mfa_satisfied_at,
    idle_expires_at, absolute_expires_at, rotated_from_session_id
  ) VALUES (
    p_new_session_id, actor_id, old_session.rotation_family_id, p_tenant_id,
    p_new_token_digest, p_new_csrf_secret_digest,
    old_session.authentication_method, old_session.mfa_satisfied_at,
    p_new_idle_expires_at, p_new_absolute_expires_at, old_session.id
  );

  PERFORM app.append_platform_audit_event(
    p_platform_audit_event_id, 'user', actor_id,
    'authentication.session.tenant_switched', 'session', p_new_session_id,
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    old_session.authentication_method, 'success', NULL,
    jsonb_build_object(
      'previous_active_tenant_id', old_session.active_tenant_id,
      'active_tenant_id', p_tenant_id,
      'rotated_from_session_id', old_session.id
    )
  );
  RETURN p_new_session_id;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION "app"."get_local_break_glass_credential"(text) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."get_totp_credential"(uuid) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."advance_totp_counter"(uuid, bigint) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."consume_recovery_code"(uuid, bytea) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."create_auth_challenge"(uuid, uuid, bytea, bytea, bytea, bytea, "public"."auth_challenge_purpose", timestamp with time zone, integer, uuid, uuid, uuid, inet, text, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."record_auth_challenge_failure"(bytea, "public"."auth_challenge_purpose") OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."get_auth_challenge"(bytea, "public"."auth_challenge_purpose") OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."consume_auth_challenge"(bytea, "public"."auth_challenge_purpose") OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."session_tenant_allowed"(uuid, uuid) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."create_auth_session"(uuid, uuid, uuid, uuid, bytea, bytea, text, timestamp with time zone, timestamp with time zone, timestamp with time zone) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."get_auth_session"(bytea) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."touch_auth_session"(bytea, timestamp with time zone) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."revoke_auth_session"(bytea, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."rotate_auth_session"(bytea, uuid, bytea, bytea, timestamp with time zone, timestamp with time zone, uuid, uuid, uuid, inet, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."complete_mfa_login"(bytea, text, bigint, bytea, uuid, uuid, uuid, bytea, bytea, timestamp with time zone, timestamp with time zone, "public"."auth_rate_limit_scope"[], bytea[], integer[], integer[], integer[], "public"."auth_rate_limit_scope"[], bytea[], uuid, uuid, uuid, inet, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."list_user_sessions"(uuid, uuid, integer) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."list_user_tenant_memberships"(uuid, integer) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."switch_auth_session_tenant"(bytea, uuid) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."revoke_user_session"(uuid, text, uuid, uuid, uuid, inet, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."rotate_auth_session_tenant"(bytea, uuid, bytea, bytea, uuid, timestamp with time zone, timestamp with time zone, uuid, uuid, uuid, inet, text) OWNER TO "periapsis_migrator";--> statement-breakpoint

REVOKE ALL ON FUNCTION "app"."get_local_break_glass_credential"(text) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."get_totp_credential"(uuid) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."advance_totp_counter"(uuid, bigint) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."consume_recovery_code"(uuid, bytea) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."create_auth_challenge"(uuid, uuid, bytea, bytea, bytea, bytea, "public"."auth_challenge_purpose", timestamp with time zone, integer, uuid, uuid, uuid, inet, text, text) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."record_auth_challenge_failure"(bytea, "public"."auth_challenge_purpose") FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."get_auth_challenge"(bytea, "public"."auth_challenge_purpose") FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."consume_auth_challenge"(bytea, "public"."auth_challenge_purpose") FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."session_tenant_allowed"(uuid, uuid) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."create_auth_session"(uuid, uuid, uuid, uuid, bytea, bytea, text, timestamp with time zone, timestamp with time zone, timestamp with time zone) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."get_auth_session"(bytea) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."touch_auth_session"(bytea, timestamp with time zone) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."revoke_auth_session"(bytea, text) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."rotate_auth_session"(bytea, uuid, bytea, bytea, timestamp with time zone, timestamp with time zone, uuid, uuid, uuid, inet, text) FROM PUBLIC;
--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."complete_mfa_login"(bytea, text, bigint, bytea, uuid, uuid, uuid, bytea, bytea, timestamp with time zone, timestamp with time zone, "public"."auth_rate_limit_scope"[], bytea[], integer[], integer[], integer[], "public"."auth_rate_limit_scope"[], bytea[], uuid, uuid, uuid, inet, text) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."list_user_sessions"(uuid, uuid, integer) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."list_user_tenant_memberships"(uuid, integer) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."switch_auth_session_tenant"(bytea, uuid) FROM PUBLIC;
--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."revoke_user_session"(uuid, text, uuid, uuid, uuid, inet, text) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."rotate_auth_session_tenant"(bytea, uuid, bytea, bytea, uuid, timestamp with time zone, timestamp with time zone, uuid, uuid, uuid, inet, text) FROM PUBLIC;
--> statement-breakpoint

CREATE FUNCTION "app"."admit_auth_attempts"(
  p_scopes "public"."auth_rate_limit_scope"[],
  p_key_digests bytea[],
  p_window_seconds integer[],
  p_max_attempts integer[],
  p_block_seconds integer[]
)
RETURNS TABLE (
  admitted boolean,
  maximum_attempt_count integer,
  blocked_until timestamp with time zone
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  candidate record;
  rate_record public.auth_rate_limits%ROWTYPE;
  rule_count integer;
  result_admitted boolean := true;
  result_maximum_attempt_count integer := 0;
  result_blocked_until timestamp with time zone;
  introduced_rate_limit_ids uuid[] := ARRAY[]::uuid[];
BEGIN
  rule_count := coalesce(cardinality(p_scopes), 0);
  IF rule_count NOT BETWEEN 1 AND 8
     OR array_ndims(p_scopes) <> 1
     OR array_ndims(p_key_digests) <> 1
     OR array_ndims(p_window_seconds) <> 1
     OR array_ndims(p_max_attempts) <> 1
     OR array_ndims(p_block_seconds) <> 1
     OR cardinality(p_key_digests) IS DISTINCT FROM rule_count
     OR cardinality(p_window_seconds) IS DISTINCT FROM rule_count
     OR cardinality(p_max_attempts) IS DISTINCT FROM rule_count
     OR cardinality(p_block_seconds) IS DISTINCT FROM rule_count THEN
    RAISE EXCEPTION 'invalid authentication admission parameters'
      USING ERRCODE = '22023';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM unnest(
      p_scopes, p_key_digests, p_window_seconds,
      p_max_attempts, p_block_seconds
    ) AS rule(scope, key_digest, window_seconds, max_attempts, block_seconds)
    WHERE rule.scope IS NULL
       OR rule.key_digest IS NULL
       OR octet_length(rule.key_digest) <> 32
       OR rule.window_seconds NOT BETWEEN 1 AND 3600
       OR rule.max_attempts NOT BETWEEN 1 AND 100
       OR rule.block_seconds NOT BETWEEN 1 AND 86400
  ) OR EXISTS (
    SELECT 1
    FROM unnest(p_scopes, p_key_digests) AS rule(scope, key_digest)
    GROUP BY rule.scope, rule.key_digest
    HAVING count(*) > 1
  ) THEN
    RAISE EXCEPTION 'invalid or duplicate authentication admission rule'
      USING ERRCODE = '22023';
  END IF;

  -- Every supplied key is updated in one database transaction. Sorting the
  -- purpose-separated digests gives overlapping account/network attempts a
  -- consistent lock order and prevents a blocked key from bypassing updates to
  -- the other shared counter.
  FOR candidate IN
    SELECT rule.scope, rule.key_digest, rule.window_seconds,
           rule.max_attempts, rule.block_seconds, uuidv7() AS new_id
    FROM unnest(
      p_scopes, p_key_digests, p_window_seconds,
      p_max_attempts, p_block_seconds
    ) AS rule(scope, key_digest, window_seconds, max_attempts, block_seconds)
    ORDER BY rule.scope::text, rule.key_digest
  LOOP
    INSERT INTO public.auth_rate_limits (
      id, scope, key_digest, attempt_count, window_started_at,
      window_expires_at, blocked_until
    ) VALUES (
      candidate.new_id, candidate.scope, candidate.key_digest, 1,
      transaction_timestamp(),
      transaction_timestamp() + make_interval(secs => candidate.window_seconds),
      NULL
    )
    ON CONFLICT (scope, key_digest) DO UPDATE
    SET attempt_count = CASE
          WHEN public.auth_rate_limits.window_expires_at <= transaction_timestamp()
           AND coalesce(public.auth_rate_limits.blocked_until,
                        transaction_timestamp()) <= transaction_timestamp()
            THEN 1
          ELSE least(public.auth_rate_limits.attempt_count + 1, 2147483647)
        END,
        window_started_at = CASE
          WHEN public.auth_rate_limits.window_expires_at <= transaction_timestamp()
           AND coalesce(public.auth_rate_limits.blocked_until,
                        transaction_timestamp()) <= transaction_timestamp()
            THEN transaction_timestamp()
          ELSE public.auth_rate_limits.window_started_at
        END,
        window_expires_at = CASE
          WHEN public.auth_rate_limits.window_expires_at <= transaction_timestamp()
           AND coalesce(public.auth_rate_limits.blocked_until,
                        transaction_timestamp()) <= transaction_timestamp()
            THEN transaction_timestamp() + make_interval(secs => candidate.window_seconds)
          ELSE public.auth_rate_limits.window_expires_at
        END,
        blocked_until = CASE
          WHEN public.auth_rate_limits.blocked_until > transaction_timestamp()
            THEN public.auth_rate_limits.blocked_until
          WHEN public.auth_rate_limits.window_expires_at <= transaction_timestamp()
            THEN NULL
          WHEN public.auth_rate_limits.attempt_count >= candidate.max_attempts
            THEN transaction_timestamp() + make_interval(secs => candidate.block_seconds)
          ELSE NULL
        END,
        updated_at = transaction_timestamp()
    RETURNING * INTO rate_record;

    IF rate_record.id = candidate.new_id THEN
      introduced_rate_limit_ids := array_append(
        introduced_rate_limit_ids,
        rate_record.id
      );
    END IF;

    result_admitted := result_admitted
      AND NOT (rate_record.blocked_until > transaction_timestamp());
    result_maximum_attempt_count := greatest(
      result_maximum_attempt_count,
      rate_record.attempt_count
    );
    IF rate_record.blocked_until IS NOT NULL THEN
      result_blocked_until := greatest(
        coalesce(result_blocked_until, rate_record.blocked_until),
        rate_record.blocked_until
      );
    END IF;
  END LOOP;

  -- A denied aggregate request must not let rotating sibling identities or
  -- networks create durable rows. Existing meters (including the key that
  -- crossed its limit) keep their updated state; only rows proven by their
  -- call-owned IDs to have been introduced by this denied transaction vanish.
  IF NOT result_admitted AND cardinality(introduced_rate_limit_ids) > 0 THEN
    DELETE FROM public.auth_rate_limits
    WHERE id = ANY(introduced_rate_limit_ids);
  END IF;

  RETURN QUERY
  SELECT result_admitted, result_maximum_attempt_count, result_blocked_until;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."record_authentication_failure"(
  p_scope "public"."auth_rate_limit_scope",
  p_metered_key_digest bytea,
  p_user_id uuid,
  p_platform_audit_event_id uuid,
  p_reason text,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_scope IS DISTINCT FROM 'local_login'
     OR p_metered_key_digest IS NULL
     OR octet_length(p_metered_key_digest) <> 32
     OR p_reason IS NULL OR p_reason !~ '^[a-z][a-z0-9_]{0,63}$'
     OR p_authentication_method IS NULL
     OR p_authentication_method !~ '^[a-z][a-z0-9_]{0,63}$' THEN
    RAISE EXCEPTION 'invalid authentication failure parameters'
      USING ERRCODE = '22023';
  END IF;
  IF NOT EXISTS (
    SELECT 1
    FROM public.auth_rate_limits AS rate
    WHERE rate.scope = p_scope
      AND rate.key_digest = p_metered_key_digest
      AND (
        rate.window_expires_at > transaction_timestamp()
        OR rate.blocked_until > transaction_timestamp()
      )
  ) THEN
    RAISE EXCEPTION 'authentication failure was not admitted and metered'
      USING ERRCODE = '55000';
  END IF;
  IF p_user_id IS NOT NULL AND NOT EXISTS (
    SELECT 1
    FROM public.users AS identity
    WHERE identity.id = p_user_id AND identity.active = true
  ) THEN
    RAISE EXCEPTION 'authentication failure user is not active'
      USING ERRCODE = '22023';
  END IF;

  PERFORM app.append_platform_audit_event(
    p_platform_audit_event_id, 'system', NULL, 'authentication.failure',
    CASE WHEN p_user_id IS NULL THEN 'authentication' ELSE 'user' END,
    p_user_id, p_request_id, p_correlation_id,
    p_ip_address, p_user_agent, p_authentication_method, 'failure',
    p_reason, jsonb_build_object('scope', p_scope::text)
  );
  RETURN true;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."record_auth_rate_limit_failure"(
  p_scopes "public"."auth_rate_limit_scope"[],
  p_key_digests bytea[],
  p_window_seconds integer[],
  p_max_attempts integer[],
  p_block_seconds integer[],
  p_platform_audit_event_id uuid,
  p_reason text,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE (
  maximum_attempt_count integer,
  blocked_until timestamp with time zone
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  candidate record;
  rate_record public.auth_rate_limits%ROWTYPE;
  rule_count integer;
  result_maximum_attempt_count integer := 0;
  result_blocked_until timestamp with time zone;
  introduced_rate_limit_ids uuid[] := ARRAY[]::uuid[];
BEGIN
  rule_count := coalesce(cardinality(p_scopes), 0);
  IF rule_count NOT BETWEEN 1 AND 8
     OR array_ndims(p_scopes) <> 1
     OR array_ndims(p_key_digests) <> 1
     OR array_ndims(p_window_seconds) <> 1
     OR array_ndims(p_max_attempts) <> 1
     OR array_ndims(p_block_seconds) <> 1
     OR cardinality(p_key_digests) IS DISTINCT FROM rule_count
     OR cardinality(p_window_seconds) IS DISTINCT FROM rule_count
     OR cardinality(p_max_attempts) IS DISTINCT FROM rule_count
     OR cardinality(p_block_seconds) IS DISTINCT FROM rule_count
     OR p_reason IS NULL OR p_reason !~ '^[a-z][a-z0-9_]{0,63}$'
     OR p_authentication_method IS NULL
     OR p_authentication_method !~ '^[a-z][a-z0-9_]{0,63}$' THEN
    RAISE EXCEPTION 'invalid authentication rate-limit parameters' USING ERRCODE = '22023';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM unnest(
      p_scopes, p_key_digests, p_window_seconds,
      p_max_attempts, p_block_seconds
    ) AS rule(scope, key_digest, window_seconds, max_attempts, block_seconds)
    WHERE rule.scope IS NULL
       OR rule.key_digest IS NULL
       OR octet_length(rule.key_digest) <> 32
       OR rule.window_seconds NOT BETWEEN 1 AND 3600
       OR rule.max_attempts NOT BETWEEN 2 AND 100
       OR rule.block_seconds NOT BETWEEN 1 AND 86400
  ) OR EXISTS (
    SELECT 1
    FROM unnest(p_scopes, p_key_digests) AS rule(scope, key_digest)
    GROUP BY rule.scope, rule.key_digest
    HAVING count(*) > 1
  ) THEN
    RAISE EXCEPTION 'invalid or duplicate authentication failure rule'
      USING ERRCODE = '22023';
  END IF;

  FOR candidate IN
    SELECT rule.scope, rule.key_digest, rule.window_seconds,
           rule.max_attempts, rule.block_seconds, uuidv7() AS new_id
    FROM unnest(
      p_scopes, p_key_digests, p_window_seconds,
      p_max_attempts, p_block_seconds
    ) AS rule(scope, key_digest, window_seconds, max_attempts, block_seconds)
    ORDER BY rule.scope::text, rule.key_digest
  LOOP
    INSERT INTO public.auth_rate_limits (
      id, scope, key_digest, attempt_count, window_started_at,
      window_expires_at, blocked_until
    ) VALUES (
      candidate.new_id, candidate.scope, candidate.key_digest, 1,
      transaction_timestamp(),
      transaction_timestamp() + make_interval(secs => candidate.window_seconds),
      NULL
    )
    ON CONFLICT (scope, key_digest) DO UPDATE
    SET attempt_count = CASE
          WHEN public.auth_rate_limits.window_expires_at <= transaction_timestamp()
           AND coalesce(public.auth_rate_limits.blocked_until,
                        transaction_timestamp()) <= transaction_timestamp()
            THEN 1
          ELSE least(public.auth_rate_limits.attempt_count + 1, 2147483647)
        END,
        window_started_at = CASE
          WHEN public.auth_rate_limits.window_expires_at <= transaction_timestamp()
           AND coalesce(public.auth_rate_limits.blocked_until,
                        transaction_timestamp()) <= transaction_timestamp()
            THEN transaction_timestamp()
          ELSE public.auth_rate_limits.window_started_at
        END,
        window_expires_at = CASE
          WHEN public.auth_rate_limits.window_expires_at <= transaction_timestamp()
           AND coalesce(public.auth_rate_limits.blocked_until,
                        transaction_timestamp()) <= transaction_timestamp()
            THEN transaction_timestamp() + make_interval(secs => candidate.window_seconds)
          ELSE public.auth_rate_limits.window_expires_at
        END,
        blocked_until = CASE
          WHEN public.auth_rate_limits.blocked_until > transaction_timestamp()
            THEN public.auth_rate_limits.blocked_until
          WHEN public.auth_rate_limits.window_expires_at <= transaction_timestamp()
            THEN NULL
          WHEN public.auth_rate_limits.attempt_count + 1 >= candidate.max_attempts
            THEN transaction_timestamp() + make_interval(secs => candidate.block_seconds)
          ELSE NULL
        END,
        updated_at = transaction_timestamp()
    RETURNING * INTO rate_record;

    IF rate_record.id = candidate.new_id THEN
      introduced_rate_limit_ids := array_append(
        introduced_rate_limit_ids,
        rate_record.id
      );
    END IF;
    result_maximum_attempt_count := greatest(
      result_maximum_attempt_count,
      rate_record.attempt_count
    );
    IF rate_record.blocked_until IS NOT NULL THEN
      result_blocked_until := greatest(
        coalesce(result_blocked_until, rate_record.blocked_until),
        rate_record.blocked_until
      );
    END IF;
  END LOOP;

  IF result_blocked_until > transaction_timestamp()
     AND cardinality(introduced_rate_limit_ids) > 0 THEN
    DELETE FROM public.auth_rate_limits
    WHERE id = ANY(introduced_rate_limit_ids);
  END IF;

  PERFORM app.append_platform_audit_event(
    p_platform_audit_event_id, 'system', NULL, 'authentication.failure',
    'authentication', NULL, p_request_id, p_correlation_id,
    p_ip_address, p_user_agent, p_authentication_method, 'failure',
    p_reason, jsonb_build_object(
      'rule_count', rule_count,
      'maximum_attempt_count', result_maximum_attempt_count,
      'blocked', result_blocked_until > transaction_timestamp()
    )
  );

  RETURN QUERY
  SELECT result_maximum_attempt_count, result_blocked_until;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."get_auth_rate_limit"(
  p_scope "public"."auth_rate_limit_scope",
  p_key_digest bytea
)
RETURNS TABLE (
  attempt_count integer,
  window_expires_at timestamp with time zone,
  blocked_until timestamp with time zone
)
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
  SELECT rate.attempt_count, rate.window_expires_at, rate.blocked_until
  FROM public.auth_rate_limits AS rate
  WHERE rate.scope = p_scope
    AND rate.key_digest = p_key_digest
    AND (
      rate.window_expires_at > statement_timestamp()
      OR rate.blocked_until > statement_timestamp()
    );
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."clear_auth_rate_limit"(
  p_scope "public"."auth_rate_limit_scope",
  p_key_digest bytea
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
BEGIN
  DELETE FROM public.auth_rate_limits
  WHERE scope = p_scope AND key_digest = p_key_digest;
  RETURN FOUND;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."prune_expired_auth_state"(p_per_class_batch_size integer)
RETURNS TABLE (
  rate_limits_deleted integer,
  challenges_deleted integer,
  sessions_deleted integer
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  deleted_rate_limits integer := 0;
  deleted_challenges integer := 0;
  deleted_sessions integer := 0;
BEGIN
  IF p_per_class_batch_size IS NULL
     OR p_per_class_batch_size NOT BETWEEN 1 AND 1000 THEN
    RAISE EXCEPTION 'authentication cleanup per-class batch must be between 1 and 1000'
      USING ERRCODE = '22023';
  END IF;

  -- The caller cap applies independently to every state class. This keeps the
  -- work bounded at no more than three batches while preventing a sustained
  -- rate-limit backlog from starving challenge or session-family retention.
  WITH candidates AS (
    SELECT stale.id
    FROM public.auth_rate_limits AS stale
    WHERE stale.window_expires_at <= transaction_timestamp()
      AND (
        stale.blocked_until IS NULL
        OR stale.blocked_until <= transaction_timestamp()
      )
    ORDER BY greatest(
      stale.window_expires_at,
      coalesce(stale.blocked_until, stale.window_expires_at)
    ), stale.id
    LIMIT p_per_class_batch_size
    FOR UPDATE SKIP LOCKED
  )
  DELETE FROM public.auth_rate_limits AS stale
  USING candidates
  WHERE stale.id = candidates.id;
  GET DIAGNOSTICS deleted_rate_limits = ROW_COUNT;

  WITH candidates AS (
    SELECT stale.id
    FROM public.auth_challenges AS stale
    WHERE (stale.consumed_at IS NOT NULL
        OR stale.expires_at <= transaction_timestamp())
      AND greatest(
        stale.expires_at,
        coalesce(stale.consumed_at, stale.expires_at)
      ) <= transaction_timestamp() - interval '24 hours'
    ORDER BY greatest(
      stale.expires_at,
      coalesce(stale.consumed_at, stale.expires_at)
    ), stale.id
    LIMIT p_per_class_batch_size
    FOR UPDATE SKIP LOCKED
  )
  DELETE FROM public.auth_challenges AS stale
  USING candidates
  WHERE stale.id = candidates.id;
  GET DIAGNOSTICS deleted_challenges = ROW_COUNT;

  WITH dead_families AS (
    SELECT family.user_id, family.rotation_family_id,
           max(greatest(
             family.absolute_expires_at,
             coalesce(family.revoked_at, family.absolute_expires_at)
           )) AS retention_ready_at
    FROM public.auth_sessions AS family
    GROUP BY family.user_id, family.rotation_family_id
    HAVING bool_and(
      family.revoked_at IS NOT NULL
      OR family.idle_expires_at <= transaction_timestamp()
      OR family.absolute_expires_at <= transaction_timestamp()
    )
    AND max(greatest(
      family.absolute_expires_at,
      coalesce(family.revoked_at, family.absolute_expires_at)
    )) <= transaction_timestamp() - interval '30 days'
  ), candidates AS (
    SELECT stale.id
    FROM public.auth_sessions AS stale
    JOIN dead_families AS family
      ON family.user_id = stale.user_id
     AND family.rotation_family_id = stale.rotation_family_id
    ORDER BY family.retention_ready_at,
             stale.user_id, stale.rotation_family_id,
             stale.created_at DESC, stale.id DESC
    LIMIT p_per_class_batch_size
    FOR UPDATE OF stale SKIP LOCKED
  )
  DELETE FROM public.auth_sessions AS stale
  USING candidates
  WHERE stale.id = candidates.id;
  GET DIAGNOSTICS deleted_sessions = ROW_COUNT;

  RETURN QUERY
  SELECT deleted_rate_limits, deleted_challenges, deleted_sessions;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."record_platform_bootstrap_failure"(
  p_authority_token_digest bytea,
  p_enrollment_token_digest bytea,
  p_scopes "public"."auth_rate_limit_scope"[],
  p_key_digests bytea[],
  p_window_seconds integer[],
  p_max_attempts integer[],
  p_block_seconds integer[],
  p_platform_audit_event_id uuid,
  p_reason text,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text
)
RETURNS TABLE (
  enrollment_attempts integer,
  enrollment_exhausted boolean,
  maximum_rate_attempt_count integer,
  blocked_until timestamp with time zone
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  state_record public.platform_bootstrap_state%ROWTYPE;
  enrollment public.platform_bootstrap_enrollments%ROWTYPE;
  recorded_rate_attempts integer;
  recorded_blocked_until timestamp with time zone;
BEGIN
  SELECT * INTO STRICT state_record
  FROM public.platform_bootstrap_state
  WHERE singleton = true
  FOR UPDATE;
  IF state_record.authority_token_digest IS NULL
     OR state_record.authority_token_digest <> p_authority_token_digest THEN
    RAISE EXCEPTION 'invalid bootstrap authority' USING ERRCODE = '42501';
  END IF;
  IF state_record.completed_at IS NOT NULL THEN
    RAISE EXCEPTION 'platform bootstrap is already complete' USING ERRCODE = '55000';
  END IF;

  SELECT * INTO enrollment
  FROM public.platform_bootstrap_enrollments
  WHERE token_digest = p_enrollment_token_digest
    AND consumed_at IS NULL
    AND invalidated_at IS NULL
    AND expires_at > transaction_timestamp()
  FOR UPDATE;
  IF NOT FOUND THEN
    RETURN;
  END IF;
  IF NOT EXISTS (
    SELECT 1
    FROM unnest(p_scopes, p_key_digests) AS rule(scope, key_digest)
    WHERE rule.scope = 'bootstrap_totp'
      AND rule.key_digest = enrollment.enrollment_rate_key_digest
  ) THEN
    RAISE EXCEPTION 'bootstrap failure rules omitted the enrollment meter'
      USING ERRCODE = '22023';
  END IF;

  UPDATE public.platform_bootstrap_enrollments
  SET attempts = least(attempts + 1, max_attempts),
      last_attempt_at = transaction_timestamp(),
      invalidated_at = CASE
        WHEN attempts + 1 >= max_attempts THEN transaction_timestamp()
        ELSE invalidated_at
      END
  WHERE id = enrollment.id
  RETURNING * INTO enrollment;

  SELECT rate.maximum_attempt_count, rate.blocked_until
    INTO recorded_rate_attempts, recorded_blocked_until
  FROM app.record_auth_rate_limit_failure(
    p_scopes, p_key_digests, p_window_seconds, p_max_attempts, p_block_seconds,
    p_platform_audit_event_id, p_reason, p_request_id, p_correlation_id,
    p_ip_address, p_user_agent, 'bootstrap_totp'
  ) AS rate;

  RETURN QUERY SELECT enrollment.attempts,
                      enrollment.invalidated_at IS NOT NULL,
                      recorded_rate_attempts,
                      recorded_blocked_until;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."record_mfa_challenge_failure"(
  p_challenge_token_digest bytea,
  p_scopes "public"."auth_rate_limit_scope"[],
  p_key_digests bytea[],
  p_window_seconds integer[],
  p_max_attempts integer[],
  p_block_seconds integer[],
  p_platform_audit_event_id uuid,
  p_reason text,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE (
  challenge_attempts integer,
  challenge_exhausted boolean,
  maximum_rate_attempt_count integer,
  blocked_until timestamp with time zone
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  challenge_record public.auth_challenges%ROWTYPE;
  recorded_challenge_attempts integer;
  recorded_challenge_exhausted boolean;
  recorded_rate_attempts integer;
  recorded_blocked_until timestamp with time zone;
BEGIN
  SELECT * INTO challenge_record
  FROM public.auth_challenges AS challenge
  WHERE challenge.token_digest = p_challenge_token_digest
    AND challenge.purpose = 'mfa_login'
    AND challenge.consumed_at IS NULL
    AND challenge.expires_at > transaction_timestamp()
    AND challenge.attempts < challenge.max_attempts
  FOR UPDATE;
  IF NOT FOUND THEN
    RETURN;
  END IF;
  IF NOT EXISTS (
    SELECT 1
    FROM unnest(p_scopes, p_key_digests) AS rule(scope, key_digest)
    WHERE rule.scope = 'mfa_challenge'
      AND rule.key_digest = challenge_record.challenge_rate_key_digest
  ) OR NOT EXISTS (
    SELECT 1
    FROM unnest(p_scopes, p_key_digests) AS rule(scope, key_digest)
    WHERE rule.scope = 'mfa_challenge'
      AND rule.key_digest = challenge_record.mfa_rate_key_digest
  ) THEN
    RAISE EXCEPTION 'MFA failure rules omitted a proof-bound challenge meter'
      USING ERRCODE = '22023';
  END IF;

  UPDATE public.auth_challenges AS challenge
  SET attempts = least(challenge.attempts + 1, challenge.max_attempts),
      last_attempt_at = transaction_timestamp(),
      consumed_at = CASE
        WHEN challenge.attempts + 1 >= challenge.max_attempts
          THEN transaction_timestamp()
        ELSE challenge.consumed_at
      END
  WHERE challenge.id = challenge_record.id
  RETURNING challenge.attempts, challenge.attempts >= challenge.max_attempts
    INTO recorded_challenge_attempts, recorded_challenge_exhausted;

  SELECT rate.maximum_attempt_count, rate.blocked_until
    INTO recorded_rate_attempts, recorded_blocked_until
  FROM app.record_auth_rate_limit_failure(
    p_scopes, p_key_digests, p_window_seconds, p_max_attempts, p_block_seconds,
    p_platform_audit_event_id, p_reason, p_request_id, p_correlation_id,
    p_ip_address, p_user_agent, p_authentication_method
  ) AS rate;

  RETURN QUERY SELECT recorded_challenge_attempts,
                      recorded_challenge_exhausted,
                      recorded_rate_attempts,
                      recorded_blocked_until;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."list_platform_tenants"(p_after_id uuid, p_limit integer)
RETURNS TABLE (
  id uuid,
  slug text,
  name text,
  status "public"."tenant_status",
  timezone text,
  locale text,
  version integer,
  created_at timestamp with time zone,
  updated_at timestamp with time zone
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor_id uuid;
BEGIN
  actor_id := app.context_user_id();
  IF NOT app.platform_user_has_permission(actor_id, 'platform.tenant.read') THEN
    RAISE EXCEPTION 'platform.tenant.read permission is required' USING ERRCODE = '42501';
  END IF;
  IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 101 THEN
    RAISE EXCEPTION 'platform tenant page limit must be between 1 and 101'
      USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  SELECT tenant.id, tenant.slug, tenant.name, tenant.status, tenant.timezone,
         tenant.locale, tenant.version, tenant.created_at, tenant.updated_at
  FROM public.tenants AS tenant
  WHERE p_after_id IS NULL OR tenant.id > p_after_id
  ORDER BY tenant.id
  LIMIT p_limit;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."create_platform_tenant"(
  p_tenant_id uuid,
  p_membership_id uuid,
  p_slug text,
  p_name text,
  p_timezone text,
  p_locale text,
  p_platform_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE (
  id uuid,
  slug text,
  name text,
  status "public"."tenant_status",
  timezone text,
  locale text,
  version integer,
  created_at timestamp with time zone,
  updated_at timestamp with time zone
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor_id uuid;
BEGIN
  actor_id := app.context_user_id();
  IF NOT app.platform_user_has_permission(actor_id, 'platform.tenant.create') THEN
    RAISE EXCEPTION 'platform.tenant.create permission is required' USING ERRCODE = '42501';
  END IF;
  IF p_slug IS DISTINCT FROM lower(btrim(p_slug))
     OR p_slug !~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'
     OR p_name IS NULL OR btrim(p_name) = ''
     OR char_length(p_name) > 160 OR p_name ~ '[[:cntrl:]]'
     OR p_timezone IS NULL OR char_length(p_timezone) NOT BETWEEN 1 AND 64
     OR p_timezone ~ '[[:cntrl:]]'
     OR lower(p_timezone) IN ('local', 'localtime')
     OR NOT EXISTS (
       SELECT 1
       FROM pg_catalog.pg_timezone_names AS timezone
       WHERE timezone.name = p_timezone
     )
     OR p_locale IS NULL OR char_length(p_locale) > 35
     OR p_locale !~ '^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$'
     OR lower(split_part(p_locale, '-', 1)) = 'und' THEN
    RAISE EXCEPTION 'tenant attributes violate the canonical contract' USING ERRCODE = '22023';
  END IF;
  IF p_authentication_method NOT IN ('bootstrap_totp', 'totp', 'recovery_code') THEN
    RAISE EXCEPTION 'tenant creation requires a live session authentication method'
      USING ERRCODE = '22023';
  END IF;

  INSERT INTO public.tenants (id, slug, name, timezone, locale)
  VALUES (p_tenant_id, p_slug, p_name, p_timezone, p_locale);

  -- Provision the independently protected zero head in the same transaction
  -- as the tenant. Its absence is therefore distinguishable from a pristine
  -- tenant audit chain and is reported fail-closed by verify_audit_chain.
  INSERT INTO public.audit_chain_heads (tenant_id)
  VALUES (p_tenant_id);

  INSERT INTO public.tenant_memberships (id, tenant_id, user_id, role, status)
  VALUES (p_membership_id, p_tenant_id, actor_id, 'tenant_admin', 'active');

  PERFORM app.append_platform_audit_event(
    p_platform_audit_event_id, 'user', actor_id, 'platform.tenant.created',
    'tenant', p_tenant_id, p_request_id, p_correlation_id,
    p_ip_address, p_user_agent, p_authentication_method, 'success', NULL,
    jsonb_build_object('slug', p_slug, 'creator_membership_id', p_membership_id)
  );

  RETURN QUERY
  SELECT tenant.id, tenant.slug, tenant.name, tenant.status, tenant.timezone,
         tenant.locale, tenant.version, tenant.created_at, tenant.updated_at
  FROM public.tenants AS tenant
  WHERE tenant.id = p_tenant_id;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."grant_platform_role"(
  p_grant_id uuid,
  p_target_user_id uuid,
  p_role_key text,
  p_platform_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor_id uuid;
  target_role_id uuid;
BEGIN
  actor_id := app.context_user_id();
  IF NOT app.platform_user_has_permission(actor_id, 'platform.role.grant') THEN
    RAISE EXCEPTION 'platform.role.grant permission is required' USING ERRCODE = '42501';
  END IF;

  SELECT role.id INTO STRICT target_role_id
  FROM public.platform_roles AS role
  WHERE role.key = p_role_key;

  INSERT INTO public.user_platform_roles (
    id, user_id, role_id, granted_by_user_id
  ) VALUES (p_grant_id, p_target_user_id, target_role_id, actor_id);

  PERFORM app.append_platform_audit_event(
    p_platform_audit_event_id, 'user', actor_id, 'platform.role.granted',
    'user', p_target_user_id, p_request_id, p_correlation_id,
    NULL, NULL, NULL, 'success', NULL,
    jsonb_build_object('role', p_role_key, 'grant_id', p_grant_id)
  );

  RETURN p_grant_id;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."read_platform_audit_events"(
  p_after_sequence bigint,
  p_limit integer
)
RETURNS SETOF "public"."platform_audit_events"
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor_id uuid;
BEGIN
  actor_id := app.context_user_id();
  IF NOT app.platform_user_has_permission(actor_id, 'platform.audit.read') THEN
    RAISE EXCEPTION 'platform.audit.read permission is required' USING ERRCODE = '42501';
  END IF;
  IF p_limit IS NULL
     OR p_limit NOT BETWEEN 1 AND 500
     OR p_after_sequence IS NULL
     OR p_after_sequence < 0 THEN
    RAISE EXCEPTION 'invalid platform audit page' USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  SELECT event.*
  FROM public.platform_audit_events AS event
  WHERE event.sequence > p_after_sequence
  ORDER BY event.sequence
  LIMIT p_limit;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION "app"."admit_auth_attempts"("public"."auth_rate_limit_scope"[], bytea[], integer[], integer[], integer[]) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."record_authentication_failure"("public"."auth_rate_limit_scope", bytea, uuid, uuid, text, uuid, uuid, inet, text, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."record_auth_rate_limit_failure"("public"."auth_rate_limit_scope"[], bytea[], integer[], integer[], integer[], uuid, text, uuid, uuid, inet, text, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."get_auth_rate_limit"("public"."auth_rate_limit_scope", bytea) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."clear_auth_rate_limit"("public"."auth_rate_limit_scope", bytea) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."prune_expired_auth_state"(integer) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."record_platform_bootstrap_failure"(bytea, bytea, "public"."auth_rate_limit_scope"[], bytea[], integer[], integer[], integer[], uuid, text, uuid, uuid, inet, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."record_mfa_challenge_failure"(bytea, "public"."auth_rate_limit_scope"[], bytea[], integer[], integer[], integer[], uuid, text, uuid, uuid, inet, text, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."list_platform_tenants"(uuid, integer) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."create_platform_tenant"(uuid, uuid, text, text, text, text, uuid, uuid, uuid, inet, text, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."grant_platform_role"(uuid, uuid, text, uuid, uuid, uuid) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."read_platform_audit_events"(bigint, integer) OWNER TO "periapsis_migrator";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."admit_auth_attempts"("public"."auth_rate_limit_scope"[], bytea[], integer[], integer[], integer[]) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."record_authentication_failure"("public"."auth_rate_limit_scope", bytea, uuid, uuid, text, uuid, uuid, inet, text, text) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."record_auth_rate_limit_failure"("public"."auth_rate_limit_scope"[], bytea[], integer[], integer[], integer[], uuid, text, uuid, uuid, inet, text, text) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."get_auth_rate_limit"("public"."auth_rate_limit_scope", bytea) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."clear_auth_rate_limit"("public"."auth_rate_limit_scope", bytea) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."prune_expired_auth_state"(integer) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."record_platform_bootstrap_failure"(bytea, bytea, "public"."auth_rate_limit_scope"[], bytea[], integer[], integer[], integer[], uuid, text, uuid, uuid, inet, text) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."record_mfa_challenge_failure"(bytea, "public"."auth_rate_limit_scope"[], bytea[], integer[], integer[], integer[], uuid, text, uuid, uuid, inet, text, text) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."list_platform_tenants"(uuid, integer) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."create_platform_tenant"(uuid, uuid, text, text, text, text, uuid, uuid, uuid, inet, text, text) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."grant_platform_role"(uuid, uuid, text, uuid, uuid, uuid) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."read_platform_audit_events"(bigint, integer) FROM PUBLIC;--> statement-breakpoint

GRANT USAGE ON TYPE "public"."auth_challenge_purpose", "public"."auth_rate_limit_scope" TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."verify_protected_configuration"(bytea, bytea) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."reserve_platform_bootstrap"(uuid, bytea, bytea, bytea, text, bytea, bytea, bytea, integer, timestamp with time zone, integer, uuid, uuid, inet, text) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."get_platform_bootstrap_enrollment"(bytea, bytea) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."confirm_platform_bootstrap"(bytea, bytea, uuid, uuid, uuid, bytea, bytea, bytea, integer, uuid, text, text, text, integer, bigint, uuid[], bytea[], integer, uuid, uuid, bytea, bytea, timestamp with time zone, timestamp with time zone, uuid, uuid, uuid, inet, text) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."get_local_break_glass_credential"(text) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."get_totp_credential"(uuid) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."create_auth_challenge"(uuid, uuid, bytea, bytea, bytea, bytea, "public"."auth_challenge_purpose", timestamp with time zone, integer, uuid, uuid, uuid, inet, text, text) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."get_auth_challenge"(bytea, "public"."auth_challenge_purpose") TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."complete_mfa_login"(bytea, text, bigint, bytea, uuid, uuid, uuid, bytea, bytea, timestamp with time zone, timestamp with time zone, "public"."auth_rate_limit_scope"[], bytea[], integer[], integer[], integer[], "public"."auth_rate_limit_scope"[], bytea[], uuid, uuid, uuid, inet, text) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."get_auth_session"(bytea) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."touch_auth_session"(bytea, timestamp with time zone) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."rotate_auth_session"(bytea, uuid, bytea, bytea, timestamp with time zone, timestamp with time zone, uuid, uuid, uuid, inet, text) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."list_user_sessions"(uuid, uuid, integer) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."list_user_tenant_memberships"(uuid, integer) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."revoke_user_session"(uuid, text, uuid, uuid, uuid, inet, text) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."rotate_auth_session_tenant"(bytea, uuid, bytea, bytea, uuid, timestamp with time zone, timestamp with time zone, uuid, uuid, uuid, inet, text) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."admit_auth_attempts"("public"."auth_rate_limit_scope"[], bytea[], integer[], integer[], integer[]) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."record_authentication_failure"("public"."auth_rate_limit_scope", bytea, uuid, uuid, text, uuid, uuid, inet, text, text) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."record_auth_rate_limit_failure"("public"."auth_rate_limit_scope"[], bytea[], integer[], integer[], integer[], uuid, text, uuid, uuid, inet, text, text) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."get_auth_rate_limit"("public"."auth_rate_limit_scope", bytea) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."record_platform_bootstrap_failure"(bytea, bytea, "public"."auth_rate_limit_scope"[], bytea[], integer[], integer[], integer[], uuid, text, uuid, uuid, inet, text) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."record_mfa_challenge_failure"(bytea, "public"."auth_rate_limit_scope"[], bytea[], integer[], integer[], integer[], uuid, text, uuid, uuid, inet, text, text) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."has_platform_permission"(text) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."list_platform_tenants"(uuid, integer) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."create_platform_tenant"(uuid, uuid, text, text, text, text, uuid, uuid, uuid, inet, text, text) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."prune_expired_auth_state"(integer) TO "periapsis_worker";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."verify_platform_audit_chain"() TO "periapsis_auditor";
