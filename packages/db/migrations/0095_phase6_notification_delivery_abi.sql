CREATE FUNCTION app.claim_notification_delivery_batch_v1(
  p_worker_id text,
  p_limit integer,
  p_lease_duration_ms integer,
  p_now timestamp with time zone
)
RETURNS TABLE(claim jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_worker_id IS NULL OR p_worker_id !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
     OR p_limit NOT BETWEEN 1 AND 100
     OR p_lease_duration_ms NOT BETWEEN 5000 AND 300000
     OR p_now IS NULL
     OR p_now < transaction_timestamp() - interval '1 minute'
     OR p_now > transaction_timestamp() + interval '1 minute' THEN
    RAISE EXCEPTION 'notification delivery claim input is invalid' USING ERRCODE = '22023';
  END IF;
  RETURN QUERY
  WITH candidate AS (
    SELECT delivery.id
    FROM public.tenant_notification_deliveries AS delivery
    WHERE delivery.channel = 'email'
      AND delivery.status IN ('queued', 'retry_scheduled', 'leased', 'reserved')
      AND delivery.attempt_count < delivery.maximum_attempts
      AND (delivery.status IN ('leased', 'reserved') AND delivery.lease_until <= p_now
        OR delivery.status IN ('queued', 'retry_scheduled') AND delivery.next_attempt_at <= p_now)
      AND delivery.template_id IS NOT NULL
      AND delivery.template_version IS NOT NULL
      AND delivery.smtp_configuration_scope IN ('tenant', 'platform')
      AND delivery.smtp_configuration_id IS NOT NULL
      AND delivery.smtp_configuration_version IS NOT NULL
    ORDER BY delivery.priority DESC, delivery.next_attempt_at, delivery.created_at, delivery.id
    LIMIT p_limit
    FOR UPDATE SKIP LOCKED
  ), fenced AS (
    UPDATE public.tenant_notification_delivery_attempts AS attempt
    SET completed_at = p_now, outcome = 'fenced'
    FROM candidate
    JOIN public.tenant_notification_deliveries AS previous
      ON previous.id = candidate.id
    WHERE attempt.tenant_id = previous.tenant_id
      AND attempt.delivery_id = previous.id
      AND attempt.attempt = previous.attempt_count
      AND attempt.completed_at IS NULL
      AND attempt.outcome IS NULL
    RETURNING attempt.tenant_id, attempt.delivery_id, attempt.attempt
  ), claimed AS (
    UPDATE public.tenant_notification_deliveries AS delivery
    SET status = 'leased',
        attempt_count = delivery.attempt_count + 1,
        lease_owner = p_worker_id,
        fence_token = uuidv7(),
        lease_until = p_now + make_interval(secs => p_lease_duration_ms::double precision / 1000.0),
        failure_at = NULL,
        failure_class = NULL,
        failure_code = NULL,
        updated_at = p_now
    FROM candidate
    WHERE delivery.id = candidate.id
      AND (SELECT count(*) FROM fenced) >= 0
    RETURNING delivery.*
  ), started AS (
    INSERT INTO public.tenant_notification_delivery_attempts (
      tenant_id, delivery_id, attempt, fence_token, started_at
    )
    SELECT claimed.tenant_id, claimed.id, claimed.attempt_count,
           claimed.fence_token, p_now
    FROM claimed
    RETURNING tenant_id, delivery_id, attempt
  )
  SELECT jsonb_build_object(
    'id', claimed.id,
    'tenantId', claimed.tenant_id,
    'eventId', claimed.event_id,
    'ruleId', coalesce(claimed.rule_id, claimed.id),
    'ruleVersion', coalesce(claimed.rule_version, 1),
    'smtpConfigurationScope', claimed.smtp_configuration_scope,
    'smtpConfigurationId', claimed.smtp_configuration_id,
    'smtpConfigurationVersion', claimed.smtp_configuration_version,
    'deduplicationKey', claimed.delivery_key,
    'recipient', claimed.recipient,
    'audience', claimed.audience,
    'context', claimed.context,
    'template', jsonb_strip_nulls(jsonb_build_object(
      'id', template.template_id,
      'tenantId', template.tenant_id,
      'key', template.key,
      'name', template.name,
      'language', template.language,
      'version', template.version,
      'subject', template.subject,
      'html', template.html,
      'plainText', template.plain_text,
      'css', template.css
    )),
    'retry', claimed.retry,
    'attempt', claimed.attempt_count,
    'fenceToken', claimed.fence_token,
    'leaseUntil', claimed.lease_until
  )
  FROM claimed
  JOIN started
    ON started.tenant_id = claimed.tenant_id
   AND started.delivery_id = claimed.id
   AND started.attempt = claimed.attempt_count
  JOIN public.tenant_notification_template_versions AS template
    ON template.tenant_id = claimed.tenant_id
   AND template.template_id = claimed.template_id
   AND template.version = claimed.template_version
  ORDER BY claimed.priority DESC, claimed.next_attempt_at, claimed.created_at, claimed.id;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.claim_notification_delivery_batch_v1(text, integer, integer, timestamp with time zone) OWNER TO periapsis_notification_dispatch_owner;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.claim_notification_delivery_batch_v1(text, integer, integer, timestamp with time zone) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.claim_notification_delivery_batch_v1(text, integer, integer, timestamp with time zone) TO periapsis_notifier;--> statement-breakpoint

CREATE FUNCTION app.private_lock_notification_delivery_claim_v1(
  p_delivery_id uuid,
  p_fence_token uuid,
  p_allow_terminal boolean DEFAULT false
)
RETURNS uuid
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE selected_tenant uuid;
BEGIN
  SELECT delivery.tenant_id INTO selected_tenant
  FROM public.tenant_notification_deliveries AS delivery
  WHERE delivery.id = p_delivery_id
    AND (p_allow_terminal AND delivery.status = 'delivered'
      OR delivery.status IN ('leased', 'reserved')
        AND delivery.fence_token = p_fence_token
        AND delivery.lease_until > transaction_timestamp())
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'notification delivery claim is stale' USING ERRCODE = '40001';
  END IF;
  PERFORM set_config('app.tenant_id', selected_tenant::text, true);
  RETURN selected_tenant;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.private_lock_notification_delivery_claim_v1(uuid, uuid, boolean) OWNER TO periapsis_notification_dispatch_owner;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_lock_notification_delivery_claim_v1(uuid, uuid, boolean) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.private_lock_notification_delivery_claim_v1(uuid, uuid, boolean) TO periapsis_notification_dispatch_owner;--> statement-breakpoint

CREATE FUNCTION app.heartbeat_notification_delivery_v1(
  p_delivery_id uuid,
  p_fence_token uuid,
  p_lease_until timestamp with time zone
)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_delivery_id IS NULL OR p_fence_token IS NULL OR p_lease_until IS NULL
     OR p_lease_until < transaction_timestamp() + interval '5 seconds'
     OR p_lease_until > transaction_timestamp() + interval '5 minutes' THEN
    RAISE EXCEPTION 'notification delivery heartbeat input is invalid' USING ERRCODE = '22023';
  END IF;
  UPDATE public.tenant_notification_deliveries AS delivery
  SET lease_until = p_lease_until, updated_at = transaction_timestamp()
  WHERE delivery.id = p_delivery_id
    AND delivery.status IN ('leased', 'reserved')
    AND delivery.fence_token = p_fence_token
    AND delivery.lease_until > transaction_timestamp();
  RETURN FOUND;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.heartbeat_notification_delivery_v1(uuid, uuid, timestamp with time zone) OWNER TO periapsis_notification_dispatch_owner;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.heartbeat_notification_delivery_v1(uuid, uuid, timestamp with time zone) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.heartbeat_notification_delivery_v1(uuid, uuid, timestamp with time zone) TO periapsis_notifier;--> statement-breakpoint

CREATE FUNCTION app.reserve_notification_delivery_submission_v1(
  p_delivery_id uuid,
  p_fence_token uuid,
  p_stable_message_id text,
  p_reserved_at timestamp with time zone
)
RETURNS text
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE context_tenant uuid; selected public.tenant_notification_deliveries%ROWTYPE;
BEGIN
  IF p_stable_message_id IS NULL
     OR p_stable_message_id !~ '^<[0-9a-f]{64}@notifications[.]periapsis[.]invalid>$'
     OR p_reserved_at IS NULL
     OR p_reserved_at < transaction_timestamp() - interval '5 minutes'
     OR p_reserved_at > transaction_timestamp() + interval '1 minute' THEN
    RAISE EXCEPTION 'notification reservation input is invalid' USING ERRCODE = '22023';
  END IF;
  context_tenant := app.private_lock_notification_delivery_claim_v1(p_delivery_id, p_fence_token, false);
  SELECT delivery.* INTO STRICT selected
  FROM public.tenant_notification_deliveries AS delivery
  WHERE delivery.tenant_id = context_tenant AND delivery.id = p_delivery_id;
  IF selected.stable_message_id IS NULL THEN
    UPDATE public.tenant_notification_deliveries AS delivery
    SET stable_message_id = p_stable_message_id,
        reserved_at = p_reserved_at,
        status = 'reserved',
        updated_at = p_reserved_at
    WHERE delivery.tenant_id = context_tenant AND delivery.id = p_delivery_id
      AND delivery.fence_token = p_fence_token;
    RETURN 'reserved';
  END IF;
  IF selected.stable_message_id <> p_stable_message_id THEN
    RAISE EXCEPTION 'notification stable message id mismatch' USING ERRCODE = '40001';
  END IF;
  RETURN 'uncertain';
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.reserve_notification_delivery_submission_v1(uuid, uuid, text, timestamp with time zone) OWNER TO periapsis_notification_dispatch_owner;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.reserve_notification_delivery_submission_v1(uuid, uuid, text, timestamp with time zone) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.reserve_notification_delivery_submission_v1(uuid, uuid, text, timestamp with time zone) TO periapsis_notifier;--> statement-breakpoint

CREATE FUNCTION app.complete_notification_delivery_v1(
  p_delivery_id uuid,
  p_fence_token uuid,
  p_response jsonb,
  p_completed_at timestamp with time zone
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE context_tenant uuid; selected public.tenant_notification_deliveries%ROWTYPE;
BEGIN
  IF p_response IS NULL OR jsonb_typeof(p_response) <> 'object'
     OR p_response - ARRAY['provider', 'receiptDigest', 'acceptedCount', 'rejectedCount', 'responseClass']::text[] <> '{}'::jsonb
     OR p_response ->> 'provider' <> 'smtp'
     OR p_response ->> 'receiptDigest' !~ '^[0-9a-f]{64}$'
     OR (p_response ->> 'acceptedCount')::integer <> 1
     OR (p_response ->> 'rejectedCount')::integer <> 0
     OR (p_response ? 'responseClass' AND (p_response ->> 'responseClass')::integer NOT IN (2, 4, 5))
     OR p_completed_at IS NULL
     OR p_completed_at < transaction_timestamp() - interval '5 minutes'
     OR p_completed_at > transaction_timestamp() + interval '1 minute' THEN
    RAISE EXCEPTION 'notification completion input is invalid' USING ERRCODE = '22023';
  END IF;
  context_tenant := app.private_lock_notification_delivery_claim_v1(p_delivery_id, p_fence_token, false);
  SELECT delivery.* INTO STRICT selected
  FROM public.tenant_notification_deliveries AS delivery
  WHERE delivery.tenant_id = context_tenant AND delivery.id = p_delivery_id;
  IF selected.status <> 'reserved' OR selected.stable_message_id IS NULL THEN
    RAISE EXCEPTION 'notification submission is not reserved' USING ERRCODE = '40001';
  END IF;
  UPDATE public.tenant_notification_deliveries AS delivery
  SET status = 'delivered', delivered_at = p_completed_at,
      provider_receipt = p_response, next_attempt_at = NULL,
      lease_owner = NULL, fence_token = NULL, lease_until = NULL,
      failure_at = NULL, failure_class = NULL, failure_code = NULL,
      updated_at = p_completed_at
  WHERE delivery.tenant_id = context_tenant AND delivery.id = p_delivery_id
    AND delivery.fence_token = p_fence_token;
  UPDATE public.tenant_notification_delivery_attempts AS attempt
  SET completed_at = p_completed_at, outcome = 'delivered',
      provider_receipt = p_response
  WHERE attempt.tenant_id = context_tenant
    AND attempt.delivery_id = p_delivery_id
    AND attempt.attempt = selected.attempt_count
    AND attempt.fence_token = p_fence_token
    AND attempt.completed_at IS NULL
    AND attempt.outcome IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'notification delivery attempt is unavailable'
      USING ERRCODE = '40001';
  END IF;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.complete_notification_delivery_v1(uuid, uuid, jsonb, timestamp with time zone) OWNER TO periapsis_notification_dispatch_owner;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.complete_notification_delivery_v1(uuid, uuid, jsonb, timestamp with time zone) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.complete_notification_delivery_v1(uuid, uuid, jsonb, timestamp with time zone) TO periapsis_notifier;--> statement-breakpoint

CREATE FUNCTION app.complete_notification_delivery_replay_v1(
  p_delivery_id uuid,
  p_fence_token uuid,
  p_completed_at timestamp with time zone
)
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_completed_at IS NULL
     OR NOT EXISTS (
       SELECT 1 FROM public.tenant_notification_deliveries AS delivery
       WHERE delivery.id = p_delivery_id
         AND delivery.status = 'delivered'
         AND delivery.stable_message_id IS NOT NULL
     ) THEN
    RAISE EXCEPTION 'notification replay is unavailable' USING ERRCODE = '40001';
  END IF;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.complete_notification_delivery_replay_v1(uuid, uuid, timestamp with time zone) OWNER TO periapsis_notification_dispatch_owner;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.complete_notification_delivery_replay_v1(uuid, uuid, timestamp with time zone) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.complete_notification_delivery_replay_v1(uuid, uuid, timestamp with time zone) TO periapsis_notifier;--> statement-breakpoint

CREATE FUNCTION app.retry_notification_delivery_v1(
  p_delivery_id uuid,
  p_fence_token uuid,
  p_failure_class public.notification_failure_class,
  p_next_attempt_at timestamp with time zone,
  p_failed_at timestamp with time zone
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE context_tenant uuid; selected public.tenant_notification_deliveries%ROWTYPE;
BEGIN
  IF p_failure_class IS NULL OR p_failure_class = 'submission_uncertain'
     OR p_failed_at IS NULL OR p_next_attempt_at IS NULL
     OR p_failed_at < transaction_timestamp() - interval '5 minutes'
     OR p_failed_at > transaction_timestamp() + interval '1 minute'
     OR p_next_attempt_at < p_failed_at + interval '1 second'
     OR p_next_attempt_at > p_failed_at + interval '7 days' THEN
    RAISE EXCEPTION 'notification retry input is invalid' USING ERRCODE = '22023';
  END IF;
  context_tenant := app.private_lock_notification_delivery_claim_v1(p_delivery_id, p_fence_token, false);
  SELECT delivery.* INTO STRICT selected
  FROM public.tenant_notification_deliveries AS delivery
  WHERE delivery.tenant_id = context_tenant AND delivery.id = p_delivery_id;
  IF selected.stable_message_id IS NOT NULL THEN
    RAISE EXCEPTION 'reserved notification delivery cannot be retried safely' USING ERRCODE = '40001';
  END IF;
  UPDATE public.tenant_notification_deliveries AS delivery
  SET status = 'retry_scheduled', next_attempt_at = p_next_attempt_at,
      lease_owner = NULL, fence_token = NULL, lease_until = NULL,
      failure_at = p_failed_at, failure_class = p_failure_class,
      failure_code = 'retry_scheduled', updated_at = p_failed_at
  WHERE delivery.tenant_id = context_tenant AND delivery.id = p_delivery_id
    AND delivery.fence_token = p_fence_token;
  UPDATE public.tenant_notification_delivery_attempts AS attempt
  SET completed_at = p_failed_at, outcome = 'retried',
      failure_class = p_failure_class
  WHERE attempt.tenant_id = context_tenant
    AND attempt.delivery_id = p_delivery_id
    AND attempt.attempt = selected.attempt_count
    AND attempt.fence_token = p_fence_token
    AND attempt.completed_at IS NULL
    AND attempt.outcome IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'notification delivery attempt is unavailable'
      USING ERRCODE = '40001';
  END IF;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.retry_notification_delivery_v1(uuid, uuid, public.notification_failure_class, timestamp with time zone, timestamp with time zone) OWNER TO periapsis_notification_dispatch_owner;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.retry_notification_delivery_v1(uuid, uuid, public.notification_failure_class, timestamp with time zone, timestamp with time zone) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.retry_notification_delivery_v1(uuid, uuid, public.notification_failure_class, timestamp with time zone, timestamp with time zone) TO periapsis_notifier;--> statement-breakpoint

CREATE FUNCTION app.dead_letter_notification_delivery_v1(
  p_delivery_id uuid,
  p_fence_token uuid,
  p_failure_class public.notification_failure_class,
  p_failed_at timestamp with time zone
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE context_tenant uuid; selected public.tenant_notification_deliveries%ROWTYPE;
BEGIN
  IF p_failure_class IS NULL OR p_failed_at IS NULL
     OR p_failed_at < transaction_timestamp() - interval '5 minutes'
     OR p_failed_at > transaction_timestamp() + interval '1 minute' THEN
    RAISE EXCEPTION 'notification dead-letter input is invalid' USING ERRCODE = '22023';
  END IF;
  context_tenant := app.private_lock_notification_delivery_claim_v1(p_delivery_id, p_fence_token, false);
  SELECT delivery.* INTO STRICT selected
  FROM public.tenant_notification_deliveries AS delivery
  WHERE delivery.tenant_id = context_tenant AND delivery.id = p_delivery_id;
  UPDATE public.tenant_notification_deliveries AS delivery
  SET status = 'dead_lettered', next_attempt_at = NULL,
      lease_owner = NULL, fence_token = NULL, lease_until = NULL,
      failure_at = p_failed_at, failure_class = p_failure_class,
      failure_code = CASE WHEN p_failure_class = 'submission_uncertain'
        THEN 'submission_uncertain' ELSE 'terminal_failure' END,
      updated_at = p_failed_at
  WHERE delivery.tenant_id = context_tenant AND delivery.id = p_delivery_id
    AND delivery.fence_token = p_fence_token;
  UPDATE public.tenant_notification_delivery_attempts AS attempt
  SET completed_at = p_failed_at,
      outcome = CASE WHEN p_failure_class = 'submission_uncertain'
        THEN 'uncertain' ELSE 'dead_lettered' END,
      failure_class = p_failure_class
  WHERE attempt.tenant_id = context_tenant
    AND attempt.delivery_id = p_delivery_id
    AND attempt.attempt = selected.attempt_count
    AND attempt.fence_token = p_fence_token
    AND attempt.completed_at IS NULL
    AND attempt.outcome IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'notification delivery attempt is unavailable'
      USING ERRCODE = '40001';
  END IF;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.dead_letter_notification_delivery_v1(uuid, uuid, public.notification_failure_class, timestamp with time zone) OWNER TO periapsis_notification_dispatch_owner;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.dead_letter_notification_delivery_v1(uuid, uuid, public.notification_failure_class, timestamp with time zone) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.dead_letter_notification_delivery_v1(uuid, uuid, public.notification_failure_class, timestamp with time zone) TO periapsis_notifier;--> statement-breakpoint

CREATE FUNCTION app.load_pinned_smtp_configuration_v1(
  p_tenant_id uuid,
  p_configuration_scope text,
  p_configuration_id uuid,
  p_configuration_version integer
)
RETURNS TABLE(
  configuration_scope text,
  tenant_id uuid,
  configuration_id uuid,
  configuration_version integer,
  name text,
  host text,
  port integer,
  security public.notification_smtp_security,
  username text,
  from_name text,
  from_email text,
  reply_to_email text,
  timeout_ms integer,
  maximum_connections integer,
  maximum_messages_per_connection integer,
  rate_limit_per_second integer,
  enabled boolean,
  password_secret_id uuid,
  password_secret_version integer,
  password_secret_kind public.notification_secret_kind,
  password_key_version smallint,
  password_nonce bytea,
  password_ciphertext bytea,
  dkim_domain_name text,
  dkim_selector text,
  dkim_secret_id uuid,
  dkim_secret_version integer,
  dkim_secret_kind public.notification_secret_kind,
  dkim_key_version smallint,
  dkim_nonce bytea,
  dkim_ciphertext bytea
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_tenant_id IS NULL OR p_configuration_scope NOT IN ('tenant', 'platform')
     OR p_configuration_id IS NULL
     OR p_configuration_version NOT BETWEEN 1 AND 2147483647 THEN
    RAISE EXCEPTION 'SMTP pin input is invalid' USING ERRCODE = '22023';
  END IF;
  PERFORM set_config('app.tenant_id', p_tenant_id::text, true);
  IF NOT EXISTS (
    SELECT 1 FROM public.tenants AS tenant
    WHERE tenant.id = p_tenant_id AND tenant.status = 'active'
  ) THEN
    RETURN;
  END IF;

  IF p_configuration_scope = 'tenant' THEN
    RETURN QUERY
    SELECT 'tenant'::text, configuration.tenant_id,
      pinned.configuration_id, pinned.version, pinned.name, pinned.host,
      pinned.port, pinned.security, pinned.username, pinned.from_name,
      pinned.from_email, pinned.reply_to_email, pinned.timeout_ms,
      pinned.maximum_connections, pinned.maximum_messages_per_connection,
      pinned.rate_limit_per_second, pinned.enabled,
      password.secret_id, password.version, password.kind,
      password.key_version, password.nonce, password.ciphertext,
      pinned.dkim_domain_name, pinned.dkim_selector,
      dkim.secret_id, dkim.version, dkim.kind,
      dkim.key_version, dkim.nonce, dkim.ciphertext
    FROM public.tenant_notification_smtp_configurations AS configuration
    JOIN public.tenant_notification_smtp_configuration_versions AS pinned
      ON pinned.tenant_id = configuration.tenant_id
     AND pinned.configuration_id = configuration.id
     AND pinned.version = p_configuration_version
    JOIN public.tenant_notification_smtp_configuration_versions AS current_version
      ON current_version.tenant_id = configuration.tenant_id
     AND current_version.configuration_id = configuration.id
     AND current_version.version = configuration.current_version
    LEFT JOIN public.tenant_notification_secret_versions AS password
      ON password.tenant_id = pinned.tenant_id
     AND password.secret_id = pinned.password_secret_id
     AND password.version = pinned.password_secret_version
     AND password.kind = 'smtp_password'
    LEFT JOIN public.tenant_notification_secret_versions AS dkim
      ON dkim.tenant_id = pinned.tenant_id
     AND dkim.secret_id = pinned.dkim_secret_id
     AND dkim.version = pinned.dkim_secret_version
     AND dkim.kind = 'smtp_dkim_private_key'
    WHERE configuration.tenant_id = p_tenant_id
      AND configuration.id = p_configuration_id
      AND configuration.revoked_at IS NULL
      AND pinned.enabled AND current_version.enabled
      AND (pinned.password_secret_id IS NULL OR password.secret_id IS NOT NULL)
      AND (pinned.dkim_secret_id IS NULL OR dkim.secret_id IS NOT NULL);
    RETURN;
  END IF;

  RETURN QUERY
  SELECT 'platform'::text, NULL::uuid,
    pinned.configuration_id, pinned.version, pinned.name, pinned.host,
    pinned.port, pinned.security, pinned.username, pinned.from_name,
    pinned.from_email, pinned.reply_to_email, pinned.timeout_ms,
    pinned.maximum_connections, pinned.maximum_messages_per_connection,
    pinned.rate_limit_per_second, pinned.enabled,
    password.secret_id, password.version, password.kind,
    password.key_version, password.nonce, password.ciphertext,
    pinned.dkim_domain_name, pinned.dkim_selector,
    dkim.secret_id, dkim.version, dkim.kind,
    dkim.key_version, dkim.nonce, dkim.ciphertext
  FROM public.platform_notification_smtp_configurations AS configuration
  JOIN public.platform_notification_smtp_configuration_versions AS pinned
    ON pinned.configuration_id = configuration.id
   AND pinned.version = p_configuration_version
  JOIN public.platform_notification_smtp_configuration_versions AS current_version
    ON current_version.configuration_id = configuration.id
   AND current_version.version = configuration.current_version
  LEFT JOIN public.platform_notification_secret_versions AS password
    ON password.secret_id = pinned.password_secret_id
   AND password.version = pinned.password_secret_version
   AND password.kind = 'smtp_password'
  LEFT JOIN public.platform_notification_secret_versions AS dkim
    ON dkim.secret_id = pinned.dkim_secret_id
   AND dkim.version = pinned.dkim_secret_version
   AND dkim.kind = 'smtp_dkim_private_key'
  WHERE configuration.id = p_configuration_id
    AND configuration.revoked_at IS NULL
    AND pinned.enabled AND current_version.enabled
    AND (pinned.password_secret_id IS NULL OR password.secret_id IS NOT NULL)
    AND (pinned.dkim_secret_id IS NULL OR dkim.secret_id IS NOT NULL);
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.load_pinned_smtp_configuration_v1(uuid, text, uuid, integer) OWNER TO periapsis_notification_dispatch_owner;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.load_pinned_smtp_configuration_v1(uuid, text, uuid, integer) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.load_pinned_smtp_configuration_v1(uuid, text, uuid, integer) TO periapsis_notifier;--> statement-breakpoint

CREATE FUNCTION app.claim_notification_webhook_delivery_batch_v1(
  p_worker_id text,
  p_limit integer,
  p_lease_duration_ms integer,
  p_now timestamp with time zone
)
RETURNS TABLE(claim jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_worker_id IS NULL OR p_worker_id !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
     OR p_limit NOT BETWEEN 1 AND 100
     OR p_lease_duration_ms NOT BETWEEN 5000 AND 300000
     OR p_now IS NULL
     OR p_now < transaction_timestamp() - interval '1 minute'
     OR p_now > transaction_timestamp() + interval '1 minute' THEN
    RAISE EXCEPTION 'notification webhook claim input is invalid' USING ERRCODE = '22023';
  END IF;

  UPDATE public.tenant_notification_delivery_attempts AS attempt
  SET completed_at = p_now, outcome = 'fenced', failure_class = 'security'
  FROM public.tenant_notification_deliveries AS delivery
  WHERE attempt.tenant_id = delivery.tenant_id
    AND attempt.delivery_id = delivery.id
    AND attempt.attempt = delivery.attempt_count
    AND attempt.completed_at IS NULL
    AND attempt.outcome IS NULL
    AND delivery.channel = 'webhook'
    AND delivery.status IN ('leased', 'reserved')
    AND NOT EXISTS (
      SELECT 1
      FROM public.tenant_notification_webhook_configurations AS identity
      JOIN public.tenant_notification_webhook_configuration_versions AS pinned
        ON pinned.tenant_id = identity.tenant_id
       AND pinned.configuration_id = identity.id
       AND pinned.version = delivery.webhook_configuration_version
      JOIN public.tenant_notification_webhook_configuration_versions AS current_version
        ON current_version.tenant_id = identity.tenant_id
       AND current_version.configuration_id = identity.id
       AND current_version.version = identity.current_version
      JOIN public.tenant_notification_secret_versions AS secret
        ON secret.tenant_id = identity.tenant_id
       AND secret.secret_id = delivery.webhook_signing_secret_id
       AND secret.version = delivery.webhook_signing_secret_version
       AND secret.kind = 'webhook_signing_key'
       AND secret.key_version = delivery.webhook_signing_key_version
      WHERE identity.tenant_id = delivery.tenant_id
        AND identity.id = delivery.webhook_configuration_id
        AND identity.revoked_at IS NULL
        AND pinned.enabled
        AND current_version.enabled
    );

  UPDATE public.tenant_notification_deliveries AS delivery
  SET status = 'dead_lettered', next_attempt_at = NULL,
      lease_owner = NULL, fence_token = NULL, lease_until = NULL,
      failure_at = p_now, failure_class = 'security',
      failure_code = 'configuration_revoked', updated_at = p_now
  WHERE delivery.channel = 'webhook'
    AND delivery.status IN ('queued', 'retry_scheduled', 'leased', 'reserved')
    AND NOT EXISTS (
      SELECT 1
      FROM public.tenant_notification_webhook_configurations AS identity
      JOIN public.tenant_notification_webhook_configuration_versions AS pinned
        ON pinned.tenant_id = identity.tenant_id
       AND pinned.configuration_id = identity.id
       AND pinned.version = delivery.webhook_configuration_version
      JOIN public.tenant_notification_webhook_configuration_versions AS current_version
        ON current_version.tenant_id = identity.tenant_id
       AND current_version.configuration_id = identity.id
       AND current_version.version = identity.current_version
      JOIN public.tenant_notification_secret_versions AS secret
        ON secret.tenant_id = identity.tenant_id
       AND secret.secret_id = delivery.webhook_signing_secret_id
       AND secret.version = delivery.webhook_signing_secret_version
       AND secret.kind = 'webhook_signing_key'
       AND secret.key_version = delivery.webhook_signing_key_version
      WHERE identity.tenant_id = delivery.tenant_id
        AND identity.id = delivery.webhook_configuration_id
        AND identity.revoked_at IS NULL
        AND pinned.enabled
        AND current_version.enabled
    );

  RETURN QUERY
  WITH candidate AS (
    SELECT delivery.id
    FROM public.tenant_notification_deliveries AS delivery
    WHERE delivery.channel = 'webhook'
      AND delivery.status IN ('queued', 'retry_scheduled', 'leased', 'reserved')
      AND delivery.attempt_count < delivery.maximum_attempts
      AND (delivery.status IN ('leased', 'reserved') AND delivery.lease_until <= p_now
        OR delivery.status IN ('queued', 'retry_scheduled') AND delivery.next_attempt_at <= p_now)
      AND EXISTS (
        SELECT 1
        FROM public.tenant_notification_webhook_configurations AS identity
        JOIN public.tenant_notification_webhook_configuration_versions AS pinned
          ON pinned.tenant_id = identity.tenant_id
         AND pinned.configuration_id = identity.id
         AND pinned.version = delivery.webhook_configuration_version
        JOIN public.tenant_notification_webhook_configuration_versions AS current_version
          ON current_version.tenant_id = identity.tenant_id
         AND current_version.configuration_id = identity.id
         AND current_version.version = identity.current_version
        JOIN public.tenant_notification_secret_versions AS secret
          ON secret.tenant_id = identity.tenant_id
         AND secret.secret_id = delivery.webhook_signing_secret_id
         AND secret.version = delivery.webhook_signing_secret_version
         AND secret.kind = 'webhook_signing_key'
         AND secret.key_version = delivery.webhook_signing_key_version
        WHERE identity.tenant_id = delivery.tenant_id
          AND identity.id = delivery.webhook_configuration_id
          AND identity.revoked_at IS NULL
          AND pinned.enabled
          AND current_version.enabled
      )
    ORDER BY delivery.priority DESC, delivery.next_attempt_at, delivery.created_at, delivery.id
    LIMIT p_limit
    FOR UPDATE SKIP LOCKED
  ), fenced AS (
    UPDATE public.tenant_notification_delivery_attempts AS attempt
    SET completed_at = p_now, outcome = 'fenced'
    FROM candidate
    JOIN public.tenant_notification_deliveries AS previous
      ON previous.id = candidate.id
    WHERE attempt.tenant_id = previous.tenant_id
      AND attempt.delivery_id = previous.id
      AND attempt.attempt = previous.attempt_count
      AND attempt.completed_at IS NULL
      AND attempt.outcome IS NULL
    RETURNING attempt.tenant_id, attempt.delivery_id, attempt.attempt
  ), claimed AS (
    UPDATE public.tenant_notification_deliveries AS delivery
    SET status = 'leased', attempt_count = delivery.attempt_count + 1,
        lease_owner = p_worker_id, fence_token = uuidv7(),
        lease_until = p_now + make_interval(secs => p_lease_duration_ms::double precision / 1000.0),
        updated_at = p_now
    FROM candidate
    WHERE delivery.id = candidate.id
      AND (SELECT count(*) FROM fenced) >= 0
    RETURNING delivery.*
  ), started AS (
    INSERT INTO public.tenant_notification_delivery_attempts (
      tenant_id, delivery_id, attempt, fence_token, started_at
    )
    SELECT claimed.tenant_id, claimed.id, claimed.attempt_count,
           claimed.fence_token, p_now
    FROM claimed
    RETURNING tenant_id, delivery_id, attempt
  )
  SELECT jsonb_build_object(
    'id', claimed.id,
    'tenantId', claimed.tenant_id,
    'eventId', claimed.event_id,
    'configurationId', claimed.webhook_configuration_id,
    'configurationVersion', claimed.webhook_configuration_version,
    'endpointUrl', configuration.endpoint_url,
    'timeoutMs', configuration.timeout_ms,
    'payload', claimed.webhook_payload,
    'signingKey', jsonb_build_object(
      'tenantId', secret.tenant_id,
      'secretId', secret.secret_id,
      'secretVersion', secret.version,
      'kind', secret.kind,
      'keyVersion', secret.key_version,
      'nonce', encode(secret.nonce, 'base64'),
      'ciphertext', encode(secret.ciphertext, 'base64')
    ),
    'createdAt', claimed.created_at,
    'attemptAt', p_now,
    'retry', claimed.retry,
    'attempt', claimed.attempt_count,
    'fenceToken', claimed.fence_token,
    'leaseUntil', claimed.lease_until
  )
  FROM claimed
  JOIN started
    ON started.tenant_id = claimed.tenant_id
   AND started.delivery_id = claimed.id
   AND started.attempt = claimed.attempt_count
  JOIN public.tenant_notification_webhook_configurations AS identity
    ON identity.tenant_id = claimed.tenant_id
   AND identity.id = claimed.webhook_configuration_id
   AND identity.revoked_at IS NULL
  JOIN public.tenant_notification_webhook_configuration_versions AS configuration
    ON configuration.tenant_id = identity.tenant_id
   AND configuration.configuration_id = identity.id
   AND configuration.version = claimed.webhook_configuration_version
   AND configuration.enabled
  JOIN public.tenant_notification_webhook_configuration_versions AS current_version
    ON current_version.tenant_id = identity.tenant_id
   AND current_version.configuration_id = identity.id
   AND current_version.version = identity.current_version
   AND current_version.enabled
  JOIN public.tenant_notification_secret_versions AS secret
    ON secret.tenant_id = claimed.tenant_id
   AND secret.secret_id = claimed.webhook_signing_secret_id
   AND secret.version = claimed.webhook_signing_secret_version
   AND secret.kind = 'webhook_signing_key'
   AND secret.key_version = claimed.webhook_signing_key_version
  ORDER BY claimed.priority DESC, claimed.next_attempt_at, claimed.created_at, claimed.id;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.claim_notification_webhook_delivery_batch_v1(text, integer, integer, timestamp with time zone) OWNER TO periapsis_notification_dispatch_owner;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.claim_notification_webhook_delivery_batch_v1(text, integer, integer, timestamp with time zone) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.claim_notification_webhook_delivery_batch_v1(text, integer, integer, timestamp with time zone) TO periapsis_notifier;--> statement-breakpoint

CREATE FUNCTION app.reserve_notification_delivery_submission_v2(
  p_delivery_id uuid,
  p_fence_token uuid,
  p_channel public.notification_channel,
  p_reservation_id text,
  p_reserved_at timestamp with time zone
)
RETURNS text
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid;
  selected public.tenant_notification_deliveries%ROWTYPE;
BEGIN
  IF p_delivery_id IS NULL OR p_fence_token IS NULL OR p_channel IS NULL
     OR p_reservation_id IS NULL
     OR p_reservation_id !~ '^<[0-9a-f]{64}@notifications[.]periapsis[.]invalid>$'
     OR p_reserved_at IS NULL
     OR p_reserved_at < transaction_timestamp() - interval '5 minutes'
     OR p_reserved_at > transaction_timestamp() + interval '1 minute' THEN
    RAISE EXCEPTION 'notification reservation input is invalid' USING ERRCODE = '22023';
  END IF;

  SELECT delivery.* INTO selected
  FROM public.tenant_notification_deliveries AS delivery
  WHERE delivery.id = p_delivery_id;
  IF FOUND AND selected.status = 'delivered' THEN
    IF selected.channel = p_channel
       AND selected.stable_message_id = p_reservation_id
       AND EXISTS (
         SELECT 1
         FROM public.tenant_notification_delivery_attempts AS attempt
         WHERE attempt.tenant_id = selected.tenant_id
           AND attempt.delivery_id = selected.id
           AND attempt.fence_token = p_fence_token
           AND attempt.outcome = 'delivered'
       ) THEN
      RETURN 'already_delivered';
    END IF;
    RAISE EXCEPTION 'notification reservation does not match delivered state'
      USING ERRCODE = '40001';
  END IF;

  context_tenant := app.private_lock_notification_delivery_claim_v1(
    p_delivery_id, p_fence_token, false
  );
  SELECT delivery.* INTO STRICT selected
  FROM public.tenant_notification_deliveries AS delivery
  WHERE delivery.tenant_id = context_tenant AND delivery.id = p_delivery_id;

  IF selected.channel <> p_channel THEN
    RAISE EXCEPTION 'notification reservation channel mismatch'
      USING ERRCODE = '40001';
  END IF;
  IF selected.stable_message_id IS NULL THEN
    UPDATE public.tenant_notification_deliveries AS delivery
    SET stable_message_id = p_reservation_id,
        reserved_at = p_reserved_at,
        status = 'reserved',
        updated_at = p_reserved_at
    WHERE delivery.tenant_id = context_tenant
      AND delivery.id = p_delivery_id
      AND delivery.fence_token = p_fence_token;
    RETURN 'reserved';
  END IF;
  IF selected.stable_message_id <> p_reservation_id THEN
    RAISE EXCEPTION 'notification reservation id mismatch'
      USING ERRCODE = '40001';
  END IF;
  IF selected.status = 'reserved' AND selected.fence_token = p_fence_token THEN
    RETURN 'reserved';
  END IF;
  RETURN 'uncertain';
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.reserve_notification_delivery_submission_v2(uuid, uuid, public.notification_channel, text, timestamp with time zone) OWNER TO periapsis_notification_dispatch_owner;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.reserve_notification_delivery_submission_v2(uuid, uuid, public.notification_channel, text, timestamp with time zone) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.reserve_notification_delivery_submission_v2(uuid, uuid, public.notification_channel, text, timestamp with time zone) TO periapsis_notifier;--> statement-breakpoint

CREATE FUNCTION app.complete_notification_delivery_v2(
  p_delivery_id uuid,
  p_fence_token uuid,
  p_channel public.notification_channel,
  p_response jsonb,
  p_completed_at timestamp with time zone
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid;
  selected public.tenant_notification_deliveries%ROWTYPE;
BEGIN
  IF p_delivery_id IS NULL OR p_fence_token IS NULL OR p_channel IS NULL
     OR p_response IS NULL OR jsonb_typeof(p_response) <> 'object'
     OR p_completed_at IS NULL
     OR p_completed_at < transaction_timestamp() - interval '5 minutes'
     OR p_completed_at > transaction_timestamp() + interval '1 minute'
     OR (p_channel = 'email' AND (
       NOT (p_response ?& ARRAY['provider', 'receiptDigest', 'acceptedCount', 'rejectedCount'])
       OR p_response - ARRAY['provider', 'receiptDigest', 'acceptedCount', 'rejectedCount', 'responseClass']::text[] <> '{}'::jsonb
       OR p_response ->> 'provider' <> 'smtp'
       OR p_response ->> 'receiptDigest' !~ '^[0-9a-f]{64}$'
       OR p_response ->> 'acceptedCount' !~ '^[0-9]+$'
       OR p_response ->> 'rejectedCount' !~ '^[0-9]+$'
       OR (p_response ->> 'acceptedCount')::integer <> 1
       OR (p_response ->> 'rejectedCount')::integer <> 0
       OR (p_response ? 'responseClass' AND p_response ->> 'responseClass' <> '2')
     ))
     OR (p_channel = 'webhook' AND (
       NOT (p_response ?& ARRAY['provider', 'receiptDigest', 'statusCode'])
       OR p_response - ARRAY['provider', 'receiptDigest', 'statusCode']::text[] <> '{}'::jsonb
       OR p_response ->> 'provider' <> 'webhook'
       OR p_response ->> 'receiptDigest' !~ '^[0-9a-f]{64}$'
       OR p_response ->> 'statusCode' !~ '^[0-9]{3}$'
       OR (p_response ->> 'statusCode')::integer NOT BETWEEN 200 AND 299
     )) THEN
    RAISE EXCEPTION 'notification completion input is invalid' USING ERRCODE = '22023';
  END IF;

  SELECT delivery.* INTO selected
  FROM public.tenant_notification_deliveries AS delivery
  WHERE delivery.id = p_delivery_id;
  IF FOUND AND selected.status = 'delivered' THEN
    IF selected.channel = p_channel
       AND selected.provider_receipt = p_response
       AND EXISTS (
         SELECT 1
         FROM public.tenant_notification_delivery_attempts AS attempt
         WHERE attempt.tenant_id = selected.tenant_id
           AND attempt.delivery_id = selected.id
           AND attempt.fence_token = p_fence_token
           AND attempt.outcome = 'delivered'
           AND attempt.provider_receipt = p_response
       ) THEN
      RETURN;
    END IF;
    RAISE EXCEPTION 'notification completion does not match delivered state'
      USING ERRCODE = '40001';
  END IF;

  context_tenant := app.private_lock_notification_delivery_claim_v1(
    p_delivery_id, p_fence_token, false
  );
  SELECT delivery.* INTO STRICT selected
  FROM public.tenant_notification_deliveries AS delivery
  WHERE delivery.tenant_id = context_tenant AND delivery.id = p_delivery_id;
  IF selected.channel <> p_channel
     OR selected.status <> 'reserved'
     OR selected.stable_message_id IS NULL THEN
    RAISE EXCEPTION 'notification submission is not reserved for this channel'
      USING ERRCODE = '40001';
  END IF;

  UPDATE public.tenant_notification_deliveries AS delivery
  SET status = 'delivered', delivered_at = p_completed_at,
      provider_receipt = p_response, next_attempt_at = NULL,
      lease_owner = NULL, fence_token = NULL, lease_until = NULL,
      failure_at = NULL, failure_class = NULL, failure_code = NULL,
      updated_at = p_completed_at
  WHERE delivery.tenant_id = context_tenant
    AND delivery.id = p_delivery_id
    AND delivery.fence_token = p_fence_token;
  UPDATE public.tenant_notification_delivery_attempts AS attempt
  SET completed_at = p_completed_at, outcome = 'delivered',
      provider_receipt = p_response
  WHERE attempt.tenant_id = context_tenant
    AND attempt.delivery_id = p_delivery_id
    AND attempt.attempt = selected.attempt_count
    AND attempt.fence_token = p_fence_token
    AND attempt.completed_at IS NULL
    AND attempt.outcome IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'notification delivery attempt is unavailable'
      USING ERRCODE = '40001';
  END IF;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.complete_notification_delivery_v2(uuid, uuid, public.notification_channel, jsonb, timestamp with time zone) OWNER TO periapsis_notification_dispatch_owner;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.complete_notification_delivery_v2(uuid, uuid, public.notification_channel, jsonb, timestamp with time zone) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.complete_notification_delivery_v2(uuid, uuid, public.notification_channel, jsonb, timestamp with time zone) TO periapsis_notifier;--> statement-breakpoint

CREATE FUNCTION app.complete_notification_delivery_replay_v2(
  p_delivery_id uuid,
  p_fence_token uuid,
  p_channel public.notification_channel,
  p_completed_at timestamp with time zone
)
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_delivery_id IS NULL OR p_fence_token IS NULL OR p_channel IS NULL
     OR p_completed_at IS NULL
     OR p_completed_at < transaction_timestamp() - interval '5 minutes'
     OR p_completed_at > transaction_timestamp() + interval '1 minute'
     OR NOT EXISTS (
       SELECT 1
       FROM public.tenant_notification_deliveries AS delivery
       WHERE delivery.id = p_delivery_id
         AND delivery.channel = p_channel
         AND delivery.status = 'delivered'
         AND delivery.stable_message_id IS NOT NULL
         AND EXISTS (
           SELECT 1
           FROM public.tenant_notification_delivery_attempts AS attempt
           WHERE attempt.tenant_id = delivery.tenant_id
             AND attempt.delivery_id = delivery.id
             AND attempt.fence_token = p_fence_token
             AND attempt.outcome = 'delivered'
         )
     ) THEN
    RAISE EXCEPTION 'notification replay is unavailable' USING ERRCODE = '40001';
  END IF;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.complete_notification_delivery_replay_v2(uuid, uuid, public.notification_channel, timestamp with time zone) OWNER TO periapsis_notification_dispatch_owner;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.complete_notification_delivery_replay_v2(uuid, uuid, public.notification_channel, timestamp with time zone) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.complete_notification_delivery_replay_v2(uuid, uuid, public.notification_channel, timestamp with time zone) TO periapsis_notifier;--> statement-breakpoint

CREATE FUNCTION app.retry_notification_delivery_v2(
  p_delivery_id uuid,
  p_fence_token uuid,
  p_channel public.notification_channel,
  p_failure_class public.notification_failure_class,
  p_next_attempt_at timestamp with time zone,
  p_failed_at timestamp with time zone,
  p_safe_after_reservation boolean
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid;
  selected public.tenant_notification_deliveries%ROWTYPE;
BEGIN
  IF p_delivery_id IS NULL OR p_fence_token IS NULL OR p_channel IS NULL
     OR p_failure_class IS NULL OR p_failure_class = 'submission_uncertain'
     OR p_safe_after_reservation IS NULL
     OR p_failed_at IS NULL OR p_next_attempt_at IS NULL
     OR p_failed_at < transaction_timestamp() - interval '5 minutes'
     OR p_failed_at > transaction_timestamp() + interval '1 minute'
     OR p_next_attempt_at < p_failed_at + interval '1 second'
     OR p_next_attempt_at > p_failed_at + interval '7 days' THEN
    RAISE EXCEPTION 'notification retry input is invalid' USING ERRCODE = '22023';
  END IF;

  SELECT delivery.* INTO selected
  FROM public.tenant_notification_deliveries AS delivery
  WHERE delivery.id = p_delivery_id;
  IF FOUND AND selected.status = 'retry_scheduled' THEN
    IF selected.channel = p_channel
       AND selected.next_attempt_at = p_next_attempt_at
       AND selected.failure_at = p_failed_at
       AND selected.failure_class = p_failure_class
       AND EXISTS (
         SELECT 1
         FROM public.tenant_notification_delivery_attempts AS attempt
         WHERE attempt.tenant_id = selected.tenant_id
           AND attempt.delivery_id = selected.id
           AND attempt.fence_token = p_fence_token
           AND attempt.outcome = 'retried'
           AND attempt.failure_class = p_failure_class
       ) THEN
      RETURN;
    END IF;
    RAISE EXCEPTION 'notification retry does not match persisted state'
      USING ERRCODE = '40001';
  END IF;

  context_tenant := app.private_lock_notification_delivery_claim_v1(
    p_delivery_id, p_fence_token, false
  );
  SELECT delivery.* INTO STRICT selected
  FROM public.tenant_notification_deliveries AS delivery
  WHERE delivery.tenant_id = context_tenant AND delivery.id = p_delivery_id;
  IF selected.channel <> p_channel THEN
    RAISE EXCEPTION 'notification retry channel mismatch' USING ERRCODE = '40001';
  END IF;
  IF selected.stable_message_id IS NOT NULL
     AND (NOT p_safe_after_reservation OR selected.status <> 'reserved') THEN
    RAISE EXCEPTION 'reserved notification delivery cannot be retried safely'
      USING ERRCODE = '40001';
  END IF;

  UPDATE public.tenant_notification_deliveries AS delivery
  SET status = 'retry_scheduled', next_attempt_at = p_next_attempt_at,
      lease_owner = NULL, fence_token = NULL, lease_until = NULL,
      stable_message_id = CASE WHEN p_safe_after_reservation THEN NULL ELSE delivery.stable_message_id END,
      reserved_at = CASE WHEN p_safe_after_reservation THEN NULL ELSE delivery.reserved_at END,
      failure_at = p_failed_at, failure_class = p_failure_class,
      failure_code = 'retry_scheduled', updated_at = p_failed_at
  WHERE delivery.tenant_id = context_tenant
    AND delivery.id = p_delivery_id
    AND delivery.fence_token = p_fence_token;
  UPDATE public.tenant_notification_delivery_attempts AS attempt
  SET completed_at = p_failed_at, outcome = 'retried',
      failure_class = p_failure_class
  WHERE attempt.tenant_id = context_tenant
    AND attempt.delivery_id = p_delivery_id
    AND attempt.attempt = selected.attempt_count
    AND attempt.fence_token = p_fence_token
    AND attempt.completed_at IS NULL
    AND attempt.outcome IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'notification delivery attempt is unavailable'
      USING ERRCODE = '40001';
  END IF;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.retry_notification_delivery_v2(uuid, uuid, public.notification_channel, public.notification_failure_class, timestamp with time zone, timestamp with time zone, boolean) OWNER TO periapsis_notification_dispatch_owner;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.retry_notification_delivery_v2(uuid, uuid, public.notification_channel, public.notification_failure_class, timestamp with time zone, timestamp with time zone, boolean) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.retry_notification_delivery_v2(uuid, uuid, public.notification_channel, public.notification_failure_class, timestamp with time zone, timestamp with time zone, boolean) TO periapsis_notifier;--> statement-breakpoint

CREATE FUNCTION app.dead_letter_notification_delivery_v2(
  p_delivery_id uuid,
  p_fence_token uuid,
  p_channel public.notification_channel,
  p_failure_class public.notification_failure_class,
  p_failed_at timestamp with time zone
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid;
  selected public.tenant_notification_deliveries%ROWTYPE;
BEGIN
  IF p_delivery_id IS NULL OR p_fence_token IS NULL OR p_channel IS NULL
     OR p_failure_class IS NULL OR p_failed_at IS NULL
     OR p_failed_at < transaction_timestamp() - interval '5 minutes'
     OR p_failed_at > transaction_timestamp() + interval '1 minute' THEN
    RAISE EXCEPTION 'notification dead-letter input is invalid' USING ERRCODE = '22023';
  END IF;

  SELECT delivery.* INTO selected
  FROM public.tenant_notification_deliveries AS delivery
  WHERE delivery.id = p_delivery_id;
  IF FOUND AND selected.status = 'dead_lettered' THEN
    IF selected.channel = p_channel
       AND selected.failure_at = p_failed_at
       AND selected.failure_class = p_failure_class
       AND EXISTS (
         SELECT 1
         FROM public.tenant_notification_delivery_attempts AS attempt
         WHERE attempt.tenant_id = selected.tenant_id
           AND attempt.delivery_id = selected.id
           AND attempt.fence_token = p_fence_token
           AND attempt.failure_class = p_failure_class
           AND attempt.outcome IN ('dead_lettered', 'uncertain')
       ) THEN
      RETURN;
    END IF;
    RAISE EXCEPTION 'notification dead-letter does not match persisted state'
      USING ERRCODE = '40001';
  END IF;

  context_tenant := app.private_lock_notification_delivery_claim_v1(
    p_delivery_id, p_fence_token, false
  );
  SELECT delivery.* INTO STRICT selected
  FROM public.tenant_notification_deliveries AS delivery
  WHERE delivery.tenant_id = context_tenant AND delivery.id = p_delivery_id;
  IF selected.channel <> p_channel THEN
    RAISE EXCEPTION 'notification dead-letter channel mismatch'
      USING ERRCODE = '40001';
  END IF;
  UPDATE public.tenant_notification_deliveries AS delivery
  SET status = 'dead_lettered', next_attempt_at = NULL,
      lease_owner = NULL, fence_token = NULL, lease_until = NULL,
      failure_at = p_failed_at, failure_class = p_failure_class,
      failure_code = CASE WHEN p_failure_class = 'submission_uncertain'
        THEN 'submission_uncertain' ELSE 'terminal_failure' END,
      updated_at = p_failed_at
  WHERE delivery.tenant_id = context_tenant
    AND delivery.id = p_delivery_id
    AND delivery.fence_token = p_fence_token;
  UPDATE public.tenant_notification_delivery_attempts AS attempt
  SET completed_at = p_failed_at,
      outcome = CASE WHEN p_failure_class = 'submission_uncertain'
        THEN 'uncertain' ELSE 'dead_lettered' END,
      failure_class = p_failure_class
  WHERE attempt.tenant_id = context_tenant
    AND attempt.delivery_id = p_delivery_id
    AND attempt.attempt = selected.attempt_count
    AND attempt.fence_token = p_fence_token
    AND attempt.completed_at IS NULL
    AND attempt.outcome IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'notification delivery attempt is unavailable'
      USING ERRCODE = '40001';
  END IF;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.dead_letter_notification_delivery_v2(uuid, uuid, public.notification_channel, public.notification_failure_class, timestamp with time zone) OWNER TO periapsis_notification_dispatch_owner;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.dead_letter_notification_delivery_v2(uuid, uuid, public.notification_channel, public.notification_failure_class, timestamp with time zone) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.dead_letter_notification_delivery_v2(uuid, uuid, public.notification_channel, public.notification_failure_class, timestamp with time zone) TO periapsis_notifier;--> statement-breakpoint

REVOKE EXECUTE ON FUNCTION app.reserve_notification_delivery_submission_v1(uuid, uuid, text, timestamp with time zone) FROM periapsis_notifier;--> statement-breakpoint
REVOKE EXECUTE ON FUNCTION app.complete_notification_delivery_v1(uuid, uuid, jsonb, timestamp with time zone) FROM periapsis_notifier;--> statement-breakpoint
REVOKE EXECUTE ON FUNCTION app.complete_notification_delivery_replay_v1(uuid, uuid, timestamp with time zone) FROM periapsis_notifier;--> statement-breakpoint
REVOKE EXECUTE ON FUNCTION app.retry_notification_delivery_v1(uuid, uuid, public.notification_failure_class, timestamp with time zone, timestamp with time zone) FROM periapsis_notifier;--> statement-breakpoint
REVOKE EXECUTE ON FUNCTION app.dead_letter_notification_delivery_v1(uuid, uuid, public.notification_failure_class, timestamp with time zone) FROM periapsis_notifier;
