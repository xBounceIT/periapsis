-- SMTP runtime assurance: exact-pinned health diagnostics, transactionally
-- coupled delivery evidence, and rolling-compatible notifier ABI successors.

CREATE FUNCTION app.load_pinned_smtp_configuration_v2(
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
  IF p_configuration_scope IS NULL
     OR p_configuration_scope NOT IN ('tenant', 'platform')
     OR p_configuration_id IS NULL
     OR p_configuration_version IS NULL
     OR p_configuration_version NOT BETWEEN 1 AND 2147483647
     OR p_configuration_scope = 'tenant' AND p_tenant_id IS NULL THEN
    RAISE EXCEPTION 'SMTP pin input is invalid' USING ERRCODE = '22023';
  END IF;

  IF p_tenant_id IS NULL THEN
    PERFORM set_config('app.tenant_id', '', true);
  ELSE
    PERFORM set_config('app.tenant_id', p_tenant_id::text, true);
    IF NOT EXISTS (
      SELECT 1
      FROM public.tenants AS tenant
      WHERE tenant.id = p_tenant_id AND tenant.status = 'active'
    ) THEN
      RETURN;
    END IF;
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
$function$;
--> statement-breakpoint
ALTER FUNCTION app.load_pinned_smtp_configuration_v2(uuid, text, uuid, integer)
OWNER TO periapsis_notification_dispatch_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.load_pinned_smtp_configuration_v2(uuid, text, uuid, integer)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_auditor,
  periapsis_notification_admin_owner, periapsis_notification_readiness_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.load_pinned_smtp_configuration_v2(uuid, text, uuid, integer)
TO periapsis_notifier;
--> statement-breakpoint

CREATE FUNCTION app.test_tenant_notification_smtp_v2(
  p_configuration_version integer,
  p_delivery_id uuid,
  p_recipient text,
  p_reason text,
  p_key_digest bytea,
  p_request_digest bytea,
  p_occurred_at timestamp with time zone,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE(projection jsonb, replayed boolean)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  legacy_projection jsonb;
  legacy_replayed boolean;
  pin record;
  queued_delivery_id uuid;
BEGIN
  SELECT tested.projection, tested.replayed
  INTO STRICT legacy_projection, legacy_replayed
  FROM app.test_tenant_notification_smtp_v1(
    p_configuration_version, p_delivery_id, p_recipient, p_reason,
    p_key_digest, p_request_digest, p_occurred_at, p_request_id,
    p_correlation_id, p_ip_address, p_user_agent, p_authentication_method
  ) AS tested;

  SELECT * INTO STRICT pin
  FROM app.private_resolve_tenant_notification_smtp_pin_v1(
    p_configuration_version
  );
  IF jsonb_typeof(legacy_projection) <> 'object'
     OR NOT (legacy_projection ?& ARRAY[
       'configurationId', 'configurationVersion', 'healthy', 'checkedAt',
       'checks', 'queuedDeliveryId'
     ])
     OR legacy_projection - ARRAY[
       'configurationId', 'configurationVersion', 'healthy', 'checkedAt',
       'checks', 'queuedDeliveryId'
     ]::text[] <> '{}'::jsonb
     OR legacy_projection ->> 'configurationId' <> pin.configuration_id::text
     OR (legacy_projection ->> 'configurationVersion')::integer
          <> pin.configuration_version
     OR legacy_projection ->> 'healthy' <> 'true'
     OR legacy_projection -> 'checks' <> jsonb_build_array(
       jsonb_build_object('kind', 'connect', 'outcome', 'skipped')
     ) THEN
    RAISE EXCEPTION 'SMTP preflight predecessor returned an invalid projection'
      USING ERRCODE = '55000';
  END IF;
  queued_delivery_id := (legacy_projection ->> 'queuedDeliveryId')::uuid;
  IF queued_delivery_id IS NOT NULL
     AND uuid_extract_version(queued_delivery_id) <> 7 THEN
    RAISE EXCEPTION 'SMTP preflight predecessor returned an invalid delivery'
      USING ERRCODE = '55000';
  END IF;

  projection := jsonb_build_object(
    'configurationId', pin.configuration_id,
    'configurationVersion', pin.configuration_version,
    'configurationScope', pin.configuration_scope,
    'queuedDeliveryId', queued_delivery_id
  );
  replayed := legacy_replayed;
  RETURN NEXT;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.test_tenant_notification_smtp_v2(
  integer, uuid, text, text, bytea, bytea, timestamp with time zone,
  uuid, uuid, inet, text, text
) OWNER TO periapsis_notification_admin_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.test_tenant_notification_smtp_v2(
  integer, uuid, text, text, bytea, bytea, timestamp with time zone,
  uuid, uuid, inet, text, text
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor,
  periapsis_notification_dispatch_owner, periapsis_notification_readiness_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.test_tenant_notification_smtp_v2(
  integer, uuid, text, text, bytea, bytea, timestamp with time zone,
  uuid, uuid, inet, text, text
) TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.test_platform_notification_smtp_v2(
  p_configuration_version integer,
  p_recipient text,
  p_reason text,
  p_key_digest bytea,
  p_request_digest bytea,
  p_occurred_at timestamp with time zone,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE(projection jsonb, replayed boolean)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  legacy_projection jsonb;
  legacy_replayed boolean;
BEGIN
  SELECT tested.projection, tested.replayed
  INTO STRICT legacy_projection, legacy_replayed
  FROM app.test_platform_notification_smtp_v1(
    p_configuration_version, p_recipient, p_reason, p_key_digest,
    p_request_digest, p_occurred_at, p_request_id, p_correlation_id,
    p_ip_address, p_user_agent, p_authentication_method
  ) AS tested;

  IF jsonb_typeof(legacy_projection) <> 'object'
     OR NOT (legacy_projection ?& ARRAY[
       'configurationId', 'configurationVersion', 'healthy', 'checkedAt',
       'checks'
     ])
     OR legacy_projection - ARRAY[
       'configurationId', 'configurationVersion', 'healthy', 'checkedAt',
       'checks'
     ]::text[] <> '{}'::jsonb
     OR uuid_extract_version(
       (legacy_projection ->> 'configurationId')::uuid
     ) <> 7
     OR (legacy_projection ->> 'configurationVersion')::integer
          <> p_configuration_version
     OR legacy_projection ->> 'healthy' <> 'true'
     OR legacy_projection -> 'checks' <> jsonb_build_array(
       jsonb_build_object('kind', 'connect', 'outcome', 'skipped')
     ) THEN
    RAISE EXCEPTION 'platform SMTP preflight predecessor returned an invalid projection'
      USING ERRCODE = '55000';
  END IF;

  projection := jsonb_build_object(
    'configurationId', (legacy_projection ->> 'configurationId')::uuid,
    'configurationVersion', p_configuration_version,
    'configurationScope', 'platform',
    'queuedDeliveryId', NULL
  );
  replayed := legacy_replayed;
  RETURN NEXT;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.test_platform_notification_smtp_v2(
  integer, text, text, bytea, bytea, timestamp with time zone,
  uuid, uuid, inet, text, text
) OWNER TO periapsis_notification_admin_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.test_platform_notification_smtp_v2(
  integer, text, text, bytea, bytea, timestamp with time zone,
  uuid, uuid, inet, text, text
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor,
  periapsis_notification_dispatch_owner, periapsis_notification_readiness_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.test_platform_notification_smtp_v2(
  integer, text, text, bytea, bytea, timestamp with time zone,
  uuid, uuid, inet, text, text
) TO periapsis_api;
--> statement-breakpoint

-- The notifier no longer has a direct audit-table write surface. Only the
-- NOLOGIN dispatch owner can append the single allowlisted delivery receipt
-- through the fenced completion ABI below.
DROP POLICY IF EXISTS audit_events_notifier_access ON public.audit_events;
--> statement-breakpoint
REVOKE INSERT (
  id, tenant_id, occurred_at, actor_type, actor_user_id,
  impersonated_by_user_id, action, resource_type, resource_id, request_id,
  correlation_id, ip_address, user_agent, authentication_method, outcome,
  reason, before, after, metadata
) ON public.audit_events FROM periapsis_notifier;
--> statement-breakpoint

GRANT SELECT (
  tenant_id, occurred_at, actor_type, actor_user_id, actor_service_account_id,
  impersonated_by_user_id, action, resource_type, resource_id, request_id,
  correlation_id, ip_address, user_agent, authentication_method, outcome,
  reason, before, after, metadata
) ON public.audit_events TO periapsis_notification_dispatch_owner;
--> statement-breakpoint
GRANT INSERT (
  id, tenant_id, occurred_at, actor_type, actor_user_id,
  impersonated_by_user_id, action, resource_type, resource_id, request_id,
  correlation_id, ip_address, user_agent, authentication_method, outcome,
  reason, before, after, metadata
) ON public.audit_events TO periapsis_notification_dispatch_owner;
--> statement-breakpoint

CREATE POLICY audit_events_notification_delivery_select_v1
ON public.audit_events AS PERMISSIVE FOR SELECT
TO periapsis_notification_dispatch_owner
USING (
  tenant_id = app.context_tenant_id()
  AND action = 'notification.email.delivered'
  AND resource_type = 'notification_delivery'
);
--> statement-breakpoint
CREATE POLICY audit_events_notification_delivery_insert_v1
ON public.audit_events AS PERMISSIVE FOR INSERT
TO periapsis_notification_dispatch_owner
WITH CHECK (
  tenant_id = app.context_tenant_id()
  AND actor_type = 'system'
  AND actor_user_id IS NULL
  AND actor_service_account_id IS NULL
  AND impersonated_by_user_id IS NULL
  AND action = 'notification.email.delivered'
  AND resource_type = 'notification_delivery'
  AND resource_id IS NOT NULL
  AND request_id = resource_id
  AND ip_address IS NULL AND user_agent IS NULL
  AND authentication_method = 'notifier'
  AND outcome = 'success'
  AND reason IS NULL AND before IS NULL AND after IS NULL
  AND jsonb_typeof(metadata) = 'object'
  AND metadata ? 'receiptDigest'
  AND metadata - 'receiptDigest' = '{}'::jsonb
  AND metadata ->> 'receiptDigest' ~ '^[0-9a-f]{64}$'
);
--> statement-breakpoint

CREATE FUNCTION app.private_append_notification_email_delivery_audit_v1(
  p_tenant_id uuid,
  p_delivery_id uuid,
  p_fence_token uuid,
  p_receipt_digest text
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  delivery_occurred_at timestamp with time zone;
  delivery_correlation_id uuid;
  existing_count bigint;
  existing_exact boolean;
BEGIN
  IF p_tenant_id IS NULL OR p_delivery_id IS NULL OR p_fence_token IS NULL
     OR p_receipt_digest IS NULL
     OR p_receipt_digest !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'notification delivery audit input is invalid'
      USING ERRCODE = '22023';
  END IF;
  PERFORM set_config('app.tenant_id', p_tenant_id::text, true);
  PERFORM pg_advisory_xact_lock(hashtextextended(
    p_tenant_id::text || ':notification.email.delivered:'
      || p_delivery_id::text, 0
  ));

  SELECT delivery.delivered_at, event.correlation_id
  INTO STRICT delivery_occurred_at, delivery_correlation_id
  FROM public.tenant_notification_deliveries AS delivery
  JOIN public.tenant_notification_delivery_attempts AS attempt
    ON attempt.tenant_id = delivery.tenant_id
   AND attempt.delivery_id = delivery.id
   AND attempt.fence_token = p_fence_token
   AND attempt.outcome = 'delivered'
   AND attempt.provider_receipt = delivery.provider_receipt
  JOIN public.outbox_events AS event
    ON event.tenant_id = delivery.tenant_id
   AND event.id = delivery.event_id
   AND event.event_type LIKE 'notification.%'
  WHERE delivery.tenant_id = p_tenant_id
    AND delivery.id = p_delivery_id
    AND delivery.channel = 'email'
    AND delivery.status = 'delivered'
    AND delivery.delivered_at IS NOT NULL
    AND delivery.provider_receipt ->> 'provider' = 'smtp'
    AND delivery.provider_receipt ->> 'receiptDigest' = p_receipt_digest;

  SELECT count(*), coalesce(bool_and(
    event.occurred_at = delivery_occurred_at
    AND event.actor_type = 'system'
    AND event.actor_user_id IS NULL
    AND event.actor_service_account_id IS NULL
    AND event.impersonated_by_user_id IS NULL
    AND event.request_id = p_delivery_id
    AND event.correlation_id IS NOT DISTINCT FROM delivery_correlation_id
    AND event.ip_address IS NULL
    AND event.user_agent IS NULL
    AND event.authentication_method = 'notifier'
    AND event.outcome = 'success'
    AND event.reason IS NULL
    AND event.before IS NULL
    AND event.after IS NULL
    AND event.metadata = jsonb_build_object('receiptDigest', p_receipt_digest)
  ), false)
  INTO existing_count, existing_exact
  FROM public.audit_events AS event
  WHERE event.tenant_id = p_tenant_id
    AND event.action = 'notification.email.delivered'
    AND event.resource_type = 'notification_delivery'
    AND event.resource_id = p_delivery_id;
  IF existing_count > 0 THEN
    IF existing_count <> 1 OR NOT existing_exact THEN
      RAISE EXCEPTION 'notification delivery audit evidence conflicts'
        USING ERRCODE = '40001';
    END IF;
    RETURN;
  END IF;

  INSERT INTO public.audit_events (
    id, tenant_id, occurred_at, actor_type, actor_user_id,
    impersonated_by_user_id, action, resource_type, resource_id, request_id,
    correlation_id, ip_address, user_agent, authentication_method, outcome,
    reason, before, after, metadata
  ) VALUES (
    uuidv7(), p_tenant_id, delivery_occurred_at, 'system', NULL, NULL,
    'notification.email.delivered', 'notification_delivery', p_delivery_id,
    p_delivery_id, delivery_correlation_id, NULL, NULL, 'notifier', 'success',
    NULL, NULL, NULL, jsonb_build_object('receiptDigest', p_receipt_digest)
  );
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_append_notification_email_delivery_audit_v1(
  uuid, uuid, uuid, text
) OWNER TO periapsis_notification_dispatch_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_append_notification_email_delivery_audit_v1(
  uuid, uuid, uuid, text
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_notification_admin_owner,
  periapsis_notification_readiness_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.private_append_notification_email_delivery_audit_v1(
  uuid, uuid, uuid, text
) TO periapsis_notification_dispatch_owner;
--> statement-breakpoint

CREATE FUNCTION app.complete_notification_delivery_v3(
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
       OR jsonb_typeof(p_response -> 'provider') <> 'string'
       OR p_response ->> 'provider' <> 'smtp'
       OR jsonb_typeof(p_response -> 'receiptDigest') <> 'string'
       OR p_response ->> 'receiptDigest' !~ '^[0-9a-f]{64}$'
       OR jsonb_typeof(p_response -> 'acceptedCount') <> 'number'
       OR p_response ->> 'acceptedCount' !~ '^[0-9]+$'
       OR jsonb_typeof(p_response -> 'rejectedCount') <> 'number'
       OR p_response ->> 'rejectedCount' !~ '^[0-9]+$'
       OR (p_response ->> 'acceptedCount')::integer <> 1
       OR (p_response ->> 'rejectedCount')::integer <> 0
       OR (p_response ? 'responseClass' AND (
         jsonb_typeof(p_response -> 'responseClass') <> 'number'
         OR p_response ->> 'responseClass' <> '2'
       ))
     ))
     OR (p_channel = 'webhook' AND (
       NOT (p_response ?& ARRAY['provider', 'receiptDigest', 'statusCode'])
       OR p_response - ARRAY['provider', 'receiptDigest', 'statusCode']::text[] <> '{}'::jsonb
       OR jsonb_typeof(p_response -> 'provider') <> 'string'
       OR p_response ->> 'provider' <> 'webhook'
       OR jsonb_typeof(p_response -> 'receiptDigest') <> 'string'
       OR p_response ->> 'receiptDigest' !~ '^[0-9a-f]{64}$'
       OR jsonb_typeof(p_response -> 'statusCode') <> 'number'
       OR p_response ->> 'statusCode' !~ '^[0-9]{3}$'
       OR (p_response ->> 'statusCode')::integer NOT BETWEEN 200 AND 299
     )) THEN
    RAISE EXCEPTION 'notification completion input is invalid' USING ERRCODE = '22023';
  END IF;

  SELECT delivery.* INTO selected
  FROM public.tenant_notification_deliveries AS delivery
  WHERE delivery.id = p_delivery_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'notification delivery claim is stale' USING ERRCODE = '40001';
  END IF;
  context_tenant := selected.tenant_id;
  PERFORM set_config('app.tenant_id', context_tenant::text, true);

  IF selected.status = 'delivered' THEN
    IF selected.channel <> p_channel
       OR selected.provider_receipt IS DISTINCT FROM p_response
       OR NOT EXISTS (
         SELECT 1
         FROM public.tenant_notification_delivery_attempts AS attempt
         WHERE attempt.tenant_id = selected.tenant_id
           AND attempt.delivery_id = selected.id
           AND attempt.fence_token = p_fence_token
           AND attempt.outcome = 'delivered'
           AND attempt.provider_receipt = p_response
       ) THEN
      RAISE EXCEPTION 'notification completion does not match delivered state'
        USING ERRCODE = '40001';
    END IF;
    IF p_channel = 'email' THEN
      PERFORM app.private_append_notification_email_delivery_audit_v1(
        context_tenant, p_delivery_id, p_fence_token,
        p_response ->> 'receiptDigest'
      );
    END IF;
    RETURN;
  END IF;

  IF selected.fence_token IS DISTINCT FROM p_fence_token
     OR selected.lease_until IS NULL
     OR selected.lease_until <= transaction_timestamp() THEN
    RAISE EXCEPTION 'notification delivery claim is stale' USING ERRCODE = '40001';
  END IF;
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
  IF NOT FOUND THEN
    RAISE EXCEPTION 'notification delivery claim is stale' USING ERRCODE = '40001';
  END IF;

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

  IF p_channel = 'email' THEN
    PERFORM app.private_append_notification_email_delivery_audit_v1(
      context_tenant, p_delivery_id, p_fence_token,
      p_response ->> 'receiptDigest'
    );
  END IF;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.complete_notification_delivery_v3(
  uuid, uuid, public.notification_channel, jsonb, timestamp with time zone
) OWNER TO periapsis_notification_dispatch_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.complete_notification_delivery_v3(
  uuid, uuid, public.notification_channel, jsonb, timestamp with time zone
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_auditor,
  periapsis_notification_admin_owner, periapsis_notification_readiness_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.complete_notification_delivery_v3(
  uuid, uuid, public.notification_channel, jsonb, timestamp with time zone
) TO periapsis_notifier;
--> statement-breakpoint

-- Migration-first rolling compatibility: an older notifier still calling v2
-- receives the same strict v3 completion and atomic delivery audit.
CREATE OR REPLACE FUNCTION app.complete_notification_delivery_v2(
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
BEGIN
  PERFORM app.complete_notification_delivery_v3(
    p_delivery_id, p_fence_token, p_channel, p_response, p_completed_at
  );
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.complete_notification_delivery_v2(
  uuid, uuid, public.notification_channel, jsonb, timestamp with time zone
) OWNER TO periapsis_notification_dispatch_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.complete_notification_delivery_v2(
  uuid, uuid, public.notification_channel, jsonb, timestamp with time zone
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_auditor,
  periapsis_notification_admin_owner, periapsis_notification_readiness_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.complete_notification_delivery_v2(
  uuid, uuid, public.notification_channel, jsonb, timestamp with time zone
) TO periapsis_notifier;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.complete_notification_delivery_replay_v2(
  p_delivery_id uuid,
  p_fence_token uuid,
  p_channel public.notification_channel,
  p_completed_at timestamp with time zone
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  selected public.tenant_notification_deliveries%ROWTYPE;
BEGIN
  IF p_delivery_id IS NULL OR p_fence_token IS NULL OR p_channel IS NULL
     OR p_completed_at IS NULL
     OR p_completed_at < transaction_timestamp() - interval '5 minutes'
     OR p_completed_at > transaction_timestamp() + interval '1 minute' THEN
    RAISE EXCEPTION 'notification replay is unavailable' USING ERRCODE = '40001';
  END IF;
  SELECT delivery.* INTO selected
  FROM public.tenant_notification_deliveries AS delivery
  WHERE delivery.id = p_delivery_id
  FOR UPDATE;
  IF NOT FOUND OR selected.channel <> p_channel
     OR selected.status <> 'delivered'
     OR selected.stable_message_id IS NULL
     OR NOT EXISTS (
       SELECT 1
       FROM public.tenant_notification_delivery_attempts AS attempt
       WHERE attempt.tenant_id = selected.tenant_id
         AND attempt.delivery_id = selected.id
         AND attempt.fence_token = p_fence_token
         AND attempt.outcome = 'delivered'
         AND attempt.provider_receipt = selected.provider_receipt
     ) THEN
    RAISE EXCEPTION 'notification replay is unavailable' USING ERRCODE = '40001';
  END IF;
  PERFORM set_config('app.tenant_id', selected.tenant_id::text, true);
  IF p_channel = 'email' THEN
    PERFORM app.private_append_notification_email_delivery_audit_v1(
      selected.tenant_id, selected.id, p_fence_token,
      selected.provider_receipt ->> 'receiptDigest'
    );
  END IF;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.complete_notification_delivery_replay_v2(
  uuid, uuid, public.notification_channel, timestamp with time zone
) OWNER TO periapsis_notification_dispatch_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.complete_notification_delivery_replay_v2(
  uuid, uuid, public.notification_channel, timestamp with time zone
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_auditor,
  periapsis_notification_admin_owner, periapsis_notification_readiness_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.complete_notification_delivery_replay_v2(
  uuid, uuid, public.notification_channel, timestamp with time zone
) TO periapsis_notifier;
--> statement-breakpoint

CREATE FUNCTION app.notification_schema_readiness_v4()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  expected record;
  function_oid regprocedure;
BEGIN
  IF NOT app.notification_schema_readiness_v3() THEN
    RETURN false;
  END IF;
  FOR expected IN
    SELECT * FROM (VALUES
      ('app.load_pinned_smtp_configuration_v2(uuid,text,uuid,integer)',
       'periapsis_notification_dispatch_owner',false,true),
      ('app.test_tenant_notification_smtp_v2(integer,uuid,text,text,bytea,bytea,timestamp with time zone,uuid,uuid,inet,text,text)',
       'periapsis_notification_admin_owner',true,false),
      ('app.test_platform_notification_smtp_v2(integer,text,text,bytea,bytea,timestamp with time zone,uuid,uuid,inet,text,text)',
       'periapsis_notification_admin_owner',true,false),
      ('app.complete_notification_delivery_v2(uuid,uuid,public.notification_channel,jsonb,timestamp with time zone)',
       'periapsis_notification_dispatch_owner',false,true),
      ('app.complete_notification_delivery_v3(uuid,uuid,public.notification_channel,jsonb,timestamp with time zone)',
       'periapsis_notification_dispatch_owner',false,true),
      ('app.complete_notification_delivery_replay_v2(uuid,uuid,public.notification_channel,timestamp with time zone)',
       'periapsis_notification_dispatch_owner',false,true),
      ('app.private_append_notification_email_delivery_audit_v1(uuid,uuid,uuid,text)',
       'periapsis_notification_dispatch_owner',false,false)
    ) AS functions(signature, expected_owner, api_execute, notifier_execute)
  LOOP
    function_oid := to_regprocedure(expected.signature);
    IF function_oid IS NULL OR (
      SELECT pg_get_userbyid(procedure.proowner)
          IS DISTINCT FROM expected.expected_owner
        OR procedure.prosecdef IS NOT TRUE
        OR procedure.proconfig[1] NOT LIKE 'search_path=pg_catalog%'
      FROM pg_proc AS procedure WHERE procedure.oid = function_oid
    ) OR EXISTS (
      SELECT 1
      FROM pg_proc AS procedure
      CROSS JOIN LATERAL aclexplode(coalesce(
        procedure.proacl, acldefault('f', procedure.proowner)
      )) AS privilege
      LEFT JOIN pg_roles AS grantee_role
        ON grantee_role.oid = privilege.grantee
      WHERE procedure.oid = function_oid
        AND privilege.privilege_type = 'EXECUTE'
        AND privilege.grantee <> procedure.proowner
        AND NOT coalesce((
          expected.api_execute
            AND grantee_role.rolname = 'periapsis_api'
          OR expected.notifier_execute
            AND grantee_role.rolname = 'periapsis_notifier'
        ), false)
    ) OR has_function_privilege('periapsis_api', function_oid, 'EXECUTE')
         IS DISTINCT FROM expected.api_execute
      OR has_function_privilege('periapsis_notifier', function_oid, 'EXECUTE')
         IS DISTINCT FROM expected.notifier_execute THEN
      RETURN false;
    END IF;
  END LOOP;

  IF has_any_column_privilege(
       'periapsis_notifier', 'public.audit_events', 'SELECT'
     ) OR has_any_column_privilege(
       'periapsis_notifier', 'public.audit_events', 'INSERT'
     ) OR has_any_column_privilege(
       'periapsis_notifier', 'public.audit_events', 'UPDATE'
     ) OR has_any_column_privilege(
       'periapsis_notifier', 'public.audit_events', 'REFERENCES'
     ) OR has_table_privilege(
       'periapsis_notifier', 'public.audit_events', 'DELETE'
     ) OR has_table_privilege(
       'periapsis_notifier', 'public.audit_events', 'TRUNCATE'
     ) OR has_table_privilege(
       'periapsis_notifier', 'public.audit_events', 'TRIGGER'
     ) OR has_table_privilege(
       'periapsis_notification_dispatch_owner', 'public.audit_events', 'SELECT'
     ) OR has_table_privilege(
       'periapsis_notification_dispatch_owner', 'public.audit_events', 'INSERT'
     ) OR has_table_privilege(
       'periapsis_notification_dispatch_owner', 'public.audit_events', 'UPDATE'
     ) OR has_table_privilege(
       'periapsis_notification_dispatch_owner', 'public.audit_events', 'DELETE'
     ) OR has_table_privilege(
       'periapsis_notification_dispatch_owner', 'public.audit_events', 'TRUNCATE'
     ) OR has_table_privilege(
       'periapsis_notification_dispatch_owner', 'public.audit_events', 'REFERENCES'
     ) OR has_table_privilege(
       'periapsis_notification_dispatch_owner', 'public.audit_events', 'TRIGGER'
     ) OR EXISTS (
       SELECT 1
       FROM pg_attribute AS attribute
       WHERE attribute.attrelid = 'public.audit_events'::regclass
         AND attribute.attnum > 0
         AND NOT attribute.attisdropped
         AND (
           has_column_privilege(
             'periapsis_notification_dispatch_owner', 'public.audit_events',
             attribute.attname, 'SELECT'
           ) IS DISTINCT FROM (attribute.attname = ANY(ARRAY[
             'tenant_id', 'occurred_at', 'actor_type', 'actor_user_id',
             'actor_service_account_id', 'impersonated_by_user_id', 'action',
             'resource_type', 'resource_id', 'request_id', 'correlation_id',
             'ip_address', 'user_agent', 'authentication_method', 'outcome',
             'reason', 'before', 'after', 'metadata'
           ]::text[]))
           OR has_column_privilege(
             'periapsis_notification_dispatch_owner', 'public.audit_events',
             attribute.attname, 'INSERT'
           ) IS DISTINCT FROM (attribute.attname = ANY(ARRAY[
             'id', 'tenant_id', 'occurred_at', 'actor_type', 'actor_user_id',
             'impersonated_by_user_id', 'action', 'resource_type', 'resource_id',
             'request_id', 'correlation_id', 'ip_address', 'user_agent',
             'authentication_method', 'outcome', 'reason', 'before', 'after',
             'metadata'
           ]::text[]))
           OR has_column_privilege(
             'periapsis_notification_dispatch_owner', 'public.audit_events',
             attribute.attname, 'UPDATE'
           )
           OR has_column_privilege(
             'periapsis_notification_dispatch_owner', 'public.audit_events',
             attribute.attname, 'REFERENCES'
           )
         )
     ) THEN
    RETURN false;
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_policy AS policy
    JOIN pg_class AS class ON class.oid = policy.polrelid
    JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
    WHERE namespace.nspname = 'public' AND class.relname = 'audit_events'
      AND policy.polname = 'audit_events_notifier_access'
  ) OR (
    SELECT count(*)
    FROM pg_policy AS policy
    JOIN pg_class AS class ON class.oid = policy.polrelid
    JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
    WHERE namespace.nspname = 'public' AND class.relname = 'audit_events'
      AND policy.polname IN (
        'audit_events_notification_delivery_select_v1',
        'audit_events_notification_delivery_insert_v1'
      )
      AND policy.polpermissive
      AND (SELECT oid FROM pg_roles
           WHERE rolname = 'periapsis_notification_dispatch_owner')
          = ANY(policy.polroles)
  ) <> 2 THEN
    RETURN false;
  END IF;
  RETURN true;
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.notification_dispatch_readiness_v4()
RETURNS TABLE(
  queue_depth bigint,
  role_safe boolean,
  schema_safe boolean,
  oldest_pending_seconds bigint
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  SELECT readiness.queue_depth, readiness.role_safe,
         readiness.oldest_pending_seconds
  INTO queue_depth, role_safe, oldest_pending_seconds
  FROM app.notification_dispatch_readiness_v3() AS readiness;
  schema_safe := app.notification_schema_readiness_v4();
  RETURN NEXT;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.notification_schema_readiness_v4()
OWNER TO periapsis_migrator;
--> statement-breakpoint
ALTER FUNCTION app.notification_dispatch_readiness_v4()
OWNER TO periapsis_notification_readiness_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.notification_schema_readiness_v4(),
  app.notification_dispatch_readiness_v4()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_notification_admin_owner,
  periapsis_notification_dispatch_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.notification_schema_readiness_v4()
TO periapsis_api, periapsis_worker, periapsis_notification_readiness_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.notification_dispatch_readiness_v4()
TO periapsis_notifier;
--> statement-breakpoint
