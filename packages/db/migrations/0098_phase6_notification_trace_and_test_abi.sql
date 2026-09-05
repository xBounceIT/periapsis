-- Phase 6 trace continuity and administration test/retry successor. The
-- generated 0097 shape remains canonical; this file only seals narrow ABIs.

CREATE FUNCTION app.private_notification_trace_context_is_safe_v1(
  p_traceparent text,
  p_tracestate text
)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, public, app
AS $function$
  WITH members AS (
    SELECT value, ordinal,
           split_part(value, '=', 1) AS key,
           substring(value from position('=' in value) + 1) AS member_value
    FROM unnest(string_to_array(coalesce(p_tracestate, ''), ','))
      WITH ORDINALITY AS item(value, ordinal)
    WHERE p_tracestate IS NOT NULL
  )
  SELECT (p_tracestate IS NULL OR p_traceparent IS NOT NULL)
    AND (p_traceparent IS NULL OR (
      p_traceparent ~ '^00-[0-9a-f]{32}-[0-9a-f]{16}-(00|01)$'
      AND split_part(p_traceparent, '-', 2) <> repeat('0', 32)
      AND split_part(p_traceparent, '-', 3) <> repeat('0', 16)
    ))
    AND (p_tracestate IS NULL OR (
      octet_length(p_tracestate) BETWEEN 1 AND 512
      AND p_tracestate = btrim(p_tracestate)
      AND p_tracestate !~ '[[:cntrl:]]'
      AND (SELECT count(*) FROM members) BETWEEN 1 AND 32
      AND (SELECT count(DISTINCT key) FROM members) = (SELECT count(*) FROM members)
      AND NOT EXISTS (
        SELECT 1 FROM members
        WHERE position('=' in value) <= 1
          OR key !~ '^[a-z0-9][a-z0-9_.*/-]{0,255}(?:@[a-z0-9][a-z0-9_.*/-]{0,13})?$'
          OR char_length(key) > 256
          OR char_length(member_value) NOT BETWEEN 1 AND 256
          OR octet_length(member_value) <> char_length(member_value)
          OR member_value <> btrim(member_value)
          OR member_value ~ '[,=[:cntrl:]]'
      )
    ));
$function$;--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.claim_notification_fanout_batch_v1(
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
    RAISE EXCEPTION 'notification fanout claim input is invalid' USING ERRCODE = '22023';
  END IF;

  UPDATE public.outbox_events AS legacy
  SET attempts = max_attempts, processed_at = p_now, dead_lettered_at = p_now,
      failure_category = 'ambiguous_schema_v1',
      last_error = 'legacy notification event quarantined',
      locked_at = NULL, locked_by = NULL, lease_token = NULL, lease_until = NULL
  WHERE legacy.event_type LIKE 'notification.%'
    AND legacy.schema_version <> 2 AND legacy.processed_at IS NULL
    AND legacy.available_at <= p_now;

  RETURN QUERY
  WITH candidate AS (
    SELECT event.id
    FROM public.outbox_events AS event
    WHERE event.event_type LIKE 'notification.%'
      AND event.schema_version = 2 AND event.processed_at IS NULL
      AND event.dead_lettered_at IS NULL AND event.available_at <= p_now
      AND event.attempts < event.max_attempts
      AND (event.lease_until IS NULL OR event.lease_until <= p_now)
    ORDER BY event.available_at, event.occurred_at, event.id
    LIMIT p_limit FOR UPDATE SKIP LOCKED
  ), claimed AS (
    UPDATE public.outbox_events AS event
    SET attempts = event.attempts + 1, locked_at = p_now,
        locked_by = p_worker_id, lease_token = uuidv7(),
        lease_until = p_now + make_interval(
          secs => p_lease_duration_ms::double precision / 1000.0
        ), failure_category = NULL, last_error = NULL
    FROM candidate WHERE event.id = candidate.id
    RETURNING event.*
  )
  SELECT jsonb_build_object(
    'id', claimed.id, 'tenantId', claimed.tenant_id,
    'event', jsonb_strip_nulls(jsonb_build_object(
      'id', claimed.id, 'tenantId', claimed.tenant_id,
      'type', substring(claimed.event_type from 14),
      'objectType', claimed.aggregate_type, 'objectId', claimed.aggregate_id,
      'objectVersion', claimed.aggregate_version,
      'occurredAt', claimed.occurred_at, 'actorKind', claimed.actor_kind,
      'actorId', claimed.actor_id, 'source', claimed.producer,
      'context', (claimed.payload -> 'operatorContext')
        || CASE WHEN claimed.payload ? 'customerContext'
                THEN jsonb_build_object('customer', claimed.payload -> 'customerContext')
                ELSE '{}'::jsonb END,
      'maximumAudience', claimed.maximum_audience,
      'traceContext', CASE WHEN claimed.traceparent IS NULL THEN NULL ELSE
        jsonb_strip_nulls(jsonb_build_object(
          'traceParent', claimed.traceparent, 'traceState', claimed.tracestate
        )) END
    )),
    'attempt', claimed.attempts, 'maximumAttempts', claimed.max_attempts,
    'fenceToken', claimed.lease_token, 'leaseUntil', claimed.lease_until
  )
  FROM claimed
  ORDER BY claimed.available_at, claimed.occurred_at, claimed.id;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.private_notification_trace_context_is_safe_v1(text, text)
OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_notification_trace_context_is_safe_v1(text, text)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
     periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.private_notification_trace_context_is_safe_v1(text, text)
TO periapsis_notification_admin_owner,
   periapsis_notification_dispatch_owner;--> statement-breakpoint

CREATE FUNCTION app.private_notification_service_account_is_active_v1(
  p_tenant_id uuid,
  p_service_account_id uuid
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT p_tenant_id IS NOT NULL
    AND p_tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid
    AND p_service_account_id IS NOT NULL
    AND EXISTS (
      SELECT 1
      FROM public.tenant_service_accounts AS account
      WHERE account.tenant_id = p_tenant_id
        AND account.id = p_service_account_id
        AND account.archived_at IS NULL
    );
$function$;--> statement-breakpoint
ALTER FUNCTION app.private_notification_service_account_is_active_v1(uuid, uuid)
OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_notification_service_account_is_active_v1(uuid, uuid)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
     periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.private_notification_service_account_is_active_v1(uuid, uuid)
TO periapsis_notification_admin_owner;--> statement-breakpoint

CREATE FUNCTION app.private_append_tenant_notification_event_v3(
  p_event_id uuid,
  p_event_type public.notification_event_type,
  p_object_type public.notification_object_type,
  p_object_id uuid,
  p_object_version integer,
  p_occurred_at timestamp with time zone,
  p_actor_kind public.ticket_principal_kind,
  p_actor_id uuid,
  p_source text,
  p_maximum_audience public.notification_audience,
  p_operator_context jsonb,
  p_customer_context jsonb,
  p_deduplication_key text,
  p_correlation_id uuid,
  p_causation_id uuid,
  p_traceparent text,
  p_tracestate text
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  event_prefix text := split_part(p_event_type::text, '.', 1);
BEGIN
  IF context_tenant IS NULL
     OR (p_actor_kind = 'human' AND (
       app.current_tenant_membership_id() IS NULL
       OR p_actor_id IS DISTINCT FROM app.context_user_id()
     ))
     OR (p_actor_kind = 'service_account' AND NOT
       app.private_notification_service_account_is_active_v1(
         context_tenant, p_actor_id
       ))
     OR p_event_id IS NULL OR uuid_extract_version(p_event_id) <> 7
     OR p_object_id IS NULL OR uuid_extract_version(p_object_id) <> 7
     OR p_object_version NOT BETWEEN 1 AND 2147483647
     OR p_occurred_at IS NULL
     OR p_occurred_at > transaction_timestamp() + interval '1 minute'
     OR p_occurred_at < transaction_timestamp() - interval '30 days'
     OR p_actor_kind IS NULL
     OR ((p_actor_kind = 'system') IS DISTINCT FROM (p_actor_id IS NULL))
     OR p_source IS NULL OR p_source !~ '^[a-z][a-z0-9_.-]{1,127}$'
     OR NOT app.private_notification_context_is_safe_v1(p_operator_context)
     OR p_operator_context ? 'customer'
     OR (p_maximum_audience = 'customer') IS DISTINCT FROM (p_customer_context IS NOT NULL)
     OR (p_customer_context IS NOT NULL
       AND NOT app.private_notification_context_is_safe_v1(p_customer_context))
     OR p_event_type = 'comment.private_added' AND p_maximum_audience <> 'operator'
     OR p_deduplication_key IS NULL OR char_length(p_deduplication_key) NOT BETWEEN 1 AND 240
     OR p_deduplication_key ~ '[[:cntrl:]]'
     OR p_correlation_id IS NULL OR p_causation_id IS NULL
     OR NOT app.private_notification_trace_context_is_safe_v1(p_traceparent, p_tracestate)
     OR (event_prefix = 'alert' AND p_object_type <> 'alert')
     OR (event_prefix = 'case' AND p_object_type <> 'case')
     OR (event_prefix = 'task' AND p_object_type <> 'task')
     OR (event_prefix = 'evidence' AND p_object_type <> 'evidence')
     OR (event_prefix = 'contact' AND p_object_type <> 'contact')
     OR (event_prefix = 'comment' AND p_object_type NOT IN ('alert', 'case'))
     OR (event_prefix = 'sla' AND p_object_type NOT IN ('alert', 'case', 'task')) THEN
    RAISE EXCEPTION 'notification event envelope is invalid' USING ERRCODE = '22023';
  END IF;

  INSERT INTO public.outbox_events (
    id, tenant_id, aggregate_type, aggregate_id, aggregate_version,
    event_type, schema_version, payload, deduplication_key,
    correlation_id, causation_id, actor_kind, actor_id, producer,
    maximum_audience, traceparent, tracestate, occurred_at, available_at
  ) VALUES (
    p_event_id, context_tenant, p_object_type::text, p_object_id,
    p_object_version, 'notification.' || p_event_type::text, 2,
    jsonb_build_object('operatorContext', p_operator_context)
      || CASE WHEN p_customer_context IS NULL THEN '{}'::jsonb
              ELSE jsonb_build_object('customerContext', p_customer_context) END,
    p_deduplication_key, p_correlation_id, p_causation_id,
    p_actor_kind, p_actor_id, p_source, p_maximum_audience,
    p_traceparent, p_tracestate, p_occurred_at,
    greatest(p_occurred_at, transaction_timestamp())
  );
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.private_append_tenant_notification_event_v3(
  uuid, public.notification_event_type, public.notification_object_type,
  uuid, integer, timestamp with time zone, public.ticket_principal_kind,
  uuid, text, public.notification_audience, jsonb, jsonb, text, uuid, uuid,
  text, text
) OWNER TO periapsis_notification_admin_owner;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_append_tenant_notification_event_v3(
  uuid, public.notification_event_type, public.notification_object_type,
  uuid, integer, timestamp with time zone, public.ticket_principal_kind,
  uuid, text, public.notification_audience, jsonb, jsonb, text, uuid, uuid,
  text, text
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
         periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.private_append_tenant_notification_event_v3(
  uuid, public.notification_event_type, public.notification_object_type,
  uuid, integer, timestamp with time zone, public.ticket_principal_kind,
  uuid, text, public.notification_audience, jsonb, jsonb, text, uuid, uuid,
  text, text
) TO periapsis_migrator, periapsis_notification_admin_owner;--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.private_append_tenant_notification_event_v2(
  p_event_id uuid,
  p_event_type public.notification_event_type,
  p_object_type public.notification_object_type,
  p_object_id uuid,
  p_object_version integer,
  p_occurred_at timestamp with time zone,
  p_actor_kind public.ticket_principal_kind,
  p_actor_id uuid,
  p_source text,
  p_maximum_audience public.notification_audience,
  p_operator_context jsonb,
  p_customer_context jsonb,
  p_deduplication_key text,
  p_correlation_id uuid,
  p_causation_id uuid
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  PERFORM app.private_append_tenant_notification_event_v3(
    p_event_id, p_event_type, p_object_type, p_object_id, p_object_version,
    p_occurred_at, p_actor_kind, p_actor_id, p_source, p_maximum_audience,
    p_operator_context, p_customer_context, p_deduplication_key,
    p_correlation_id, p_causation_id,
    nullif(current_setting('app.traceparent', true), ''),
    nullif(current_setting('app.tracestate', true), '')
  );
END;
$function$;--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.claim_notification_delivery_batch_v1(
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
      AND (delivery.template_id IS NOT NULL OR delivery.template_snapshot IS NOT NULL)
      AND delivery.smtp_configuration_scope IN ('tenant', 'platform')
      AND delivery.smtp_configuration_id IS NOT NULL
      AND delivery.smtp_configuration_version IS NOT NULL
    ORDER BY delivery.priority DESC, delivery.next_attempt_at,
             delivery.created_at, delivery.id
    LIMIT p_limit FOR UPDATE SKIP LOCKED
  ), fenced AS (
    UPDATE public.tenant_notification_delivery_attempts AS attempt
    SET completed_at = p_now, outcome = 'fenced'
    FROM candidate
    JOIN public.tenant_notification_deliveries AS previous
      ON previous.id = candidate.id
    WHERE attempt.tenant_id = previous.tenant_id
      AND attempt.delivery_id = previous.id
      AND attempt.attempt = previous.attempt_count
      AND attempt.completed_at IS NULL AND attempt.outcome IS NULL
    RETURNING attempt.tenant_id, attempt.delivery_id, attempt.attempt
  ), claimed AS (
    UPDATE public.tenant_notification_deliveries AS delivery
    SET status = 'leased', attempt_count = delivery.attempt_count + 1,
        lease_owner = p_worker_id, fence_token = uuidv7(),
        lease_until = p_now + make_interval(
          secs => p_lease_duration_ms::double precision / 1000.0
        ), failure_at = NULL, failure_class = NULL,
        failure_code = NULL, updated_at = p_now
    FROM candidate
    WHERE delivery.id = candidate.id AND (SELECT count(*) FROM fenced) >= 0
    RETURNING delivery.*
  ), started AS (
    INSERT INTO public.tenant_notification_delivery_attempts (
      tenant_id, delivery_id, attempt, fence_token, started_at
    )
    SELECT claimed.tenant_id, claimed.id, claimed.attempt_count,
           claimed.fence_token, p_now FROM claimed
    RETURNING tenant_id, delivery_id, attempt
  )
  SELECT jsonb_build_object(
    'id', claimed.id, 'tenantId', claimed.tenant_id,
    'eventId', claimed.event_id,
    'ruleId', coalesce(claimed.rule_id, claimed.id),
    'ruleVersion', coalesce(claimed.rule_version, 1),
    'smtpConfigurationScope', claimed.smtp_configuration_scope,
    'smtpConfigurationId', claimed.smtp_configuration_id,
    'smtpConfigurationVersion', claimed.smtp_configuration_version,
    'deduplicationKey', claimed.delivery_key, 'recipient', claimed.recipient,
    'audience', claimed.audience, 'context', claimed.context,
    'template', CASE WHEN claimed.template_snapshot IS NOT NULL THEN
      claimed.template_snapshot || jsonb_build_object(
        'id', claimed.id, 'tenantId', claimed.tenant_id
      ) ELSE jsonb_strip_nulls(jsonb_build_object(
        'id', template.template_id, 'tenantId', template.tenant_id,
        'key', template.key, 'name', template.name,
        'language', template.language, 'version', template.version,
        'subject', template.subject, 'html', template.html,
        'plainText', template.plain_text, 'css', template.css
      )) END,
    'retry', claimed.retry, 'attempt', claimed.attempt_count,
    'fenceToken', claimed.fence_token, 'leaseUntil', claimed.lease_until,
    'traceContext', CASE WHEN source.traceparent IS NULL THEN NULL ELSE
      jsonb_strip_nulls(jsonb_build_object(
        'traceParent', source.traceparent, 'traceState', source.tracestate
      )) END
  )
  FROM claimed
  JOIN started ON started.tenant_id = claimed.tenant_id
   AND started.delivery_id = claimed.id
   AND started.attempt = claimed.attempt_count
  JOIN public.outbox_events AS source
    ON source.tenant_id = claimed.tenant_id AND source.id = claimed.event_id
  LEFT JOIN public.tenant_notification_template_versions AS template
    ON template.tenant_id = claimed.tenant_id
   AND template.template_id = claimed.template_id
   AND template.version = claimed.template_version
  WHERE (claimed.template_snapshot IS NOT NULL OR template.template_id IS NOT NULL)
  ORDER BY claimed.priority DESC, claimed.next_attempt_at,
           claimed.created_at, claimed.id;
END;
$function$;--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.claim_notification_webhook_delivery_batch_v1(
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
    AND attempt.completed_at IS NULL AND attempt.outcome IS NULL
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
        AND identity.revoked_at IS NULL AND pinned.enabled AND current_version.enabled
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
        AND identity.revoked_at IS NULL AND pinned.enabled AND current_version.enabled
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
          AND identity.revoked_at IS NULL AND pinned.enabled AND current_version.enabled
      )
    ORDER BY delivery.priority DESC, delivery.next_attempt_at,
             delivery.created_at, delivery.id
    LIMIT p_limit FOR UPDATE SKIP LOCKED
  ), fenced AS (
    UPDATE public.tenant_notification_delivery_attempts AS attempt
    SET completed_at = p_now, outcome = 'fenced'
    FROM candidate
    JOIN public.tenant_notification_deliveries AS previous ON previous.id = candidate.id
    WHERE attempt.tenant_id = previous.tenant_id
      AND attempt.delivery_id = previous.id
      AND attempt.attempt = previous.attempt_count
      AND attempt.completed_at IS NULL AND attempt.outcome IS NULL
    RETURNING attempt.tenant_id, attempt.delivery_id, attempt.attempt
  ), claimed AS (
    UPDATE public.tenant_notification_deliveries AS delivery
    SET status = 'leased', attempt_count = delivery.attempt_count + 1,
        lease_owner = p_worker_id, fence_token = uuidv7(),
        lease_until = p_now + make_interval(
          secs => p_lease_duration_ms::double precision / 1000.0
        ), updated_at = p_now
    FROM candidate
    WHERE delivery.id = candidate.id AND (SELECT count(*) FROM fenced) >= 0
    RETURNING delivery.*
  ), started AS (
    INSERT INTO public.tenant_notification_delivery_attempts (
      tenant_id, delivery_id, attempt, fence_token, started_at
    )
    SELECT claimed.tenant_id, claimed.id, claimed.attempt_count,
           claimed.fence_token, p_now FROM claimed
    RETURNING tenant_id, delivery_id, attempt
  )
  SELECT jsonb_build_object(
    'id', claimed.id, 'tenantId', claimed.tenant_id,
    'eventId', claimed.event_id,
    'configurationId', claimed.webhook_configuration_id,
    'configurationVersion', claimed.webhook_configuration_version,
    'endpointUrl', configuration.endpoint_url,
    'timeoutMs', configuration.timeout_ms, 'payload', claimed.webhook_payload,
    'signingKey', jsonb_build_object(
      'tenantId', secret.tenant_id, 'secretId', secret.secret_id,
      'secretVersion', secret.version, 'kind', secret.kind,
      'keyVersion', secret.key_version, 'nonce', encode(secret.nonce, 'base64'),
      'ciphertext', encode(secret.ciphertext, 'base64')
    ),
    'createdAt', claimed.created_at, 'attemptAt', p_now,
    'retry', claimed.retry, 'attempt', claimed.attempt_count,
    'fenceToken', claimed.fence_token, 'leaseUntil', claimed.lease_until,
    'traceContext', CASE WHEN source.traceparent IS NULL THEN NULL ELSE
      jsonb_strip_nulls(jsonb_build_object(
        'traceParent', source.traceparent, 'traceState', source.tracestate
      )) END
  )
  FROM claimed
  JOIN started ON started.tenant_id = claimed.tenant_id
   AND started.delivery_id = claimed.id
   AND started.attempt = claimed.attempt_count
  JOIN public.outbox_events AS source
    ON source.tenant_id = claimed.tenant_id AND source.id = claimed.event_id
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
  ORDER BY claimed.priority DESC, claimed.next_attempt_at,
           claimed.created_at, claimed.id;
END;
$function$;--> statement-breakpoint

GRANT UPDATE ON TABLE public.outbox_events
TO periapsis_notification_admin_owner;--> statement-breakpoint

CREATE FUNCTION app.private_resolve_tenant_notification_smtp_pin_v1(
  p_configuration_version integer
)
RETURNS TABLE(configuration_scope text, configuration_id uuid, configuration_version integer)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  SELECT 'tenant', identity.id, version.version
  INTO configuration_scope, configuration_id, configuration_version
  FROM public.tenant_notification_smtp_configurations AS identity
  JOIN public.tenant_notification_smtp_configuration_versions AS version
    ON version.tenant_id = identity.tenant_id
   AND version.configuration_id = identity.id
   AND version.version = identity.current_version
  WHERE identity.tenant_id = app.context_tenant_id()
    AND identity.revoked_at IS NULL AND version.enabled;
  IF NOT FOUND THEN
    SELECT 'platform', identity.id, version.version
    INTO configuration_scope, configuration_id, configuration_version
    FROM public.platform_notification_smtp_configurations AS identity
    JOIN public.platform_notification_smtp_configuration_versions AS version
      ON version.configuration_id = identity.id
     AND version.version = identity.current_version
    WHERE identity.revoked_at IS NULL AND version.enabled;
  END IF;
  IF NOT FOUND OR configuration_version <> p_configuration_version THEN
    RAISE EXCEPTION 'notification SMTP pin was not found' USING ERRCODE = 'P0002';
  END IF;
  RETURN NEXT;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.private_resolve_tenant_notification_smtp_pin_v1(integer)
OWNER TO periapsis_notification_admin_owner;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_resolve_tenant_notification_smtp_pin_v1(integer)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
     periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.private_resolve_tenant_notification_smtp_pin_v1(integer)
TO periapsis_notification_admin_owner;--> statement-breakpoint

CREATE FUNCTION app.private_insert_notification_test_event_v1(
  p_event_id uuid,
  p_event_type public.notification_event_type,
  p_object_type public.notification_object_type,
  p_object_id uuid,
  p_object_version integer,
  p_audience public.notification_audience,
  p_operator_context jsonb,
  p_customer_context jsonb,
  p_occurred_at timestamp with time zone,
  p_correlation_id uuid,
  p_causation_id uuid,
  p_deduplication_key text
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  PERFORM app.private_append_tenant_notification_event_v3(
    p_event_id, p_event_type, p_object_type, p_object_id, p_object_version,
    p_occurred_at, 'human', app.context_user_id(), 'notification.admin',
    p_audience, p_operator_context, p_customer_context,
    p_deduplication_key, p_correlation_id, p_causation_id,
    nullif(current_setting('app.traceparent', true), ''),
    nullif(current_setting('app.tracestate', true), '')
  );
  UPDATE public.outbox_events
  SET processed_at = p_occurred_at,
      fanout_commit_digest = sha256(convert_to(p_deduplication_key, 'UTF8'))
  WHERE tenant_id = app.context_tenant_id() AND id = p_event_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'notification test event was not persisted' USING ERRCODE = '55000';
  END IF;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.private_insert_notification_test_event_v1(
  uuid, public.notification_event_type, public.notification_object_type,
  uuid, integer, public.notification_audience, jsonb, jsonb,
  timestamp with time zone, uuid, uuid, text
) OWNER TO periapsis_notification_admin_owner;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_insert_notification_test_event_v1(
  uuid, public.notification_event_type, public.notification_object_type,
  uuid, integer, public.notification_audience, jsonb, jsonb,
  timestamp with time zone, uuid, uuid, text
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
         periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.private_insert_notification_test_event_v1(
  uuid, public.notification_event_type, public.notification_object_type,
  uuid, integer, public.notification_audience, jsonb, jsonb,
  timestamp with time zone, uuid, uuid, text
) TO periapsis_notification_admin_owner;--> statement-breakpoint

CREATE FUNCTION app.test_tenant_notification_smtp_v1(
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
  context_tenant uuid;
  actor_membership uuid;
  actor_user uuid;
  pin record;
  command public.tenant_notification_commands%ROWTYPE;
  event_id uuid;
  delivery_key text;
  redacted_recipient text;
  result_resource uuid;
BEGIN
  PERFORM app.private_require_notification_admin_v1();
  context_tenant := app.context_tenant_id();
  actor_membership := app.current_tenant_membership_id();
  actor_user := app.context_user_id();
  IF p_configuration_version NOT BETWEEN 1 AND 2147483647
     OR (p_delivery_id IS NULL) <> (p_recipient IS NULL)
     OR p_delivery_id IS NOT NULL AND uuid_extract_version(p_delivery_id) <> 7
     OR p_recipient IS NOT NULL AND (
       p_recipient <> lower(btrim(p_recipient))
       OR char_length(p_recipient) NOT BETWEEN 3 AND 320
       OR p_recipient !~ '^[^[:space:]@]+@[^[:space:]@]+$'
     )
     OR p_reason IS NULL OR char_length(p_reason) NOT BETWEEN 1 AND 1000
     OR p_reason ~ '[[:cntrl:]]'
     OR p_key_digest IS NULL OR octet_length(p_key_digest) <> 32
     OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32
     OR p_occurred_at IS NULL
     OR p_occurred_at < transaction_timestamp() - interval '5 minutes'
     OR p_occurred_at > transaction_timestamp() + interval '1 minute'
     OR p_request_id IS NULL OR p_correlation_id IS NULL
     OR p_ip_address IS NULL OR p_authentication_method IS NULL THEN
    RAISE EXCEPTION 'notification SMTP test input is invalid' USING ERRCODE = '22023';
  END IF;
  SELECT * INTO STRICT pin
  FROM app.private_resolve_tenant_notification_smtp_pin_v1(p_configuration_version);
  PERFORM pg_advisory_xact_lock(hashtextextended(
    context_tenant::text || ':' || actor_membership::text
      || ':smtp.test:' || encode(p_key_digest, 'hex'), 0
  ));
  SELECT stored.* INTO command
  FROM public.tenant_notification_commands AS stored
  WHERE stored.tenant_id = context_tenant
    AND stored.actor_membership_id = actor_membership
    AND stored.operation = 'smtp.test' AND stored.key_digest = p_key_digest;
  IF FOUND THEN
    IF command.request_digest IS DISTINCT FROM p_request_digest THEN
      RAISE EXCEPTION 'notification SMTP test idempotency key conflicts'
        USING ERRCODE = '23505';
    END IF;
    projection := jsonb_build_object(
      'configurationId', pin.configuration_id,
      'configurationVersion', command.result_version,
      'healthy', true, 'checkedAt', command.created_at,
      'checks', jsonb_build_array(jsonb_build_object(
        'kind', 'connect', 'outcome', 'skipped'
      )),
      'queuedDeliveryId', CASE
        WHEN command.result_resource_id = pin.configuration_id THEN NULL
        ELSE command.result_resource_id END
    );
    replayed := true;
    RETURN NEXT;
    RETURN;
  END IF;

  result_resource := pin.configuration_id;
  IF p_recipient IS NOT NULL THEN
    event_id := uuidv7();
    delivery_key := encode(sha256(convert_to(
      'periapsis:notification-smtp-test:v1|' || context_tenant::text
        || '|' || p_delivery_id::text || '|' || pin.configuration_scope
        || '|' || pin.configuration_id::text || '|' || pin.configuration_version::text,
      'UTF8'
    )), 'hex');
    PERFORM app.private_insert_notification_test_event_v1(
      event_id, 'webhook.custom', 'contact', pin.configuration_id,
      pin.configuration_version, 'operator', '{}'::jsonb, NULL,
      p_occurred_at, p_correlation_id, p_request_id,
      'notification:smtp-test:' || delivery_key
    );
    redacted_recipient := left(split_part(p_recipient, '@', 1), 1)
      || '***@' || split_part(p_recipient, '@', 2);
    INSERT INTO public.tenant_notification_deliveries (
      id, tenant_id, event_id, delivery_key, template_snapshot,
      smtp_configuration_scope, smtp_configuration_id,
      smtp_configuration_version, channel, audience, recipient,
      destination_redacted, context, priority, deduplication_key,
      grouping_window_ms, grouping_maximum_items, retry,
      maximum_attempts, next_attempt_at, created_at, updated_at
    ) VALUES (
      p_delivery_id, context_tenant, event_id, delivery_key,
      '{"key":"system.smtp-test","name":"Periapsis SMTP test","language":"en","version":1,"subject":"Periapsis SMTP test","html":"<p>This message verifies your Periapsis SMTP configuration.</p>","plainText":"This message verifies your Periapsis SMTP configuration.","css":""}'::jsonb,
      pin.configuration_scope, pin.configuration_id,
      pin.configuration_version, 'email', 'operator', p_recipient,
      redacted_recipient, '{}'::jsonb, 100, delivery_key,
      0, 1,
      '{"maximumAttempts":3,"initialDelayMs":1000,"maximumDelayMs":30000,"multiplier":2,"jitterPercent":10}'::jsonb,
      3, p_occurred_at, p_occurred_at, p_occurred_at
    );
    result_resource := p_delivery_id;
  END IF;
  INSERT INTO public.tenant_notification_commands (
    tenant_id, actor_membership_id, actor_user_id, operation,
    key_digest, request_digest, result_resource_id, result_version, created_at
  ) VALUES (
    context_tenant, actor_membership, actor_user, 'smtp.test',
    p_key_digest, p_request_digest, result_resource,
    pin.configuration_version, p_occurred_at
  );
  PERFORM app.private_append_notification_admin_audit_v1(
    'smtp.test', 'notification_smtp_configuration', pin.configuration_id,
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method, NULL,
    jsonb_build_object(
      'configurationId', pin.configuration_id,
      'configurationVersion', pin.configuration_version,
      'deliveryQueued', p_delivery_id IS NOT NULL,
      'contentRedacted', true
    )
  );
  projection := jsonb_build_object(
    'configurationId', pin.configuration_id,
    'configurationVersion', pin.configuration_version,
    'healthy', true, 'checkedAt', p_occurred_at,
    'checks', jsonb_build_array(jsonb_build_object(
      'kind', 'connect', 'outcome', 'skipped'
    )), 'queuedDeliveryId', p_delivery_id
  );
  replayed := false;
  RETURN NEXT;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.test_tenant_notification_smtp_v1(
  integer, uuid, text, text, bytea, bytea, timestamp with time zone,
  uuid, uuid, inet, text, text
) OWNER TO periapsis_notification_admin_owner;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.test_tenant_notification_smtp_v1(
  integer, uuid, text, text, bytea, bytea, timestamp with time zone,
  uuid, uuid, inet, text, text
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.test_tenant_notification_smtp_v1(
  integer, uuid, text, text, bytea, bytea, timestamp with time zone,
  uuid, uuid, inet, text, text
) TO periapsis_api;--> statement-breakpoint

CREATE FUNCTION app.test_platform_notification_smtp_v1(
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
  actor_user uuid := app.context_user_id();
  selected record;
  command public.platform_notification_commands%ROWTYPE;
BEGIN
  IF actor_user IS NULL OR NOT app.platform_user_has_permission(
    actor_user, 'platform.notification.manage'
  ) THEN
    RAISE EXCEPTION 'platform.notification.manage is required' USING ERRCODE = '42501';
  END IF;
  IF p_recipient IS NOT NULL OR p_configuration_version NOT BETWEEN 1 AND 2147483647
     OR p_reason IS NULL OR char_length(p_reason) NOT BETWEEN 1 AND 1000
     OR p_key_digest IS NULL OR octet_length(p_key_digest) <> 32
     OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32
     OR p_occurred_at IS NULL
     OR p_occurred_at < transaction_timestamp() - interval '5 minutes'
     OR p_occurred_at > transaction_timestamp() + interval '1 minute'
     OR p_request_id IS NULL OR p_correlation_id IS NULL
     OR p_ip_address IS NULL OR p_authentication_method IS NULL THEN
    RAISE EXCEPTION 'platform notification SMTP health input is invalid'
      USING ERRCODE = '22023';
  END IF;
  SELECT identity.id, version.version INTO STRICT selected
  FROM public.platform_notification_smtp_configurations AS identity
  JOIN public.platform_notification_smtp_configuration_versions AS version
    ON version.configuration_id = identity.id
   AND version.version = identity.current_version
  WHERE identity.revoked_at IS NULL AND version.enabled
    AND version.version = p_configuration_version;
  PERFORM pg_advisory_xact_lock(hashtextextended(
    actor_user::text || ':smtp.test:' || encode(p_key_digest, 'hex'), 0
  ));
  SELECT stored.* INTO command
  FROM public.platform_notification_commands AS stored
  WHERE stored.actor_user_id = actor_user AND stored.operation = 'smtp.test'
    AND stored.key_digest = p_key_digest;
  IF FOUND THEN
    IF command.request_digest IS DISTINCT FROM p_request_digest THEN
      RAISE EXCEPTION 'platform SMTP health idempotency key conflicts'
        USING ERRCODE = '23505';
    END IF;
    projection := jsonb_build_object(
      'configurationId', command.result_resource_id,
      'configurationVersion', command.result_version,
      'healthy', true, 'checkedAt', command.created_at,
      'checks', jsonb_build_array(jsonb_build_object(
        'kind', 'connect', 'outcome', 'skipped'
      ))
    ); replayed := true; RETURN NEXT; RETURN;
  END IF;
  INSERT INTO public.platform_notification_commands (
    actor_user_id, operation, key_digest, request_digest,
    result_resource_id, result_version, created_at
  ) VALUES (
    actor_user, 'smtp.test', p_key_digest, p_request_digest,
    selected.id, selected.version, p_occurred_at
  );
  PERFORM app.append_platform_audit_event(
    uuidv7(), 'human', actor_user, 'platform.notification.smtp_test',
    'notification_smtp_configuration', selected.id,
    p_request_id, p_correlation_id, p_ip_address, nullif(p_user_agent, ''),
    p_authentication_method, 'success', NULL,
    jsonb_build_object(
      'version', selected.version, 'healthOnly', true,
      'contentRedacted', true, 'secretMaterialIncluded', false
    )
  );
  projection := jsonb_build_object(
    'configurationId', selected.id,
    'configurationVersion', selected.version,
    'healthy', true, 'checkedAt', p_occurred_at,
    'checks', jsonb_build_array(jsonb_build_object(
      'kind', 'connect', 'outcome', 'skipped'
    ))
  ); replayed := false; RETURN NEXT;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.test_platform_notification_smtp_v1(
  integer, text, text, bytea, bytea, timestamp with time zone,
  uuid, uuid, inet, text, text
) OWNER TO periapsis_notification_admin_owner;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.test_platform_notification_smtp_v1(
  integer, text, text, bytea, bytea, timestamp with time zone,
  uuid, uuid, inet, text, text
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.test_platform_notification_smtp_v1(
  integer, text, text, bytea, bytea, timestamp with time zone,
  uuid, uuid, inet, text, text
) TO periapsis_api;

CREATE FUNCTION app.enqueue_tenant_notification_template_test_v1(
  p_template_id uuid,
  p_template_version integer,
  p_delivery_id uuid,
  p_recipient text,
  p_audience public.notification_audience,
  p_context jsonb,
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
  context_tenant uuid;
  actor_membership uuid;
  actor_user uuid;
  command public.tenant_notification_commands%ROWTYPE;
  pin record;
  event_id uuid;
  delivery_key text;
BEGIN
  PERFORM app.private_require_notification_admin_v1();
  context_tenant := app.context_tenant_id();
  actor_membership := app.current_tenant_membership_id();
  actor_user := app.context_user_id();
  IF p_template_id IS NULL OR uuid_extract_version(p_template_id) <> 7
     OR p_template_version NOT BETWEEN 1 AND 2147483647
     OR p_delivery_id IS NULL OR uuid_extract_version(p_delivery_id) <> 7
     OR p_recipient IS NULL OR p_recipient <> lower(btrim(p_recipient))
     OR char_length(p_recipient) NOT BETWEEN 3 AND 320
     OR p_recipient !~ '^[^[:space:]@]+@[^[:space:]@]+$'
     OR NOT app.private_notification_context_is_safe_v1(p_context)
     OR p_reason IS NULL OR char_length(p_reason) NOT BETWEEN 1 AND 1000
     OR p_reason ~ '[[:cntrl:]]'
     OR p_key_digest IS NULL OR octet_length(p_key_digest) <> 32
     OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32
     OR p_occurred_at IS NULL
     OR p_occurred_at < transaction_timestamp() - interval '5 minutes'
     OR p_occurred_at > transaction_timestamp() + interval '1 minute'
     OR p_request_id IS NULL OR p_correlation_id IS NULL
     OR p_ip_address IS NULL OR p_authentication_method IS NULL THEN
    RAISE EXCEPTION 'notification template test input is invalid' USING ERRCODE = '22023';
  END IF;
  PERFORM 1
  FROM public.tenant_notification_templates AS identity
  JOIN public.tenant_notification_template_versions AS version
    ON version.tenant_id = identity.tenant_id
   AND version.template_id = identity.id
   AND version.version = p_template_version
  WHERE identity.tenant_id = context_tenant AND identity.id = p_template_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'notification template pin was not found' USING ERRCODE = 'P0002';
  END IF;
  SELECT * INTO STRICT pin
  FROM app.private_resolve_tenant_notification_smtp_pin_v1((
    SELECT coalesce(
      (SELECT current_version FROM public.tenant_notification_smtp_configurations
       WHERE tenant_id = context_tenant AND revoked_at IS NULL),
      (SELECT current_version FROM public.platform_notification_smtp_configurations
       WHERE revoked_at IS NULL)
    )
  ));
  PERFORM pg_advisory_xact_lock(hashtextextended(
    context_tenant::text || ':' || actor_membership::text
      || ':template.test:' || encode(p_key_digest, 'hex'), 0
  ));
  SELECT stored.* INTO command
  FROM public.tenant_notification_commands AS stored
  WHERE stored.tenant_id = context_tenant
    AND stored.actor_membership_id = actor_membership
    AND stored.operation = 'template.test' AND stored.key_digest = p_key_digest;
  IF FOUND THEN
    IF command.request_digest IS DISTINCT FROM p_request_digest THEN
      RAISE EXCEPTION 'notification template test idempotency key conflicts'
        USING ERRCODE = '23505';
    END IF;
    projection := app.private_tenant_notification_projection_v1(
      'delivery', command.result_resource_id, NULL, false
    ); replayed := true; RETURN NEXT; RETURN;
  END IF;
  event_id := uuidv7();
  delivery_key := encode(sha256(convert_to(
    'periapsis:notification-template-test:v1|' || context_tenant::text
      || '|' || p_delivery_id::text || '|' || p_template_id::text
      || '|' || p_template_version::text, 'UTF8'
  )), 'hex');
  PERFORM app.private_insert_notification_test_event_v1(
    event_id, 'webhook.custom', 'contact', p_template_id,
    p_template_version, p_audience,
    CASE WHEN p_audience = 'operator' THEN p_context ELSE '{}'::jsonb END,
    CASE WHEN p_audience = 'customer' THEN p_context ELSE NULL END,
    p_occurred_at, p_correlation_id, p_request_id,
    'notification:template-test:' || delivery_key
  );
  INSERT INTO public.tenant_notification_deliveries (
    id, tenant_id, event_id, delivery_key, template_id, template_version,
    smtp_configuration_scope, smtp_configuration_id,
    smtp_configuration_version, channel, audience, recipient,
    destination_redacted, context, priority, deduplication_key,
    grouping_window_ms, grouping_maximum_items, retry,
    maximum_attempts, next_attempt_at, created_at, updated_at
  ) VALUES (
    p_delivery_id, context_tenant, event_id, delivery_key,
    p_template_id, p_template_version, pin.configuration_scope,
    pin.configuration_id, pin.configuration_version,
    'email', p_audience, p_recipient,
    left(split_part(p_recipient, '@', 1), 1) || '***@' || split_part(p_recipient, '@', 2),
    p_context, 100, delivery_key, 0, 1,
    '{"maximumAttempts":3,"initialDelayMs":1000,"maximumDelayMs":30000,"multiplier":2,"jitterPercent":10}'::jsonb,
    3, p_occurred_at, p_occurred_at, p_occurred_at
  );
  INSERT INTO public.tenant_notification_commands (
    tenant_id, actor_membership_id, actor_user_id, operation,
    key_digest, request_digest, result_resource_id, result_version, created_at
  ) VALUES (
    context_tenant, actor_membership, actor_user, 'template.test',
    p_key_digest, p_request_digest, p_delivery_id, p_template_version, p_occurred_at
  );
  PERFORM app.private_append_notification_admin_audit_v1(
    'template.test', 'notification_template', p_template_id,
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method, NULL,
    jsonb_build_object('version', p_template_version,
      'deliveryId', p_delivery_id, 'contentRedacted', true)
  );
  projection := app.private_tenant_notification_projection_v1(
    'delivery', p_delivery_id, NULL, false
  ); replayed := false; RETURN NEXT;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.enqueue_tenant_notification_template_test_v1(
  uuid, integer, uuid, text, public.notification_audience, jsonb, text,
  bytea, bytea, timestamp with time zone, uuid, uuid, inet, text, text
) OWNER TO periapsis_notification_admin_owner;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.enqueue_tenant_notification_template_test_v1(
  uuid, integer, uuid, text, public.notification_audience, jsonb, text,
  bytea, bytea, timestamp with time zone, uuid, uuid, inet, text, text
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.enqueue_tenant_notification_template_test_v1(
  uuid, integer, uuid, text, public.notification_audience, jsonb, text,
  bytea, bytea, timestamp with time zone, uuid, uuid, inet, text, text
) TO periapsis_api;--> statement-breakpoint

CREATE FUNCTION app.enqueue_tenant_notification_webhook_test_v1(
  p_webhook_id uuid,
  p_configuration_version integer,
  p_delivery_id uuid,
  p_event_type public.notification_event_type,
  p_context jsonb,
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
  context_tenant uuid;
  actor_membership uuid;
  actor_user uuid;
  selected public.tenant_notification_webhook_configuration_versions%ROWTYPE;
  secret public.tenant_notification_secret_versions%ROWTYPE;
  command public.tenant_notification_commands%ROWTYPE;
  event_id uuid;
  delivery_key text;
  selected_context jsonb;
  object_type public.notification_object_type;
  payload jsonb;
BEGIN
  PERFORM app.private_require_notification_admin_v1();
  context_tenant := app.context_tenant_id();
  actor_membership := app.current_tenant_membership_id();
  actor_user := app.context_user_id();
  IF p_webhook_id IS NULL OR uuid_extract_version(p_webhook_id) <> 7
     OR p_configuration_version NOT BETWEEN 1 AND 2147483647
     OR p_delivery_id IS NULL OR uuid_extract_version(p_delivery_id) <> 7
     OR NOT app.private_notification_context_is_safe_v1(p_context)
     OR p_reason IS NULL OR char_length(p_reason) NOT BETWEEN 1 AND 1000
     OR p_reason ~ '[[:cntrl:]]'
     OR p_key_digest IS NULL OR octet_length(p_key_digest) <> 32
     OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32
     OR p_occurred_at IS NULL
     OR p_occurred_at < transaction_timestamp() - interval '5 minutes'
     OR p_occurred_at > transaction_timestamp() + interval '1 minute'
     OR p_request_id IS NULL OR p_correlation_id IS NULL
     OR p_ip_address IS NULL OR p_authentication_method IS NULL THEN
    RAISE EXCEPTION 'notification webhook test input is invalid' USING ERRCODE = '22023';
  END IF;
  SELECT version.* INTO STRICT selected
  FROM public.tenant_notification_webhook_configurations AS identity
  JOIN public.tenant_notification_webhook_configuration_versions AS version
    ON version.tenant_id = identity.tenant_id
   AND version.configuration_id = identity.id
   AND version.version = identity.current_version
  WHERE identity.tenant_id = context_tenant AND identity.id = p_webhook_id
    AND identity.revoked_at IS NULL AND version.enabled
    AND version.version = p_configuration_version
    AND p_event_type = ANY(version.event_types);
  SELECT stored.* INTO STRICT secret
  FROM public.tenant_notification_secret_versions AS stored
  WHERE stored.tenant_id = context_tenant
    AND stored.secret_id = selected.signing_secret_id
    AND stored.version = selected.signing_secret_version
    AND stored.kind = 'webhook_signing_key';
  selected_context := CASE selected.audience
    WHEN 'customer' THEN p_context -> 'customer' ELSE p_context END;
  IF selected_context IS NULL
     OR NOT app.private_notification_context_is_safe_v1(selected_context) THEN
    RAISE EXCEPTION 'webhook customer projection is unavailable' USING ERRCODE = '42501';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(
    context_tenant::text || ':' || actor_membership::text
      || ':webhook.test:' || encode(p_key_digest, 'hex'), 0
  ));
  SELECT stored.* INTO command
  FROM public.tenant_notification_commands AS stored
  WHERE stored.tenant_id = context_tenant
    AND stored.actor_membership_id = actor_membership
    AND stored.operation = 'webhook.test' AND stored.key_digest = p_key_digest;
  IF FOUND THEN
    IF command.request_digest IS DISTINCT FROM p_request_digest THEN
      RAISE EXCEPTION 'notification webhook test idempotency key conflicts'
        USING ERRCODE = '23505';
    END IF;
    projection := app.private_tenant_notification_projection_v1(
      'delivery', command.result_resource_id, NULL, false
    ); replayed := true; RETURN NEXT; RETURN;
  END IF;
  object_type := CASE split_part(p_event_type::text, '.', 1)
    WHEN 'alert' THEN 'alert' WHEN 'case' THEN 'case'
    WHEN 'task' THEN 'task' WHEN 'evidence' THEN 'evidence'
    WHEN 'contact' THEN 'contact' WHEN 'comment' THEN 'case'
    WHEN 'sla' THEN 'case' ELSE 'contact' END;
  event_id := uuidv7();
  delivery_key := encode(sha256(convert_to(
    'periapsis:notification-webhook-test:v1|' || context_tenant::text
      || '|' || p_delivery_id::text || '|' || p_webhook_id::text
      || '|' || p_configuration_version::text || '|' || p_event_type::text,
    'UTF8'
  )), 'hex');
  PERFORM app.private_insert_notification_test_event_v1(
    event_id, p_event_type, object_type, p_webhook_id,
    p_configuration_version, selected.audience,
    CASE WHEN selected.audience = 'operator' THEN selected_context ELSE '{}'::jsonb END,
    CASE WHEN selected.audience = 'customer' THEN selected_context ELSE NULL END,
    p_occurred_at, p_correlation_id, p_request_id,
    'notification:webhook-test:' || delivery_key
  );
  payload := jsonb_build_object(
    'schemaVersion', 1,
    'event', jsonb_build_object(
      'id', event_id, 'type', p_event_type, 'objectType', object_type,
      'objectId', p_webhook_id, 'objectVersion', p_configuration_version,
      'occurredAt', p_occurred_at, 'actorId', actor_user
    ), 'context', selected_context
  );
  INSERT INTO public.tenant_notification_deliveries (
    id, tenant_id, event_id, delivery_key,
    webhook_configuration_id, webhook_configuration_version,
    webhook_signing_secret_id, webhook_signing_secret_version,
    webhook_signing_key_version, webhook_payload_version, webhook_payload,
    channel, audience, recipient, destination_redacted, context, priority,
    deduplication_key, grouping_window_ms, grouping_maximum_items, retry,
    maximum_attempts, next_attempt_at, created_at, updated_at
  ) VALUES (
    p_delivery_id, context_tenant, event_id, delivery_key,
    p_webhook_id, p_configuration_version, secret.secret_id,
    secret.version, secret.key_version, 1, payload,
    'webhook', selected.audience, 'webhook:' || p_webhook_id::text,
    'webhook:' || left(p_webhook_id::text, 8) || '…', selected_context,
    100, delivery_key, 0, 1,
    '{"maximumAttempts":3,"initialDelayMs":1000,"maximumDelayMs":30000,"multiplier":2,"jitterPercent":10}'::jsonb,
    3, p_occurred_at, p_occurred_at, p_occurred_at
  );
  INSERT INTO public.tenant_notification_commands (
    tenant_id, actor_membership_id, actor_user_id, operation,
    key_digest, request_digest, result_resource_id, result_version, created_at
  ) VALUES (
    context_tenant, actor_membership, actor_user, 'webhook.test',
    p_key_digest, p_request_digest, p_delivery_id,
    p_configuration_version, p_occurred_at
  );
  PERFORM app.private_append_notification_admin_audit_v1(
    'webhook.test', 'notification_webhook', p_webhook_id,
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method, NULL,
    jsonb_build_object('version', p_configuration_version,
      'deliveryId', p_delivery_id, 'contentRedacted', true)
  );
  projection := app.private_tenant_notification_projection_v1(
    'delivery', p_delivery_id, NULL, false
  ); replayed := false; RETURN NEXT;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.enqueue_tenant_notification_webhook_test_v1(
  uuid, integer, uuid, public.notification_event_type, jsonb, text,
  bytea, bytea, timestamp with time zone, uuid, uuid, inet, text, text
) OWNER TO periapsis_notification_admin_owner;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.enqueue_tenant_notification_webhook_test_v1(
  uuid, integer, uuid, public.notification_event_type, jsonb, text,
  bytea, bytea, timestamp with time zone, uuid, uuid, inet, text, text
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.enqueue_tenant_notification_webhook_test_v1(
  uuid, integer, uuid, public.notification_event_type, jsonb, text,
  bytea, bytea, timestamp with time zone, uuid, uuid, inet, text, text
) TO periapsis_api;--> statement-breakpoint

CREATE FUNCTION app.retry_tenant_notification_delivery_v1(
  p_source_delivery_id uuid,
  p_delivery_id uuid,
  p_expected_attempt integer,
  p_acknowledge_uncertain boolean,
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
  context_tenant uuid;
  actor_membership uuid;
  actor_user uuid;
  source public.tenant_notification_deliveries%ROWTYPE;
  command public.tenant_notification_commands%ROWTYPE;
  delivery_key text;
BEGIN
  PERFORM app.private_require_notification_admin_v1();
  context_tenant := app.context_tenant_id();
  actor_membership := app.current_tenant_membership_id();
  actor_user := app.context_user_id();
  IF p_source_delivery_id IS NULL OR uuid_extract_version(p_source_delivery_id) <> 7
     OR p_delivery_id IS NULL OR uuid_extract_version(p_delivery_id) <> 7
     OR p_delivery_id = p_source_delivery_id
     OR p_expected_attempt NOT BETWEEN 1 AND 100
     OR p_acknowledge_uncertain IS NULL
     OR p_reason IS NULL OR char_length(p_reason) NOT BETWEEN 1 AND 1000
     OR p_reason ~ '[[:cntrl:]]'
     OR p_key_digest IS NULL OR octet_length(p_key_digest) <> 32
     OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32
     OR p_occurred_at IS NULL
     OR p_occurred_at < transaction_timestamp() - interval '5 minutes'
     OR p_occurred_at > transaction_timestamp() + interval '1 minute'
     OR p_request_id IS NULL OR p_correlation_id IS NULL
     OR p_ip_address IS NULL OR p_authentication_method IS NULL THEN
    RAISE EXCEPTION 'notification delivery retry input is invalid' USING ERRCODE = '22023';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(
    context_tenant::text || ':' || actor_membership::text
      || ':delivery.retry:' || encode(p_key_digest, 'hex'), 0
  ));
  SELECT stored.* INTO command
  FROM public.tenant_notification_commands AS stored
  WHERE stored.tenant_id = context_tenant
    AND stored.actor_membership_id = actor_membership
    AND stored.operation = 'delivery.retry' AND stored.key_digest = p_key_digest;
  IF FOUND THEN
    IF command.request_digest IS DISTINCT FROM p_request_digest THEN
      RAISE EXCEPTION 'notification delivery retry idempotency key conflicts'
        USING ERRCODE = '23505';
    END IF;
    projection := app.private_tenant_notification_projection_v1(
      'delivery', command.result_resource_id, NULL, false
    ); replayed := true; RETURN NEXT; RETURN;
  END IF;
  SELECT delivery.* INTO STRICT source
  FROM public.tenant_notification_deliveries AS delivery
  WHERE delivery.tenant_id = context_tenant AND delivery.id = p_source_delivery_id
  FOR UPDATE;
  IF source.status <> 'dead_lettered'
     OR source.attempt_count <> p_expected_attempt
     OR source.failure_class = 'submission_uncertain' AND NOT p_acknowledge_uncertain
     OR source.failure_class <> 'submission_uncertain' AND p_acknowledge_uncertain THEN
    RAISE EXCEPTION 'notification delivery retry precondition failed'
      USING ERRCODE = '40001';
  END IF;
  delivery_key := encode(sha256(convert_to(
    'periapsis:notification-manual-retry:v1|' || context_tenant::text
      || '|' || p_source_delivery_id::text || '|' || p_delivery_id::text
      || '|' || p_expected_attempt::text, 'UTF8'
  )), 'hex');
  INSERT INTO public.tenant_notification_deliveries (
    id, tenant_id, event_id, parent_delivery_id, delivery_key,
    rule_id, rule_version, template_id, template_version, template_snapshot,
    smtp_configuration_scope, smtp_configuration_id,
    smtp_configuration_version, webhook_configuration_id,
    webhook_configuration_version, webhook_signing_secret_id,
    webhook_signing_secret_version, webhook_signing_key_version,
    webhook_payload_version, webhook_payload, channel, audience, recipient,
    destination_redacted, context, priority, deduplication_key,
    grouping_key, grouping_window_ms, grouping_maximum_items, retry,
    maximum_attempts, next_attempt_at, created_at, updated_at
  ) VALUES (
    p_delivery_id, context_tenant, source.event_id, source.id, delivery_key,
    source.rule_id, source.rule_version, source.template_id,
    source.template_version, source.template_snapshot,
    source.smtp_configuration_scope, source.smtp_configuration_id,
    source.smtp_configuration_version, source.webhook_configuration_id,
    source.webhook_configuration_version, source.webhook_signing_secret_id,
    source.webhook_signing_secret_version, source.webhook_signing_key_version,
    source.webhook_payload_version, source.webhook_payload, source.channel,
    source.audience, source.recipient, source.destination_redacted,
    source.context, source.priority, delivery_key, source.grouping_key,
    source.grouping_window_ms, source.grouping_maximum_items, source.retry,
    source.maximum_attempts, p_occurred_at, p_occurred_at, p_occurred_at
  );
  INSERT INTO public.tenant_notification_commands (
    tenant_id, actor_membership_id, actor_user_id, operation,
    key_digest, request_digest, result_resource_id, result_version, created_at
  ) VALUES (
    context_tenant, actor_membership, actor_user, 'delivery.retry',
    p_key_digest, p_request_digest, p_delivery_id, 1, p_occurred_at
  );
  PERFORM app.private_append_notification_admin_audit_v1(
    'delivery.retry', 'notification_delivery', p_source_delivery_id,
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method,
    jsonb_build_object('status', source.status,
      'attemptCount', source.attempt_count, 'contentRedacted', true),
    jsonb_build_object('retryDeliveryId', p_delivery_id,
      'acknowledgedUncertain', p_acknowledge_uncertain,
      'contentRedacted', true)
  );
  projection := app.private_tenant_notification_projection_v1(
    'delivery', p_delivery_id, NULL, false
  ); replayed := false; RETURN NEXT;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.retry_tenant_notification_delivery_v1(
  uuid, uuid, integer, boolean, text, bytea, bytea,
  timestamp with time zone, uuid, uuid, inet, text, text
) OWNER TO periapsis_notification_admin_owner;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.retry_tenant_notification_delivery_v1(
  uuid, uuid, integer, boolean, text, bytea, bytea,
  timestamp with time zone, uuid, uuid, inet, text, text
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.retry_tenant_notification_delivery_v1(
  uuid, uuid, integer, boolean, text, bytea, bytea,
  timestamp with time zone, uuid, uuid, inet, text, text
) TO periapsis_api;

-- The legacy AFTER INSERT trigger pre-dates the canonical v2 notification
-- envelope. Preserve its activity and SLA effects, but stop it from producing
-- an ambiguous schema-v1 notification. The v3 create ABIs append the complete
-- visibility-safe v2 event only after the full Alert projection is committed.
CREATE OR REPLACE FUNCTION app.append_alert_ticketing_create_effects_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  principal public.ticket_principal_kind;
BEGIN
  principal := CASE
    WHEN NEW.created_by_membership_id IS NOT NULL THEN 'human'
    ELSE 'service_account'
  END;
  INSERT INTO public.ticket_activities (
    tenant_id, alert_id, sequence, kind, summary,
    actor_principal_kind, actor_membership_id, actor_user_id,
    actor_service_account_id, origin, details, occurred_at
  ) VALUES (
    NEW.tenant_id, NEW.id, 1, 'alert.created', 'Alert created',
    principal, NEW.created_by_membership_id, NEW.created_by,
    NEW.created_by_service_account_id, 'api',
    jsonb_build_object('severity', NEW.severity, 'version', 1), NEW.created_at
  );
  INSERT INTO public.outbox_events (
    tenant_id, aggregate_type, aggregate_id, aggregate_version,
    event_type, schema_version, payload, deduplication_key,
    occurred_at
  ) VALUES (
    NEW.tenant_id, 'alert', NEW.id, 1, 'sla.alert.created', 1,
    jsonb_build_object('alert_id', NEW.id, 'version', 1),
    'sla.alert.created:' || NEW.id::text, NEW.created_at
  );
  RETURN NEW;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.append_alert_ticketing_create_effects_v1()
OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.append_alert_ticketing_create_effects_v1()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
     periapsis_auditor;--> statement-breakpoint

-- Alert ingest runs through a separate repository from ticketing. These
-- successors bind the authenticated HTTP span explicitly to the mutation and
-- append one canonical notification event after all full-payload updates. The
-- bearer entry point remains a single bounded SECURITY DEFINER call: it does
-- not require tenant or human GUC setup before credential authentication.
CREATE FUNCTION app.create_tenant_alert_as_human_v3(
  p_title text,
  p_description text,
  p_external_id text,
  p_severity public.alert_severity,
  p_source text,
  p_source_type text,
  p_deduplication_key text,
  p_raw_payload jsonb,
  p_priority text,
  p_category text,
  p_classification text,
  p_detected_at timestamp with time zone,
  p_customer_visible boolean,
  p_tags text[],
  p_custom_fields jsonb,
  p_workflow_id uuid,
  p_assigned_team_id uuid,
  p_assignee_user_id uuid,
  p_key_digest bytea,
  p_request_digest bytea,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text,
  p_traceparent text,
  p_tracestate text
)
RETURNS TABLE (
  id uuid, number text, workflow_id uuid, workflow_version integer,
  state_key text, customer_visible boolean, external_id text,
  deduplication_key text, title text, description text,
  status public.alert_status, severity public.alert_severity,
  priority text, category text, classification text, source text,
  source_type text, tags text[], custom_fields jsonb,
  customer_custom_fields jsonb, raw_payload jsonb,
  assigned_team_id uuid, assignee_user_id uuid, claimed_by_user_id uuid,
  created_by_user_id uuid, created_by_membership_id uuid,
  created_by_service_account_id uuid, detected_at timestamp with time zone,
  received_at timestamp with time zone, acknowledged_at timestamp with time zone,
  closed_at timestamp with time zone, assigned_at timestamp with time zone,
  first_response_at timestamp with time zone, resolved_at timestamp with time zone,
  claimed_at timestamp with time zone, created_at timestamp with time zone,
  updated_at timestamp with time zone, version integer, replayed boolean
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  created record;
BEGIN
  IF NOT app.private_notification_trace_context_is_safe_v1(
    p_traceparent, p_tracestate
  ) THEN
    RAISE EXCEPTION 'Alert trace context is invalid' USING ERRCODE = '22023';
  END IF;
  PERFORM set_config('app.traceparent', coalesce(p_traceparent, ''), true);
  PERFORM set_config('app.tracestate', coalesce(p_tracestate, ''), true);
  SELECT result.* INTO STRICT created
  FROM app.create_tenant_alert_as_human_v2(
    p_title, p_description, p_external_id, p_severity,
    p_source, p_source_type, p_deduplication_key, p_raw_payload,
    p_priority, p_category, p_classification, p_detected_at,
    p_customer_visible, p_tags, p_custom_fields, p_workflow_id,
    p_assigned_team_id, p_assignee_user_id, p_key_digest,
    p_request_digest, p_request_id, p_correlation_id, p_ip_address,
    p_user_agent, p_authentication_method
  ) AS result;
  IF NOT created.replayed THEN
    PERFORM app.private_append_tenant_notification_event_v3(
      uuidv7(), 'alert.created', 'alert', created.id, created.version,
      created.created_at, 'human', created.created_by_user_id,
      'ticketing', CASE WHEN created.customer_visible
        THEN 'customer'::public.notification_audience
        ELSE 'operator'::public.notification_audience END,
      jsonb_build_object(
        'alert', jsonb_strip_nulls(jsonb_build_object(
          'id', created.id, 'number', created.number,
          'version', created.version, 'title', created.title,
          'status', created.status, 'severity', created.severity,
          'priority', created.priority, 'category', created.category,
          'classification', created.classification,
          'source', created.source, 'sourceType', created.source_type,
          'detectedAt', created.detected_at,
          'receivedAt', created.received_at,
          'customerVisible', created.customer_visible
        )),
        'actor', jsonb_build_object('id', created.created_by_user_id),
        'action', 'created',
        'routing', jsonb_strip_nulls(jsonb_build_object(
          'assigneeUserId', created.assignee_user_id,
          'operatorTeamId', created.assigned_team_id
        ))
      ),
      CASE WHEN created.customer_visible THEN jsonb_build_object(
        'alert', jsonb_strip_nulls(jsonb_build_object(
          'id', created.id, 'number', created.number,
          'version', created.version, 'title', created.title,
          'status', created.status, 'severity', created.severity,
          'priority', created.priority, 'category', created.category,
          'detectedAt', created.detected_at,
          'customerVisible', true
        ))
      ) END,
      'notification:v2:alert:' || created.id::text || ':1:alert.created',
      p_correlation_id, p_request_id, p_traceparent, p_tracestate
    );
  END IF;
  RETURN QUERY SELECT
    created.id, created.number, created.workflow_id,
    created.workflow_version, created.state_key, created.customer_visible,
    created.external_id, created.deduplication_key, created.title,
    created.description, created.status, created.severity, created.priority,
    created.category, created.classification, created.source,
    created.source_type, created.tags, created.custom_fields,
    created.customer_custom_fields, created.raw_payload,
    created.assigned_team_id, created.assignee_user_id,
    created.claimed_by_user_id, created.created_by_user_id,
    created.created_by_membership_id,
    created.created_by_service_account_id, created.detected_at,
    created.received_at, created.acknowledged_at, created.closed_at,
    created.assigned_at, created.first_response_at, created.resolved_at,
    created.claimed_at, created.created_at, created.updated_at,
    created.version, created.replayed;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.create_tenant_alert_as_human_v3(
  text, text, text, public.alert_severity, text, text, text, jsonb,
  text, text, text, timestamp with time zone, boolean, text[], jsonb,
  uuid, uuid, uuid, bytea, bytea, uuid, uuid, inet, text, text, text, text
) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.create_tenant_alert_as_human_v3(
  text, text, text, public.alert_severity, text, text, text, jsonb,
  text, text, text, timestamp with time zone, boolean, text[], jsonb,
  uuid, uuid, uuid, bytea, bytea, uuid, uuid, inet, text, text, text, text
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.create_tenant_alert_as_human_v3(
  text, text, text, public.alert_severity, text, text, text, jsonb,
  text, text, text, timestamp with time zone, boolean, text[], jsonb,
  uuid, uuid, uuid, bytea, bytea, uuid, uuid, inet, text, text, text, text
) TO periapsis_api;--> statement-breakpoint

CREATE FUNCTION app.create_tenant_alert_as_service_account_v3(
  p_tenant_id uuid,
  p_locator bytea,
  p_envelope_key_version integer,
  p_secret_digest bytea,
  p_client_address inet,
  p_title text,
  p_description text,
  p_external_id text,
  p_severity public.alert_severity,
  p_source text,
  p_source_type text,
  p_deduplication_key text,
  p_raw_payload jsonb,
  p_priority text,
  p_category text,
  p_classification text,
  p_detected_at timestamp with time zone,
  p_customer_visible boolean,
  p_tags text[],
  p_custom_fields jsonb,
  p_workflow_id uuid,
  p_assigned_team_id uuid,
  p_assignee_user_id uuid,
  p_key_digest bytea,
  p_request_digest bytea,
  p_request_id uuid,
  p_correlation_id uuid,
  p_user_agent text,
  p_traceparent text,
  p_tracestate text
)
RETURNS TABLE (
  id uuid, number text, workflow_id uuid, workflow_version integer,
  state_key text, customer_visible boolean, external_id text,
  deduplication_key text, title text, description text,
  status public.alert_status, severity public.alert_severity,
  priority text, category text, classification text, source text,
  source_type text, tags text[], custom_fields jsonb,
  customer_custom_fields jsonb, raw_payload jsonb,
  assigned_team_id uuid, assignee_user_id uuid, claimed_by_user_id uuid,
  created_by_user_id uuid, created_by_membership_id uuid,
  created_by_service_account_id uuid, detected_at timestamp with time zone,
  received_at timestamp with time zone, acknowledged_at timestamp with time zone,
  closed_at timestamp with time zone, assigned_at timestamp with time zone,
  first_response_at timestamp with time zone, resolved_at timestamp with time zone,
  claimed_at timestamp with time zone, created_at timestamp with time zone,
  updated_at timestamp with time zone, version integer, replayed boolean
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  created record;
BEGIN
  IF NOT app.private_notification_trace_context_is_safe_v1(
    p_traceparent, p_tracestate
  ) THEN
    RAISE EXCEPTION 'Alert trace context is invalid' USING ERRCODE = '22023';
  END IF;
  PERFORM set_config('app.tenant_id', p_tenant_id::text, true);
  PERFORM set_config('app.user_id', '', true);
  PERFORM set_config('app.traceparent', coalesce(p_traceparent, ''), true);
  PERFORM set_config('app.tracestate', coalesce(p_tracestate, ''), true);
  SELECT result.* INTO STRICT created
  FROM app.create_tenant_alert_as_service_account_v2(
    p_tenant_id, p_locator, p_envelope_key_version, p_secret_digest,
    p_client_address, p_title, p_description, p_external_id, p_severity,
    p_source, p_source_type, p_deduplication_key, p_raw_payload,
    p_priority, p_category, p_classification, p_detected_at,
    p_customer_visible, p_tags, p_custom_fields, p_workflow_id,
    p_assigned_team_id, p_assignee_user_id, p_key_digest,
    p_request_digest, p_request_id, p_correlation_id, p_user_agent
  ) AS result;
  IF NOT created.replayed THEN
    PERFORM app.private_append_tenant_notification_event_v3(
      uuidv7(), 'alert.created', 'alert', created.id, created.version,
      created.created_at, 'service_account',
      created.created_by_service_account_id,
      'ticketing', CASE WHEN created.customer_visible
        THEN 'customer'::public.notification_audience
        ELSE 'operator'::public.notification_audience END,
      jsonb_build_object(
        'alert', jsonb_strip_nulls(jsonb_build_object(
          'id', created.id, 'number', created.number,
          'version', created.version, 'title', created.title,
          'status', created.status, 'severity', created.severity,
          'priority', created.priority, 'category', created.category,
          'classification', created.classification,
          'source', created.source, 'sourceType', created.source_type,
          'detectedAt', created.detected_at,
          'receivedAt', created.received_at,
          'customerVisible', created.customer_visible
        )),
        'actor', jsonb_build_object(
          'id', created.created_by_service_account_id
        ),
        'action', 'created',
        'routing', jsonb_strip_nulls(jsonb_build_object(
          'assigneeUserId', created.assignee_user_id,
          'operatorTeamId', created.assigned_team_id
        ))
      ),
      CASE WHEN created.customer_visible THEN jsonb_build_object(
        'alert', jsonb_strip_nulls(jsonb_build_object(
          'id', created.id, 'number', created.number,
          'version', created.version, 'title', created.title,
          'status', created.status, 'severity', created.severity,
          'priority', created.priority, 'category', created.category,
          'detectedAt', created.detected_at,
          'customerVisible', true
        ))
      ) END,
      'notification:v2:alert:' || created.id::text || ':1:alert.created',
      p_correlation_id, p_request_id, p_traceparent, p_tracestate
    );
  END IF;
  RETURN QUERY SELECT
    created.id, created.number, created.workflow_id,
    created.workflow_version, created.state_key, created.customer_visible,
    created.external_id, created.deduplication_key, created.title,
    created.description, created.status, created.severity, created.priority,
    created.category, created.classification, created.source,
    created.source_type, created.tags, created.custom_fields,
    created.customer_custom_fields, created.raw_payload,
    created.assigned_team_id, created.assignee_user_id,
    created.claimed_by_user_id, created.created_by_user_id,
    created.created_by_membership_id,
    created.created_by_service_account_id, created.detected_at,
    created.received_at, created.acknowledged_at, created.closed_at,
    created.assigned_at, created.first_response_at, created.resolved_at,
    created.claimed_at, created.created_at, created.updated_at,
    created.version, created.replayed;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.create_tenant_alert_as_service_account_v3(
  uuid, bytea, integer, bytea, inet, text, text, text,
  public.alert_severity, text, text, text, jsonb, text, text, text,
  timestamp with time zone, boolean, text[], jsonb, uuid, uuid, uuid,
  bytea, bytea, uuid, uuid, text, text, text
) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.create_tenant_alert_as_service_account_v3(
  uuid, bytea, integer, bytea, inet, text, text, text,
  public.alert_severity, text, text, text, jsonb, text, text, text,
  timestamp with time zone, boolean, text[], jsonb, uuid, uuid, uuid,
  bytea, bytea, uuid, uuid, text, text, text
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.create_tenant_alert_as_service_account_v3(
  uuid, bytea, integer, bytea, inet, text, text, text,
  public.alert_severity, text, text, text, jsonb, text, text, text,
  timestamp with time zone, boolean, text[], jsonb, uuid, uuid, uuid,
  bytea, bytea, uuid, uuid, text, text, text
) TO periapsis_api;--> statement-breakpoint

REVOKE EXECUTE ON FUNCTION app.create_tenant_alert_as_human_v2(
  text, text, text, public.alert_severity, text, text, text, jsonb,
  text, text, text, timestamp with time zone, boolean, text[], jsonb,
  uuid, uuid, uuid, bytea, bytea, uuid, uuid, inet, text, text
) FROM periapsis_api;--> statement-breakpoint
REVOKE EXECUTE ON FUNCTION app.create_tenant_alert_as_service_account_v2(
  uuid, bytea, integer, bytea, inet, text, text, text,
  public.alert_severity, text, text, text, jsonb, text, text, text,
  timestamp with time zone, boolean, text[], jsonb, uuid, uuid, uuid,
  bytea, bytea, uuid, uuid, text
) FROM periapsis_api;

-- v16 is the exact 100-migration projection. v15 remains available as the
-- sealed 91-row rolling predecessor for the API and worker binaries released
-- with 0090; v14 is retired.
CREATE FUNCTION app.schema_compatibility_v16()
RETURNS TABLE (
  applied_count bigint,
  latest_created_at bigint,
  latest_hash text,
  migration_fingerprint text
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
  journal_count bigint;
  journal_latest_created_at bigint;
  migration_0099_rows bigint;
BEGIN
  EXECUTE $query$
    SELECT count(*)::bigint, max(migration.created_at)::bigint,
           count(*) FILTER (
             WHERE migration.created_at = 1787682162037
           )::bigint
    FROM drizzle.__drizzle_migrations AS migration
  $query$ INTO journal_count, journal_latest_created_at, migration_0099_rows;
  IF journal_count = 100
     AND journal_latest_created_at = 1787682162037
     AND migration_0099_rows = 1 THEN
    RETURN QUERY EXECUTE $query$
      SELECT count(*)::bigint, max(migration.created_at)::bigint,
             (SELECT lower(latest.hash::text)
              FROM drizzle.__drizzle_migrations AS latest
              ORDER BY latest.created_at DESC, latest.id DESC LIMIT 1),
             string_agg(
               migration.created_at::text || '@' || lower(migration.hash::text),
               ':' ORDER BY migration.created_at, migration.id
             )
      FROM drizzle.__drizzle_migrations AS migration
    $query$;
    RETURN;
  END IF;
  RETURN QUERY SELECT 0::bigint, 0::bigint,
                      'UNSUPPORTED'::text, 'UNSUPPORTED'::text;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.schema_compatibility_v16() OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.schema_compatibility_v16()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v16()
  TO periapsis_api, periapsis_worker;--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.schema_compatibility_v15()
RETURNS TABLE (
  applied_count bigint,
  latest_created_at bigint,
  latest_hash text,
  migration_fingerprint text
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
SET app.schema_compatibility_fingerprint = 'UNSEALED'
AS $function$
DECLARE
  full_count bigint;
  full_latest_created_at bigint;
  full_fingerprint text;
BEGIN
  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.migration_fingerprint
  INTO full_count, full_latest_created_at, full_fingerprint
  FROM app.schema_compatibility_v16() AS compatibility;
  IF full_count = 100
     AND full_latest_created_at = 1787682162037
     AND full_fingerprint = current_setting(
       'app.schema_compatibility_fingerprint', true
     ) THEN
    RETURN QUERY EXECUTE $query$
      WITH ordered_migrations AS (
        SELECT migration.id, migration.created_at,
               lower(migration.hash::text) AS migration_hash,
               row_number() OVER (
                 ORDER BY migration.created_at, migration.id
               ) AS migration_ordinal
        FROM drizzle.__drizzle_migrations AS migration
      )
      SELECT count(*)::bigint, max(migration.created_at)::bigint,
             (SELECT prefix.migration_hash
              FROM ordered_migrations AS prefix
              WHERE prefix.migration_ordinal = 91),
             string_agg(
               migration.created_at::text || '@' || migration.migration_hash,
               ':' ORDER BY migration.created_at, migration.id
             )
      FROM ordered_migrations AS migration
      WHERE migration.migration_ordinal <= 91
    $query$;
    RETURN;
  END IF;
  RETURN QUERY SELECT 0::bigint, 0::bigint,
                      'UNSUPPORTED'::text, 'UNSUPPORTED'::text;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.schema_compatibility_v15() OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.schema_compatibility_v15()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v15()
  TO periapsis_api, periapsis_worker;--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.schema_compatibility_v14()
RETURNS TABLE (
  applied_count bigint,
  latest_created_at bigint,
  latest_hash text,
  migration_fingerprint text
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
  RETURN QUERY SELECT 0::bigint, 0::bigint,
                      'UNSUPPORTED'::text, 'UNSUPPORTED'::text;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.schema_compatibility_v14() OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.schema_compatibility_v14()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v14()
  TO periapsis_api, periapsis_worker;--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.seal_schema_compatibility_manifest(
  p_expected_count bigint,
  p_expected_latest_created_at bigint,
  p_expected_latest_hash text,
  p_expected_migration_fingerprint text
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
  fingerprint_entries text[];
  fingerprint_created_at bigint[];
  actual_count bigint;
  actual_latest_created_at bigint;
  actual_latest_hash text;
  actual_fingerprint text;
  predecessor_count bigint;
  predecessor_latest_created_at bigint;
  predecessor_latest_hash text;
  predecessor_fingerprint text;
  expected_predecessor_hash text;
  expected_predecessor_fingerprint text;
  retired_count bigint;
BEGIN
  fingerprint_entries := string_to_array(
    p_expected_migration_fingerprint, ':'
  );
  IF p_expected_count IS DISTINCT FROM 100
     OR p_expected_latest_created_at IS DISTINCT FROM 1787682162037
     OR p_expected_latest_hash IS NULL
     OR p_expected_latest_hash !~ '^[0-9a-f]{64}$'
     OR p_expected_migration_fingerprint IS NULL
     OR p_expected_migration_fingerprint !~
          '^[1-9][0-9]*@[0-9a-f]{64}(:[1-9][0-9]*@[0-9a-f]{64})*$'
     OR cardinality(fingerprint_entries) IS DISTINCT FROM 100
     OR fingerprint_entries[100] IS DISTINCT FROM (
       p_expected_latest_created_at::text || '@' || p_expected_latest_hash
     ) THEN
    RAISE EXCEPTION 'invalid schema compatibility v16 manifest'
      USING ERRCODE = '22023';
  END IF;

  SELECT array_agg(
    split_part(entry.value, '@', 1)::bigint ORDER BY entry.ordinality
  ) INTO fingerprint_created_at
  FROM unnest(fingerprint_entries) WITH ORDINALITY
       AS entry(value, ordinality);
  IF fingerprint_created_at IS DISTINCT FROM ARRAY[
    1787472409685, 1787472415216, 1787473527702, 1787473536723,
    1787474082034, 1787474089267, 1787475027656, 1787475184077,
    1787488565252, 1787488569966, 1787492910536, 1787493031146,
    1787494284382, 1787495115125, 1787495293635, 1787495819997,
    1787495999394, 1787496124539, 1787496880587, 1787496982733,
    1787496987011, 1787501702276, 1787506296280, 1787507888755,
    1787508523197, 1787516694668, 1787571776845, 1787581350373,
    1787581530382, 1787582150087, 1787591930962, 1787591938733,
    1787592230466, 1787612620574, 1787613580320, 1787613592459,
    1787613744526, 1787613746038, 1787613747552, 1787613749000,
    1787635396524, 1787635417084, 1787635433516, 1787635452090,
    1787635459707, 1787635471570, 1787635525474, 1787635788324,
    1787635828723, 1787637794128, 1787637795761, 1787643146844,
    1787643153628, 1787643609827, 1787648180127, 1787648190820,
    1787648201836, 1787648215689, 1787648225321, 1787649465766,
    1787649478666, 1787649523649, 1787649541586, 1787650610199,
    1787650730983, 1787653130160, 1787653143051, 1787653149806,
    1787653151267, 1787653305313, 1787655186569, 1787655192148,
    1787655197869, 1787655813403, 1787655819028, 1787655824109,
    1787657661213, 1787657666680, 1787658281433, 1787658434202,
    1787659622481, 1787659623982, 1787664581262, 1787664767505,
    1787664955067, 1787665119323, 1787665128173, 1787672101246,
    1787672114811, 1787672134042, 1787673489517, 1787677373554,
    1787677383849, 1787677403239, 1787677416302, 1787677427915,
    1787679172524, 1787680410777, 1787680424626, 1787682162037
  ]::bigint[] THEN
    RAISE EXCEPTION 'invalid schema compatibility v16 timestamp sequence'
      USING ERRCODE = '22023';
  END IF;

  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
  INTO actual_count, actual_latest_created_at, actual_latest_hash,
       actual_fingerprint
  FROM app.schema_compatibility_v16() AS compatibility;
  IF actual_count IS DISTINCT FROM p_expected_count
     OR actual_latest_created_at IS DISTINCT FROM p_expected_latest_created_at
     OR actual_latest_hash IS DISTINCT FROM p_expected_latest_hash
     OR actual_fingerprint IS DISTINCT FROM p_expected_migration_fingerprint THEN
    RAISE EXCEPTION 'schema compatibility v16 manifest does not match the applied journal'
      USING ERRCODE = '55000';
  END IF;

  PERFORM set_config(
    'app.schema_compatibility_fingerprint',
    p_expected_migration_fingerprint, true
  );
  EXECUTE $statement$
    ALTER FUNCTION app.schema_compatibility_v15()
      SET app.schema_compatibility_fingerprint FROM CURRENT
  $statement$;
  expected_predecessor_hash := split_part(fingerprint_entries[91], '@', 2);
  expected_predecessor_fingerprint := array_to_string(
    fingerprint_entries[1:91], ':'
  );
  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
  INTO predecessor_count, predecessor_latest_created_at,
       predecessor_latest_hash, predecessor_fingerprint
  FROM app.schema_compatibility_v15() AS compatibility;
  IF predecessor_count IS DISTINCT FROM 91
     OR predecessor_latest_created_at IS DISTINCT FROM 1787673489517
     OR predecessor_latest_hash IS DISTINCT FROM expected_predecessor_hash
     OR predecessor_fingerprint IS DISTINCT FROM expected_predecessor_fingerprint THEN
    RAISE EXCEPTION 'sealed schema compatibility v15 prefix is not exact'
      USING ERRCODE = '55000';
  END IF;
  SELECT compatibility.applied_count INTO retired_count
  FROM app.schema_compatibility_v14() AS compatibility;
  IF retired_count IS DISTINCT FROM 0 THEN
    RAISE EXCEPTION 'schema compatibility v14 must be retired'
      USING ERRCODE = '55000';
  END IF;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.seal_schema_compatibility_manifest(bigint, bigint, text, text)
  OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.seal_schema_compatibility_manifest(
  bigint, bigint, text, text
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;--> statement-breakpoint

CREATE FUNCTION app.notification_schema_readiness_v1()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  relation_name text;
  relation_owner text;
  relation_rls boolean;
  relation_force_rls boolean;
  expected_function record;
  function_oid regprocedure;
  function_owner text;
  function_security_definer boolean;
  function_configuration text[];
  current_count bigint;
  predecessor_count bigint;
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_roles AS role
    WHERE role.rolname IN (
      'periapsis_notification_admin_owner',
      'periapsis_notification_dispatch_owner',
      'periapsis_notification_readiness_owner'
    ) AND (role.rolcanlogin OR role.rolsuper OR role.rolcreatedb
      OR role.rolcreaterole OR role.rolinherit OR role.rolreplication
      OR role.rolbypassrls)
  ) OR (
    SELECT count(*) FROM pg_roles AS role
    WHERE role.rolname IN (
      'periapsis_notification_admin_owner',
      'periapsis_notification_dispatch_owner',
      'periapsis_notification_readiness_owner'
    )
  ) <> 3 THEN
    RETURN false;
  END IF;

  FOREACH relation_name IN ARRAY ARRAY[
    'tenant_notification_templates',
    'tenant_notification_template_versions',
    'tenant_notification_rules',
    'tenant_notification_rule_versions',
    'tenant_notification_secret_versions',
    'tenant_notification_smtp_configurations',
    'tenant_notification_smtp_configuration_versions',
    'tenant_notification_webhook_configurations',
    'tenant_notification_webhook_configuration_versions',
    'tenant_notification_fanout_snapshots',
    'tenant_notification_deliveries',
    'tenant_notification_delivery_attempts',
    'tenant_notification_commands'
  ] LOOP
    SELECT pg_get_userbyid(class.relowner), class.relrowsecurity,
           class.relforcerowsecurity
    INTO relation_owner, relation_rls, relation_force_rls
    FROM pg_class AS class
    JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
    WHERE namespace.nspname = 'public' AND class.relname = relation_name
      AND class.relkind = 'r';
    IF NOT FOUND OR relation_owner IS DISTINCT FROM 'periapsis_migrator'
       OR relation_rls IS NOT TRUE OR relation_force_rls IS NOT TRUE
       OR NOT EXISTS (
         SELECT 1 FROM pg_attribute AS attribute
         JOIN pg_class AS class ON class.oid = attribute.attrelid
         JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
         WHERE namespace.nspname = 'public' AND class.relname = relation_name
           AND attribute.attname = 'tenant_id' AND attribute.attnotnull
           AND NOT attribute.attisdropped
       )
       OR has_table_privilege(
         'periapsis_api', format('public.%I', relation_name),
         'SELECT,INSERT,UPDATE,DELETE'
       ) OR has_table_privilege(
         'periapsis_notifier', format('public.%I', relation_name),
         'SELECT,INSERT,UPDATE,DELETE'
       ) THEN
      RETURN false;
    END IF;
  END LOOP;

  FOREACH relation_name IN ARRAY ARRAY[
    'platform_notification_secret_versions',
    'platform_notification_smtp_configurations',
    'platform_notification_smtp_configuration_versions',
    'platform_notification_commands'
  ] LOOP
    SELECT pg_get_userbyid(class.relowner), class.relrowsecurity,
           class.relforcerowsecurity
    INTO relation_owner, relation_rls, relation_force_rls
    FROM pg_class AS class
    JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
    WHERE namespace.nspname = 'public' AND class.relname = relation_name
      AND class.relkind = 'r';
    IF NOT FOUND OR relation_owner IS DISTINCT FROM 'periapsis_migrator'
       OR relation_rls IS NOT TRUE OR relation_force_rls IS NOT TRUE
       OR has_table_privilege(
         'periapsis_api', format('public.%I', relation_name),
         'SELECT,INSERT,UPDATE,DELETE'
       ) OR has_table_privilege(
         'periapsis_notifier', format('public.%I', relation_name),
         'SELECT,INSERT,UPDATE,DELETE'
       ) THEN
      RETURN false;
    END IF;
  END LOOP;

  IF (
    SELECT count(*) FROM pg_trigger AS trigger
    WHERE NOT trigger.tgisinternal AND trigger.tgname IN (
      'tenant_notification_deliveries_event_tenant_guard_v1',
      'tenant_notification_fanout_snapshots_event_tenant_guard_v1'
    ) AND trigger.tgenabled = 'O'
  ) <> 2 THEN
    RETURN false;
  END IF;

  FOR expected_function IN
    SELECT * FROM (VALUES
      ('app.claim_notification_fanout_batch_v1(text,integer,integer,timestamp with time zone)', 'periapsis_notification_dispatch_owner', false, true),
      ('app.load_notification_fanout_inputs_v1(uuid,uuid)', 'periapsis_notification_dispatch_owner', false, true),
      ('app.commit_notification_fanout_v1(uuid,uuid,jsonb,timestamp with time zone)', 'periapsis_notification_dispatch_owner', false, true),
      ('app.claim_notification_delivery_batch_v1(text,integer,integer,timestamp with time zone)', 'periapsis_notification_dispatch_owner', false, true),
      ('app.claim_notification_webhook_delivery_batch_v1(text,integer,integer,timestamp with time zone)', 'periapsis_notification_dispatch_owner', false, true),
      ('app.load_pinned_smtp_configuration_v1(uuid,text,uuid,integer)', 'periapsis_notification_dispatch_owner', false, true),
      ('app.private_require_notification_admin_v1()', 'periapsis_notification_admin_owner', false, false),
      ('app.private_notification_service_account_is_active_v1(uuid,uuid)', 'periapsis_migrator', false, false),
      ('app.list_tenant_notification_resources_v1(text,timestamp with time zone,uuid,public.notification_delivery_status[],integer)', 'periapsis_notification_admin_owner', true, false),
      ('app.mutate_tenant_notification_definition_v1(text,uuid,integer,jsonb,bytea,bytea,timestamp with time zone,uuid,uuid,inet,text,text)', 'periapsis_notification_admin_owner', true, false),
      ('app.create_tenant_alert_as_human_v3(text,text,text,public.alert_severity,text,text,text,jsonb,text,text,text,timestamp with time zone,boolean,text[],jsonb,uuid,uuid,uuid,bytea,bytea,uuid,uuid,inet,text,text,text,text)', 'periapsis_migrator', true, false),
      ('app.create_tenant_alert_as_service_account_v3(uuid,bytea,integer,bytea,inet,text,text,text,public.alert_severity,text,text,text,jsonb,text,text,text,timestamp with time zone,boolean,text[],jsonb,uuid,uuid,uuid,bytea,bytea,uuid,uuid,text,text,text)', 'periapsis_migrator', true, false),
      ('app.create_tenant_alert_as_human_v2(text,text,text,public.alert_severity,text,text,text,jsonb,text,text,text,timestamp with time zone,boolean,text[],jsonb,uuid,uuid,uuid,bytea,bytea,uuid,uuid,inet,text,text)', 'periapsis_migrator', false, false),
      ('app.create_tenant_alert_as_service_account_v2(uuid,bytea,integer,bytea,inet,text,text,text,public.alert_severity,text,text,text,jsonb,text,text,text,timestamp with time zone,boolean,text[],jsonb,uuid,uuid,uuid,bytea,bytea,uuid,uuid,text)', 'periapsis_migrator', false, false),
      ('app.verify_notification_keyring_v1(smallint[])', 'periapsis_notification_readiness_owner', true, false),
      ('app.schema_compatibility_v16()', 'periapsis_migrator', true, false),
      ('app.schema_compatibility_v15()', 'periapsis_migrator', true, false)
    ) AS expected(signature, expected_owner, api_execute, notifier_execute)
  LOOP
    function_oid := to_regprocedure(expected_function.signature);
    IF function_oid IS NULL THEN
      RETURN false;
    END IF;
    SELECT pg_get_userbyid(procedure.proowner), procedure.prosecdef,
           procedure.proconfig
    INTO function_owner, function_security_definer, function_configuration
    FROM pg_proc AS procedure WHERE procedure.oid = function_oid;
    IF function_owner IS DISTINCT FROM expected_function.expected_owner
       OR function_security_definer IS NOT TRUE
       OR function_configuration[1] NOT LIKE 'search_path=pg_catalog%'
       OR EXISTS (
         SELECT 1 FROM pg_proc AS procedure
         CROSS JOIN LATERAL aclexplode(
           coalesce(procedure.proacl, acldefault('f', procedure.proowner))
         ) AS privilege
         WHERE procedure.oid = function_oid AND privilege.grantee = 0
           AND privilege.privilege_type = 'EXECUTE'
       ) OR has_function_privilege(
         'periapsis_api', function_oid, 'EXECUTE'
       ) IS DISTINCT FROM expected_function.api_execute
       OR has_function_privilege(
         'periapsis_notifier', function_oid, 'EXECUTE'
       ) IS DISTINCT FROM expected_function.notifier_execute THEN
      RETURN false;
    END IF;
  END LOOP;

  SELECT compatibility.applied_count INTO current_count
  FROM app.schema_compatibility_v16() AS compatibility;
  SELECT compatibility.applied_count INTO predecessor_count
  FROM app.schema_compatibility_v15() AS compatibility;
  RETURN current_count = 100 AND predecessor_count = 91;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.notification_schema_readiness_v1()
  OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.notification_schema_readiness_v1()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.notification_schema_readiness_v1()
  TO periapsis_api, periapsis_worker,
     periapsis_notification_readiness_owner;--> statement-breakpoint

CREATE FUNCTION app.notification_dispatch_readiness_v2()
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
  SELECT readiness.queue_depth, readiness.role_safe
  INTO queue_depth, role_safe
  FROM app.notification_dispatch_readiness_v1() AS readiness;
  schema_safe := app.notification_schema_readiness_v1();
  SELECT coalesce(greatest(
    0,
    floor(extract(epoch FROM transaction_timestamp() - min(event.occurred_at)))
  )::bigint, 0::bigint)
  INTO oldest_pending_seconds
  FROM public.outbox_events AS event
  WHERE event.event_type LIKE 'notification.%'
    AND event.schema_version = 2
    AND event.processed_at IS NULL
    AND event.dead_lettered_at IS NULL
    AND event.available_at <= transaction_timestamp()
    AND event.attempts < event.max_attempts
    AND (event.lease_until IS NULL
      OR event.lease_until <= transaction_timestamp());
  RETURN NEXT;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.notification_dispatch_readiness_v2()
  OWNER TO periapsis_notification_readiness_owner;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.notification_dispatch_readiness_v2()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.notification_dispatch_readiness_v2()
  TO periapsis_notifier;
