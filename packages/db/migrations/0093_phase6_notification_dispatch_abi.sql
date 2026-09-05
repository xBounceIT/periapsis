-- Cross-tenant dequeue is available only through bounded, fenced SECURITY
-- DEFINER functions. The dispatch owner is NOLOGIN/NOBYPASSRLS and its global
-- outbox policy admits only notification.* rows.

CREATE FUNCTION app.claim_notification_fanout_batch_v1(
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
  SET attempts = max_attempts,
      processed_at = p_now,
      dead_lettered_at = p_now,
      failure_category = 'ambiguous_schema_v1',
      last_error = 'legacy notification event quarantined',
      locked_at = NULL,
      locked_by = NULL,
      lease_token = NULL,
      lease_until = NULL
  WHERE legacy.event_type LIKE 'notification.%'
    AND legacy.schema_version <> 2
    AND legacy.processed_at IS NULL
    AND legacy.available_at <= p_now;

  RETURN QUERY
  WITH candidate AS (
    SELECT event.id
    FROM public.outbox_events AS event
    WHERE event.event_type LIKE 'notification.%'
      AND event.schema_version = 2
      AND event.processed_at IS NULL
      AND event.dead_lettered_at IS NULL
      AND event.available_at <= p_now
      AND event.attempts < event.max_attempts
      AND (event.lease_until IS NULL OR event.lease_until <= p_now)
    ORDER BY event.available_at, event.occurred_at, event.id
    LIMIT p_limit
    FOR UPDATE SKIP LOCKED
  ), claimed AS (
    UPDATE public.outbox_events AS event
    SET attempts = event.attempts + 1,
        locked_at = p_now,
        locked_by = p_worker_id,
        lease_token = uuidv7(),
        lease_until = p_now + make_interval(secs => p_lease_duration_ms::double precision / 1000.0),
        failure_category = NULL,
        last_error = NULL
    FROM candidate
    WHERE event.id = candidate.id
    RETURNING event.*
  )
  SELECT jsonb_build_object(
    'id', claimed.id,
    'tenantId', claimed.tenant_id,
    'event', jsonb_strip_nulls(jsonb_build_object(
      'id', claimed.id,
      'tenantId', claimed.tenant_id,
      'type', substring(claimed.event_type from 14),
      'objectType', claimed.aggregate_type,
      'objectId', claimed.aggregate_id,
      'objectVersion', claimed.aggregate_version,
      'occurredAt', claimed.occurred_at,
      'actorKind', claimed.actor_kind,
      'actorId', claimed.actor_id,
      'source', claimed.producer,
      'context', (claimed.payload -> 'operatorContext')
        || CASE WHEN claimed.payload ? 'customerContext'
                THEN jsonb_build_object('customer', claimed.payload -> 'customerContext')
                ELSE '{}'::jsonb END,
      'maximumAudience', claimed.maximum_audience
    )),
    'attempt', claimed.attempts,
    'maximumAttempts', claimed.max_attempts,
    'fenceToken', claimed.lease_token,
    'leaseUntil', claimed.lease_until
  )
  FROM claimed
  ORDER BY claimed.available_at, claimed.occurred_at, claimed.id;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.claim_notification_fanout_batch_v1(text, integer, integer, timestamp with time zone) OWNER TO periapsis_notification_dispatch_owner;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.claim_notification_fanout_batch_v1(text, integer, integer, timestamp with time zone) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.claim_notification_fanout_batch_v1(text, integer, integer, timestamp with time zone) TO periapsis_notifier;--> statement-breakpoint

CREATE FUNCTION app.heartbeat_notification_fanout_v1(
  p_event_id uuid,
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
  IF p_event_id IS NULL OR p_fence_token IS NULL
     OR p_lease_until IS NULL
     OR p_lease_until < transaction_timestamp() + interval '5 seconds'
     OR p_lease_until > transaction_timestamp() + interval '5 minutes' THEN
    RAISE EXCEPTION 'notification fanout heartbeat input is invalid' USING ERRCODE = '22023';
  END IF;
  UPDATE public.outbox_events AS event
  SET lease_until = p_lease_until
  WHERE event.id = p_event_id
    AND event.event_type LIKE 'notification.%'
    AND event.schema_version = 2
    AND event.processed_at IS NULL
    AND event.lease_token = p_fence_token
    AND event.lease_until > transaction_timestamp();
  RETURN FOUND;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.heartbeat_notification_fanout_v1(uuid, uuid, timestamp with time zone) OWNER TO periapsis_notification_dispatch_owner;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.heartbeat_notification_fanout_v1(uuid, uuid, timestamp with time zone) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.heartbeat_notification_fanout_v1(uuid, uuid, timestamp with time zone) TO periapsis_notifier;--> statement-breakpoint

CREATE FUNCTION app.private_lock_notification_fanout_claim_v1(
  p_event_id uuid,
  p_fence_token uuid
)
RETURNS uuid
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE selected_tenant uuid;
BEGIN
  SELECT event.tenant_id INTO selected_tenant
  FROM public.outbox_events AS event
  WHERE event.id = p_event_id
    AND event.event_type LIKE 'notification.%'
    AND event.schema_version = 2
    AND event.processed_at IS NULL
    AND event.lease_token = p_fence_token
    AND event.lease_until > transaction_timestamp()
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'notification fanout claim is stale' USING ERRCODE = '40001';
  END IF;
  PERFORM set_config('app.tenant_id', selected_tenant::text, true);
  RETURN selected_tenant;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.private_lock_notification_fanout_claim_v1(uuid, uuid) OWNER TO periapsis_notification_dispatch_owner;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_lock_notification_fanout_claim_v1(uuid, uuid) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.private_lock_notification_fanout_claim_v1(uuid, uuid) TO periapsis_notification_dispatch_owner;--> statement-breakpoint

CREATE FUNCTION app.retry_notification_fanout_v1(
  p_event_id uuid,
  p_fence_token uuid,
  p_next_attempt_at timestamp with time zone,
  p_failed_at timestamp with time zone
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_failed_at IS NULL OR p_next_attempt_at IS NULL
     OR p_failed_at < transaction_timestamp() - interval '5 minutes'
     OR p_failed_at > transaction_timestamp() + interval '1 minute'
     OR p_next_attempt_at < p_failed_at + interval '1 second'
     OR p_next_attempt_at > p_failed_at + interval '7 days' THEN
    RAISE EXCEPTION 'notification fanout retry input is invalid' USING ERRCODE = '22023';
  END IF;
  UPDATE public.outbox_events AS event
  SET available_at = p_next_attempt_at,
      locked_at = NULL,
      locked_by = NULL,
      lease_token = NULL,
      lease_until = NULL,
      failure_category = 'retry_scheduled',
      last_error = 'notification fanout retry scheduled'
  WHERE event.id = p_event_id
    AND event.event_type LIKE 'notification.%'
    AND event.schema_version = 2
    AND event.processed_at IS NULL
    AND event.lease_token = p_fence_token
    AND event.lease_until > transaction_timestamp();
  IF NOT FOUND THEN
    RAISE EXCEPTION 'notification fanout retry was fenced' USING ERRCODE = '40001';
  END IF;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.retry_notification_fanout_v1(uuid, uuid, timestamp with time zone, timestamp with time zone) OWNER TO periapsis_notification_dispatch_owner;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.retry_notification_fanout_v1(uuid, uuid, timestamp with time zone, timestamp with time zone) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.retry_notification_fanout_v1(uuid, uuid, timestamp with time zone, timestamp with time zone) TO periapsis_notifier;--> statement-breakpoint

CREATE FUNCTION app.dead_letter_notification_fanout_v1(
  p_event_id uuid,
  p_fence_token uuid,
  p_reason text,
  p_failed_at timestamp with time zone
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_reason NOT IN ('configuration', 'security', 'validation', 'attempts_exhausted')
     OR p_failed_at IS NULL
     OR p_failed_at < transaction_timestamp() - interval '5 minutes'
     OR p_failed_at > transaction_timestamp() + interval '1 minute' THEN
    RAISE EXCEPTION 'notification fanout dead-letter input is invalid' USING ERRCODE = '22023';
  END IF;
  UPDATE public.outbox_events AS event
  SET attempts = max_attempts,
      processed_at = p_failed_at,
      dead_lettered_at = p_failed_at,
      locked_at = NULL,
      locked_by = NULL,
      lease_token = NULL,
      lease_until = NULL,
      failure_category = p_reason,
      last_error = 'notification fanout moved to dead letter'
  WHERE event.id = p_event_id
    AND event.event_type LIKE 'notification.%'
    AND event.schema_version = 2
    AND event.processed_at IS NULL
    AND event.lease_token = p_fence_token
    AND event.lease_until > transaction_timestamp();
  IF NOT FOUND THEN
    RAISE EXCEPTION 'notification fanout dead letter was fenced' USING ERRCODE = '40001';
  END IF;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.dead_letter_notification_fanout_v1(uuid, uuid, text, timestamp with time zone) OWNER TO periapsis_notification_dispatch_owner;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.dead_letter_notification_fanout_v1(uuid, uuid, text, timestamp with time zone) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.dead_letter_notification_fanout_v1(uuid, uuid, text, timestamp with time zone) TO periapsis_notifier;--> statement-breakpoint
