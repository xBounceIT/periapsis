ALTER TYPE "public"."auth_rate_limit_scope" ADD VALUE 'api_network' BEFORE 'bootstrap_totp';--> statement-breakpoint
ALTER TYPE "public"."auth_rate_limit_scope" ADD VALUE 'api_credential' BEFORE 'bootstrap_totp';--> statement-breakpoint
ALTER TYPE "public"."auth_rate_limit_scope" ADD VALUE 'api_tenant_subject' BEFORE 'bootstrap_totp';--> statement-breakpoint

-- API traffic has much higher identity churn than authentication attempts.
-- Keep the existing lock-ordered, aggregate admission semantics, but retire up
-- to one stale API meter per supplied rule on every call so rotating opaque
-- credentials cannot outgrow the worker's bounded fallback cleanup.
CREATE FUNCTION app.admit_api_request_v1(
  p_scopes public.auth_rate_limit_scope[],
  p_key_digests bytea[],
  p_max_requests integer[]
)
RETURNS TABLE (
  admitted boolean,
  retry_after_seconds integer
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  decision record;
  rule_count integer := coalesce(cardinality(p_scopes), 0);
BEGIN
  IF rule_count NOT BETWEEN 1 AND 3
     OR array_ndims(p_scopes) <> 1
     OR array_ndims(p_key_digests) <> 1
     OR array_ndims(p_max_requests) <> 1
     OR cardinality(p_key_digests) IS DISTINCT FROM rule_count
     OR cardinality(p_max_requests) IS DISTINCT FROM rule_count
     OR (
       SELECT count(*)
       FROM unnest(p_scopes) AS supplied(scope)
       WHERE supplied.scope = 'api_network'::public.auth_rate_limit_scope
     ) <> 1
     OR EXISTS (
       SELECT 1
       FROM unnest(p_scopes) AS supplied(scope)
       WHERE supplied.scope IS NULL
          OR supplied.scope NOT IN (
            'api_network'::public.auth_rate_limit_scope,
            'api_credential'::public.auth_rate_limit_scope,
            'api_tenant_subject'::public.auth_rate_limit_scope
          )
     )
     OR EXISTS (
       SELECT 1
       FROM unnest(p_scopes) AS supplied(scope)
       GROUP BY supplied.scope
       HAVING count(*) > 1
     ) THEN
    RAISE EXCEPTION 'invalid API request admission parameters'
      USING ERRCODE = '22023';
  END IF;

  SELECT attempt.admitted, attempt.blocked_until
  INTO STRICT decision
  FROM app.admit_auth_attempts(
    p_scopes,
    p_key_digests,
    array_fill(1, ARRAY[rule_count]),
    p_max_requests,
    array_fill(1, ARRAY[rule_count])
  ) AS attempt;

  WITH stale AS (
    SELECT meter.id
    FROM public.auth_rate_limits AS meter
    WHERE meter.scope IN (
        'api_network'::public.auth_rate_limit_scope,
        'api_credential'::public.auth_rate_limit_scope,
        'api_tenant_subject'::public.auth_rate_limit_scope
      )
      AND meter.window_expires_at <= transaction_timestamp()
      AND (
        meter.blocked_until IS NULL
        OR meter.blocked_until <= transaction_timestamp()
      )
    ORDER BY greatest(
      meter.window_expires_at,
      coalesce(meter.blocked_until, meter.window_expires_at)
    ), meter.id
    LIMIT rule_count
    FOR UPDATE SKIP LOCKED
  )
  DELETE FROM public.auth_rate_limits AS meter
  USING stale
  WHERE meter.id = stale.id;

  RETURN QUERY
  SELECT decision.admitted::boolean,
    CASE
      WHEN decision.admitted THEN 0
      ELSE greatest(
        1,
        ceil(
          extract(epoch FROM decision.blocked_until - transaction_timestamp())
        )::integer
      )
    END::integer;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.admit_api_request_v1(
  public.auth_rate_limit_scope[], bytea[], integer[]
) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.admit_api_request_v1(
  public.auth_rate_limit_scope[], bytea[], integer[]
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.admit_api_request_v1(
  public.auth_rate_limit_scope[], bytea[], integer[]
) TO periapsis_api;
