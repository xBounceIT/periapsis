-- A fresh meter has NULL blocked_until. SQL three-valued logic must not turn
-- the aggregate admission result into NULL and break the typed Go scanner.
CREATE OR REPLACE FUNCTION "app"."admit_auth_attempts"(
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
      AND (
        rate_record.blocked_until IS NULL
        OR rate_record.blocked_until <= transaction_timestamp()
      );
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
$function$;
