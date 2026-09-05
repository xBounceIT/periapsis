-- Keep verification fail-closed if either side of the independently protected tail is
-- missing. SECURITY INVOKER deliberately preserves the caller's tenant RLS boundary.
CREATE OR REPLACE FUNCTION "app"."verify_audit_chain"(p_tenant_id uuid)
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
SECURITY INVOKER
SET search_path = pg_catalog, public, app
AS $function$
  WITH ordered AS (
    SELECT
      event AS event_record,
      event.sequence,
      event.id,
      event.previous_hash,
      event.event_hash,
      lag(
        event.event_hash,
        1,
        repeat('0', 64)::character(64)
      ) OVER (ORDER BY event.sequence) AS expected_previous_hash
    FROM public.audit_events AS event
    WHERE event.tenant_id = p_tenant_id
  ),
  latest_event AS (
    SELECT ordered.sequence, ordered.event_hash
    FROM ordered
    ORDER BY ordered.sequence DESC
    LIMIT 1
  ),
  visible_tenant AS (
    SELECT tenant.id
    FROM public.tenants AS tenant
    WHERE tenant.id = p_tenant_id
  ),
  visible_head AS (
    SELECT head.tenant_id, head.last_sequence, head.last_event_hash
    FROM public.audit_chain_heads AS head
    WHERE head.tenant_id = p_tenant_id
  ),
  validation_rows AS (
    SELECT
      ordered.sequence,
      ordered.id AS event_id,
      ordered.expected_previous_hash,
      ordered.previous_hash AS stored_previous_hash,
      ordered.event_hash AS stored_event_hash,
      (
        ordered.previous_hash = ordered.expected_previous_hash
        AND ordered.event_hash = app.calculate_audit_event_hash(
          ordered.event_record,
          ordered.expected_previous_hash
        )
      ) IS TRUE AS valid,
      0 AS row_kind
    FROM ordered

    UNION ALL

    SELECT
      coalesce(head.last_sequence, latest.sequence, 0),
      NULL::uuid AS event_id,
      latest.event_hash AS expected_previous_hash,
      head.last_event_hash AS stored_previous_hash,
      latest.event_hash AS stored_event_hash,
      (
        head.tenant_id IS NOT NULL
        AND (
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
      ) IS TRUE AS valid,
      1 AS row_kind
    FROM visible_head AS head
    LEFT JOIN latest_event AS latest ON true

    UNION ALL

    SELECT
      latest.sequence,
      NULL::uuid AS event_id,
      latest.event_hash AS expected_previous_hash,
      NULL::character(64) AS stored_previous_hash,
      latest.event_hash AS stored_event_hash,
      false AS valid,
      1 AS row_kind
    FROM latest_event AS latest
    WHERE NOT EXISTS (SELECT 1 FROM visible_head)

    UNION ALL

    -- Every provisioned tenant owns an independently protected zero-or-later
    -- chain head. Seeing the tenant while both the head and event tail are
    -- absent is privileged tampering, not an empty pristine chain.
    SELECT
      0::bigint AS sequence,
      NULL::uuid AS event_id,
      repeat('0', 64)::character(64) AS expected_previous_hash,
      NULL::character(64) AS stored_previous_hash,
      NULL::character(64) AS stored_event_hash,
      false AS valid,
      1 AS row_kind
    FROM visible_tenant
    WHERE NOT EXISTS (SELECT 1 FROM visible_head)
      AND NOT EXISTS (SELECT 1 FROM latest_event)
  )
  SELECT
    validation_rows.sequence,
    validation_rows.event_id,
    validation_rows.expected_previous_hash,
    validation_rows.stored_previous_hash,
    validation_rows.stored_event_hash,
    validation_rows.valid
  FROM validation_rows
  ORDER BY validation_rows.sequence, validation_rows.row_kind;
$function$;
