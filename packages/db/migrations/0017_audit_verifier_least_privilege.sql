-- The tenant audit verifier needs the independently protected tenant/head rows, but
-- granting the auditor either table would expose customer metadata or chain state
-- outside the deliberately narrow verification projection. Run the projection as the
-- migrator while explicitly reproducing the caller boundary before reading any row.
CREATE OR REPLACE FUNCTION "app"."verify_audit_chain"(p_tenant_id uuid)
RETURNS TABLE (
  sequence bigint,
  event_id uuid,
  expected_previous_hash character(64),
  stored_previous_hash character(64),
  stored_event_hash character(64),
  valid boolean
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid;
  context_user uuid;
  invoker_role text;
BEGIN
  context_tenant := nullif(current_setting('app.tenant_id', true), '')::uuid;
  IF context_tenant IS NULL OR p_tenant_id IS DISTINCT FROM context_tenant THEN
    RAISE EXCEPTION 'audit verification requires matching tenant context'
      USING ERRCODE = '42501';
  END IF;

  -- SECURITY DEFINER changes current_user. Resolve the permission-checked active
  -- role, falling back to the immutable session login when SET ROLE is not active.
  invoker_role := nullif(current_setting('role', true), '');
  IF invoker_role IS NULL OR invoker_role = 'none' THEN
    invoker_role := session_user::text;
  END IF;

  IF pg_catalog.pg_has_role(invoker_role, 'periapsis_auditor', 'USAGE') THEN
    NULL;
  ELSIF pg_catalog.pg_has_role(invoker_role, 'periapsis_api', 'USAGE') THEN
    context_user := nullif(current_setting('app.user_id', true), '')::uuid;
    IF context_user IS NULL OR NOT EXISTS (
      SELECT 1
      FROM public.tenant_memberships AS membership
      WHERE membership.tenant_id = context_tenant
        AND membership.user_id = context_user
        AND membership.status = 'active'
    ) THEN
      RAISE EXCEPTION 'audit verification requires active tenant membership'
        USING ERRCODE = '42501';
    END IF;
  ELSE
    RAISE EXCEPTION 'database role cannot verify tenant audit chains'
      USING ERRCODE = '42501';
  END IF;

  RETURN QUERY
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
    WHERE event.tenant_id = context_tenant
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
    WHERE tenant.id = context_tenant
  ),
  visible_head AS (
    SELECT head.tenant_id, head.last_sequence, head.last_event_hash
    FROM public.audit_chain_heads AS head
    WHERE head.tenant_id = context_tenant
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
END;
$function$;--> statement-breakpoint

ALTER FUNCTION "app"."verify_audit_chain"(uuid) OWNER TO "periapsis_migrator";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."verify_audit_chain"(uuid) FROM PUBLIC;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."verify_audit_chain"(uuid) TO "periapsis_api", "periapsis_auditor";--> statement-breakpoint

-- These are intentionally redundant with the original least-privilege grants: they
-- make the repair fail closed even if an environment drifted before applying it.
REVOKE ALL ON TABLE "public"."tenants", "public"."audit_chain_heads" FROM "periapsis_auditor";
