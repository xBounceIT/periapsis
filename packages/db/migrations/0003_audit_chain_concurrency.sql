-- Serialize per-tenant audit sequence assignment at the chain head. A global identity can
-- allocate values before the tenant lock is acquired and therefore does not define chain order.
CREATE OR REPLACE FUNCTION "app"."seal_audit_event"()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  prior_hash character(64);
  prior_sequence bigint;
BEGIN
  INSERT INTO public.audit_chain_heads (tenant_id)
  VALUES (NEW.tenant_id)
  ON CONFLICT (tenant_id) DO NOTHING;

  SELECT last_event_hash, last_sequence
    INTO STRICT prior_hash, prior_sequence
    FROM public.audit_chain_heads
    WHERE tenant_id = NEW.tenant_id
    FOR UPDATE;

  NEW.sequence := prior_sequence + 1;
  NEW.previous_hash := prior_hash;
  NEW.event_hash := app.calculate_audit_event_hash(NEW, prior_hash);

  UPDATE public.audit_chain_heads
    SET last_sequence = NEW.sequence,
        last_event_hash = NEW.event_hash,
        updated_at = transaction_timestamp()
    WHERE tenant_id = NEW.tenant_id;

  RETURN NEW;
END;
$function$;--> statement-breakpoint

-- Verification must be able to compare the last stored event with the separately protected
-- chain head, while retaining RLS and active-membership checks under SECURITY INVOKER.
GRANT SELECT ON TABLE "public"."audit_chain_heads" TO "periapsis_api", "periapsis_auditor";--> statement-breakpoint
CREATE POLICY "audit_chain_heads_api_verify" ON "public"."audit_chain_heads"
AS PERMISSIVE FOR SELECT TO "periapsis_api"
USING (
  "audit_chain_heads"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  AND EXISTS (
    SELECT 1
    FROM "public"."tenant_memberships" AS membership
    WHERE membership."tenant_id" = "audit_chain_heads"."tenant_id"
      AND membership."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      AND membership."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "audit_chain_heads_auditor_verify" ON "public"."audit_chain_heads"
AS PERMISSIVE FOR SELECT TO "periapsis_auditor"
USING (
  "audit_chain_heads"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
);--> statement-breakpoint

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
  validation_rows AS (
    SELECT
      ordered.sequence,
      ordered.id AS event_id,
      ordered.expected_previous_hash,
      ordered.previous_hash AS stored_previous_hash,
      ordered.event_hash AS stored_event_hash,
      ordered.previous_hash = ordered.expected_previous_hash
        AND ordered.event_hash = app.calculate_audit_event_hash(
          ordered.event_record,
          ordered.expected_previous_hash
        ) AS valid,
      0 AS row_kind
    FROM ordered

    UNION ALL

    SELECT
      head.last_sequence,
      NULL::uuid AS event_id,
      coalesce(
        latest.event_hash,
        repeat('0', 64)::character(64)
      ) AS expected_previous_hash,
      head.last_event_hash AS stored_previous_hash,
      head.last_event_hash AS stored_event_hash,
      head.last_sequence = coalesce(latest.sequence, 0)
        AND head.last_event_hash = coalesce(
          latest.event_hash,
          repeat('0', 64)::character(64)
        ) AS valid,
      1 AS row_kind
    FROM public.audit_chain_heads AS head
    LEFT JOIN latest_event AS latest ON true
    WHERE head.tenant_id = p_tenant_id
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
