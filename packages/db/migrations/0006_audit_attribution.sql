ALTER TABLE "audit_events" DROP CONSTRAINT "audit_events_actor_consistency_check";--> statement-breakpoint
ALTER TABLE "audit_events" ADD CONSTRAINT "audit_events_actor_consistency_check" CHECK (("audit_events"."actor_type" = 'user' and "audit_events"."actor_user_id" is not null)
        or ("audit_events"."actor_type" <> 'user'
          and "audit_events"."actor_user_id" is null
          and "audit_events"."impersonated_by_user_id" is null));--> statement-breakpoint

-- The SECURITY DEFINER switch changes current_user, so attribution resolves the caller from
-- PostgreSQL's permission-checked role setting and falls back to the fixed session login when
-- no SET ROLE is active. Only an explicit SET ROLE periapsis_migrator bypasses user context.
CREATE OR REPLACE FUNCTION "app"."seal_audit_event"()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  prior_hash character(64);
  prior_sequence bigint;
  invoker_role text;
  context_user uuid;
BEGIN
  invoker_role := nullif(current_setting('role', true), '');
  IF invoker_role IS NULL OR invoker_role = 'none' THEN
    invoker_role := session_user::text;
  END IF;

  IF NEW.actor_type = 'user' THEN
    IF NEW.actor_user_id IS NULL THEN
      RAISE EXCEPTION 'user audit events require an actor user'
        USING ERRCODE = '23514';
    END IF;

    IF invoker_role <> 'periapsis_migrator' THEN
      IF invoker_role NOT IN ('periapsis_api', 'periapsis_api_login') THEN
        RAISE EXCEPTION 'this database role cannot emit user-attributed audit events'
          USING ERRCODE = '42501';
      END IF;

      context_user := nullif(current_setting('app.user_id', true), '')::uuid;
      IF context_user IS NULL THEN
        RAISE EXCEPTION 'user audit events require app.user_id context'
          USING ERRCODE = '23514';
      END IF;

      IF NEW.impersonated_by_user_id IS NULL THEN
        IF NEW.actor_user_id IS DISTINCT FROM context_user THEN
          RAISE EXCEPTION 'audit actor does not match app.user_id context'
            USING ERRCODE = '23514';
        END IF;
      ELSIF NEW.impersonated_by_user_id IS DISTINCT FROM context_user THEN
        RAISE EXCEPTION 'audit impersonator does not match app.user_id context'
          USING ERRCODE = '23514';
      END IF;
    END IF;
  ELSIF NEW.actor_user_id IS NOT NULL OR NEW.impersonated_by_user_id IS NOT NULL THEN
    RAISE EXCEPTION 'non-user audit events cannot carry user attribution'
      USING ERRCODE = '23514';
  END IF;

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
$function$;
