-- Controls not represented by the Drizzle schema DSL. The preceding generated migration
-- remains the canonical table/policy snapshot; this migration only hardens ownership,
-- privileges, forced RLS, and the tamper-evident audit boundary.

-- The one-shot migration/seed role owns schema objects and may bypass RLS. It is NOLOGIN
-- and is never granted to a runtime service connection.
ALTER ROLE "periapsis_migrator" WITH NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION BYPASSRLS;--> statement-breakpoint
ALTER ROLE "periapsis_api" WITH NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;--> statement-breakpoint
ALTER ROLE "periapsis_worker" WITH NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;--> statement-breakpoint
ALTER ROLE "periapsis_notifier" WITH NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;--> statement-breakpoint
ALTER ROLE "periapsis_auditor" WITH NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;--> statement-breakpoint

ALTER TYPE "public"."alert_severity" OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER TYPE "public"."alert_status" OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER TYPE "public"."audit_actor_type" OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER TYPE "public"."audit_outcome" OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER TYPE "public"."membership_role" OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER TYPE "public"."membership_status" OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER TYPE "public"."tenant_status" OWNER TO "periapsis_migrator";--> statement-breakpoint

ALTER TABLE "public"."tenants" OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER TABLE "public"."users" OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER TABLE "public"."tenant_memberships" OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER TABLE "public"."alerts" OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER TABLE "public"."audit_events" OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER TABLE "public"."audit_chain_heads" OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER TABLE "public"."outbox_events" OWNER TO "periapsis_migrator";--> statement-breakpoint

ALTER TABLE "public"."tenants" FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "public"."users" FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "public"."tenant_memberships" FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "public"."alerts" FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "public"."audit_events" FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "public"."audit_chain_heads" FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "public"."outbox_events" FORCE ROW LEVEL SECURITY;--> statement-breakpoint

REVOKE CREATE ON SCHEMA "public" FROM PUBLIC;--> statement-breakpoint
CREATE SCHEMA IF NOT EXISTS "app" AUTHORIZATION "periapsis_migrator";--> statement-breakpoint
REVOKE ALL ON SCHEMA "app" FROM PUBLIC;--> statement-breakpoint

REVOKE ALL ON TABLE "public"."tenants" FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON TABLE "public"."users" FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON TABLE "public"."tenant_memberships" FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON TABLE "public"."alerts" FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON TABLE "public"."audit_events" FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON TABLE "public"."audit_chain_heads" FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON TABLE "public"."outbox_events" FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON SEQUENCE "public"."audit_events_sequence_seq" FROM PUBLIC;--> statement-breakpoint

GRANT USAGE ON SCHEMA "public" TO "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
GRANT USAGE ON SCHEMA "app" TO "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint

GRANT SELECT ON TABLE "public"."tenants", "public"."users", "public"."tenant_memberships" TO "periapsis_api";--> statement-breakpoint
GRANT SELECT, DELETE ON TABLE "public"."alerts" TO "periapsis_api";--> statement-breakpoint
GRANT INSERT ("id", "tenant_id", "external_id", "title", "description", "status", "severity", "created_by", "created_at", "updated_at", "version") ON TABLE "public"."alerts" TO "periapsis_api";--> statement-breakpoint
GRANT UPDATE ("title", "description", "status", "severity", "updated_at", "version") ON TABLE "public"."alerts" TO "periapsis_api";--> statement-breakpoint

GRANT SELECT ON TABLE "public"."outbox_events" TO "periapsis_api", "periapsis_worker", "periapsis_notifier";--> statement-breakpoint
GRANT INSERT ("id", "tenant_id", "aggregate_type", "aggregate_id", "event_type", "schema_version", "payload", "deduplication_key", "correlation_id", "causation_id", "occurred_at", "available_at", "max_attempts", "created_at") ON TABLE "public"."outbox_events" TO "periapsis_api";--> statement-breakpoint
GRANT UPDATE ("available_at", "attempts", "locked_at", "locked_by", "processed_at", "last_error") ON TABLE "public"."outbox_events" TO "periapsis_worker", "periapsis_notifier";--> statement-breakpoint

GRANT SELECT ON TABLE "public"."audit_events" TO "periapsis_api", "periapsis_auditor";--> statement-breakpoint
GRANT INSERT ("id", "tenant_id", "occurred_at", "actor_type", "actor_user_id", "impersonated_by_user_id", "action", "resource_type", "resource_id", "request_id", "correlation_id", "ip_address", "user_agent", "authentication_method", "outcome", "reason", "before", "after", "metadata") ON TABLE "public"."audit_events" TO "periapsis_api", "periapsis_worker", "periapsis_notifier";--> statement-breakpoint
GRANT USAGE, SELECT ON SEQUENCE "public"."audit_events_sequence_seq" TO "periapsis_api", "periapsis_worker", "periapsis_notifier";--> statement-breakpoint

CREATE FUNCTION "app"."audit_event_payload"(p_event "public"."audit_events")
RETURNS jsonb
LANGUAGE sql
STABLE
STRICT
PARALLEL SAFE
SET search_path = pg_catalog, public, app
AS $function$
  SELECT
    (to_jsonb(p_event) - 'previous_hash' - 'event_hash' - 'occurred_at')
    || jsonb_build_object(
      'occurred_at',
      to_char(
        p_event.occurred_at AT TIME ZONE 'UTC',
        'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
      )
    );
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."calculate_audit_event_hash"(
  p_event "public"."audit_events",
  p_previous_hash character(64)
)
RETURNS character(64)
LANGUAGE sql
STABLE
STRICT
PARALLEL SAFE
SET search_path = pg_catalog, public, app
AS $function$
  SELECT encode(
    sha256(
      convert_to(
        p_previous_hash::text || app.audit_event_payload(p_event)::text,
        'UTF8'
      )
    ),
    'hex'
  )::character(64);
$function$;--> statement-breakpoint

CREATE FUNCTION "app"."seal_audit_event"()
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

  IF NEW.sequence <= prior_sequence THEN
    RAISE EXCEPTION 'audit sequence must increase within a tenant'
      USING ERRCODE = '23514';
  END IF;

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

CREATE FUNCTION "app"."reject_audit_event_mutation"()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  RAISE EXCEPTION 'audit events are append-only'
    USING ERRCODE = '55000';
END;
$function$;--> statement-breakpoint

ALTER FUNCTION "app"."audit_event_payload"("public"."audit_events") OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."calculate_audit_event_hash"("public"."audit_events", character) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."seal_audit_event"() OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."reject_audit_event_mutation"() OWNER TO "periapsis_migrator";--> statement-breakpoint

REVOKE ALL ON FUNCTION "app"."audit_event_payload"("public"."audit_events") FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."calculate_audit_event_hash"("public"."audit_events", character) FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."seal_audit_event"() FROM PUBLIC;--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."reject_audit_event_mutation"() FROM PUBLIC;--> statement-breakpoint

CREATE TRIGGER "audit_events_seal_before_insert"
BEFORE INSERT ON "public"."audit_events"
FOR EACH ROW
EXECUTE FUNCTION "app"."seal_audit_event"();--> statement-breakpoint

CREATE TRIGGER "audit_events_reject_update_delete"
BEFORE UPDATE OR DELETE ON "public"."audit_events"
FOR EACH ROW
EXECUTE FUNCTION "app"."reject_audit_event_mutation"();--> statement-breakpoint

CREATE FUNCTION "app"."verify_audit_chain"(p_tenant_id uuid)
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
  )
  SELECT
    ordered.sequence,
    ordered.id,
    ordered.expected_previous_hash,
    ordered.previous_hash,
    ordered.event_hash,
    ordered.previous_hash = ordered.expected_previous_hash
      AND ordered.event_hash = app.calculate_audit_event_hash(
        ordered.event_record,
        ordered.expected_previous_hash
      )
  FROM ordered
  ORDER BY ordered.sequence;
$function$;--> statement-breakpoint

ALTER FUNCTION "app"."verify_audit_chain"(uuid) OWNER TO "periapsis_migrator";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."verify_audit_chain"(uuid) FROM PUBLIC;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."verify_audit_chain"(uuid) TO "periapsis_api", "periapsis_auditor";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."calculate_audit_event_hash"("public"."audit_events", character) TO "periapsis_api", "periapsis_auditor";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."audit_event_payload"("public"."audit_events") TO "periapsis_api", "periapsis_auditor";--> statement-breakpoint

ALTER DEFAULT PRIVILEGES FOR ROLE "periapsis_migrator" IN SCHEMA "public" REVOKE ALL ON TABLES FROM PUBLIC;--> statement-breakpoint
ALTER DEFAULT PRIVILEGES FOR ROLE "periapsis_migrator" IN SCHEMA "public" REVOKE ALL ON SEQUENCES FROM PUBLIC;--> statement-breakpoint
ALTER DEFAULT PRIVILEGES FOR ROLE "periapsis_migrator" IN SCHEMA "public" REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;--> statement-breakpoint
ALTER DEFAULT PRIVILEGES FOR ROLE "periapsis_migrator" IN SCHEMA "app" REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
