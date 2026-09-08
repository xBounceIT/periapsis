-- Disambiguate the frozen customer activity contact without changing its live link checks.
-- Definitions are based on the installed V61 catalog.
CREATE OR REPLACE FUNCTION app.capture_ticket_activity_author_snapshot_v1()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'app'
AS $function$
DECLARE
  actor_contact_id uuid;
  audience_value text := 'operator';
BEGIN
  IF NEW.actor_principal_kind='human' AND NOT EXISTS (
    SELECT 1
    FROM public.tenant_memberships AS membership
    JOIN public.users AS identity ON identity.id=membership.user_id
    WHERE membership.tenant_id=NEW.tenant_id
      AND membership.id=NEW.actor_membership_id
      AND membership.user_id=NEW.actor_user_id
      AND membership.status='active' AND identity.active
  ) THEN
    RAISE EXCEPTION 'activity author is not a live tenant identity'
      USING ERRCODE='42501';
  END IF;
  IF NEW.origin='customer_portal' THEN
    IF NEW.actor_principal_kind<>'human' THEN
      RAISE EXCEPTION 'customer activity must have a human actor'
        USING ERRCODE='42501';
    END IF;
    actor_contact_id := nullif(
      current_setting('app.ticket_comment_author_contact_id',true),''
    )::uuid;
    IF actor_contact_id IS NULL OR NOT EXISTS (
      SELECT 1
      FROM public.customer_contacts AS contact
      JOIN public.ticket_customer_contacts AS link
        ON link.tenant_id=contact.tenant_id
       AND link.contact_id=contact.id AND link.archived_at IS NULL
       AND (link.alert_id=NEW.alert_id OR link.case_id=NEW.case_id)
      WHERE contact.tenant_id=NEW.tenant_id AND contact.id=actor_contact_id
        AND contact.linked_membership_id=NEW.actor_membership_id
        AND contact.linked_user_id=NEW.actor_user_id
        AND contact.active AND contact.archived_at IS NULL
    ) THEN
      RAISE EXCEPTION 'customer activity lacks its exact active contact link'
        USING ERRCODE='42501';
    END IF;
    audience_value := 'customer';
  ELSIF NEW.origin NOT IN ('api','system','escalation_copy') THEN
    RAISE EXCEPTION 'ticket activity origin is invalid'
      USING ERRCODE='22023';
  END IF;
  INSERT INTO public.ticket_activity_author_snapshots(
    tenant_id,activity_id,audience,author_contact_id,created_at
  ) VALUES (
    NEW.tenant_id,NEW.id,audience_value,actor_contact_id,NEW.occurred_at
  );
  RETURN NEW;
END;
$function$
;
--> statement-breakpoint

-- Service-specific projections perform the full release attestation once per
-- invocation. These functions are themselves included in the V62 catalog hash.
-- V62 does not exist until the next migration: this interval fails closed.
CREATE FUNCTION app.api_runtime_schema_readiness_v62()
RETURNS boolean[]
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
DECLARE
  release_ready boolean;
BEGIN
  release_ready := app.release_runtime_schema_readiness_v62();
  IF release_ready IS DISTINCT FROM true THEN
    RETURN ARRAY[false,false,false,false,false,false,false,false]::boolean[];
  END IF;
  RETURN ARRAY[
    true,
    true,
    true,
    true,
    coalesce(app.platform_local_account_runtime_schema_readiness_v1(),false),
    coalesce(app.ticket_bulk_runtime_schema_readiness_v2(),false),
    coalesce(app.ticket_export_runtime_schema_readiness_v2(),false),
    coalesce(app.ticket_metadata_runtime_schema_readiness_v1(),false)
  ]::boolean[];
EXCEPTION
  WHEN undefined_table OR undefined_function OR insufficient_privilege
    OR invalid_schema_name OR cardinality_violation OR data_exception THEN
    RETURN ARRAY[false,false,false,false,false,false,false,false]::boolean[];
END;
$function$;
ALTER FUNCTION app.api_runtime_schema_readiness_v62() OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.api_runtime_schema_readiness_v62()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.api_runtime_schema_readiness_v62()
  TO periapsis_migrator,periapsis_api;
--> statement-breakpoint
CREATE FUNCTION app.worker_runtime_schema_readiness_v62()
RETURNS boolean[]
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
DECLARE
  release_ready boolean;
BEGIN
  release_ready := app.release_runtime_schema_readiness_v62();
  IF release_ready IS DISTINCT FROM true THEN
    RETURN ARRAY[false,false,false,false,false]::boolean[];
  END IF;
  RETURN ARRAY[
    true,
    coalesce(app.private_sla_system_principal_catalog_ready_v1(),false),
    coalesce(app.sla_object_event_ingress_schema_readiness_v1(),false),
    coalesce(app.ticket_bulk_runtime_schema_readiness_v2(),false),
    coalesce(app.ticket_export_runtime_schema_readiness_v2(),false)
  ]::boolean[];
EXCEPTION
  WHEN undefined_table OR undefined_function OR insufficient_privilege
    OR invalid_schema_name OR cardinality_violation OR data_exception THEN
    RETURN ARRAY[false,false,false,false,false]::boolean[];
END;
$function$;
ALTER FUNCTION app.worker_runtime_schema_readiness_v62() OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.worker_runtime_schema_readiness_v62()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.worker_runtime_schema_readiness_v62()
  TO periapsis_migrator,periapsis_worker;
--> statement-breakpoint

