-- Read only the live caller's SLA authority epochs through a guarded ABI.
-- Runtime roles retain no direct access to identity authority tables.
CREATE FUNCTION app.read_sla_authority_epochs_v1(
  p_tenant_id uuid,
  p_membership_id uuid
)
RETURNS TABLE(permission_epoch bigint, subject_epoch bigint)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_tenant_id IS NULL OR p_membership_id IS NULL
     OR p_tenant_id IS DISTINCT FROM app.context_tenant_id()
     OR p_membership_id IS DISTINCT FROM app.current_tenant_membership_id()
  THEN
    RAISE EXCEPTION 'SLA authority epoch context is invalid'
      USING ERRCODE = '42501';
  END IF;
  RETURN QUERY
  SELECT state.revision, profile.version::bigint
  FROM public.tenant_authorization_states AS state
  JOIN public.tenant_user_profiles AS profile
    ON profile.tenant_id = state.tenant_id
   AND profile.membership_id = p_membership_id
  WHERE state.tenant_id = p_tenant_id;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.read_sla_authority_epochs_v1(uuid, uuid)
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.read_sla_authority_epochs_v1(uuid, uuid)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.read_sla_authority_epochs_v1(uuid, uuid)
TO periapsis_api;
--> statement-breakpoint
-- Service-specific projections perform the full release attestation once per
-- invocation. These functions are themselves included in the V57 catalog hash.
-- V57 does not exist until the next migration: this interval fails closed.
CREATE FUNCTION app.api_runtime_schema_readiness_v57()
RETURNS boolean[]
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
DECLARE
  release_ready boolean;
BEGIN
  release_ready := app.release_runtime_schema_readiness_v57();
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
ALTER FUNCTION app.api_runtime_schema_readiness_v57() OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.api_runtime_schema_readiness_v57()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.api_runtime_schema_readiness_v57()
  TO periapsis_migrator,periapsis_api;
--> statement-breakpoint
CREATE FUNCTION app.worker_runtime_schema_readiness_v57()
RETURNS boolean[]
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
DECLARE
  release_ready boolean;
BEGIN
  release_ready := app.release_runtime_schema_readiness_v57();
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
ALTER FUNCTION app.worker_runtime_schema_readiness_v57() OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.worker_runtime_schema_readiness_v57()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.worker_runtime_schema_readiness_v57()
  TO periapsis_migrator,periapsis_worker;
--> statement-breakpoint
