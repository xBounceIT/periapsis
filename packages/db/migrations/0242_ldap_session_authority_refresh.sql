-- LDAP planning preserves the exact live access grant; session rotation refreshes
-- authorization pins only after the existing lifecycle and assurance checks.
CREATE FUNCTION app.claim_tenant_ldap_jit_planning_v2(
  p_operation_run_id uuid,
  p_receipt_digest bytea,
  p_digest_key_versions integer[],
  p_subject_digests bytea[],
  p_terminal_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text
)
RETURNS TABLE (
  operation_run_id uuid,
  tenant_id uuid,
  provider_id uuid,
  provider_version integer,
  binding_id uuid,
  binding_version integer,
  binding_auth_revision integer,
  binding_access_epoch_id uuid,
  configuration_revision integer,
  rule_set_revision bigint,
  authorization_revision bigint,
  jit_mode public.identity_jit_mode,
  no_match_policy public.identity_no_match_policy,
  provider_access_source_id uuid,
  external_identity_id uuid,
  user_id uuid,
  membership_id uuid,
  external_identity_exists boolean,
  user_active boolean,
  tenant_membership_exists boolean,
  tenant_membership_active boolean,
  access_grant_live boolean,
  rules jsonb,
  role_policies jsonb,
  existing_effective_role_ids uuid[],
  live_owned_edges jsonb,
  access_grant_id uuid
)
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT claim.*, grant_row.id
  FROM app.claim_tenant_ldap_jit_planning_v1(
    p_operation_run_id,p_receipt_digest,p_digest_key_versions,p_subject_digests,
    p_terminal_audit_event_id,p_request_id,p_correlation_id,p_ip_address,p_user_agent
  ) AS claim
  LEFT JOIN public.tenant_ldap_provider_access_grants AS grant_row
    ON claim.access_grant_live
   AND grant_row.tenant_id=claim.tenant_id
   AND grant_row.binding_id=claim.binding_id
   AND grant_row.membership_id=claim.membership_id
   AND grant_row.external_identity_id=claim.external_identity_id
   AND grant_row.access_epoch_id=claim.binding_access_epoch_id
   AND grant_row.source_id=claim.provider_access_source_id
   AND grant_row.ended_at IS NULL;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.claim_tenant_ldap_jit_planning_v2(uuid,bytea,integer[],bytea[],uuid,uuid,uuid,inet,text) OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.claim_tenant_ldap_jit_planning_v2(uuid,bytea,integer[],bytea[],uuid,uuid,uuid,inet,text) FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.claim_tenant_ldap_jit_planning_v2(uuid,bytea,integer[],bytea[],uuid,uuid,uuid,inet,text) TO periapsis_api;
--> statement-breakpoint
DO $repair$
DECLARE
  definition text:=pg_get_functiondef('app.private_load_ldap_session_revalidation_v1(jsonb)'::regprocedure);
BEGIN
  IF length(definition)-length(replace(definition,$old$'recoveryRestricted',v_state.recovery_restricted,$old$,'')) <> length($old$'recoveryRestricted',v_state.recovery_restricted,$old$) THEN
    RAISE EXCEPTION 'LDAP authority refresh patch point drifted';
  END IF;
  definition:=replace(definition,$old$'recoveryRestricted',v_state.recovery_restricted,$old$,$new$'recoveryRestricted',v_state.recovery_restricted,
      'authorizationRevision',v_provenance.authorization_revision,$new$);
  EXECUTE definition;
END;
$repair$;
--> statement-breakpoint
DO $repair$
DECLARE
  definition text:=pg_get_functiondef('app.private_apply_ldap_session_revalidation_v1(jsonb)'::regprocedure);
BEGIN
  IF length(definition)-length(replace(definition,$old$OR (v_decision='rotate' AND v_reason='policy_refresh')$old$,'')) <> length($old$OR (v_decision='rotate' AND v_reason='policy_refresh')$old$) THEN
    RAISE EXCEPTION 'LDAP authority refresh patch point drifted';
  END IF;
  definition:=replace(definition,$old$OR (v_decision='rotate' AND v_reason='policy_refresh')$old$,$new$OR (v_decision='rotate' AND v_reason IN ('policy_refresh','authorization_refresh'))$new$);
  IF length(definition)-length(replace(definition,$old$          OR v_projection#>'{snapshot,policyRevisions}' IS NOT DISTINCT FROM
             v_projection#>'{live,requirement,policyRevisions}'$old$,'')) <> length($old$          OR v_projection#>'{snapshot,policyRevisions}' IS NOT DISTINCT FROM
             v_projection#>'{live,requirement,policyRevisions}'$old$) THEN
    RAISE EXCEPTION 'LDAP authority refresh patch point drifted';
  END IF;
  definition:=replace(definition,$old$          OR v_projection#>'{snapshot,policyRevisions}' IS NOT DISTINCT FROM
             v_projection#>'{live,requirement,policyRevisions}'$old$,$new$          OR (v_reason='policy_refresh' AND
            v_projection#>'{snapshot,policyRevisions}' IS NOT DISTINCT FROM
              v_projection#>'{live,requirement,policyRevisions}')
          OR (v_reason='authorization_refresh' AND (
            v_live_authorization_revision<=v_provenance.authorization_revision
            OR v_projection#>'{snapshot,policyRevisions}' IS DISTINCT FROM
              v_projection#>'{live,requirement,policyRevisions}'))$new$);
  EXECUTE definition;
END;
$repair$;
--> statement-breakpoint
-- Service-specific projections perform the full release attestation once per
-- invocation. These functions are themselves included in the V56 catalog hash.
-- V56 does not exist until the next migration: this interval fails closed.
CREATE FUNCTION app.api_runtime_schema_readiness_v56()
RETURNS boolean[]
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
DECLARE
  release_ready boolean;
BEGIN
  release_ready := app.release_runtime_schema_readiness_v56();
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
ALTER FUNCTION app.api_runtime_schema_readiness_v56() OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.api_runtime_schema_readiness_v56()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.api_runtime_schema_readiness_v56()
  TO periapsis_migrator,periapsis_api;
--> statement-breakpoint
CREATE FUNCTION app.worker_runtime_schema_readiness_v56()
RETURNS boolean[]
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
DECLARE
  release_ready boolean;
BEGIN
  release_ready := app.release_runtime_schema_readiness_v56();
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
ALTER FUNCTION app.worker_runtime_schema_readiness_v56() OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.worker_runtime_schema_readiness_v56()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.worker_runtime_schema_readiness_v56()
  TO periapsis_migrator,periapsis_worker;
--> statement-breakpoint
