-- Avoid PL/pgSQL's variable/column ambiguity on the ordinary service-account
-- role-grant path. The trigger remains private and keeps its exact runtime
-- ownership, configuration, and ACL boundary.
CREATE OR REPLACE FUNCTION app.private_guard_sla_system_principal_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  target_tenant_id uuid := coalesce(NEW.tenant_id, OLD.tenant_id);
  protected_target boolean := false;
BEGIN
  IF TG_TABLE_NAME = 'tenant_service_accounts' THEN
    protected_target := coalesce(NEW.system_owned, false)
      OR coalesce(OLD.system_owned, false)
      OR coalesce(NEW.key, '') = 'sla_action_runtime'
      OR coalesce(OLD.key, '') = 'sla_action_runtime';
  ELSIF TG_TABLE_NAME = 'tenant_api_credentials' THEN
    SELECT account.system_owned INTO protected_target
    FROM public.tenant_service_accounts AS account
    WHERE account.tenant_id = target_tenant_id
      AND account.id = coalesce(NEW.service_account_id,
                                OLD.service_account_id);
  ELSIF TG_TABLE_NAME = 'tenant_service_account_role_grants' THEN
    SELECT account.system_owned INTO protected_target
    FROM public.tenant_service_accounts AS account
    WHERE account.tenant_id = target_tenant_id
      AND account.id = coalesce(NEW.service_account_id,
                                OLD.service_account_id);
  ELSE
    RAISE EXCEPTION 'unsupported SLA system-principal guard relation'
      USING ERRCODE = '55000';
  END IF;
  IF coalesce(protected_target, false)
     AND NOT app.private_sla_system_principal_write_allowed_v1(
       target_tenant_id
     ) THEN
    RAISE EXCEPTION 'SLA action runtime identity is system-owned'
      USING ERRCODE = '42501';
  END IF;
  RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_guard_sla_system_principal_v1()
OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_guard_sla_system_principal_v1()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
