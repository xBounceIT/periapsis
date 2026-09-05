-- Dedicated queue owners bypass the generated runtime-role policies through
-- their own permissive policies. Replace every permissive delivery/worker
-- route so a suspended tenant cannot be claimed through an alternate role.
DROP POLICY IF EXISTS notification_dispatch_owner_deliveries_v1
ON public.tenant_notification_deliveries;
--> statement-breakpoint
CREATE POLICY notification_dispatch_owner_deliveries_v1
ON public.tenant_notification_deliveries AS PERMISSIVE FOR ALL
TO periapsis_notification_dispatch_owner
USING (
  tenant_id = app.context_tenant_id()
  AND app.tenant_is_active_v1(tenant_id)
)
WITH CHECK (
  tenant_id = app.context_tenant_id()
  AND app.tenant_is_active_v1(tenant_id)
);
--> statement-breakpoint
DROP POLICY IF EXISTS notification_dispatch_owner_delivery_claim_global_v1
ON public.tenant_notification_deliveries;
--> statement-breakpoint
CREATE POLICY notification_dispatch_owner_delivery_claim_global_v1
ON public.tenant_notification_deliveries AS PERMISSIVE FOR ALL
TO periapsis_notification_dispatch_owner
USING (app.tenant_is_active_v1(tenant_id))
WITH CHECK (app.tenant_is_active_v1(tenant_id));
--> statement-breakpoint

DROP POLICY IF EXISTS sla_evaluation_jobs_sla_worker_owner_v1
ON public.sla_evaluation_jobs;
--> statement-breakpoint
CREATE POLICY sla_evaluation_jobs_sla_worker_owner_v1
ON public.sla_evaluation_jobs AS PERMISSIVE FOR ALL
TO periapsis_sla_worker_owner
USING (app.tenant_is_active_v1(tenant_id))
WITH CHECK (app.tenant_is_active_v1(tenant_id));
--> statement-breakpoint

-- A prior hardening migration narrowed this policy to SELECT after revoking
-- every direct Alert write privilege. Restore the canonical policy command
-- before Drizzle alters its expression; table privileges still make bounded
-- SECURITY DEFINER commands the only write surface.
DROP POLICY IF EXISTS alerts_api_tenant ON public.alerts;
--> statement-breakpoint
CREATE POLICY alerts_api_tenant
ON public.alerts AS PERMISSIVE FOR ALL TO periapsis_api
USING (
  tenant_id = app.context_tenant_id()
  AND app.tenant_is_active_v1(tenant_id)
  AND app.current_tenant_membership_id() IS NOT NULL
)
WITH CHECK (
  tenant_id = app.context_tenant_id()
  AND app.tenant_is_active_v1(tenant_id)
  AND app.current_tenant_membership_id() IS NOT NULL
);
--> statement-breakpoint

-- Every Alert/Case write, including SECURITY DEFINER and service-account
-- entry points, takes the same authorization-state fence as suspension. This
-- closes the active-check/write race that RLS visibility alone cannot close.
CREATE FUNCTION app.guard_active_tenant_ticket_write_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, app
AS $function$
BEGIN
  IF TG_OP = 'UPDATE' AND NEW.tenant_id IS DISTINCT FROM OLD.tenant_id THEN
    RAISE EXCEPTION 'ticket tenant ownership is immutable'
      USING ERRCODE = '42501';
  END IF;

  PERFORM 1
  FROM public.tenant_authorization_states AS authorization_state
  WHERE authorization_state.tenant_id = NEW.tenant_id
    AND authorization_state.initialized_at IS NOT NULL
  FOR KEY SHARE;
  IF NOT FOUND OR NOT app.tenant_is_active_v1(NEW.tenant_id) THEN
    RAISE EXCEPTION 'active initialized tenant is required for ticket writes'
      USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.guard_active_tenant_ticket_write_v1()
OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_active_tenant_ticket_write_v1()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_notification_admin_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner;
--> statement-breakpoint

DROP TRIGGER IF EXISTS alerts_active_tenant_write_v1 ON public.alerts;
--> statement-breakpoint
CREATE TRIGGER alerts_active_tenant_write_v1
BEFORE INSERT OR UPDATE ON public.alerts
FOR EACH ROW EXECUTE FUNCTION app.guard_active_tenant_ticket_write_v1();
--> statement-breakpoint
DROP TRIGGER IF EXISTS cases_active_tenant_write_v1 ON public.cases;
--> statement-breakpoint
CREATE TRIGGER cases_active_tenant_write_v1
BEFORE INSERT OR UPDATE ON public.cases
FOR EACH ROW EXECUTE FUNCTION app.guard_active_tenant_ticket_write_v1();
--> statement-breakpoint

-- This readiness surface is deliberately semantic rather than a migration
-- number check. Health and the final manifest seal call it after generated RLS
-- changes have landed, so an incomplete or hand-edited bundle stays unready.
CREATE FUNCTION app.platform_tenant_lifecycle_schema_readiness_v1()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, app
AS $function$
DECLARE
  helper_oid oid;
  lifecycle_oid oid;
  readiness_oid oid;
  helper_definition text;
  lifecycle_definition text;
  session_v2_definition text;
  session_v3_definition text;
  membership_definition text;
  session_tenant_definition text;
BEGIN
  SELECT function.oid, pg_get_functiondef(function.oid)
  INTO helper_oid, helper_definition
  FROM pg_catalog.pg_proc AS function
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid = function.pronamespace
  JOIN pg_catalog.pg_roles AS owner ON owner.oid = function.proowner
  WHERE namespace.nspname = 'app'
    AND function.proname = 'tenant_is_active_v1'
    AND function.proargtypes = '2950'::pg_catalog.oidvector
    AND function.prorettype = 'boolean'::pg_catalog.regtype
    AND function.provolatile = 's'
    AND function.prosecdef
    AND function.proisstrict
    AND owner.rolname = 'periapsis_migrator';
  IF helper_oid IS NULL
     OR helper_definition NOT LIKE '%tenant.status = ''active''%'
     OR NOT has_function_privilege(
       'periapsis_api', helper_oid, 'EXECUTE'
     )
     OR NOT has_function_privilege(
       'periapsis_worker', helper_oid, 'EXECUTE'
     )
     OR NOT has_function_privilege(
       'periapsis_notifier', helper_oid, 'EXECUTE'
     )
     OR NOT has_function_privilege(
       'periapsis_notification_dispatch_owner', helper_oid, 'EXECUTE'
     )
     OR NOT has_function_privilege(
       'periapsis_sla_worker_owner', helper_oid, 'EXECUTE'
     )
     OR has_function_privilege(
       'periapsis_auditor', helper_oid, 'EXECUTE'
     )
     OR EXISTS (
       SELECT 1
       FROM pg_catalog.pg_proc AS function
       CROSS JOIN LATERAL pg_catalog.aclexplode(
         coalesce(
           function.proacl,
           pg_catalog.acldefault('f', function.proowner)
         )
       ) AS privilege
       WHERE function.oid = helper_oid
         AND privilege.grantee = 0
         AND privilege.privilege_type = 'EXECUTE'
     ) THEN
    RETURN false;
  END IF;

  SELECT function.oid, pg_get_functiondef(function.oid)
  INTO lifecycle_oid, lifecycle_definition
  FROM pg_catalog.pg_proc AS function
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid = function.pronamespace
  JOIN pg_catalog.pg_roles AS owner ON owner.oid = function.proowner
  WHERE namespace.nspname = 'app'
    AND function.proname = 'change_platform_tenant_lifecycle'
    AND function.oid =
      'app.change_platform_tenant_lifecycle(uuid,uuid,public.tenant_status,integer,text,uuid,uuid,uuid,inet,text,text)'::regprocedure
    AND function.provolatile = 'v'
    AND function.prosecdef
    AND owner.rolname = 'periapsis_migrator';
  IF lifecycle_oid IS NULL
     OR lifecycle_definition NOT LIKE '%tenant_authorization_states%'
     OR lifecycle_definition NOT LIKE '%FOR UPDATE%'
     OR lifecycle_definition NOT LIKE '%authorization_revision + 1%'
     OR lifecycle_definition NOT LIKE '%notification_deliveries_fenced%'
     OR lifecycle_definition NOT LIKE '%tenant_suspended%'
     OR lifecycle_definition NOT LIKE '%sla_jobs_fenced%'
     OR NOT has_function_privilege(
       'periapsis_api', lifecycle_oid, 'EXECUTE'
     )
     OR has_function_privilege(
       'periapsis_worker', lifecycle_oid, 'EXECUTE'
     )
     OR has_function_privilege(
       'periapsis_notifier', lifecycle_oid, 'EXECUTE'
     )
     OR has_function_privilege(
       'periapsis_auditor', lifecycle_oid, 'EXECUTE'
     )
     OR EXISTS (
       SELECT 1
       FROM pg_catalog.pg_proc AS function
       CROSS JOIN LATERAL pg_catalog.aclexplode(
         coalesce(
           function.proacl,
           pg_catalog.acldefault('f', function.proowner)
         )
       ) AS privilege
       WHERE function.oid = lifecycle_oid
         AND privilege.grantee = 0
         AND privilege.privilege_type = 'EXECUTE'
     ) THEN
    RETURN false;
  END IF;

  SELECT pg_get_functiondef(
    'app.get_auth_session_v2(bytea)'::regprocedure
  ) INTO session_v2_definition;
  SELECT pg_get_functiondef(
    'app.get_auth_session_v3(bytea)'::regprocedure
  ) INTO session_v3_definition;
  SELECT pg_get_functiondef(
    'app.current_tenant_membership_id()'::regprocedure
  ) INTO membership_definition;
  SELECT pg_get_functiondef(
    'app.session_tenant_allowed(uuid,uuid)'::regprocedure
  ) INTO session_tenant_definition;
  IF session_v2_definition NOT LIKE '%get_auth_session_v3%'
     OR session_v2_definition NOT LIKE '%platform.tenant.manage%'
     OR session_v3_definition LIKE '%permission_key <> ''platform.tenant.manage''%'
     OR membership_definition NOT LIKE '%tenant.status = ''active''%'
     OR session_tenant_definition NOT LIKE '%tenant.status = ''active''%' THEN
    RETURN false;
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM public.platform_permissions AS permission
    JOIN public.platform_role_permissions AS role_permission
      ON role_permission.permission_id = permission.id
    JOIN public.platform_roles AS role ON role.id = role_permission.role_id
    WHERE permission.key = 'platform.tenant.manage'
      AND role.key = 'platform_super_admin'
  ) OR NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_constraint AS constraint_record
    WHERE constraint_record.conrelid =
            'public.platform_audit_events'::regclass
      AND constraint_record.conname = 'platform_audit_events_reason_check'
      AND pg_get_constraintdef(constraint_record.oid) LIKE '%octet_length%'
      AND pg_get_constraintdef(constraint_record.oid) LIKE '%2048%'
  ) THEN
    RETURN false;
  END IF;

  IF EXISTS (
    SELECT 1
    FROM (VALUES
      ('notification_dispatch_owner_deliveries_v1',
       'tenant_notification_deliveries',
       'periapsis_notification_dispatch_owner'),
      ('notification_dispatch_owner_delivery_claim_global_v1',
       'tenant_notification_deliveries',
       'periapsis_notification_dispatch_owner'),
      ('sla_evaluation_jobs_sla_worker_owner_v1',
       'sla_evaluation_jobs',
       'periapsis_sla_worker_owner'),
      ('alerts_api_tenant', 'alerts', 'periapsis_api'),
      ('cases_api_tenant', 'cases', 'periapsis_api'),
      ('users_api_tenant_select', 'users', 'periapsis_api'),
      ('tenant_notification_deliveries_notifier_tenant',
       'tenant_notification_deliveries', 'periapsis_notifier'),
      ('tenant_notification_delivery_attempts_notifier_tenant',
       'tenant_notification_delivery_attempts', 'periapsis_notifier'),
      ('sla_evaluation_jobs_worker_tenant',
       'sla_evaluation_jobs', 'periapsis_worker')
    ) AS expected(policy_name, table_name, role_name)
    WHERE NOT EXISTS (
      SELECT 1
      FROM pg_catalog.pg_policies AS policy
      WHERE policy.schemaname = 'public'
        AND policy.tablename = expected.table_name
        AND policy.policyname = expected.policy_name
        AND policy.roles = ARRAY[expected.role_name]::name[]
        AND position(
          'tenant_is_active_v1' IN coalesce(policy.qual, '')
        ) > 0
        AND (
          policy.cmd = 'SELECT'
          OR position(
            'tenant_is_active_v1' IN coalesce(policy.with_check, '')
          ) > 0
        )
    )
  ) THEN
    RETURN false;
  END IF;

  IF EXISTS (
    SELECT 1
    FROM (VALUES
      ('public.alerts'::regclass, 'alerts_active_tenant_write_v1'),
      ('public.cases'::regclass, 'cases_active_tenant_write_v1')
    ) AS expected(relation_oid, trigger_name)
    WHERE NOT EXISTS (
      SELECT 1
      FROM pg_catalog.pg_trigger AS trigger
      WHERE trigger.tgrelid = expected.relation_oid
        AND trigger.tgname = expected.trigger_name
        AND NOT trigger.tgisinternal
        AND trigger.tgenabled = 'O'
        AND trigger.tgfoid =
          'app.guard_active_tenant_ticket_write_v1()'::regprocedure
        AND pg_get_triggerdef(trigger.oid) LIKE
          '%BEFORE INSERT OR UPDATE%'
    )
  ) OR EXISTS (
    SELECT 1
    FROM (VALUES
      ('public.alerts'::regclass),
      ('public.cases'::regclass),
      ('public.tenant_notification_deliveries'::regclass),
      ('public.tenant_notification_delivery_attempts'::regclass),
      ('public.sla_evaluation_jobs'::regclass)
    ) AS expected(relation_oid)
    JOIN pg_catalog.pg_class AS relation
      ON relation.oid = expected.relation_oid
    WHERE NOT relation.relrowsecurity OR NOT relation.relforcerowsecurity
  ) THEN
    RETURN false;
  END IF;

  SELECT function.oid INTO readiness_oid
  FROM pg_catalog.pg_proc AS function
  WHERE function.oid =
    'app.platform_tenant_lifecycle_schema_readiness_v1()'::regprocedure;
  RETURN readiness_oid IS NOT NULL
    AND has_function_privilege(
      'periapsis_api', readiness_oid, 'EXECUTE'
    )
    AND has_function_privilege(
      'periapsis_worker', readiness_oid, 'EXECUTE'
    )
    AND NOT has_function_privilege(
      'periapsis_notifier', readiness_oid, 'EXECUTE'
    )
    AND NOT has_function_privilege(
      'periapsis_auditor', readiness_oid, 'EXECUTE'
    )
    AND NOT EXISTS (
      SELECT 1
      FROM pg_catalog.pg_proc AS function
      CROSS JOIN LATERAL pg_catalog.aclexplode(
        coalesce(
          function.proacl,
          pg_catalog.acldefault('f', function.proowner)
        )
      ) AS privilege
      WHERE function.oid = readiness_oid
        AND privilege.grantee = 0
        AND privilege.privilege_type = 'EXECUTE'
    );
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.platform_tenant_lifecycle_schema_readiness_v1()
OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.platform_tenant_lifecycle_schema_readiness_v1()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_notification_admin_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.platform_tenant_lifecycle_schema_readiness_v1()
TO periapsis_api, periapsis_worker;
