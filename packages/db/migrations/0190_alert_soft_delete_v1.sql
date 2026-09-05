ALTER TABLE "alert_commands" DROP CONSTRAINT "alert_commands_operation_check";--> statement-breakpoint
ALTER TABLE "alerts" ADD COLUMN "deleted_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "alerts" ADD COLUMN "deleted_by_membership_id" uuid;--> statement-breakpoint
ALTER TABLE "alerts" ADD COLUMN "deletion_reason" text;--> statement-breakpoint
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_deleter_membership_fk" FOREIGN KEY ("tenant_id","deleted_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
CREATE INDEX "alerts_tenant_live_id_idx" ON "alerts" USING btree ("tenant_id","id") WHERE "alerts"."deleted_at" is null;--> statement-breakpoint
ALTER TABLE "alert_commands" ADD CONSTRAINT "alert_commands_operation_check" CHECK ("alert_commands"."operation" in ('alert.create', 'alert.delete'));--> statement-breakpoint
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_tombstone_shape_check" CHECK (("alerts"."deleted_at" is null
          and "alerts"."deleted_by_membership_id" is null
          and "alerts"."deletion_reason" is null)
        or ("alerts"."deleted_at" is not null
          and "alerts"."deleted_by_membership_id" is not null
          and "alerts"."deletion_reason" is not null
          and btrim("alerts"."deletion_reason") <> ''
          and char_length("alerts"."deletion_reason") <= 2000
          and "alerts"."deletion_reason" !~ '[[:cntrl:]]'
          and "alerts"."deleted_at" >= "alerts"."created_at"));--> statement-breakpoint
ALTER POLICY "alerts_api_tenant" ON "alerts" TO periapsis_api USING (
  "alerts"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("alerts"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "alerts"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
 and "alerts"."deleted_at" is null) WITH CHECK (
  "alerts"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("alerts"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "alerts"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
 and "alerts"."deleted_at" is null);
--> statement-breakpoint

COMMENT ON COLUMN public.alerts.deleted_at IS
  'Immutable logical-deletion instant. Ordinary tenant projections and RLS exclude tombstoned Alerts.';
--> statement-breakpoint
COMMENT ON COLUMN public.alerts.deleted_by_membership_id IS
  'Exact live human membership that applied the immutable Alert tombstone.';
--> statement-breakpoint
COMMENT ON COLUMN public.alerts.deletion_reason IS
  'Bounded operator reason retained with the immutable Alert tombstone; never projected as ordinary ticket content.';
--> statement-breakpoint

INSERT INTO public.tenant_permissions (
  id, key, display_name, description, service_account_allowed
)
VALUES (
  uuidv7(), 'alert.delete', 'Delete alerts',
  'Apply an immutable logical-deletion tombstone to an authorized Alert.',
  false
)
ON CONFLICT (key) DO NOTHING;
--> statement-breakpoint

INSERT INTO public.tenant_permission_scopes (permission_id, scope)
SELECT permission.id, scope.value
FROM public.tenant_permissions AS permission
CROSS JOIN LATERAL unnest(ARRAY[
  'assigned'::public.authorization_scope,
  'operator_team'::public.authorization_scope,
  'tenant'::public.authorization_scope
]) AS scope(value)
WHERE permission.key = 'alert.delete'
ON CONFLICT DO NOTHING;
--> statement-breakpoint

DO $alert_delete_permission_contract$
DECLARE
  permission_record record;
  actual_scopes public.authorization_scope[];
BEGIN
  SELECT permission.* INTO STRICT permission_record
  FROM public.tenant_permissions AS permission
  WHERE permission.key = 'alert.delete';

  SELECT array_agg(scope.scope ORDER BY scope.scope)
  INTO actual_scopes
  FROM public.tenant_permission_scopes AS scope
  WHERE scope.permission_id = permission_record.id;

  IF permission_record.display_name <> 'Delete alerts'
     OR permission_record.description <>
       'Apply an immutable logical-deletion tombstone to an authorized Alert.'
     OR permission_record.service_account_allowed
     OR actual_scopes IS DISTINCT FROM ARRAY[
       'assigned'::public.authorization_scope,
       'operator_team'::public.authorization_scope,
       'tenant'::public.authorization_scope
     ] THEN
    RAISE EXCEPTION 'alert.delete permission catalog is poisoned'
      USING ERRCODE = '55000';
  END IF;
END;
$alert_delete_permission_contract$;
--> statement-breakpoint

CREATE FUNCTION app.private_seed_tenant_alert_delete_authorization_v1(
  p_tenant_id uuid
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  administrator_role record;
  inserted_policies integer := 0;
  inserted_ceilings integer := 0;
BEGIN
  SELECT role.* INTO STRICT administrator_role
  FROM public.tenant_roles AS role
  WHERE role.tenant_id = p_tenant_id
    AND role.key = 'tenant_admin'
    AND role.principal_kind = 'human'
    AND role.system_role
    AND role.protected_role
    AND role.archived_at IS NULL
  FOR UPDATE;

  INSERT INTO public.tenant_role_permissions (
    tenant_id, role_id, permission_id, scope, created_by_membership_id
  )
  SELECT p_tenant_id, administrator_role.id, permission_scope.permission_id,
         permission_scope.scope, NULL
  FROM public.tenant_permission_scopes AS permission_scope
  JOIN public.tenant_permissions AS permission
    ON permission.id = permission_scope.permission_id
  WHERE permission.key = 'alert.delete'
  ON CONFLICT DO NOTHING;
  GET DIAGNOSTICS inserted_policies = ROW_COUNT;

  INSERT INTO public.tenant_role_delegation_ceilings (
    tenant_id, role_id, permission_id, scope, created_by_membership_id
  )
  SELECT p_tenant_id, administrator_role.id, permission_scope.permission_id,
         permission_scope.scope, NULL
  FROM public.tenant_permission_scopes AS permission_scope
  JOIN public.tenant_permissions AS permission
    ON permission.id = permission_scope.permission_id
  WHERE permission.key = 'alert.delete'
  ON CONFLICT DO NOTHING;
  GET DIAGNOSTICS inserted_ceilings = ROW_COUNT;

  IF inserted_policies > 0 OR inserted_ceilings > 0 THEN
    IF administrator_role.version >= 2147483647 THEN
      RAISE EXCEPTION 'tenant_admin Alert-delete authorization version exhausted'
        USING ERRCODE = '55000';
    END IF;
    UPDATE public.tenant_roles
    SET version = administrator_role.version + 1,
        updated_at = transaction_timestamp()
    WHERE tenant_id = p_tenant_id
      AND id = administrator_role.id
      AND version = administrator_role.version;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'tenant_admin Alert-delete authorization changed concurrently'
        USING ERRCODE = '40001';
    END IF;

    INSERT INTO public.audit_events (
      id, tenant_id, sequence, actor_type, action, resource_type,
      resource_id, authentication_method, outcome, after, metadata
    ) VALUES (
      uuidv7(), p_tenant_id, 0, 'system',
      'tenant.authorization.alert_delete_enabled', 'tenant_role',
      administrator_role.id, 'database_migration', 'success',
      jsonb_build_object(
        'permission', 'alert.delete',
        'prior_version', administrator_role.version,
        'result_version', administrator_role.version + 1
      ),
      jsonb_build_object('migration', '0190_alert_soft_delete_v1')
    );
  END IF;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_seed_tenant_alert_delete_authorization_v1(uuid)
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_seed_tenant_alert_delete_authorization_v1(uuid)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;
--> statement-breakpoint

DO $seed_existing_tenants$
DECLARE
  tenant_record record;
BEGIN
  FOR tenant_record IN
    SELECT tenant.id FROM public.tenants AS tenant ORDER BY tenant.id
  LOOP
    PERFORM app.private_seed_tenant_alert_delete_authorization_v1(
      tenant_record.id
    );
  END LOOP;
END;
$seed_existing_tenants$;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.seed_tenant_authorization(
  p_tenant_id uuid,
  p_initial_admin_membership_id uuid
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  PERFORM app.seed_tenant_authorization_contacts_compatibility_impl(
    p_tenant_id, p_initial_admin_membership_id
  );
  PERFORM app.private_seed_tenant_contact_authorization_v1(p_tenant_id);
  PERFORM app.private_seed_tenant_alert_delete_authorization_v1(p_tenant_id);
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.seed_tenant_authorization(uuid, uuid)
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.seed_tenant_authorization(uuid, uuid)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;
--> statement-breakpoint

CREATE FUNCTION app.guard_alert_soft_delete_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'Alert rows use immutable logical deletion'
      USING ERRCODE = '55000';
  END IF;
  IF OLD.deleted_at IS NOT NULL THEN
    RAISE EXCEPTION 'Alert tombstones are immutable'
      USING ERRCODE = '55000';
  END IF;
  IF NEW.deleted_at IS NULL THEN
    RETURN NEW;
  END IF;
  IF current_setting('app.alert_delete_target', true)
       IS DISTINCT FROM OLD.id::text
     OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.version IS DISTINCT FROM OLD.version + 1
     OR NEW.deleted_by_membership_id IS DISTINCT FROM
       app.current_tenant_membership_id()
     OR NEW.deleted_at IS DISTINCT FROM transaction_timestamp()
     OR NEW.updated_at IS DISTINCT FROM NEW.deleted_at
     OR to_jsonb(NEW) - ARRAY[
       'deleted_at', 'deleted_by_membership_id', 'deletion_reason',
       'updated_at', 'version'
     ]::text[] IS DISTINCT FROM to_jsonb(OLD) - ARRAY[
       'deleted_at', 'deleted_by_membership_id', 'deletion_reason',
       'updated_at', 'version'
     ]::text[] THEN
    RAISE EXCEPTION 'Alert tombstone transition is not authorized or exact'
      USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.guard_alert_soft_delete_v1()
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_alert_soft_delete_v1()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;
--> statement-breakpoint
CREATE TRIGGER alerts_soft_delete_guard_v1
BEFORE UPDATE OR DELETE ON public.alerts
FOR EACH ROW EXECUTE FUNCTION app.guard_alert_soft_delete_v1();
--> statement-breakpoint

CREATE FUNCTION app.lookup_tenant_alert_delete_replay_v1(
  p_alert_id uuid,
  p_key_digest bytea,
  p_request_digest bytea
)
RETURNS TABLE(
  alert_id uuid,
  previous_version bigint,
  tombstone_version bigint,
  deleted_at timestamp with time zone
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid;
  command_record public.alert_commands%ROWTYPE;
  alert_record public.alerts%ROWTYPE;
BEGIN
  IF p_alert_id IS NULL OR uuid_extract_version(p_alert_id) <> 7
     OR p_key_digest IS NULL OR octet_length(p_key_digest) <> 32
     OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32 THEN
    RAISE EXCEPTION 'Alert-delete replay lookup is invalid'
      USING ERRCODE = '22023';
  END IF;
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();

  SELECT command.* INTO command_record
  FROM public.alert_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.operation = 'alert.delete'
    AND command.principal_kind = 'human'
    AND command.actor_membership_id = actor_membership
    AND command.key_digest = p_key_digest;
  IF NOT FOUND THEN
    RETURN;
  END IF;
  IF command_record.request_digest IS DISTINCT FROM p_request_digest
     OR command_record.result_alert_id IS DISTINCT FROM p_alert_id THEN
    RAISE EXCEPTION 'Alert-delete idempotency key conflicts'
      USING ERRCODE = '23505',
            CONSTRAINT = 'alert_commands_human_replay_key';
  END IF;

  SELECT alert.* INTO alert_record
  FROM public.alerts AS alert
  WHERE alert.tenant_id = context_tenant
    AND alert.id = p_alert_id;
  IF NOT FOUND
     OR alert_record.deleted_at IS NULL
     OR alert_record.deleted_at IS DISTINCT FROM command_record.created_at
     OR alert_record.version IS DISTINCT FROM command_record.result_version
     OR command_record.result_version NOT BETWEEN 2 AND 2147483647
     OR NOT app.private_current_ticket_scope_allows_v1(
       'alert.delete', alert_record.assigned_team_id, alert_record.created_by,
       alert_record.assignee_user_id, alert_record.claimed_by_user_id
     ) THEN
    RAISE EXCEPTION 'Alert-delete replay is unavailable'
      USING ERRCODE = '42501';
  END IF;

  RETURN QUERY SELECT p_alert_id,
    (command_record.result_version - 1)::bigint,
    command_record.result_version::bigint,
    command_record.created_at;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.lookup_tenant_alert_delete_replay_v1(uuid, bytea, bytea)
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.lookup_tenant_alert_delete_replay_v1(uuid, bytea, bytea)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.lookup_tenant_alert_delete_replay_v1(uuid, bytea, bytea)
  TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.delete_tenant_alert_v1(
  p_alert_id uuid,
  p_expected_version bigint,
  p_reason text,
  p_key_digest bytea,
  p_request_digest bytea,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE(
  alert_id uuid,
  previous_version bigint,
  tombstone_version bigint,
  deleted_at timestamp with time zone,
  replayed boolean
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid;
  command_record public.alert_commands%ROWTYPE;
  alert_record public.alerts%ROWTYPE;
  operation_at timestamp with time zone := transaction_timestamp();
  changed_rows integer;
BEGIN
  IF p_alert_id IS NULL OR uuid_extract_version(p_alert_id) <> 7
     OR p_expected_version NOT BETWEEN 1 AND 2147483646
     OR p_reason IS NULL OR btrim(p_reason) = ''
     OR char_length(p_reason) > 2000 OR p_reason ~ '[[:cntrl:]]'
     OR p_key_digest IS NULL OR octet_length(p_key_digest) <> 32
     OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32
     OR p_request_id IS NULL OR uuid_extract_version(p_request_id) <> 7
     OR p_correlation_id IS NULL OR uuid_extract_version(p_correlation_id) <> 7
     OR p_ip_address IS NULL
     OR p_user_agent IS NOT NULL AND char_length(p_user_agent) > 1024
     OR p_authentication_method IS NULL
     OR p_authentication_method !~ '^[a-z][a-z0-9_.-]{0,63}$' THEN
    RAISE EXCEPTION 'Alert-delete request is invalid'
      USING ERRCODE = '22023';
  END IF;

  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  PERFORM pg_advisory_xact_lock(hashtextextended(
    context_tenant::text || ':' || actor_membership::text
      || ':alert.delete:' || encode(p_key_digest, 'hex'), 0
  ));

  SELECT command.* INTO command_record
  FROM public.alert_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.operation = 'alert.delete'
    AND command.principal_kind = 'human'
    AND command.actor_membership_id = actor_membership
    AND command.key_digest = p_key_digest
  FOR UPDATE;
  IF FOUND THEN
    IF command_record.request_digest IS DISTINCT FROM p_request_digest
       OR command_record.result_alert_id IS DISTINCT FROM p_alert_id
       OR command_record.result_version IS DISTINCT FROM p_expected_version + 1 THEN
      RAISE EXCEPTION 'Alert-delete idempotency key conflicts'
        USING ERRCODE = '23505',
              CONSTRAINT = 'alert_commands_human_replay_key';
    END IF;
    SELECT alert.* INTO alert_record
    FROM public.alerts AS alert
    WHERE alert.tenant_id = context_tenant
      AND alert.id = p_alert_id
    FOR SHARE;
    IF NOT FOUND
       OR alert_record.deleted_at IS NULL
       OR alert_record.deleted_at IS DISTINCT FROM command_record.created_at
       OR alert_record.version IS DISTINCT FROM command_record.result_version
       OR NOT app.private_current_ticket_scope_allows_v1(
         'alert.delete', alert_record.assigned_team_id, alert_record.created_by,
         alert_record.assignee_user_id, alert_record.claimed_by_user_id
       ) THEN
      RAISE EXCEPTION 'Alert-delete replay is unavailable'
        USING ERRCODE = '42501';
    END IF;
    RETURN QUERY SELECT p_alert_id, p_expected_version,
      command_record.result_version::bigint, command_record.created_at, true;
    RETURN;
  END IF;

  SELECT alert.* INTO alert_record
  FROM public.alerts AS alert
  WHERE alert.tenant_id = context_tenant
    AND alert.id = p_alert_id
  FOR UPDATE;
  IF NOT FOUND OR alert_record.deleted_at IS NOT NULL THEN
    RAISE EXCEPTION 'Alert is unavailable'
      USING ERRCODE = 'P0002';
  END IF;
  IF NOT app.private_current_ticket_scope_allows_v1(
    'alert.delete', alert_record.assigned_team_id, alert_record.created_by,
    alert_record.assignee_user_id, alert_record.claimed_by_user_id
  ) THEN
    RAISE EXCEPTION 'Alert-delete authority is required'
      USING ERRCODE = '42501';
  END IF;
  IF alert_record.version IS DISTINCT FROM p_expected_version THEN
    RAISE EXCEPTION 'Alert-delete version is stale'
      USING ERRCODE = '40001';
  END IF;

  PERFORM set_config('app.alert_delete_target', p_alert_id::text, true);
  UPDATE public.alerts AS alert
  SET deleted_at = operation_at,
      deleted_by_membership_id = actor_membership,
      deletion_reason = p_reason,
      updated_at = operation_at,
      version = alert_record.version + 1
  WHERE alert.tenant_id = context_tenant
    AND alert.id = p_alert_id
    AND alert.version = alert_record.version
    AND alert.deleted_at IS NULL;
  GET DIAGNOSTICS changed_rows = ROW_COUNT;
  PERFORM set_config('app.alert_delete_target', '', true);
  IF changed_rows <> 1 THEN
    RAISE EXCEPTION 'Alert-delete version changed concurrently'
      USING ERRCODE = '40001';
  END IF;

  INSERT INTO public.alert_commands (
    id, tenant_id, operation, principal_kind, actor_membership_id,
    actor_service_account_id, key_digest, request_digest,
    result_alert_id, result_version, created_at
  ) VALUES (
    uuidv7(), context_tenant, 'alert.delete', 'human', actor_membership,
    NULL, p_key_digest, p_request_digest, p_alert_id,
    alert_record.version + 1, operation_at
  );

  PERFORM app.private_append_ticket_side_effects_v1(
    'alert', p_alert_id, 'deleted', alert_record.version + 1,
    ARRAY['activity', 'audit']::text[],
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method,
    jsonb_build_object(
      'version', alert_record.version,
      'deleted_at', NULL
    ),
    jsonb_build_object(
      'version', alert_record.version + 1,
      'deleted_at', operation_at
    ),
    jsonb_build_object(
      'reason', p_reason,
      'previous_version', alert_record.version,
      'tombstone_version', alert_record.version + 1,
      'logical_delete', true
    )
  );

  RETURN QUERY SELECT p_alert_id, alert_record.version::bigint,
    (alert_record.version + 1)::bigint, operation_at, false;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.delete_tenant_alert_v1(
  uuid, bigint, text, bytea, bytea, uuid, uuid, inet, text, text
) OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.delete_tenant_alert_v1(
  uuid, bigint, text, bytea, bytea, uuid, uuid, inet, text, text
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.delete_tenant_alert_v1(
  uuid, bigint, text, bytea, bytea, uuid, uuid, inet, text, text
) TO periapsis_api;
