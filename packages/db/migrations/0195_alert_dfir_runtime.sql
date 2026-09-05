CREATE TABLE "alert_dfir_resource_commands" (
	"command_id" uuid PRIMARY KEY NOT NULL,
	"tenant_id" uuid NOT NULL,
	"actor_user_id" uuid NOT NULL,
	"actor_membership_id" uuid NOT NULL,
	"alert_id" uuid NOT NULL,
	"operation" text NOT NULL,
	"resource_id" uuid NOT NULL,
	"result_version" bigint NOT NULL,
	"key_digest" "bytea" NOT NULL,
	"request_digest" "bytea" NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "alert_dfir_resource_commands_replay_key" UNIQUE("tenant_id","actor_user_id","actor_membership_id","operation","key_digest"),
	CONSTRAINT "alert_dfir_resource_commands_result_key" UNIQUE("tenant_id","alert_id","operation","resource_id","result_version"),
	CONSTRAINT "alert_dfir_resource_commands_shape_check" CHECK ((uuid_extract_version("alert_dfir_resource_commands"."command_id") = 7) is true
        and (uuid_extract_version("alert_dfir_resource_commands"."resource_id") = 7) is true
        and "alert_dfir_resource_commands"."operation" in ('dfir.ioc.create','dfir.ioc.replace','dfir.asset.create','dfir.asset.replace','dfir.timeline.create')
        and "alert_dfir_resource_commands"."result_version" between 1 and 9007199254740991
        and octet_length("alert_dfir_resource_commands"."key_digest") = 32
        and octet_length("alert_dfir_resource_commands"."request_digest") = 32)
);
--> statement-breakpoint
ALTER TABLE "alert_dfir_resource_commands" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "dfir_timeline_events" ALTER COLUMN "case_id" DROP NOT NULL;--> statement-breakpoint
ALTER TABLE "dfir_timeline_events" ADD COLUMN "alert_id" uuid;--> statement-breakpoint
ALTER TABLE "alert_dfir_resource_commands" ADD CONSTRAINT "alert_dfir_resource_commands_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "alert_dfir_resource_commands" ADD CONSTRAINT "alert_dfir_resource_commands_alert_fk" FOREIGN KEY ("tenant_id","alert_id") REFERENCES "public"."alerts"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "alert_dfir_resource_commands" ADD CONSTRAINT "alert_dfir_resource_commands_actor_fk" FOREIGN KEY ("tenant_id","actor_membership_id","actor_user_id") REFERENCES "public"."tenant_memberships"("tenant_id","id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_timeline_events" ADD CONSTRAINT "dfir_timeline_events_alert_fk" FOREIGN KEY ("tenant_id","alert_id") REFERENCES "public"."alerts"("tenant_id","id") ON DELETE cascade ON UPDATE cascade;--> statement-breakpoint
CREATE INDEX "dfir_timeline_events_alert_time_idx" ON "dfir_timeline_events" USING btree ("tenant_id","alert_id","event_time","id");--> statement-breakpoint
ALTER TABLE "dfir_timeline_events" ADD CONSTRAINT "dfir_timeline_events_subject_check" CHECK (num_nonnulls("dfir_timeline_events"."alert_id", "dfir_timeline_events"."case_id") = 1);
--> statement-breakpoint

-- Alert-scoped DFIR mutations use a closed command journal.  The application
-- role can execute the narrow ABI below but cannot inspect or mutate receipts.
ALTER TABLE public.alert_dfir_resource_commands
  OWNER TO periapsis_migrator;
--> statement-breakpoint
ALTER TABLE public.alert_dfir_resource_commands FORCE ROW LEVEL SECURITY;
--> statement-breakpoint
REVOKE ALL ON TABLE public.alert_dfir_resource_commands
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;
--> statement-breakpoint

CREATE TRIGGER alert_dfir_resource_commands_immutable_v1
BEFORE UPDATE OR DELETE ON public.alert_dfir_resource_commands
FOR EACH ROW EXECUTE FUNCTION app.guard_phase4_append_only_v1();
--> statement-breakpoint

CREATE FUNCTION app.private_current_alert_dfir_manage_scope_allows_v1(
  p_permission_key text,
  p_alert_id uuid
)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor_user uuid := app.context_user_id();
  actor_membership uuid := app.current_tenant_membership_id();
  context_tenant uuid := app.context_tenant_id();
  target_alert public.alerts%ROWTYPE;
BEGIN
  IF p_permission_key IS NULL
     OR p_permission_key NOT IN (
       'dfir.ioc.manage', 'dfir.asset.manage',
       'dfir.timeline.manage', 'dfir.attachment.manage'
     )
     OR p_alert_id IS NULL THEN
    RETURN false;
  END IF;

  SELECT alert.* INTO target_alert
  FROM public.alerts AS alert
  WHERE alert.tenant_id = context_tenant
    AND alert.id = p_alert_id
    AND alert.deleted_at IS NULL;
  IF NOT FOUND THEN
    RETURN false;
  END IF;

  IF app.current_tenant_human_has_exact_permission_v3(
    p_permission_key, 'tenant'
  ) THEN
    RETURN true;
  END IF;
  IF app.current_tenant_human_has_exact_permission_v3(
       p_permission_key, 'assigned'
     ) AND actor_user IN (
       target_alert.assignee_user_id, target_alert.claimed_by_user_id
     ) THEN
    RETURN true;
  END IF;

  RETURN target_alert.assigned_team_id IS NOT NULL
    AND target_alert.assigned_team_epoch_id IS NOT NULL
    AND app.current_tenant_human_has_exact_permission_v3(
      p_permission_key, 'operator_team'
    )
    AND EXISTS (
      SELECT 1
      FROM public.operator_team_assignment_epochs AS assignment
      JOIN public.operator_team_roster_entries AS roster
        ON roster.tenant_id = assignment.tenant_id
       AND roster.assignment_epoch_id = assignment.id
      JOIN public.tenant_authorization_sources AS source
        ON source.tenant_id = roster.tenant_id
       AND source.id = roster.source_id
      WHERE assignment.tenant_id = context_tenant
        AND assignment.id = target_alert.assigned_team_epoch_id
        AND assignment.operator_team_id = target_alert.assigned_team_id
        AND assignment.ended_at IS NULL
        AND roster.membership_id = actor_membership
        AND roster.revoked_at IS NULL
        AND (roster.expires_at IS NULL
          OR roster.expires_at > transaction_timestamp())
        AND source.retired_at IS NULL
    );
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_current_alert_dfir_manage_scope_allows_v1(text, uuid)
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_current_alert_dfir_manage_scope_allows_v1(text, uuid)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;
--> statement-breakpoint

CREATE FUNCTION app.reserve_alert_dfir_resource_command_v1(
  p_command_id uuid,
  p_alert_id uuid,
  p_operation text,
  p_resource_id uuid,
  p_result_version bigint,
  p_key_digest bytea,
  p_request_digest bytea
)
RETURNS TABLE(
  result_resource_id uuid,
  result_version bigint,
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
  actor_user uuid := app.context_user_id();
  actor_membership uuid := app.current_tenant_membership_id();
  expected_permission text;
  command_record public.alert_dfir_resource_commands%ROWTYPE;
  inserted_rows bigint;
BEGIN
  expected_permission := CASE p_operation
    WHEN 'dfir.ioc.create' THEN 'dfir.ioc.manage'
    WHEN 'dfir.ioc.replace' THEN 'dfir.ioc.manage'
    WHEN 'dfir.asset.create' THEN 'dfir.asset.manage'
    WHEN 'dfir.asset.replace' THEN 'dfir.asset.manage'
    WHEN 'dfir.timeline.create' THEN 'dfir.timeline.manage'
    ELSE NULL
  END;
  IF p_command_id IS NULL
     OR uuid_extract_version(p_command_id) IS DISTINCT FROM 7
     OR p_alert_id IS NULL
     OR uuid_extract_version(p_alert_id) IS DISTINCT FROM 7
     OR p_resource_id IS NULL
     OR uuid_extract_version(p_resource_id) IS DISTINCT FROM 7
     OR expected_permission IS NULL
     OR p_result_version NOT BETWEEN 1 AND 9007199254740991
     OR (p_operation LIKE '%.create' AND p_result_version <> 1)
     OR (p_operation LIKE '%.replace' AND p_result_version < 2)
     OR p_key_digest IS NULL OR octet_length(p_key_digest) <> 32
     OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32 THEN
    RAISE EXCEPTION 'Alert DFIR command binding is invalid'
      USING ERRCODE = '22023';
  END IF;

  -- Authorization-state writers take this same row lock.  Keeping it first
  -- freezes permissions, membership, exact team epoch and roster while the
  -- Alert row is locked for the caller's whole SERIALIZABLE transaction.
  PERFORM app.lock_current_tenant_authorization_state();
  PERFORM 1
  FROM public.tenant_memberships AS membership
  JOIN public.users AS identity ON identity.id = membership.user_id
  WHERE membership.tenant_id = context_tenant
    AND membership.id = actor_membership
    AND membership.user_id = actor_user
    AND membership.status = 'active'
    AND identity.active
  FOR SHARE OF membership, identity;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Alert DFIR human authority is unavailable'
      USING ERRCODE = '42501';
  END IF;

  PERFORM 1
  FROM public.alerts AS alert
  WHERE alert.tenant_id = context_tenant
    AND alert.id = p_alert_id
    AND alert.deleted_at IS NULL
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Alert is unavailable'
      USING ERRCODE = 'P0002';
  END IF;
  IF NOT app.private_current_alert_dfir_manage_scope_allows_v1(
    expected_permission, p_alert_id
  ) THEN
    RAISE EXCEPTION 'Alert DFIR authority is required'
      USING ERRCODE = '42501';
  END IF;

  INSERT INTO public.alert_dfir_resource_commands (
    command_id, tenant_id, actor_user_id, actor_membership_id, alert_id,
    operation, resource_id, result_version, key_digest, request_digest
  ) VALUES (
    p_command_id, context_tenant, actor_user, actor_membership, p_alert_id,
    p_operation, p_resource_id, p_result_version, p_key_digest,
    p_request_digest
  )
  ON CONFLICT (
    tenant_id, actor_user_id, actor_membership_id, operation, key_digest
  ) DO NOTHING;
  GET DIAGNOSTICS inserted_rows = ROW_COUNT;

  SELECT command.* INTO STRICT command_record
  FROM public.alert_dfir_resource_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.actor_user_id = actor_user
    AND command.actor_membership_id = actor_membership
    AND command.operation = p_operation
    AND command.key_digest = p_key_digest
  FOR UPDATE;
  IF command_record.request_digest IS DISTINCT FROM p_request_digest
     OR command_record.alert_id IS DISTINCT FROM p_alert_id
     OR command_record.resource_id IS DISTINCT FROM p_resource_id
     OR command_record.result_version IS DISTINCT FROM p_result_version THEN
    RAISE EXCEPTION 'Alert DFIR idempotency key conflicts'
      USING ERRCODE = '23505',
            CONSTRAINT = 'alert_dfir_resource_commands_replay_key';
  END IF;

  RETURN QUERY SELECT command_record.resource_id,
                      command_record.result_version,
                      inserted_rows = 0;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.reserve_alert_dfir_resource_command_v1(
  uuid, uuid, text, uuid, bigint, bytea, bytea
) OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.reserve_alert_dfir_resource_command_v1(
  uuid, uuid, text, uuid, bigint, bytea, bytea
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.reserve_alert_dfir_resource_command_v1(
  uuid, uuid, text, uuid, bigint, bytea, bytea
) TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.validate_alert_dfir_timeline_link_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  root_alert_id uuid;
BEGIN
  SELECT event.alert_id INTO root_alert_id
  FROM public.dfir_timeline_events AS event
  WHERE event.tenant_id = NEW.tenant_id
    AND event.id = NEW.timeline_event_id;
  IF NOT FOUND OR root_alert_id IS NULL THEN
    RETURN NEW;
  END IF;

  IF TG_TABLE_NAME = 'dfir_timeline_evidence_links' THEN
    RAISE EXCEPTION 'Alert timeline events cannot reference Case evidence'
      USING ERRCODE = '23514';
  ELSIF TG_TABLE_NAME = 'dfir_timeline_ioc_links' THEN
    IF NOT EXISTS (
      SELECT 1
      FROM public.dfir_ioc_links AS link
      JOIN public.dfir_iocs AS resource
        ON resource.tenant_id = link.tenant_id
       AND resource.id = link.ioc_id
       AND resource.archived_at IS NULL
      WHERE link.tenant_id = NEW.tenant_id
        AND link.alert_id = root_alert_id
        AND link.ioc_id = NEW.ioc_id
    ) THEN
      RAISE EXCEPTION 'Alert timeline IOC is not directly linked to the Alert'
        USING ERRCODE = '23503';
    END IF;
  ELSIF TG_TABLE_NAME = 'dfir_timeline_asset_links' THEN
    IF NOT EXISTS (
      SELECT 1
      FROM public.dfir_asset_links AS link
      JOIN public.dfir_assets AS resource
        ON resource.tenant_id = link.tenant_id
       AND resource.id = link.asset_id
       AND resource.archived_at IS NULL
      WHERE link.tenant_id = NEW.tenant_id
        AND link.alert_id = root_alert_id
        AND link.asset_id = NEW.asset_id
    ) THEN
      RAISE EXCEPTION 'Alert timeline asset is not directly linked to the Alert'
        USING ERRCODE = '23503';
    END IF;
  ELSE
    RAISE EXCEPTION 'unsupported Alert timeline link table'
      USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.validate_alert_dfir_timeline_link_v1()
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.validate_alert_dfir_timeline_link_v1()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;
--> statement-breakpoint
CREATE TRIGGER dfir_timeline_ioc_links_alert_scope_v1
BEFORE INSERT OR UPDATE ON public.dfir_timeline_ioc_links
FOR EACH ROW EXECUTE FUNCTION app.validate_alert_dfir_timeline_link_v1();
--> statement-breakpoint
CREATE TRIGGER dfir_timeline_asset_links_alert_scope_v1
BEFORE INSERT OR UPDATE ON public.dfir_timeline_asset_links
FOR EACH ROW EXECUTE FUNCTION app.validate_alert_dfir_timeline_link_v1();
--> statement-breakpoint
CREATE TRIGGER dfir_timeline_evidence_links_alert_scope_v1
BEFORE INSERT OR UPDATE ON public.dfir_timeline_evidence_links
FOR EACH ROW EXECUTE FUNCTION app.validate_alert_dfir_timeline_link_v1();
--> statement-breakpoint

CREATE FUNCTION app.append_alert_dfir_mutation_effects_v1(
  p_alert_id uuid,
  p_permission_key text,
  p_action text,
  p_resource_type text,
  p_resource_id uuid,
  p_resource_version bigint,
  p_command_operation text,
  p_key_digest bytea,
  p_request_digest bytea,
  p_activity_id uuid,
  p_before jsonb,
  p_after jsonb,
  p_metadata jsonb,
  p_audit_event_id uuid,
  p_outbox_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_user uuid := app.context_user_id();
  actor_membership uuid := app.current_tenant_membership_id();
  expected_permission text;
  expected_action text;
  expected_resource_type text;
  fixed_summary text;
  operation_is_create boolean;
  command_id uuid;
  alert_command public.alert_dfir_resource_commands%ROWTYPE;
  attachment_command public.tenant_authorization_commands%ROWTYPE;
  resource_version bigint;
  activity_sequence bigint;
  relation_count bigint;
  safe_before jsonb;
  safe_after jsonb;
  safe_metadata jsonb;
BEGIN
  SELECT mapping.permission_key, mapping.action, mapping.resource_type,
         mapping.summary, mapping.is_create
  INTO expected_permission, expected_action, expected_resource_type,
       fixed_summary, operation_is_create
  FROM (VALUES
    ('dfir.ioc.create', 'dfir.ioc.manage', 'dfir.ioc.created',
      'dfir_ioc', 'Alert IOC created', true),
    ('dfir.ioc.replace', 'dfir.ioc.manage', 'dfir.ioc.replaced',
      'dfir_ioc', 'Alert IOC replaced', false),
    ('dfir.asset.create', 'dfir.asset.manage', 'dfir.asset.created',
      'dfir_asset', 'Alert asset created', true),
    ('dfir.asset.replace', 'dfir.asset.manage', 'dfir.asset.replaced',
      'dfir_asset', 'Alert asset replaced', false),
    ('dfir.timeline.create', 'dfir.timeline.manage', 'dfir.timeline.created',
      'dfir_timeline_event', 'Alert timeline event created', true),
    ('dfir.attachment.prepare', 'dfir.attachment.manage',
      'dfir.attachment.prepared', 'dfir_storage_object',
      'Alert attachment upload prepared', true)
  ) AS mapping(
    operation, permission_key, action, resource_type, summary, is_create
  )
  WHERE mapping.operation = p_command_operation;

  IF expected_permission IS NULL
     OR p_alert_id IS NULL
     OR uuid_extract_version(p_alert_id) IS DISTINCT FROM 7
     OR p_permission_key IS DISTINCT FROM expected_permission
     OR p_action IS DISTINCT FROM expected_action
     OR p_resource_type IS DISTINCT FROM expected_resource_type
     OR p_resource_id IS NULL
     OR uuid_extract_version(p_resource_id) IS DISTINCT FROM 7
     OR p_resource_version NOT BETWEEN 1 AND 9007199254740991
     OR operation_is_create AND p_resource_version <> 1
     OR NOT operation_is_create AND p_resource_version < 2
     OR p_key_digest IS NULL OR octet_length(p_key_digest) <> 32
     OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32
     OR p_activity_id IS NULL
     OR uuid_extract_version(p_activity_id) IS DISTINCT FROM 7
     OR p_audit_event_id IS NULL
     OR uuid_extract_version(p_audit_event_id) IS DISTINCT FROM 7
     OR p_outbox_event_id IS NULL
     OR uuid_extract_version(p_outbox_event_id) IS DISTINCT FROM 7
     OR p_request_id IS NULL
     OR uuid_extract_version(p_request_id) IS DISTINCT FROM 7
     OR p_correlation_id IS NULL
     OR uuid_extract_version(p_correlation_id) IS DISTINCT FROM 7
     OR p_ip_address IS NULL
     OR p_user_agent IS NULL
     OR octet_length(p_user_agent) NOT BETWEEN 1 AND 1024
     OR p_authentication_method NOT IN (
       'bootstrap_totp', 'totp', 'recovery_code', 'ldap',
       'oidc', 'saml', 'passkey'
     )
     OR p_before IS NULL OR jsonb_typeof(p_before) <> 'object'
     OR p_after IS NULL OR jsonb_typeof(p_after) <> 'object'
     OR p_metadata IS NULL OR jsonb_typeof(p_metadata) <> 'object'
     OR pg_column_size(p_before) > 32768
     OR pg_column_size(p_after) > 32768
     OR pg_column_size(p_metadata) > 32768 THEN
    RAISE EXCEPTION 'Alert DFIR mutation effect input is invalid'
      USING ERRCODE = '22023';
  END IF;

  PERFORM app.lock_current_tenant_authorization_state();
  PERFORM 1
  FROM public.tenant_memberships AS membership
  JOIN public.users AS identity ON identity.id = membership.user_id
  WHERE membership.tenant_id = context_tenant
    AND membership.id = actor_membership
    AND membership.user_id = actor_user
    AND membership.status = 'active'
    AND identity.active
  FOR SHARE OF membership, identity;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Alert DFIR human authority is unavailable'
      USING ERRCODE = '42501';
  END IF;

  PERFORM 1
  FROM public.alerts AS alert
  WHERE alert.tenant_id = context_tenant
    AND alert.id = p_alert_id
    AND alert.deleted_at IS NULL
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Alert is unavailable'
      USING ERRCODE = 'P0002';
  END IF;
  IF NOT app.private_current_alert_dfir_manage_scope_allows_v1(
    expected_permission, p_alert_id
  ) THEN
    RAISE EXCEPTION 'Alert DFIR authority is required'
      USING ERRCODE = '42501';
  END IF;

  IF p_command_operation = 'dfir.attachment.prepare' THEN
    SELECT command.* INTO attachment_command
    FROM public.tenant_authorization_commands AS command
    WHERE command.tenant_id = context_tenant
      AND command.actor_membership_id = actor_membership
      AND command.operation = p_command_operation
      AND command.key_digest = p_key_digest
      AND command.expires_at > transaction_timestamp()
    FOR SHARE;
    IF NOT FOUND
       OR attachment_command.request_digest IS DISTINCT FROM p_request_digest
       OR attachment_command.result_resource_id IS DISTINCT FROM p_resource_id
       OR attachment_command.result_version IS DISTINCT FROM p_resource_version THEN
      RAISE EXCEPTION 'Alert attachment command reservation is unavailable'
        USING ERRCODE = '23503';
    END IF;
    command_id := attachment_command.id;
  ELSE
    SELECT command.* INTO alert_command
    FROM public.alert_dfir_resource_commands AS command
    WHERE command.tenant_id = context_tenant
      AND command.actor_user_id = actor_user
      AND command.actor_membership_id = actor_membership
      AND command.operation = p_command_operation
      AND command.key_digest = p_key_digest
    FOR SHARE;
    IF NOT FOUND
       OR alert_command.request_digest IS DISTINCT FROM p_request_digest
       OR alert_command.alert_id IS DISTINCT FROM p_alert_id
       OR alert_command.resource_id IS DISTINCT FROM p_resource_id
       OR alert_command.result_version IS DISTINCT FROM p_resource_version THEN
      RAISE EXCEPTION 'Alert DFIR command reservation is unavailable'
        USING ERRCODE = '23503';
    END IF;
    command_id := alert_command.command_id;
  END IF;

  IF p_command_operation IN ('dfir.ioc.create', 'dfir.ioc.replace') THEN
    SELECT resource.version INTO resource_version
    FROM public.dfir_iocs AS resource
    WHERE resource.tenant_id = context_tenant
      AND resource.id = p_resource_id
      AND resource.archived_at IS NULL
    FOR SHARE;
    IF NOT FOUND OR resource_version IS DISTINCT FROM p_resource_version
       OR NOT EXISTS (
         SELECT 1 FROM public.dfir_ioc_links AS link
         WHERE link.tenant_id = context_tenant
           AND link.ioc_id = p_resource_id
           AND link.alert_id = p_alert_id
       ) THEN
      RAISE EXCEPTION 'Alert IOC projection is unavailable or stale'
        USING ERRCODE = '23503';
    END IF;
  ELSIF p_command_operation IN ('dfir.asset.create', 'dfir.asset.replace') THEN
    SELECT resource.version INTO resource_version
    FROM public.dfir_assets AS resource
    WHERE resource.tenant_id = context_tenant
      AND resource.id = p_resource_id
      AND resource.archived_at IS NULL
    FOR SHARE;
    IF NOT FOUND OR resource_version IS DISTINCT FROM p_resource_version
       OR NOT EXISTS (
         SELECT 1 FROM public.dfir_asset_links AS link
         WHERE link.tenant_id = context_tenant
           AND link.asset_id = p_resource_id
           AND link.alert_id = p_alert_id
       ) THEN
      RAISE EXCEPTION 'Alert asset projection is unavailable or stale'
        USING ERRCODE = '23503';
    END IF;
  ELSIF p_command_operation = 'dfir.timeline.create' THEN
    SELECT event.version INTO resource_version
    FROM public.dfir_timeline_events AS event
    WHERE event.tenant_id = context_tenant
      AND event.id = p_resource_id
      AND event.alert_id = p_alert_id
      AND event.case_id IS NULL
    FOR SHARE;
    IF NOT FOUND OR resource_version IS DISTINCT FROM p_resource_version
       OR EXISTS (
         SELECT 1 FROM public.dfir_timeline_evidence_links AS evidence_link
         WHERE evidence_link.tenant_id = context_tenant
           AND evidence_link.timeline_event_id = p_resource_id
       ) THEN
      RAISE EXCEPTION 'Alert timeline projection is unavailable or invalid'
        USING ERRCODE = '23503';
    END IF;

    SELECT count(*) INTO relation_count
    FROM (
      SELECT ioc_link.ioc_id AS resource_id
      FROM public.dfir_timeline_ioc_links AS ioc_link
      WHERE ioc_link.tenant_id = context_tenant
        AND ioc_link.timeline_event_id = p_resource_id
      UNION ALL
      SELECT asset_link.asset_id
      FROM public.dfir_timeline_asset_links AS asset_link
      WHERE asset_link.tenant_id = context_tenant
        AND asset_link.timeline_event_id = p_resource_id
    ) AS relation;
    IF relation_count > 1000 THEN
      RAISE EXCEPTION 'Alert timeline relation limit is exceeded'
        USING ERRCODE = '54000';
    END IF;

    PERFORM 1
    FROM public.dfir_timeline_ioc_links AS timeline_link
    JOIN public.dfir_ioc_links AS alert_link
      ON alert_link.tenant_id = timeline_link.tenant_id
     AND alert_link.ioc_id = timeline_link.ioc_id
     AND alert_link.alert_id = p_alert_id
    JOIN public.dfir_iocs AS resource
      ON resource.tenant_id = timeline_link.tenant_id
     AND resource.id = timeline_link.ioc_id
     AND resource.archived_at IS NULL
    WHERE timeline_link.tenant_id = context_tenant
      AND timeline_link.timeline_event_id = p_resource_id
    FOR SHARE OF timeline_link, alert_link, resource;
    IF EXISTS (
      SELECT 1
      FROM public.dfir_timeline_ioc_links AS timeline_link
      LEFT JOIN public.dfir_ioc_links AS alert_link
        ON alert_link.tenant_id = timeline_link.tenant_id
       AND alert_link.ioc_id = timeline_link.ioc_id
       AND alert_link.alert_id = p_alert_id
      LEFT JOIN public.dfir_iocs AS resource
        ON resource.tenant_id = timeline_link.tenant_id
       AND resource.id = timeline_link.ioc_id
       AND resource.archived_at IS NULL
      WHERE timeline_link.tenant_id = context_tenant
        AND timeline_link.timeline_event_id = p_resource_id
        AND (alert_link.id IS NULL OR resource.id IS NULL)
    ) THEN
      RAISE EXCEPTION 'Alert timeline IOC scope is invalid'
        USING ERRCODE = '23503';
    END IF;

    PERFORM 1
    FROM public.dfir_timeline_asset_links AS timeline_link
    JOIN public.dfir_asset_links AS alert_link
      ON alert_link.tenant_id = timeline_link.tenant_id
     AND alert_link.asset_id = timeline_link.asset_id
     AND alert_link.alert_id = p_alert_id
    JOIN public.dfir_assets AS resource
      ON resource.tenant_id = timeline_link.tenant_id
     AND resource.id = timeline_link.asset_id
     AND resource.archived_at IS NULL
    WHERE timeline_link.tenant_id = context_tenant
      AND timeline_link.timeline_event_id = p_resource_id
    FOR SHARE OF timeline_link, alert_link, resource;
    IF EXISTS (
      SELECT 1
      FROM public.dfir_timeline_asset_links AS timeline_link
      LEFT JOIN public.dfir_asset_links AS alert_link
        ON alert_link.tenant_id = timeline_link.tenant_id
       AND alert_link.asset_id = timeline_link.asset_id
       AND alert_link.alert_id = p_alert_id
      LEFT JOIN public.dfir_assets AS resource
        ON resource.tenant_id = timeline_link.tenant_id
       AND resource.id = timeline_link.asset_id
       AND resource.archived_at IS NULL
      WHERE timeline_link.tenant_id = context_tenant
        AND timeline_link.timeline_event_id = p_resource_id
        AND (alert_link.id IS NULL OR resource.id IS NULL)
    ) THEN
      RAISE EXCEPTION 'Alert timeline asset scope is invalid'
        USING ERRCODE = '23503';
    END IF;
  ELSE
    SELECT storage.version INTO resource_version
    FROM public.dfir_storage_objects AS storage
    JOIN public.dfir_attachments AS attachment
      ON attachment.tenant_id = storage.tenant_id
     AND attachment.storage_object_id = storage.id
    WHERE storage.tenant_id = context_tenant
      AND storage.id = p_resource_id
      AND storage.state = 'pending_upload'
      AND attachment.subject_kind = 'alert'
      AND attachment.alert_id = p_alert_id
      AND attachment.case_id IS NULL
      AND attachment.ioc_id IS NULL
      AND attachment.asset_id IS NULL
      AND attachment.evidence_id IS NULL
      AND attachment.task_id IS NULL
      AND attachment.version = 1
      AND attachment.scan_state = 'pending_upload'
    FOR SHARE OF storage, attachment;
    IF NOT FOUND OR resource_version IS DISTINCT FROM p_resource_version THEN
      RAISE EXCEPTION 'Alert attachment projection is unavailable or stale'
        USING ERRCODE = '23503';
    END IF;
  END IF;

  SELECT coalesce(max(activity.sequence), 0)::bigint + 1
  INTO activity_sequence
  FROM public.ticket_activities AS activity
  WHERE activity.tenant_id = context_tenant
    AND activity.alert_id = p_alert_id;
  IF activity_sequence NOT BETWEEN 1 AND 2147483647 THEN
    RAISE EXCEPTION 'Alert activity sequence is exhausted'
      USING ERRCODE = '54000';
  END IF;

  safe_before := CASE WHEN operation_is_create THEN '{}'::jsonb
    ELSE jsonb_build_object(
      'resourceId', p_resource_id,
      'resourceVersion', p_resource_version - 1,
      'contentRedacted', true
    ) END;
  safe_after := jsonb_build_object(
    'resourceId', p_resource_id,
    'resourceVersion', p_resource_version,
    'contentRedacted', true
  );
  safe_metadata := jsonb_build_object(
    'alertId', p_alert_id,
    'commandId', command_id,
    'commandOperation', p_command_operation,
    'actorMembershipId', actor_membership,
    'contentRedacted', true
  );

  INSERT INTO public.ticket_activities (
    id, tenant_id, alert_id, case_id, sequence, kind, summary,
    actor_principal_kind, actor_membership_id, actor_user_id,
    actor_service_account_id, origin, details, occurred_at
  ) VALUES (
    p_activity_id, context_tenant, p_alert_id, NULL,
    activity_sequence::integer, p_action, fixed_summary,
    'human', actor_membership, actor_user, NULL, 'api',
    jsonb_build_object(
      'resourceId', p_resource_id,
      'resourceVersion', p_resource_version,
      'contentRedacted', true
    ),
    transaction_timestamp()
  );

  PERFORM app.append_tenant_authorization_audit(
    p_audit_event_id, p_action, p_resource_type, p_resource_id,
    p_request_id, p_correlation_id, p_ip_address,
    p_user_agent, p_authentication_method,
    safe_before, safe_after, safe_metadata
  );

  INSERT INTO public.outbox_events (
    id, tenant_id, aggregate_type, aggregate_id, event_type,
    schema_version, payload, deduplication_key, correlation_id,
    causation_id, occurred_at
  ) VALUES (
    p_outbox_event_id, context_tenant, p_resource_type, p_resource_id,
    p_action, 1,
    jsonb_build_object(
      'tenantId', context_tenant,
      'alertId', p_alert_id,
      'resourceId', p_resource_id,
      'resourceVersion', p_resource_version
    ),
    'alert-dfir:' || command_id::text || ':' || p_audit_event_id::text,
    p_correlation_id, p_request_id, transaction_timestamp()
  );
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.append_alert_dfir_mutation_effects_v1(
  uuid, text, text, text, uuid, bigint, text, bytea, bytea, uuid,
  jsonb, jsonb, jsonb, uuid, uuid, uuid, uuid, inet, text, text
) OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.append_alert_dfir_mutation_effects_v1(
  uuid, text, text, text, uuid, bigint, text, bytea, bytea, uuid,
  jsonb, jsonb, jsonb, uuid, uuid, uuid, uuid, inet, text, text
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.append_alert_dfir_mutation_effects_v1(
  uuid, text, text, text, uuid, bigint, text, bytea, bytea, uuid,
  jsonb, jsonb, jsonb, uuid, uuid, uuid, uuid, inet, text, text
) TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.alert_dfir_runtime_schema_readiness_v1()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET quote_all_identifiers = off
SET TimeZone = 'UTC'
SET DateStyle = 'ISO, YMD'
SET IntervalStyle = 'postgres'
SET extra_float_digits = 3
SET bytea_output = 'hex'
SET standard_conforming_strings = on
SET lc_numeric = 'C'
AS $function$
DECLARE
  function_identity text;
  constraint_definition text;
BEGIN
  IF NOT EXISTS (
       SELECT 1
       FROM pg_catalog.pg_class AS relation
       JOIN pg_catalog.pg_namespace AS namespace
         ON namespace.oid = relation.relnamespace
       WHERE namespace.nspname = 'public'
         AND relation.relname = 'alert_dfir_resource_commands'
         AND relation.relkind = 'r'
         AND relation.relrowsecurity
         AND relation.relforcerowsecurity
         AND pg_catalog.pg_get_userbyid(relation.relowner) =
           'periapsis_migrator'
     )
     OR has_table_privilege(
       'periapsis_api', 'public.alert_dfir_resource_commands',
       'SELECT,INSERT,UPDATE,DELETE'
     )
     OR has_table_privilege(
       'periapsis_worker', 'public.alert_dfir_resource_commands',
       'SELECT,INSERT,UPDATE,DELETE'
     )
     OR has_table_privilege(
       'periapsis_notifier', 'public.alert_dfir_resource_commands',
       'SELECT,INSERT,UPDATE,DELETE'
     )
     OR has_table_privilege(
       'periapsis_auditor', 'public.alert_dfir_resource_commands',
       'SELECT,INSERT,UPDATE,DELETE'
     ) THEN
    RETURN false;
  END IF;

  SELECT pg_catalog.pg_get_constraintdef(catalog_constraint.oid, true)
  INTO constraint_definition
  FROM pg_catalog.pg_constraint AS catalog_constraint
  WHERE catalog_constraint.conrelid =
      'public.alert_dfir_resource_commands'::regclass
    AND catalog_constraint.conname = 'alert_dfir_resource_commands_shape_check';
  IF constraint_definition IS NULL
     OR position('dfir.ioc.create' IN constraint_definition) = 0
     OR position('dfir.ioc.replace' IN constraint_definition) = 0
     OR position('dfir.asset.create' IN constraint_definition) = 0
     OR position('dfir.asset.replace' IN constraint_definition) = 0
     OR position('dfir.timeline.create' IN constraint_definition) = 0
     OR position('dfir.attachment.prepare' IN constraint_definition) <> 0 THEN
    RETURN false;
  END IF;

  IF NOT EXISTS (
       SELECT 1
       FROM pg_catalog.pg_attribute AS attribute
       WHERE attribute.attrelid = 'public.dfir_timeline_events'::regclass
         AND attribute.attname = 'alert_id'
         AND NOT attribute.attnotnull
         AND NOT attribute.attisdropped
     )
     OR NOT EXISTS (
       SELECT 1
       FROM pg_catalog.pg_attribute AS attribute
       WHERE attribute.attrelid = 'public.dfir_timeline_events'::regclass
         AND attribute.attname = 'case_id'
         AND NOT attribute.attnotnull
         AND NOT attribute.attisdropped
     )
     OR NOT EXISTS (
       SELECT 1
       FROM pg_catalog.pg_constraint AS catalog_constraint
       WHERE catalog_constraint.conrelid = 'public.dfir_timeline_events'::regclass
         AND catalog_constraint.conname = 'dfir_timeline_events_subject_check'
         AND pg_catalog.pg_get_constraintdef(catalog_constraint.oid, true) =
           'CHECK (num_nonnulls(alert_id, case_id) = 1)'
     )
     OR NOT EXISTS (
       SELECT 1
       FROM pg_catalog.pg_constraint AS catalog_constraint
       WHERE catalog_constraint.conrelid = 'public.dfir_timeline_events'::regclass
         AND catalog_constraint.conname = 'dfir_timeline_events_alert_fk'
         AND catalog_constraint.contype = 'f'
     )
     OR to_regclass('public.dfir_timeline_events_alert_time_idx') IS NULL THEN
    RETURN false;
  END IF;

  IF NOT EXISTS (
       SELECT 1 FROM pg_catalog.pg_trigger AS trigger
       WHERE trigger.tgrelid =
           'public.alert_dfir_resource_commands'::regclass
         AND trigger.tgname = 'alert_dfir_resource_commands_immutable_v1'
         AND trigger.tgenabled = 'O' AND NOT trigger.tgisinternal
     )
     OR (SELECT count(*)
         FROM pg_catalog.pg_trigger AS trigger
         WHERE trigger.tgname IN (
           'dfir_timeline_ioc_links_alert_scope_v1',
           'dfir_timeline_asset_links_alert_scope_v1',
           'dfir_timeline_evidence_links_alert_scope_v1'
         ) AND trigger.tgenabled = 'O' AND NOT trigger.tgisinternal) <> 3 THEN
    RETURN false;
  END IF;

  FOREACH function_identity IN ARRAY ARRAY[
    'app.reserve_alert_dfir_resource_command_v1(uuid,uuid,text,uuid,bigint,bytea,bytea)',
    'app.append_alert_dfir_mutation_effects_v1(uuid,text,text,text,uuid,bigint,text,bytea,bytea,uuid,jsonb,jsonb,jsonb,uuid,uuid,uuid,uuid,inet,text,text)'
  ] LOOP
    IF to_regprocedure(function_identity) IS NULL
       OR NOT EXISTS (
         SELECT 1 FROM pg_catalog.pg_proc AS procedure
         WHERE procedure.oid = to_regprocedure(function_identity)
           AND procedure.prosecdef
           AND procedure.provolatile = 'v'
           AND procedure.proconfig =
             ARRAY['search_path=pg_catalog, public, app']::text[]
           AND pg_catalog.pg_get_userbyid(procedure.proowner) =
             'periapsis_migrator'
       )
       OR NOT has_function_privilege(
         'periapsis_api', function_identity, 'EXECUTE'
       )
       OR has_function_privilege(
         'periapsis_worker', function_identity, 'EXECUTE'
       )
       OR has_function_privilege(
         'periapsis_notifier', function_identity, 'EXECUTE'
       )
       OR has_function_privilege(
         'periapsis_auditor', function_identity, 'EXECUTE'
       )
       OR EXISTS (
         SELECT 1
         FROM pg_catalog.pg_proc AS procedure
         CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(
           procedure.proacl,
           pg_catalog.acldefault('f', procedure.proowner)
         )) AS privilege
         WHERE procedure.oid = to_regprocedure(function_identity)
           AND privilege.grantee = 0
           AND privilege.privilege_type = 'EXECUTE'
       ) THEN
      RETURN false;
    END IF;
  END LOOP;

  FOREACH function_identity IN ARRAY ARRAY[
    'app.private_current_alert_dfir_manage_scope_allows_v1(text,uuid)',
    'app.validate_alert_dfir_timeline_link_v1()'
  ] LOOP
    IF to_regprocedure(function_identity) IS NULL
       OR NOT EXISTS (
         SELECT 1 FROM pg_catalog.pg_proc AS procedure
         WHERE procedure.oid = to_regprocedure(function_identity)
           AND procedure.prosecdef
           AND pg_catalog.pg_get_userbyid(procedure.proowner) =
             'periapsis_migrator'
       )
       OR has_function_privilege(
         'periapsis_api', function_identity, 'EXECUTE'
       )
       OR has_function_privilege(
         'periapsis_worker', function_identity, 'EXECUTE'
       )
       OR has_function_privilege(
         'periapsis_notifier', function_identity, 'EXECUTE'
       )
       OR has_function_privilege(
         'periapsis_auditor', function_identity, 'EXECUTE'
       )
       OR EXISTS (
         SELECT 1
         FROM pg_catalog.pg_proc AS procedure
         CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(
           procedure.proacl,
           pg_catalog.acldefault('f', procedure.proowner)
         )) AS privilege
         WHERE procedure.oid = to_regprocedure(function_identity)
           AND privilege.grantee = 0
           AND privilege.privilege_type = 'EXECUTE'
       ) THEN
      RETURN false;
    END IF;
  END LOOP;

  RETURN position(
      'lock_current_tenant_authorization_state'
      IN pg_catalog.pg_get_functiondef(
        'app.reserve_alert_dfir_resource_command_v1(uuid,uuid,text,uuid,bigint,bytea,bytea)'::regprocedure
      )
    ) > 0
    AND position(
      'tenant_authorization_commands'
      IN pg_catalog.pg_get_functiondef(
        'app.append_alert_dfir_mutation_effects_v1(uuid,text,text,text,uuid,bigint,text,bytea,bytea,uuid,jsonb,jsonb,jsonb,uuid,uuid,uuid,uuid,inet,text,text)'::regprocedure
      )
    ) > 0
    AND position(
      'alert_dfir_resource_commands'
      IN pg_catalog.pg_get_functiondef(
        'app.append_alert_dfir_mutation_effects_v1(uuid,text,text,text,uuid,bigint,text,bytea,bytea,uuid,jsonb,jsonb,jsonb,uuid,uuid,uuid,uuid,inet,text,text)'::regprocedure
      )
    ) > 0
    AND position(
      'deleted_at IS NULL'
      IN pg_catalog.pg_get_functiondef(
        'app.append_alert_dfir_mutation_effects_v1(uuid,text,text,text,uuid,bigint,text,bytea,bytea,uuid,jsonb,jsonb,jsonb,uuid,uuid,uuid,uuid,inet,text,text)'::regprocedure
      )
    ) > 0;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.alert_dfir_runtime_schema_readiness_v1()
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.alert_dfir_runtime_schema_readiness_v1()
  FROM PUBLIC, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.alert_dfir_runtime_schema_readiness_v1()
  TO periapsis_api, periapsis_worker;
--> statement-breakpoint

COMMENT ON TABLE public.alert_dfir_resource_commands IS
  'Immutable tenant- and actor-bound idempotency receipts for Alert-scoped IOC, asset, and timeline mutations.';
COMMENT ON FUNCTION app.reserve_alert_dfir_resource_command_v1(
  uuid, uuid, text, uuid, bigint, bytea, bytea
) IS
  'Locks live Alert authority and reserves one payload-bound Alert DFIR result before application DML.';
COMMENT ON FUNCTION app.append_alert_dfir_mutation_effects_v1(
  uuid, text, text, text, uuid, bigint, text, bytea, bytea, uuid,
  jsonb, jsonb, jsonb, uuid, uuid, uuid, uuid, inet, text, text
) IS
  'Revalidates the exact Alert DFIR result and atomically appends redacted activity, audit, and outbox effects.';
COMMENT ON FUNCTION app.alert_dfir_runtime_schema_readiness_v1() IS
  'Attests Alert timeline root separation, immutable command receipts, ABI ownership, ACLs, RLS, guards, and live-Alert rechecks.';
