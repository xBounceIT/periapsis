ALTER TYPE "public"."notification_event_type" ADD VALUE 'alert.watcher_added' BEFORE 'case.created';--> statement-breakpoint
ALTER TYPE "public"."notification_event_type" ADD VALUE 'alert.watcher_removed' BEFORE 'case.created';--> statement-breakpoint
ALTER TYPE "public"."notification_event_type" ADD VALUE 'case.watcher_added' BEFORE 'comment.public_added';--> statement-breakpoint
ALTER TYPE "public"."notification_event_type" ADD VALUE 'case.watcher_removed' BEFORE 'comment.public_added';--> statement-breakpoint
CREATE TABLE "ticket_watcher_commands" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"alert_id" uuid,
	"case_id" uuid,
	"actor_membership_id" uuid NOT NULL,
	"actor_user_id" uuid NOT NULL,
	"target_user_id" uuid NOT NULL,
	"action" text NOT NULL,
	"key_digest" "bytea" NOT NULL,
	"request_digest" "bytea" NOT NULL,
	"result_version" integer NOT NULL,
	"result_updated_at" timestamp with time zone NOT NULL,
	"result_projection" jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "ticket_watcher_commands_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "ticket_watcher_commands_replay_key" UNIQUE("tenant_id","actor_membership_id","key_digest"),
	CONSTRAINT "ticket_watcher_commands_id_uuidv7_check" CHECK ((uuid_extract_version("ticket_watcher_commands"."id") = 7) is true),
	CONSTRAINT "ticket_watcher_commands_resource_check" CHECK (("ticket_watcher_commands"."alert_id" is null) <> ("ticket_watcher_commands"."case_id" is null)),
	CONSTRAINT "ticket_watcher_commands_action_check" CHECK ("ticket_watcher_commands"."action" in ('add','remove')),
	CONSTRAINT "ticket_watcher_commands_digest_check" CHECK (octet_length("ticket_watcher_commands"."key_digest") = 32
        and octet_length("ticket_watcher_commands"."request_digest") = 32),
	CONSTRAINT "ticket_watcher_commands_result_check" CHECK ("ticket_watcher_commands"."result_version" between 1 and 2147483647
        and "ticket_watcher_commands"."result_updated_at" <= "ticket_watcher_commands"."created_at"
        and jsonb_typeof("ticket_watcher_commands"."result_projection") = 'object'
        and octet_length("ticket_watcher_commands"."result_projection"::text) <= 1048576)
);
--> statement-breakpoint
ALTER TABLE "ticket_watcher_commands" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "ticket_watcher_events" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"alert_id" uuid,
	"case_id" uuid,
	"target_user_id" uuid NOT NULL,
	"action" text NOT NULL,
	"display_name_snapshot" text NOT NULL,
	"ticket_version" integer NOT NULL,
	"actor_membership_id" uuid NOT NULL,
	"actor_user_id" uuid NOT NULL,
	"occurred_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "ticket_watcher_events_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "ticket_watcher_events_id_uuidv7_check" CHECK ((uuid_extract_version("ticket_watcher_events"."id") = 7) is true),
	CONSTRAINT "ticket_watcher_events_resource_check" CHECK (("ticket_watcher_events"."alert_id" is null) <> ("ticket_watcher_events"."case_id" is null)),
	CONSTRAINT "ticket_watcher_events_action_check" CHECK ("ticket_watcher_events"."action" in ('add','remove')),
	CONSTRAINT "ticket_watcher_events_display_name_check" CHECK (btrim("ticket_watcher_events"."display_name_snapshot") <> ''
        and btrim("ticket_watcher_events"."display_name_snapshot") = "ticket_watcher_events"."display_name_snapshot"
        and char_length("ticket_watcher_events"."display_name_snapshot") <= 160
        and "ticket_watcher_events"."display_name_snapshot" !~ '[[:cntrl:]]'),
	CONSTRAINT "ticket_watcher_events_version_check" CHECK ("ticket_watcher_events"."ticket_version" between 2 and 2147483647)
);
--> statement-breakpoint
ALTER TABLE "ticket_watcher_events" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "ticket_watcher_commands" ADD CONSTRAINT "ticket_watcher_commands_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ticket_watcher_commands" ADD CONSTRAINT "ticket_watcher_commands_alert_fk" FOREIGN KEY ("tenant_id","alert_id") REFERENCES "public"."alerts"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "ticket_watcher_commands" ADD CONSTRAINT "ticket_watcher_commands_case_fk" FOREIGN KEY ("tenant_id","case_id") REFERENCES "public"."cases"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "ticket_watcher_commands" ADD CONSTRAINT "ticket_watcher_commands_actor_fk" FOREIGN KEY ("tenant_id","actor_membership_id","actor_user_id") REFERENCES "public"."tenant_memberships"("tenant_id","id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "ticket_watcher_commands" ADD CONSTRAINT "ticket_watcher_commands_target_membership_fk" FOREIGN KEY ("tenant_id","target_user_id") REFERENCES "public"."tenant_memberships"("tenant_id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "ticket_watcher_events" ADD CONSTRAINT "ticket_watcher_events_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ticket_watcher_events" ADD CONSTRAINT "ticket_watcher_events_alert_fk" FOREIGN KEY ("tenant_id","alert_id") REFERENCES "public"."alerts"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "ticket_watcher_events" ADD CONSTRAINT "ticket_watcher_events_case_fk" FOREIGN KEY ("tenant_id","case_id") REFERENCES "public"."cases"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "ticket_watcher_events" ADD CONSTRAINT "ticket_watcher_events_target_membership_fk" FOREIGN KEY ("tenant_id","target_user_id") REFERENCES "public"."tenant_memberships"("tenant_id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "ticket_watcher_events" ADD CONSTRAINT "ticket_watcher_events_actor_fk" FOREIGN KEY ("tenant_id","actor_membership_id","actor_user_id") REFERENCES "public"."tenant_memberships"("tenant_id","id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
CREATE INDEX "ticket_watcher_commands_ticket_idx" ON "ticket_watcher_commands" USING btree ("tenant_id","alert_id","case_id","created_at","id");--> statement-breakpoint
CREATE UNIQUE INDEX "ticket_watcher_events_alert_version_key" ON "ticket_watcher_events" USING btree ("tenant_id","alert_id","ticket_version") WHERE "ticket_watcher_events"."alert_id" is not null;--> statement-breakpoint
CREATE UNIQUE INDEX "ticket_watcher_events_case_version_key" ON "ticket_watcher_events" USING btree ("tenant_id","case_id","ticket_version") WHERE "ticket_watcher_events"."case_id" is not null;--> statement-breakpoint
CREATE INDEX "ticket_watcher_events_alert_target_history_idx" ON "ticket_watcher_events" USING btree ("tenant_id","alert_id","target_user_id","ticket_version");--> statement-breakpoint
CREATE INDEX "ticket_watcher_events_case_target_history_idx" ON "ticket_watcher_events" USING btree ("tenant_id","case_id","target_user_id","ticket_version");--> statement-breakpoint
CREATE POLICY "ticket_watcher_commands_owner_access" ON "ticket_watcher_commands" AS PERMISSIVE FOR ALL TO "periapsis_ticket_runtime_owner" USING (true) WITH CHECK (true);--> statement-breakpoint
CREATE POLICY "ticket_watcher_events_owner_access" ON "ticket_watcher_events" AS PERMISSIVE FOR ALL TO "periapsis_ticket_runtime_owner" USING (true) WITH CHECK (true);
--> statement-breakpoint

-- Watcher state is a tenant-owned temporal ledger. The inert runtime owner is
-- the only table owner, while all application traffic is constrained to the
-- closed SECURITY DEFINER entry points below.
ALTER TABLE public.ticket_watcher_events FORCE ROW LEVEL SECURITY;
ALTER TABLE public.ticket_watcher_commands FORCE ROW LEVEL SECURITY;
ALTER TABLE public.ticket_watcher_events OWNER TO periapsis_ticket_runtime_owner;
ALTER TABLE public.ticket_watcher_commands OWNER TO periapsis_ticket_runtime_owner;
REVOKE ALL ON TABLE public.ticket_watcher_events,
  public.ticket_watcher_commands
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner, periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT ALL ON TABLE public.ticket_watcher_events,
  public.ticket_watcher_commands TO periapsis_migrator;
--> statement-breakpoint

CREATE TRIGGER ticket_watcher_events_write_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.ticket_watcher_events
FOR EACH ROW EXECUTE FUNCTION app.guard_ticket_runtime_rows_v1('immutable');
CREATE TRIGGER ticket_watcher_commands_write_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.ticket_watcher_commands
FOR EACH ROW EXECUTE FUNCTION app.guard_ticket_runtime_rows_v1('immutable');
--> statement-breakpoint

-- Parameterized live authority is used both while admitting a watcher and at
-- notification planning time. It intentionally excludes the two customer
-- membership roles: the operator watcher concept is unrelated to a linked
-- customer contact whose portal role happens to be named watcher.
CREATE FUNCTION app.private_ticket_watcher_user_scope_allows_v1(
  p_tenant_id uuid,
  p_aggregate_kind public.ticket_aggregate_kind,
  p_ticket_id uuid,
  p_user_id uuid,
  p_operation text
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  WITH target AS (
    SELECT membership.id AS membership_id
    FROM public.tenant_memberships AS membership
    JOIN public.users AS identity ON identity.id=membership.user_id
    JOIN public.tenants AS tenant ON tenant.id=membership.tenant_id
    WHERE membership.tenant_id=p_tenant_id
      AND membership.user_id=p_user_id
      AND membership.status='active'
      AND membership.role NOT IN ('customer_manager','customer_user')
      AND identity.active AND tenant.status='active'
  ), ticket AS (
    SELECT alert.assigned_team_id, alert.assigned_team_epoch_id,
           alert.created_by AS owner_user_id, alert.assignee_user_id,
           alert.claimed_by_user_id
    FROM public.alerts AS alert
    WHERE p_aggregate_kind='alert'
      AND alert.tenant_id=p_tenant_id AND alert.id=p_ticket_id
      AND alert.deleted_at IS NULL
    UNION ALL
    SELECT case_row.assigned_team_id, case_row.assigned_team_epoch_id,
           case_row.created_by_user_id, case_row.assignee_user_id,
           case_row.claimed_by_user_id
    FROM public.cases AS case_row
    WHERE p_aggregate_kind='case'
      AND case_row.tenant_id=p_tenant_id AND case_row.id=p_ticket_id
  ), admitted AS (
    SELECT target.membership_id, ticket.*,
           p_aggregate_kind::text || '.' || p_operation AS permission_key
    FROM target CROSS JOIN ticket
    WHERE p_operation IN ('read','update')
  )
  SELECT EXISTS (
    SELECT 1
    FROM admitted
    WHERE app.tenant_human_has_exact_permission_v3(
            p_tenant_id,p_user_id,admitted.permission_key,'tenant'
          )
       OR app.tenant_human_has_exact_permission_v3(
            p_tenant_id,p_user_id,admitted.permission_key,'own'
          ) AND p_user_id IN (
            admitted.owner_user_id,admitted.assignee_user_id,
            admitted.claimed_by_user_id
          )
       OR app.tenant_human_has_exact_permission_v3(
            p_tenant_id,p_user_id,admitted.permission_key,'assigned'
          ) AND p_user_id IN (
            admitted.assignee_user_id,admitted.claimed_by_user_id
          )
       OR admitted.assigned_team_id IS NOT NULL
          AND admitted.assigned_team_epoch_id IS NOT NULL
          AND app.tenant_human_has_exact_permission_v3(
            p_tenant_id,p_user_id,admitted.permission_key,'operator_team'
          )
          AND EXISTS (
            SELECT 1
            FROM public.operator_team_assignment_epochs AS epoch
            JOIN public.operator_team_roster_entries AS roster
              ON roster.tenant_id=epoch.tenant_id
             AND roster.assignment_epoch_id=epoch.id
            JOIN public.tenant_authorization_sources AS source
              ON source.tenant_id=roster.tenant_id
             AND source.id=roster.source_id
            WHERE epoch.tenant_id=p_tenant_id
              AND epoch.id=admitted.assigned_team_epoch_id
              AND epoch.operator_team_id=admitted.assigned_team_id
              AND epoch.ended_at IS NULL
              AND roster.membership_id=admitted.membership_id
              AND roster.granted_at<=transaction_timestamp()
              AND roster.revoked_at IS NULL
              AND (roster.expires_at IS NULL
                OR roster.expires_at>transaction_timestamp())
              AND source.retired_at IS NULL
          )
  );
$function$;
ALTER FUNCTION app.private_ticket_watcher_user_scope_allows_v1(
  uuid,public.ticket_aggregate_kind,uuid,uuid,text
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_watcher_user_scope_allows_v1(
  uuid,public.ticket_aggregate_kind,uuid,uuid,text
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner;
GRANT EXECUTE ON FUNCTION app.private_ticket_watcher_user_scope_allows_v1(
  uuid,public.ticket_aggregate_kind,uuid,uuid,text
) TO periapsis_notification_dispatch_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_watcher_projection_v1(
  p_tenant_id uuid,
  p_aggregate_kind public.ticket_aggregate_kind,
  p_ticket_id uuid,
  p_version bigint,
  p_updated_at timestamp with time zone
)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
  WITH latest AS (
    SELECT DISTINCT ON (event.target_user_id)
           event.target_user_id,event.action,event.display_name_snapshot,
           event.occurred_at,event.ticket_version
    FROM public.ticket_watcher_events AS event
    WHERE event.tenant_id=p_tenant_id
      AND (p_aggregate_kind='alert' AND event.alert_id=p_ticket_id
        OR p_aggregate_kind='case' AND event.case_id=p_ticket_id)
      AND event.ticket_version<=p_version
    ORDER BY event.target_user_id,event.ticket_version DESC,event.id DESC
  ), watchers AS (
    SELECT latest.target_user_id,
           latest.display_name_snapshot AS display_name,
           latest.occurred_at
    FROM latest
    WHERE latest.action='add'
    ORDER BY latest.display_name_snapshot COLLATE "C",latest.target_user_id
  )
  SELECT jsonb_build_object(
    'schema_version',1,
    'tenant_id',p_tenant_id,
    'ticket_id',p_ticket_id,
    'aggregate_kind',p_aggregate_kind::text,
    'version',p_version,
    'updated_at',p_updated_at,
    'watchers',coalesce((
      SELECT jsonb_agg(jsonb_build_object(
        'user_id',watcher.target_user_id,
        'display_name',watcher.display_name,
        'added_at',watcher.occurred_at
      ) ORDER BY watcher.display_name COLLATE "C",watcher.target_user_id)
      FROM watchers AS watcher
    ),'[]'::jsonb)
  );
$function$;
ALTER FUNCTION app.private_ticket_watcher_projection_v1(
  uuid,public.ticket_aggregate_kind,uuid,bigint,timestamp with time zone
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_watcher_projection_v1(
  uuid,public.ticket_aggregate_kind,uuid,bigint,timestamp with time zone
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner,
  periapsis_notification_dispatch_owner;
--> statement-breakpoint

CREATE FUNCTION app.list_tenant_ticket_watchers_v1(
  p_aggregate_kind public.ticket_aggregate_kind,
  p_ticket_id uuid
)
RETURNS TABLE(
  result_version bigint,
  result_updated_at timestamp with time zone,
  result_projection jsonb
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
DECLARE
  context_tenant uuid:=app.context_tenant_id();
  actor_user uuid:=app.context_user_id();
  actor_membership uuid:=app.current_tenant_membership_id();
BEGIN
  IF p_ticket_id IS NULL OR uuid_extract_version(p_ticket_id)<>7 THEN
    RAISE EXCEPTION 'ticket watcher list input is invalid'
      USING ERRCODE='22023';
  END IF;
  PERFORM actor_membership;
  IF NOT app.private_ticket_watcher_user_scope_allows_v1(
    context_tenant,p_aggregate_kind,p_ticket_id,actor_user,'read'
  ) THEN
    RAISE EXCEPTION 'live operator ticket-read authority is required'
      USING ERRCODE='42501';
  END IF;
  IF p_aggregate_kind='alert' THEN
    SELECT alert.version::bigint,alert.updated_at
      INTO result_version,result_updated_at
    FROM public.alerts AS alert
    WHERE alert.tenant_id=context_tenant AND alert.id=p_ticket_id
      AND alert.deleted_at IS NULL;
  ELSE
    SELECT case_row.version::bigint,case_row.updated_at
      INTO result_version,result_updated_at
    FROM public.cases AS case_row
    WHERE case_row.tenant_id=context_tenant AND case_row.id=p_ticket_id;
  END IF;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'ticket is not available' USING ERRCODE='42501';
  END IF;
  result_projection:=app.private_ticket_watcher_projection_v1(
    context_tenant,p_aggregate_kind,p_ticket_id,
    result_version,result_updated_at
  );
  RETURN NEXT;
END;
$function$;
ALTER FUNCTION app.list_tenant_ticket_watchers_v1(
  public.ticket_aggregate_kind,uuid
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.list_tenant_ticket_watchers_v1(
  public.ticket_aggregate_kind,uuid
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor,
  periapsis_ticket_runtime_owner, periapsis_notification_dispatch_owner;
GRANT EXECUTE ON FUNCTION app.list_tenant_ticket_watchers_v1(
  public.ticket_aggregate_kind,uuid
) TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.mutate_tenant_ticket_watcher_v1(
  p_aggregate_kind public.ticket_aggregate_kind,
  p_ticket_id uuid,
  p_expected_version bigint,
  p_action text,
  p_target_user_id uuid,
  p_key_digest bytea,
  p_request_digest bytea,
  p_request_id uuid,
  p_correlation_id uuid,
  p_remote_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE(
  result_version bigint,
  result_updated_at timestamp with time zone,
  result_projection jsonb,
  replayed boolean
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
#variable_conflict use_variable
DECLARE
  context_tenant uuid:=app.context_tenant_id();
  actor_user uuid:=app.context_user_id();
  actor_membership uuid;
  command_record public.ticket_watcher_commands%ROWTYPE;
  current_version integer;
  current_updated_at timestamp with time zone;
  operation_at timestamp with time zone:=transaction_timestamp();
  prior_action text;
  prior_display_name text;
  target_display_name text;
  target_present boolean:=false;
  changed boolean:=false;
  watcher_count integer;
BEGIN
  IF p_ticket_id IS NULL OR uuid_extract_version(p_ticket_id)<>7
     OR p_expected_version NOT BETWEEN 1 AND 2147483646
     OR p_action NOT IN ('add','remove')
     OR p_target_user_id IS NULL OR uuid_extract_version(p_target_user_id)<>7
     OR p_key_digest IS NULL OR octet_length(p_key_digest)<>32
     OR p_key_digest=decode(repeat('00',32),'hex')
     OR p_request_digest IS NULL OR octet_length(p_request_digest)<>32
     OR p_request_digest=decode(repeat('00',32),'hex')
     OR p_request_id IS NULL OR uuid_extract_version(p_request_id)<>7
     OR p_correlation_id IS NULL OR uuid_extract_version(p_correlation_id)<>7
     OR p_remote_address IS NULL
     OR p_user_agent IS NULL OR btrim(p_user_agent)=''
     OR char_length(p_user_agent)>512 OR p_user_agent~'[[:cntrl:]]'
     OR p_authentication_method IS NULL
        OR p_authentication_method NOT IN (
          'bootstrap_totp','totp','recovery_code','ldap','oidc','saml','passkey'
        ) THEN
    RAISE EXCEPTION 'ticket watcher mutation input is invalid'
      USING ERRCODE='22023';
  END IF;

  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership:=app.current_tenant_membership_id();
  PERFORM pg_advisory_xact_lock(hashtextextended(
    context_tenant::text||':'||actor_membership::text
      ||':ticket.watcher:'||encode(p_key_digest,'hex'),0
  ));

  IF p_aggregate_kind='alert' THEN
    SELECT alert.version,alert.updated_at
      INTO current_version,current_updated_at
    FROM public.alerts AS alert
    WHERE alert.tenant_id=context_tenant AND alert.id=p_ticket_id
      AND alert.deleted_at IS NULL
    FOR UPDATE;
  ELSE
    SELECT case_row.version,case_row.updated_at
      INTO current_version,current_updated_at
    FROM public.cases AS case_row
    WHERE case_row.tenant_id=context_tenant AND case_row.id=p_ticket_id
    FOR UPDATE;
  END IF;
  IF NOT FOUND OR NOT app.private_ticket_watcher_user_scope_allows_v1(
    context_tenant,p_aggregate_kind,p_ticket_id,actor_user,'update'
  ) THEN
    RAISE EXCEPTION 'live operator ticket-update authority is required'
      USING ERRCODE='42501';
  END IF;

  SELECT command.* INTO command_record
  FROM public.ticket_watcher_commands AS command
  WHERE command.tenant_id=context_tenant
    AND command.actor_membership_id=actor_membership
    AND command.key_digest=p_key_digest;
  IF FOUND THEN
    IF command_record.actor_user_id<>actor_user
       OR command_record.action<>p_action
       OR command_record.target_user_id<>p_target_user_id
       OR command_record.request_digest<>p_request_digest
       OR (p_aggregate_kind='alert' AND (
         command_record.alert_id IS DISTINCT FROM p_ticket_id
         OR command_record.case_id IS NOT NULL
       )) OR (p_aggregate_kind='case' AND (
         command_record.case_id IS DISTINCT FROM p_ticket_id
         OR command_record.alert_id IS NOT NULL
       )) THEN
      RAISE EXCEPTION 'ticket watcher idempotency key conflicts'
        USING ERRCODE='23505',
          CONSTRAINT='ticket_watcher_commands_replay_key';
    END IF;
    result_version:=command_record.result_version::bigint;
    result_updated_at:=command_record.result_updated_at;
    result_projection:=command_record.result_projection;
    replayed:=true;
    RETURN NEXT;
    RETURN;
  END IF;

  IF current_version::bigint<>p_expected_version THEN
    RAISE EXCEPTION 'ticket watcher version conflict' USING ERRCODE='40001';
  END IF;

  SELECT event.action,event.display_name_snapshot
    INTO prior_action,prior_display_name
  FROM public.ticket_watcher_events AS event
  WHERE event.tenant_id=context_tenant
    AND event.target_user_id=p_target_user_id
    AND (p_aggregate_kind='alert' AND event.alert_id=p_ticket_id
      OR p_aggregate_kind='case' AND event.case_id=p_ticket_id)
  ORDER BY event.ticket_version DESC,event.id DESC
  LIMIT 1;
  target_present:=FOUND AND prior_action='add';
  changed:=p_action='add' AND NOT target_present
    OR p_action='remove' AND target_present;

  IF p_action='add' THEN
    IF NOT app.private_ticket_watcher_user_scope_allows_v1(
      context_tenant,p_aggregate_kind,p_ticket_id,p_target_user_id,'read'
    ) THEN
      RAISE EXCEPTION 'watcher target lacks live operator ticket-read authority'
        USING ERRCODE='42501';
    END IF;
    IF NOT target_present THEN
      SELECT profile.display_name INTO target_display_name
      FROM public.tenant_user_profiles AS profile
      WHERE profile.tenant_id=context_tenant
        AND profile.user_id=p_target_user_id;
      IF NOT FOUND THEN
        RAISE EXCEPTION 'watcher target profile is unavailable'
          USING ERRCODE='42501';
      END IF;
      SELECT count(*) INTO watcher_count
      FROM (
        SELECT DISTINCT ON (event.target_user_id) event.action
        FROM public.ticket_watcher_events AS event
        WHERE event.tenant_id=context_tenant
          AND (p_aggregate_kind='alert' AND event.alert_id=p_ticket_id
            OR p_aggregate_kind='case' AND event.case_id=p_ticket_id)
        ORDER BY event.target_user_id,event.ticket_version DESC,event.id DESC
      ) AS latest
      WHERE latest.action='add';
      IF watcher_count>=1000 THEN
        RAISE EXCEPTION 'ticket watcher cardinality limit exceeded'
          USING ERRCODE='54000';
      END IF;
    END IF;
  ELSIF p_action='remove' AND target_present THEN
    target_display_name:=prior_display_name;
  END IF;

  IF changed THEN
    result_version:=current_version::bigint+1;
    result_updated_at:=operation_at;
    PERFORM set_config('app.ticket_runtime_write_v1','enabled',true);
    IF p_aggregate_kind='alert' THEN
      UPDATE public.alerts AS alert SET
        version=result_version::integer,updated_at=result_updated_at
      WHERE alert.tenant_id=context_tenant AND alert.id=p_ticket_id
        AND alert.version=current_version AND alert.deleted_at IS NULL;
    ELSE
      UPDATE public.cases AS case_row SET
        version=result_version::integer,updated_at=result_updated_at
      WHERE case_row.tenant_id=context_tenant AND case_row.id=p_ticket_id
        AND case_row.version=current_version;
    END IF;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'ticket watcher mutation lost its version fence'
        USING ERRCODE='40001';
    END IF;
    INSERT INTO public.ticket_watcher_events(
      id,tenant_id,alert_id,case_id,target_user_id,action,
      display_name_snapshot,ticket_version,actor_membership_id,
      actor_user_id,occurred_at
    ) VALUES (
      uuidv7(),context_tenant,
      CASE WHEN p_aggregate_kind='alert' THEN p_ticket_id END,
      CASE WHEN p_aggregate_kind='case' THEN p_ticket_id END,
      p_target_user_id,p_action,target_display_name,result_version::integer,
      actor_membership,actor_user,result_updated_at
    );
    PERFORM app.private_append_ticket_side_effects_v1(
      p_aggregate_kind,p_ticket_id,
      CASE WHEN p_action='add' THEN 'watcher_added' ELSE 'watcher_removed' END,
      result_version::integer,ARRAY['activity','audit','notification']::text[],
      p_request_id,p_correlation_id,p_remote_address,p_user_agent,
      p_authentication_method,
      jsonb_build_object('target_user_id',p_target_user_id,'present',target_present),
      jsonb_build_object('target_user_id',p_target_user_id,'present',p_action='add'),
      jsonb_build_object(
        'target_user_id',p_target_user_id,
        'content_redacted',true
      )
    );
  ELSE
    result_version:=current_version::bigint;
    result_updated_at:=current_updated_at;
    PERFORM set_config('app.ticket_runtime_write_v1','enabled',true);
  END IF;

  result_projection:=app.private_ticket_watcher_projection_v1(
    context_tenant,p_aggregate_kind,p_ticket_id,
    result_version,result_updated_at
  );
  INSERT INTO public.ticket_watcher_commands(
    id,tenant_id,alert_id,case_id,actor_membership_id,actor_user_id,
    target_user_id,action,key_digest,request_digest,result_version,
    result_updated_at,result_projection,created_at
  ) VALUES (
    uuidv7(),context_tenant,
    CASE WHEN p_aggregate_kind='alert' THEN p_ticket_id END,
    CASE WHEN p_aggregate_kind='case' THEN p_ticket_id END,
    actor_membership,actor_user,p_target_user_id,p_action,p_key_digest,
    p_request_digest,result_version::integer,result_updated_at,
    result_projection,operation_at
  );
  replayed:=false;
  RETURN NEXT;
END;
$function$;
ALTER FUNCTION app.mutate_tenant_ticket_watcher_v1(
  public.ticket_aggregate_kind,uuid,bigint,text,uuid,bytea,bytea,uuid,uuid,
  inet,text,text
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.mutate_tenant_ticket_watcher_v1(
  public.ticket_aggregate_kind,uuid,bigint,text,uuid,bytea,bytea,uuid,uuid,
  inet,text,text
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor,
  periapsis_ticket_runtime_owner, periapsis_notification_dispatch_owner;
GRANT EXECUTE ON FUNCTION app.mutate_tenant_ticket_watcher_v1(
  public.ticket_aggregate_kind,uuid,bigint,text,uuid,bytea,bytea,uuid,uuid,
  inet,text,text
) TO periapsis_api;
--> statement-breakpoint

-- Extend the existing transactionally coupled ticket side-effect writer
-- without copying its large security envelope. The source hash binds this
-- forward repair to the sealed V45 predecessor.
DO $extend_ticket_watcher_notification_actions_v1$
DECLARE
  predecessor_definition text;
  predecessor_source_hash text;
  extended_definition text;
  old_mapping constant text :=
    $old$WHEN p_aggregate_kind = 'case' AND p_action = 'transitioned' THEN 'case.status_changed'::public.notification_event_type
      WHEN p_action = 'commented'$old$;
  new_mapping constant text :=
    $new$WHEN p_aggregate_kind = 'case' AND p_action = 'transitioned' THEN 'case.status_changed'::public.notification_event_type
      WHEN p_aggregate_kind = 'alert' AND p_action = 'watcher_added' THEN 'alert.watcher_added'::public.notification_event_type
      WHEN p_aggregate_kind = 'alert' AND p_action = 'watcher_removed' THEN 'alert.watcher_removed'::public.notification_event_type
      WHEN p_aggregate_kind = 'case' AND p_action = 'watcher_added' THEN 'case.watcher_added'::public.notification_event_type
      WHEN p_aggregate_kind = 'case' AND p_action = 'watcher_removed' THEN 'case.watcher_removed'::public.notification_event_type
      WHEN p_action = 'commented'$new$;
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex')
    INTO STRICT predecessor_definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_append_ticket_side_effects_v1(public.ticket_aggregate_kind,uuid,text,integer,text[],uuid,uuid,inet,text,text,jsonb,jsonb,jsonb)'::regprocedure;
  IF predecessor_source_hash<>
    'eb9920daf6c7fa6f814ba75bbefe21835ebef9bc4c764c377a5e79d0eba87b65'
     OR pg_catalog.strpos(predecessor_definition,old_mapping)=0 THEN
    RAISE EXCEPTION 'ticket side-effect writer drifted from sealed V45'
      USING ERRCODE='55000';
  END IF;
  extended_definition:=pg_catalog.replace(
    predecessor_definition,old_mapping,new_mapping
  );
  IF extended_definition IS NOT DISTINCT FROM predecessor_definition
     OR pg_catalog.strpos(extended_definition,'watcher_added')=0
     OR pg_catalog.strpos(extended_definition,'watcher_removed')=0 THEN
    RAISE EXCEPTION 'ticket watcher notification mapping extension failed'
      USING ERRCODE='55000';
  END IF;
  EXECUTE extended_definition;
END;
$extend_ticket_watcher_notification_actions_v1$;
ALTER FUNCTION app.private_append_ticket_side_effects_v1(
  public.ticket_aggregate_kind,uuid,text,integer,text[],uuid,uuid,inet,text,
  text,jsonb,jsonb,jsonb
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_append_ticket_side_effects_v1(
  public.ticket_aggregate_kind,uuid,text,integer,text[],uuid,uuid,inet,text,
  text,jsonb,jsonb,jsonb
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner,
  periapsis_notification_dispatch_owner;
--> statement-breakpoint

CREATE POLICY ticket_watcher_events_notification_dispatch_select
ON public.ticket_watcher_events
AS PERMISSIVE FOR SELECT TO periapsis_notification_dispatch_owner
USING (
  tenant_id=nullif(current_setting('app.tenant_id',true),'')::uuid
);
GRANT SELECT ON TABLE public.ticket_watcher_events
TO periapsis_notification_dispatch_owner;
--> statement-breakpoint

-- Recipient kind `watcher` is temporal and fail-closed. A candidate must have
-- been a watcher at the source event instant and aggregate version, must still
-- be a watcher when fanout is planned, and must retain a live active operator
-- identity plus exact ticket-read authority at planning time.
CREATE OR REPLACE FUNCTION app.private_notification_operator_candidates_v1(
  p_tenant_id uuid,
  p_event_id uuid
)
RETURNS TABLE(
  sort_email text,
  sort_principal uuid,
  sort_source text,
  value jsonb
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  WITH source AS (
    SELECT event.*,
      CASE event.aggregate_type
        WHEN 'alert' THEN 'alert.read'
        WHEN 'case' THEN 'case.read'
        WHEN 'contact' THEN 'contact.read'
      END AS read_permission
    FROM public.outbox_events AS event
    WHERE event.tenant_id=p_tenant_id AND event.id=p_event_id
  ), candidates AS (
    SELECT profile.email AS sort_email,
           identity.id AS sort_principal,
           'operator'::text AS sort_source,
           source.*,
           membership.id AS membership_id,
           relation.team_related,
           relation.watcher_related,
           capability.read_tenant,
           capability.read_own,
           capability.read_assigned,
           capability.read_team,
           identity.id::text=source.payload #>>
             '{operatorContext,routing,creatorUserId}' AS creator_related,
           identity.id::text=source.payload #>>
             '{operatorContext,routing,assigneeUserId}' AS assignee_related,
           identity.id::text=source.payload #>>
             '{operatorContext,routing,previousAssigneeUserId}'
             AS previous_assignee_related,
           source.actor_kind='human' AND identity.id=source.actor_id
             AS actor_related,
           app.private_notification_human_has_canonical_tenant_admin_v1(
             p_tenant_id,identity.id
           ) AS canonical_tenant_admin
    FROM source
    JOIN public.tenant_user_profiles AS profile
      ON profile.tenant_id=source.tenant_id AND profile.email IS NOT NULL
    JOIN public.tenant_memberships AS membership
      ON membership.tenant_id=profile.tenant_id
     AND membership.id=profile.membership_id
     AND membership.user_id=profile.user_id
     AND membership.status='active'
    JOIN public.users AS identity
      ON identity.id=profile.user_id AND identity.active
    CROSS JOIN LATERAL (
      SELECT EXISTS (
        SELECT 1
        FROM public.operator_team_roster_entries AS roster
        JOIN public.operator_team_assignment_epochs AS epoch
          ON epoch.tenant_id=roster.tenant_id
         AND epoch.id=roster.assignment_epoch_id
        JOIN public.tenant_authorization_sources AS authority_source
          ON authority_source.tenant_id=roster.tenant_id
         AND authority_source.id=roster.source_id
         AND authority_source.retired_at IS NULL
        WHERE roster.tenant_id=p_tenant_id
          AND roster.membership_id=membership.id
          AND epoch.operator_team_id::text=source.payload #>>
            '{operatorContext,routing,operatorTeamId}'
          AND roster.assignment_epoch_id::text=source.payload #>>
            '{operatorContext,routing,operatorTeamEpochId}'
          AND epoch.assigned_at<=source.occurred_at
          AND (epoch.ended_at IS NULL OR epoch.ended_at>source.occurred_at)
          AND (epoch.ended_at IS NULL
            OR epoch.ended_at>transaction_timestamp())
          AND roster.granted_at<=source.occurred_at
          AND (roster.expires_at IS NULL
            OR roster.expires_at>source.occurred_at)
          AND (roster.revoked_at IS NULL
            OR roster.revoked_at>source.occurred_at)
          AND roster.granted_at<=transaction_timestamp()
          AND (roster.expires_at IS NULL
            OR roster.expires_at>transaction_timestamp())
          AND (roster.revoked_at IS NULL
            OR roster.revoked_at>transaction_timestamp())
      ) AS team_related,
      source.aggregate_type IN ('alert','case')
      AND EXISTS (
        SELECT 1
        FROM LATERAL (
          SELECT event.action
          FROM public.ticket_watcher_events AS event
          WHERE event.tenant_id=p_tenant_id
            AND event.target_user_id=identity.id
            AND (source.aggregate_type='alert'
              AND event.alert_id=source.aggregate_id
              OR source.aggregate_type='case'
              AND event.case_id=source.aggregate_id)
            AND event.ticket_version<=source.aggregate_version
            AND (event.occurred_at<source.occurred_at
              OR event.occurred_at=source.occurred_at
                AND event.ticket_version<=source.aggregate_version)
          ORDER BY event.ticket_version DESC,event.id DESC
          LIMIT 1
        ) AS historical
        WHERE historical.action='add'
      )
      AND EXISTS (
        SELECT 1
        FROM LATERAL (
          SELECT event.action
          FROM public.ticket_watcher_events AS event
          WHERE event.tenant_id=p_tenant_id
            AND event.target_user_id=identity.id
            AND (source.aggregate_type='alert'
              AND event.alert_id=source.aggregate_id
              OR source.aggregate_type='case'
              AND event.case_id=source.aggregate_id)
          ORDER BY event.ticket_version DESC,event.id DESC
          LIMIT 1
        ) AS current_relation
        WHERE current_relation.action='add'
      )
      AND CASE WHEN source.aggregate_type IN ('alert','case') THEN
        app.private_ticket_watcher_user_scope_allows_v1(
          p_tenant_id,
          source.aggregate_type::public.ticket_aggregate_kind,
          source.aggregate_id,identity.id,'read'
        )
      ELSE false END AS watcher_related
    ) AS relation
    CROSS JOIN LATERAL (
      SELECT
        app.tenant_human_has_exact_permission_v3(
          p_tenant_id,identity.id,source.read_permission,'tenant'
        ) AS read_tenant,
        app.tenant_human_has_exact_permission_v3(
          p_tenant_id,identity.id,source.read_permission,'own'
        ) AS read_own,
        app.tenant_human_has_exact_permission_v3(
          p_tenant_id,identity.id,source.read_permission,'assigned'
        ) AS read_assigned,
        app.tenant_human_has_exact_permission_v3(
          p_tenant_id,identity.id,source.read_permission,'operator_team'
        ) AS read_team
    ) AS capability
    WHERE source.read_permission IS NOT NULL
  ), projected AS (
    SELECT candidate.*,
      candidate.actor_related AND (
        candidate.read_tenant
        OR candidate.creator_related AND candidate.read_own
        OR (candidate.assignee_related
          OR candidate.previous_assignee_related)
          AND candidate.read_assigned
        OR candidate.team_related AND candidate.read_team
      ) AS include_actor,
      candidate.assignee_related
        AND (candidate.read_tenant OR candidate.read_assigned)
        AS include_assignee,
      candidate.previous_assignee_related
        AND (candidate.read_tenant OR candidate.read_assigned)
        AS include_previous_assignee,
      candidate.team_related
        AND (candidate.read_tenant OR candidate.read_team)
        AS include_team,
      candidate.watcher_related AS include_watcher,
      candidate.canonical_tenant_admin AND candidate.read_tenant
        AS include_tenant_admin
    FROM candidates AS candidate
  ), shaped AS (
    SELECT projected.*,
      (CASE WHEN include_actor
        THEN jsonb_build_array('actor') ELSE '[]'::jsonb END)
      || (CASE WHEN include_assignee
        THEN jsonb_build_array('assignee') ELSE '[]'::jsonb END)
      || (CASE WHEN include_previous_assignee
        THEN jsonb_build_array('previous_assignee') ELSE '[]'::jsonb END)
      || (CASE WHEN include_team
        THEN jsonb_build_array('operator_team') ELSE '[]'::jsonb END)
      || (CASE WHEN include_watcher
        THEN jsonb_build_array('watcher') ELSE '[]'::jsonb END)
      || (CASE WHEN include_tenant_admin
        THEN jsonb_build_array('tenant_admin') ELSE '[]'::jsonb END)
      AS kinds
    FROM projected
  )
  SELECT shaped.sort_email,shaped.sort_principal,shaped.sort_source,
         jsonb_build_object(
           'tenantId',p_tenant_id,
           'email',shaped.sort_email,
           'audience','operator',
           'kinds',shaped.kinds,
           'values',CASE WHEN shaped.include_team THEN jsonb_build_object(
             'operator_team',jsonb_build_array(
               shaped.payload #>>
                 '{operatorContext,routing,operatorTeamId}'
             )
           ) ELSE '{}'::jsonb END,
           'principalId',shaped.sort_principal,
           'enabled',true,
           'emailAllowed',true
         ) AS value
  FROM shaped
  WHERE jsonb_array_length(shaped.kinds)>0;
$function$;
ALTER FUNCTION app.private_notification_operator_candidates_v1(uuid,uuid)
  OWNER TO periapsis_notification_dispatch_owner;
REVOKE ALL ON FUNCTION app.private_notification_operator_candidates_v1(
  uuid,uuid
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner;
--> statement-breakpoint

CREATE FUNCTION app.ticket_watcher_runtime_schema_readiness_v1()
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
  relation_name text;
  function_definition text;
BEGIN
  FOREACH relation_name IN ARRAY ARRAY[
    'ticket_watcher_events','ticket_watcher_commands'
  ] LOOP
    IF NOT EXISTS (
      SELECT 1
      FROM pg_catalog.pg_class AS relation
      JOIN pg_catalog.pg_namespace AS namespace
        ON namespace.oid=relation.relnamespace
      WHERE namespace.nspname='public'
        AND relation.relname=relation_name
        AND relation.relkind='r'
        AND relation.relrowsecurity AND relation.relforcerowsecurity
        AND pg_catalog.pg_get_userbyid(relation.relowner)=
          'periapsis_ticket_runtime_owner'
    ) OR NOT EXISTS (
      SELECT 1
      FROM pg_catalog.pg_attribute AS attribute
      WHERE attribute.attrelid=format('public.%I',relation_name)::regclass
        AND attribute.attname='tenant_id' AND attribute.attnotnull
        AND NOT attribute.attisdropped
    ) OR EXISTS (
      SELECT 1
      FROM (VALUES
        ('periapsis_api'),('periapsis_worker'),('periapsis_notifier'),
        ('periapsis_auditor'),('periapsis_audit_reader_owner'),
        ('periapsis_sla_api_owner'),('periapsis_sla_worker_owner'),
        ('periapsis_sla_readiness_owner'),
        ('periapsis_ticket_saved_view_owner'),
        ('periapsis_ticket_attribution_owner'),
        ('periapsis_ticket_sla_projection_owner')
      ) AS denied_role(name)
      WHERE has_table_privilege(
        denied_role.name,format('public.%I',relation_name),
        'SELECT,INSERT,UPDATE,DELETE'
      )
    ) THEN
      RETURN false;
    END IF;
  END LOOP;

  IF NOT has_table_privilege(
       'periapsis_notification_dispatch_owner',
       'public.ticket_watcher_events','SELECT'
     ) OR has_table_privilege(
       'periapsis_notification_dispatch_owner',
       'public.ticket_watcher_events',
       'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN'
     ) OR has_table_privilege(
       'periapsis_notification_dispatch_owner',
       'public.ticket_watcher_commands',
       'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN'
     ) OR (SELECT count(*) FROM pg_catalog.pg_trigger AS trigger
       WHERE trigger.tgname IN (
         'ticket_watcher_events_write_guard_v1',
         'ticket_watcher_commands_write_guard_v1'
       ) AND trigger.tgfoid=
           'app.guard_ticket_runtime_rows_v1()'::regprocedure
         AND trigger.tgtype=31 AND trigger.tgenabled='O'
         AND NOT trigger.tgisinternal)<>2
     OR NOT EXISTS (
       SELECT 1 FROM pg_catalog.pg_policy AS policy
       WHERE policy.polrelid='public.ticket_watcher_events'::regclass
         AND policy.polname='ticket_watcher_events_notification_dispatch_select'
         AND policy.polcmd='r'
     ) THEN
    RETURN false;
  END IF;

  IF EXISTS (
    SELECT 1
    FROM (VALUES
      ('app.private_ticket_watcher_user_scope_allows_v1(uuid,public.ticket_aggregate_kind,uuid,uuid,text)',
       '7842a9f8f3f50a3909709f40549f6293cbf84d386ffb6ce561579ef444d12f7e',
       'periapsis_migrator','s',
       ARRAY['search_path=pg_catalog, public, app']::text[],
       ARRAY['periapsis_migrator','periapsis_notification_dispatch_owner']::text[]),
      ('app.private_ticket_watcher_projection_v1(uuid,public.ticket_aggregate_kind,uuid,bigint,timestamp with time zone)',
       'c507f05d8c548c1993b87ff6487d03de809892acd997e6557d02fd8b393dc7ed',
       'periapsis_migrator','s',
       ARRAY['search_path=pg_catalog, public, app','TimeZone=UTC']::text[],
       ARRAY['periapsis_migrator']::text[]),
      ('app.list_tenant_ticket_watchers_v1(public.ticket_aggregate_kind,uuid)',
       '9050a227d21895fa59d4487c3a268c947bc8c551f3ef95364b191fa5c95df125',
       'periapsis_migrator','s',
       ARRAY['search_path=pg_catalog, public, app','TimeZone=UTC']::text[],
       ARRAY['periapsis_migrator','periapsis_api']::text[]),
      ('app.mutate_tenant_ticket_watcher_v1(public.ticket_aggregate_kind,uuid,bigint,text,uuid,bytea,bytea,uuid,uuid,inet,text,text)',
       'e7f410d552464b701ebee3c4f5f5fa800768198821eb2ab0f411088bdb61fbbd',
       'periapsis_migrator','v',
       ARRAY['search_path=pg_catalog, public, app','TimeZone=UTC']::text[],
       ARRAY['periapsis_migrator','periapsis_api']::text[]),
      ('app.private_notification_operator_candidates_v1(uuid,uuid)',
       '7578ee7692d7d08ab7b4dac54857737ee4da052bef7ee1d346892f06e8d08c8b',
       'periapsis_notification_dispatch_owner','s',
       ARRAY['search_path=pg_catalog, public, app']::text[],
       ARRAY['periapsis_notification_dispatch_owner']::text[]),
      ('app.private_append_ticket_side_effects_v1(public.ticket_aggregate_kind,uuid,text,integer,text[],uuid,uuid,inet,text,text,jsonb,jsonb,jsonb)',
       '594cc458c667a63a9beb29663545c64608038b78cd4740087743fabce1be22de',
       'periapsis_migrator','v',
       ARRAY['search_path=pg_catalog, public, app']::text[],
       ARRAY['periapsis_migrator']::text[])
    ) AS expected(
      identity,source_hash,owner_name,volatility,configuration,execute_roles
    )
    LEFT JOIN pg_catalog.pg_proc AS procedure
      ON procedure.oid=pg_catalog.to_regprocedure(expected.identity)
    LEFT JOIN pg_catalog.pg_roles AS owner
      ON owner.oid=procedure.proowner
    WHERE procedure.oid IS NULL OR owner.rolname<>expected.owner_name
       OR NOT procedure.prosecdef
       OR procedure.provolatile::text<>expected.volatility
       OR procedure.proconfig IS DISTINCT FROM expected.configuration
       OR pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
            procedure.prosrc,'UTF8'
          )),'hex')<>expected.source_hash
       OR (
         SELECT count(*)<>pg_catalog.cardinality(expected.execute_roles)
            OR NOT coalesce(bool_and(
              privilege.grantor=procedure.proowner
              AND CASE WHEN privilege.grantee=0 THEN 'PUBLIC'
                    ELSE pg_catalog.pg_get_userbyid(privilege.grantee) END
                  =ANY(expected.execute_roles)
              AND privilege.privilege_type='EXECUTE'
              AND NOT privilege.is_grantable
            ),false)
         FROM pg_catalog.aclexplode(coalesce(
           procedure.proacl,
           pg_catalog.acldefault('f',procedure.proowner)
         )) AS privilege
       )
  ) THEN
    RETURN false;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_proc AS procedure
    WHERE procedure.oid=
      'app.list_tenant_ticket_watchers_v1(public.ticket_aggregate_kind,uuid)'::regprocedure
      AND procedure.proargnames[3:5]=ARRAY[
        'result_version','result_updated_at','result_projection'
      ]::text[]
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_proc AS procedure
    WHERE procedure.oid=
      'app.mutate_tenant_ticket_watcher_v1(public.ticket_aggregate_kind,uuid,bigint,text,uuid,bytea,bytea,uuid,uuid,inet,text,text)'::regprocedure
      AND procedure.proargnames[13:16]=ARRAY[
        'result_version','result_updated_at','result_projection','replayed'
      ]::text[]
  ) THEN
    RETURN false;
  END IF;

  SELECT pg_catalog.pg_get_functiondef(procedure.oid)
    INTO STRICT function_definition
  FROM pg_catalog.pg_proc AS procedure
  WHERE procedure.oid=
    'app.mutate_tenant_ticket_watcher_v1(public.ticket_aggregate_kind,uuid,bigint,text,uuid,bytea,bytea,uuid,uuid,inet,text,text)'::regprocedure;
  IF function_definition NOT LIKE '%watcher_count>=1000%'
     OR function_definition NOT LIKE '%ticket_runtime_write_v1%'
     OR function_definition NOT LIKE '%private_append_ticket_side_effects_v1%'
     OR function_definition NOT LIKE '%IF p_action=''add'' THEN%'
     OR function_definition NOT LIKE '%ticket_watcher_commands_replay_key%' THEN
    RETURN false;
  END IF;
  SELECT pg_catalog.pg_get_functiondef(procedure.oid)
    INTO STRICT function_definition
  FROM pg_catalog.pg_proc AS procedure
  WHERE procedure.oid=
    'app.private_ticket_watcher_projection_v1(uuid,public.ticket_aggregate_kind,uuid,bigint,timestamp with time zone)'::regprocedure;
  IF function_definition NOT LIKE '%schema_version%'
     OR function_definition NOT LIKE '%display_name%COLLATE "C"%'
     OR function_definition NOT LIKE '%latest.display_name_snapshot%'
     OR function_definition LIKE '%tenant_user_profiles%'
     OR function_definition NOT LIKE '%target_user_id%' THEN
    RETURN false;
  END IF;
  SELECT pg_catalog.pg_get_functiondef(procedure.oid)
    INTO STRICT function_definition
  FROM pg_catalog.pg_proc AS procedure
  WHERE procedure.oid=
    'app.private_notification_operator_candidates_v1(uuid,uuid)'::regprocedure;
  IF function_definition NOT LIKE '%watcher_related%'
     OR function_definition NOT LIKE '%historical.action%add%'
     OR function_definition NOT LIKE '%current_relation.action%add%'
     OR function_definition NOT LIKE
       '%JOIN public.tenant_authorization_sources AS authority_source%'
     OR function_definition NOT LIKE
       '%authority_source.retired_at IS NULL%'
     OR function_definition NOT LIKE
       '%private_ticket_watcher_user_scope_allows_v1%' THEN
    RETURN false;
  END IF;
  SELECT pg_catalog.pg_get_functiondef(procedure.oid)
    INTO STRICT function_definition
  FROM pg_catalog.pg_proc AS procedure
  WHERE procedure.oid=
    'app.private_append_ticket_side_effects_v1(public.ticket_aggregate_kind,uuid,text,integer,text[],uuid,uuid,inet,text,text,jsonb,jsonb,jsonb)'::regprocedure;
  RETURN function_definition LIKE '%alert.watcher_added%'
    AND function_definition LIKE '%alert.watcher_removed%'
    AND function_definition LIKE '%case.watcher_added%'
    AND function_definition LIKE '%case.watcher_removed%'
    AND EXISTS (
      SELECT 1 FROM pg_catalog.pg_enum AS enum_value
      JOIN pg_catalog.pg_type AS enum_type
        ON enum_type.oid=enum_value.enumtypid
      JOIN pg_catalog.pg_namespace AS namespace
        ON namespace.oid=enum_type.typnamespace
      WHERE namespace.nspname='public'
        AND enum_type.typname='notification_event_type'
        AND enum_value.enumlabel IN (
          'alert.watcher_added','alert.watcher_removed',
          'case.watcher_added','case.watcher_removed'
        )
      HAVING count(*)=4
    );
END;
$function$;
ALTER FUNCTION app.ticket_watcher_runtime_schema_readiness_v1()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.ticket_watcher_runtime_schema_readiness_v1()
FROM PUBLIC, periapsis_notifier, periapsis_auditor,
  periapsis_ticket_runtime_owner, periapsis_notification_dispatch_owner;
GRANT EXECUTE ON FUNCTION app.ticket_watcher_runtime_schema_readiness_v1()
TO periapsis_api,periapsis_worker;
--> statement-breakpoint

COMMENT ON TABLE public.ticket_watcher_events IS
  'Immutable tenant-owned operator watcher history; latest action is live state and event-time history is retained for notification planning.';
COMMENT ON TABLE public.ticket_watcher_commands IS
  'Immutable exact watcher command results keyed across operations for durable idempotent replay.';
COMMENT ON FUNCTION app.ticket_watcher_runtime_schema_readiness_v1() IS
  'Attests V46 watcher ABI shape, forced RLS, closed DML and EXECUTE, temporal fanout, projection ordering, and side-effect mappings.';
