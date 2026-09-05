CREATE TABLE "sla_trigger_action_executions" (
	"tenant_id" uuid NOT NULL,
	"occurrence_id" uuid NOT NULL,
	"status" "sla_job_status" DEFAULT 'queued' NOT NULL,
	"available_at" timestamp with time zone NOT NULL,
	"attempt" integer DEFAULT 0 NOT NULL,
	"maximum_attempts" integer DEFAULT 8 NOT NULL,
	"worker_id" uuid,
	"lease_expires_at" timestamp with time zone,
	"fence" bigint DEFAULT 0 NOT NULL,
	"last_failure_code" text,
	"completed_at" timestamp with time zone,
	"dead_lettered_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "sla_trigger_action_executions_pkey" PRIMARY KEY("tenant_id","occurrence_id"),
	CONSTRAINT "sla_trigger_action_executions_bounds_check" CHECK ("sla_trigger_action_executions"."attempt" between 0 and 65535
        and "sla_trigger_action_executions"."maximum_attempts" between 1 and 65535
        and "sla_trigger_action_executions"."attempt" <= "sla_trigger_action_executions"."maximum_attempts"
        and "sla_trigger_action_executions"."fence" between 0 and 9223372036854775806
        and ("sla_trigger_action_executions"."worker_id" is null
          or (uuid_extract_version("sla_trigger_action_executions"."worker_id") = 7) is true)
        and ("sla_trigger_action_executions"."last_failure_code" is null
          or "sla_trigger_action_executions"."last_failure_code" ~ '^[a-z][a-z0-9_.-]{0,127}$')),
	CONSTRAINT "sla_trigger_action_executions_state_check" CHECK (("sla_trigger_action_executions"."status" = 'leased'
          and "sla_trigger_action_executions"."worker_id" is not null
          and "sla_trigger_action_executions"."lease_expires_at" is not null
          and "sla_trigger_action_executions"."attempt" > 0
          and "sla_trigger_action_executions"."fence" > 0
          and "sla_trigger_action_executions"."completed_at" is null
          and "sla_trigger_action_executions"."dead_lettered_at" is null)
        or ("sla_trigger_action_executions"."status" in ('queued', 'retry_scheduled')
          and "sla_trigger_action_executions"."worker_id" is null
          and "sla_trigger_action_executions"."lease_expires_at" is null
          and "sla_trigger_action_executions"."completed_at" is null
          and "sla_trigger_action_executions"."dead_lettered_at" is null)
        or ("sla_trigger_action_executions"."status" = 'completed'
          and "sla_trigger_action_executions"."worker_id" is null
          and "sla_trigger_action_executions"."lease_expires_at" is null
          and "sla_trigger_action_executions"."completed_at" is not null
          and "sla_trigger_action_executions"."dead_lettered_at" is null)
        or ("sla_trigger_action_executions"."status" = 'dead_lettered'
          and "sla_trigger_action_executions"."worker_id" is null
          and "sla_trigger_action_executions"."lease_expires_at" is null
          and "sla_trigger_action_executions"."completed_at" is null
          and "sla_trigger_action_executions"."dead_lettered_at" is not null)),
	CONSTRAINT "sla_trigger_action_executions_timestamps_check" CHECK ("sla_trigger_action_executions"."available_at" >= "sla_trigger_action_executions"."created_at"
        and "sla_trigger_action_executions"."updated_at" >= "sla_trigger_action_executions"."created_at"
        and ("sla_trigger_action_executions"."lease_expires_at" is null
          or "sla_trigger_action_executions"."lease_expires_at" > "sla_trigger_action_executions"."updated_at")
        and ("sla_trigger_action_executions"."completed_at" is null
          or "sla_trigger_action_executions"."completed_at" between "sla_trigger_action_executions"."created_at" and "sla_trigger_action_executions"."updated_at")
        and ("sla_trigger_action_executions"."dead_lettered_at" is null
          or "sla_trigger_action_executions"."dead_lettered_at" between "sla_trigger_action_executions"."created_at" and "sla_trigger_action_executions"."updated_at"))
);
--> statement-breakpoint
ALTER TABLE "sla_trigger_action_executions" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "sla_trigger_action_receipts" (
	"tenant_id" uuid NOT NULL,
	"occurrence_id" uuid NOT NULL,
	"worker_id" uuid NOT NULL,
	"action_kind" "sla_trigger_action_kind" NOT NULL,
	"deduplication_digest" "bytea" NOT NULL,
	"fence" bigint NOT NULL,
	"effect_kind" text NOT NULL,
	"effect_id" uuid,
	"effect_version" bigint,
	"effect_digest" "bytea" NOT NULL,
	"applied_at" timestamp with time zone NOT NULL,
	CONSTRAINT "sla_trigger_action_receipts_pkey" PRIMARY KEY("tenant_id","occurrence_id"),
	CONSTRAINT "sla_trigger_action_receipts_identity_check" CHECK ((uuid_extract_version("sla_trigger_action_receipts"."worker_id") = 7) is true
        and "sla_trigger_action_receipts"."fence" between 1 and 9223372036854775806
        and "sla_trigger_action_receipts"."effect_kind" ~ '^[a-z][a-z0-9_.-]{0,127}$'
        and ("sla_trigger_action_receipts"."effect_id" is null
          or (uuid_extract_version("sla_trigger_action_receipts"."effect_id") = 7) is true)
        and ("sla_trigger_action_receipts"."effect_version" is null
          or "sla_trigger_action_receipts"."effect_version" between 1 and 9223372036854775807)
        and octet_length("sla_trigger_action_receipts"."deduplication_digest") = 32
        and octet_length("sla_trigger_action_receipts"."effect_digest") = 32)
);
--> statement-breakpoint
ALTER TABLE "sla_trigger_action_receipts" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "dfir_tasks" ALTER COLUMN "created_by_membership_id" DROP NOT NULL;--> statement-breakpoint
ALTER TABLE "dfir_tasks" ALTER COLUMN "updated_by_membership_id" DROP NOT NULL;--> statement-breakpoint
ALTER TABLE "dfir_tasks" ADD COLUMN "created_by_service_account_id" uuid;--> statement-breakpoint
ALTER TABLE "dfir_tasks" ADD COLUMN "updated_by_service_account_id" uuid;--> statement-breakpoint
ALTER TABLE "sla_trigger_action_executions" ADD CONSTRAINT "sla_trigger_action_executions_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_trigger_action_executions" ADD CONSTRAINT "sla_trigger_action_executions_occurrence_fk" FOREIGN KEY ("tenant_id","occurrence_id") REFERENCES "public"."sla_trigger_occurrences"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_trigger_action_receipts" ADD CONSTRAINT "sla_trigger_action_receipts_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_trigger_action_receipts" ADD CONSTRAINT "sla_trigger_action_receipts_occurrence_fk" FOREIGN KEY ("tenant_id","occurrence_id") REFERENCES "public"."sla_trigger_occurrences"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "sla_trigger_action_executions_queue_idx" ON "sla_trigger_action_executions" USING btree ("tenant_id","status","available_at","lease_expires_at","occurrence_id");--> statement-breakpoint
CREATE INDEX "sla_trigger_action_executions_metrics_idx" ON "sla_trigger_action_executions" USING btree ("status","available_at","created_at");--> statement-breakpoint
ALTER TABLE "dfir_tasks" ADD CONSTRAINT "dfir_tasks_creator_service_account_fk" FOREIGN KEY ("tenant_id","created_by_service_account_id") REFERENCES "public"."tenant_service_accounts"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_tasks" ADD CONSTRAINT "dfir_tasks_updater_service_account_fk" FOREIGN KEY ("tenant_id","updated_by_service_account_id") REFERENCES "public"."tenant_service_accounts"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_tasks" ADD CONSTRAINT "dfir_tasks_attribution_check" CHECK (("dfir_tasks"."created_by_membership_id" is null) <>
            ("dfir_tasks"."created_by_service_account_id" is null)
        and ("dfir_tasks"."updated_by_membership_id" is null) <>
            ("dfir_tasks"."updated_by_service_account_id" is null));--> statement-breakpoint
CREATE POLICY "sla_trigger_action_executions_worker_tenant" ON "sla_trigger_action_executions" AS PERMISSIVE FOR ALL TO "periapsis_worker" USING ("sla_trigger_action_executions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
      and app.tenant_is_active_v1("sla_trigger_action_executions"."tenant_id")) WITH CHECK ("sla_trigger_action_executions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
      and app.tenant_is_active_v1("sla_trigger_action_executions"."tenant_id"));--> statement-breakpoint
CREATE POLICY "sla_trigger_action_receipts_worker_tenant" ON "sla_trigger_action_receipts" AS PERMISSIVE FOR ALL TO "periapsis_worker" USING ("sla_trigger_action_receipts"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
      and app.tenant_is_active_v1("sla_trigger_action_receipts"."tenant_id")) WITH CHECK ("sla_trigger_action_receipts"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
      and app.tenant_is_active_v1("sla_trigger_action_receipts"."tenant_id"));
--> statement-breakpoint

-- SLA trigger occurrences are immutable facts. Lease, retry, fence and
-- terminal state live in a separate mutable table; successful effects receive
-- one append-only receipt keyed by the occurrence.
ALTER TABLE public.sla_trigger_action_executions
  OWNER TO periapsis_migrator;
--> statement-breakpoint
ALTER TABLE public.sla_trigger_action_receipts
  OWNER TO periapsis_migrator;
--> statement-breakpoint
ALTER TABLE public.sla_trigger_action_executions FORCE ROW LEVEL SECURITY;
--> statement-breakpoint
ALTER TABLE public.sla_trigger_action_receipts FORCE ROW LEVEL SECURITY;
--> statement-breakpoint
REVOKE ALL ON TABLE public.sla_trigger_action_executions,
  public.sla_trigger_action_receipts
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor;
--> statement-breakpoint
GRANT SELECT, INSERT, UPDATE ON TABLE public.sla_trigger_action_executions
TO periapsis_sla_worker_owner;
--> statement-breakpoint
GRANT SELECT, INSERT ON TABLE public.sla_trigger_action_receipts
TO periapsis_sla_worker_owner;
--> statement-breakpoint
CREATE POLICY sla_trigger_action_executions_owner_v1
ON public.sla_trigger_action_executions AS PERMISSIVE FOR ALL
TO periapsis_sla_worker_owner USING (true) WITH CHECK (true);
--> statement-breakpoint
CREATE POLICY sla_trigger_action_receipts_owner_v1
ON public.sla_trigger_action_receipts AS PERMISSIVE FOR ALL
TO periapsis_sla_worker_owner USING (true) WITH CHECK (true);
--> statement-breakpoint
CREATE TRIGGER sla_trigger_action_receipts_immutable_v1
BEFORE UPDATE OR DELETE ON public.sla_trigger_action_receipts
FOR EACH ROW EXECUTE FUNCTION app.guard_sla_append_only_v1();
--> statement-breakpoint

COMMENT ON TABLE public.sla_trigger_action_executions IS
  'Mutable worker lease, fence, retry and terminal state for immutable SLA trigger occurrences.';
--> statement-breakpoint
COMMENT ON TABLE public.sla_trigger_action_receipts IS
  'Append-only exactly-once receipts for committed SLA trigger action effects; contains no notification content.';
--> statement-breakpoint

CREATE FUNCTION app.private_seed_sla_trigger_action_execution_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
BEGIN
  INSERT INTO public.sla_trigger_action_executions (
    tenant_id, occurrence_id, status, available_at, attempt,
    maximum_attempts, fence, created_at, updated_at
  ) VALUES (
    NEW.tenant_id, NEW.id, 'queued', greatest(NEW.scheduled_at, NEW.created_at),
    0, 8, 0, NEW.created_at, NEW.created_at
  );
  RETURN NEW;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_seed_sla_trigger_action_execution_v1()
  OWNER TO periapsis_sla_worker_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_seed_sla_trigger_action_execution_v1()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_sla_api_owner,
  periapsis_sla_readiness_owner;
--> statement-breakpoint
CREATE TRIGGER sla_trigger_occurrences_seed_action_v1
AFTER INSERT ON public.sla_trigger_occurrences
FOR EACH ROW EXECUTE FUNCTION app.private_seed_sla_trigger_action_execution_v1();
--> statement-breakpoint
INSERT INTO public.sla_trigger_action_executions (
  tenant_id, occurrence_id, status, available_at, attempt,
  maximum_attempts, fence, created_at, updated_at
)
SELECT occurrence.tenant_id, occurrence.id, 'queued',
       greatest(occurrence.scheduled_at, occurrence.created_at),
       0, 8, 0, occurrence.created_at, occurrence.created_at
FROM public.sla_trigger_occurrences AS occurrence
ON CONFLICT (tenant_id, occurrence_id) DO NOTHING;
--> statement-breakpoint

-- The definer owns no broad role membership. Explicit grants and tenant-bound
-- RLS policies are the complete action surface needed by the implementation.
GRANT SELECT, INSERT, UPDATE ON TABLE public.alerts, public.cases,
  public.dfir_tasks, public.ticket_activities
TO periapsis_sla_worker_owner;
--> statement-breakpoint
GRANT SELECT ON TABLE public.tenant_service_accounts,
  public.ticket_workflows, public.ticket_workflow_versions,
  public.operator_teams, public.operator_team_assignment_epochs,
  public.tenant_notification_smtp_configurations,
  public.tenant_notification_webhook_configurations,
  public.sla_instances, public.sla_metric_instances,
  public.sla_trigger_definitions, public.sla_trigger_occurrences
TO periapsis_sla_worker_owner;
--> statement-breakpoint
GRANT SELECT, INSERT ON TABLE public.outbox_events, public.audit_events
TO periapsis_sla_worker_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.private_next_ticket_number_v1(
  uuid, public.ticket_aggregate_kind, timestamp with time zone
) TO periapsis_sla_worker_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.tenant_is_active_v1(uuid)
TO periapsis_sla_worker_owner;
--> statement-breakpoint

CREATE POLICY alerts_sla_action_owner_v1
ON public.alerts AS PERMISSIVE FOR ALL TO periapsis_sla_worker_owner
USING (tenant_id = app.context_tenant_id() AND deleted_at IS NULL)
WITH CHECK (tenant_id = app.context_tenant_id() AND deleted_at IS NULL);
--> statement-breakpoint
CREATE POLICY cases_sla_action_owner_v1
ON public.cases AS PERMISSIVE FOR ALL TO periapsis_sla_worker_owner
USING (tenant_id = app.context_tenant_id())
WITH CHECK (tenant_id = app.context_tenant_id());
--> statement-breakpoint
CREATE POLICY dfir_tasks_sla_action_owner_v1
ON public.dfir_tasks AS PERMISSIVE FOR ALL TO periapsis_sla_worker_owner
USING (tenant_id = app.context_tenant_id())
WITH CHECK (tenant_id = app.context_tenant_id());
--> statement-breakpoint
CREATE POLICY ticket_activities_sla_action_owner_v1
ON public.ticket_activities AS PERMISSIVE FOR ALL TO periapsis_sla_worker_owner
USING (tenant_id = app.context_tenant_id())
WITH CHECK (tenant_id = app.context_tenant_id());
--> statement-breakpoint
CREATE POLICY tenant_service_accounts_sla_action_owner_v1
ON public.tenant_service_accounts AS PERMISSIVE FOR SELECT
TO periapsis_sla_worker_owner
USING (tenant_id = app.context_tenant_id() AND archived_at IS NULL);
--> statement-breakpoint
CREATE POLICY ticket_workflows_sla_action_owner_v1
ON public.ticket_workflows AS PERMISSIVE FOR SELECT
TO periapsis_sla_worker_owner
USING (tenant_id = app.context_tenant_id() AND archived_at IS NULL);
--> statement-breakpoint
CREATE POLICY ticket_workflow_versions_sla_action_owner_v1
ON public.ticket_workflow_versions AS PERMISSIVE FOR SELECT
TO periapsis_sla_worker_owner
USING (tenant_id = app.context_tenant_id());
--> statement-breakpoint
CREATE POLICY operator_teams_sla_action_owner_v1
ON public.operator_teams AS PERMISSIVE FOR SELECT
TO periapsis_sla_worker_owner USING (archived_at IS NULL);
--> statement-breakpoint
CREATE POLICY operator_team_epochs_sla_action_owner_v1
ON public.operator_team_assignment_epochs AS PERMISSIVE FOR SELECT
TO periapsis_sla_worker_owner
USING (tenant_id = app.context_tenant_id() AND ended_at IS NULL);
--> statement-breakpoint
CREATE POLICY tenant_smtp_sla_action_owner_v1
ON public.tenant_notification_smtp_configurations AS PERMISSIVE FOR SELECT
TO periapsis_sla_worker_owner
USING (tenant_id = app.context_tenant_id() AND revoked_at IS NULL);
--> statement-breakpoint
CREATE POLICY tenant_webhook_sla_action_owner_v1
ON public.tenant_notification_webhook_configurations AS PERMISSIVE FOR SELECT
TO periapsis_sla_worker_owner
USING (tenant_id = app.context_tenant_id() AND revoked_at IS NULL);
--> statement-breakpoint
CREATE POLICY outbox_events_sla_action_owner_v1
ON public.outbox_events AS PERMISSIVE FOR ALL TO periapsis_sla_worker_owner
USING (
  tenant_id = app.context_tenant_id()
  AND (event_type LIKE 'sla.%'
    OR event_type IN ('notification.sla.warning', 'notification.sla.breached'))
)
WITH CHECK (
  tenant_id = app.context_tenant_id()
  AND (event_type LIKE 'sla.%'
    OR event_type IN ('notification.sla.warning', 'notification.sla.breached'))
);
--> statement-breakpoint
CREATE POLICY audit_events_sla_action_owner_v1
ON public.audit_events AS PERMISSIVE FOR INSERT TO periapsis_sla_worker_owner
WITH CHECK (
  tenant_id = app.context_tenant_id()
  AND actor_type = 'system'
  AND action LIKE 'tenant.sla.action.%'
);
--> statement-breakpoint

CREATE FUNCTION app.private_append_sla_action_audit_v1(
  p_tenant_id uuid,
  p_occurrence_id uuid,
  p_action text,
  p_occurred_at timestamp with time zone,
  p_metadata jsonb
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_tenant_id IS NULL OR p_occurrence_id IS NULL
     OR p_tenant_id IS DISTINCT FROM app.context_tenant_id()
     OR p_action NOT IN ('executed', 'dead_lettered')
     OR p_occurred_at IS NULL
     OR jsonb_typeof(p_metadata) <> 'object'
     OR pg_column_size(p_metadata) > 16384 THEN
    RAISE EXCEPTION 'SLA action audit input is invalid'
      USING ERRCODE = '22023';
  END IF;
  INSERT INTO public.audit_events (
    id, tenant_id, sequence, occurred_at, actor_type, action,
    resource_type, resource_id, authentication_method, outcome,
    before, after, metadata
  ) VALUES (
    uuidv7(), p_tenant_id, 0, p_occurred_at, 'system',
    'tenant.sla.action.' || p_action, 'sla_trigger_occurrence',
    p_occurrence_id, 'system',
    CASE WHEN p_action = 'executed' THEN 'success' ELSE 'failure' END,
    NULL, NULL, p_metadata || jsonb_build_object('contentRedacted', true)
  );
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_append_sla_action_audit_v1(
  uuid, uuid, text, timestamp with time zone, jsonb
) OWNER TO periapsis_sla_worker_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_append_sla_action_audit_v1(
  uuid, uuid, text, timestamp with time zone, jsonb
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_sla_api_owner,
  periapsis_sla_readiness_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_append_sla_action_activity_v1(
  p_tenant_id uuid,
  p_object_type public.sla_object_type,
  p_object_id uuid,
  p_occurrence_id uuid,
  p_action_kind public.sla_trigger_action_kind,
  p_occurred_at timestamp with time zone,
  p_effect_id uuid,
  p_effect_version bigint
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE next_sequence integer;
BEGIN
  IF p_tenant_id IS NULL OR p_tenant_id IS DISTINCT FROM app.context_tenant_id()
     OR p_object_id IS NULL OR p_occurrence_id IS NULL
     OR p_object_type NOT IN ('alert', 'case')
     OR p_action_kind IS NULL OR p_occurred_at IS NULL
     OR p_effect_version IS NOT NULL
       AND p_effect_version NOT BETWEEN 1 AND 9223372036854775807 THEN
    RAISE EXCEPTION 'SLA action activity input is invalid'
      USING ERRCODE = '22023';
  END IF;
  SELECT coalesce(max(activity.sequence), 0) + 1
  INTO next_sequence
  FROM public.ticket_activities AS activity
  WHERE activity.tenant_id = p_tenant_id
    AND (p_object_type = 'alert' AND activity.alert_id = p_object_id
      OR p_object_type = 'case' AND activity.case_id = p_object_id);
  IF next_sequence NOT BETWEEN 1 AND 2147483647 THEN
    RAISE EXCEPTION 'SLA action activity sequence is exhausted'
      USING ERRCODE = '54000';
  END IF;
  INSERT INTO public.ticket_activities (
    id, tenant_id, alert_id, case_id, sequence, kind, summary,
    actor_principal_kind, origin, details, occurred_at
  ) VALUES (
    uuidv7(), p_tenant_id,
    CASE WHEN p_object_type = 'alert' THEN p_object_id END,
    CASE WHEN p_object_type = 'case' THEN p_object_id END,
    next_sequence, 'sla.action.executed', 'SLA action executed',
    'system', 'system', jsonb_build_object(
      'occurrenceId', p_occurrence_id,
      'actionKind', p_action_kind,
      'effectId', p_effect_id,
      'effectVersion', p_effect_version,
      'contentRedacted', true
    ), p_occurred_at
  );
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_append_sla_action_activity_v1(
  uuid, public.sla_object_type, uuid, uuid,
  public.sla_trigger_action_kind, timestamp with time zone, uuid, bigint
) OWNER TO periapsis_sla_worker_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_append_sla_action_activity_v1(
  uuid, public.sla_object_type, uuid, uuid,
  public.sla_trigger_action_kind, timestamp with time zone, uuid, bigint
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_sla_api_owner,
  periapsis_sla_readiness_owner;
--> statement-breakpoint

CREATE FUNCTION app.list_sla_trigger_action_queues_v1(
  p_observed_at timestamp with time zone,
  p_limit integer
)
RETURNS TABLE(tenant_id uuid)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
BEGIN
  IF p_observed_at IS NULL OR p_limit NOT BETWEEN 1 AND 500 THEN
    RAISE EXCEPTION 'SLA action queue request is invalid'
      USING ERRCODE = '22023';
  END IF;
  RETURN QUERY
  SELECT execution.tenant_id
  FROM public.sla_trigger_action_executions AS execution
  WHERE app.tenant_is_active_v1(execution.tenant_id)
    AND execution.attempt < execution.maximum_attempts
    AND (execution.status IN ('queued', 'retry_scheduled')
          AND execution.available_at <= p_observed_at
      OR execution.status = 'leased'
          AND execution.lease_expires_at <= p_observed_at)
  GROUP BY execution.tenant_id
  ORDER BY min(execution.available_at), execution.tenant_id
  LIMIT p_limit;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.list_sla_trigger_action_queues_v1(
  timestamp with time zone, integer
) OWNER TO periapsis_sla_worker_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.list_sla_trigger_action_queues_v1(
  timestamp with time zone, integer
) FROM PUBLIC, periapsis_api, periapsis_notifier, periapsis_auditor,
  periapsis_sla_api_owner, periapsis_sla_readiness_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.list_sla_trigger_action_queues_v1(
  timestamp with time zone, integer
) TO periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.claim_sla_trigger_actions_v1(
  p_worker_id uuid,
  p_tenant_id uuid,
  p_now timestamp with time zone,
  p_limit integer,
  p_lease_micros bigint
)
RETURNS TABLE(
  occurrence_id uuid,
  tenant_id uuid,
  sla_instance_id uuid,
  metric_instance_id uuid,
  trigger_definition_id uuid,
  action_kind public.sla_trigger_action_kind,
  deduplication_digest bytea,
  fence bigint,
  attempt integer,
  scheduled_at timestamp with time zone,
  claimed_at timestamp with time zone,
  lease_expires_at timestamp with time zone
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_worker_id IS NULL
     OR (uuid_extract_version(p_worker_id) = 7) IS NOT TRUE
     OR p_tenant_id IS NULL
     OR (uuid_extract_version(p_tenant_id) = 7) IS NOT TRUE
     OR p_now IS NULL OR p_limit NOT BETWEEN 1 AND 100
     OR p_lease_micros NOT BETWEEN 30000000 AND 900000000 THEN
    RAISE EXCEPTION 'SLA action claim request is invalid'
      USING ERRCODE = '22023';
  END IF;
  IF NOT app.tenant_is_active_v1(p_tenant_id) THEN
    RETURN;
  END IF;
  PERFORM set_config('app.tenant_id', p_tenant_id::text, true);
  RETURN QUERY
  WITH candidate AS (
    SELECT execution.tenant_id, execution.occurrence_id
    FROM public.sla_trigger_action_executions AS execution
    JOIN public.sla_trigger_occurrences AS occurrence
      ON occurrence.tenant_id = execution.tenant_id
     AND occurrence.id = execution.occurrence_id
    WHERE execution.tenant_id = p_tenant_id
      AND execution.attempt < execution.maximum_attempts
      AND (execution.status IN ('queued', 'retry_scheduled')
            AND execution.available_at <= p_now
        OR execution.status = 'leased'
            AND execution.lease_expires_at <= p_now)
    ORDER BY occurrence.scheduled_at, execution.occurrence_id
    FOR UPDATE OF execution SKIP LOCKED
    LIMIT p_limit
  ), claimed AS (
    UPDATE public.sla_trigger_action_executions AS execution
    SET status = 'leased', worker_id = p_worker_id,
        lease_expires_at = p_now
          + p_lease_micros * interval '1 microsecond',
        fence = execution.fence + 1,
        attempt = execution.attempt + 1,
        updated_at = p_now
    FROM candidate
    WHERE execution.tenant_id = candidate.tenant_id
      AND execution.occurrence_id = candidate.occurrence_id
      AND execution.fence < 9223372036854775806
    RETURNING execution.*
  )
  SELECT occurrence.id, occurrence.tenant_id, occurrence.sla_instance_id,
         occurrence.metric_instance_id, occurrence.trigger_definition_id,
         occurrence.action_kind, occurrence.deduplication_digest,
         claimed.fence, claimed.attempt, occurrence.scheduled_at,
         claimed.updated_at, claimed.lease_expires_at
  FROM claimed
  JOIN public.sla_trigger_occurrences AS occurrence
    ON occurrence.tenant_id = claimed.tenant_id
   AND occurrence.id = claimed.occurrence_id
  ORDER BY occurrence.scheduled_at, occurrence.id;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.claim_sla_trigger_actions_v1(
  uuid, uuid, timestamp with time zone, integer, bigint
) OWNER TO periapsis_sla_worker_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.claim_sla_trigger_actions_v1(
  uuid, uuid, timestamp with time zone, integer, bigint
) FROM PUBLIC, periapsis_api, periapsis_notifier, periapsis_auditor,
  periapsis_sla_api_owner, periapsis_sla_readiness_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.claim_sla_trigger_actions_v1(
  uuid, uuid, timestamp with time zone, integer, bigint
) TO periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.execute_sla_trigger_action_v1(
  p_worker_id uuid,
  p_tenant_id uuid,
  p_occurrence_id uuid,
  p_fence bigint,
  p_deduplication_digest bytea,
  p_action_kind public.sla_trigger_action_kind,
  p_applied_at timestamp with time zone
)
RETURNS text
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  execution public.sla_trigger_action_executions%ROWTYPE;
  occurrence public.sla_trigger_occurrences%ROWTYPE;
  instance public.sla_instances%ROWTYPE;
  metric public.sla_metric_instances%ROWTYPE;
  definition public.sla_trigger_definitions%ROWTYPE;
  prior_receipt public.sla_trigger_action_receipts%ROWTYPE;
  runtime_account_id uuid;
  default_workflow_id uuid;
  default_workflow_version integer;
  default_workflow_state text;
  team_epoch_id uuid;
  effect_id uuid;
  effect_version bigint;
  effect_kind text;
  effect_digest bytea;
  event_id uuid;
  notification_event text;
  source_version bigint;
  changed_rows integer;
  failure_code text;
  failure_detail text;
  permanent_failure boolean := false;
  action_applied boolean := false;
  retry_delay_seconds integer;
BEGIN
  IF p_worker_id IS NULL
     OR (uuid_extract_version(p_worker_id) = 7) IS NOT TRUE
     OR p_tenant_id IS NULL
     OR (uuid_extract_version(p_tenant_id) = 7) IS NOT TRUE
     OR p_occurrence_id IS NULL
     OR (uuid_extract_version(p_occurrence_id) = 7) IS NOT TRUE
     OR p_fence NOT BETWEEN 1 AND 9223372036854775806
     OR p_deduplication_digest IS NULL
     OR octet_length(p_deduplication_digest) <> 32
     OR p_action_kind IS NULL OR p_applied_at IS NULL THEN
    RAISE EXCEPTION 'SLA action execution request is invalid'
      USING ERRCODE = '22023';
  END IF;
  PERFORM set_config('app.tenant_id', p_tenant_id::text, true);

  SELECT receipt.* INTO prior_receipt
  FROM public.sla_trigger_action_receipts AS receipt
  WHERE receipt.tenant_id = p_tenant_id
    AND receipt.occurrence_id = p_occurrence_id;
  IF FOUND THEN
    IF prior_receipt.worker_id = p_worker_id
       AND prior_receipt.fence = p_fence
       AND prior_receipt.action_kind = p_action_kind
       AND prior_receipt.deduplication_digest = p_deduplication_digest THEN
      RETURN 'replayed';
    END IF;
    RETURN 'fence_lost';
  END IF;

  SELECT execution_row.* INTO execution
  FROM public.sla_trigger_action_executions AS execution_row
  WHERE execution_row.tenant_id = p_tenant_id
    AND execution_row.occurrence_id = p_occurrence_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RETURN 'fence_lost';
  END IF;
  SELECT occurrence_row.* INTO occurrence
  FROM public.sla_trigger_occurrences AS occurrence_row
  WHERE occurrence_row.tenant_id = execution.tenant_id
    AND occurrence_row.id = execution.occurrence_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RETURN 'fence_lost';
  END IF;
  SELECT instance_row.* INTO instance
  FROM public.sla_instances AS instance_row
  WHERE instance_row.tenant_id = occurrence.tenant_id
    AND instance_row.id = occurrence.sla_instance_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RETURN 'fence_lost';
  END IF;
  SELECT metric_row.* INTO metric
  FROM public.sla_metric_instances AS metric_row
  WHERE metric_row.tenant_id = occurrence.tenant_id
    AND metric_row.id = occurrence.metric_instance_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RETURN 'fence_lost';
  END IF;
  SELECT definition_row.* INTO definition
  FROM public.sla_trigger_definitions AS definition_row
  WHERE definition_row.tenant_id = occurrence.tenant_id
    AND definition_row.id = occurrence.trigger_definition_id
  FOR SHARE;
  IF NOT FOUND THEN
    RETURN 'fence_lost';
  END IF;

  IF execution.status <> 'leased'
     OR execution.worker_id IS DISTINCT FROM p_worker_id
     OR execution.fence IS DISTINCT FROM p_fence
     OR execution.lease_expires_at < p_applied_at
     OR execution.updated_at > p_applied_at
     OR occurrence.deduplication_digest IS DISTINCT FROM
          p_deduplication_digest
     OR occurrence.action_kind IS DISTINCT FROM p_action_kind
     OR definition.action_kind IS DISTINCT FROM occurrence.action_kind
     OR definition.action_configuration_id IS DISTINCT FROM
          occurrence.action_configuration_id
     OR definition.action_value IS DISTINCT FROM occurrence.action_value
     OR definition.allow_recursive_sla IS DISTINCT FROM
          occurrence.allow_recursive_sla THEN
    RETURN 'fence_lost';
  END IF;

  BEGIN
    -- Lock the exact source aggregate before every side effect. This serializes
    -- activity sequencing and prevents an action from committing against a
    -- deleted/replaced ticket snapshot.
    IF instance.object_type = 'alert' THEN
      SELECT alert.version::bigint INTO source_version
      FROM public.alerts AS alert
      WHERE alert.tenant_id = p_tenant_id
        AND alert.id = instance.object_id
        AND alert.deleted_at IS NULL
      FOR UPDATE;
    ELSIF instance.object_type = 'case' THEN
      SELECT case_row.version::bigint INTO source_version
      FROM public.cases AS case_row
      WHERE case_row.tenant_id = p_tenant_id
        AND case_row.id = instance.object_id
      FOR UPDATE;
    ELSE
      SELECT task.version INTO source_version
      FROM public.dfir_tasks AS task
      WHERE task.tenant_id = p_tenant_id
        AND task.id = instance.object_id
      FOR UPDATE;
    END IF;
    IF source_version IS NULL THEN
      RAISE EXCEPTION 'SLA action source is unavailable'
        USING ERRCODE = 'P1001', DETAIL = 'target_unavailable';
    END IF;

    IF p_action_kind IN ('email', 'webhook') THEN
      IF p_action_kind = 'email' AND NOT EXISTS (
        SELECT 1
        FROM public.tenant_notification_smtp_configurations AS configuration
        WHERE configuration.tenant_id = p_tenant_id
          AND configuration.id = occurrence.action_configuration_id
          AND configuration.revoked_at IS NULL
        FOR SHARE
      ) OR p_action_kind = 'webhook' AND NOT EXISTS (
        SELECT 1
        FROM public.tenant_notification_webhook_configurations AS configuration
        WHERE configuration.tenant_id = p_tenant_id
          AND configuration.id = occurrence.action_configuration_id
          AND configuration.revoked_at IS NULL
        FOR SHARE
      ) THEN
        RAISE EXCEPTION 'SLA notification configuration is unavailable'
          USING ERRCODE = 'P1002', DETAIL = 'configuration_unavailable';
      END IF;
      notification_event := CASE
        WHEN metric.state = 'breached'
          OR definition.kind IN ('due', 'after_breach', 'repeated_after_breach')
          THEN 'notification.sla.breached'
        ELSE 'notification.sla.warning'
      END;
      event_id := uuidv7();
      INSERT INTO public.outbox_events (
        id, tenant_id, aggregate_type, aggregate_id, aggregate_version,
        event_type, schema_version, payload, deduplication_key,
        actor_kind, producer, maximum_audience, traceparent, tracestate,
        occurred_at, available_at
      ) VALUES (
        event_id, p_tenant_id, instance.object_type::text,
        instance.object_id, instance.aggregate_version,
        notification_event, 2,
        jsonb_build_object('operatorContext', jsonb_build_object(
          'slaInstanceId', instance.id,
          'metricInstanceId', metric.id,
          'triggerOccurrenceId', occurrence.id,
          'actionKind', occurrence.action_kind,
          'configurationId', occurrence.action_configuration_id,
          'contentRedacted', true
        )), 'sla:action:' || occurrence.id::text || ':notification',
        'system', 'sla-action', 'operator',
        nullif(current_setting('app.traceparent', true), ''),
        nullif(current_setting('app.tracestate', true), ''),
        p_applied_at, p_applied_at
      );
      effect_id := event_id;
      effect_version := 1;
      effect_kind := 'notification';

    ELSIF p_action_kind = 'add_tag' THEN
      IF occurrence.action_value IS NULL
         OR occurrence.action_value !~ '^[a-z][a-z0-9_.-]{0,62}[a-z0-9]$' THEN
        RAISE EXCEPTION 'SLA tag action is malformed'
          USING ERRCODE = 'P1001', DETAIL = 'invalid_action_configuration';
      END IF;
      IF instance.object_type = 'alert' THEN
        UPDATE public.alerts AS alert
        SET tags = ARRAY(
              SELECT DISTINCT tag
              FROM unnest(alert.tags || occurrence.action_value) AS tag
              ORDER BY tag
            ), version = alert.version + 1, updated_at = p_applied_at
        WHERE alert.tenant_id = p_tenant_id AND alert.id = instance.object_id
          AND NOT occurrence.action_value = ANY(alert.tags)
          AND cardinality(alert.tags) < 100
          AND alert.version < 2147483647;
        GET DIAGNOSTICS changed_rows = ROW_COUNT;
        IF changed_rows = 1 THEN
          source_version := source_version + 1;
        ELSIF NOT EXISTS (
          SELECT 1 FROM public.alerts AS alert
          WHERE alert.tenant_id = p_tenant_id
            AND alert.id = instance.object_id
            AND occurrence.action_value = ANY(alert.tags)
        ) THEN
          RAISE EXCEPTION 'SLA tag target cannot accept another tag'
            USING ERRCODE = 'P1001', DETAIL = 'target_capacity_exhausted';
        END IF;
      ELSIF instance.object_type = 'case' THEN
        UPDATE public.cases AS case_row
        SET tags = ARRAY(
              SELECT DISTINCT tag
              FROM unnest(case_row.tags || occurrence.action_value) AS tag
              ORDER BY tag
            ), version = case_row.version + 1, updated_at = p_applied_at
        WHERE case_row.tenant_id = p_tenant_id
          AND case_row.id = instance.object_id
          AND NOT occurrence.action_value = ANY(case_row.tags)
          AND cardinality(case_row.tags) < 100
          AND case_row.version < 2147483647;
        GET DIAGNOSTICS changed_rows = ROW_COUNT;
        IF changed_rows = 1 THEN
          source_version := source_version + 1;
        ELSIF NOT EXISTS (
          SELECT 1 FROM public.cases AS case_row
          WHERE case_row.tenant_id = p_tenant_id
            AND case_row.id = instance.object_id
            AND occurrence.action_value = ANY(case_row.tags)
        ) THEN
          RAISE EXCEPTION 'SLA tag target cannot accept another tag'
            USING ERRCODE = 'P1001', DETAIL = 'target_capacity_exhausted';
        END IF;
      ELSE
        RAISE EXCEPTION 'SLA tag target is unsupported'
          USING ERRCODE = 'P1001', DETAIL = 'unsupported_target_kind';
      END IF;
      effect_id := instance.object_id;
      effect_version := source_version;
      effect_kind := 'ticket_tag';

    ELSIF p_action_kind = 'change_priority' THEN
      IF occurrence.action_value IS NULL
         OR occurrence.action_value !~ '^[a-z][a-z0-9_.-]{0,62}[a-z0-9]$' THEN
        RAISE EXCEPTION 'SLA priority action is malformed'
          USING ERRCODE = 'P1001', DETAIL = 'invalid_action_configuration';
      END IF;
      IF instance.object_type = 'alert' THEN
        UPDATE public.alerts AS alert
        SET priority = occurrence.action_value,
            version = alert.version + 1, updated_at = p_applied_at
        WHERE alert.tenant_id = p_tenant_id AND alert.id = instance.object_id
          AND alert.priority IS DISTINCT FROM occurrence.action_value
          AND alert.version < 2147483647;
        GET DIAGNOSTICS changed_rows = ROW_COUNT;
        IF changed_rows = 0 AND NOT EXISTS (
          SELECT 1 FROM public.alerts AS alert
          WHERE alert.tenant_id = p_tenant_id
            AND alert.id = instance.object_id
            AND alert.priority = occurrence.action_value
        ) THEN
          RAISE EXCEPTION 'SLA priority target revision is exhausted'
            USING ERRCODE = 'P1001', DETAIL = 'target_revision_exhausted';
        END IF;
      ELSIF instance.object_type = 'case' THEN
        UPDATE public.cases AS case_row
        SET priority = occurrence.action_value,
            version = case_row.version + 1, updated_at = p_applied_at
        WHERE case_row.tenant_id = p_tenant_id
          AND case_row.id = instance.object_id
          AND case_row.priority IS DISTINCT FROM occurrence.action_value
          AND case_row.version < 2147483647;
        GET DIAGNOSTICS changed_rows = ROW_COUNT;
        IF changed_rows = 0 AND NOT EXISTS (
          SELECT 1 FROM public.cases AS case_row
          WHERE case_row.tenant_id = p_tenant_id
            AND case_row.id = instance.object_id
            AND case_row.priority = occurrence.action_value
        ) THEN
          RAISE EXCEPTION 'SLA priority target revision is exhausted'
            USING ERRCODE = 'P1001', DETAIL = 'target_revision_exhausted';
        END IF;
      ELSE
        IF occurrence.action_value NOT IN ('low', 'medium', 'high', 'critical') THEN
          RAISE EXCEPTION 'SLA task priority is invalid'
            USING ERRCODE = 'P1001', DETAIL = 'invalid_action_configuration';
        END IF;
        UPDATE public.dfir_tasks AS task
        SET priority = occurrence.action_value::public.dfir_task_priority,
            updated_by_membership_id = NULL,
            updated_by_service_account_id = (
              SELECT account.id FROM public.tenant_service_accounts AS account
              WHERE account.tenant_id = p_tenant_id
                AND account.key = 'sla_action_runtime'
                AND account.system_owned
                AND account.archived_at IS NULL
            ),
            version = task.version + 1, updated_at = p_applied_at
        WHERE task.tenant_id = p_tenant_id AND task.id = instance.object_id
          AND task.priority IS DISTINCT FROM
            occurrence.action_value::public.dfir_task_priority
          AND task.version < 9223372036854775807;
        GET DIAGNOSTICS changed_rows = ROW_COUNT;
        IF changed_rows = 0 AND NOT EXISTS (
          SELECT 1 FROM public.tenant_service_accounts AS account
          WHERE account.tenant_id = p_tenant_id
            AND account.key = 'sla_action_runtime'
            AND account.system_owned
            AND account.archived_at IS NULL
        ) THEN
          RAISE EXCEPTION 'SLA runtime account is unavailable'
            USING ERRCODE = 'P1002', DETAIL = 'runtime_identity_unavailable';
        ELSIF changed_rows = 0 AND NOT EXISTS (
          SELECT 1 FROM public.dfir_tasks AS task
          WHERE task.tenant_id = p_tenant_id
            AND task.id = instance.object_id
            AND task.priority =
              occurrence.action_value::public.dfir_task_priority
        ) THEN
          RAISE EXCEPTION 'SLA priority target revision is exhausted'
            USING ERRCODE = 'P1001', DETAIL = 'target_revision_exhausted';
        END IF;
      END IF;
      IF changed_rows = 1 THEN source_version := source_version + 1; END IF;
      effect_id := instance.object_id;
      effect_version := source_version;
      effect_kind := 'ticket_priority';

    ELSIF p_action_kind = 'assign_operator_team' THEN
      SELECT epoch.id INTO team_epoch_id
      FROM public.operator_teams AS team
      JOIN public.operator_team_assignment_epochs AS epoch
        ON epoch.operator_team_id = team.id
       AND epoch.tenant_id = p_tenant_id AND epoch.ended_at IS NULL
      WHERE team.id = occurrence.action_configuration_id
        AND team.archived_at IS NULL
      FOR SHARE OF team, epoch;
      IF team_epoch_id IS NULL THEN
        RAISE EXCEPTION 'SLA assignment target is unavailable'
          USING ERRCODE = 'P1001', DETAIL = 'assignment_target_unavailable';
      END IF;
      IF instance.object_type = 'alert' THEN
        UPDATE public.alerts AS alert
        SET assigned_team_id = occurrence.action_configuration_id,
            assigned_team_epoch_id = team_epoch_id,
            assignee_user_id = NULL, claimed_by_user_id = NULL,
            claimed_at = NULL, assigned_at = p_applied_at,
            version = alert.version + 1, updated_at = p_applied_at
        WHERE alert.tenant_id = p_tenant_id AND alert.id = instance.object_id
          AND (alert.assigned_team_id IS DISTINCT FROM occurrence.action_configuration_id
            OR alert.assigned_team_epoch_id IS DISTINCT FROM team_epoch_id
            OR alert.assignee_user_id IS NOT NULL
            OR alert.claimed_by_user_id IS NOT NULL)
          AND alert.version < 2147483647;
        GET DIAGNOSTICS changed_rows = ROW_COUNT;
        IF changed_rows = 0 AND NOT EXISTS (
          SELECT 1 FROM public.alerts AS alert
          WHERE alert.tenant_id = p_tenant_id
            AND alert.id = instance.object_id
            AND alert.assigned_team_id = occurrence.action_configuration_id
            AND alert.assigned_team_epoch_id = team_epoch_id
            AND alert.assignee_user_id IS NULL
            AND alert.claimed_by_user_id IS NULL
        ) THEN
          RAISE EXCEPTION 'SLA assignment target revision is exhausted'
            USING ERRCODE = 'P1001', DETAIL = 'target_revision_exhausted';
        END IF;
      ELSIF instance.object_type = 'case' THEN
        UPDATE public.cases AS case_row
        SET assigned_team_id = occurrence.action_configuration_id,
            assigned_team_epoch_id = team_epoch_id,
            assignee_user_id = NULL, claimed_by_user_id = NULL,
            claimed_at = NULL, assigned_at = p_applied_at,
            version = case_row.version + 1, updated_at = p_applied_at
        WHERE case_row.tenant_id = p_tenant_id
          AND case_row.id = instance.object_id
          AND (case_row.assigned_team_id IS DISTINCT FROM occurrence.action_configuration_id
            OR case_row.assigned_team_epoch_id IS DISTINCT FROM team_epoch_id
            OR case_row.assignee_user_id IS NOT NULL
            OR case_row.claimed_by_user_id IS NOT NULL)
          AND case_row.version < 2147483647;
        GET DIAGNOSTICS changed_rows = ROW_COUNT;
        IF changed_rows = 0 AND NOT EXISTS (
          SELECT 1 FROM public.cases AS case_row
          WHERE case_row.tenant_id = p_tenant_id
            AND case_row.id = instance.object_id
            AND case_row.assigned_team_id = occurrence.action_configuration_id
            AND case_row.assigned_team_epoch_id = team_epoch_id
            AND case_row.assignee_user_id IS NULL
            AND case_row.claimed_by_user_id IS NULL
        ) THEN
          RAISE EXCEPTION 'SLA assignment target revision is exhausted'
            USING ERRCODE = 'P1001', DETAIL = 'target_revision_exhausted';
        END IF;
      ELSE
        SELECT account.id INTO runtime_account_id
        FROM public.tenant_service_accounts AS account
        WHERE account.tenant_id = p_tenant_id
          AND account.key = 'sla_action_runtime'
          AND account.system_owned
          AND account.archived_at IS NULL
        FOR SHARE;
        IF runtime_account_id IS NULL THEN
          RAISE EXCEPTION 'SLA runtime account is unavailable'
            USING ERRCODE = 'P1002', DETAIL = 'runtime_identity_unavailable';
        END IF;
        UPDATE public.dfir_tasks AS task
        SET operator_team_id = occurrence.action_configuration_id,
            operator_team_epoch_id = team_epoch_id,
            assignee_user_id = NULL,
            updated_by_membership_id = NULL,
            updated_by_service_account_id = runtime_account_id,
            version = task.version + 1, updated_at = p_applied_at
        WHERE task.tenant_id = p_tenant_id AND task.id = instance.object_id
          AND (task.operator_team_id IS DISTINCT FROM occurrence.action_configuration_id
            OR task.operator_team_epoch_id IS DISTINCT FROM team_epoch_id
            OR task.assignee_user_id IS NOT NULL)
          AND task.version < 9223372036854775807;
        GET DIAGNOSTICS changed_rows = ROW_COUNT;
        IF changed_rows = 0 AND NOT EXISTS (
          SELECT 1 FROM public.dfir_tasks AS task
          WHERE task.tenant_id = p_tenant_id
            AND task.id = instance.object_id
            AND task.operator_team_id = occurrence.action_configuration_id
            AND task.operator_team_epoch_id = team_epoch_id
            AND task.assignee_user_id IS NULL
        ) THEN
          RAISE EXCEPTION 'SLA assignment target revision is exhausted'
            USING ERRCODE = 'P1001', DETAIL = 'target_revision_exhausted';
        END IF;
      END IF;
      IF changed_rows = 1 THEN source_version := source_version + 1; END IF;
      effect_id := instance.object_id;
      effect_version := source_version;
      effect_kind := 'ticket_assignment';

    ELSIF p_action_kind = 'create_task' THEN
      IF instance.object_type <> 'case'
         OR occurrence.action_value IS NULL
         OR octet_length(occurrence.action_value) NOT BETWEEN 1 AND 2048
         OR occurrence.action_value ~ '[[:cntrl:]]' THEN
        RAISE EXCEPTION 'SLA task action is invalid for its target'
          USING ERRCODE = 'P1001', DETAIL = 'unsupported_target_kind';
      END IF;
      SELECT account.id INTO runtime_account_id
      FROM public.tenant_service_accounts AS account
      WHERE account.tenant_id = p_tenant_id
        AND account.key = 'sla_action_runtime'
        AND account.system_owned
        AND account.archived_at IS NULL
      FOR SHARE;
      IF runtime_account_id IS NULL THEN
        RAISE EXCEPTION 'SLA runtime account is unavailable'
          USING ERRCODE = 'P1002', DETAIL = 'runtime_identity_unavailable';
      END IF;
      effect_id := uuidv7();
      INSERT INTO public.dfir_tasks (
        id, tenant_id, case_id, title, description, status, priority,
        checklist, comment_ids, created_by_service_account_id,
        updated_by_service_account_id, version, created_at, updated_at
      ) VALUES (
        effect_id, p_tenant_id, instance.object_id,
        occurrence.action_value, '', 'todo', 'medium', '[]'::jsonb,
        ARRAY[]::uuid[], runtime_account_id, runtime_account_id,
        1, p_applied_at, p_applied_at
      );
      effect_version := 1;
      effect_kind := 'dfir_task';

    ELSIF p_action_kind = 'create_system_alert' THEN
      IF occurrence.action_value IS NULL
         OR occurrence.action_value !~ '^[a-z][a-z0-9_.-]{0,62}[a-z0-9]$' THEN
        RAISE EXCEPTION 'SLA system alert action is malformed'
          USING ERRCODE = 'P1001', DETAIL = 'invalid_action_configuration';
      END IF;
      SELECT account.id INTO runtime_account_id
      FROM public.tenant_service_accounts AS account
      WHERE account.tenant_id = p_tenant_id
        AND account.key = 'sla_action_runtime'
        AND account.system_owned
        AND account.archived_at IS NULL
      FOR SHARE;
      SELECT workflow.id, workflow.current_version, initial_state.value ->> 'key'
      INTO default_workflow_id, default_workflow_version,
           default_workflow_state
      FROM public.ticket_workflows AS workflow
      JOIN public.ticket_workflow_versions AS version
        ON version.tenant_id = workflow.tenant_id
       AND version.workflow_id = workflow.id
       AND version.version = workflow.current_version
      JOIN LATERAL (
        SELECT state.value
        FROM jsonb_array_elements(version.states) AS state(value)
        WHERE (state.value ->> 'initial')::boolean
        ORDER BY state.value ->> 'key'
        LIMIT 1
      ) AS initial_state ON true
      WHERE workflow.tenant_id = p_tenant_id
        AND workflow.aggregate_kind = 'alert'
        AND workflow.is_default AND workflow.archived_at IS NULL
      FOR SHARE OF workflow, version;
      IF runtime_account_id IS NULL OR default_workflow_id IS NULL
         OR default_workflow_state IS NULL THEN
        RAISE EXCEPTION 'SLA system alert dependencies are unavailable'
          USING ERRCODE = 'P1002', DETAIL = 'runtime_configuration_unavailable';
      END IF;
      effect_id := uuidv7();
      INSERT INTO public.alerts (
        id, tenant_id, number, workflow_id, workflow_version, state_key,
        customer_visible, title, description, status, severity, priority,
        category, source, source_type, tags, custom_fields,
        customer_custom_fields, raw_payload, created_by_service_account_id,
        detected_at, received_at, created_at, updated_at, version
      ) VALUES (
        effect_id, p_tenant_id,
        app.private_next_ticket_number_v1(p_tenant_id, 'alert', p_applied_at),
        default_workflow_id, default_workflow_version,
        default_workflow_state, false,
        left('SLA system alert: ' || occurrence.action_value, 240),
        'Generated by an SLA trigger action.', 'new', 'medium', 'medium',
        occurrence.action_value, 'sla-engine', 'system',
        ARRAY['sla', 'system']::text[], '{}'::jsonb, '{}'::jsonb,
        '{}'::jsonb, runtime_account_id,
        p_applied_at, p_applied_at, p_applied_at, p_applied_at, 1
      );
      INSERT INTO public.ticket_activities (
        id, tenant_id, alert_id, sequence, kind, summary,
        actor_principal_kind, origin, details, occurred_at
      ) VALUES (
        uuidv7(), p_tenant_id, effect_id, 1, 'alert.created',
        'Alert created by SLA action', 'system', 'system',
        jsonb_build_object('occurrenceId', occurrence.id,
          'contentRedacted', true), p_applied_at
      );
      INSERT INTO public.sla_system_alert_origins (
        tenant_id, alert_id, source_occurrence_id, allow_recursive_sla,
        created_at
      ) VALUES (
        p_tenant_id, effect_id, occurrence.id,
        occurrence.allow_recursive_sla, p_applied_at
      );
      IF occurrence.allow_recursive_sla THEN
        INSERT INTO public.outbox_events (
          id, tenant_id, aggregate_type, aggregate_id, aggregate_version,
          event_type, schema_version, payload, deduplication_key,
          actor_kind, producer, maximum_audience, occurred_at, available_at
        ) VALUES (
          uuidv7(), p_tenant_id, 'alert', effect_id, 1,
          'sla.alert.created', 1,
          jsonb_build_object('alert_id', effect_id, 'version', 1,
            'source', 'sla-engine'),
          'sla:system-alert:' || occurrence.id::text,
          'system', 'sla-action', 'operator', p_applied_at, p_applied_at
        );
      END IF;
      effect_version := 1;
      effect_kind := 'system_alert';

    ELSIF p_action_kind = 'domain_event' THEN
      IF occurrence.action_value IS NULL
         OR occurrence.action_value !~ '^[a-z][a-z0-9_.-]{0,62}[a-z0-9]$' THEN
        RAISE EXCEPTION 'SLA domain event action is malformed'
          USING ERRCODE = 'P1001', DETAIL = 'invalid_action_configuration';
      END IF;
      effect_id := uuidv7();
      INSERT INTO public.outbox_events (
        id, tenant_id, aggregate_type, aggregate_id, aggregate_version,
        event_type, schema_version, payload, deduplication_key,
        actor_kind, producer, maximum_audience, occurred_at, available_at
      ) VALUES (
        effect_id, p_tenant_id, instance.object_type::text,
        instance.object_id, instance.aggregate_version,
        'sla.domain.' || occurrence.action_value, 1,
        jsonb_build_object('slaInstanceId', instance.id,
          'occurrenceId', occurrence.id, 'contentRedacted', true),
        'sla:action:' || occurrence.id::text || ':domain',
        'system', 'sla-action', 'operator', p_applied_at, p_applied_at
      );
      effect_version := 1;
      effect_kind := 'domain_event';
    ELSE
      RAISE EXCEPTION 'SLA action kind is unsupported'
        USING ERRCODE = 'P1001', DETAIL = 'unsupported_action_kind';
    END IF;

    IF instance.object_type IN ('alert', 'case') THEN
      PERFORM app.private_append_sla_action_activity_v1(
        p_tenant_id, instance.object_type, instance.object_id,
        occurrence.id, occurrence.action_kind, p_applied_at,
        effect_id, effect_version
      );
    END IF;
    effect_digest := digest(convert_to(
      'periapsis/sla-action/effect/v1' || chr(0)
      || occurrence.id::text || chr(0) || occurrence.action_kind::text
      || chr(0) || effect_kind || chr(0)
      || coalesce(effect_id::text, '') || chr(0)
      || coalesce(effect_version::text, ''), 'UTF8'), 'sha256');
    INSERT INTO public.sla_trigger_action_receipts (
      tenant_id, occurrence_id, worker_id, action_kind,
      deduplication_digest, fence, effect_kind, effect_id,
      effect_version, effect_digest, applied_at
    ) VALUES (
      p_tenant_id, occurrence.id, p_worker_id, occurrence.action_kind,
      occurrence.deduplication_digest, p_fence, effect_kind, effect_id,
      effect_version, effect_digest, p_applied_at
    );
    PERFORM app.private_append_sla_action_audit_v1(
      p_tenant_id, occurrence.id, 'executed', p_applied_at,
      jsonb_build_object('actionKind', occurrence.action_kind,
        'effectKind', effect_kind, 'effectId', effect_id,
        'effectVersion', effect_version)
    );
    INSERT INTO public.outbox_events (
      id, tenant_id, aggregate_type, aggregate_id, aggregate_version,
      event_type, schema_version, payload, deduplication_key,
      actor_kind, producer, maximum_audience, occurred_at, available_at
    ) VALUES (
      uuidv7(), p_tenant_id, 'sla_trigger_occurrence', occurrence.id,
      1, 'sla.action.executed', 1,
      jsonb_build_object('occurrenceId', occurrence.id,
        'actionKind', occurrence.action_kind, 'effectKind', effect_kind,
        'contentRedacted', true),
      'sla:action:' || occurrence.id::text || ':executed',
      'system', 'sla-action', 'operator', p_applied_at, p_applied_at
    );
    UPDATE public.sla_trigger_action_executions AS current_execution
    SET status = 'completed', worker_id = NULL, lease_expires_at = NULL,
        completed_at = p_applied_at, last_failure_code = NULL,
        updated_at = p_applied_at
    WHERE current_execution.tenant_id = p_tenant_id
      AND current_execution.occurrence_id = p_occurrence_id;
    action_applied := true;
  EXCEPTION
    WHEN SQLSTATE 'P1001' THEN
      GET STACKED DIAGNOSTICS failure_detail = PG_EXCEPTION_DETAIL;
      failure_code := coalesce(nullif(failure_detail, ''),
        'invalid_action_configuration');
      permanent_failure := true;
    WHEN SQLSTATE 'P1002' THEN
      GET STACKED DIAGNOSTICS failure_detail = PG_EXCEPTION_DETAIL;
      failure_code := coalesce(nullif(failure_detail, ''),
        'runtime_configuration_unavailable');
      permanent_failure := false;
    WHEN OTHERS THEN
      failure_code := 'action_execution_failed';
      permanent_failure := false;
  END;

  IF action_applied THEN
    RETURN 'applied';
  END IF;
  IF failure_code !~ '^[a-z][a-z0-9_.-]{0,127}$' THEN
    failure_code := 'action_execution_failed';
  END IF;
  IF permanent_failure OR execution.attempt >= execution.maximum_attempts THEN
    UPDATE public.sla_trigger_action_executions AS current_execution
    SET status = 'dead_lettered', worker_id = NULL, lease_expires_at = NULL,
        last_failure_code = failure_code, dead_lettered_at = p_applied_at,
        updated_at = p_applied_at
    WHERE current_execution.tenant_id = p_tenant_id
      AND current_execution.occurrence_id = p_occurrence_id;
    PERFORM app.private_append_sla_action_audit_v1(
      p_tenant_id, p_occurrence_id, 'dead_lettered', p_applied_at,
      jsonb_build_object('actionKind', p_action_kind,
        'failureCode', failure_code, 'attempt', execution.attempt)
    );
    RETURN 'dead_lettered';
  END IF;
  retry_delay_seconds := least(3600,
    5 * (1 << least(execution.attempt - 1, 9)));
  UPDATE public.sla_trigger_action_executions AS current_execution
  SET status = 'retry_scheduled', worker_id = NULL,
      lease_expires_at = NULL, last_failure_code = failure_code,
      available_at = p_applied_at
        + retry_delay_seconds * interval '1 second',
      updated_at = p_applied_at
  WHERE current_execution.tenant_id = p_tenant_id
    AND current_execution.occurrence_id = p_occurrence_id;
  RETURN 'retry_scheduled';
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.execute_sla_trigger_action_v1(
  uuid, uuid, uuid, bigint, bytea,
  public.sla_trigger_action_kind, timestamp with time zone
) OWNER TO periapsis_sla_worker_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.execute_sla_trigger_action_v1(
  uuid, uuid, uuid, bigint, bytea,
  public.sla_trigger_action_kind, timestamp with time zone
) FROM PUBLIC, periapsis_api, periapsis_notifier, periapsis_auditor,
  periapsis_sla_api_owner, periapsis_sla_readiness_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.execute_sla_trigger_action_v1(
  uuid, uuid, uuid, bigint, bytea,
  public.sla_trigger_action_kind, timestamp with time zone
) TO periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.read_sla_trigger_action_queue_metrics_v1()
RETURNS TABLE(
  observed_at timestamp with time zone,
  pending_actions bigint,
  oldest_pending_micros bigint
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE observation timestamp with time zone :=
  date_trunc('microseconds', transaction_timestamp());
BEGIN
  RETURN QUERY
  SELECT observation,
         count(*)::bigint,
         CASE WHEN count(*) = 0 THEN 0::bigint ELSE greatest(0::bigint,
           floor(extract(epoch FROM (
             observation - min(CASE
               WHEN execution.status = 'leased'
                 THEN execution.lease_expires_at
               ELSE execution.available_at
             END)
           )) * 1000000)::bigint)
         END
  FROM public.sla_trigger_action_executions AS execution
  WHERE execution.status IN ('queued', 'retry_scheduled', 'leased');
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.read_sla_trigger_action_queue_metrics_v1()
  OWNER TO periapsis_sla_worker_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.read_sla_trigger_action_queue_metrics_v1()
FROM PUBLIC, periapsis_api, periapsis_notifier, periapsis_auditor,
  periapsis_sla_api_owner, periapsis_sla_readiness_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.read_sla_trigger_action_queue_metrics_v1()
TO periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.sla_trigger_action_runtime_schema_readiness_v1()
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
  function_record record;
  table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'sla_trigger_action_executions', 'sla_trigger_action_receipts',
    'sla_system_alert_origins', 'sla_system_principal_write_capabilities'
  ] LOOP
    IF NOT EXISTS (
      SELECT 1
      FROM pg_catalog.pg_class AS relation
      JOIN pg_catalog.pg_namespace AS namespace
        ON namespace.oid = relation.relnamespace
      WHERE namespace.nspname = 'public' AND relation.relname = table_name
        AND relation.relkind = 'r'
        AND relation.relrowsecurity AND relation.relforcerowsecurity
        AND pg_catalog.pg_get_userbyid(relation.relowner) =
          'periapsis_migrator'
    ) OR has_table_privilege('periapsis_api',
          format('public.%I', table_name), 'SELECT,INSERT,UPDATE,DELETE')
       OR has_table_privilege('periapsis_worker',
          format('public.%I', table_name), 'SELECT,INSERT,UPDATE,DELETE')
       OR has_table_privilege('periapsis_notifier',
          format('public.%I', table_name), 'SELECT,INSERT,UPDATE,DELETE') THEN
      RETURN false;
    END IF;
  END LOOP;

  FOR function_record IN
    SELECT expected.identity, expected.volatility
    FROM (VALUES
      ('app.list_sla_trigger_action_queues_v1(timestamp with time zone,integer)', 's'::"char"),
      ('app.claim_sla_trigger_actions_v1(uuid,uuid,timestamp with time zone,integer,bigint)', 'v'::"char"),
      ('app.execute_sla_trigger_action_v1(uuid,uuid,uuid,bigint,bytea,public.sla_trigger_action_kind,timestamp with time zone)', 'v'::"char"),
      ('app.read_sla_trigger_action_queue_metrics_v1()', 's'::"char")
    ) AS expected(identity, volatility)
  LOOP
    IF to_regprocedure(function_record.identity) IS NULL
       OR NOT EXISTS (
         SELECT 1 FROM pg_catalog.pg_proc AS procedure
         WHERE procedure.oid = to_regprocedure(function_record.identity)
           AND procedure.prosecdef
           AND procedure.provolatile = function_record.volatility
           AND pg_catalog.pg_get_userbyid(procedure.proowner) =
             'periapsis_sla_worker_owner'
       )
       OR NOT has_function_privilege(
         'periapsis_worker', function_record.identity, 'EXECUTE')
       OR EXISTS (
         SELECT 1
         FROM pg_catalog.pg_proc AS procedure
         CROSS JOIN LATERAL pg_catalog.aclexplode(
           coalesce(
             procedure.proacl,
             pg_catalog.acldefault('f', procedure.proowner)
           )
         ) AS privilege
         WHERE procedure.oid = to_regprocedure(function_record.identity)
           AND privilege.grantee = 0
           AND privilege.privilege_type = 'EXECUTE'
       )
       OR has_function_privilege(
         'periapsis_api', function_record.identity, 'EXECUTE')
       OR has_function_privilege(
         'periapsis_notifier', function_record.identity, 'EXECUTE') THEN
      RETURN false;
    END IF;
  END LOOP;

  RETURN EXISTS (
      SELECT 1 FROM pg_catalog.pg_trigger AS trigger
      WHERE trigger.tgrelid = 'public.sla_trigger_occurrences'::regclass
        AND trigger.tgname = 'sla_trigger_occurrences_seed_action_v1'
        AND trigger.tgenabled = 'O' AND NOT trigger.tgisinternal
    ) AND EXISTS (
      SELECT 1 FROM pg_catalog.pg_trigger AS trigger
      WHERE trigger.tgrelid = 'public.sla_trigger_action_receipts'::regclass
        AND trigger.tgname = 'sla_trigger_action_receipts_immutable_v1'
        AND trigger.tgenabled = 'O' AND NOT trigger.tgisinternal
    ) AND EXISTS (
      SELECT 1 FROM pg_catalog.pg_trigger AS trigger
      WHERE trigger.tgrelid = 'public.sla_system_alert_origins'::regclass
        AND trigger.tgname = 'sla_system_alert_origins_immutable_v1'
        AND trigger.tgenabled = 'O' AND NOT trigger.tgisinternal
    ) AND EXISTS (
      SELECT 1 FROM pg_catalog.pg_trigger AS trigger
      WHERE trigger.tgrelid = 'public.sla_instances'::regclass
        AND trigger.tgname = 'aaa_sla_instances_system_alert_recursion_v1'
        AND trigger.tgenabled = 'O' AND NOT trigger.tgisinternal
    ) AND app.private_sla_system_principal_catalog_ready_v1();
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.sla_trigger_action_runtime_schema_readiness_v1()
  OWNER TO periapsis_sla_readiness_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.sla_trigger_action_runtime_schema_readiness_v1()
FROM PUBLIC, periapsis_api, periapsis_notifier, periapsis_auditor,
  periapsis_sla_api_owner, periapsis_sla_worker_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.sla_trigger_action_runtime_schema_readiness_v1()
TO periapsis_worker;
