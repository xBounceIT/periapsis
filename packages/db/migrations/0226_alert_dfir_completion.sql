CREATE TABLE "alert_dfir_resource_command_results" (
	"command_id" uuid PRIMARY KEY NOT NULL,
	"tenant_id" uuid NOT NULL,
	"alert_id" uuid NOT NULL,
	"operation" text NOT NULL,
	"resource_id" uuid NOT NULL,
	"result_version" bigint NOT NULL,
	"result_snapshot" jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "alert_dfir_resource_command_results_coordinate_key" UNIQUE("tenant_id","alert_id","operation","resource_id","result_version"),
	CONSTRAINT "alert_dfir_resource_command_results_shape_check" CHECK ((uuid_extract_version("alert_dfir_resource_command_results"."command_id") = 7) is true
        and (uuid_extract_version("alert_dfir_resource_command_results"."resource_id") = 7) is true
        and "alert_dfir_resource_command_results"."result_version" between 1 and 9007199254740991
        and jsonb_typeof("alert_dfir_resource_command_results"."result_snapshot") = 'object'
        and octet_length("alert_dfir_resource_command_results"."result_snapshot"::text) <= 16777216)
);
--> statement-breakpoint
ALTER TABLE "alert_dfir_resource_command_results" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "dfir_relationship_retractions" (
	"id" uuid PRIMARY KEY NOT NULL,
	"tenant_id" uuid NOT NULL,
	"relationship_id" uuid NOT NULL,
	"alert_id" uuid,
	"case_id" uuid,
	"retracted_by_membership_id" uuid NOT NULL,
	"reason" text NOT NULL,
	"prior_version" bigint NOT NULL,
	"result_version" bigint NOT NULL,
	"retracted_at" timestamp with time zone NOT NULL,
	CONSTRAINT "dfir_relationship_retractions_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "dfir_relationship_retractions_relationship_key" UNIQUE("tenant_id","relationship_id"),
	CONSTRAINT "dfir_relationship_retractions_id_uuidv7_check" CHECK ((uuid_extract_version("dfir_relationship_retractions"."id") = 7) is true),
	CONSTRAINT "dfir_relationship_retractions_root_check" CHECK (num_nonnulls("dfir_relationship_retractions"."alert_id", "dfir_relationship_retractions"."case_id") = 1),
	CONSTRAINT "dfir_relationship_retractions_reason_check" CHECK (btrim("dfir_relationship_retractions"."reason") <> '' and octet_length("dfir_relationship_retractions"."reason") <= 2000
        and "dfir_relationship_retractions"."reason" !~ '[[:cntrl:]]'),
	CONSTRAINT "dfir_relationship_retractions_version_check" CHECK ("dfir_relationship_retractions"."prior_version" between 1 and 9007199254740990
        and "dfir_relationship_retractions"."result_version" = "dfir_relationship_retractions"."prior_version" + 1)
);
--> statement-breakpoint
ALTER TABLE "dfir_relationship_retractions" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "alert_dfir_resource_commands" DROP CONSTRAINT "alert_dfir_resource_commands_shape_check";--> statement-breakpoint
ALTER TABLE "dfir_evidence" DROP CONSTRAINT "dfir_evidence_version_check";--> statement-breakpoint
ALTER TABLE "dfir_relationships" DROP CONSTRAINT "dfir_relationships_type_check";--> statement-breakpoint
ALTER TABLE "dfir_relationships" DROP CONSTRAINT "dfir_relationships_metadata_check";--> statement-breakpoint
ALTER TABLE "dfir_tasks" DROP CONSTRAINT "dfir_tasks_version_check";--> statement-breakpoint
ALTER TABLE "dfir_activities" ALTER COLUMN "case_id" DROP NOT NULL;--> statement-breakpoint
ALTER TABLE "dfir_evidence" ALTER COLUMN "case_id" DROP NOT NULL;--> statement-breakpoint
ALTER TABLE "dfir_tasks" ALTER COLUMN "case_id" DROP NOT NULL;--> statement-breakpoint
ALTER TABLE "dfir_activities" ADD COLUMN "alert_id" uuid;--> statement-breakpoint
ALTER TABLE "dfir_evidence" ADD COLUMN "alert_id" uuid;--> statement-breakpoint
ALTER TABLE "dfir_relationships" ADD COLUMN "alert_id" uuid;--> statement-breakpoint
ALTER TABLE "dfir_relationships" ADD COLUMN "case_id" uuid;--> statement-breakpoint
ALTER TABLE "dfir_relationships" ADD COLUMN "version" bigint DEFAULT 1 NOT NULL;--> statement-breakpoint
ALTER TABLE "dfir_tasks" ADD COLUMN "alert_id" uuid;--> statement-breakpoint
-- Before 0226 a general DFIR relationship did not persist its workspace root.
-- The Case write path nevertheless required the relationship to touch that Case.
-- Reconstruct only the unambiguous shape and stop the migration rather than
-- silently assigning a Case-to-Case or malformed legacy edge to the wrong root.
DO $block$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM public.dfir_relationships AS relationship
    WHERE num_nonnulls(
      CASE WHEN relationship.source_kind = 'case' THEN relationship.source_id END,
      CASE WHEN relationship.target_kind = 'case' THEN relationship.target_id END
    ) <> 1
  ) THEN
    RAISE EXCEPTION
      '0226 cannot infer an exact Case root for a legacy DFIR relationship'
      USING ERRCODE = '23514';
  END IF;

  UPDATE public.dfir_relationships AS relationship
  SET case_id = CASE
    WHEN relationship.source_kind = 'case' THEN relationship.source_id
    ELSE relationship.target_id
  END;
END;
$block$;--> statement-breakpoint
ALTER TABLE "alert_dfir_resource_commands" ADD CONSTRAINT "alert_dfir_resource_commands_tenant_command_key" UNIQUE("tenant_id","command_id");--> statement-breakpoint
ALTER TABLE "alert_dfir_resource_commands" ADD CONSTRAINT "alert_dfir_resource_commands_result_coordinate_key" UNIQUE("tenant_id","command_id","alert_id","operation","resource_id","result_version");--> statement-breakpoint
ALTER TABLE "dfir_relationships" ADD CONSTRAINT "dfir_relationships_alert_root_key" UNIQUE("tenant_id","id","alert_id");--> statement-breakpoint
ALTER TABLE "dfir_relationships" ADD CONSTRAINT "dfir_relationships_case_root_key" UNIQUE("tenant_id","id","case_id");--> statement-breakpoint
ALTER TABLE "alert_dfir_resource_command_results" ADD CONSTRAINT "alert_dfir_resource_command_results_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "alert_dfir_resource_command_results" ADD CONSTRAINT "alert_dfir_resource_command_results_command_fk" FOREIGN KEY ("tenant_id","command_id","alert_id","operation","resource_id","result_version") REFERENCES "public"."alert_dfir_resource_commands"("tenant_id","command_id","alert_id","operation","resource_id","result_version") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "alert_dfir_resource_command_results" ADD CONSTRAINT "alert_dfir_resource_command_results_alert_fk" FOREIGN KEY ("tenant_id","alert_id") REFERENCES "public"."alerts"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_relationship_retractions" ADD CONSTRAINT "dfir_relationship_retractions_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dfir_relationship_retractions" ADD CONSTRAINT "dfir_relationship_retractions_relationship_fk" FOREIGN KEY ("tenant_id","relationship_id") REFERENCES "public"."dfir_relationships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_relationship_retractions" ADD CONSTRAINT "dfir_relationship_retractions_alert_root_fk" FOREIGN KEY ("tenant_id","relationship_id","alert_id") REFERENCES "public"."dfir_relationships"("tenant_id","id","alert_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_relationship_retractions" ADD CONSTRAINT "dfir_relationship_retractions_case_root_fk" FOREIGN KEY ("tenant_id","relationship_id","case_id") REFERENCES "public"."dfir_relationships"("tenant_id","id","case_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_relationship_retractions" ADD CONSTRAINT "dfir_relationship_retractions_alert_fk" FOREIGN KEY ("tenant_id","alert_id") REFERENCES "public"."alerts"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_relationship_retractions" ADD CONSTRAINT "dfir_relationship_retractions_case_fk" FOREIGN KEY ("tenant_id","case_id") REFERENCES "public"."cases"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_relationship_retractions" ADD CONSTRAINT "dfir_relationship_retractions_actor_fk" FOREIGN KEY ("tenant_id","retracted_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
CREATE INDEX "dfir_relationship_retractions_alert_idx" ON "dfir_relationship_retractions" USING btree ("tenant_id","alert_id","retracted_at","id");--> statement-breakpoint
CREATE INDEX "dfir_relationship_retractions_case_idx" ON "dfir_relationship_retractions" USING btree ("tenant_id","case_id","retracted_at","id");--> statement-breakpoint
ALTER TABLE "dfir_activities" ADD CONSTRAINT "dfir_activities_alert_fk" FOREIGN KEY ("tenant_id","alert_id") REFERENCES "public"."alerts"("tenant_id","id") ON DELETE cascade ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_evidence" ADD CONSTRAINT "dfir_evidence_alert_fk" FOREIGN KEY ("tenant_id","alert_id") REFERENCES "public"."alerts"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_relationships" ADD CONSTRAINT "dfir_relationships_alert_fk" FOREIGN KEY ("tenant_id","alert_id") REFERENCES "public"."alerts"("tenant_id","id") ON DELETE cascade ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_relationships" ADD CONSTRAINT "dfir_relationships_case_fk" FOREIGN KEY ("tenant_id","case_id") REFERENCES "public"."cases"("tenant_id","id") ON DELETE cascade ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_tasks" ADD CONSTRAINT "dfir_tasks_alert_fk" FOREIGN KEY ("tenant_id","alert_id") REFERENCES "public"."alerts"("tenant_id","id") ON DELETE cascade ON UPDATE cascade;--> statement-breakpoint
CREATE INDEX "dfir_activities_alert_idx" ON "dfir_activities" USING btree ("tenant_id","alert_id","occurred_at","id");--> statement-breakpoint
CREATE INDEX "dfir_evidence_alert_idx" ON "dfir_evidence" USING btree ("tenant_id","alert_id","collected_at","id");--> statement-breakpoint
CREATE INDEX "dfir_relationships_alert_idx" ON "dfir_relationships" USING btree ("tenant_id","alert_id","created_at","id");--> statement-breakpoint
CREATE INDEX "dfir_relationships_case_idx" ON "dfir_relationships" USING btree ("tenant_id","case_id","created_at","id");--> statement-breakpoint
CREATE INDEX "dfir_tasks_alert_status_idx" ON "dfir_tasks" USING btree ("tenant_id","alert_id","status","due_at","id");--> statement-breakpoint
ALTER TABLE "alert_dfir_resource_commands" ADD CONSTRAINT "alert_dfir_resource_commands_shape_check" CHECK ((uuid_extract_version("alert_dfir_resource_commands"."command_id") = 7) is true
        and (uuid_extract_version("alert_dfir_resource_commands"."resource_id") = 7) is true
        and "alert_dfir_resource_commands"."operation" in (
          'dfir.ioc.create','dfir.ioc.replace','dfir.asset.create','dfir.asset.replace','dfir.timeline.create',
          'dfir.alert.evidence.create','dfir.alert.evidence.custody.append',
          'dfir.alert.task.create','dfir.alert.task.transition','dfir.alert.task.assign',
          'dfir.alert.task.reschedule','dfir.alert.task.checklist.replace',
          'dfir.alert.relationship.create','dfir.alert.relationship.retract'
        )
        and "alert_dfir_resource_commands"."result_version" between 1 and 9007199254740991
        and octet_length("alert_dfir_resource_commands"."key_digest") = 32
        and octet_length("alert_dfir_resource_commands"."request_digest") = 32);--> statement-breakpoint
ALTER TABLE "dfir_activities" ADD CONSTRAINT "dfir_activities_root_check" CHECK (num_nonnulls("dfir_activities"."alert_id", "dfir_activities"."case_id") = 1);--> statement-breakpoint
ALTER TABLE "dfir_evidence" ADD CONSTRAINT "dfir_evidence_root_check" CHECK (num_nonnulls("dfir_evidence"."alert_id", "dfir_evidence"."case_id") = 1);--> statement-breakpoint
ALTER TABLE "dfir_evidence" ADD CONSTRAINT "dfir_evidence_version_check" CHECK ("dfir_evidence"."version" = "dfir_evidence"."custody_count" and "dfir_evidence"."version" between 1 and 9007199254740991);--> statement-breakpoint
ALTER TABLE "dfir_relationships" ADD CONSTRAINT "dfir_relationships_root_check" CHECK (num_nonnulls("dfir_relationships"."alert_id", "dfir_relationships"."case_id") = 1);--> statement-breakpoint
ALTER TABLE "dfir_relationships" ADD CONSTRAINT "dfir_relationships_version_check" CHECK ("dfir_relationships"."version" between 1 and 9007199254740991);--> statement-breakpoint
ALTER TABLE "dfir_relationships" ADD CONSTRAINT "dfir_relationships_type_check" CHECK ("dfir_relationships"."relationship_type" ~ '^[a-z][a-z0-9_.-]{0,63}$'
        and not ("dfir_relationships"."source_kind" = 'alert' and "dfir_relationships"."target_kind" = 'alert'
          and "dfir_relationships"."relationship_type" in ('duplicate_of', 'correlation')));--> statement-breakpoint
ALTER TABLE "dfir_relationships" ADD CONSTRAINT "dfir_relationships_metadata_check" CHECK ("dfir_relationships"."metadata" is null or (jsonb_typeof("dfir_relationships"."metadata") = 'object' and octet_length("dfir_relationships"."metadata"::text) <= 65536));--> statement-breakpoint
ALTER TABLE "dfir_tasks" ADD CONSTRAINT "dfir_tasks_root_check" CHECK (num_nonnulls("dfir_tasks"."alert_id", "dfir_tasks"."case_id") = 1);--> statement-breakpoint
ALTER TABLE "dfir_tasks" ADD CONSTRAINT "dfir_tasks_version_check" CHECK ("dfir_tasks"."version" between 1 and 9007199254740991);--> statement-breakpoint
CREATE POLICY "dfir_relationship_retractions_api_tenant" ON "dfir_relationship_retractions" AS PERMISSIVE FOR SELECT TO "periapsis_api" USING (
  "dfir_relationship_retractions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("dfir_relationship_retractions"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_relationship_retractions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);
--> statement-breakpoint

-- 0226 Alert investigation security boundary. Receipt/result rows and
-- retractions are reachable only through the closed SECURITY DEFINER ABI.
ALTER TABLE public.alert_dfir_resource_command_results OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.dfir_relationship_retractions OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.alert_dfir_resource_command_results FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.dfir_relationship_retractions FORCE ROW LEVEL SECURITY;--> statement-breakpoint
REVOKE ALL ON TABLE public.alert_dfir_resource_command_results
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON TABLE public.dfir_relationship_retractions
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;--> statement-breakpoint
GRANT SELECT ON TABLE public.dfir_relationship_retractions TO periapsis_api;--> statement-breakpoint
REVOKE DELETE, UPDATE ON TABLE public.dfir_relationships FROM periapsis_api;--> statement-breakpoint

CREATE TRIGGER alert_dfir_resource_command_results_immutable_v1
BEFORE UPDATE OR DELETE ON public.alert_dfir_resource_command_results
FOR EACH ROW EXECUTE FUNCTION app.guard_phase4_append_only_v1();--> statement-breakpoint
CREATE TRIGGER dfir_relationship_retractions_immutable_v1
BEFORE UPDATE OR DELETE ON public.dfir_relationship_retractions
FOR EACH ROW EXECUTE FUNCTION app.guard_phase4_append_only_v1();--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.guard_dfir_evidence_identity_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP = 'DELETE'
     OR NEW.id IS DISTINCT FROM OLD.id
     OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.alert_id IS DISTINCT FROM OLD.alert_id
     OR NEW.case_id IS DISTINCT FROM OLD.case_id
     OR NEW.storage_object_id IS DISTINCT FROM OLD.storage_object_id
     OR NEW.title IS DISTINCT FROM OLD.title
     OR NEW.description IS DISTINCT FROM OLD.description
     OR NEW.evidence_type IS DISTINCT FROM OLD.evidence_type
     OR NEW.classification IS DISTINCT FROM OLD.classification
     OR NEW.content_sha256 IS DISTINCT FROM OLD.content_sha256
     OR NEW.size_bytes IS DISTINCT FROM OLD.size_bytes
     OR NEW.detected_mime IS DISTINCT FROM OLD.detected_mime
     OR NEW.collected_at IS DISTINCT FROM OLD.collected_at
     OR NEW.collected_by_membership_id IS DISTINCT FROM OLD.collected_by_membership_id
     OR NEW.source IS DISTINCT FROM OLD.source
     OR NEW.initial_retention_until IS DISTINCT FROM OLD.initial_retention_until
     OR NEW.initial_legal_hold IS DISTINCT FROM OLD.initial_legal_hold
     OR NEW.initial_scan_state IS DISTINCT FROM OLD.initial_scan_state
     OR NEW.anchor_hash IS DISTINCT FROM OLD.anchor_hash
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'DFIR evidence provenance is immutable'
      USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.guard_dfir_evidence_identity_v1() OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_dfir_evidence_identity_v1()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.private_current_alert_dfir_manage_scope_allows_v1(
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
       'dfir.ioc.manage', 'dfir.asset.manage', 'dfir.timeline.manage',
       'dfir.attachment.manage', 'dfir.evidence.manage',
       'dfir.task.manage', 'dfir.relationship.manage'
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
$function$;--> statement-breakpoint
ALTER FUNCTION app.private_current_alert_dfir_manage_scope_allows_v1(text, uuid)
  OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_current_alert_dfir_manage_scope_allows_v1(text, uuid)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.private_dfir_entity_exists_v1(
  p_tenant_id uuid,
  p_kind public.dfir_entity_kind,
  p_id uuid
)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_tenant_id IS NULL OR p_kind IS NULL OR p_id IS NULL OR p_kind = 'external' THEN
    RETURN false;
  END IF;
  RETURN CASE p_kind
    WHEN 'alert' THEN EXISTS (
      SELECT 1 FROM public.alerts
      WHERE tenant_id = p_tenant_id AND id = p_id AND deleted_at IS NULL
    )
    WHEN 'case' THEN EXISTS (
      SELECT 1 FROM public.cases WHERE tenant_id = p_tenant_id AND id = p_id
    )
    WHEN 'ioc' THEN EXISTS (
      SELECT 1 FROM public.dfir_iocs
      WHERE tenant_id = p_tenant_id AND id = p_id AND archived_at IS NULL
    )
    WHEN 'asset' THEN EXISTS (
      SELECT 1 FROM public.dfir_assets
      WHERE tenant_id = p_tenant_id AND id = p_id AND archived_at IS NULL
    )
    WHEN 'evidence' THEN EXISTS (
      SELECT 1 FROM public.dfir_evidence
      WHERE tenant_id = p_tenant_id AND id = p_id AND NOT destroyed
    )
    WHEN 'task' THEN EXISTS (
      SELECT 1 FROM public.dfir_tasks WHERE tenant_id = p_tenant_id AND id = p_id
    )
    WHEN 'attachment' THEN EXISTS (
      SELECT 1 FROM public.dfir_attachments
      WHERE tenant_id = p_tenant_id AND id = p_id AND scan_state <> 'deleted'
    )
    ELSE false
  END;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.private_dfir_entity_exists_v1(uuid, public.dfir_entity_kind, uuid)
  OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_dfir_entity_exists_v1(uuid, public.dfir_entity_kind, uuid)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.validate_alert_dfir_timeline_link_v1()
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
    IF NOT EXISTS (
      SELECT 1 FROM public.dfir_evidence AS evidence
      WHERE evidence.tenant_id = NEW.tenant_id
        AND evidence.alert_id = root_alert_id
        AND evidence.case_id IS NULL
        AND evidence.id = NEW.evidence_id
        AND NOT evidence.destroyed
    ) THEN
      RAISE EXCEPTION 'Alert timeline evidence is not live on the same Alert'
        USING ERRCODE = '23503';
    END IF;
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
$function$;--> statement-breakpoint
ALTER FUNCTION app.validate_alert_dfir_timeline_link_v1()
  OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.validate_alert_dfir_timeline_link_v1()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;--> statement-breakpoint

-- Length-prefix and timestamp helpers reproduce modules/dfir/evidence.go
-- byte-for-byte. UUIDs use their 16 network-order bytes and integers use
-- PostgreSQL's signed int8send representation, which is the same two's
-- complement representation used by binary.BigEndian.PutUint64.
CREATE FUNCTION app.private_alert_dfir_hash_field_v1(p_value bytea)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT pg_catalog.int8send(pg_catalog.octet_length(p_value)::bigint) || p_value
$function$;--> statement-breakpoint
ALTER FUNCTION app.private_alert_dfir_hash_field_v1(bytea)
  OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_alert_dfir_hash_field_v1(bytea)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;--> statement-breakpoint

CREATE FUNCTION app.private_alert_dfir_instant_text_v1(
  p_value timestamp with time zone
)
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
  SELECT pg_catalog.rtrim(
           pg_catalog.rtrim(
             pg_catalog.to_char(
               p_value AT TIME ZONE 'UTC',
               'YYYY-MM-DD"T"HH24:MI:SS.US'
             ),
             '0'
           ),
           '.'
         ) || 'Z'
$function$;--> statement-breakpoint
ALTER FUNCTION app.private_alert_dfir_instant_text_v1(timestamp with time zone)
  OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_alert_dfir_instant_text_v1(timestamp with time zone)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;--> statement-breakpoint

CREATE FUNCTION app.private_alert_dfir_anchor_hash_v1(
  p_evidence_id uuid,
  p_tenant_id uuid,
  p_alert_id uuid,
  p_storage_object_id uuid,
  p_title text,
  p_description text,
  p_evidence_type text,
  p_classification public.dfir_evidence_classification,
  p_content_sha256 bytea,
  p_detected_mime text,
  p_source text,
  p_size_bytes bigint,
  p_collected_at timestamp with time zone,
  p_collected_by uuid,
  p_initial_scan_state public.dfir_scan_state,
  p_initial_retention_until timestamp with time zone,
  p_initial_legal_hold boolean
)
RETURNS bytea
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
  SELECT pg_catalog.sha256(
    app.private_alert_dfir_hash_field_v1(
      pg_catalog.convert_to('periapsis:dfir:alert-evidence-anchor:v1', 'UTF8')
    ) ||
    app.private_alert_dfir_hash_field_v1(pg_catalog.uuid_send(p_evidence_id)) ||
    app.private_alert_dfir_hash_field_v1(pg_catalog.uuid_send(p_tenant_id)) ||
    app.private_alert_dfir_hash_field_v1(pg_catalog.uuid_send(p_alert_id)) ||
    app.private_alert_dfir_hash_field_v1(pg_catalog.uuid_send(p_storage_object_id)) ||
    app.private_alert_dfir_hash_field_v1(pg_catalog.convert_to(p_title, 'UTF8')) ||
    app.private_alert_dfir_hash_field_v1(pg_catalog.convert_to(p_description, 'UTF8')) ||
    app.private_alert_dfir_hash_field_v1(pg_catalog.convert_to(p_evidence_type, 'UTF8')) ||
    app.private_alert_dfir_hash_field_v1(pg_catalog.convert_to(p_classification::text, 'UTF8')) ||
    app.private_alert_dfir_hash_field_v1(
      pg_catalog.convert_to(pg_catalog.encode(p_content_sha256, 'hex'), 'UTF8')
    ) ||
    app.private_alert_dfir_hash_field_v1(pg_catalog.convert_to(p_detected_mime, 'UTF8')) ||
    app.private_alert_dfir_hash_field_v1(pg_catalog.convert_to(p_source, 'UTF8')) ||
    pg_catalog.int8send(p_size_bytes) ||
    pg_catalog.int8send(
      (extract(epoch FROM p_collected_at) * 1000000)::bigint
    ) ||
    app.private_alert_dfir_hash_field_v1(pg_catalog.uuid_send(p_collected_by)) ||
    app.private_alert_dfir_hash_field_v1(
      pg_catalog.convert_to(p_initial_scan_state::text, 'UTF8')
    ) ||
    app.private_alert_dfir_hash_field_v1(
      CASE WHEN p_initial_retention_until IS NULL THEN ''::bytea
      ELSE pg_catalog.convert_to(
        app.private_alert_dfir_instant_text_v1(p_initial_retention_until), 'UTF8'
      ) END
    ) ||
    app.private_alert_dfir_hash_field_v1(
      CASE WHEN p_initial_legal_hold THEN pg_catalog.decode('01', 'hex')
      ELSE pg_catalog.decode('00', 'hex') END
    )
  )
$function$;--> statement-breakpoint
ALTER FUNCTION app.private_alert_dfir_anchor_hash_v1(
  uuid,uuid,uuid,uuid,text,text,text,public.dfir_evidence_classification,
  bytea,text,text,bigint,timestamp with time zone,uuid,
  public.dfir_scan_state,timestamp with time zone,boolean
) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_alert_dfir_anchor_hash_v1(
  uuid,uuid,uuid,uuid,text,text,text,public.dfir_evidence_classification,
  bytea,text,text,bigint,timestamp with time zone,uuid,
  public.dfir_scan_state,timestamp with time zone,boolean
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;--> statement-breakpoint

CREATE FUNCTION app.private_dfir_custody_hash_v1(
  p_previous_hash bytea,
  p_event_id uuid,
  p_tenant_id uuid,
  p_evidence_id uuid,
  p_sequence bigint,
  p_action public.dfir_custody_action,
  p_actor_id uuid,
  p_reason text,
  p_state_value text,
  p_occurred_at timestamp with time zone
)
RETURNS bytea
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
  SELECT pg_catalog.sha256(
    app.private_alert_dfir_hash_field_v1(
      pg_catalog.convert_to('periapsis:dfir:custody-event:v1', 'UTF8')
    ) ||
    app.private_alert_dfir_hash_field_v1(p_previous_hash) ||
    app.private_alert_dfir_hash_field_v1(pg_catalog.uuid_send(p_event_id)) ||
    app.private_alert_dfir_hash_field_v1(pg_catalog.uuid_send(p_tenant_id)) ||
    app.private_alert_dfir_hash_field_v1(pg_catalog.uuid_send(p_evidence_id)) ||
    pg_catalog.int8send(p_sequence) ||
    app.private_alert_dfir_hash_field_v1(pg_catalog.convert_to(p_action::text, 'UTF8')) ||
    app.private_alert_dfir_hash_field_v1(pg_catalog.uuid_send(p_actor_id)) ||
    app.private_alert_dfir_hash_field_v1(pg_catalog.convert_to(p_reason, 'UTF8')) ||
    app.private_alert_dfir_hash_field_v1(pg_catalog.convert_to(p_state_value, 'UTF8')) ||
    pg_catalog.int8send(
      (extract(epoch FROM p_occurred_at) * 1000000)::bigint
    )
  )
$function$;--> statement-breakpoint
ALTER FUNCTION app.private_dfir_custody_hash_v1(
  bytea,uuid,uuid,uuid,bigint,public.dfir_custody_action,uuid,text,text,
  timestamp with time zone
) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_dfir_custody_hash_v1(
  bytea,uuid,uuid,uuid,bigint,public.dfir_custody_action,uuid,text,text,
  timestamp with time zone
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;--> statement-breakpoint

CREATE FUNCTION app.reserve_alert_investigation_command_v1(
  p_command_id uuid,
  p_alert_id uuid,
  p_operation text,
  p_resource_id uuid,
  p_result_version bigint,
  p_key_digest bytea,
  p_request_digest bytea
)
RETURNS TABLE(
  command_id uuid,
  result_resource_id uuid,
  result_version bigint,
  result_snapshot jsonb,
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
  operation_is_create boolean;
  command_record public.alert_dfir_resource_commands%ROWTYPE;
  snapshot_record public.alert_dfir_resource_command_results%ROWTYPE;
  inserted_rows bigint;
BEGIN
  SELECT mapping.permission_key, mapping.is_create
  INTO expected_permission, operation_is_create
  FROM (VALUES
    ('dfir.alert.evidence.create', 'dfir.evidence.manage', true),
    ('dfir.alert.evidence.custody.append', 'dfir.evidence.manage', false),
    ('dfir.alert.task.create', 'dfir.task.manage', true),
    ('dfir.alert.task.transition', 'dfir.task.manage', false),
    ('dfir.alert.task.assign', 'dfir.task.manage', false),
    ('dfir.alert.task.reschedule', 'dfir.task.manage', false),
    ('dfir.alert.task.checklist.replace', 'dfir.task.manage', false),
    ('dfir.alert.relationship.create', 'dfir.relationship.manage', true),
    ('dfir.alert.relationship.retract', 'dfir.relationship.manage', false)
  ) AS mapping(operation, permission_key, is_create)
  WHERE mapping.operation = p_operation;

  IF p_command_id IS NULL
     OR uuid_extract_version(p_command_id) IS DISTINCT FROM 7
     OR p_alert_id IS NULL
     OR uuid_extract_version(p_alert_id) IS DISTINCT FROM 7
     OR p_resource_id IS NULL
     OR uuid_extract_version(p_resource_id) IS DISTINCT FROM 7
     OR expected_permission IS NULL
     OR p_result_version NOT BETWEEN 1 AND 9007199254740991
     OR operation_is_create AND p_result_version <> 1
     OR NOT operation_is_create AND p_result_version < 2
     OR p_key_digest IS NULL OR octet_length(p_key_digest) <> 32
     OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32 THEN
    RAISE EXCEPTION 'Alert investigation command binding is invalid'
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
    RAISE EXCEPTION 'Alert investigation human authority is unavailable'
      USING ERRCODE = '42501';
  END IF;

  PERFORM 1
  FROM public.alerts AS alert
  WHERE alert.tenant_id = context_tenant
    AND alert.id = p_alert_id
    AND alert.deleted_at IS NULL
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Alert is unavailable' USING ERRCODE = 'P0002';
  END IF;
  IF NOT app.private_current_alert_dfir_manage_scope_allows_v1(
    expected_permission, p_alert_id
  ) THEN
    RAISE EXCEPTION 'Alert investigation authority is required'
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
    RAISE EXCEPTION 'Alert investigation idempotency key conflicts'
      USING ERRCODE = '23505',
            CONSTRAINT = 'alert_dfir_resource_commands_replay_key';
  END IF;

  IF inserted_rows = 0 THEN
    SELECT result.* INTO snapshot_record
    FROM public.alert_dfir_resource_command_results AS result
    WHERE result.tenant_id = context_tenant
      AND result.command_id = command_record.command_id
      AND result.alert_id = command_record.alert_id
      AND result.operation = command_record.operation
      AND result.resource_id = command_record.resource_id
      AND result.result_version = command_record.result_version;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'Alert investigation replay snapshot is unavailable'
        USING ERRCODE = '55000';
    END IF;
  END IF;

  RETURN QUERY SELECT command_record.command_id,
                      command_record.resource_id,
                      command_record.result_version,
                      CASE WHEN inserted_rows = 0
                        THEN snapshot_record.result_snapshot ELSE NULL END,
                      inserted_rows = 0;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.reserve_alert_investigation_command_v1(
  uuid,uuid,text,uuid,bigint,bytea,bytea
) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.reserve_alert_investigation_command_v1(
  uuid,uuid,text,uuid,bigint,bytea,bytea
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.reserve_alert_investigation_command_v1(
  uuid,uuid,text,uuid,bigint,bytea,bytea
) TO periapsis_api;--> statement-breakpoint

CREATE FUNCTION app.store_alert_investigation_command_result_v1(
  p_command_id uuid,
  p_result_snapshot jsonb
)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_user uuid := app.context_user_id();
  actor_membership uuid := app.current_tenant_membership_id();
  command_record public.alert_dfir_resource_commands%ROWTYPE;
  expected_kind text;
  resource_document jsonb;
BEGIN
  SELECT command.* INTO command_record
  FROM public.alert_dfir_resource_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.command_id = p_command_id
    AND command.actor_user_id = actor_user
    AND command.actor_membership_id = actor_membership
  FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Alert investigation command is unavailable'
      USING ERRCODE = '23503';
  END IF;

  expected_kind := CASE
    WHEN command_record.operation IN (
      'dfir.alert.evidence.create', 'dfir.alert.evidence.custody.append'
    ) THEN 'alert_evidence'
    WHEN command_record.operation IN (
      'dfir.alert.task.create', 'dfir.alert.task.transition',
      'dfir.alert.task.assign', 'dfir.alert.task.reschedule',
      'dfir.alert.task.checklist.replace'
    ) THEN 'alert_task'
    WHEN command_record.operation IN (
      'dfir.alert.relationship.create', 'dfir.alert.relationship.retract'
    ) THEN 'alert_relationship'
    ELSE NULL
  END;
  resource_document := CASE expected_kind
    WHEN 'alert_evidence' THEN p_result_snapshot -> 'evidence'
    WHEN 'alert_task' THEN p_result_snapshot -> 'task'
    WHEN 'alert_relationship' THEN p_result_snapshot -> 'relationship'
    ELSE NULL
  END;

  IF expected_kind IS NULL
     OR p_result_snapshot IS NULL
     OR jsonb_typeof(p_result_snapshot) <> 'object'
     OR octet_length(p_result_snapshot::text) > 16777216
     OR p_result_snapshot ->> 'kind' IS DISTINCT FROM expected_kind
     OR resource_document IS NULL
     OR jsonb_typeof(resource_document) <> 'object'
     OR resource_document ->> 'tenantId' IS DISTINCT FROM context_tenant::text
     OR resource_document ->> 'alertId' IS DISTINCT FROM command_record.alert_id::text
     OR resource_document ->> 'id' IS DISTINCT FROM command_record.resource_id::text
     OR resource_document ->> 'version' IS DISTINCT FROM command_record.result_version::text THEN
    RAISE EXCEPTION 'Alert investigation result snapshot is invalid'
      USING ERRCODE = '22023';
  END IF;

  INSERT INTO public.alert_dfir_resource_command_results (
    command_id, tenant_id, alert_id, operation, resource_id,
    result_version, result_snapshot
  ) VALUES (
    command_record.command_id, command_record.tenant_id,
    command_record.alert_id, command_record.operation,
    command_record.resource_id, command_record.result_version,
    p_result_snapshot
  );
  RETURN true;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.store_alert_investigation_command_result_v1(uuid,jsonb)
  OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.store_alert_investigation_command_result_v1(uuid,jsonb)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.store_alert_investigation_command_result_v1(uuid,jsonb)
  TO periapsis_api;--> statement-breakpoint

CREATE FUNCTION app.require_alert_investigation_result_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF NEW.operation LIKE 'dfir.alert.%'
     AND NOT EXISTS (
       SELECT 1
       FROM public.alert_dfir_resource_command_results AS result
       WHERE result.tenant_id = NEW.tenant_id
         AND result.command_id = NEW.command_id
         AND result.alert_id = NEW.alert_id
         AND result.operation = NEW.operation
         AND result.resource_id = NEW.resource_id
         AND result.result_version = NEW.result_version
     ) THEN
    RAISE EXCEPTION 'Alert investigation command result is required'
      USING ERRCODE = '23514';
  END IF;
  RETURN NULL;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.require_alert_investigation_result_v1()
  OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.require_alert_investigation_result_v1()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;--> statement-breakpoint
CREATE CONSTRAINT TRIGGER alert_dfir_resource_commands_result_required_v1
AFTER INSERT ON public.alert_dfir_resource_commands
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.require_alert_investigation_result_v1();--> statement-breakpoint

CREATE FUNCTION app.create_alert_dfir_evidence_v1(
  p_command_id uuid,
  p_evidence_id uuid,
  p_alert_id uuid,
  p_storage_object_id uuid,
  p_title text,
  p_description text,
  p_evidence_type text,
  p_classification public.dfir_evidence_classification,
  p_collected_at timestamp with time zone,
  p_source text,
  p_retention_until timestamp with time zone,
  p_legal_hold boolean,
  p_custody_event_id uuid,
  p_anchor_hash bytea,
  p_event_hash bytea
)
RETURNS TABLE(evidence_id uuid, evidence_version bigint)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid := app.current_tenant_membership_id();
  actor_user uuid := app.context_user_id();
  command_record public.alert_dfir_resource_commands%ROWTYPE;
  storage_record public.dfir_storage_objects%ROWTYPE;
  computed_anchor bytea;
  computed_event bytea;
BEGIN
  IF p_command_id IS NULL
     OR p_evidence_id IS NULL OR uuid_extract_version(p_evidence_id) IS DISTINCT FROM 7
     OR p_alert_id IS NULL OR uuid_extract_version(p_alert_id) IS DISTINCT FROM 7
     OR p_storage_object_id IS NULL OR uuid_extract_version(p_storage_object_id) IS DISTINCT FROM 7
     OR p_custody_event_id IS NULL OR uuid_extract_version(p_custody_event_id) IS DISTINCT FROM 7
     OR p_collected_at IS NULL OR p_collected_at > transaction_timestamp() + interval '5 minutes'
     OR p_retention_until < p_collected_at
     OR p_anchor_hash IS NULL OR octet_length(p_anchor_hash) <> 32
     OR p_event_hash IS NULL OR octet_length(p_event_hash) <> 32 THEN
    RAISE EXCEPTION 'Alert evidence collection input is invalid' USING ERRCODE = '22023';
  END IF;

  SELECT command.* INTO command_record
  FROM public.alert_dfir_resource_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.command_id = p_command_id
    AND command.actor_user_id = actor_user
    AND command.actor_membership_id = actor_membership
  FOR SHARE;
  IF NOT FOUND
     OR command_record.alert_id IS DISTINCT FROM p_alert_id
     OR command_record.operation IS DISTINCT FROM 'dfir.alert.evidence.create'
     OR command_record.resource_id IS DISTINCT FROM p_evidence_id
     OR command_record.result_version IS DISTINCT FROM 1 THEN
    RAISE EXCEPTION 'Alert evidence command binding is unavailable' USING ERRCODE = '23503';
  END IF;

  SELECT storage.* INTO storage_record
  FROM public.dfir_storage_objects AS storage
  JOIN public.dfir_attachments AS attachment
    ON attachment.tenant_id = storage.tenant_id
   AND attachment.storage_object_id = storage.id
  WHERE storage.tenant_id = context_tenant
    AND storage.id = p_storage_object_id
    AND attachment.subject_kind = 'alert'
    AND attachment.alert_id = p_alert_id
    AND attachment.case_id IS NULL AND attachment.ioc_id IS NULL
    AND attachment.asset_id IS NULL AND attachment.evidence_id IS NULL
    AND attachment.task_id IS NULL
  FOR UPDATE OF storage, attachment;
  IF NOT FOUND
     OR storage_record.state NOT IN ('quarantined','scanning','available','rejected','scan_failed','retained')
     OR storage_record.content_sha256 IS NULL OR octet_length(storage_record.content_sha256) <> 32
     OR storage_record.size_bytes NOT BETWEEN 1 AND 5000000000
     OR storage_record.detected_mime IS NULL OR storage_record.verified_at IS NULL
     OR storage_record.classification IS DISTINCT FROM p_classification
     OR storage_record.retention_until IS DISTINCT FROM p_retention_until
     OR storage_record.legal_hold IS DISTINCT FROM p_legal_hold
     OR storage_record.state = 'retained' AND NOT storage_record.legal_hold
        AND NOT coalesce(storage_record.retention_until > p_collected_at, false) THEN
    RAISE EXCEPTION 'verified Alert evidence storage is not collectable' USING ERRCODE = '55000';
  END IF;

  computed_anchor := app.private_alert_dfir_anchor_hash_v1(
    p_evidence_id, context_tenant, p_alert_id, p_storage_object_id,
    p_title, p_description, p_evidence_type, p_classification,
    storage_record.content_sha256, storage_record.detected_mime, p_source,
    storage_record.size_bytes, p_collected_at, actor_membership,
    storage_record.state, p_retention_until, p_legal_hold
  );
  computed_event := app.private_dfir_custody_hash_v1(
    computed_anchor, p_custody_event_id, context_tenant, p_evidence_id,
    1, 'collected', actor_user, 'initial collection', '', p_collected_at
  );
  IF computed_anchor IS DISTINCT FROM p_anchor_hash
     OR computed_event IS DISTINCT FROM p_event_hash THEN
    RAISE EXCEPTION 'Alert evidence custody hashes are invalid' USING ERRCODE = '22023';
  END IF;

  INSERT INTO public.dfir_evidence (
    id, tenant_id, alert_id, case_id, storage_object_id, title, description,
    evidence_type, classification, content_sha256, size_bytes, detected_mime,
    collected_at, collected_by_membership_id, source,
    initial_retention_until, retention_until, initial_legal_hold, legal_hold,
    initial_scan_state, scan_state, sealed, destroyed, anchor_hash,
    custody_head_hash, custody_count, version, created_at, updated_at
  ) VALUES (
    p_evidence_id, context_tenant, p_alert_id, NULL, p_storage_object_id,
    p_title, p_description, p_evidence_type, p_classification,
    storage_record.content_sha256, storage_record.size_bytes,
    storage_record.detected_mime, p_collected_at, actor_membership, p_source,
    p_retention_until, p_retention_until, p_legal_hold, p_legal_hold,
    storage_record.state, storage_record.state, false, false, p_anchor_hash,
    p_event_hash, 1, 1, transaction_timestamp(), transaction_timestamp()
  );
  INSERT INTO public.dfir_custody_events (
    id, tenant_id, evidence_id, sequence, action, actor_principal_kind,
    actor_id, actor_membership_id, actor_user_id, actor_service_account_id,
    reason, state_value, previous_hash, event_hash, occurred_at
  ) VALUES (
    p_custody_event_id, context_tenant, p_evidence_id, 1, 'collected',
    'human', actor_user, actor_membership, actor_user, NULL,
    'initial collection', '', p_anchor_hash, p_event_hash, p_collected_at
  );
  RETURN QUERY SELECT p_evidence_id, 1::bigint;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.create_alert_dfir_evidence_v1(
  uuid,uuid,uuid,uuid,text,text,text,public.dfir_evidence_classification,
  timestamp with time zone,text,timestamp with time zone,boolean,uuid,bytea,bytea
) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.create_alert_dfir_evidence_v1(
  uuid,uuid,uuid,uuid,text,text,text,public.dfir_evidence_classification,
  timestamp with time zone,text,timestamp with time zone,boolean,uuid,bytea,bytea
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.create_alert_dfir_evidence_v1(
  uuid,uuid,uuid,uuid,text,text,text,public.dfir_evidence_classification,
  timestamp with time zone,text,timestamp with time zone,boolean,uuid,bytea,bytea
) TO periapsis_api;--> statement-breakpoint

CREATE FUNCTION app.append_alert_dfir_custody_event_v1(
  p_command_id uuid,
  p_evidence_id uuid,
  p_alert_id uuid,
  p_expected_version bigint,
  p_custody_event_id uuid,
  p_action public.dfir_custody_action,
  p_reason text,
  p_state_value text,
  p_previous_hash bytea,
  p_event_hash bytea,
  p_occurred_at timestamp with time zone
)
RETURNS TABLE(evidence_id uuid, evidence_version bigint)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid := app.current_tenant_membership_id();
  actor_user uuid := app.context_user_id();
  command_record public.alert_dfir_resource_commands%ROWTYPE;
  target public.dfir_evidence%ROWTYPE;
  previous_occurred_at timestamp with time zone;
  next_scan_state public.dfir_scan_state;
  next_retention timestamp with time zone;
  next_version bigint;
  affected_rows bigint;
  computed_hash bytea;
BEGIN
  IF p_evidence_id IS NULL OR p_alert_id IS NULL
     OR p_expected_version NOT BETWEEN 1 AND 999
     OR p_custody_event_id IS NULL OR uuid_extract_version(p_custody_event_id) IS DISTINCT FROM 7
     OR p_action IS NULL OR p_action = 'collected'
     OR p_reason IS NULL OR btrim(p_reason) = '' OR octet_length(p_reason) > 2000
     OR p_reason ~ '[[:cntrl:]]' OR p_state_value IS NULL OR octet_length(p_state_value) > 512
     OR p_state_value ~ '[[:cntrl:]]' OR p_occurred_at IS NULL
     OR p_previous_hash IS NULL OR octet_length(p_previous_hash) <> 32
     OR p_event_hash IS NULL OR octet_length(p_event_hash) <> 32 THEN
    RAISE EXCEPTION 'Alert custody input is invalid' USING ERRCODE = '22023';
  END IF;
  SELECT command.* INTO command_record
  FROM public.alert_dfir_resource_commands AS command
  WHERE command.tenant_id = context_tenant AND command.command_id = p_command_id
    AND command.actor_user_id = actor_user AND command.actor_membership_id = actor_membership
  FOR SHARE;
  IF NOT FOUND OR command_record.alert_id IS DISTINCT FROM p_alert_id
     OR command_record.operation IS DISTINCT FROM 'dfir.alert.evidence.custody.append'
     OR command_record.resource_id IS DISTINCT FROM p_evidence_id
     OR command_record.result_version IS DISTINCT FROM p_expected_version + 1 THEN
    RAISE EXCEPTION 'Alert custody command binding is unavailable' USING ERRCODE = '23503';
  END IF;
  SELECT evidence.* INTO target
  FROM public.dfir_evidence AS evidence
  WHERE evidence.tenant_id = context_tenant AND evidence.id = p_evidence_id
    AND evidence.alert_id = p_alert_id AND evidence.case_id IS NULL
  FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Alert evidence was not found' USING ERRCODE = 'P0002'; END IF;
  IF target.version IS DISTINCT FROM p_expected_version THEN
    RAISE EXCEPTION 'Alert evidence version conflict' USING ERRCODE = '40001';
  END IF;
  IF target.destroyed OR target.custody_count IS DISTINCT FROM target.version
     OR target.custody_head_hash IS DISTINCT FROM p_previous_hash THEN
    RAISE EXCEPTION 'Alert custody chain cannot advance' USING ERRCODE = '55000';
  END IF;
  SELECT event.occurred_at INTO STRICT previous_occurred_at
  FROM public.dfir_custody_events AS event
  WHERE event.tenant_id = context_tenant AND event.evidence_id = target.id
    AND event.sequence = target.custody_count;
  IF p_occurred_at < previous_occurred_at
     OR p_occurred_at > transaction_timestamp() + interval '5 minutes' THEN
    RAISE EXCEPTION 'Alert custody event time is invalid' USING ERRCODE = '22023';
  END IF;

  CASE p_action
    WHEN 'accessed', 'transferred' THEN
      IF p_state_value <> '' THEN RAISE EXCEPTION 'Alert custody state is invalid' USING ERRCODE = '22023'; END IF;
    WHEN 'sealed' THEN
      IF target.sealed OR p_state_value <> '' THEN RAISE EXCEPTION 'Alert custody state is invalid' USING ERRCODE = '22023'; END IF;
    WHEN 'unsealed' THEN
      IF NOT target.sealed OR p_state_value <> '' THEN RAISE EXCEPTION 'Alert custody state is invalid' USING ERRCODE = '22023'; END IF;
    WHEN 'legal_hold_placed' THEN
      IF target.legal_hold OR p_state_value <> 'true' THEN RAISE EXCEPTION 'Alert custody state is invalid' USING ERRCODE = '22023'; END IF;
    WHEN 'legal_hold_released' THEN
      IF NOT target.legal_hold OR p_state_value <> 'false' THEN RAISE EXCEPTION 'Alert custody state is invalid' USING ERRCODE = '22023'; END IF;
    WHEN 'retention_changed' THEN
      IF p_state_value = 'none' THEN next_retention := NULL;
      ELSE
        BEGIN next_retention := p_state_value::timestamp with time zone;
        EXCEPTION WHEN invalid_datetime_format OR datetime_field_overflow THEN
          RAISE EXCEPTION 'Alert custody retention value is invalid' USING ERRCODE = '22023';
        END;
        IF next_retention < target.collected_at THEN RAISE EXCEPTION 'Alert custody retention value is invalid' USING ERRCODE = '22023'; END IF;
      END IF;
      IF next_retention IS NOT DISTINCT FROM target.retention_until THEN RAISE EXCEPTION 'Alert custody retention is unchanged' USING ERRCODE = '22023'; END IF;
    WHEN 'scan_state_changed' THEN
      BEGIN next_scan_state := p_state_value::public.dfir_scan_state;
      EXCEPTION WHEN invalid_text_representation THEN RAISE EXCEPTION 'Alert custody scan state is invalid' USING ERRCODE = '22023'; END;
      IF NOT (CASE target.scan_state
        WHEN 'pending_upload' THEN next_scan_state = 'uploaded'
        WHEN 'uploaded' THEN next_scan_state = 'verifying'
        WHEN 'verifying' THEN next_scan_state IN ('quarantined','rejected')
        WHEN 'quarantined' THEN next_scan_state = 'scanning'
        WHEN 'scanning' THEN next_scan_state IN ('available','rejected','scan_failed')
        WHEN 'scan_failed' THEN next_scan_state = 'scanning'
        WHEN 'available' THEN next_scan_state IN ('retained','deleted')
        WHEN 'retained' THEN next_scan_state = 'available'
        ELSE false END) THEN
        RAISE EXCEPTION 'Alert custody scan transition is invalid' USING ERRCODE = '22023';
      END IF;
      IF next_scan_state = 'deleted' AND (target.legal_hold OR target.sealed OR target.retention_until > p_occurred_at)
         OR next_scan_state = 'retained' AND NOT target.legal_hold AND NOT coalesce(target.retention_until > p_occurred_at, false)
         OR target.scan_state = 'retained' AND next_scan_state = 'available'
            AND (target.legal_hold OR coalesce(target.retention_until > p_occurred_at, false)) THEN
        RAISE EXCEPTION 'Alert custody transition violates retention policy' USING ERRCODE = '55000';
      END IF;
    WHEN 'destroyed' THEN
      IF p_state_value <> '' OR target.scan_state <> 'available' OR target.legal_hold
         OR target.sealed OR target.retention_until > p_occurred_at THEN
        RAISE EXCEPTION 'Alert evidence cannot be destroyed' USING ERRCODE = '55000';
      END IF;
      next_scan_state := 'deleted';
    ELSE RAISE EXCEPTION 'Alert custody action is invalid' USING ERRCODE = '22023';
  END CASE;

  next_version := target.version + 1;
  computed_hash := app.private_dfir_custody_hash_v1(
    p_previous_hash, p_custody_event_id, context_tenant, target.id,
    next_version, p_action, actor_user, p_reason, p_state_value, p_occurred_at
  );
  IF computed_hash IS DISTINCT FROM p_event_hash THEN
    RAISE EXCEPTION 'Alert custody event hash is invalid' USING ERRCODE = '22023';
  END IF;
  INSERT INTO public.dfir_custody_events (
    id, tenant_id, evidence_id, sequence, action, actor_principal_kind,
    actor_id, actor_membership_id, actor_user_id, actor_service_account_id,
    reason, state_value, previous_hash, event_hash, occurred_at
  ) VALUES (
    p_custody_event_id, context_tenant, target.id, next_version, p_action,
    'human', actor_user, actor_membership, actor_user, NULL,
    p_reason, p_state_value, p_previous_hash, p_event_hash, p_occurred_at
  );
  UPDATE public.dfir_evidence AS evidence
  SET scan_state = CASE WHEN p_action IN ('scan_state_changed','destroyed') THEN next_scan_state ELSE evidence.scan_state END,
      retention_until = CASE WHEN p_action = 'retention_changed' THEN next_retention ELSE evidence.retention_until END,
      legal_hold = CASE WHEN p_action = 'legal_hold_placed' THEN true WHEN p_action = 'legal_hold_released' THEN false ELSE evidence.legal_hold END,
      sealed = CASE WHEN p_action = 'sealed' THEN true WHEN p_action = 'unsealed' THEN false ELSE evidence.sealed END,
      destroyed = evidence.destroyed OR p_action = 'destroyed' OR p_action = 'scan_state_changed' AND next_scan_state = 'deleted',
      custody_head_hash = p_event_hash, custody_count = next_version,
      version = next_version, updated_at = greatest(transaction_timestamp(), p_occurred_at)
  WHERE evidence.tenant_id = context_tenant AND evidence.id = target.id;

  IF p_action IN ('scan_state_changed','destroyed','retention_changed','legal_hold_placed','legal_hold_released') THEN
    UPDATE public.dfir_storage_objects AS storage
    SET state = CASE WHEN p_action IN ('scan_state_changed','destroyed') THEN next_scan_state ELSE storage.state END,
        retention_until = CASE WHEN p_action = 'retention_changed' THEN next_retention ELSE storage.retention_until END,
        legal_hold = CASE WHEN p_action = 'legal_hold_placed' THEN true WHEN p_action = 'legal_hold_released' THEN false ELSE storage.legal_hold END,
        version = storage.version + 1, updated_at = greatest(transaction_timestamp(), p_occurred_at)
    WHERE storage.tenant_id = context_tenant AND storage.id = target.storage_object_id
      AND storage.version < 9007199254740991 AND storage.state = target.scan_state
      AND storage.retention_until IS NOT DISTINCT FROM target.retention_until
      AND storage.legal_hold IS NOT DISTINCT FROM target.legal_hold;
    GET DIAGNOSTICS affected_rows = ROW_COUNT;
    IF affected_rows <> 1 THEN RAISE EXCEPTION 'Alert storage and evidence projections have drifted' USING ERRCODE = '55000'; END IF;
    IF p_action IN ('scan_state_changed','destroyed') THEN
      IF next_scan_state = 'deleted' THEN
        DELETE FROM public.dfir_attachments WHERE tenant_id = context_tenant AND storage_object_id = target.storage_object_id;
      ELSE
        UPDATE public.dfir_attachments SET scan_state = next_scan_state,
          visibility = CASE WHEN next_scan_state = 'available' THEN visibility ELSE 'private'::public.dfir_visibility END,
          version = version + 1
        WHERE tenant_id = context_tenant AND storage_object_id = target.storage_object_id;
      END IF;
    END IF;
  END IF;
  RETURN QUERY SELECT target.id, next_version;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.append_alert_dfir_custody_event_v1(
  uuid,uuid,uuid,bigint,uuid,public.dfir_custody_action,text,text,bytea,bytea,
  timestamp with time zone
) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.append_alert_dfir_custody_event_v1(
  uuid,uuid,uuid,bigint,uuid,public.dfir_custody_action,text,text,bytea,bytea,
  timestamp with time zone
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.append_alert_dfir_custody_event_v1(
  uuid,uuid,uuid,bigint,uuid,public.dfir_custody_action,text,text,bytea,bytea,
  timestamp with time zone
) TO periapsis_api;--> statement-breakpoint

CREATE FUNCTION app.validate_dfir_relationship_retraction_root_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  target public.dfir_relationships%ROWTYPE;
BEGIN
  SELECT relationship.* INTO target
  FROM public.dfir_relationships AS relationship
  WHERE relationship.tenant_id = NEW.tenant_id
    AND relationship.id = NEW.relationship_id
  FOR SHARE;
  IF NOT FOUND
     OR NEW.alert_id IS DISTINCT FROM target.alert_id
     OR NEW.case_id IS DISTINCT FROM target.case_id
     OR NEW.prior_version IS DISTINCT FROM target.version
     OR NEW.result_version IS DISTINCT FROM target.version + 1 THEN
    RAISE EXCEPTION 'DFIR relationship retraction root or revision is invalid'
      USING ERRCODE = '23503';
  END IF;
  RETURN NEW;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.validate_dfir_relationship_retraction_root_v1()
  OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.validate_dfir_relationship_retraction_root_v1()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
CREATE TRIGGER dfir_relationship_retractions_validate_root_v1
BEFORE INSERT ON public.dfir_relationship_retractions
FOR EACH ROW EXECUTE FUNCTION app.validate_dfir_relationship_retraction_root_v1();--> statement-breakpoint

CREATE FUNCTION app.guard_dfir_relationship_identity_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'DFIR relationships are append-only' USING ERRCODE = '55000';
  END IF;
  IF NEW.id IS DISTINCT FROM OLD.id OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.alert_id IS DISTINCT FROM OLD.alert_id OR NEW.case_id IS DISTINCT FROM OLD.case_id
     OR NEW.source_kind IS DISTINCT FROM OLD.source_kind OR NEW.source_id IS DISTINCT FROM OLD.source_id
     OR NEW.source_external_type IS DISTINCT FROM OLD.source_external_type
     OR NEW.source_external_id IS DISTINCT FROM OLD.source_external_id
     OR NEW.target_kind IS DISTINCT FROM OLD.target_kind OR NEW.target_id IS DISTINCT FROM OLD.target_id
     OR NEW.target_external_type IS DISTINCT FROM OLD.target_external_type
     OR NEW.target_external_id IS DISTINCT FROM OLD.target_external_id
     OR NEW.relationship_type IS DISTINCT FROM OLD.relationship_type
     OR NEW.metadata IS DISTINCT FROM OLD.metadata
     OR NEW.created_by_membership_id IS DISTINCT FROM OLD.created_by_membership_id
     OR NEW.created_at IS DISTINCT FROM OLD.created_at
     OR NEW.version IS DISTINCT FROM OLD.version + 1
     OR NOT EXISTS (
       SELECT 1 FROM public.dfir_relationship_retractions AS retraction
       WHERE retraction.tenant_id = OLD.tenant_id
         AND retraction.relationship_id = OLD.id
         AND retraction.alert_id IS NOT DISTINCT FROM OLD.alert_id
         AND retraction.case_id IS NOT DISTINCT FROM OLD.case_id
         AND retraction.prior_version = OLD.version
         AND retraction.result_version = NEW.version
     ) THEN
    RAISE EXCEPTION 'DFIR relationship identity is immutable' USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.guard_dfir_relationship_identity_v1() OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_dfir_relationship_identity_v1()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
CREATE TRIGGER dfir_relationships_identity_v1
BEFORE UPDATE OR DELETE ON public.dfir_relationships
FOR EACH ROW EXECUTE FUNCTION app.guard_dfir_relationship_identity_v1();--> statement-breakpoint

CREATE FUNCTION app.create_alert_dfir_relationship_v1(
  p_command_id uuid,
  p_relationship_id uuid,
  p_alert_id uuid,
  p_source_kind public.dfir_entity_kind,
  p_source_id uuid,
  p_source_external_type text,
  p_source_external_id text,
  p_target_kind public.dfir_entity_kind,
  p_target_id uuid,
  p_target_external_type text,
  p_target_external_id text,
  p_relationship_type text,
  p_metadata jsonb,
  p_created_at timestamp with time zone
)
RETURNS TABLE(relationship_id uuid)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid := app.current_tenant_membership_id();
  actor_user uuid := app.context_user_id();
  command_record public.alert_dfir_resource_commands%ROWTYPE;
BEGIN
  IF p_relationship_id IS NULL OR uuid_extract_version(p_relationship_id) IS DISTINCT FROM 7
     OR p_alert_id IS NULL OR uuid_extract_version(p_alert_id) IS DISTINCT FROM 7
     OR p_source_kind IS NULL OR p_target_kind IS NULL
     OR p_relationship_type IS NULL
     OR p_created_at IS NULL OR p_created_at > transaction_timestamp() + interval '5 minutes'
     OR NOT ((p_source_kind = 'alert' AND p_source_id = p_alert_id)
          OR (p_target_kind = 'alert' AND p_target_id = p_alert_id)) THEN
    RAISE EXCEPTION 'Alert relationship input is invalid' USING ERRCODE = '22023';
  END IF;
  SELECT command.* INTO command_record
  FROM public.alert_dfir_resource_commands AS command
  WHERE command.tenant_id = context_tenant AND command.command_id = p_command_id
    AND command.actor_user_id = actor_user AND command.actor_membership_id = actor_membership
  FOR SHARE;
  IF NOT FOUND OR command_record.alert_id IS DISTINCT FROM p_alert_id
     OR command_record.operation IS DISTINCT FROM 'dfir.alert.relationship.create'
     OR command_record.resource_id IS DISTINCT FROM p_relationship_id
     OR command_record.result_version IS DISTINCT FROM 1 THEN
    RAISE EXCEPTION 'Alert relationship command binding is unavailable' USING ERRCODE = '23503';
  END IF;

  PERFORM pg_advisory_xact_lock(pg_catalog.hashtextextended(
    concat_ws(E'\u001f', context_tenant::text, p_source_kind::text, p_source_id::text,
      p_source_external_type, p_source_external_id, p_target_kind::text, p_target_id::text,
      p_target_external_type, p_target_external_id, p_relationship_type), 0
  ));
  IF EXISTS (
    SELECT 1 FROM public.dfir_relationships AS relationship
    WHERE relationship.tenant_id = context_tenant
      AND relationship.source_kind = p_source_kind
      AND relationship.source_id IS NOT DISTINCT FROM p_source_id
      AND relationship.source_external_type IS NOT DISTINCT FROM p_source_external_type
      AND relationship.source_external_id IS NOT DISTINCT FROM p_source_external_id
      AND relationship.target_kind = p_target_kind
      AND relationship.target_id IS NOT DISTINCT FROM p_target_id
      AND relationship.target_external_type IS NOT DISTINCT FROM p_target_external_type
      AND relationship.target_external_id IS NOT DISTINCT FROM p_target_external_id
      AND relationship.relationship_type = p_relationship_type
      AND NOT EXISTS (
        SELECT 1 FROM public.dfir_relationship_retractions AS retraction
        WHERE retraction.tenant_id = relationship.tenant_id
          AND retraction.relationship_id = relationship.id
      )
  ) THEN
    RAISE EXCEPTION 'active Alert relationship already exists'
      USING ERRCODE = '23505', CONSTRAINT = 'dfir_relationships_active_coordinate_key';
  END IF;
  INSERT INTO public.dfir_relationships (
    id, tenant_id, alert_id, case_id, source_kind, source_id,
    source_external_type, source_external_id, target_kind, target_id,
    target_external_type, target_external_id, relationship_type, metadata,
    created_by_membership_id, version, created_at
  ) VALUES (
    p_relationship_id, context_tenant, p_alert_id, NULL, p_source_kind,
    p_source_id, p_source_external_type, p_source_external_id, p_target_kind,
    p_target_id, p_target_external_type, p_target_external_id,
    p_relationship_type, p_metadata, actor_membership, 1, p_created_at
  );
  RETURN QUERY SELECT p_relationship_id;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.create_alert_dfir_relationship_v1(
  uuid,uuid,uuid,public.dfir_entity_kind,uuid,text,text,
  public.dfir_entity_kind,uuid,text,text,text,jsonb,timestamp with time zone
) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.create_alert_dfir_relationship_v1(
  uuid,uuid,uuid,public.dfir_entity_kind,uuid,text,text,
  public.dfir_entity_kind,uuid,text,text,text,jsonb,timestamp with time zone
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.create_alert_dfir_relationship_v1(
  uuid,uuid,uuid,public.dfir_entity_kind,uuid,text,text,
  public.dfir_entity_kind,uuid,text,text,text,jsonb,timestamp with time zone
) TO periapsis_api;--> statement-breakpoint

CREATE FUNCTION app.retract_alert_dfir_relationship_v1(
  p_command_id uuid,
  p_relationship_id uuid,
  p_alert_id uuid,
  p_expected_version bigint,
  p_retraction_id uuid,
  p_reason text,
  p_retracted_at timestamp with time zone
)
RETURNS TABLE(relationship_id uuid, relationship_version bigint)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid := app.current_tenant_membership_id();
  actor_user uuid := app.context_user_id();
  command_record public.alert_dfir_resource_commands%ROWTYPE;
  target public.dfir_relationships%ROWTYPE;
  next_version bigint;
BEGIN
  IF p_relationship_id IS NULL OR p_alert_id IS NULL
     OR p_expected_version NOT BETWEEN 1 AND 9007199254740990
     OR p_retraction_id IS NULL OR uuid_extract_version(p_retraction_id) IS DISTINCT FROM 7
     OR p_reason IS NULL OR btrim(p_reason) = '' OR octet_length(p_reason) > 2000
     OR p_reason ~ '[[:cntrl:]]' OR p_retracted_at IS NULL
     OR p_retracted_at > transaction_timestamp() + interval '5 minutes' THEN
    RAISE EXCEPTION 'Alert relationship retraction input is invalid' USING ERRCODE = '22023';
  END IF;
  SELECT command.* INTO command_record
  FROM public.alert_dfir_resource_commands AS command
  WHERE command.tenant_id = context_tenant AND command.command_id = p_command_id
    AND command.actor_user_id = actor_user AND command.actor_membership_id = actor_membership
  FOR SHARE;
  IF NOT FOUND OR command_record.alert_id IS DISTINCT FROM p_alert_id
     OR command_record.operation IS DISTINCT FROM 'dfir.alert.relationship.retract'
     OR command_record.resource_id IS DISTINCT FROM p_relationship_id
     OR command_record.result_version IS DISTINCT FROM p_expected_version + 1 THEN
    RAISE EXCEPTION 'Alert relationship retraction command is unavailable' USING ERRCODE = '23503';
  END IF;
  SELECT relationship.* INTO target
  FROM public.dfir_relationships AS relationship
  WHERE relationship.tenant_id = context_tenant AND relationship.id = p_relationship_id
    AND relationship.alert_id = p_alert_id AND relationship.case_id IS NULL
  FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Alert relationship was not found' USING ERRCODE = 'P0002'; END IF;
  IF target.version IS DISTINCT FROM p_expected_version THEN
    RAISE EXCEPTION 'Alert relationship version conflict' USING ERRCODE = '40001';
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.dfir_relationship_retractions AS existing_retraction
    WHERE existing_retraction.tenant_id = context_tenant
      AND existing_retraction.relationship_id = target.id
  ) THEN
    RAISE EXCEPTION 'Alert relationship is already retracted' USING ERRCODE = '55000';
  END IF;
  IF p_retracted_at < target.created_at THEN
    RAISE EXCEPTION 'Alert relationship retraction time is invalid' USING ERRCODE = '22023';
  END IF;
  next_version := target.version + 1;
  INSERT INTO public.dfir_relationship_retractions (
    id, tenant_id, relationship_id, alert_id, case_id,
    retracted_by_membership_id, reason, prior_version, result_version, retracted_at
  ) VALUES (
    p_retraction_id, context_tenant, target.id, target.alert_id, NULL,
    actor_membership, p_reason, target.version, next_version, p_retracted_at
  );
  UPDATE public.dfir_relationships
  SET version = next_version
  WHERE tenant_id = context_tenant AND id = target.id AND version = target.version;
  RETURN QUERY SELECT target.id, next_version;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.retract_alert_dfir_relationship_v1(
  uuid,uuid,uuid,bigint,uuid,text,timestamp with time zone
) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.retract_alert_dfir_relationship_v1(
  uuid,uuid,uuid,bigint,uuid,text,timestamp with time zone
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.retract_alert_dfir_relationship_v1(
  uuid,uuid,uuid,bigint,uuid,text,timestamp with time zone
) TO periapsis_api;--> statement-breakpoint

CREATE FUNCTION app.append_alert_investigation_effects_v1(
  p_alert_id uuid,
  p_operation text,
  p_activity_type text,
  p_audit_action text,
  p_audit_reason text,
  p_outbox_type text,
  p_resource_type text,
  p_resource_id uuid,
  p_resource_version bigint,
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
  expected_activity text;
  expected_audit text;
  expected_outbox text;
  expected_resource text;
  expected_permission text;
  fixed_summary text;
  operation_is_create boolean;
  command_record public.alert_dfir_resource_commands%ROWTYPE;
  actual_version bigint;
  activity_sequence bigint;
  activity_resource_kind public.dfir_entity_kind;
  safe_before jsonb;
  safe_after jsonb;
  safe_metadata jsonb;
BEGIN
  SELECT mapping.activity_type, mapping.audit_action, mapping.outbox_type,
         mapping.resource_type, mapping.permission_key, mapping.summary,
         mapping.is_create, mapping.resource_kind
  INTO expected_activity, expected_audit, expected_outbox,
       expected_resource, expected_permission, fixed_summary,
       operation_is_create, activity_resource_kind
  FROM (VALUES
    ('dfir.alert.evidence.create','alert.evidence.added','dfir.alert.evidence.create','alert.evidence.added.v1','dfir_evidence','dfir.evidence.manage','Alert evidence collected',true,'evidence'::public.dfir_entity_kind),
    ('dfir.alert.evidence.custody.append','alert.evidence.custody_appended','dfir.alert.evidence.custody.append','alert.evidence.custody_appended.v1','dfir_evidence','dfir.evidence.manage','Alert evidence custody updated',false,'evidence'::public.dfir_entity_kind),
    ('dfir.alert.task.create','alert.task.created','dfir.alert.task.create','alert.task.created.v1','dfir_task','dfir.task.manage','Alert investigation task created',true,'task'::public.dfir_entity_kind),
    ('dfir.alert.task.transition','alert.task.transitioned','dfir.alert.task.transition','alert.task.transitioned.v1','dfir_task','dfir.task.manage','Alert investigation task transitioned',false,'task'::public.dfir_entity_kind),
    ('dfir.alert.task.assign','alert.task.assigned','dfir.alert.task.assign','alert.task.assigned.v1','dfir_task','dfir.task.manage','Alert investigation task assigned',false,'task'::public.dfir_entity_kind),
    ('dfir.alert.task.reschedule','alert.task.rescheduled','dfir.alert.task.reschedule','alert.task.rescheduled.v1','dfir_task','dfir.task.manage','Alert investigation task rescheduled',false,'task'::public.dfir_entity_kind),
    ('dfir.alert.task.checklist.replace','alert.task.checklist_replaced','dfir.alert.task.checklist.replace','alert.task.checklist_replaced.v1','dfir_task','dfir.task.manage','Alert investigation task checklist replaced',false,'task'::public.dfir_entity_kind),
    ('dfir.alert.relationship.create','alert.relationship.created','dfir.alert.relationship.create','alert.relationship.created.v1','dfir_relationship','dfir.relationship.manage','Alert relationship created',true,'alert'::public.dfir_entity_kind),
    ('dfir.alert.relationship.retract','alert.relationship.retracted','dfir.alert.relationship.retract','alert.relationship.retracted.v1','dfir_relationship','dfir.relationship.manage','Alert relationship retracted',false,'alert'::public.dfir_entity_kind)
  ) AS mapping(operation,activity_type,audit_action,outbox_type,resource_type,permission_key,summary,is_create,resource_kind)
  WHERE mapping.operation = p_operation;

  IF expected_activity IS NULL
     OR p_activity_type IS DISTINCT FROM expected_activity
     OR p_audit_action IS DISTINCT FROM expected_audit
     OR p_outbox_type IS DISTINCT FROM expected_outbox
     OR p_resource_type IS DISTINCT FROM expected_resource
     OR p_alert_id IS NULL OR uuid_extract_version(p_alert_id) IS DISTINCT FROM 7
     OR p_resource_id IS NULL OR uuid_extract_version(p_resource_id) IS DISTINCT FROM 7
     OR p_resource_version NOT BETWEEN 1 AND 9007199254740991
     OR operation_is_create AND p_resource_version <> 1
     OR NOT operation_is_create AND p_resource_version < 2
     OR p_key_digest IS NULL OR octet_length(p_key_digest) <> 32
     OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32
     OR p_activity_id IS NULL OR uuid_extract_version(p_activity_id) IS DISTINCT FROM 7
     OR p_audit_event_id IS NULL OR uuid_extract_version(p_audit_event_id) IS DISTINCT FROM 7
     OR p_outbox_event_id IS NULL OR uuid_extract_version(p_outbox_event_id) IS DISTINCT FROM 7
     OR p_request_id IS NULL OR uuid_extract_version(p_request_id) IS DISTINCT FROM 7
     OR p_correlation_id IS NULL OR uuid_extract_version(p_correlation_id) IS DISTINCT FROM 7
     OR p_ip_address IS NULL OR p_user_agent IS NULL
     OR octet_length(p_user_agent) NOT BETWEEN 1 AND 1024
     OR p_authentication_method NOT IN ('bootstrap_totp','totp','recovery_code','ldap','oidc','saml','passkey')
     OR p_audit_reason IS NULL OR btrim(p_audit_reason) IS DISTINCT FROM p_audit_reason
     OR octet_length(p_audit_reason) NOT BETWEEN 1 AND 2000 OR p_audit_reason ~ '[[:cntrl:]]'
     OR strpos(p_audit_reason, U&'\2028') > 0 OR strpos(p_audit_reason, U&'\2029') > 0
     OR strpos(p_audit_reason, U&'\200E') > 0 OR strpos(p_audit_reason, U&'\200F') > 0
     OR p_audit_reason ~ U&'[\202A-\202E\2066-\2069]'
     OR p_before IS NULL OR jsonb_typeof(p_before) <> 'object'
     OR p_after IS NULL OR jsonb_typeof(p_after) <> 'object'
     OR p_metadata IS NULL OR jsonb_typeof(p_metadata) <> 'object'
     OR octet_length(p_before::text) > 32768
     OR octet_length(p_after::text) > 32768
     OR octet_length(p_metadata::text) > 32768 THEN
    RAISE EXCEPTION 'Alert investigation effect input is invalid' USING ERRCODE = '22023';
  END IF;
  PERFORM app.lock_current_tenant_authorization_state();
  PERFORM 1 FROM public.tenant_memberships AS membership
  JOIN public.users AS identity ON identity.id = membership.user_id
  WHERE membership.tenant_id = context_tenant AND membership.id = actor_membership
    AND membership.user_id = actor_user AND membership.status = 'active' AND identity.active
  FOR SHARE OF membership, identity;
  IF NOT FOUND THEN RAISE EXCEPTION 'Alert investigation human authority is unavailable' USING ERRCODE = '42501'; END IF;
  PERFORM 1 FROM public.alerts AS alert
  WHERE alert.tenant_id = context_tenant AND alert.id = p_alert_id AND alert.deleted_at IS NULL
  FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Alert is unavailable' USING ERRCODE = 'P0002'; END IF;
  IF NOT app.private_current_alert_dfir_manage_scope_allows_v1(expected_permission,p_alert_id) THEN
    RAISE EXCEPTION 'Alert investigation authority is required' USING ERRCODE = '42501';
  END IF;
  SELECT command.* INTO command_record
  FROM public.alert_dfir_resource_commands AS command
  WHERE command.tenant_id = context_tenant AND command.actor_user_id = actor_user
    AND command.actor_membership_id = actor_membership AND command.operation = p_operation
    AND command.key_digest = p_key_digest
  FOR SHARE;
  IF NOT FOUND OR command_record.request_digest IS DISTINCT FROM p_request_digest
     OR command_record.alert_id IS DISTINCT FROM p_alert_id
     OR command_record.resource_id IS DISTINCT FROM p_resource_id
     OR command_record.result_version IS DISTINCT FROM p_resource_version THEN
    RAISE EXCEPTION 'Alert investigation command reservation is unavailable' USING ERRCODE = '23503';
  END IF;

  IF p_resource_type = 'dfir_evidence' THEN
    SELECT evidence.version INTO actual_version FROM public.dfir_evidence AS evidence
    WHERE evidence.tenant_id = context_tenant AND evidence.id = p_resource_id
      AND evidence.alert_id = p_alert_id AND evidence.case_id IS NULL
    FOR SHARE;
  ELSIF p_resource_type = 'dfir_task' THEN
    SELECT task.version INTO actual_version FROM public.dfir_tasks AS task
    WHERE task.tenant_id = context_tenant AND task.id = p_resource_id
      AND task.alert_id = p_alert_id AND task.case_id IS NULL
    FOR SHARE;
  ELSE
    SELECT relationship.version INTO actual_version FROM public.dfir_relationships AS relationship
    WHERE relationship.tenant_id = context_tenant AND relationship.id = p_resource_id
      AND relationship.alert_id = p_alert_id AND relationship.case_id IS NULL
    FOR SHARE;
  END IF;
  IF NOT FOUND OR actual_version IS DISTINCT FROM p_resource_version
     OR p_operation = 'dfir.alert.relationship.create' AND EXISTS (
       SELECT 1 FROM public.dfir_relationship_retractions
       WHERE tenant_id = context_tenant AND relationship_id = p_resource_id
     )
     OR p_operation = 'dfir.alert.relationship.retract' AND NOT EXISTS (
       SELECT 1 FROM public.dfir_relationship_retractions
       WHERE tenant_id = context_tenant AND relationship_id = p_resource_id
         AND alert_id = p_alert_id AND case_id IS NULL
         AND result_version = p_resource_version
     ) THEN
    RAISE EXCEPTION 'Alert investigation resource projection is unavailable or stale' USING ERRCODE = '23503';
  END IF;

  SELECT coalesce(max(activity.sequence),0)::bigint + 1 INTO activity_sequence
  FROM public.ticket_activities AS activity
  WHERE activity.tenant_id = context_tenant AND activity.alert_id = p_alert_id;
  IF activity_sequence NOT BETWEEN 1 AND 2147483647 THEN
    RAISE EXCEPTION 'Alert activity sequence is exhausted' USING ERRCODE = '54000';
  END IF;
  safe_before := CASE WHEN operation_is_create THEN '{}'::jsonb ELSE jsonb_build_object(
    'resourceId',p_resource_id,'resourceVersion',p_resource_version-1,'contentRedacted',true) END;
  safe_after := jsonb_build_object(
    'resourceId',p_resource_id,'resourceVersion',p_resource_version,'contentRedacted',true);
  safe_metadata := jsonb_build_object(
    'alertId',p_alert_id,'commandId',command_record.command_id,
    'commandOperation',p_operation,'actorMembershipId',actor_membership,
    'contentRedacted',true);
  INSERT INTO public.ticket_activities (
    id,tenant_id,alert_id,case_id,sequence,kind,summary,
    actor_principal_kind,actor_membership_id,actor_user_id,
    actor_service_account_id,origin,details,occurred_at
  ) VALUES (
    p_activity_id,context_tenant,p_alert_id,NULL,activity_sequence::integer,
    p_activity_type,fixed_summary,'human',actor_membership,actor_user,NULL,
    'api',jsonb_build_object('resourceId',p_resource_id,'resourceVersion',p_resource_version,'contentRedacted',true),
    transaction_timestamp()
  );
  INSERT INTO public.dfir_activities (
    id,tenant_id,alert_id,case_id,resource_kind,resource_id,action,summary,
    actor_principal_kind,actor_membership_id,actor_user_id,
    actor_service_account_id,details,occurred_at
  ) VALUES (
    p_activity_id,context_tenant,p_alert_id,NULL,activity_resource_kind,
    p_resource_id,p_audit_action,fixed_summary,'human',actor_membership,
    actor_user,NULL,jsonb_build_object('resourceVersion',p_resource_version,'contentRedacted',true),
    transaction_timestamp()
  );
  INSERT INTO public.audit_events (
    id,tenant_id,sequence,actor_type,actor_user_id,action,resource_type,
    resource_id,request_id,correlation_id,ip_address,user_agent,
    authentication_method,outcome,reason,before,after,metadata
  ) VALUES (
    p_audit_event_id,context_tenant,0,'user',actor_user,p_audit_action,
    p_resource_type,p_resource_id,p_request_id,p_correlation_id,p_ip_address,
    p_user_agent,p_authentication_method,'success',p_audit_reason,
    safe_before,safe_after,safe_metadata
  );
  INSERT INTO public.outbox_events (
    id,tenant_id,aggregate_type,aggregate_id,event_type,schema_version,
    payload,deduplication_key,correlation_id,causation_id,actor_kind,
    actor_id,producer,maximum_audience,occurred_at
  ) VALUES (
    p_outbox_event_id,context_tenant,p_resource_type,p_resource_id,p_outbox_type,1,
    jsonb_build_object('tenantId',context_tenant,'alertId',p_alert_id,
      'resourceId',p_resource_id,'resourceVersion',p_resource_version),
    'alert-investigation:'||command_record.command_id::text,p_correlation_id,
    p_request_id,'human',actor_user,'api','operator',transaction_timestamp()
  );
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.append_alert_investigation_effects_v1(
  uuid,text,text,text,text,text,text,uuid,bigint,bytea,bytea,uuid,
  jsonb,jsonb,jsonb,uuid,uuid,uuid,uuid,inet,text,text
) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.append_alert_investigation_effects_v1(
  uuid,text,text,text,text,text,text,uuid,bigint,bytea,bytea,uuid,
  jsonb,jsonb,jsonb,uuid,uuid,uuid,uuid,inet,text,text
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.append_alert_investigation_effects_v1(
  uuid,text,text,text,text,text,text,uuid,bigint,bytea,bytea,uuid,
  jsonb,jsonb,jsonb,uuid,uuid,uuid,uuid,inet,text,text
) TO periapsis_api;--> statement-breakpoint

CREATE FUNCTION app.advance_dfir_storage_object_as_worker_v3(
  p_storage_object_id uuid,
  p_expected_version bigint,
  p_next_state public.dfir_scan_state,
  p_content_sha256 bytea,
  p_size_bytes bigint,
  p_detected_mime text,
  p_transitioned_at timestamp with time zone,
  p_custody_event_id uuid,
  p_audit_event_id uuid,
  p_outbox_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid
)
RETURNS TABLE(storage_object_id uuid, storage_version bigint, replayed boolean)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  target public.dfir_storage_objects%ROWTYPE;
  evidence_record public.dfir_evidence%ROWTYPE;
  bound_evidence_id uuid;
  next_version bigint;
  next_evidence_version bigint;
  custody_hash bytea;
  attachment_rows bigint;
BEGIN
  IF NOT pg_has_role(session_user,'periapsis_worker','member') THEN
    RAISE EXCEPTION 'DFIR storage transition requires worker role' USING ERRCODE = '42501';
  END IF;
  IF p_storage_object_id IS NULL OR p_expected_version NOT BETWEEN 1 AND 9007199254740990
     OR p_next_state IS NULL OR p_transitioned_at IS NULL
     OR p_custody_event_id IS NULL OR uuid_extract_version(p_custody_event_id) IS DISTINCT FROM 7
     OR p_audit_event_id IS NULL OR uuid_extract_version(p_audit_event_id) IS DISTINCT FROM 7
     OR p_outbox_event_id IS NULL OR uuid_extract_version(p_outbox_event_id) IS DISTINCT FROM 7
     OR p_request_id IS NULL OR uuid_extract_version(p_request_id) IS DISTINCT FROM 7
     OR p_correlation_id IS NULL OR uuid_extract_version(p_correlation_id) IS DISTINCT FROM 7
     OR p_transitioned_at > transaction_timestamp() + interval '5 minutes' THEN
    RAISE EXCEPTION 'DFIR storage transition input is invalid' USING ERRCODE = '22023';
  END IF;

  -- Evidence is the higher-level aggregate. Lock it before storage whenever it
  -- already exists so API custody and worker transitions share one lock order.
  SELECT evidence.id INTO bound_evidence_id
  FROM public.dfir_evidence AS evidence
  WHERE evidence.tenant_id = context_tenant
    AND evidence.storage_object_id = p_storage_object_id;
  IF bound_evidence_id IS NOT NULL THEN
    SELECT evidence.* INTO evidence_record
    FROM public.dfir_evidence AS evidence
    WHERE evidence.tenant_id = context_tenant AND evidence.id = bound_evidence_id
    FOR UPDATE;
  END IF;
  SELECT storage.* INTO target
  FROM public.dfir_storage_objects AS storage
  WHERE storage.tenant_id = context_tenant AND storage.id = p_storage_object_id
  FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'DFIR storage object was not found' USING ERRCODE = 'P0002'; END IF;

  IF target.version = p_expected_version + 1 AND target.state = p_next_state
     AND target.updated_at = p_transitioned_at
     AND target.content_sha256 IS NOT DISTINCT FROM p_content_sha256
     AND target.size_bytes IS NOT DISTINCT FROM p_size_bytes
     AND target.detected_mime IS NOT DISTINCT FROM p_detected_mime
     AND (bound_evidence_id IS NULL OR EXISTS (
       SELECT 1 FROM public.dfir_custody_events AS event
       WHERE event.tenant_id = context_tenant AND event.id = p_custody_event_id
         AND event.evidence_id = bound_evidence_id AND event.action = 'scan_state_changed'
         AND event.state_value = p_next_state::text AND event.occurred_at = p_transitioned_at
     )) THEN
    RETURN QUERY SELECT target.id,target.version,true;
    RETURN;
  END IF;
  IF target.version IS DISTINCT FROM p_expected_version THEN
    RAISE EXCEPTION 'DFIR storage object version conflict' USING ERRCODE = '40001';
  END IF;
  IF target.expected_size_bytes NOT BETWEEN 1 AND 5000000000
     OR p_transitioned_at < target.updated_at THEN
    RAISE EXCEPTION 'DFIR storage projection is stale' USING ERRCODE = '55000';
  END IF;
  IF NOT (CASE target.state
    WHEN 'pending_upload' THEN p_next_state = 'uploaded'
    WHEN 'uploaded' THEN p_next_state = 'verifying'
    WHEN 'verifying' THEN p_next_state IN ('quarantined','rejected')
    WHEN 'quarantined' THEN p_next_state = 'scanning'
    WHEN 'scanning' THEN p_next_state IN ('available','rejected','scan_failed')
    WHEN 'scan_failed' THEN p_next_state = 'scanning'
    WHEN 'available' THEN p_next_state IN ('retained','deleted')
    WHEN 'retained' THEN p_next_state = 'available'
    ELSE false END) THEN
    RAISE EXCEPTION 'DFIR storage state transition is invalid' USING ERRCODE = '22023';
  END IF;
  IF p_next_state = 'deleted' AND (
       target.legal_hold OR target.retention_until > p_transitioned_at
       OR bound_evidence_id IS NOT NULL AND evidence_record.sealed
     )
     OR p_next_state = 'retained' AND NOT target.legal_hold
        AND NOT coalesce(target.retention_until > p_transitioned_at,false)
     OR target.state = 'retained' AND p_next_state = 'available'
        AND (target.legal_hold OR coalesce(target.retention_until > p_transitioned_at,false)) THEN
    RAISE EXCEPTION 'DFIR storage object is retained' USING ERRCODE = '55000';
  END IF;
  IF target.state = 'verifying' AND p_next_state = 'quarantined' THEN
    IF p_content_sha256 IS NULL OR octet_length(p_content_sha256) <> 32
       OR p_size_bytes IS DISTINCT FROM target.expected_size_bytes
       OR p_size_bytes NOT BETWEEN 1 AND 5000000000
       OR p_detected_mime IS NULL OR octet_length(p_detected_mime) NOT BETWEEN 3 AND 512 THEN
      RAISE EXCEPTION 'DFIR verified content projection is invalid' USING ERRCODE = '22023';
    END IF;
  ELSIF p_content_sha256 IS DISTINCT FROM target.content_sha256
        OR p_size_bytes IS DISTINCT FROM target.size_bytes
        OR p_detected_mime IS DISTINCT FROM target.detected_mime THEN
    RAISE EXCEPTION 'DFIR storage transition cannot replace content metadata' USING ERRCODE = '55000';
  END IF;

  next_version := target.version + 1;
  IF bound_evidence_id IS NOT NULL THEN
    IF evidence_record.destroyed OR evidence_record.scan_state IS DISTINCT FROM target.state
       OR evidence_record.retention_until IS DISTINCT FROM target.retention_until
       OR evidence_record.legal_hold IS DISTINCT FROM target.legal_hold
       OR evidence_record.version IS DISTINCT FROM evidence_record.custody_count
       OR evidence_record.version NOT BETWEEN 1 AND 999
       OR p_transitioned_at < evidence_record.updated_at THEN
      RAISE EXCEPTION 'DFIR storage and evidence projections have drifted' USING ERRCODE = '55000';
    END IF;
    next_evidence_version := evidence_record.version + 1;
    custody_hash := app.private_dfir_custody_hash_v1(
      evidence_record.custody_head_hash,p_custody_event_id,context_tenant,
      evidence_record.id,next_evidence_version,'scan_state_changed',p_request_id,
      'automated malware scan state transition',p_next_state::text,p_transitioned_at
    );
    INSERT INTO public.dfir_custody_events (
      id,tenant_id,evidence_id,sequence,action,actor_principal_kind,actor_id,
      actor_membership_id,actor_user_id,actor_service_account_id,reason,
      state_value,previous_hash,event_hash,occurred_at
    ) VALUES (
      p_custody_event_id,context_tenant,evidence_record.id,next_evidence_version,
      'scan_state_changed','system',p_request_id,NULL,NULL,NULL,
      'automated malware scan state transition',p_next_state::text,
      evidence_record.custody_head_hash,custody_hash,p_transitioned_at
    );
    UPDATE public.dfir_evidence
    SET scan_state=p_next_state,destroyed=destroyed OR p_next_state='deleted',
        custody_head_hash=custody_hash,custody_count=next_evidence_version,
        version=next_evidence_version,updated_at=p_transitioned_at
    WHERE tenant_id=context_tenant AND id=evidence_record.id;
  END IF;

  UPDATE public.dfir_storage_objects
  SET state=p_next_state,
      content_sha256=CASE WHEN target.state='verifying' AND p_next_state='quarantined' THEN p_content_sha256 ELSE content_sha256 END,
      size_bytes=CASE WHEN target.state='verifying' AND p_next_state='quarantined' THEN p_size_bytes ELSE size_bytes END,
      detected_mime=CASE WHEN target.state='verifying' AND p_next_state='quarantined' THEN p_detected_mime ELSE detected_mime END,
      verified_at=CASE WHEN target.state='verifying' AND p_next_state='quarantined' THEN p_transitioned_at ELSE verified_at END,
      version=next_version,updated_at=p_transitioned_at
  WHERE tenant_id=context_tenant AND id=target.id;
  IF p_next_state='deleted' AND bound_evidence_id IS NOT NULL THEN
    DELETE FROM public.dfir_attachments AS attachment
    WHERE attachment.tenant_id=context_tenant
      AND attachment.storage_object_id=target.id;
  ELSE
    UPDATE public.dfir_attachments AS attachment
    SET scan_state=p_next_state,
        visibility=CASE WHEN p_next_state='available' THEN visibility ELSE 'private'::public.dfir_visibility END,
        version=version+1
    WHERE attachment.tenant_id=context_tenant
      AND attachment.storage_object_id=target.id;
    GET DIAGNOSTICS attachment_rows = ROW_COUNT;
    IF attachment_rows <> 1 THEN RAISE EXCEPTION 'DFIR storage attachment projection is incomplete' USING ERRCODE = '55000'; END IF;
  END IF;
  INSERT INTO public.audit_events (
    id,tenant_id,sequence,actor_type,action,resource_type,resource_id,
    request_id,correlation_id,authentication_method,outcome,reason,before,after,metadata
  ) VALUES (
    p_audit_event_id,context_tenant,0,'system','dfir.storage.state_changed',
    'dfir_storage_object',target.id,p_request_id,p_correlation_id,'worker','success',
    'automated malware scan state transition',
    jsonb_build_object('state',target.state,'version',target.version),
    jsonb_build_object('state',p_next_state,'version',next_version),
    jsonb_build_object('phase',4,'contentMetadataRedacted',true,
      'evidenceCustodyAppended',bound_evidence_id IS NOT NULL)
  );
  INSERT INTO public.outbox_events (
    id,tenant_id,aggregate_type,aggregate_id,event_type,schema_version,payload,
    deduplication_key,correlation_id,causation_id,actor_kind,actor_id,producer,
    maximum_audience,occurred_at
  ) VALUES (
    p_outbox_event_id,context_tenant,'dfir_storage_object',target.id,
    'dfir.storage.state_changed',1,
    jsonb_build_object('tenantId',context_tenant,'resourceId',target.id,
      'resourceVersion',next_version,'state',p_next_state),
    'phase4:'||p_request_id::text||':dfir.storage.state_changed:'||target.id::text,
    p_correlation_id,p_request_id,'system',NULL,'worker','operator',p_transitioned_at
  );
  RETURN QUERY SELECT target.id,next_version,false;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.advance_dfir_storage_object_as_worker_v3(
  uuid,bigint,public.dfir_scan_state,bytea,bigint,text,timestamp with time zone,
  uuid,uuid,uuid,uuid,uuid
) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.advance_dfir_storage_object_as_worker_v3(
  uuid,bigint,public.dfir_scan_state,bytea,bigint,text,timestamp with time zone,
  uuid,uuid,uuid,uuid,uuid
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.advance_dfir_storage_object_as_worker_v3(
  uuid,bigint,public.dfir_scan_state,bytea,bigint,text,timestamp with time zone,
  uuid,uuid,uuid,uuid,uuid
) TO periapsis_worker;--> statement-breakpoint

-- Keep the proven 0195 path for every legacy operation, but replace the
-- timeline branch when it contains the now-supported same-Alert evidence
-- links. The original function rejected every evidence link unconditionally.
ALTER FUNCTION app.append_alert_dfir_mutation_effects_v1(
  uuid,text,text,text,uuid,bigint,text,bytea,bytea,uuid,jsonb,jsonb,jsonb,
  uuid,uuid,uuid,uuid,inet,text,text
) RENAME TO append_alert_dfir_mutation_effects_legacy_v1;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.append_alert_dfir_mutation_effects_legacy_v1(
  uuid,text,text,text,uuid,bigint,text,bytea,bytea,uuid,jsonb,jsonb,jsonb,
  uuid,uuid,uuid,uuid,inet,text,text
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint

CREATE FUNCTION app.append_alert_dfir_mutation_effects_v1(
  p_alert_id uuid,p_permission_key text,p_action text,p_resource_type text,
  p_resource_id uuid,p_resource_version bigint,p_command_operation text,
  p_key_digest bytea,p_request_digest bytea,p_activity_id uuid,p_before jsonb,
  p_after jsonb,p_metadata jsonb,p_audit_event_id uuid,p_outbox_event_id uuid,
  p_request_id uuid,p_correlation_id uuid,p_ip_address inet,p_user_agent text,
  p_authentication_method text
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_user uuid := app.context_user_id();
  actor_membership uuid := app.current_tenant_membership_id();
  command_record public.alert_dfir_resource_commands%ROWTYPE;
  activity_sequence bigint;
  relation_count bigint;
BEGIN
  -- Compatibility marker for the legacy attachment branch, whose reservation
  -- remains in tenant_authorization_commands inside the delegated function.
  IF p_command_operation <> 'dfir.timeline.create'
     OR NOT EXISTS (
       SELECT 1 FROM public.dfir_timeline_evidence_links
       WHERE tenant_id = context_tenant AND timeline_event_id = p_resource_id
     ) THEN
    PERFORM app.append_alert_dfir_mutation_effects_legacy_v1(
      p_alert_id,p_permission_key,p_action,p_resource_type,p_resource_id,
      p_resource_version,p_command_operation,p_key_digest,p_request_digest,
      p_activity_id,p_before,p_after,p_metadata,p_audit_event_id,
      p_outbox_event_id,p_request_id,p_correlation_id,p_ip_address,
      p_user_agent,p_authentication_method
    );
    RETURN;
  END IF;
  IF p_permission_key IS DISTINCT FROM 'dfir.timeline.manage'
     OR p_action IS DISTINCT FROM 'dfir.timeline.created'
     OR p_resource_type IS DISTINCT FROM 'dfir_timeline_event'
     OR p_resource_version IS DISTINCT FROM 1
     OR p_alert_id IS NULL OR uuid_extract_version(p_alert_id) IS DISTINCT FROM 7
     OR p_resource_id IS NULL OR uuid_extract_version(p_resource_id) IS DISTINCT FROM 7
     OR p_key_digest IS NULL OR octet_length(p_key_digest) <> 32
     OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32
     OR p_activity_id IS NULL OR uuid_extract_version(p_activity_id) IS DISTINCT FROM 7
     OR p_audit_event_id IS NULL OR uuid_extract_version(p_audit_event_id) IS DISTINCT FROM 7
     OR p_outbox_event_id IS NULL OR uuid_extract_version(p_outbox_event_id) IS DISTINCT FROM 7
     OR p_request_id IS NULL OR uuid_extract_version(p_request_id) IS DISTINCT FROM 7
     OR p_correlation_id IS NULL OR uuid_extract_version(p_correlation_id) IS DISTINCT FROM 7
     OR p_ip_address IS NULL OR p_user_agent IS NULL OR octet_length(p_user_agent) NOT BETWEEN 1 AND 1024
     OR p_authentication_method NOT IN ('bootstrap_totp','totp','recovery_code','ldap','oidc','saml','passkey')
     OR p_before IS NULL OR jsonb_typeof(p_before) <> 'object'
     OR p_after IS NULL OR jsonb_typeof(p_after) <> 'object'
     OR p_metadata IS NULL OR jsonb_typeof(p_metadata) <> 'object'
     OR octet_length(p_before::text) > 32768 OR octet_length(p_after::text) > 32768
     OR octet_length(p_metadata::text) > 32768 THEN
    RAISE EXCEPTION 'Alert DFIR timeline effect input is invalid' USING ERRCODE = '22023';
  END IF;
  PERFORM app.lock_current_tenant_authorization_state();
  PERFORM 1 FROM public.tenant_memberships AS membership
  JOIN public.users AS identity ON identity.id=membership.user_id
  WHERE membership.tenant_id=context_tenant AND membership.id=actor_membership
    AND membership.user_id=actor_user AND membership.status='active' AND identity.active
  FOR SHARE OF membership,identity;
  IF NOT FOUND THEN RAISE EXCEPTION 'Alert DFIR human authority is unavailable' USING ERRCODE='42501'; END IF;
  PERFORM 1 FROM public.alerts AS alert
  WHERE alert.tenant_id=context_tenant AND alert.id=p_alert_id AND alert.deleted_at IS NULL
  FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Alert is unavailable' USING ERRCODE='P0002'; END IF;
  IF NOT app.private_current_alert_dfir_manage_scope_allows_v1('dfir.timeline.manage',p_alert_id) THEN
    RAISE EXCEPTION 'Alert DFIR authority is required' USING ERRCODE='42501';
  END IF;
  SELECT command.* INTO command_record
  FROM public.alert_dfir_resource_commands AS command
  WHERE command.tenant_id=context_tenant AND command.actor_user_id=actor_user
    AND command.actor_membership_id=actor_membership
    AND command.operation='dfir.timeline.create' AND command.key_digest=p_key_digest
  FOR SHARE;
  IF NOT FOUND OR command_record.request_digest IS DISTINCT FROM p_request_digest
     OR command_record.alert_id IS DISTINCT FROM p_alert_id
     OR command_record.resource_id IS DISTINCT FROM p_resource_id
     OR command_record.result_version IS DISTINCT FROM 1 THEN
    RAISE EXCEPTION 'Alert timeline command reservation is unavailable' USING ERRCODE='23503';
  END IF;
  PERFORM 1 FROM public.dfir_timeline_events AS event
  WHERE event.tenant_id=context_tenant AND event.id=p_resource_id
    AND event.alert_id=p_alert_id AND event.case_id IS NULL AND event.version=1
  FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Alert timeline projection is unavailable' USING ERRCODE='23503'; END IF;
  SELECT count(*) INTO relation_count FROM (
    SELECT ioc_id AS id FROM public.dfir_timeline_ioc_links WHERE tenant_id=context_tenant AND timeline_event_id=p_resource_id
    UNION ALL SELECT asset_id FROM public.dfir_timeline_asset_links WHERE tenant_id=context_tenant AND timeline_event_id=p_resource_id
    UNION ALL SELECT evidence_id FROM public.dfir_timeline_evidence_links WHERE tenant_id=context_tenant AND timeline_event_id=p_resource_id
  ) AS links;
  IF relation_count > 1000 THEN RAISE EXCEPTION 'Alert timeline relation limit is exceeded' USING ERRCODE='54000'; END IF;
  IF EXISTS (
    SELECT 1 FROM public.dfir_timeline_ioc_links AS timeline_link
    LEFT JOIN public.dfir_ioc_links AS alert_link
      ON alert_link.tenant_id=timeline_link.tenant_id AND alert_link.ioc_id=timeline_link.ioc_id AND alert_link.alert_id=p_alert_id
    LEFT JOIN public.dfir_iocs AS resource
      ON resource.tenant_id=timeline_link.tenant_id AND resource.id=timeline_link.ioc_id AND resource.archived_at IS NULL
    WHERE timeline_link.tenant_id=context_tenant AND timeline_link.timeline_event_id=p_resource_id
      AND (alert_link.id IS NULL OR resource.id IS NULL)
  ) OR EXISTS (
    SELECT 1 FROM public.dfir_timeline_asset_links AS timeline_link
    LEFT JOIN public.dfir_asset_links AS alert_link
      ON alert_link.tenant_id=timeline_link.tenant_id AND alert_link.asset_id=timeline_link.asset_id AND alert_link.alert_id=p_alert_id
    LEFT JOIN public.dfir_assets AS resource
      ON resource.tenant_id=timeline_link.tenant_id AND resource.id=timeline_link.asset_id AND resource.archived_at IS NULL
    WHERE timeline_link.tenant_id=context_tenant AND timeline_link.timeline_event_id=p_resource_id
      AND (alert_link.id IS NULL OR resource.id IS NULL)
  ) OR EXISTS (
    SELECT 1 FROM public.dfir_timeline_evidence_links AS timeline_link
    LEFT JOIN public.dfir_evidence AS evidence
      ON evidence.tenant_id=timeline_link.tenant_id AND evidence.id=timeline_link.evidence_id
      AND evidence.alert_id=p_alert_id AND evidence.case_id IS NULL AND NOT evidence.destroyed
    WHERE timeline_link.tenant_id=context_tenant AND timeline_link.timeline_event_id=p_resource_id
      AND evidence.id IS NULL
  ) THEN
    RAISE EXCEPTION 'Alert timeline relation scope is invalid' USING ERRCODE='23503';
  END IF;
  SELECT coalesce(max(sequence),0)::bigint+1 INTO activity_sequence
  FROM public.ticket_activities WHERE tenant_id=context_tenant AND alert_id=p_alert_id;
  IF activity_sequence NOT BETWEEN 1 AND 2147483647 THEN RAISE EXCEPTION 'Alert activity sequence is exhausted' USING ERRCODE='54000'; END IF;
  INSERT INTO public.ticket_activities (
    id,tenant_id,alert_id,case_id,sequence,kind,summary,actor_principal_kind,
    actor_membership_id,actor_user_id,actor_service_account_id,origin,details,occurred_at
  ) VALUES (
    p_activity_id,context_tenant,p_alert_id,NULL,activity_sequence::integer,
    p_action,'Alert timeline event created','human',actor_membership,actor_user,NULL,'api',
    jsonb_build_object('resourceId',p_resource_id,'resourceVersion',1,'contentRedacted',true),transaction_timestamp()
  );
  PERFORM app.append_tenant_authorization_audit(
    p_audit_event_id,p_action,p_resource_type,p_resource_id,p_request_id,
    p_correlation_id,p_ip_address,p_user_agent,p_authentication_method,
    '{}'::jsonb,jsonb_build_object('resourceId',p_resource_id,'resourceVersion',1,'contentRedacted',true),
    jsonb_build_object('alertId',p_alert_id,'commandId',command_record.command_id,
      'commandOperation',p_command_operation,'actorMembershipId',actor_membership,'contentRedacted',true)
  );
  INSERT INTO public.outbox_events (
    id,tenant_id,aggregate_type,aggregate_id,event_type,schema_version,payload,
    deduplication_key,correlation_id,causation_id,occurred_at
  ) VALUES (
    p_outbox_event_id,context_tenant,p_resource_type,p_resource_id,p_action,1,
    jsonb_build_object('tenantId',context_tenant,'alertId',p_alert_id,'resourceId',p_resource_id,'resourceVersion',1),
    'alert-dfir:'||command_record.command_id::text||':'||p_audit_event_id::text,
    p_correlation_id,p_request_id,transaction_timestamp()
  );
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.append_alert_dfir_mutation_effects_v1(
  uuid,text,text,text,uuid,bigint,text,bytea,bytea,uuid,jsonb,jsonb,jsonb,
  uuid,uuid,uuid,uuid,inet,text,text
) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.append_alert_dfir_mutation_effects_v1(
  uuid,text,text,text,uuid,bigint,text,bytea,bytea,uuid,jsonb,jsonb,jsonb,
  uuid,uuid,uuid,uuid,inet,text,text
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.append_alert_dfir_mutation_effects_v1(
  uuid,text,text,text,uuid,bigint,text,bytea,bytea,uuid,jsonb,jsonb,jsonb,
  uuid,uuid,uuid,uuid,inet,text,text
) TO periapsis_api;--> statement-breakpoint

CREATE FUNCTION app.alert_dfir_runtime_schema_readiness_v2()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  function_identity text;
  shape_definition text;
BEGIN
  IF to_regclass('public.alert_dfir_resource_command_results') IS NULL
     OR to_regclass('public.dfir_relationship_retractions') IS NULL
     OR NOT EXISTS (
       SELECT 1 FROM pg_catalog.pg_class AS relation
       WHERE relation.oid='public.alert_dfir_resource_command_results'::regclass
         AND relation.relrowsecurity AND relation.relforcerowsecurity
         AND pg_catalog.pg_get_userbyid(relation.relowner)='periapsis_migrator'
     )
     OR NOT EXISTS (
       SELECT 1 FROM pg_catalog.pg_class AS relation
       WHERE relation.oid='public.dfir_relationship_retractions'::regclass
         AND relation.relrowsecurity AND relation.relforcerowsecurity
         AND pg_catalog.pg_get_userbyid(relation.relowner)='periapsis_migrator'
     )
     OR has_table_privilege('periapsis_api','public.alert_dfir_resource_command_results','SELECT,INSERT,UPDATE,DELETE')
     OR has_table_privilege('periapsis_worker','public.alert_dfir_resource_command_results','SELECT,INSERT,UPDATE,DELETE')
     OR has_table_privilege('periapsis_api','public.dfir_relationship_retractions','INSERT,UPDATE,DELETE')
     OR has_table_privilege('periapsis_worker','public.dfir_relationship_retractions','SELECT,INSERT,UPDATE,DELETE') THEN
    RETURN false;
  END IF;
  SELECT pg_catalog.pg_get_constraintdef(constraint_row.oid,true) INTO shape_definition
  FROM pg_catalog.pg_constraint AS constraint_row
  WHERE constraint_row.conrelid='public.alert_dfir_resource_commands'::regclass
    AND constraint_row.conname='alert_dfir_resource_commands_shape_check';
  IF shape_definition IS NULL
     OR position('dfir.alert.evidence.create' IN shape_definition)=0
     OR position('dfir.alert.task.checklist.replace' IN shape_definition)=0
     OR position('dfir.alert.relationship.retract' IN shape_definition)=0
     OR NOT EXISTS (
       SELECT 1 FROM pg_catalog.pg_constraint
       WHERE conrelid='public.alert_dfir_resource_command_results'::regclass
         AND conname='alert_dfir_resource_command_results_command_fk' AND contype='f'
     )
     OR NOT EXISTS (
       SELECT 1 FROM pg_catalog.pg_constraint
       WHERE conrelid='public.dfir_evidence'::regclass
         AND conname='dfir_evidence_root_check'
     )
     OR NOT EXISTS (
       SELECT 1 FROM pg_catalog.pg_constraint
       WHERE conrelid='public.dfir_tasks'::regclass AND conname='dfir_tasks_root_check'
     )
     OR NOT EXISTS (
       SELECT 1 FROM pg_catalog.pg_constraint
       WHERE conrelid='public.dfir_relationships'::regclass AND conname='dfir_relationships_root_check'
     )
     OR NOT EXISTS (
       SELECT 1 FROM pg_catalog.pg_constraint
       WHERE conrelid='public.dfir_activities'::regclass AND conname='dfir_activities_root_check'
     ) THEN
    RETURN false;
  END IF;
  IF (SELECT count(*) FROM pg_catalog.pg_trigger
      WHERE tgname IN (
        'alert_dfir_resource_command_results_immutable_v1',
        'alert_dfir_resource_commands_result_required_v1',
        'dfir_relationship_retractions_immutable_v1',
        'dfir_relationship_retractions_validate_root_v1',
        'dfir_relationships_identity_v1'
      ) AND tgenabled='O' AND NOT tgisinternal) <> 5 THEN
    RETURN false;
  END IF;
  FOREACH function_identity IN ARRAY ARRAY[
    'app.reserve_alert_investigation_command_v1(uuid,uuid,text,uuid,bigint,bytea,bytea)',
    'app.store_alert_investigation_command_result_v1(uuid,jsonb)',
    'app.create_alert_dfir_evidence_v1(uuid,uuid,uuid,uuid,text,text,text,public.dfir_evidence_classification,timestamp with time zone,text,timestamp with time zone,boolean,uuid,bytea,bytea)',
    'app.append_alert_dfir_custody_event_v1(uuid,uuid,uuid,bigint,uuid,public.dfir_custody_action,text,text,bytea,bytea,timestamp with time zone)',
    'app.create_alert_dfir_relationship_v1(uuid,uuid,uuid,public.dfir_entity_kind,uuid,text,text,public.dfir_entity_kind,uuid,text,text,text,jsonb,timestamp with time zone)',
    'app.retract_alert_dfir_relationship_v1(uuid,uuid,uuid,bigint,uuid,text,timestamp with time zone)',
    'app.append_alert_investigation_effects_v1(uuid,text,text,text,text,text,text,uuid,bigint,bytea,bytea,uuid,jsonb,jsonb,jsonb,uuid,uuid,uuid,uuid,inet,text,text)'
  ] LOOP
    IF to_regprocedure(function_identity) IS NULL
       OR NOT has_function_privilege('periapsis_api',function_identity,'EXECUTE')
       OR has_function_privilege('periapsis_worker',function_identity,'EXECUTE')
       OR has_function_privilege('periapsis_notifier',function_identity,'EXECUTE')
       OR has_function_privilege('periapsis_auditor',function_identity,'EXECUTE')
       OR EXISTS (
         SELECT 1 FROM pg_catalog.pg_proc AS procedure
         CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(
           procedure.proacl,pg_catalog.acldefault('f',procedure.proowner)
         )) AS privilege
         WHERE procedure.oid=to_regprocedure(function_identity)
           AND privilege.grantee=0 AND privilege.privilege_type='EXECUTE'
       ) THEN RETURN false; END IF;
  END LOOP;
  function_identity := 'app.advance_dfir_storage_object_as_worker_v3(uuid,bigint,public.dfir_scan_state,bytea,bigint,text,timestamp with time zone,uuid,uuid,uuid,uuid,uuid)';
  RETURN to_regprocedure(function_identity) IS NOT NULL
    AND has_function_privilege('periapsis_worker',function_identity,'EXECUTE')
    AND NOT has_function_privilege('periapsis_api',function_identity,'EXECUTE')
    AND NOT has_function_privilege('periapsis_notifier',function_identity,'EXECUTE')
    AND NOT has_function_privilege('periapsis_auditor',function_identity,'EXECUTE')
    AND NOT EXISTS (
      SELECT 1 FROM pg_catalog.pg_proc AS procedure
      CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(
        procedure.proacl,pg_catalog.acldefault('f',procedure.proowner)
      )) AS privilege
      WHERE procedure.oid=to_regprocedure(function_identity)
        AND privilege.grantee=0 AND privilege.privilege_type='EXECUTE'
    );
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.alert_dfir_runtime_schema_readiness_v2() OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.alert_dfir_runtime_schema_readiness_v2()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.alert_dfir_runtime_schema_readiness_v2()
  TO periapsis_api, periapsis_worker;--> statement-breakpoint

COMMENT ON TABLE public.alert_dfir_resource_command_results IS
  'Immutable exact-coordinate response snapshots for replaying Alert investigation mutations.';--> statement-breakpoint
COMMENT ON TABLE public.dfir_relationship_retractions IS
  'Append-only exact-root retractions for general Case- or Alert-rooted DFIR relationships.';--> statement-breakpoint
COMMENT ON FUNCTION app.alert_dfir_runtime_schema_readiness_v2() IS
  'Attests the isolated 0226 Alert investigation ABI, exact roots, result snapshots, guards, ownership, RLS, and closed role grants.';--> statement-breakpoint
