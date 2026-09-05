CREATE TYPE "public"."ticket_aggregate_kind" AS ENUM('alert', 'case');--> statement-breakpoint
CREATE TYPE "public"."ticket_comment_visibility" AS ENUM('public', 'private');--> statement-breakpoint
CREATE TYPE "public"."ticket_principal_kind" AS ENUM('human', 'service_account', 'system');--> statement-breakpoint
CREATE TABLE "ticket_number_counters" (
	"tenant_id" uuid NOT NULL,
	"aggregate_kind" "ticket_aggregate_kind" NOT NULL,
	"period" integer NOT NULL,
	"next_value" integer DEFAULT 1 NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "ticket_number_counters_key" UNIQUE("tenant_id","aggregate_kind","period"),
	CONSTRAINT "ticket_number_counters_period_check" CHECK ("ticket_number_counters"."period" between 2000 and 9999),
	CONSTRAINT "ticket_number_counters_next_value_check" CHECK ("ticket_number_counters"."next_value" between 1 and 2147483647)
);
--> statement-breakpoint
ALTER TABLE "ticket_number_counters" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "ticket_workflow_versions" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"workflow_id" uuid NOT NULL,
	"aggregate_kind" "ticket_aggregate_kind" NOT NULL,
	"version" integer NOT NULL,
	"states" jsonb NOT NULL,
	"transitions" jsonb NOT NULL,
	"published_by_membership_id" uuid,
	"published_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "ticket_workflow_versions_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "ticket_workflow_versions_identity_key" UNIQUE("tenant_id","workflow_id","version"),
	CONSTRAINT "ticket_workflow_versions_exact_kind_key" UNIQUE("tenant_id","workflow_id","aggregate_kind","version"),
	CONSTRAINT "ticket_workflow_versions_id_uuidv7_check" CHECK ((uuid_extract_version("ticket_workflow_versions"."id") = 7) is true),
	CONSTRAINT "ticket_workflow_versions_version_check" CHECK ("ticket_workflow_versions"."version" > 0),
	CONSTRAINT "ticket_workflow_versions_states_check" CHECK (jsonb_typeof("ticket_workflow_versions"."states") = 'array' and jsonb_array_length("ticket_workflow_versions"."states") between 2 and 64),
	CONSTRAINT "ticket_workflow_versions_transitions_check" CHECK (jsonb_typeof("ticket_workflow_versions"."transitions") = 'array' and jsonb_array_length("ticket_workflow_versions"."transitions") between 1 and 256),
	CONSTRAINT "ticket_workflow_versions_timestamps_check" CHECK ("ticket_workflow_versions"."published_at" >= "ticket_workflow_versions"."created_at")
);
--> statement-breakpoint
ALTER TABLE "ticket_workflow_versions" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "ticket_workflows" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"aggregate_kind" "ticket_aggregate_kind" NOT NULL,
	"key" text NOT NULL,
	"display_name" text NOT NULL,
	"description" text DEFAULT '' NOT NULL,
	"is_default" boolean DEFAULT false NOT NULL,
	"current_version" integer DEFAULT 1 NOT NULL,
	"archived_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "ticket_workflows_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "ticket_workflows_tenant_kind_key_key" UNIQUE("tenant_id","aggregate_kind","key"),
	CONSTRAINT "ticket_workflows_exact_kind_key" UNIQUE("tenant_id","id","aggregate_kind"),
	CONSTRAINT "ticket_workflows_id_uuidv7_check" CHECK ((uuid_extract_version("ticket_workflows"."id") = 7) is true),
	CONSTRAINT "ticket_workflows_key_check" CHECK ("ticket_workflows"."key" ~ '^[a-z][a-z0-9_]{2,63}$'),
	CONSTRAINT "ticket_workflows_display_name_check" CHECK (btrim("ticket_workflows"."display_name") <> '' and char_length("ticket_workflows"."display_name") <= 120 and "ticket_workflows"."display_name" !~ '[[:cntrl:]]'),
	CONSTRAINT "ticket_workflows_description_check" CHECK (char_length("ticket_workflows"."description") <= 1000 and "ticket_workflows"."description" !~ '[[:cntrl:]]'),
	CONSTRAINT "ticket_workflows_current_version_check" CHECK ("ticket_workflows"."current_version" > 0),
	CONSTRAINT "ticket_workflows_timestamps_check" CHECK ("ticket_workflows"."updated_at" >= "ticket_workflows"."created_at" and ("ticket_workflows"."archived_at" is null or "ticket_workflows"."archived_at" >= "ticket_workflows"."created_at"))
);
--> statement-breakpoint
ALTER TABLE "ticket_workflows" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "alert_case_links" (
	"id" uuid PRIMARY KEY NOT NULL,
	"tenant_id" uuid NOT NULL,
	"alert_id" uuid NOT NULL,
	"case_id" uuid NOT NULL,
	"relation" text NOT NULL,
	"reason" text NOT NULL,
	"linked_by_membership_id" uuid NOT NULL,
	"linked_by_user_id" uuid NOT NULL,
	"source_alert_version" integer NOT NULL,
	"copy_fields" text[] DEFAULT ARRAY[]::text[] NOT NULL,
	"custom_field_keys" text[] DEFAULT ARRAY[]::text[] NOT NULL,
	"item_ids" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"public_comment_ids" uuid[] DEFAULT ARRAY[]::uuid[] NOT NULL,
	"copied_field_snapshot" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"linked_at" timestamp with time zone NOT NULL,
	CONSTRAINT "alert_case_links_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "alert_case_links_exact_key" UNIQUE("tenant_id","alert_id","case_id"),
	CONSTRAINT "alert_case_links_id_uuidv7_check" CHECK ((uuid_extract_version("alert_case_links"."id") = 7) is true),
	CONSTRAINT "alert_case_links_relation_check" CHECK ("alert_case_links"."relation" in ('escalation', 'correlation')),
	CONSTRAINT "alert_case_links_reason_check" CHECK (btrim("alert_case_links"."reason") <> '' and char_length("alert_case_links"."reason") <= 2000),
	CONSTRAINT "alert_case_links_source_version_check" CHECK ("alert_case_links"."source_alert_version" > 0),
	CONSTRAINT "alert_case_links_selection_check" CHECK (cardinality("alert_case_links"."copy_fields") <= 12 and cardinality("alert_case_links"."custom_field_keys") <= 100 and cardinality("alert_case_links"."public_comment_ids") <= 100 and jsonb_typeof("alert_case_links"."item_ids") = 'object' and jsonb_typeof("alert_case_links"."copied_field_snapshot") = 'object')
);
--> statement-breakpoint
ALTER TABLE "alert_case_links" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "cases" (
	"id" uuid PRIMARY KEY NOT NULL,
	"tenant_id" uuid NOT NULL,
	"number" text NOT NULL,
	"workflow_id" uuid NOT NULL,
	"workflow_version" integer NOT NULL,
	"state_key" text NOT NULL,
	"customer_visible" boolean DEFAULT false NOT NULL,
	"title" text NOT NULL,
	"description" text DEFAULT '' NOT NULL,
	"summary" text DEFAULT '' NOT NULL,
	"severity" "alert_severity" DEFAULT 'medium' NOT NULL,
	"priority" text DEFAULT 'medium' NOT NULL,
	"category" text DEFAULT 'general' NOT NULL,
	"classification" text,
	"tags" text[] DEFAULT ARRAY[]::text[] NOT NULL,
	"custom_fields" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"customer_custom_fields" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"assigned_team_id" uuid,
	"assigned_team_epoch_id" uuid,
	"assignee_user_id" uuid,
	"claimed_by_user_id" uuid,
	"created_by_membership_id" uuid NOT NULL,
	"created_by_user_id" uuid NOT NULL,
	"detection_time" timestamp with time zone DEFAULT now() NOT NULL,
	"opened_at" timestamp with time zone DEFAULT now() NOT NULL,
	"acknowledged_at" timestamp with time zone,
	"closed_at" timestamp with time zone,
	"assigned_at" timestamp with time zone,
	"first_response_at" timestamp with time zone,
	"resolved_at" timestamp with time zone,
	"claimed_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"version" integer DEFAULT 1 NOT NULL,
	CONSTRAINT "cases_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "cases_tenant_number_key" UNIQUE("tenant_id","number"),
	CONSTRAINT "cases_id_uuidv7_check" CHECK ((uuid_extract_version("cases"."id") = 7) is true),
	CONSTRAINT "cases_number_check" CHECK ("cases"."number" ~ '^CAS-[0-9]{4}-[0-9]{6,10}$'),
	CONSTRAINT "cases_state_key_check" CHECK ("cases"."state_key" ~ '^[a-z][a-z0-9_.-]{0,63}$'),
	CONSTRAINT "cases_title_check" CHECK (btrim("cases"."title") <> '' and char_length("cases"."title") <= 240 and "cases"."title" !~ '[[:cntrl:]]'),
	CONSTRAINT "cases_text_check" CHECK (char_length("cases"."description") <= 10000 and char_length("cases"."summary") <= 4000),
	CONSTRAINT "cases_tags_check" CHECK (cardinality("cases"."tags") <= 100),
	CONSTRAINT "cases_custom_fields_check" CHECK (jsonb_typeof("cases"."custom_fields") = 'object' and jsonb_typeof("cases"."customer_custom_fields") = 'object'),
	CONSTRAINT "cases_assignment_shape_check" CHECK (("cases"."assigned_team_id" is null) = ("cases"."assigned_team_epoch_id" is null) and ("cases"."assigned_team_id" is not null or ("cases"."assignee_user_id" is null and "cases"."claimed_by_user_id" is null)) and ("cases"."claimed_by_user_id" is null or "cases"."claimed_by_user_id" = "cases"."assignee_user_id")),
	CONSTRAINT "cases_version_check" CHECK ("cases"."version" > 0),
	CONSTRAINT "cases_timestamps_check" CHECK ("cases"."updated_at" >= "cases"."created_at" and "cases"."opened_at" >= "cases"."created_at" and ("cases"."closed_at" is null or "cases"."closed_at" >= "cases"."created_at"))
);
--> statement-breakpoint
ALTER TABLE "cases" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "ticket_activities" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"alert_id" uuid,
	"case_id" uuid,
	"sequence" integer NOT NULL,
	"kind" text NOT NULL,
	"summary" text NOT NULL,
	"actor_principal_kind" "ticket_principal_kind" NOT NULL,
	"actor_membership_id" uuid,
	"actor_user_id" uuid,
	"actor_service_account_id" uuid,
	"origin" text DEFAULT 'api' NOT NULL,
	"details" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"occurred_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "ticket_activities_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "ticket_activities_id_uuidv7_check" CHECK ((uuid_extract_version("ticket_activities"."id") = 7) is true),
	CONSTRAINT "ticket_activities_resource_check" CHECK (("ticket_activities"."alert_id" is null) <> ("ticket_activities"."case_id" is null)),
	CONSTRAINT "ticket_activities_sequence_check" CHECK ("ticket_activities"."sequence" > 0),
	CONSTRAINT "ticket_activities_kind_check" CHECK ("ticket_activities"."kind" ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'),
	CONSTRAINT "ticket_activities_actor_check" CHECK (("ticket_activities"."actor_principal_kind" = 'human' and "ticket_activities"."actor_membership_id" is not null and "ticket_activities"."actor_user_id" is not null and "ticket_activities"."actor_service_account_id" is null) or ("ticket_activities"."actor_principal_kind" = 'service_account' and "ticket_activities"."actor_membership_id" is null and "ticket_activities"."actor_user_id" is null and "ticket_activities"."actor_service_account_id" is not null) or ("ticket_activities"."actor_principal_kind" = 'system' and "ticket_activities"."actor_membership_id" is null and "ticket_activities"."actor_user_id" is null and "ticket_activities"."actor_service_account_id" is null)),
	CONSTRAINT "ticket_activities_details_check" CHECK (jsonb_typeof("ticket_activities"."details") = 'object')
);
--> statement-breakpoint
ALTER TABLE "ticket_activities" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "ticket_assignment_history" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"aggregate_kind" "ticket_aggregate_kind" NOT NULL,
	"aggregate_id" uuid NOT NULL,
	"version" integer NOT NULL,
	"action" text NOT NULL,
	"prior_team_id" uuid,
	"resulting_team_id" uuid,
	"prior_assignee_user_id" uuid,
	"resulting_assignee_user_id" uuid,
	"prior_claimant_user_id" uuid,
	"resulting_claimant_user_id" uuid,
	"actor_membership_id" uuid NOT NULL,
	"actor_user_id" uuid NOT NULL,
	"reason" text DEFAULT '' NOT NULL,
	"occurred_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "ticket_assignment_history_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "ticket_assignment_history_version_key" UNIQUE("tenant_id","aggregate_kind","aggregate_id","version"),
	CONSTRAINT "ticket_assignment_history_id_uuidv7_check" CHECK ((uuid_extract_version("ticket_assignment_history"."id") = 7) is true),
	CONSTRAINT "ticket_assignment_history_version_check" CHECK ("ticket_assignment_history"."version" > 0),
	CONSTRAINT "ticket_assignment_history_action_check" CHECK ("ticket_assignment_history"."action" in ('assign', 'claim', 'release', 'transfer'))
);
--> statement-breakpoint
ALTER TABLE "ticket_assignment_history" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "ticket_commands" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"operation" text NOT NULL,
	"actor_membership_id" uuid NOT NULL,
	"actor_user_id" uuid NOT NULL,
	"key_digest" "bytea" NOT NULL,
	"request_digest" "bytea" NOT NULL,
	"result_aggregate_kind" "ticket_aggregate_kind" NOT NULL,
	"result_aggregate_id" uuid NOT NULL,
	"result_version" integer NOT NULL,
	"result_metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "ticket_commands_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "ticket_commands_replay_key" UNIQUE("tenant_id","actor_membership_id","operation","key_digest"),
	CONSTRAINT "ticket_commands_id_uuidv7_check" CHECK ((uuid_extract_version("ticket_commands"."id") = 7) is true),
	CONSTRAINT "ticket_commands_operation_check" CHECK ("ticket_commands"."operation" ~ '^(alert|case|ticket)\.[a-z][a-z0-9_.-]{1,63}$'),
	CONSTRAINT "ticket_commands_digest_check" CHECK (octet_length("ticket_commands"."key_digest") = 32 and octet_length("ticket_commands"."request_digest") = 32),
	CONSTRAINT "ticket_commands_result_version_check" CHECK ("ticket_commands"."result_version" > 0),
	CONSTRAINT "ticket_commands_metadata_check" CHECK (jsonb_typeof("ticket_commands"."result_metadata") = 'object')
);
--> statement-breakpoint
ALTER TABLE "ticket_commands" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "ticket_comments" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"alert_id" uuid,
	"case_id" uuid,
	"visibility" "ticket_comment_visibility" NOT NULL,
	"body_markdown" text NOT NULL,
	"body_html" text NOT NULL,
	"author_membership_id" uuid NOT NULL,
	"author_user_id" uuid NOT NULL,
	"origin" text DEFAULT 'api' NOT NULL,
	"revision" integer DEFAULT 1 NOT NULL,
	"mentioned_user_ids" uuid[] DEFAULT ARRAY[]::uuid[] NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "ticket_comments_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "ticket_comments_id_uuidv7_check" CHECK ((uuid_extract_version("ticket_comments"."id") = 7) is true),
	CONSTRAINT "ticket_comments_resource_check" CHECK (("ticket_comments"."alert_id" is null) <> ("ticket_comments"."case_id" is null)),
	CONSTRAINT "ticket_comments_body_check" CHECK (btrim("ticket_comments"."body_markdown") <> '' and char_length("ticket_comments"."body_markdown") <= 50000 and char_length("ticket_comments"."body_html") <= 100000),
	CONSTRAINT "ticket_comments_origin_check" CHECK ("ticket_comments"."origin" in ('api', 'escalation_copy', 'system')),
	CONSTRAINT "ticket_comments_revision_check" CHECK ("ticket_comments"."revision" > 0),
	CONSTRAINT "ticket_comments_mentions_check" CHECK (cardinality("ticket_comments"."mentioned_user_ids") <= 64)
);
--> statement-breakpoint
ALTER TABLE "ticket_comments" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "alerts" DROP CONSTRAINT "alerts_updated_after_created_check";--> statement-breakpoint
ALTER TABLE "alerts" ADD COLUMN "number" text;--> statement-breakpoint
ALTER TABLE "alerts" ADD COLUMN "workflow_id" uuid;--> statement-breakpoint
ALTER TABLE "alerts" ADD COLUMN "workflow_version" integer DEFAULT 1 NOT NULL;--> statement-breakpoint
ALTER TABLE "alerts" ADD COLUMN "state_key" text DEFAULT 'new' NOT NULL;--> statement-breakpoint
ALTER TABLE "alerts" ADD COLUMN "customer_visible" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "alerts" ADD COLUMN "deduplication_key" text;--> statement-breakpoint
ALTER TABLE "alerts" ADD COLUMN "priority" text DEFAULT 'medium' NOT NULL;--> statement-breakpoint
ALTER TABLE "alerts" ADD COLUMN "category" text DEFAULT 'general' NOT NULL;--> statement-breakpoint
ALTER TABLE "alerts" ADD COLUMN "classification" text;--> statement-breakpoint
ALTER TABLE "alerts" ADD COLUMN "source" text DEFAULT 'manual' NOT NULL;--> statement-breakpoint
ALTER TABLE "alerts" ADD COLUMN "source_type" text DEFAULT 'manual' NOT NULL;--> statement-breakpoint
ALTER TABLE "alerts" ADD COLUMN "tags" text[] DEFAULT ARRAY[]::text[] NOT NULL;--> statement-breakpoint
ALTER TABLE "alerts" ADD COLUMN "custom_fields" jsonb DEFAULT '{}'::jsonb NOT NULL;--> statement-breakpoint
ALTER TABLE "alerts" ADD COLUMN "customer_custom_fields" jsonb DEFAULT '{}'::jsonb NOT NULL;--> statement-breakpoint
ALTER TABLE "alerts" ADD COLUMN "raw_payload" jsonb DEFAULT '{}'::jsonb NOT NULL;--> statement-breakpoint
ALTER TABLE "alerts" ADD COLUMN "assigned_team_id" uuid;--> statement-breakpoint
ALTER TABLE "alerts" ADD COLUMN "assigned_team_epoch_id" uuid;--> statement-breakpoint
ALTER TABLE "alerts" ADD COLUMN "assignee_user_id" uuid;--> statement-breakpoint
ALTER TABLE "alerts" ADD COLUMN "claimed_by_user_id" uuid;--> statement-breakpoint
ALTER TABLE "alerts" ADD COLUMN "detected_at" timestamp with time zone DEFAULT now() NOT NULL;--> statement-breakpoint
ALTER TABLE "alerts" ADD COLUMN "received_at" timestamp with time zone DEFAULT now() NOT NULL;--> statement-breakpoint
ALTER TABLE "alerts" ADD COLUMN "acknowledged_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "alerts" ADD COLUMN "closed_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "alerts" ADD COLUMN "assigned_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "alerts" ADD COLUMN "first_response_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "alerts" ADD COLUMN "resolved_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "alerts" ADD COLUMN "claimed_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "ticket_number_counters" ADD CONSTRAINT "ticket_number_counters_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ticket_workflow_versions" ADD CONSTRAINT "ticket_workflow_versions_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ticket_workflow_versions" ADD CONSTRAINT "ticket_workflow_versions_workflow_fk" FOREIGN KEY ("tenant_id","workflow_id","aggregate_kind") REFERENCES "public"."ticket_workflows"("tenant_id","id","aggregate_kind") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "ticket_workflow_versions" ADD CONSTRAINT "ticket_workflow_versions_publisher_fk" FOREIGN KEY ("tenant_id","published_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "ticket_workflows" ADD CONSTRAINT "ticket_workflows_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "alert_case_links" ADD CONSTRAINT "alert_case_links_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "alert_case_links" ADD CONSTRAINT "alert_case_links_alert_fk" FOREIGN KEY ("tenant_id","alert_id") REFERENCES "public"."alerts"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "alert_case_links" ADD CONSTRAINT "alert_case_links_case_fk" FOREIGN KEY ("tenant_id","case_id") REFERENCES "public"."cases"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "alert_case_links" ADD CONSTRAINT "alert_case_links_actor_membership_fk" FOREIGN KEY ("tenant_id","linked_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "alert_case_links" ADD CONSTRAINT "alert_case_links_actor_user_fk" FOREIGN KEY ("tenant_id","linked_by_user_id") REFERENCES "public"."tenant_memberships"("tenant_id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "cases" ADD CONSTRAINT "cases_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "cases" ADD CONSTRAINT "cases_workflow_version_fk" FOREIGN KEY ("tenant_id","workflow_id","workflow_version") REFERENCES "public"."ticket_workflow_versions"("tenant_id","workflow_id","version") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "cases" ADD CONSTRAINT "cases_assignment_epoch_fk" FOREIGN KEY ("tenant_id","assigned_team_epoch_id","assigned_team_id") REFERENCES "public"."operator_team_assignment_epochs"("tenant_id","id","operator_team_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "cases" ADD CONSTRAINT "cases_assignee_membership_fk" FOREIGN KEY ("tenant_id","assignee_user_id") REFERENCES "public"."tenant_memberships"("tenant_id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "cases" ADD CONSTRAINT "cases_claimant_membership_fk" FOREIGN KEY ("tenant_id","claimed_by_user_id") REFERENCES "public"."tenant_memberships"("tenant_id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "cases" ADD CONSTRAINT "cases_creator_membership_fk" FOREIGN KEY ("tenant_id","created_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "cases" ADD CONSTRAINT "cases_creator_user_membership_fk" FOREIGN KEY ("tenant_id","created_by_user_id") REFERENCES "public"."tenant_memberships"("tenant_id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "ticket_activities" ADD CONSTRAINT "ticket_activities_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ticket_activities" ADD CONSTRAINT "ticket_activities_alert_fk" FOREIGN KEY ("tenant_id","alert_id") REFERENCES "public"."alerts"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "ticket_activities" ADD CONSTRAINT "ticket_activities_case_fk" FOREIGN KEY ("tenant_id","case_id") REFERENCES "public"."cases"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "ticket_activities" ADD CONSTRAINT "ticket_activities_actor_membership_fk" FOREIGN KEY ("tenant_id","actor_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "ticket_activities" ADD CONSTRAINT "ticket_activities_actor_user_fk" FOREIGN KEY ("tenant_id","actor_user_id") REFERENCES "public"."tenant_memberships"("tenant_id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "ticket_assignment_history" ADD CONSTRAINT "ticket_assignment_history_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ticket_assignment_history" ADD CONSTRAINT "ticket_assignment_history_actor_membership_fk" FOREIGN KEY ("tenant_id","actor_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "ticket_assignment_history" ADD CONSTRAINT "ticket_assignment_history_actor_user_fk" FOREIGN KEY ("tenant_id","actor_user_id") REFERENCES "public"."tenant_memberships"("tenant_id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "ticket_commands" ADD CONSTRAINT "ticket_commands_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ticket_commands" ADD CONSTRAINT "ticket_commands_actor_membership_fk" FOREIGN KEY ("tenant_id","actor_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "ticket_commands" ADD CONSTRAINT "ticket_commands_actor_user_fk" FOREIGN KEY ("tenant_id","actor_user_id") REFERENCES "public"."tenant_memberships"("tenant_id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "ticket_comments" ADD CONSTRAINT "ticket_comments_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ticket_comments" ADD CONSTRAINT "ticket_comments_alert_fk" FOREIGN KEY ("tenant_id","alert_id") REFERENCES "public"."alerts"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "ticket_comments" ADD CONSTRAINT "ticket_comments_case_fk" FOREIGN KEY ("tenant_id","case_id") REFERENCES "public"."cases"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "ticket_comments" ADD CONSTRAINT "ticket_comments_author_membership_fk" FOREIGN KEY ("tenant_id","author_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "ticket_comments" ADD CONSTRAINT "ticket_comments_author_user_fk" FOREIGN KEY ("tenant_id","author_user_id") REFERENCES "public"."tenant_memberships"("tenant_id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
CREATE INDEX "ticket_workflow_versions_lookup_idx" ON "ticket_workflow_versions" USING btree ("tenant_id","aggregate_kind","workflow_id","version");--> statement-breakpoint
CREATE UNIQUE INDEX "ticket_workflows_one_default_key" ON "ticket_workflows" USING btree ("tenant_id","aggregate_kind") WHERE "ticket_workflows"."is_default" and "ticket_workflows"."archived_at" is null;--> statement-breakpoint
CREATE INDEX "ticket_workflows_tenant_kind_idx" ON "ticket_workflows" USING btree ("tenant_id","aggregate_kind","id");--> statement-breakpoint
CREATE INDEX "alert_case_links_alert_idx" ON "alert_case_links" USING btree ("tenant_id","alert_id","linked_at","id");--> statement-breakpoint
CREATE INDEX "alert_case_links_case_idx" ON "alert_case_links" USING btree ("tenant_id","case_id","linked_at","id");--> statement-breakpoint
CREATE INDEX "cases_tenant_updated_idx" ON "cases" USING btree ("tenant_id","updated_at","id");--> statement-breakpoint
CREATE INDEX "cases_tenant_state_priority_idx" ON "cases" USING btree ("tenant_id","state_key","priority","id");--> statement-breakpoint
CREATE INDEX "cases_tenant_assignment_idx" ON "cases" USING btree ("tenant_id","assigned_team_id","assignee_user_id","id");--> statement-breakpoint
CREATE UNIQUE INDEX "ticket_activities_alert_sequence_key" ON "ticket_activities" USING btree ("tenant_id","alert_id","sequence") WHERE "ticket_activities"."alert_id" is not null;--> statement-breakpoint
CREATE UNIQUE INDEX "ticket_activities_case_sequence_key" ON "ticket_activities" USING btree ("tenant_id","case_id","sequence") WHERE "ticket_activities"."case_id" is not null;--> statement-breakpoint
CREATE INDEX "ticket_activities_alert_idx" ON "ticket_activities" USING btree ("tenant_id","alert_id","occurred_at","id");--> statement-breakpoint
CREATE INDEX "ticket_activities_case_idx" ON "ticket_activities" USING btree ("tenant_id","case_id","occurred_at","id");--> statement-breakpoint
CREATE INDEX "ticket_assignment_history_resource_idx" ON "ticket_assignment_history" USING btree ("tenant_id","aggregate_kind","aggregate_id","version");--> statement-breakpoint
CREATE INDEX "ticket_commands_result_idx" ON "ticket_commands" USING btree ("tenant_id","result_aggregate_kind","result_aggregate_id");--> statement-breakpoint
CREATE INDEX "ticket_comments_alert_idx" ON "ticket_comments" USING btree ("tenant_id","alert_id","created_at","id");--> statement-breakpoint
CREATE INDEX "ticket_comments_case_idx" ON "ticket_comments" USING btree ("tenant_id","case_id","created_at","id");--> statement-breakpoint
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_workflow_version_fk" FOREIGN KEY ("tenant_id","workflow_id","workflow_version") REFERENCES "public"."ticket_workflow_versions"("tenant_id","workflow_id","version") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_assignment_epoch_fk" FOREIGN KEY ("tenant_id","assigned_team_epoch_id","assigned_team_id") REFERENCES "public"."operator_team_assignment_epochs"("tenant_id","id","operator_team_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_assignee_membership_fk" FOREIGN KEY ("tenant_id","assignee_user_id") REFERENCES "public"."tenant_memberships"("tenant_id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_claimant_membership_fk" FOREIGN KEY ("tenant_id","claimed_by_user_id") REFERENCES "public"."tenant_memberships"("tenant_id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
CREATE UNIQUE INDEX "alerts_tenant_source_deduplication_key" ON "alerts" USING btree ("tenant_id","source","deduplication_key") WHERE "alerts"."deduplication_key" is not null;--> statement-breakpoint
CREATE INDEX "alerts_tenant_state_priority_idx" ON "alerts" USING btree ("tenant_id","state_key","priority","id");--> statement-breakpoint
CREATE INDEX "alerts_tenant_assignment_idx" ON "alerts" USING btree ("tenant_id","assigned_team_id","assignee_user_id","id");--> statement-breakpoint
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_tenant_number_key" UNIQUE("tenant_id","number");--> statement-breakpoint
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_number_check" CHECK ("alerts"."number" is null or "alerts"."number" ~ '^ALT-[0-9]{4}-[0-9]{6,10}$');--> statement-breakpoint
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_state_key_check" CHECK ("alerts"."state_key" ~ '^[a-z][a-z0-9_.-]{0,63}$');--> statement-breakpoint
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_business_text_check" CHECK (btrim("alerts"."priority") <> '' and char_length("alerts"."priority") <= 64
        and btrim("alerts"."category") <> '' and char_length("alerts"."category") <= 120
        and btrim("alerts"."source") <> '' and char_length("alerts"."source") <= 120
        and btrim("alerts"."source_type") <> '' and char_length("alerts"."source_type") <= 64
        and ("alerts"."classification" is null or char_length("alerts"."classification") <= 120)
        and ("alerts"."deduplication_key" is null or (btrim("alerts"."deduplication_key") <> '' and char_length("alerts"."deduplication_key") <= 200)));--> statement-breakpoint
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_tags_check" CHECK (cardinality("alerts"."tags") <= 100);--> statement-breakpoint
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_json_check" CHECK (jsonb_typeof("alerts"."custom_fields") = 'object'
        and jsonb_typeof("alerts"."customer_custom_fields") = 'object'
        and jsonb_typeof("alerts"."raw_payload") = 'object');--> statement-breakpoint
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_assignment_shape_check" CHECK (("alerts"."assigned_team_id" is null) = ("alerts"."assigned_team_epoch_id" is null)
        and ("alerts"."assigned_team_id" is not null or ("alerts"."assignee_user_id" is null and "alerts"."claimed_by_user_id" is null))
        and ("alerts"."claimed_by_user_id" is null or "alerts"."claimed_by_user_id" = "alerts"."assignee_user_id"));--> statement-breakpoint
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_updated_after_created_check" CHECK ("alerts"."updated_at" >= "alerts"."created_at"
        and "alerts"."received_at" >= "alerts"."detected_at"
        and ("alerts"."closed_at" is null or "alerts"."closed_at" >= "alerts"."created_at"));--> statement-breakpoint
CREATE POLICY "ticket_workflow_versions_api_tenant" ON "ticket_workflow_versions" AS PERMISSIVE FOR SELECT TO "periapsis_api" USING (
  "ticket_workflow_versions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "ticket_workflow_versions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "ticket_workflows_api_tenant" ON "ticket_workflows" AS PERMISSIVE FOR SELECT TO "periapsis_api" USING (
  "ticket_workflows"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "ticket_workflows"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "alert_case_links_api_tenant" ON "alert_case_links" AS PERMISSIVE FOR SELECT TO "periapsis_api" USING (
  "alert_case_links"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "alert_case_links"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "cases_api_tenant" ON "cases" AS PERMISSIVE FOR SELECT TO "periapsis_api" USING (
  "cases"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "cases"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "ticket_activities_api_tenant" ON "ticket_activities" AS PERMISSIVE FOR SELECT TO "periapsis_api" USING (
  "ticket_activities"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "ticket_activities"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "ticket_comments_api_tenant" ON "ticket_comments" AS PERMISSIVE FOR SELECT TO "periapsis_api" USING (
  "ticket_comments"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "ticket_comments"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);