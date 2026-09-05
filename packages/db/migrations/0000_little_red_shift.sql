CREATE TYPE "public"."alert_severity" AS ENUM('informational', 'low', 'medium', 'high', 'critical');--> statement-breakpoint
CREATE TYPE "public"."alert_status" AS ENUM('new', 'in_progress', 'closed');--> statement-breakpoint
CREATE TYPE "public"."audit_actor_type" AS ENUM('user', 'service_account', 'system');--> statement-breakpoint
CREATE TYPE "public"."audit_outcome" AS ENUM('success', 'failure', 'denied');--> statement-breakpoint
CREATE TYPE "public"."membership_role" AS ENUM('tenant_admin', 'soc_manager', 'senior_analyst', 'analyst', 'customer_manager', 'customer_user', 'read_only');--> statement-breakpoint
CREATE TYPE "public"."membership_status" AS ENUM('invited', 'active', 'suspended');--> statement-breakpoint
CREATE TYPE "public"."tenant_status" AS ENUM('active', 'suspended');--> statement-breakpoint
CREATE ROLE "periapsis_api";--> statement-breakpoint
CREATE ROLE "periapsis_auditor";--> statement-breakpoint
CREATE ROLE "periapsis_migrator";--> statement-breakpoint
CREATE ROLE "periapsis_notifier";--> statement-breakpoint
CREATE ROLE "periapsis_worker";--> statement-breakpoint
CREATE TABLE "alerts" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"external_id" text,
	"title" text NOT NULL,
	"description" text,
	"status" "alert_status" DEFAULT 'new' NOT NULL,
	"severity" "alert_severity" DEFAULT 'medium' NOT NULL,
	"created_by" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"version" integer DEFAULT 1 NOT NULL,
	CONSTRAINT "alerts_tenant_external_id_key" UNIQUE("tenant_id","external_id"),
	CONSTRAINT "alerts_id_uuidv7_check" CHECK (uuid_extract_version("alerts"."id") = 7),
	CONSTRAINT "alerts_title_not_blank_check" CHECK (btrim("alerts"."title") <> ''),
	CONSTRAINT "alerts_version_positive_check" CHECK ("alerts"."version" > 0),
	CONSTRAINT "alerts_updated_after_created_check" CHECK ("alerts"."updated_at" >= "alerts"."created_at")
);
--> statement-breakpoint
ALTER TABLE "alerts" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "audit_chain_heads" (
	"tenant_id" uuid PRIMARY KEY NOT NULL,
	"last_sequence" bigint DEFAULT 0 NOT NULL,
	"last_event_hash" char(64) DEFAULT '0000000000000000000000000000000000000000000000000000000000000000' NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "audit_chain_heads_tenant_uuidv7_check" CHECK (uuid_extract_version("audit_chain_heads"."tenant_id") = 7),
	CONSTRAINT "audit_chain_heads_last_sequence_nonnegative_check" CHECK ("audit_chain_heads"."last_sequence" >= 0),
	CONSTRAINT "audit_chain_heads_last_hash_format_check" CHECK ("audit_chain_heads"."last_event_hash" ~ '^[0-9a-f]{64}$')
);
--> statement-breakpoint
ALTER TABLE "audit_chain_heads" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "audit_events" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"sequence" bigint GENERATED ALWAYS AS IDENTITY (sequence name "audit_events_sequence_seq" INCREMENT BY 1 MINVALUE 1 MAXVALUE 9223372036854775807 START WITH 1 CACHE 1),
	"occurred_at" timestamp with time zone DEFAULT now() NOT NULL,
	"actor_type" "audit_actor_type" NOT NULL,
	"actor_user_id" uuid,
	"impersonated_by_user_id" uuid,
	"action" text NOT NULL,
	"resource_type" text NOT NULL,
	"resource_id" uuid,
	"request_id" uuid,
	"correlation_id" uuid,
	"ip_address" "inet",
	"user_agent" text,
	"authentication_method" text,
	"outcome" "audit_outcome" NOT NULL,
	"reason" text,
	"before" jsonb,
	"after" jsonb,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"previous_hash" char(64) DEFAULT '0000000000000000000000000000000000000000000000000000000000000000' NOT NULL,
	"event_hash" char(64) DEFAULT '0000000000000000000000000000000000000000000000000000000000000000' NOT NULL,
	CONSTRAINT "audit_events_tenant_sequence_key" UNIQUE("tenant_id","sequence"),
	CONSTRAINT "audit_events_id_uuidv7_check" CHECK (uuid_extract_version("audit_events"."id") = 7),
	CONSTRAINT "audit_events_action_not_blank_check" CHECK (btrim("audit_events"."action") <> ''),
	CONSTRAINT "audit_events_resource_type_not_blank_check" CHECK (btrim("audit_events"."resource_type") <> ''),
	CONSTRAINT "audit_events_actor_consistency_check" CHECK (("audit_events"."actor_type" = 'user' and "audit_events"."actor_user_id" is not null)
        or ("audit_events"."actor_type" <> 'user' and "audit_events"."actor_user_id" is null)),
	CONSTRAINT "audit_events_previous_hash_format_check" CHECK ("audit_events"."previous_hash" ~ '^[0-9a-f]{64}$'),
	CONSTRAINT "audit_events_event_hash_format_check" CHECK ("audit_events"."event_hash" ~ '^[0-9a-f]{64}$')
);
--> statement-breakpoint
ALTER TABLE "audit_events" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_memberships" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"role" "membership_role" NOT NULL,
	"status" "membership_status" DEFAULT 'active' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_memberships_tenant_user_key" UNIQUE("tenant_id","user_id"),
	CONSTRAINT "tenant_memberships_id_uuidv7_check" CHECK (uuid_extract_version("tenant_memberships"."id") = 7),
	CONSTRAINT "tenant_memberships_updated_after_created_check" CHECK ("tenant_memberships"."updated_at" >= "tenant_memberships"."created_at")
);
--> statement-breakpoint
ALTER TABLE "tenant_memberships" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "users" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"email" text NOT NULL,
	"display_name" text NOT NULL,
	"first_name" text,
	"last_name" text,
	"active" boolean DEFAULT true NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "users_email_key" UNIQUE("email"),
	CONSTRAINT "users_id_uuidv7_check" CHECK (uuid_extract_version("users"."id") = 7),
	CONSTRAINT "users_email_canonical_check" CHECK ("users"."email" = lower("users"."email")),
	CONSTRAINT "users_email_shape_check" CHECK (position('@' in "users"."email") > 1),
	CONSTRAINT "users_display_name_not_blank_check" CHECK (btrim("users"."display_name") <> ''),
	CONSTRAINT "users_updated_after_created_check" CHECK ("users"."updated_at" >= "users"."created_at")
);
--> statement-breakpoint
ALTER TABLE "users" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "outbox_events" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"aggregate_type" text NOT NULL,
	"aggregate_id" uuid NOT NULL,
	"event_type" text NOT NULL,
	"schema_version" integer DEFAULT 1 NOT NULL,
	"payload" jsonb NOT NULL,
	"deduplication_key" text,
	"correlation_id" uuid,
	"causation_id" uuid,
	"occurred_at" timestamp with time zone DEFAULT now() NOT NULL,
	"available_at" timestamp with time zone DEFAULT now() NOT NULL,
	"attempts" integer DEFAULT 0 NOT NULL,
	"max_attempts" integer DEFAULT 12 NOT NULL,
	"locked_at" timestamp with time zone,
	"locked_by" text,
	"processed_at" timestamp with time zone,
	"last_error" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "outbox_events_tenant_deduplication_key" UNIQUE("tenant_id","deduplication_key"),
	CONSTRAINT "outbox_events_id_uuidv7_check" CHECK (uuid_extract_version("outbox_events"."id") = 7),
	CONSTRAINT "outbox_events_aggregate_type_not_blank_check" CHECK (btrim("outbox_events"."aggregate_type") <> ''),
	CONSTRAINT "outbox_events_event_type_not_blank_check" CHECK (btrim("outbox_events"."event_type") <> ''),
	CONSTRAINT "outbox_events_schema_version_positive_check" CHECK ("outbox_events"."schema_version" > 0),
	CONSTRAINT "outbox_events_attempts_nonnegative_check" CHECK ("outbox_events"."attempts" >= 0),
	CONSTRAINT "outbox_events_max_attempts_positive_check" CHECK ("outbox_events"."max_attempts" > 0),
	CONSTRAINT "outbox_events_lock_consistency_check" CHECK (("outbox_events"."locked_at" is null) = ("outbox_events"."locked_by" is null))
);
--> statement-breakpoint
ALTER TABLE "outbox_events" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenants" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"slug" text NOT NULL,
	"name" text NOT NULL,
	"status" "tenant_status" DEFAULT 'active' NOT NULL,
	"timezone" text DEFAULT 'UTC' NOT NULL,
	"locale" text DEFAULT 'en' NOT NULL,
	"version" integer DEFAULT 1 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenants_slug_key" UNIQUE("slug"),
	CONSTRAINT "tenants_id_uuidv7_check" CHECK (uuid_extract_version("tenants"."id") = 7),
	CONSTRAINT "tenants_slug_canonical_check" CHECK ("tenants"."slug" = lower("tenants"."slug")),
	CONSTRAINT "tenants_slug_not_blank_check" CHECK (btrim("tenants"."slug") <> ''),
	CONSTRAINT "tenants_name_not_blank_check" CHECK (btrim("tenants"."name") <> ''),
	CONSTRAINT "tenants_version_positive_check" CHECK ("tenants"."version" > 0),
	CONSTRAINT "tenants_updated_after_created_check" CHECK ("tenants"."updated_at" >= "tenants"."created_at")
);
--> statement-breakpoint
ALTER TABLE "tenants" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_creator_membership_fk" FOREIGN KEY ("tenant_id","created_by") REFERENCES "public"."tenant_memberships"("tenant_id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "audit_chain_heads" ADD CONSTRAINT "audit_chain_heads_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "audit_events" ADD CONSTRAINT "audit_events_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "audit_events" ADD CONSTRAINT "audit_events_actor_user_id_users_id_fk" FOREIGN KEY ("actor_user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "audit_events" ADD CONSTRAINT "audit_events_impersonated_by_user_id_users_id_fk" FOREIGN KEY ("impersonated_by_user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "audit_events" ADD CONSTRAINT "audit_events_actor_membership_fk" FOREIGN KEY ("tenant_id","actor_user_id") REFERENCES "public"."tenant_memberships"("tenant_id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "audit_events" ADD CONSTRAINT "audit_events_impersonator_membership_fk" FOREIGN KEY ("tenant_id","impersonated_by_user_id") REFERENCES "public"."tenant_memberships"("tenant_id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_memberships" ADD CONSTRAINT "tenant_memberships_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_memberships" ADD CONSTRAINT "tenant_memberships_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "outbox_events" ADD CONSTRAINT "outbox_events_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "alerts_tenant_created_idx" ON "alerts" USING btree ("tenant_id","created_at","id");--> statement-breakpoint
CREATE INDEX "alerts_tenant_status_severity_idx" ON "alerts" USING btree ("tenant_id","status","severity");--> statement-breakpoint
CREATE INDEX "audit_events_tenant_time_idx" ON "audit_events" USING btree ("tenant_id","occurred_at","id");--> statement-breakpoint
CREATE INDEX "audit_events_tenant_resource_idx" ON "audit_events" USING btree ("tenant_id","resource_type","resource_id");--> statement-breakpoint
CREATE INDEX "tenant_memberships_user_tenant_idx" ON "tenant_memberships" USING btree ("user_id","tenant_id");--> statement-breakpoint
CREATE INDEX "tenant_memberships_tenant_role_idx" ON "tenant_memberships" USING btree ("tenant_id","role");--> statement-breakpoint
CREATE INDEX "users_active_idx" ON "users" USING btree ("active");--> statement-breakpoint
CREATE INDEX "outbox_events_dequeue_idx" ON "outbox_events" USING btree ("available_at","occurred_at","id") WHERE "outbox_events"."processed_at" is null and "outbox_events"."attempts" < "outbox_events"."max_attempts";--> statement-breakpoint
CREATE INDEX "outbox_events_tenant_aggregate_idx" ON "outbox_events" USING btree ("tenant_id","aggregate_type","aggregate_id");--> statement-breakpoint
CREATE INDEX "tenants_status_idx" ON "tenants" USING btree ("status");--> statement-breakpoint
CREATE POLICY "alerts_api_tenant" ON "alerts" AS PERMISSIVE FOR ALL TO "periapsis_api" USING (
  "alerts"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "alerts"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "alerts"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "alerts"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "audit_chain_heads_migrator_access" ON "audit_chain_heads" AS PERMISSIVE FOR ALL TO "periapsis_migrator" USING (true) WITH CHECK (true);--> statement-breakpoint
CREATE POLICY "audit_events_api_tenant" ON "audit_events" AS PERMISSIVE FOR ALL TO "periapsis_api" USING (
  "audit_events"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "audit_events"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "audit_events"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "audit_events"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "audit_events_worker_access" ON "audit_events" AS PERMISSIVE FOR ALL TO "periapsis_worker" USING (true) WITH CHECK (true);--> statement-breakpoint
CREATE POLICY "audit_events_notifier_access" ON "audit_events" AS PERMISSIVE FOR ALL TO "periapsis_notifier" USING (true) WITH CHECK (true);--> statement-breakpoint
CREATE POLICY "audit_events_auditor_select" ON "audit_events" AS PERMISSIVE FOR SELECT TO "periapsis_auditor" USING (true);--> statement-breakpoint
CREATE POLICY "tenant_memberships_api_self" ON "tenant_memberships" AS PERMISSIVE FOR SELECT TO "periapsis_api" USING ("tenant_memberships"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
        and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
        and "tenant_memberships"."status" = 'active');--> statement-breakpoint
CREATE POLICY "users_api_tenant_select" ON "users" AS PERMISSIVE FOR SELECT TO "periapsis_api" USING (exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."user_id" = "users"."id"
      and "tenant_memberships"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  ));--> statement-breakpoint
CREATE POLICY "outbox_events_api_tenant" ON "outbox_events" AS PERMISSIVE FOR ALL TO "periapsis_api" USING (
  "outbox_events"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "outbox_events"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "outbox_events"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "outbox_events"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "outbox_events_worker_access" ON "outbox_events" AS PERMISSIVE FOR ALL TO "periapsis_worker" USING (true) WITH CHECK (true);--> statement-breakpoint
CREATE POLICY "outbox_events_notifier_access" ON "outbox_events" AS PERMISSIVE FOR ALL TO "periapsis_notifier" USING (true) WITH CHECK (true);--> statement-breakpoint
CREATE POLICY "tenants_api_select_current" ON "tenants" AS PERMISSIVE FOR SELECT TO "periapsis_api" USING (
  "tenants"."id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenants"."id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);