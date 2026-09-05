CREATE TABLE "customer_contact_commands" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"actor_membership_id" uuid NOT NULL,
	"actor_user_id" uuid NOT NULL,
	"operation" text NOT NULL,
	"key_digest" "bytea" NOT NULL,
	"request_digest" "bytea" NOT NULL,
	"result_resource_id" uuid NOT NULL,
	"result_version" integer NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone DEFAULT now() + interval '24 hours' NOT NULL,
	CONSTRAINT "customer_contact_commands_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "customer_contact_commands_replay_key" UNIQUE("tenant_id","actor_membership_id","operation","key_digest"),
	CONSTRAINT "customer_contact_commands_id_uuidv7_check" CHECK ((uuid_extract_version("customer_contact_commands"."id") = 7) is true),
	CONSTRAINT "customer_contact_commands_operation_check" CHECK ("customer_contact_commands"."operation" in (
        'contact.create',
        'contact.replace',
        'contact.archive',
        'portal.preference.replace',
        'contact_group.create',
        'contact_group.version',
        'contact_group.archive',
        'ticket_contact.link',
        'ticket_contact.archive'
      )),
	CONSTRAINT "customer_contact_commands_digest_check" CHECK (octet_length("customer_contact_commands"."key_digest") = 32
        and octet_length("customer_contact_commands"."request_digest") = 32),
	CONSTRAINT "customer_contact_commands_result_check" CHECK ("customer_contact_commands"."result_version" > 0),
	CONSTRAINT "customer_contact_commands_retention_check" CHECK ("customer_contact_commands"."expires_at" > "customer_contact_commands"."created_at"
        and "customer_contact_commands"."expires_at" <= "customer_contact_commands"."created_at" + interval '7 days')
);
--> statement-breakpoint
ALTER TABLE "customer_contact_commands" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "customer_contact_group_version_members" (
	"tenant_id" uuid NOT NULL,
	"group_id" uuid NOT NULL,
	"group_version" integer NOT NULL,
	"contact_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "customer_contact_group_version_members_pkey" PRIMARY KEY("tenant_id","group_id","group_version","contact_id")
);
--> statement-breakpoint
ALTER TABLE "customer_contact_group_version_members" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "customer_contact_group_versions" (
	"tenant_id" uuid NOT NULL,
	"group_id" uuid NOT NULL,
	"version" integer NOT NULL,
	"name" text NOT NULL,
	"description" text DEFAULT '' NOT NULL,
	"mode" text NOT NULL,
	"rule_schema_version" integer DEFAULT 1 NOT NULL,
	"rule" jsonb,
	"created_by_membership_id" uuid NOT NULL,
	"created_by_user_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "customer_contact_group_versions_pkey" PRIMARY KEY("tenant_id","group_id","version"),
	CONSTRAINT "customer_contact_group_versions_version_check" CHECK ("customer_contact_group_versions"."version" > 0 and "customer_contact_group_versions"."rule_schema_version" = 1),
	CONSTRAINT "customer_contact_group_versions_name_check" CHECK (btrim("customer_contact_group_versions"."name") <> ''
        and char_length("customer_contact_group_versions"."name") <= 160
        and char_length("customer_contact_group_versions"."description") <= 2000
        and "customer_contact_group_versions"."name" !~ '[[:cntrl:]]'
        and "customer_contact_group_versions"."description" !~ '[[:cntrl:]]'),
	CONSTRAINT "customer_contact_group_versions_shape_check" CHECK (("customer_contact_group_versions"."mode" = 'manual' and "customer_contact_group_versions"."rule" is null)
        or ("customer_contact_group_versions"."mode" = 'dynamic'
          and jsonb_typeof("customer_contact_group_versions"."rule") = 'object'
          and octet_length("customer_contact_group_versions"."rule"::text) <= 32768))
);
--> statement-breakpoint
ALTER TABLE "customer_contact_group_versions" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "customer_contact_groups" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"key" text NOT NULL,
	"current_version" integer DEFAULT 1 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"archived_at" timestamp with time zone,
	CONSTRAINT "customer_contact_groups_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "customer_contact_groups_tenant_key_key" UNIQUE("tenant_id","key"),
	CONSTRAINT "customer_contact_groups_id_uuidv7_check" CHECK ((uuid_extract_version("customer_contact_groups"."id") = 7) is true),
	CONSTRAINT "customer_contact_groups_key_check" CHECK ("customer_contact_groups"."key" ~ '^[a-z][a-z0-9_.-]{0,63}$'),
	CONSTRAINT "customer_contact_groups_version_check" CHECK ("customer_contact_groups"."current_version" > 0),
	CONSTRAINT "customer_contact_groups_lifecycle_check" CHECK ("customer_contact_groups"."updated_at" >= "customer_contact_groups"."created_at"
        and ("customer_contact_groups"."archived_at" is null or (
          "customer_contact_groups"."archived_at" >= "customer_contact_groups"."created_at"
          and "customer_contact_groups"."updated_at" >= "customer_contact_groups"."archived_at"
        )))
);
--> statement-breakpoint
ALTER TABLE "customer_contact_groups" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "customer_contact_notification_windows" (
	"tenant_id" uuid NOT NULL,
	"contact_id" uuid NOT NULL,
	"iso_weekday" integer NOT NULL,
	"start_minute" integer NOT NULL,
	"end_minute" integer NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "customer_contact_notification_windows_pkey" PRIMARY KEY("tenant_id","contact_id","iso_weekday","start_minute"),
	CONSTRAINT "customer_contact_notification_windows_bounds_check" CHECK ("customer_contact_notification_windows"."iso_weekday" between 1 and 7
        and "customer_contact_notification_windows"."start_minute" between 0 and 1439
        and "customer_contact_notification_windows"."end_minute" between 1 and 1440
        and "customer_contact_notification_windows"."start_minute" < "customer_contact_notification_windows"."end_minute")
);
--> statement-breakpoint
ALTER TABLE "customer_contact_notification_windows" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "customer_contacts" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"first_name" text NOT NULL,
	"last_name" text NOT NULL,
	"email" text NOT NULL,
	"phone" text,
	"function" text NOT NULL,
	"language" text NOT NULL,
	"timezone" text NOT NULL,
	"escalation_priority" integer DEFAULT 0 NOT NULL,
	"contact_class" text NOT NULL,
	"notification_categories" text[] DEFAULT ARRAY[]::text[] NOT NULL,
	"email_allowed" boolean DEFAULT true NOT NULL,
	"active" boolean DEFAULT true NOT NULL,
	"tags" text[] DEFAULT ARRAY[]::text[] NOT NULL,
	"linked_membership_id" uuid,
	"linked_user_id" uuid,
	"version" integer DEFAULT 1 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"archived_at" timestamp with time zone,
	CONSTRAINT "customer_contacts_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "customer_contacts_link_snapshot_key" UNIQUE("tenant_id","id","linked_membership_id","linked_user_id"),
	CONSTRAINT "customer_contacts_id_uuidv7_check" CHECK ((uuid_extract_version("customer_contacts"."id") = 7) is true),
	CONSTRAINT "customer_contacts_link_shape_check" CHECK (("customer_contacts"."linked_membership_id" is null) = ("customer_contacts"."linked_user_id" is null)),
	CONSTRAINT "customer_contacts_name_check" CHECK (btrim("customer_contacts"."first_name") <> ''
        and btrim("customer_contacts"."last_name") <> ''
        and char_length("customer_contacts"."first_name") <= 160
        and char_length("customer_contacts"."last_name") <= 160
        and "customer_contacts"."first_name" !~ '[[:cntrl:]]'
        and "customer_contacts"."last_name" !~ '[[:cntrl:]]'),
	CONSTRAINT "customer_contacts_email_check" CHECK ("customer_contacts"."email" = lower(btrim("customer_contacts"."email"))
        and position('@' in "customer_contacts"."email") > 1
        and char_length("customer_contacts"."email") <= 320
        and "customer_contacts"."email" !~ '[[:cntrl:]]'),
	CONSTRAINT "customer_contacts_phone_check" CHECK ("customer_contacts"."phone" is null or (
        btrim("customer_contacts"."phone") <> ''
        and char_length("customer_contacts"."phone") <= 64
        and "customer_contacts"."phone" !~ '[[:cntrl:]<>]'
      )),
	CONSTRAINT "customer_contacts_function_check" CHECK (btrim("customer_contacts"."function") <> ''
        and char_length("customer_contacts"."function") <= 160
        and "customer_contacts"."function" !~ '[[:cntrl:]]'),
	CONSTRAINT "customer_contacts_language_check" CHECK ("customer_contacts"."language" ~ '^[a-z]{2,3}(-[A-Z][a-z]{3})?(-([A-Z]{2}|[0-9]{3}))?$'),
	CONSTRAINT "customer_contacts_timezone_check" CHECK (char_length("customer_contacts"."timezone") <= 64
        and ("customer_contacts"."timezone" = 'UTC'
          or "customer_contacts"."timezone" ~ '^[A-Za-z][A-Za-z0-9_+.-]{0,62}(/[A-Za-z0-9_+.-]{1,63}){1,3}$')),
	CONSTRAINT "customer_contacts_escalation_priority_check" CHECK ("customer_contacts"."escalation_priority" between 0 and 100),
	CONSTRAINT "customer_contacts_class_check" CHECK ("customer_contacts"."contact_class" ~ '^[a-z][a-z0-9_.-]{0,63}$'),
	CONSTRAINT "customer_contacts_category_check" CHECK (cardinality("customer_contacts"."notification_categories") <= 64
        and array_position("customer_contacts"."notification_categories", null) is null
        and array_to_string("customer_contacts"."notification_categories", ',')
          ~ '^([a-z][a-z0-9_.-]{0,63}(,[a-z][a-z0-9_.-]{0,63})*)?$'),
	CONSTRAINT "customer_contacts_tags_check" CHECK (cardinality("customer_contacts"."tags") <= 100
        and array_position("customer_contacts"."tags", null) is null
        and array_to_string("customer_contacts"."tags", ',')
          ~ '^([a-z][a-z0-9_.-]{0,63}(,[a-z][a-z0-9_.-]{0,63})*)?$'),
	CONSTRAINT "customer_contacts_version_check" CHECK ("customer_contacts"."version" > 0),
	CONSTRAINT "customer_contacts_lifecycle_check" CHECK ("customer_contacts"."updated_at" >= "customer_contacts"."created_at"
        and ("customer_contacts"."archived_at" is null or (
          "customer_contacts"."archived_at" >= "customer_contacts"."created_at"
          and "customer_contacts"."updated_at" >= "customer_contacts"."archived_at"
          and "customer_contacts"."active" is false
        )))
);
--> statement-breakpoint
ALTER TABLE "customer_contacts" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "ticket_activity_author_snapshots" (
	"tenant_id" uuid NOT NULL,
	"activity_id" uuid NOT NULL,
	"audience" text NOT NULL,
	"author_contact_id" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "ticket_activity_author_snapshots_pkey" PRIMARY KEY("tenant_id","activity_id"),
	CONSTRAINT "ticket_activity_author_snapshots_shape_check" CHECK (("ticket_activity_author_snapshots"."audience" = 'operator' and "ticket_activity_author_snapshots"."author_contact_id" is null)
        or ("ticket_activity_author_snapshots"."audience" = 'customer' and "ticket_activity_author_snapshots"."author_contact_id" is not null))
);
--> statement-breakpoint
ALTER TABLE "ticket_activity_author_snapshots" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "ticket_comment_author_snapshots" (
	"tenant_id" uuid NOT NULL,
	"comment_id" uuid NOT NULL,
	"audience" text NOT NULL,
	"author_membership_id" uuid NOT NULL,
	"author_user_id" uuid NOT NULL,
	"author_contact_id" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "ticket_comment_author_snapshots_pkey" PRIMARY KEY("tenant_id","comment_id"),
	CONSTRAINT "ticket_comment_author_snapshots_shape_check" CHECK (("ticket_comment_author_snapshots"."audience" = 'operator' and "ticket_comment_author_snapshots"."author_contact_id" is null)
        or ("ticket_comment_author_snapshots"."audience" = 'customer' and "ticket_comment_author_snapshots"."author_contact_id" is not null))
);
--> statement-breakpoint
ALTER TABLE "ticket_comment_author_snapshots" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "ticket_customer_contacts" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"alert_id" uuid,
	"case_id" uuid,
	"contact_id" uuid NOT NULL,
	"role" text NOT NULL,
	"origin" text DEFAULT 'manual' NOT NULL,
	"source_alert_id" uuid,
	"source_alert_version" integer,
	"version" integer DEFAULT 1 NOT NULL,
	"created_by_membership_id" uuid NOT NULL,
	"created_by_user_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"archived_at" timestamp with time zone,
	CONSTRAINT "ticket_customer_contacts_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "ticket_customer_contacts_id_uuidv7_check" CHECK ((uuid_extract_version("ticket_customer_contacts"."id") = 7) is true),
	CONSTRAINT "ticket_customer_contacts_resource_check" CHECK (("ticket_customer_contacts"."alert_id" is null) <> ("ticket_customer_contacts"."case_id" is null)),
	CONSTRAINT "ticket_customer_contacts_role_check" CHECK ("ticket_customer_contacts"."role" in ('primary', 'escalation', 'watcher')),
	CONSTRAINT "ticket_customer_contacts_origin_check" CHECK (("ticket_customer_contacts"."origin" = 'manual'
          and "ticket_customer_contacts"."source_alert_id" is null
          and "ticket_customer_contacts"."source_alert_version" is null)
        or ("ticket_customer_contacts"."origin" = 'escalation_copy'
          and "ticket_customer_contacts"."case_id" is not null
          and "ticket_customer_contacts"."source_alert_id" is not null
          and "ticket_customer_contacts"."source_alert_version" > 0)),
	CONSTRAINT "ticket_customer_contacts_version_check" CHECK ("ticket_customer_contacts"."version" > 0),
	CONSTRAINT "ticket_customer_contacts_archive_check" CHECK ("ticket_customer_contacts"."archived_at" is null or "ticket_customer_contacts"."archived_at" >= "ticket_customer_contacts"."created_at")
);
--> statement-breakpoint
ALTER TABLE "ticket_customer_contacts" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "ticket_comments" DROP CONSTRAINT "ticket_comments_origin_check";--> statement-breakpoint
ALTER TABLE "customer_contact_commands" ADD CONSTRAINT "customer_contact_commands_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "customer_contact_commands" ADD CONSTRAINT "customer_contact_commands_actor_fk" FOREIGN KEY ("tenant_id","actor_membership_id","actor_user_id") REFERENCES "public"."tenant_memberships"("tenant_id","id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "customer_contact_group_version_members" ADD CONSTRAINT "customer_contact_group_version_members_version_fk" FOREIGN KEY ("tenant_id","group_id","group_version") REFERENCES "public"."customer_contact_group_versions"("tenant_id","group_id","version") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "customer_contact_group_version_members" ADD CONSTRAINT "customer_contact_group_version_members_contact_fk" FOREIGN KEY ("tenant_id","contact_id") REFERENCES "public"."customer_contacts"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "customer_contact_group_versions" ADD CONSTRAINT "customer_contact_group_versions_group_fk" FOREIGN KEY ("tenant_id","group_id") REFERENCES "public"."customer_contact_groups"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "customer_contact_group_versions" ADD CONSTRAINT "customer_contact_group_versions_actor_fk" FOREIGN KEY ("tenant_id","created_by_membership_id","created_by_user_id") REFERENCES "public"."tenant_memberships"("tenant_id","id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "customer_contact_groups" ADD CONSTRAINT "customer_contact_groups_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "customer_contact_notification_windows" ADD CONSTRAINT "customer_contact_notification_windows_contact_fk" FOREIGN KEY ("tenant_id","contact_id") REFERENCES "public"."customer_contacts"("tenant_id","id") ON DELETE cascade ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "customer_contacts" ADD CONSTRAINT "customer_contacts_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "customer_contacts" ADD CONSTRAINT "customer_contacts_linked_membership_fk" FOREIGN KEY ("tenant_id","linked_membership_id","linked_user_id") REFERENCES "public"."tenant_memberships"("tenant_id","id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "ticket_activity_author_snapshots" ADD CONSTRAINT "ticket_activity_author_snapshots_activity_fk" FOREIGN KEY ("tenant_id","activity_id") REFERENCES "public"."ticket_activities"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "ticket_activity_author_snapshots" ADD CONSTRAINT "ticket_activity_author_snapshots_customer_contact_fk" FOREIGN KEY ("tenant_id","author_contact_id") REFERENCES "public"."customer_contacts"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "ticket_comment_author_snapshots" ADD CONSTRAINT "ticket_comment_author_snapshots_comment_fk" FOREIGN KEY ("tenant_id","comment_id") REFERENCES "public"."ticket_comments"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "ticket_comment_author_snapshots" ADD CONSTRAINT "ticket_comment_author_snapshots_customer_contact_fk" FOREIGN KEY ("tenant_id","author_contact_id","author_membership_id","author_user_id") REFERENCES "public"."customer_contacts"("tenant_id","id","linked_membership_id","linked_user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "ticket_customer_contacts" ADD CONSTRAINT "ticket_customer_contacts_alert_fk" FOREIGN KEY ("tenant_id","alert_id") REFERENCES "public"."alerts"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "ticket_customer_contacts" ADD CONSTRAINT "ticket_customer_contacts_case_fk" FOREIGN KEY ("tenant_id","case_id") REFERENCES "public"."cases"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "ticket_customer_contacts" ADD CONSTRAINT "ticket_customer_contacts_contact_fk" FOREIGN KEY ("tenant_id","contact_id") REFERENCES "public"."customer_contacts"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "ticket_customer_contacts" ADD CONSTRAINT "ticket_customer_contacts_source_alert_fk" FOREIGN KEY ("tenant_id","source_alert_id") REFERENCES "public"."alerts"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "ticket_customer_contacts" ADD CONSTRAINT "ticket_customer_contacts_actor_fk" FOREIGN KEY ("tenant_id","created_by_membership_id","created_by_user_id") REFERENCES "public"."tenant_memberships"("tenant_id","id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
CREATE INDEX "customer_contact_commands_expiry_idx" ON "customer_contact_commands" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "customer_contact_group_version_members_contact_idx" ON "customer_contact_group_version_members" USING btree ("tenant_id","contact_id","group_id","group_version");--> statement-breakpoint
CREATE INDEX "customer_contact_groups_tenant_active_idx" ON "customer_contact_groups" USING btree ("tenant_id","key","id") WHERE "customer_contact_groups"."archived_at" is null;--> statement-breakpoint
CREATE UNIQUE INDEX "customer_contacts_tenant_membership_key" ON "customer_contacts" USING btree ("tenant_id","linked_membership_id") WHERE "customer_contacts"."linked_membership_id" is not null;--> statement-breakpoint
CREATE INDEX "customer_contacts_tenant_active_name_idx" ON "customer_contacts" USING btree ("tenant_id","active","last_name","first_name","id");--> statement-breakpoint
CREATE INDEX "customer_contacts_tenant_email_idx" ON "customer_contacts" USING btree ("tenant_id","email","id");--> statement-breakpoint
CREATE UNIQUE INDEX "ticket_customer_contacts_active_alert_contact_key" ON "ticket_customer_contacts" USING btree ("tenant_id","alert_id","contact_id") WHERE "ticket_customer_contacts"."alert_id" is not null and "ticket_customer_contacts"."archived_at" is null;--> statement-breakpoint
CREATE UNIQUE INDEX "ticket_customer_contacts_active_case_contact_key" ON "ticket_customer_contacts" USING btree ("tenant_id","case_id","contact_id") WHERE "ticket_customer_contacts"."case_id" is not null and "ticket_customer_contacts"."archived_at" is null;--> statement-breakpoint
CREATE INDEX "ticket_customer_contacts_contact_idx" ON "ticket_customer_contacts" USING btree ("tenant_id","contact_id","id");--> statement-breakpoint
ALTER TABLE "ticket_activities" ADD CONSTRAINT "ticket_activities_origin_check" CHECK ("ticket_activities"."origin" in ('api', 'customer_portal', 'escalation_copy', 'system'));--> statement-breakpoint
ALTER TABLE "ticket_comments" ADD CONSTRAINT "ticket_comments_origin_check" CHECK ("ticket_comments"."origin" in ('api', 'customer_portal', 'escalation_copy', 'system'));--> statement-breakpoint
CREATE POLICY "customer_contact_group_version_members_api_tenant" ON "customer_contact_group_version_members" AS PERMISSIVE FOR SELECT TO "periapsis_api" USING (
  "customer_contact_group_version_members"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "customer_contact_group_version_members"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "customer_contact_group_versions_api_tenant" ON "customer_contact_group_versions" AS PERMISSIVE FOR SELECT TO "periapsis_api" USING (
  "customer_contact_group_versions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "customer_contact_group_versions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "customer_contact_groups_api_tenant" ON "customer_contact_groups" AS PERMISSIVE FOR SELECT TO "periapsis_api" USING (
  "customer_contact_groups"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "customer_contact_groups"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "customer_contact_notification_windows_api_tenant" ON "customer_contact_notification_windows" AS PERMISSIVE FOR SELECT TO "periapsis_api" USING (
  "customer_contact_notification_windows"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "customer_contact_notification_windows"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "customer_contacts_api_tenant" ON "customer_contacts" AS PERMISSIVE FOR SELECT TO "periapsis_api" USING (
  "customer_contacts"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "customer_contacts"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "ticket_activity_author_snapshots_api_tenant" ON "ticket_activity_author_snapshots" AS PERMISSIVE FOR SELECT TO "periapsis_api" USING (
  "ticket_activity_author_snapshots"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "ticket_activity_author_snapshots"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "ticket_comment_author_snapshots_api_tenant" ON "ticket_comment_author_snapshots" AS PERMISSIVE FOR SELECT TO "periapsis_api" USING (
  "ticket_comment_author_snapshots"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "ticket_comment_author_snapshots"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "ticket_customer_contacts_api_tenant" ON "ticket_customer_contacts" AS PERMISSIVE FOR SELECT TO "periapsis_api" USING (
  "ticket_customer_contacts"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "ticket_customer_contacts"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);
--> statement-breakpoint

-- Contacts are selected through tenant RLS but all mutation paths stay behind
-- bounded SECURITY DEFINER commands that re-check live authorization.
ALTER TABLE public.customer_contacts OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.customer_contact_notification_windows OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.customer_contact_groups OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.customer_contact_group_versions OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.customer_contact_group_version_members OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.ticket_customer_contacts OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.ticket_comment_author_snapshots OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.ticket_activity_author_snapshots OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.customer_contact_commands OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.customer_contacts FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.customer_contact_notification_windows FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.customer_contact_groups FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.customer_contact_group_versions FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.customer_contact_group_version_members FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.ticket_customer_contacts FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.ticket_comment_author_snapshots FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.ticket_activity_author_snapshots FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.customer_contact_commands FORCE ROW LEVEL SECURITY;--> statement-breakpoint
REVOKE ALL ON TABLE
  public.customer_contacts,
  public.customer_contact_notification_windows,
  public.customer_contact_groups,
  public.customer_contact_group_versions,
  public.customer_contact_group_version_members,
  public.ticket_customer_contacts,
  public.ticket_comment_author_snapshots,
  public.ticket_activity_author_snapshots,
  public.customer_contact_commands
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
     periapsis_auditor;--> statement-breakpoint
GRANT SELECT ON TABLE
  public.customer_contacts,
  public.customer_contact_notification_windows,
  public.customer_contact_groups,
  public.customer_contact_group_versions,
  public.customer_contact_group_version_members,
  public.ticket_customer_contacts,
  public.ticket_comment_author_snapshots,
  public.ticket_activity_author_snapshots
TO periapsis_api;--> statement-breakpoint

INSERT INTO public.tenant_permissions (
  id, key, display_name, description, service_account_allowed
)
VALUES
  (uuidv7(), 'contact.read', 'Read contacts', 'Read tenant customer contacts and their notification preferences.', false),
  (uuidv7(), 'contact.manage', 'Manage contacts', 'Create, update, archive, and link tenant customer contacts.', false),
  (uuidv7(), 'contact.preference.manage', 'Manage contact preferences', 'Manage notification preferences for tenant customer contacts.', false),
  (uuidv7(), 'contact.group.read', 'Read contact groups', 'Read immutable tenant recipient-group versions.', false),
  (uuidv7(), 'contact.group.manage', 'Manage contact groups', 'Create, version, and archive tenant recipient groups.', false),
  (uuidv7(), 'portal.alert.read', 'Read portal alerts', 'Read customer-safe Alerts linked to the caller contact.', false),
  (uuidv7(), 'portal.case.read', 'Read portal cases', 'Read customer-safe Cases linked to the caller contact.', false),
  (uuidv7(), 'portal.comment.public', 'Create portal comments', 'Create public comments on customer-visible linked tickets.', false),
  (uuidv7(), 'portal.attachment.read', 'Read portal attachments', 'Read customer-visible attachments on linked tickets.', false),
  (uuidv7(), 'portal.contact.preference.manage', 'Manage portal contact preferences', 'Manage notification preferences for the exact caller contact.', false)
ON CONFLICT (key) DO NOTHING;--> statement-breakpoint

INSERT INTO public.tenant_permission_scopes (permission_id, scope)
SELECT permission.id,
       CASE WHEN permission.key LIKE 'portal.%'
            THEN 'own'::public.authorization_scope
            ELSE 'tenant'::public.authorization_scope END
FROM public.tenant_permissions AS permission
WHERE permission.key IN (
  'contact.read', 'contact.manage', 'contact.preference.manage',
  'contact.group.read', 'contact.group.manage',
  'portal.alert.read', 'portal.case.read', 'portal.comment.public',
  'portal.attachment.read', 'portal.contact.preference.manage'
)
ON CONFLICT DO NOTHING;--> statement-breakpoint

CREATE FUNCTION app.private_seed_tenant_contact_authorization_v1(
  p_tenant_id uuid
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  changed_role record;
  changed_role_ids uuid[] := ARRAY[]::uuid[];
  newly_changed_role_ids uuid[];
BEGIN
  IF p_tenant_id IS NULL OR NOT EXISTS (
    SELECT 1 FROM public.tenants AS tenant WHERE tenant.id = p_tenant_id
  ) THEN
    RAISE EXCEPTION 'contact authorization tenant is unavailable'
      USING ERRCODE = 'P0002';
  END IF;

  WITH inserted AS (
    INSERT INTO public.tenant_role_permissions (
      tenant_id, role_id, permission_id, scope, created_by_membership_id
    )
    SELECT p_tenant_id, role.id, permission.id,
           'tenant'::public.authorization_scope, NULL
    FROM public.tenant_roles AS role
    JOIN public.tenant_permissions AS permission
      ON permission.key IN (
        'contact.read', 'contact.manage', 'contact.preference.manage',
        'contact.group.read', 'contact.group.manage'
      )
    WHERE role.tenant_id = p_tenant_id
      AND role.key = 'tenant_admin'
      AND role.principal_kind = 'human'
      AND role.system_role AND role.archived_at IS NULL
    ON CONFLICT DO NOTHING
    RETURNING role_id
  )
  SELECT coalesce(array_agg(DISTINCT inserted.role_id), ARRAY[]::uuid[])
  INTO changed_role_ids
  FROM inserted;

  WITH inserted AS (
    INSERT INTO public.tenant_role_permissions (
      tenant_id, role_id, permission_id, scope, created_by_membership_id
    )
    SELECT p_tenant_id, role.id, permission.id,
           'own'::public.authorization_scope, NULL
    FROM public.tenant_roles AS role
    JOIN public.tenant_permissions AS permission ON (
      (role.key IN ('customer_manager', 'customer_user')
      AND permission.key IN (
        'portal.alert.read', 'portal.case.read', 'portal.comment.public',
        'portal.attachment.read', 'portal.contact.preference.manage'
      )) OR (role.key = 'read_only'
      AND permission.key IN (
        'portal.alert.read', 'portal.case.read', 'portal.attachment.read'
      ))
    )
    WHERE role.tenant_id = p_tenant_id
      AND role.principal_kind = 'human'
      AND role.system_role AND role.archived_at IS NULL
    ON CONFLICT DO NOTHING
    RETURNING role_id
  )
  SELECT coalesce(array_agg(DISTINCT inserted.role_id), ARRAY[]::uuid[])
  INTO newly_changed_role_ids
  FROM inserted;
  changed_role_ids := ARRAY(
    SELECT DISTINCT role_id
    FROM unnest(changed_role_ids || newly_changed_role_ids) AS changed(role_id)
    ORDER BY role_id
  );

  INSERT INTO public.tenant_role_delegation_ceilings (
    tenant_id, role_id, permission_id, scope, created_by_membership_id
  )
  SELECT p_tenant_id, role.id, permission.id,
         'tenant'::public.authorization_scope, NULL
  FROM public.tenant_roles AS role
  JOIN public.tenant_permissions AS permission
    ON permission.key IN (
      'contact.read', 'contact.manage', 'contact.preference.manage',
      'contact.group.read', 'contact.group.manage'
    )
  WHERE role.tenant_id = p_tenant_id
    AND role.key = 'tenant_admin'
    AND role.principal_kind = 'human'
    AND role.system_role AND role.archived_at IS NULL
  ON CONFLICT DO NOTHING;

  FOR changed_role IN
    SELECT role.*
    FROM public.tenant_roles AS role
    WHERE role.tenant_id = p_tenant_id
      AND role.id = ANY(changed_role_ids)
    FOR UPDATE OF role
  LOOP
    IF changed_role.version >= 2147483647 THEN
      RAISE EXCEPTION 'contact authorization role version is exhausted'
        USING ERRCODE = '55000';
    END IF;
    UPDATE public.tenant_roles
    SET version = changed_role.version + 1,
        updated_at = transaction_timestamp()
    WHERE tenant_id = p_tenant_id AND id = changed_role.id;
  END LOOP;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.private_seed_tenant_contact_authorization_v1(uuid)
  OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_seed_tenant_contact_authorization_v1(uuid)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;--> statement-breakpoint

DO $contact_permission_seed$
DECLARE tenant_record record;
BEGIN
  FOR tenant_record IN
    SELECT tenant.id FROM public.tenants AS tenant ORDER BY tenant.id
  LOOP
    PERFORM app.private_seed_tenant_contact_authorization_v1(tenant_record.id);
  END LOOP;
END
$contact_permission_seed$;--> statement-breakpoint

CREATE FUNCTION app.seed_tenant_authorization_contacts_successor(
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
  PERFORM app.seed_tenant_authorization(
    p_tenant_id, p_initial_admin_membership_id
  );
  PERFORM app.private_seed_tenant_contact_authorization_v1(p_tenant_id);
END;
$function$;--> statement-breakpoint
DO $contact_seed_successor$
BEGIN
  EXECUTE 'ALTER FUNCTION app.seed_tenant_authorization(uuid, uuid) RENAME TO seed_tenant_authorization_contacts_compatibility_impl';
  EXECUTE 'ALTER FUNCTION app.seed_tenant_authorization_contacts_successor(uuid, uuid) RENAME TO seed_tenant_authorization';
END
$contact_seed_successor$;--> statement-breakpoint
ALTER FUNCTION app.seed_tenant_authorization(uuid, uuid)
  OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION
  app.seed_tenant_authorization(uuid, uuid),
  app.seed_tenant_authorization_contacts_compatibility_impl(uuid, uuid)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
     periapsis_auditor;--> statement-breakpoint

-- Historical rows predate an authoritative audience snapshot. Classifying
-- them as operator is the only fail-closed backfill; new rows are captured by
-- the trigger in the same transaction as their source row.
INSERT INTO public.ticket_comment_author_snapshots (
  tenant_id, comment_id, audience, author_membership_id, author_user_id,
  author_contact_id, created_at
)
SELECT comment.tenant_id, comment.id, 'operator',
       comment.author_membership_id, comment.author_user_id,
       NULL, comment.created_at
FROM public.ticket_comments AS comment
ON CONFLICT DO NOTHING;--> statement-breakpoint
INSERT INTO public.ticket_activity_author_snapshots (
  tenant_id, activity_id, audience, author_contact_id, created_at
)
SELECT activity.tenant_id, activity.id, 'operator', NULL, activity.occurred_at
FROM public.ticket_activities AS activity
ON CONFLICT DO NOTHING;--> statement-breakpoint

CREATE FUNCTION app.capture_ticket_comment_author_snapshot_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  customer_actor boolean := false;
  contact_id uuid;
BEGIN
  -- Escalation copies preserve historical content but do not carry an exact
  -- source-comment provenance column.  Classify those rows as operator rather
  -- than re-evaluating a possibly stale customer role against the target Case.
  IF NEW.origin <> 'escalation_copy' THEN
    SELECT membership.role IN ('customer_manager', 'customer_user', 'read_only')
    INTO customer_actor
    FROM public.tenant_memberships AS membership
    WHERE membership.tenant_id = NEW.tenant_id
      AND membership.id = NEW.author_membership_id
      AND membership.user_id = NEW.author_user_id
      AND membership.status = 'active';
    IF NOT FOUND THEN
      RAISE EXCEPTION 'comment author is not a live tenant identity'
        USING ERRCODE = '42501';
    END IF;
  END IF;
  IF customer_actor THEN
    IF NEW.visibility <> 'public' THEN
      RAISE EXCEPTION 'customer comments must be public'
        USING ERRCODE = '42501';
    END IF;
    SELECT contact.id INTO STRICT contact_id
    FROM public.customer_contacts AS contact
    JOIN public.ticket_customer_contacts AS link
      ON link.tenant_id = contact.tenant_id
     AND link.contact_id = contact.id
     AND link.archived_at IS NULL
     AND (link.alert_id = NEW.alert_id OR link.case_id = NEW.case_id)
    WHERE contact.tenant_id = NEW.tenant_id
      AND contact.linked_membership_id = NEW.author_membership_id
      AND contact.linked_user_id = NEW.author_user_id
      AND contact.active AND contact.archived_at IS NULL;
  END IF;
  INSERT INTO public.ticket_comment_author_snapshots (
    tenant_id, comment_id, audience, author_membership_id, author_user_id,
    author_contact_id, created_at
  ) VALUES (
    NEW.tenant_id, NEW.id,
    CASE WHEN customer_actor THEN 'customer' ELSE 'operator' END,
    NEW.author_membership_id, NEW.author_user_id, contact_id, NEW.created_at
  );
  RETURN NEW;
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'customer comment lacks one exact active contact link'
    USING ERRCODE = '42501';
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.capture_ticket_comment_author_snapshot_v1()
  OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.capture_ticket_comment_author_snapshot_v1()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;--> statement-breakpoint
CREATE TRIGGER ticket_comments_capture_author_snapshot_v1
AFTER INSERT ON public.ticket_comments
FOR EACH ROW EXECUTE FUNCTION app.capture_ticket_comment_author_snapshot_v1();--> statement-breakpoint

CREATE FUNCTION app.capture_ticket_activity_author_snapshot_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  customer_actor boolean := false;
  contact_id uuid;
BEGIN
  IF NEW.actor_principal_kind = 'human' THEN
    SELECT membership.role IN (
      'customer_manager', 'customer_user', 'read_only'
    ) INTO customer_actor
    FROM public.tenant_memberships AS membership
    WHERE membership.tenant_id = NEW.tenant_id
      AND membership.id = NEW.actor_membership_id
      AND membership.user_id = NEW.actor_user_id
      AND membership.status = 'active';
    IF NOT FOUND THEN
      RAISE EXCEPTION 'activity author is not a live tenant identity'
        USING ERRCODE = '42501';
    END IF;
  END IF;
  IF customer_actor THEN
    SELECT contact.id INTO STRICT contact_id
    FROM public.customer_contacts AS contact
    JOIN public.ticket_customer_contacts AS link
      ON link.tenant_id = contact.tenant_id
     AND link.contact_id = contact.id
     AND link.archived_at IS NULL
     AND (link.alert_id = NEW.alert_id OR link.case_id = NEW.case_id)
    WHERE contact.tenant_id = NEW.tenant_id
      AND contact.linked_membership_id = NEW.actor_membership_id
      AND contact.linked_user_id = NEW.actor_user_id
      AND contact.active AND contact.archived_at IS NULL;
  END IF;
  INSERT INTO public.ticket_activity_author_snapshots (
    tenant_id, activity_id, audience, author_contact_id, created_at
  ) VALUES (
    NEW.tenant_id, NEW.id,
    CASE WHEN customer_actor THEN 'customer' ELSE 'operator' END,
    contact_id, NEW.occurred_at
  );
  RETURN NEW;
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'customer activity lacks one exact active contact link'
    USING ERRCODE = '42501';
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.capture_ticket_activity_author_snapshot_v1()
  OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.capture_ticket_activity_author_snapshot_v1()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;--> statement-breakpoint
CREATE TRIGGER ticket_activities_capture_author_snapshot_v1
AFTER INSERT ON public.ticket_activities
FOR EACH ROW EXECUTE FUNCTION app.capture_ticket_activity_author_snapshot_v1();--> statement-breakpoint

CREATE FUNCTION app.private_contact_windows_are_valid_v1(p_windows jsonb)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
  WITH entries AS (
    SELECT entry.value, entry.ordinality
    FROM jsonb_array_elements(
      CASE WHEN jsonb_typeof(p_windows) = 'array'
           THEN p_windows ELSE '[]'::jsonb END
    ) WITH ORDINALITY AS entry(value, ordinality)
  ), parsed AS (
    SELECT ordinality,
      CASE WHEN value ->> 'isoWeekday' ~ '^[1-7]$'
           THEN (value ->> 'isoWeekday')::integer END AS weekday,
      CASE WHEN value ->> 'startMinute' ~ '^(0|[1-9][0-9]{0,3})$'
           THEN (value ->> 'startMinute')::integer END AS start_minute,
      CASE WHEN value ->> 'endMinute' ~ '^[1-9][0-9]{0,3}$'
           THEN (value ->> 'endMinute')::integer END AS end_minute,
      value
    FROM entries
  ), ordered AS (
    SELECT parsed.*,
      lag(weekday) OVER (ORDER BY ordinality) AS prior_weekday,
      lag(start_minute) OVER (ORDER BY ordinality) AS prior_start,
      lag(end_minute) OVER (ORDER BY ordinality) AS prior_end
    FROM parsed
  )
  SELECT jsonb_typeof(p_windows) = 'array'
    AND jsonb_array_length(p_windows) <= 64
    AND NOT EXISTS (
      SELECT 1 FROM ordered
      WHERE jsonb_typeof(value) <> 'object'
         OR (SELECT count(*) FROM jsonb_object_keys(value)) <> 3
         OR NOT value ?& ARRAY['isoWeekday','startMinute','endMinute']
         OR jsonb_typeof(value -> 'isoWeekday') <> 'number'
         OR jsonb_typeof(value -> 'startMinute') <> 'number'
         OR jsonb_typeof(value -> 'endMinute') <> 'number'
         OR weekday IS NULL OR start_minute IS NULL OR end_minute IS NULL
         OR start_minute < 0 OR start_minute > 1439
         OR end_minute < 1 OR end_minute > 1440
         OR start_minute >= end_minute
         OR prior_weekday IS NOT NULL AND (
           ROW(weekday, start_minute, end_minute)
             <= ROW(prior_weekday, prior_start, prior_end)
           OR weekday = prior_weekday AND start_minute < prior_end
         )
    );
$function$;--> statement-breakpoint
ALTER FUNCTION app.private_contact_windows_are_valid_v1(jsonb)
  OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_contact_windows_are_valid_v1(jsonb)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;--> statement-breakpoint

CREATE FUNCTION app.private_contact_rule_is_valid_v1(p_rule jsonb)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
  WITH RECURSIVE walk(node, depth) AS (
    SELECT p_rule, 1
    UNION ALL
    SELECT child.value, walk.depth + 1
    FROM walk
    CROSS JOIN LATERAL jsonb_array_elements(
      CASE WHEN jsonb_typeof(walk.node -> 'children') = 'array'
           THEN walk.node -> 'children' ELSE '[]'::jsonb END
    ) AS child(value)
    WHERE walk.depth < 9
  ), facts AS (
    SELECT count(*) AS node_count, max(depth) AS maximum_depth
    FROM walk
  ), invalid AS (
    SELECT 1
    FROM walk
    WHERE jsonb_typeof(node) <> 'object'
       OR node ->> 'kind' NOT IN ('all','any','not','predicate')
       OR CASE node ->> 'kind'
         WHEN 'all' THEN
           (SELECT count(*) FROM jsonb_object_keys(node)) <> 2
           OR NOT node ?& ARRAY['kind','children']
           OR jsonb_typeof(node -> 'children') <> 'array'
           OR jsonb_array_length(node -> 'children') NOT BETWEEN 1 AND 64
           OR EXISTS (
             SELECT 1
             FROM (
               SELECT child.value::text AS signature,
                      lag(child.value::text) OVER (ORDER BY child.ordinality) AS prior
               FROM jsonb_array_elements(node -> 'children')
                    WITH ORDINALITY AS child(value, ordinality)
             ) AS ordered
             WHERE ordered.prior IS NOT NULL
               AND ordered.signature <= ordered.prior
           )
         WHEN 'any' THEN
           (SELECT count(*) FROM jsonb_object_keys(node)) <> 2
           OR NOT node ?& ARRAY['kind','children']
           OR jsonb_typeof(node -> 'children') <> 'array'
           OR jsonb_array_length(node -> 'children') NOT BETWEEN 1 AND 64
           OR EXISTS (
             SELECT 1
             FROM (
               SELECT child.value::text AS signature,
                      lag(child.value::text) OVER (ORDER BY child.ordinality) AS prior
               FROM jsonb_array_elements(node -> 'children')
                    WITH ORDINALITY AS child(value, ordinality)
             ) AS ordered
             WHERE ordered.prior IS NOT NULL
               AND ordered.signature <= ordered.prior
           )
         WHEN 'not' THEN
           (SELECT count(*) FROM jsonb_object_keys(node)) <> 2
           OR NOT node ?& ARRAY['kind','children']
           OR jsonb_typeof(node -> 'children') <> 'array'
           OR jsonb_array_length(node -> 'children') <> 1
         WHEN 'predicate' THEN
           (SELECT count(*) FROM jsonb_object_keys(node)) <> 4
           OR NOT node ?& ARRAY['kind','field','operator','values']
           OR node ->> 'field' NOT IN (
             'active','email_allowed','contact_class','tag',
             'notification_category','language','timezone',
             'escalation_priority','linked_account'
           )
           OR node ->> 'operator' NOT IN (
             'equals','not_equals','one_of','none_of','contains',
             'not_contains','greater_than_or_equal','less_than_or_equal',
             'exists','not_exists'
           )
           OR jsonb_typeof(node -> 'values') <> 'array'
           OR jsonb_array_length(node -> 'values') > 64
           OR EXISTS (
             SELECT 1
             FROM jsonb_array_elements(node -> 'values') AS value(item)
             WHERE jsonb_typeof(value.item) <> 'string'
                OR char_length(value.item #>> '{}') > 64
           )
           OR EXISTS (
             SELECT 1
             FROM (
               SELECT value.item #>> '{}' AS item,
                      lag(value.item #>> '{}') OVER (
                        ORDER BY value.ordinality
                      ) AS prior
               FROM jsonb_array_elements(node -> 'values')
                    WITH ORDINALITY AS value(item, ordinality)
             ) AS ordered
             WHERE ordered.prior IS NOT NULL
               AND ordered.item <= ordered.prior
           )
           OR CASE node ->> 'field'
             WHEN 'active' THEN
               node ->> 'operator' NOT IN ('equals','not_equals')
               OR jsonb_array_length(node -> 'values') <> 1
               OR node #>> '{values,0}' NOT IN ('true','false')
             WHEN 'email_allowed' THEN
               node ->> 'operator' NOT IN ('equals','not_equals')
               OR jsonb_array_length(node -> 'values') <> 1
               OR node #>> '{values,0}' NOT IN ('true','false')
             WHEN 'contact_class' THEN
               node ->> 'operator' NOT IN (
                 'equals','not_equals','one_of','none_of'
               ) OR jsonb_array_length(node -> 'values') NOT BETWEEN 1 AND 64
               OR EXISTS (
                 SELECT 1
                 FROM jsonb_array_elements_text(node -> 'values') AS item(value)
                 WHERE item.value !~ '^[a-z][a-z0-9_.-]{0,63}$'
               )
             WHEN 'tag' THEN
               node ->> 'operator' NOT IN ('contains','not_contains')
               OR jsonb_array_length(node -> 'values') <> 1
               OR node #>> '{values,0}' !~ '^[a-z][a-z0-9_.-]{0,63}$'
             WHEN 'notification_category' THEN
               node ->> 'operator' NOT IN ('contains','not_contains')
               OR jsonb_array_length(node -> 'values') <> 1
               OR node #>> '{values,0}' !~ '^[a-z][a-z0-9_.-]{0,63}$'
             WHEN 'language' THEN
               node ->> 'operator' NOT IN (
                 'equals','not_equals','one_of','none_of'
               ) OR jsonb_array_length(node -> 'values') NOT BETWEEN 1 AND 64
               OR EXISTS (
                 SELECT 1
                 FROM jsonb_array_elements_text(node -> 'values') AS item(value)
                 WHERE item.value !~ '^[a-z]{2,3}(-[A-Z][a-z]{3})?(-([A-Z]{2}|[0-9]{3}))?$'
               )
             WHEN 'timezone' THEN
               node ->> 'operator' NOT IN (
                 'equals','not_equals','one_of','none_of'
               ) OR jsonb_array_length(node -> 'values') NOT BETWEEN 1 AND 64
               OR EXISTS (
                 SELECT 1
                 FROM jsonb_array_elements_text(node -> 'values') AS item(value)
                 WHERE char_length(item.value) > 64
                   OR item.value <> 'UTC'
                      AND item.value !~ '^[A-Za-z][A-Za-z0-9_+.-]{0,62}(/[A-Za-z0-9_+.-]{1,63}){1,3}$'
               )
             WHEN 'escalation_priority' THEN
               node ->> 'operator' NOT IN (
                 'equals','not_equals','greater_than_or_equal',
                 'less_than_or_equal'
               ) OR jsonb_array_length(node -> 'values') <> 1
               OR node #>> '{values,0}' !~ '^(0|[1-9][0-9]?|100)$'
             WHEN 'linked_account' THEN
               node ->> 'operator' NOT IN ('exists','not_exists')
               OR jsonb_array_length(node -> 'values') <> 0
             ELSE true
           END
         ELSE true
       END
  )
  SELECT jsonb_typeof(p_rule) = 'object'
    AND facts.node_count BETWEEN 1 AND 128
    AND facts.maximum_depth <= 8
    AND NOT EXISTS (SELECT 1 FROM invalid)
  FROM facts;
$function$;--> statement-breakpoint
ALTER FUNCTION app.private_contact_rule_is_valid_v1(jsonb)
  OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_contact_rule_is_valid_v1(jsonb)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;--> statement-breakpoint

CREATE FUNCTION app.private_contact_rule_matches_v1(
  p_rule jsonb,
  p_contact public.customer_contacts
)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  child jsonb;
  actual_text text;
  expected_texts text[];
  expected_boolean boolean;
  expected_integer integer;
BEGIN
  IF NOT app.private_contact_rule_is_valid_v1(p_rule) THEN
    RETURN false;
  END IF;
  CASE p_rule ->> 'kind'
    WHEN 'all' THEN
      FOR child IN SELECT value FROM jsonb_array_elements(p_rule -> 'children') LOOP
        IF NOT app.private_contact_rule_matches_v1(child, p_contact) THEN
          RETURN false;
        END IF;
      END LOOP;
      RETURN true;
    WHEN 'any' THEN
      FOR child IN SELECT value FROM jsonb_array_elements(p_rule -> 'children') LOOP
        IF app.private_contact_rule_matches_v1(child, p_contact) THEN
          RETURN true;
        END IF;
      END LOOP;
      RETURN false;
    WHEN 'not' THEN
      RETURN NOT app.private_contact_rule_matches_v1(
        p_rule #> '{children,0}', p_contact
      );
    WHEN 'predicate' THEN
      SELECT array_agg(value ORDER BY ordinality)
      INTO expected_texts
      FROM jsonb_array_elements_text(p_rule -> 'values')
           WITH ORDINALITY AS item(value, ordinality);
      CASE p_rule ->> 'field'
        WHEN 'active' THEN
          expected_boolean := (p_rule #>> '{values,0}')::boolean;
          RETURN CASE p_rule ->> 'operator'
            WHEN 'equals' THEN p_contact.active = expected_boolean
            ELSE p_contact.active <> expected_boolean END;
        WHEN 'email_allowed' THEN
          expected_boolean := (p_rule #>> '{values,0}')::boolean;
          RETURN CASE p_rule ->> 'operator'
            WHEN 'equals' THEN p_contact.email_allowed = expected_boolean
            ELSE p_contact.email_allowed <> expected_boolean END;
        WHEN 'contact_class' THEN actual_text := p_contact.contact_class;
        WHEN 'language' THEN actual_text := p_contact.language;
        WHEN 'timezone' THEN actual_text := p_contact.timezone;
        WHEN 'tag' THEN
          RETURN CASE p_rule ->> 'operator'
            WHEN 'contains' THEN p_contact.tags @> ARRAY[p_rule #>> '{values,0}']
            ELSE NOT p_contact.tags @> ARRAY[p_rule #>> '{values,0}'] END;
        WHEN 'notification_category' THEN
          RETURN CASE p_rule ->> 'operator'
            WHEN 'contains' THEN p_contact.notification_categories
              @> ARRAY[p_rule #>> '{values,0}']
            ELSE NOT p_contact.notification_categories
              @> ARRAY[p_rule #>> '{values,0}'] END;
        WHEN 'escalation_priority' THEN
          expected_integer := (p_rule #>> '{values,0}')::integer;
          RETURN CASE p_rule ->> 'operator'
            WHEN 'equals' THEN p_contact.escalation_priority = expected_integer
            WHEN 'not_equals' THEN p_contact.escalation_priority <> expected_integer
            WHEN 'greater_than_or_equal' THEN p_contact.escalation_priority >= expected_integer
            ELSE p_contact.escalation_priority <= expected_integer END;
        WHEN 'linked_account' THEN
          RETURN CASE p_rule ->> 'operator'
            WHEN 'exists' THEN p_contact.linked_membership_id IS NOT NULL
            ELSE p_contact.linked_membership_id IS NULL END;
        ELSE RETURN false;
      END CASE;
      RETURN CASE p_rule ->> 'operator'
        WHEN 'equals' THEN actual_text = ANY(expected_texts)
        WHEN 'one_of' THEN actual_text = ANY(expected_texts)
        WHEN 'not_equals' THEN NOT (actual_text = ANY(expected_texts))
        ELSE NOT (actual_text = ANY(expected_texts))
      END;
    ELSE RETURN false;
  END CASE;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.private_contact_rule_matches_v1(jsonb, public.customer_contacts)
  OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_contact_rule_matches_v1(jsonb, public.customer_contacts)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.private_contact_rule_matches_v1(jsonb, public.customer_contacts)
  TO periapsis_notification_dispatch_owner;--> statement-breakpoint

CREATE FUNCTION app.private_append_contact_change_v1(
  p_action text,
  p_contact_id uuid,
  p_version integer,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text,
  p_before jsonb,
  p_after jsonb,
  p_metadata jsonb
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor_membership uuid := app.current_tenant_membership_id();
  actor_user uuid := app.context_user_id();
  event_id uuid := uuidv7();
BEGIN
  IF p_action NOT IN ('created','replaced','archived','preferences_replaced')
     OR p_contact_id IS NULL
     OR (uuid_extract_version(p_contact_id) = 7) IS NOT TRUE
     OR p_version NOT BETWEEN 1 AND 2147483647
     OR p_request_id IS NULL OR p_correlation_id IS NULL
     OR p_ip_address IS NULL OR p_authentication_method IS NULL
     OR p_before IS NOT NULL AND jsonb_typeof(p_before) <> 'object'
     OR p_after IS NULL OR jsonb_typeof(p_after) <> 'object'
     OR p_metadata IS NULL OR jsonb_typeof(p_metadata) <> 'object'
     OR p_before ?| ARRAY['email','phone','firstName','lastName']
     OR p_after ?| ARRAY['email','phone','firstName','lastName']
     OR p_metadata ?| ARRAY['email','phone','firstName','lastName'] THEN
    RAISE EXCEPTION 'contact side-effect envelope is invalid'
      USING ERRCODE = '22023';
  END IF;
  PERFORM app.append_tenant_authorization_audit(
    uuidv7(), 'tenant.contact.' || p_action, 'customer_contact',
    p_contact_id, p_request_id, p_correlation_id, p_ip_address,
    nullif(p_user_agent, ''), p_authentication_method,
    p_before, p_after,
    p_metadata || jsonb_build_object(
      'actor_membership_id', actor_membership,
      'pii_redacted', true
    )
  );
  PERFORM app.private_append_tenant_notification_event_v2(
    event_id, 'contact.changed', 'contact', p_contact_id, p_version,
    transaction_timestamp(), 'human', actor_user, 'api.contacts',
    'operator',
    jsonb_build_object(
      'contactId', p_contact_id,
      'version', p_version,
      'action', p_action,
      'piiRedacted', true
    ),
    NULL,
    'contact.changed:' || p_contact_id::text || ':' || p_version::text,
    p_correlation_id, p_request_id
  );
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.private_append_contact_change_v1(
  text, uuid, integer, uuid, uuid, inet, text, text, jsonb, jsonb, jsonb
) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_append_contact_change_v1(
  text, uuid, integer, uuid, uuid, inet, text, text, jsonb, jsonb, jsonb
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;--> statement-breakpoint

CREATE FUNCTION app.commit_customer_contact_v1(
  p_operation text,
  p_contact_id uuid,
  p_expected_version bigint,
  p_payload jsonb,
  p_key_digest bytea,
  p_request_digest bytea,
  p_reason text,
  p_request_id uuid,
  p_correlation_id uuid,
  p_actor_membership_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE(contact_id uuid, version integer, replayed boolean)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid;
  actor_user uuid := app.context_user_id();
  actor_is_customer boolean := false;
  command_record public.customer_contact_commands%ROWTYPE;
  locked public.customer_contacts%ROWTYPE;
  next_version integer;
  next_first_name text;
  next_last_name text;
  next_email text;
  next_phone text;
  next_function text;
  next_language text;
  next_timezone text;
  next_priority integer;
  next_class text;
  next_categories text[];
  next_windows jsonb;
  next_email_allowed boolean;
  next_active boolean;
  next_tags text[];
  next_linked_membership uuid;
  next_linked_user uuid;
  next_archived_at timestamp with time zone;
  side_effect_action text;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF p_operation NOT IN (
       'contact.create','contact.replace','contact.archive',
       'portal.preference.replace'
     )
     OR p_contact_id IS NULL
     OR (uuid_extract_version(p_contact_id) = 7) IS NOT TRUE
     OR p_expected_version NOT BETWEEN 0 AND 2147483646
     OR p_payload IS NULL OR jsonb_typeof(p_payload) <> 'object'
     OR (SELECT count(*) FROM jsonb_object_keys(p_payload)) <> 20
     OR NOT p_payload ?& ARRAY[
       'firstName','lastName','email','phone','function','language',
       'timezone','escalationPriority','contactClass',
       'notificationCategories','notificationWindows','emailAllowed',
       'active','tags','linkedMembershipId','linkedUserId','version',
       'createdAt','updatedAt','archivedAt'
     ]
     OR p_key_digest IS NULL OR octet_length(p_key_digest) <> 32
     OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32
     OR p_request_id IS NULL OR p_correlation_id IS NULL
     OR p_actor_membership_id IS DISTINCT FROM actor_membership
     OR p_ip_address IS NULL OR p_authentication_method IS NULL
     OR p_reason IS NULL OR char_length(p_reason) > 2000
     OR p_operation = 'contact.archive' AND btrim(p_reason) = ''
     OR p_operation <> 'contact.archive' AND p_reason <> '' THEN
    RAISE EXCEPTION 'contact command envelope is invalid'
      USING ERRCODE = '22023';
  END IF;

  IF jsonb_typeof(p_payload -> 'notificationCategories') <> 'array'
     OR jsonb_typeof(p_payload -> 'notificationWindows') <> 'array'
     OR jsonb_typeof(p_payload -> 'tags') <> 'array'
     OR jsonb_typeof(p_payload -> 'emailAllowed') <> 'boolean'
     OR jsonb_typeof(p_payload -> 'active') <> 'boolean'
     OR NOT app.private_contact_windows_are_valid_v1(
       p_payload -> 'notificationWindows'
     ) THEN
    RAISE EXCEPTION 'contact payload collections are invalid'
      USING ERRCODE = '22023';
  END IF;

  next_first_name := p_payload ->> 'firstName';
  next_last_name := p_payload ->> 'lastName';
  next_email := p_payload ->> 'email';
  next_phone := p_payload ->> 'phone';
  next_function := p_payload ->> 'function';
  next_language := p_payload ->> 'language';
  next_timezone := p_payload ->> 'timezone';
  next_priority := (p_payload ->> 'escalationPriority')::integer;
  next_class := p_payload ->> 'contactClass';
  next_email_allowed := (p_payload ->> 'emailAllowed')::boolean;
  next_active := (p_payload ->> 'active')::boolean;
  next_version := (p_payload ->> 'version')::integer;
  next_linked_membership := (p_payload ->> 'linkedMembershipId')::uuid;
  next_linked_user := (p_payload ->> 'linkedUserId')::uuid;
  next_archived_at := (p_payload ->> 'archivedAt')::timestamp with time zone;
  next_windows := p_payload -> 'notificationWindows';
  SELECT coalesce(array_agg(item.value ORDER BY item.ordinality), ARRAY[]::text[])
    INTO next_categories
  FROM jsonb_array_elements_text(p_payload -> 'notificationCategories')
       WITH ORDINALITY AS item(value, ordinality);
  SELECT coalesce(array_agg(item.value ORDER BY item.ordinality), ARRAY[]::text[])
    INTO next_tags
  FROM jsonb_array_elements_text(p_payload -> 'tags')
       WITH ORDINALITY AS item(value, ordinality);

  IF next_first_name IS NULL OR next_last_name IS NULL OR next_email IS NULL
     OR next_function IS NULL OR next_language IS NULL OR next_timezone IS NULL
     OR next_class IS NULL OR next_version IS NULL
     OR next_categories IS DISTINCT FROM ARRAY(
       SELECT DISTINCT value FROM unnest(next_categories) AS item(value)
       ORDER BY value
     )
     OR next_tags IS DISTINCT FROM ARRAY(
       SELECT DISTINCT value FROM unnest(next_tags) AS item(value)
       ORDER BY value
     )
     OR cardinality(next_categories) > 64 OR cardinality(next_tags) > 100
     OR (next_linked_membership IS NULL) <> (next_linked_user IS NULL)
     OR NOT EXISTS (
       SELECT 1 FROM pg_timezone_names AS timezone
       WHERE timezone.name = next_timezone
     ) THEN
    RAISE EXCEPTION 'contact payload is not canonical'
      USING ERRCODE = '22023';
  END IF;
  IF next_linked_membership IS NOT NULL AND NOT EXISTS (
    SELECT 1
    FROM public.tenant_memberships AS membership
    JOIN public.users AS identity ON identity.id = membership.user_id
    WHERE membership.tenant_id = context_tenant
      AND membership.id = next_linked_membership
      AND membership.user_id = next_linked_user
      AND membership.status = 'active' AND identity.active
      AND membership.role IN ('customer_manager','customer_user','read_only')
  ) THEN
    RAISE EXCEPTION 'linked customer identity is unavailable'
      USING ERRCODE = '23503';
  END IF;

  PERFORM pg_advisory_xact_lock(hashtextextended(
    context_tenant::text || ':' || actor_membership::text || ':'
      || p_operation || ':' || encode(p_key_digest, 'hex'), 0
  ));
  DELETE FROM public.customer_contact_commands AS command
  WHERE command.expires_at <= transaction_timestamp();
  SELECT command.* INTO command_record
  FROM public.customer_contact_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.actor_membership_id = actor_membership
    AND command.operation = p_operation
    AND command.key_digest = p_key_digest
  FOR UPDATE;
  IF FOUND THEN
    IF command_record.request_digest IS DISTINCT FROM p_request_digest THEN
      RAISE EXCEPTION 'contact idempotency key conflicts'
        USING ERRCODE = '23505',
              CONSTRAINT = 'customer_contact_commands_replay_key';
    END IF;
    RETURN QUERY SELECT command_record.result_resource_id,
                        command_record.result_version, true;
    RETURN;
  END IF;

  SELECT membership.role IN ('customer_manager','customer_user','read_only')
  INTO actor_is_customer
  FROM public.tenant_memberships AS membership
  WHERE membership.tenant_id = context_tenant
    AND membership.id = actor_membership
    AND membership.user_id = actor_user
    AND membership.status = 'active';
  IF NOT FOUND THEN
    RAISE EXCEPTION 'contact actor is unavailable' USING ERRCODE = '42501';
  END IF;
  IF p_operation = 'portal.preference.replace' THEN
    IF NOT actor_is_customer
       OR NOT app.current_tenant_has_exact_permission(
         'portal.contact.preference.manage', 'own'
       ) THEN
      RAISE EXCEPTION 'portal preference permission is required'
        USING ERRCODE = '42501';
    END IF;
  ELSIF actor_is_customer
     OR NOT app.current_tenant_has_exact_permission(
       'contact.manage', 'tenant'
     ) THEN
    RAISE EXCEPTION 'contact management permission is required'
      USING ERRCODE = '42501';
  END IF;

  IF p_operation = 'contact.create' THEN
    IF p_expected_version <> 0 OR next_version <> 1
       OR next_archived_at IS NOT NULL OR NOT next_active THEN
      RAISE EXCEPTION 'contact create state is invalid'
        USING ERRCODE = '22023';
    END IF;
    INSERT INTO public.customer_contacts (
      id, tenant_id, first_name, last_name, email, phone, function,
      language, timezone, escalation_priority, contact_class,
      notification_categories, email_allowed, active, tags,
      linked_membership_id, linked_user_id, version, created_at, updated_at
    ) VALUES (
      p_contact_id, context_tenant, next_first_name, next_last_name,
      next_email, next_phone, next_function, next_language, next_timezone,
      next_priority, next_class, next_categories, next_email_allowed,
      next_active, next_tags, next_linked_membership, next_linked_user,
      1, transaction_timestamp(), transaction_timestamp()
    );
    side_effect_action := 'created';
  ELSE
    SELECT contact.* INTO locked
    FROM public.customer_contacts AS contact
    WHERE contact.tenant_id = context_tenant AND contact.id = p_contact_id
    FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'contact not found' USING ERRCODE = 'P0002';
    END IF;
    IF locked.version IS DISTINCT FROM p_expected_version
       OR locked.archived_at IS NOT NULL
       OR next_version IS DISTINCT FROM locked.version + 1 THEN
      RAISE EXCEPTION 'contact version precondition failed'
        USING ERRCODE = '40001';
    END IF;
    IF p_operation = 'portal.preference.replace' THEN
      IF locked.linked_membership_id IS DISTINCT FROM actor_membership
         OR locked.linked_user_id IS DISTINCT FROM actor_user
         OR NOT locked.active
         OR next_first_name IS DISTINCT FROM locked.first_name
         OR next_last_name IS DISTINCT FROM locked.last_name
         OR next_email IS DISTINCT FROM locked.email
         OR next_phone IS DISTINCT FROM locked.phone
         OR next_function IS DISTINCT FROM locked.function
         OR next_language IS DISTINCT FROM locked.language
         OR next_timezone IS DISTINCT FROM locked.timezone
         OR next_priority IS DISTINCT FROM locked.escalation_priority
         OR next_class IS DISTINCT FROM locked.contact_class
         OR next_active IS DISTINCT FROM locked.active
         OR next_tags IS DISTINCT FROM locked.tags
         OR next_linked_membership IS DISTINCT FROM locked.linked_membership_id
         OR next_linked_user IS DISTINCT FROM locked.linked_user_id
         OR next_archived_at IS NOT NULL THEN
        RAISE EXCEPTION 'portal preference payload exceeds self scope'
          USING ERRCODE = '42501';
      END IF;
      UPDATE public.customer_contacts
      SET notification_categories = next_categories,
          email_allowed = next_email_allowed,
          version = next_version,
          updated_at = transaction_timestamp()
      WHERE tenant_id = context_tenant AND id = p_contact_id;
      side_effect_action := 'preferences_replaced';
    ELSIF p_operation = 'contact.archive' THEN
      IF next_active OR next_archived_at IS NULL
         OR next_archived_at < locked.created_at
         OR next_archived_at > transaction_timestamp() + interval '1 minute' THEN
        RAISE EXCEPTION 'contact archive state is invalid'
          USING ERRCODE = '22023';
      END IF;
      UPDATE public.customer_contacts
      SET active = false, archived_at = next_archived_at,
          version = next_version, updated_at = next_archived_at
      WHERE tenant_id = context_tenant AND id = p_contact_id;
      side_effect_action := 'archived';
    ELSE
      IF next_archived_at IS NOT NULL THEN
        RAISE EXCEPTION 'contact replacement cannot archive'
          USING ERRCODE = '22023';
      END IF;
      UPDATE public.customer_contacts
      SET first_name = next_first_name, last_name = next_last_name,
          email = next_email, phone = next_phone, function = next_function,
          language = next_language, timezone = next_timezone,
          escalation_priority = next_priority, contact_class = next_class,
          notification_categories = next_categories,
          email_allowed = next_email_allowed, active = next_active,
          tags = next_tags, linked_membership_id = next_linked_membership,
          linked_user_id = next_linked_user, version = next_version,
          updated_at = transaction_timestamp()
      WHERE tenant_id = context_tenant AND id = p_contact_id;
      side_effect_action := 'replaced';
    END IF;
  END IF;

  DELETE FROM public.customer_contact_notification_windows
  WHERE tenant_id = context_tenant AND contact_id = p_contact_id;
  INSERT INTO public.customer_contact_notification_windows (
    tenant_id, contact_id, iso_weekday, start_minute, end_minute
  )
  SELECT context_tenant, p_contact_id,
         (window_entry.value ->> 'isoWeekday')::integer,
         (window_entry.value ->> 'startMinute')::integer,
         (window_entry.value ->> 'endMinute')::integer
  FROM jsonb_array_elements(next_windows) AS window_entry(value);

  PERFORM app.private_append_contact_change_v1(
    side_effect_action, p_contact_id, next_version,
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method,
    CASE WHEN p_operation = 'contact.create' THEN NULL
         ELSE jsonb_build_object(
           'version', locked.version,
           'active', locked.active,
           'archived', locked.archived_at IS NOT NULL
         ) END,
    jsonb_build_object(
      'version', next_version,
      'active', CASE WHEN p_operation = 'contact.archive'
                     THEN false ELSE next_active END,
      'archived', p_operation = 'contact.archive'
    ),
    jsonb_build_object(
      'reason_present', btrim(p_reason) <> '',
      'linked_identity', next_linked_membership IS NOT NULL,
      'category_count', cardinality(next_categories),
      'window_count', jsonb_array_length(next_windows),
      'tag_count', cardinality(next_tags)
    )
  );
  INSERT INTO public.customer_contact_commands (
    tenant_id, actor_membership_id, actor_user_id, operation,
    key_digest, request_digest, result_resource_id, result_version
  ) VALUES (
    context_tenant, actor_membership, actor_user, p_operation,
    p_key_digest, p_request_digest, p_contact_id, next_version
  );
  RETURN QUERY SELECT p_contact_id, next_version, false;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.commit_customer_contact_v1(
  text, uuid, bigint, jsonb, bytea, bytea, text, uuid, uuid, uuid,
  inet, text, text
) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.commit_customer_contact_v1(
  text, uuid, bigint, jsonb, bytea, bytea, text, uuid, uuid, uuid,
  inet, text, text
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.commit_customer_contact_v1(
  text, uuid, bigint, jsonb, bytea, bytea, text, uuid, uuid, uuid,
  inet, text, text
) TO periapsis_api;--> statement-breakpoint

CREATE FUNCTION app.commit_customer_contact_group_v1(
  p_operation text,
  p_group_id uuid,
  p_expected_version bigint,
  p_payload jsonb,
  p_key_digest bytea,
  p_request_digest bytea,
  p_request_id uuid,
  p_correlation_id uuid,
  p_actor_membership_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE(group_id uuid, version integer, replayed boolean)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid;
  actor_user uuid := app.context_user_id();
  command_record public.customer_contact_commands%ROWTYPE;
  locked public.customer_contact_groups%ROWTYPE;
  next_key text;
  next_version integer;
  next_name text;
  next_description text;
  next_mode text;
  next_rule_version integer;
  next_rule jsonb;
  next_member_ids uuid[];
  next_archived_at timestamp with time zone;
  action text;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF p_operation NOT IN (
       'contact_group.create','contact_group.version','contact_group.archive'
     )
     OR p_group_id IS NULL
     OR (uuid_extract_version(p_group_id) = 7) IS NOT TRUE
     OR p_expected_version NOT BETWEEN 0 AND 2147483646
     OR p_payload IS NULL OR jsonb_typeof(p_payload) <> 'object'
     OR (SELECT count(*) FROM jsonb_object_keys(p_payload)) <> 11
     OR NOT p_payload ?& ARRAY[
       'key','version','name','description','mode','ruleSchemaVersion',
       'rule','memberIds','createdAt','updatedAt','archivedAt'
     ]
     OR jsonb_typeof(p_payload -> 'memberIds') <> 'array'
     OR p_key_digest IS NULL OR octet_length(p_key_digest) <> 32
     OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32
     OR p_request_id IS NULL OR p_correlation_id IS NULL
     OR p_actor_membership_id IS DISTINCT FROM actor_membership
     OR p_ip_address IS NULL OR p_authentication_method IS NULL THEN
    RAISE EXCEPTION 'contact-group command envelope is invalid'
      USING ERRCODE = '22023';
  END IF;
  IF NOT app.current_tenant_has_exact_permission(
       'contact.group.manage', 'tenant'
     ) OR EXISTS (
       SELECT 1 FROM public.tenant_memberships AS membership
       WHERE membership.tenant_id = context_tenant
         AND membership.id = actor_membership
         AND membership.user_id = actor_user
         AND membership.role IN ('customer_manager','customer_user','read_only')
     ) THEN
    RAISE EXCEPTION 'contact-group management permission is required'
      USING ERRCODE = '42501';
  END IF;

  next_key := p_payload ->> 'key';
  next_version := (p_payload ->> 'version')::integer;
  next_name := p_payload ->> 'name';
  next_description := p_payload ->> 'description';
  next_mode := p_payload ->> 'mode';
  next_rule_version := (p_payload ->> 'ruleSchemaVersion')::integer;
  next_rule := p_payload -> 'rule';
  next_archived_at := (p_payload ->> 'archivedAt')::timestamp with time zone;
  SELECT coalesce(array_agg(item.value::uuid ORDER BY item.ordinality), ARRAY[]::uuid[])
  INTO next_member_ids
  FROM jsonb_array_elements_text(p_payload -> 'memberIds')
       WITH ORDINALITY AS item(value, ordinality);
  IF next_key IS NULL OR next_key !~ '^[a-z][a-z0-9_.-]{0,63}$'
     OR next_version NOT BETWEEN 1 AND 2147483647
     OR next_name IS NULL OR btrim(next_name) = ''
     OR char_length(next_name) > 160 OR next_name ~ '[[:cntrl:]]'
     OR next_description IS NULL OR char_length(next_description) > 2000
     OR next_description ~ '[[:cntrl:]]'
     OR next_rule_version <> 1
     OR cardinality(next_member_ids) > 10000
     OR next_member_ids IS DISTINCT FROM ARRAY(
       SELECT DISTINCT value FROM unnest(next_member_ids) AS item(value)
       ORDER BY value
     )
     OR EXISTS (
       SELECT 1 FROM unnest(next_member_ids) AS member(id)
       WHERE (uuid_extract_version(member.id) = 7) IS NOT TRUE
          OR NOT EXISTS (
            SELECT 1 FROM public.customer_contacts AS contact
            WHERE contact.tenant_id = context_tenant
              AND contact.id = member.id
              AND contact.active AND contact.archived_at IS NULL
          )
     )
     OR next_mode = 'manual' AND (
       next_rule IS DISTINCT FROM 'null'::jsonb
     )
     OR next_mode = 'dynamic' AND (
       cardinality(next_member_ids) <> 0
       OR NOT app.private_contact_rule_is_valid_v1(next_rule)
     )
     OR next_mode NOT IN ('manual','dynamic') THEN
    RAISE EXCEPTION 'contact-group payload is invalid'
      USING ERRCODE = '22023';
  END IF;

  PERFORM pg_advisory_xact_lock(hashtextextended(
    context_tenant::text || ':' || actor_membership::text || ':'
      || p_operation || ':' || encode(p_key_digest, 'hex'), 0
  ));
  DELETE FROM public.customer_contact_commands AS command
  WHERE command.expires_at <= transaction_timestamp();
  SELECT command.* INTO command_record
  FROM public.customer_contact_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.actor_membership_id = actor_membership
    AND command.operation = p_operation
    AND command.key_digest = p_key_digest
  FOR UPDATE;
  IF FOUND THEN
    IF command_record.request_digest IS DISTINCT FROM p_request_digest THEN
      RAISE EXCEPTION 'contact-group idempotency key conflicts'
        USING ERRCODE = '23505',
              CONSTRAINT = 'customer_contact_commands_replay_key';
    END IF;
    RETURN QUERY SELECT command_record.result_resource_id,
                        command_record.result_version, true;
    RETURN;
  END IF;

  IF p_operation = 'contact_group.create' THEN
    IF p_expected_version <> 0 OR next_version <> 1
       OR next_archived_at IS NOT NULL THEN
      RAISE EXCEPTION 'contact-group create state is invalid'
        USING ERRCODE = '22023';
    END IF;
    INSERT INTO public.customer_contact_groups (
      id, tenant_id, key, current_version, created_at, updated_at
    ) VALUES (
      p_group_id, context_tenant, next_key, 1,
      transaction_timestamp(), transaction_timestamp()
    );
    action := 'created';
  ELSE
    SELECT group_record.* INTO locked
    FROM public.customer_contact_groups AS group_record
    WHERE group_record.tenant_id = context_tenant
      AND group_record.id = p_group_id
    FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'contact group not found' USING ERRCODE = 'P0002';
    END IF;
    IF locked.current_version IS DISTINCT FROM p_expected_version
       OR locked.archived_at IS NOT NULL
       OR next_key IS DISTINCT FROM locked.key THEN
      RAISE EXCEPTION 'contact-group version precondition failed'
        USING ERRCODE = '40001';
    END IF;
    IF p_operation = 'contact_group.archive' THEN
      IF next_version IS DISTINCT FROM locked.current_version
         OR next_archived_at IS NULL
         OR next_archived_at < locked.created_at
         OR next_archived_at > transaction_timestamp() + interval '1 minute' THEN
        RAISE EXCEPTION 'contact-group archive state is invalid'
          USING ERRCODE = '22023';
      END IF;
      UPDATE public.customer_contact_groups
      SET archived_at = next_archived_at, updated_at = next_archived_at
      WHERE tenant_id = context_tenant AND id = p_group_id;
      action := 'archived';
    ELSE
      IF next_version IS DISTINCT FROM locked.current_version + 1
         OR next_archived_at IS NOT NULL THEN
        RAISE EXCEPTION 'contact-group next version is invalid'
          USING ERRCODE = '22023';
      END IF;
      UPDATE public.customer_contact_groups
      SET current_version = next_version,
          updated_at = transaction_timestamp()
      WHERE tenant_id = context_tenant AND id = p_group_id;
      action := 'versioned';
    END IF;
  END IF;

  IF p_operation <> 'contact_group.archive' THEN
    INSERT INTO public.customer_contact_group_versions (
      tenant_id, group_id, version, name, description, mode,
      rule_schema_version, rule, created_by_membership_id,
      created_by_user_id, created_at
    ) VALUES (
      context_tenant, p_group_id, next_version, next_name,
      next_description, next_mode, next_rule_version,
      CASE WHEN next_mode = 'dynamic' THEN next_rule ELSE NULL END,
      actor_membership, actor_user, transaction_timestamp()
    );
    INSERT INTO public.customer_contact_group_version_members (
      tenant_id, group_id, group_version, contact_id
    )
    SELECT context_tenant, p_group_id, next_version, member.id
    FROM unnest(next_member_ids) AS member(id);
  END IF;

  PERFORM app.append_tenant_authorization_audit(
    uuidv7(), 'tenant.contact_group.' || action, 'customer_contact_group',
    p_group_id, p_request_id, p_correlation_id, p_ip_address,
    nullif(p_user_agent, ''), p_authentication_method,
    CASE WHEN p_operation = 'contact_group.create' THEN NULL
         ELSE jsonb_build_object(
           'version', locked.current_version,
           'archived', locked.archived_at IS NOT NULL
         ) END,
    jsonb_build_object(
      'version', next_version,
      'mode', next_mode,
      'archived', p_operation = 'contact_group.archive'
    ),
    jsonb_build_object(
      'actor_membership_id', actor_membership,
      'member_count', cardinality(next_member_ids),
      'rule_present', next_mode = 'dynamic',
      'pii_redacted', true
    )
  );
  INSERT INTO public.outbox_events (
    tenant_id, aggregate_type, aggregate_id, aggregate_version,
    event_type, schema_version, payload, deduplication_key,
    correlation_id, causation_id, actor_kind, actor_id, producer,
    maximum_audience, occurred_at, available_at
  ) VALUES (
    context_tenant, 'contact', p_group_id, next_version,
    'contact_group.' || action, 1,
    jsonb_build_object(
      'group_id', p_group_id, 'version', next_version,
      'member_count', cardinality(next_member_ids),
      'pii_redacted', true
    ),
    'contact_group.' || action || ':' || p_group_id::text || ':' || next_version::text,
    p_correlation_id, p_request_id, 'human', actor_user,
    'api.contacts', 'operator', transaction_timestamp(),
    transaction_timestamp()
  );
  INSERT INTO public.customer_contact_commands (
    tenant_id, actor_membership_id, actor_user_id, operation,
    key_digest, request_digest, result_resource_id, result_version
  ) VALUES (
    context_tenant, actor_membership, actor_user, p_operation,
    p_key_digest, p_request_digest, p_group_id, next_version
  );
  RETURN QUERY SELECT p_group_id, next_version, false;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.commit_customer_contact_group_v1(
  text, uuid, bigint, jsonb, bytea, bytea, uuid, uuid, uuid,
  inet, text, text
) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.commit_customer_contact_group_v1(
  text, uuid, bigint, jsonb, bytea, bytea, uuid, uuid, uuid,
  inet, text, text
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.commit_customer_contact_group_v1(
  text, uuid, bigint, jsonb, bytea, bytea, uuid, uuid, uuid,
  inet, text, text
) TO periapsis_api;--> statement-breakpoint

CREATE FUNCTION app.commit_ticket_customer_contact_v1(
  p_operation text,
  p_link_id uuid,
  p_expected_link_version bigint,
  p_expected_ticket_version bigint,
  p_payload jsonb,
  p_key_digest bytea,
  p_request_digest bytea,
  p_reason text,
  p_request_id uuid,
  p_correlation_id uuid,
  p_actor_membership_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE(link_id uuid, version integer, replayed boolean)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid;
  actor_user uuid := app.context_user_id();
  command_record public.customer_contact_commands%ROWTYPE;
  locked_link public.ticket_customer_contacts%ROWTYPE;
  ticket_record record;
  next_kind text;
  next_ticket_id uuid;
  next_contact_id uuid;
  next_role text;
  next_origin text;
  next_source_alert_id uuid;
  next_source_alert_version integer;
  next_version integer;
  next_archived_at timestamp with time zone;
  ticket_permission text;
  ticket_action text;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF p_operation NOT IN ('ticket_contact.link','ticket_contact.archive')
     OR p_link_id IS NULL
     OR (uuid_extract_version(p_link_id) = 7) IS NOT TRUE
     OR p_expected_link_version NOT BETWEEN 0 AND 2147483646
     OR p_expected_ticket_version NOT BETWEEN 1 AND 2147483647
     OR p_payload IS NULL OR jsonb_typeof(p_payload) <> 'object'
     OR (SELECT count(*) FROM jsonb_object_keys(p_payload)) <> 10
     OR NOT p_payload ?& ARRAY[
       'ticketKind','ticketId','contactId','role','origin',
       'sourceAlertId','sourceAlertVersion','version','createdAt','archivedAt'
     ]
     OR p_key_digest IS NULL OR octet_length(p_key_digest) <> 32
     OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32
     OR p_request_id IS NULL OR p_correlation_id IS NULL
     OR p_actor_membership_id IS DISTINCT FROM actor_membership
     OR p_ip_address IS NULL OR p_authentication_method IS NULL
     OR p_reason IS NULL OR char_length(p_reason) > 2000
     OR p_operation = 'ticket_contact.archive' AND btrim(p_reason) = ''
     OR p_operation = 'ticket_contact.link' AND p_reason <> '' THEN
    RAISE EXCEPTION 'ticket-contact command envelope is invalid'
      USING ERRCODE = '22023';
  END IF;
  next_kind := p_payload ->> 'ticketKind';
  next_ticket_id := (p_payload ->> 'ticketId')::uuid;
  next_contact_id := (p_payload ->> 'contactId')::uuid;
  next_role := p_payload ->> 'role';
  next_origin := p_payload ->> 'origin';
  next_source_alert_id := (p_payload ->> 'sourceAlertId')::uuid;
  next_source_alert_version := (p_payload ->> 'sourceAlertVersion')::integer;
  next_version := (p_payload ->> 'version')::integer;
  next_archived_at := (p_payload ->> 'archivedAt')::timestamp with time zone;
  IF next_kind NOT IN ('alert','case')
     OR (uuid_extract_version(next_ticket_id) = 7) IS NOT TRUE
     OR (uuid_extract_version(next_contact_id) = 7) IS NOT TRUE
     OR next_role NOT IN ('primary','escalation','watcher')
     OR next_origin <> 'manual'
     OR next_source_alert_id IS NOT NULL
     OR next_source_alert_version IS NOT NULL
     OR next_version NOT BETWEEN 1 AND 2147483647 THEN
    RAISE EXCEPTION 'ticket-contact payload is invalid'
      USING ERRCODE = '22023';
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.tenant_memberships AS membership
    WHERE membership.tenant_id = context_tenant
      AND membership.id = actor_membership
      AND membership.user_id = actor_user
      AND membership.role IN ('customer_manager','customer_user','read_only')
  ) OR NOT app.current_tenant_has_exact_permission(
    'contact.read', 'tenant'
  ) THEN
    RAISE EXCEPTION 'operator contact-read permission is required'
      USING ERRCODE = '42501';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM public.customer_contacts AS contact
    WHERE contact.tenant_id = context_tenant
      AND contact.id = next_contact_id
      AND contact.active AND contact.archived_at IS NULL
  ) THEN
    RAISE EXCEPTION 'contact is unavailable' USING ERRCODE = 'P0002';
  END IF;

  ticket_permission := CASE next_kind
    WHEN 'alert' THEN 'alert.update' ELSE 'case.update' END;
  IF next_kind = 'alert' THEN
    SELECT alert.* INTO ticket_record
    FROM public.alerts AS alert
    WHERE alert.tenant_id = context_tenant AND alert.id = next_ticket_id
    FOR UPDATE;
  ELSE
    SELECT case_row.* INTO ticket_record
    FROM public.cases AS case_row
    WHERE case_row.tenant_id = context_tenant AND case_row.id = next_ticket_id
    FOR UPDATE;
  END IF;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'ticket not found' USING ERRCODE = 'P0002';
  END IF;
  IF ticket_record.version IS DISTINCT FROM p_expected_ticket_version
     OR NOT app.private_current_ticket_scope_allows_v1(
       ticket_permission, ticket_record.assigned_team_id,
       CASE next_kind WHEN 'alert' THEN ticket_record.created_by
                      ELSE ticket_record.created_by_user_id END,
       ticket_record.assignee_user_id, ticket_record.claimed_by_user_id
     ) THEN
    RAISE EXCEPTION 'ticket-contact ticket scope is stale'
      USING ERRCODE = '40001';
  END IF;
  PERFORM app.private_ticket_state_action_effects_v1(
    next_kind::public.ticket_aggregate_kind,
    ticket_record.workflow_id, ticket_record.workflow_version,
    ticket_record.state_key, 'link'
  );

  PERFORM pg_advisory_xact_lock(hashtextextended(
    context_tenant::text || ':' || actor_membership::text || ':'
      || p_operation || ':' || encode(p_key_digest, 'hex'), 0
  ));
  DELETE FROM public.customer_contact_commands AS command
  WHERE command.expires_at <= transaction_timestamp();
  SELECT command.* INTO command_record
  FROM public.customer_contact_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.actor_membership_id = actor_membership
    AND command.operation = p_operation
    AND command.key_digest = p_key_digest
  FOR UPDATE;
  IF FOUND THEN
    IF command_record.request_digest IS DISTINCT FROM p_request_digest THEN
      RAISE EXCEPTION 'ticket-contact idempotency key conflicts'
        USING ERRCODE = '23505',
              CONSTRAINT = 'customer_contact_commands_replay_key';
    END IF;
    RETURN QUERY SELECT command_record.result_resource_id,
                        command_record.result_version, true;
    RETURN;
  END IF;

  IF p_operation = 'ticket_contact.link' THEN
    IF p_expected_link_version <> 0 OR next_version <> 1
       OR next_archived_at IS NOT NULL THEN
      RAISE EXCEPTION 'ticket-contact create state is invalid'
        USING ERRCODE = '22023';
    END IF;
    INSERT INTO public.ticket_customer_contacts (
      id, tenant_id, alert_id, case_id, contact_id, role, origin,
      version, created_by_membership_id, created_by_user_id, created_at
    ) VALUES (
      p_link_id, context_tenant,
      CASE WHEN next_kind = 'alert' THEN next_ticket_id END,
      CASE WHEN next_kind = 'case' THEN next_ticket_id END,
      next_contact_id, next_role, 'manual', 1,
      actor_membership, actor_user, transaction_timestamp()
    );
    ticket_action := 'linked';
  ELSE
    SELECT link.* INTO locked_link
    FROM public.ticket_customer_contacts AS link
    WHERE link.tenant_id = context_tenant AND link.id = p_link_id
      AND (next_kind = 'alert' AND link.alert_id = next_ticket_id
        OR next_kind = 'case' AND link.case_id = next_ticket_id)
      AND link.contact_id = next_contact_id
    FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'ticket-contact link not found' USING ERRCODE = 'P0002';
    END IF;
    IF locked_link.archived_at IS NOT NULL
       OR locked_link.version IS DISTINCT FROM p_expected_link_version
       OR next_version IS DISTINCT FROM locked_link.version + 1
       OR next_archived_at IS NULL
       OR next_archived_at < locked_link.created_at
       OR next_archived_at > transaction_timestamp() + interval '1 minute'
       OR next_role IS DISTINCT FROM locked_link.role
       OR next_origin IS DISTINCT FROM locked_link.origin THEN
      RAISE EXCEPTION 'ticket-contact link precondition failed'
        USING ERRCODE = '40001';
    END IF;
    UPDATE public.ticket_customer_contacts
    SET version = next_version, archived_at = next_archived_at
    WHERE tenant_id = context_tenant AND id = p_link_id;
    ticket_action := 'unlinked';
  END IF;

  PERFORM app.private_append_ticket_side_effects_v1(
    next_kind::public.ticket_aggregate_kind, next_ticket_id,
    ticket_action, ticket_record.version,
    ARRAY['activity','audit']::text[],
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method,
    NULL,
    jsonb_build_object(
      'ticket_version', ticket_record.version,
      'contact_link_id', p_link_id,
      'contact_id', next_contact_id,
      'link_version', next_version
    ),
    jsonb_build_object(
      'contact_link_id', p_link_id,
      'contact_id', next_contact_id,
      'role', next_role,
      'reason_present', btrim(p_reason) <> '',
      'pii_redacted', true
    )
  );
  INSERT INTO public.customer_contact_commands (
    tenant_id, actor_membership_id, actor_user_id, operation,
    key_digest, request_digest, result_resource_id, result_version
  ) VALUES (
    context_tenant, actor_membership, actor_user, p_operation,
    p_key_digest, p_request_digest, p_link_id, next_version
  );
  RETURN QUERY SELECT p_link_id, next_version, false;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.commit_ticket_customer_contact_v1(
  text, uuid, bigint, bigint, jsonb, bytea, bytea, text, uuid, uuid,
  uuid, inet, text, text
) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.commit_ticket_customer_contact_v1(
  text, uuid, bigint, bigint, jsonb, bytea, bytea, text, uuid, uuid,
  uuid, inet, text, text
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.commit_ticket_customer_contact_v1(
  text, uuid, bigint, bigint, jsonb, bytea, bytea, text, uuid, uuid,
  uuid, inet, text, text
) TO periapsis_api;--> statement-breakpoint

CREATE FUNCTION app.create_customer_portal_ticket_comment_v1(
  p_aggregate_kind public.ticket_aggregate_kind,
  p_ticket_id uuid,
  p_contact_id uuid,
  p_body_markdown text,
  p_body_html text,
  p_key_digest bytea,
  p_request_digest bytea,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE(comment_id uuid, replayed boolean)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid;
  actor_user uuid := app.context_user_id();
  ticket_record record;
  replay_record public.ticket_comment_commands%ROWTYPE;
  created_comment_id uuid := uuidv7();
  customer_state_visible boolean := false;
  permission_key text;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  permission_key := CASE p_aggregate_kind
    WHEN 'alert' THEN 'portal.alert.read'
    ELSE 'portal.case.read' END;
  IF p_aggregate_kind IS NULL
     OR p_ticket_id IS NULL
     OR (uuid_extract_version(p_ticket_id) = 7) IS NOT TRUE
     OR p_contact_id IS NULL
     OR (uuid_extract_version(p_contact_id) = 7) IS NOT TRUE
     OR p_body_markdown IS NULL OR btrim(p_body_markdown) = ''
     OR char_length(p_body_markdown) > 50000
     OR p_body_html IS NULL OR char_length(p_body_html) > 100000
     OR lower(p_body_html) LIKE '%<script%'
     OR lower(p_body_html) LIKE '%javascript:%'
     OR lower(p_body_html) ~ '<[^>]+[[:space:]]on[a-z]+[[:space:]]*='
     OR p_key_digest IS NULL OR octet_length(p_key_digest) <> 32
     OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32
     OR p_request_id IS NULL OR p_correlation_id IS NULL
     OR p_ip_address IS NULL OR p_authentication_method IS NULL THEN
    RAISE EXCEPTION 'portal comment envelope is invalid'
      USING ERRCODE = '22023';
  END IF;
  IF NOT app.current_tenant_has_exact_permission(
       'portal.comment.public', 'own'
     ) OR NOT app.current_tenant_has_exact_permission(
       permission_key, 'own'
     ) OR NOT EXISTS (
       SELECT 1
       FROM public.tenant_memberships AS membership
       JOIN public.users AS identity ON identity.id = membership.user_id
       JOIN public.customer_contacts AS contact
         ON contact.tenant_id = membership.tenant_id
        AND contact.linked_membership_id = membership.id
        AND contact.linked_user_id = membership.user_id
       JOIN public.ticket_customer_contacts AS link
         ON link.tenant_id = contact.tenant_id
        AND link.contact_id = contact.id
        AND link.archived_at IS NULL
        AND (p_aggregate_kind = 'alert' AND link.alert_id = p_ticket_id
          OR p_aggregate_kind = 'case' AND link.case_id = p_ticket_id)
       WHERE membership.tenant_id = context_tenant
         AND membership.id = actor_membership
         AND membership.user_id = actor_user
         AND membership.status = 'active' AND identity.active
         AND membership.role IN ('customer_manager','customer_user')
         AND contact.id = p_contact_id
         AND contact.active AND contact.archived_at IS NULL
     ) THEN
    RAISE EXCEPTION 'exact portal comment relation is required'
      USING ERRCODE = '42501';
  END IF;

  IF p_aggregate_kind = 'alert' THEN
    SELECT alert.* INTO ticket_record
    FROM public.alerts AS alert
    WHERE alert.tenant_id = context_tenant AND alert.id = p_ticket_id
    FOR UPDATE;
  ELSE
    SELECT case_row.* INTO ticket_record
    FROM public.cases AS case_row
    WHERE case_row.tenant_id = context_tenant AND case_row.id = p_ticket_id
    FOR UPDATE;
  END IF;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'portal ticket not found' USING ERRCODE = 'P0002';
  END IF;
  SELECT ticket_record.customer_visible
    AND coalesce((state.value ->> 'visibility') = 'customer', false)
  INTO customer_state_visible
  FROM public.ticket_workflow_versions AS workflow_version
  CROSS JOIN LATERAL jsonb_array_elements(workflow_version.states) AS state(value)
  WHERE workflow_version.tenant_id = context_tenant
    AND workflow_version.workflow_id = ticket_record.workflow_id
    AND workflow_version.aggregate_kind = p_aggregate_kind
    AND workflow_version.version = ticket_record.workflow_version
    AND state.value ->> 'key' = ticket_record.state_key;
  IF customer_state_visible IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'portal ticket is not customer-projectable'
      USING ERRCODE = '42501';
  END IF;

  PERFORM pg_advisory_xact_lock(hashtextextended(
    context_tenant::text || ':' || actor_membership::text || ':'
      || p_aggregate_kind::text || '.comment.create:'
      || encode(p_key_digest, 'hex'), 0
  ));
  SELECT command.* INTO replay_record
  FROM public.ticket_comment_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.actor_membership_id = actor_membership
    AND command.operation = p_aggregate_kind::text || '.comment.create'
    AND command.key_digest = p_key_digest
  FOR UPDATE;
  IF FOUND THEN
    IF replay_record.request_digest IS DISTINCT FROM p_request_digest THEN
      RAISE EXCEPTION 'portal comment idempotency key conflicts'
        USING ERRCODE = '23505',
              CONSTRAINT = 'ticket_comment_commands_replay_key';
    END IF;
    RETURN QUERY SELECT replay_record.result_comment_id, true;
    RETURN;
  END IF;

  INSERT INTO public.ticket_comments (
    id, tenant_id, alert_id, case_id, visibility, body_markdown,
    body_html, author_membership_id, author_user_id, origin,
    mentioned_user_ids, created_at, updated_at
  ) VALUES (
    created_comment_id, context_tenant,
    CASE WHEN p_aggregate_kind = 'alert' THEN p_ticket_id END,
    CASE WHEN p_aggregate_kind = 'case' THEN p_ticket_id END,
    'public', p_body_markdown, p_body_html,
    actor_membership, actor_user, 'customer_portal', ARRAY[]::uuid[],
    transaction_timestamp(), transaction_timestamp()
  );
  PERFORM app.private_append_ticket_side_effects_v1(
    p_aggregate_kind, p_ticket_id, 'commented', ticket_record.version,
    ARRAY['activity','audit','sla','notification']::text[],
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method, NULL,
    jsonb_build_object(
      'comment_id', created_comment_id,
      'visibility', 'public',
      'ticket_version', ticket_record.version
    ),
    jsonb_build_object(
      'comment_id', created_comment_id,
      'author_contact_id', p_contact_id,
      'visibility', 'public',
      'content_redacted', true,
      'mention_count', 0,
      'origin', 'customer_portal'
    )
  );
  INSERT INTO public.ticket_comment_commands (
    tenant_id, operation, actor_membership_id, actor_user_id,
    key_digest, request_digest, result_comment_id
  ) VALUES (
    context_tenant, p_aggregate_kind::text || '.comment.create',
    actor_membership, actor_user, p_key_digest, p_request_digest,
    created_comment_id
  );
  RETURN QUERY SELECT created_comment_id, false;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.create_customer_portal_ticket_comment_v1(
  public.ticket_aggregate_kind, uuid, uuid, text, text, bytea, bytea,
  uuid, uuid, inet, text, text
) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.create_customer_portal_ticket_comment_v1(
  public.ticket_aggregate_kind, uuid, uuid, text, text, bytea, bytea,
  uuid, uuid, inet, text, text
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.create_customer_portal_ticket_comment_v1(
  public.ticket_aggregate_kind, uuid, uuid, text, text, bytea, bytea,
  uuid, uuid, inet, text, text
) TO periapsis_api;

-- Contacts are a separate aggregate from ticketing.  The successor wraps the
-- sealed escalation ABI, removes contact-only selections before invoking it,
-- then persists the exact selection and copied ticket-contact relations in the
-- same transaction.  The original request digest remains the idempotency
-- identity, so a retry cannot substitute a different selection.
CREATE FUNCTION app.commit_tenant_ticket_escalation_v2(
  p_path_alert_id uuid,
  p_case_id uuid,
  p_create_case boolean,
  p_target jsonb,
  p_sources jsonb,
  p_relation text,
  p_reason text,
  p_key_digest bytea,
  p_request_digest bytea,
  p_effects text[],
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE (
  result_case_id uuid,
  result_case_version integer,
  result_path_alert_version integer,
  result_metadata jsonb,
  replayed boolean
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid;
  actor_user uuid := app.context_user_id();
  source_value jsonb;
  source_items jsonb;
  selected_fields text[];
  selected_contacts uuid[];
  sanitized_fields text[];
  sanitized_sources jsonb := '[]'::jsonb;
  committed_case_id uuid;
  committed_case_version integer;
  committed_path_version integer;
  committed_metadata jsonb;
  was_replayed boolean;
  affected_rows integer;
  matching_contacts integer;
BEGIN
  IF p_sources IS NULL OR jsonb_typeof(p_sources) <> 'array'
     OR jsonb_array_length(p_sources) NOT BETWEEN 1 AND 100 THEN
    RAISE EXCEPTION 'contact escalation sources are invalid'
      USING ERRCODE = '22023';
  END IF;

  FOR source_value IN
    SELECT source.value
    FROM jsonb_array_elements(p_sources) WITH ORDINALITY
         AS source(value, ordinal)
    ORDER BY source.ordinal
  LOOP
    IF jsonb_typeof(source_value) <> 'object'
       OR jsonb_typeof(source_value -> 'copyFields') <> 'array'
       OR jsonb_typeof(source_value -> 'itemIds') <> 'object' THEN
      RAISE EXCEPTION 'contact escalation selection is invalid'
        USING ERRCODE = '22023';
    END IF;
    selected_fields := ARRAY(
      SELECT field.value
      FROM jsonb_array_elements_text(source_value -> 'copyFields')
           AS field(value)
      ORDER BY field.value COLLATE "C"
    );
    source_items := source_value -> 'itemIds';
    IF source_items - 'contactIds' <> '{}'::jsonb
       OR source_items ? 'contactIds'
          AND jsonb_typeof(source_items -> 'contactIds') <> 'array' THEN
      RAISE EXCEPTION 'unsupported escalation item selection'
        USING ERRCODE = '0A000';
    END IF;
    selected_contacts := CASE WHEN source_items ? 'contactIds' THEN ARRAY(
      SELECT item.value::uuid
      FROM jsonb_array_elements_text(source_items -> 'contactIds')
           AS item(value)
      ORDER BY item.value::uuid
    ) ELSE ARRAY[]::uuid[] END;
    IF cardinality(selected_contacts) > 100
       OR EXISTS (
         SELECT 1 FROM unnest(selected_contacts) AS contact(id)
         WHERE (uuid_extract_version(contact.id) = 7) IS NOT TRUE
       )
       OR source_items ? 'contactIds'
          AND source_items -> 'contactIds' IS DISTINCT FROM to_jsonb(selected_contacts)
       OR cardinality(selected_contacts) <> (
         SELECT count(DISTINCT contact.id)
         FROM unnest(selected_contacts) AS contact(id)
       )
       OR source_value -> 'copyFields' IS DISTINCT FROM to_jsonb(selected_fields)
       OR ('contacts' = ANY(selected_fields)) IS DISTINCT FROM
          (cardinality(selected_contacts) > 0)
       OR EXISTS (
         SELECT 1 FROM unnest(selected_fields) AS field(value)
         WHERE field.value NOT IN (
           'title', 'description', 'severity', 'priority', 'category',
           'tags', 'custom_fields', 'contacts', 'public_comments'
         )
       ) THEN
      RAISE EXCEPTION 'contact escalation selection is not canonical'
        USING ERRCODE = '22023';
    END IF;
    sanitized_fields := ARRAY(
      SELECT field.value
      FROM unnest(selected_fields) AS field(value)
      WHERE field.value <> 'contacts'
      ORDER BY field.value COLLATE "C"
    );
    sanitized_sources := sanitized_sources || jsonb_build_array(
      jsonb_set(
        jsonb_set(source_value, '{copyFields}', to_jsonb(sanitized_fields), false),
        '{itemIds}', '{}'::jsonb, false
      )
    );
  END LOOP;

  SELECT committed.result_case_id, committed.result_case_version,
         committed.result_path_alert_version, committed.result_metadata,
         committed.replayed
  INTO committed_case_id, committed_case_version, committed_path_version,
       committed_metadata, was_replayed
  FROM app.commit_tenant_ticket_escalation_v1(
    p_path_alert_id, p_case_id, p_create_case, p_target,
    sanitized_sources, p_relation, p_reason, p_key_digest,
    p_request_digest, p_effects, p_request_id, p_correlation_id,
    p_ip_address, p_user_agent, p_authentication_method
  ) AS committed;
  IF committed_case_id IS NULL OR was_replayed IS NULL THEN
    RAISE EXCEPTION 'contact escalation result is unavailable'
      USING ERRCODE = '55000';
  END IF;

  actor_membership := app.current_tenant_membership_id();
  FOR source_value IN
    SELECT source.value
    FROM jsonb_array_elements(p_sources) WITH ORDINALITY
         AS source(value, ordinal)
    ORDER BY source.ordinal
  LOOP
    selected_fields := ARRAY(
      SELECT field.value
      FROM jsonb_array_elements_text(source_value -> 'copyFields')
           AS field(value)
      ORDER BY field.value COLLATE "C"
    );
    source_items := source_value -> 'itemIds';
    selected_contacts := CASE WHEN source_items ? 'contactIds' THEN ARRAY(
      SELECT item.value::uuid
      FROM jsonb_array_elements_text(source_items -> 'contactIds')
           AS item(value)
      ORDER BY item.value::uuid
    ) ELSE ARRAY[]::uuid[] END;

    IF was_replayed THEN
      IF NOT EXISTS (
        SELECT 1
        FROM public.alert_case_links AS link
        WHERE link.tenant_id = context_tenant
          AND link.id = (source_value ->> 'linkId')::uuid
          AND link.alert_id = (source_value ->> 'alertId')::uuid
          AND link.case_id = committed_case_id
          AND link.copy_fields IS NOT DISTINCT FROM selected_fields
          AND link.item_ids IS NOT DISTINCT FROM source_items
      ) THEN
        RAISE EXCEPTION 'replayed contact escalation selection drifted'
          USING ERRCODE = '55000';
      END IF;
      CONTINUE;
    END IF;

    SELECT count(*) INTO matching_contacts
    FROM public.ticket_customer_contacts AS source_link
    JOIN public.customer_contacts AS contact
      ON contact.tenant_id = source_link.tenant_id
     AND contact.id = source_link.contact_id
    WHERE source_link.tenant_id = context_tenant
      AND source_link.alert_id = (source_value ->> 'alertId')::uuid
      AND source_link.contact_id = ANY(selected_contacts)
      AND source_link.archived_at IS NULL
      AND contact.active AND contact.archived_at IS NULL;
    IF matching_contacts IS DISTINCT FROM cardinality(selected_contacts) THEN
      RAISE EXCEPTION 'source Alert contact selection is not exact and active'
        USING ERRCODE = '22023';
    END IF;

    UPDATE public.alert_case_links AS link
    SET copy_fields = selected_fields,
        item_ids = source_items,
        copied_field_snapshot = link.copied_field_snapshot ||
          jsonb_build_object('contactIds', to_jsonb(selected_contacts))
    WHERE link.tenant_id = context_tenant
      AND link.id = (source_value ->> 'linkId')::uuid
      AND link.alert_id = (source_value ->> 'alertId')::uuid
      AND link.case_id = committed_case_id;
    GET DIAGNOSTICS affected_rows = ROW_COUNT;
    IF affected_rows <> 1 THEN
      RAISE EXCEPTION 'contact escalation link result is unavailable'
        USING ERRCODE = '55000';
    END IF;

    INSERT INTO public.ticket_customer_contacts (
      id, tenant_id, alert_id, case_id, contact_id, role, origin,
      source_alert_id, source_alert_version, version,
      created_by_membership_id, created_by_user_id, created_at
    )
    SELECT uuidv7(), context_tenant, NULL, committed_case_id,
           source_link.contact_id, source_link.role, 'escalation_copy',
           (source_value ->> 'alertId')::uuid,
           (source_value ->> 'expectedVersion')::integer, 1,
           actor_membership, actor_user, transaction_timestamp()
    FROM public.ticket_customer_contacts AS source_link
    WHERE source_link.tenant_id = context_tenant
      AND source_link.alert_id = (source_value ->> 'alertId')::uuid
      AND source_link.contact_id = ANY(selected_contacts)
      AND source_link.archived_at IS NULL
    ORDER BY source_link.contact_id
    ON CONFLICT DO NOTHING;

    PERFORM app.append_tenant_authorization_audit(
      uuidv7(), 'tenant.ticket.contact_copied', 'alert_case_link',
      (source_value ->> 'linkId')::uuid,
      p_request_id, p_correlation_id, p_ip_address,
      nullif(p_user_agent, ''), p_authentication_method,
      NULL,
      jsonb_build_object(
        'source_alert_version', (source_value ->> 'expectedVersion')::integer,
        'contact_count', cardinality(selected_contacts),
        'pii_redacted', true
      ),
      jsonb_build_object('case_id', committed_case_id)
    );
  END LOOP;

  RETURN QUERY SELECT committed_case_id, committed_case_version,
    committed_path_version, committed_metadata, was_replayed;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.commit_tenant_ticket_escalation_v2(
  uuid, uuid, boolean, jsonb, jsonb, text, text, bytea, bytea, text[],
  uuid, uuid, inet, text, text
) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.commit_tenant_ticket_escalation_v2(
  uuid, uuid, boolean, jsonb, jsonb, text, text, bytea, bytea, text[],
  uuid, uuid, inet, text, text
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.commit_tenant_ticket_escalation_v2(
  uuid, uuid, boolean, jsonb, jsonb, text, text, bytea, bytea, text[],
  uuid, uuid, inet, text, text
) TO periapsis_api;

GRANT SELECT ON TABLE
  public.customer_contacts,
  public.customer_contact_notification_windows,
  public.customer_contact_groups,
  public.customer_contact_group_versions,
  public.customer_contact_group_version_members,
  public.ticket_customer_contacts
TO periapsis_notification_dispatch_owner;--> statement-breakpoint
CREATE POLICY customer_contacts_notification_dispatch_tenant
ON public.customer_contacts FOR SELECT
TO periapsis_notification_dispatch_owner
USING (
  tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid
);--> statement-breakpoint
CREATE POLICY customer_contact_windows_notification_dispatch_tenant
ON public.customer_contact_notification_windows FOR SELECT
TO periapsis_notification_dispatch_owner
USING (
  tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid
);--> statement-breakpoint
CREATE POLICY customer_contact_groups_notification_dispatch_tenant
ON public.customer_contact_groups FOR SELECT
TO periapsis_notification_dispatch_owner
USING (
  tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid
);--> statement-breakpoint
CREATE POLICY customer_contact_group_versions_notification_dispatch_tenant
ON public.customer_contact_group_versions FOR SELECT
TO periapsis_notification_dispatch_owner
USING (
  tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid
);--> statement-breakpoint
CREATE POLICY customer_contact_group_members_notification_dispatch_tenant
ON public.customer_contact_group_version_members FOR SELECT
TO periapsis_notification_dispatch_owner
USING (
  tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid
);--> statement-breakpoint
CREATE POLICY ticket_customer_contacts_notification_dispatch_tenant
ON public.ticket_customer_contacts FOR SELECT
TO periapsis_notification_dispatch_owner
USING (
  tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid
);--> statement-breakpoint

CREATE FUNCTION app.load_notification_fanout_inputs_v2(
  p_event_id uuid,
  p_fence_token uuid
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid;
  source_event public.outbox_events%ROWTYPE;
  selected_snapshot public.tenant_notification_fanout_snapshots%ROWTYPE;
  selected_rule_pins jsonb;
  selected_webhook_pins jsonb;
  selected_smtp_scope text;
  selected_smtp_id uuid;
  selected_smtp_version integer;
  snapshot_value jsonb;
  rules_value jsonb;
  templates_value jsonb;
  candidates_value jsonb;
  candidate_count integer;
BEGIN
  context_tenant := app.private_lock_notification_fanout_claim_v1(
    p_event_id, p_fence_token
  );
  SELECT event.* INTO STRICT source_event
  FROM public.outbox_events AS event
  WHERE event.id = p_event_id AND event.tenant_id = context_tenant;
  IF NOT EXISTS (
    SELECT 1 FROM public.tenants AS tenant
    WHERE tenant.id = context_tenant AND tenant.status = 'active'
  ) THEN
    RAISE EXCEPTION 'notification tenant is unavailable'
      USING ERRCODE = '42501';
  END IF;

  SELECT snapshot.* INTO selected_snapshot
  FROM public.tenant_notification_fanout_snapshots AS snapshot
  WHERE snapshot.tenant_id = context_tenant AND snapshot.event_id = p_event_id;
  IF NOT FOUND THEN
    SELECT coalesce(jsonb_agg(jsonb_build_object(
      'ruleId', rule.id, 'version', version.version
    ) ORDER BY rule.id, version.version), '[]'::jsonb)
    INTO selected_rule_pins
    FROM public.tenant_notification_rules AS rule
    JOIN public.tenant_notification_rule_versions AS version
      ON version.tenant_id = rule.tenant_id
     AND version.rule_id = rule.id
     AND version.version = rule.current_version
    WHERE rule.tenant_id = context_tenant
      AND version.channel = 'email'
      AND version.enabled
      AND version.event_type::text = substring(source_event.event_type from 14)
      AND version.object_type::text = source_event.aggregate_type
      AND version.effective_from <= source_event.occurred_at
      AND (version.effective_until IS NULL
        OR version.effective_until > source_event.occurred_at);
    IF jsonb_array_length(selected_rule_pins) > 1000 THEN
      RAISE EXCEPTION 'notification rule snapshot is oversized'
        USING ERRCODE = '54000';
    END IF;

    SELECT coalesce(jsonb_agg(jsonb_build_object(
      'configurationId', configuration.id,
      'version', version.version
    ) ORDER BY configuration.id, version.version), '[]'::jsonb)
    INTO selected_webhook_pins
    FROM public.tenant_notification_webhook_configurations AS configuration
    JOIN public.tenant_notification_webhook_configuration_versions AS version
      ON version.tenant_id = configuration.tenant_id
     AND version.configuration_id = configuration.id
     AND version.version = configuration.current_version
    WHERE configuration.tenant_id = context_tenant
      AND configuration.revoked_at IS NULL
      AND version.enabled
      AND substring(source_event.event_type from 14)::public.notification_event_type
        = ANY(version.event_types)
      AND (version.audience = 'operator'
        OR source_event.maximum_audience = 'customer');
    IF jsonb_array_length(selected_webhook_pins) > 1000 THEN
      RAISE EXCEPTION 'notification webhook snapshot is oversized'
        USING ERRCODE = '54000';
    END IF;

    IF jsonb_array_length(selected_rule_pins) > 0 THEN
      SELECT 'tenant', configuration.id, configuration.current_version
      INTO selected_smtp_scope, selected_smtp_id, selected_smtp_version
      FROM public.tenant_notification_smtp_configurations AS configuration
      JOIN public.tenant_notification_smtp_configuration_versions AS version
        ON version.tenant_id = configuration.tenant_id
       AND version.configuration_id = configuration.id
       AND version.version = configuration.current_version
      WHERE configuration.tenant_id = context_tenant
        AND configuration.revoked_at IS NULL AND version.enabled
      ORDER BY configuration.id
      LIMIT 1;
      IF NOT FOUND THEN
        SELECT 'platform', configuration.id, configuration.current_version
        INTO selected_smtp_scope, selected_smtp_id, selected_smtp_version
        FROM public.platform_notification_smtp_configurations AS configuration
        JOIN public.platform_notification_smtp_configuration_versions AS version
          ON version.configuration_id = configuration.id
         AND version.version = configuration.current_version
        WHERE configuration.revoked_at IS NULL AND version.enabled
        ORDER BY configuration.id
        LIMIT 1;
      END IF;
    END IF;

    snapshot_value := jsonb_build_object(
      'rules', selected_rule_pins,
      'webhooks', selected_webhook_pins,
      'smtpScope', selected_smtp_scope,
      'smtpId', selected_smtp_id,
      'smtpVersion', selected_smtp_version
    );
    INSERT INTO public.tenant_notification_fanout_snapshots (
      tenant_id, event_id, rule_pins, webhook_configuration_pins,
      smtp_configuration_scope, smtp_configuration_id,
      smtp_configuration_version, snapshot_digest
    ) VALUES (
      context_tenant, p_event_id, selected_rule_pins, selected_webhook_pins,
      selected_smtp_scope, selected_smtp_id, selected_smtp_version,
      sha256(convert_to(snapshot_value::text, 'UTF8'))
    );
    SELECT snapshot.* INTO STRICT selected_snapshot
    FROM public.tenant_notification_fanout_snapshots AS snapshot
    WHERE snapshot.tenant_id = context_tenant
      AND snapshot.event_id = p_event_id;
  END IF;

  SELECT coalesce(jsonb_agg(jsonb_strip_nulls(jsonb_build_object(
    'id', version.rule_id,
    'tenantId', version.tenant_id,
    'name', version.name,
    'description', version.description,
    'eventType', version.event_type,
    'objectType', version.object_type,
    'condition', version.condition,
    'recipients', version.recipients,
    'templateId', version.template_id,
    'templateVersion', version.template_version,
    'channel', version.channel,
    'priority', version.priority,
    'delayMs', version.delay_ms,
    'quietHours', version.quiet_hours,
    'deduplicationWindowMs', version.deduplication_window_ms,
    'grouping', version.grouping,
    'retry', version.retry,
    'enabled', version.enabled,
    'version', version.version,
    'effectiveFrom', version.effective_from,
    'effectiveUntil', version.effective_until
  )) ORDER BY version.rule_id, version.version), '[]'::jsonb)
  INTO rules_value
  FROM jsonb_array_elements(selected_snapshot.rule_pins) AS pin(value)
  JOIN public.tenant_notification_rule_versions AS version
    ON version.tenant_id = context_tenant
   AND version.rule_id = (pin.value ->> 'ruleId')::uuid
   AND version.version = (pin.value ->> 'version')::integer;

  SELECT coalesce(jsonb_agg(jsonb_strip_nulls(jsonb_build_object(
    'id', version.template_id,
    'tenantId', version.tenant_id,
    'key', version.key,
    'name', version.name,
    'language', version.language,
    'version', version.version,
    'subject', version.subject,
    'html', version.html,
    'plainText', version.plain_text,
    'css', version.css
  )) ORDER BY version.template_id, version.version), '[]'::jsonb)
  INTO templates_value
  FROM (
    SELECT DISTINCT rule_version.template_id, rule_version.template_version
    FROM jsonb_array_elements(selected_snapshot.rule_pins) AS pin(value)
    JOIN public.tenant_notification_rule_versions AS rule_version
      ON rule_version.tenant_id = context_tenant
     AND rule_version.rule_id = (pin.value ->> 'ruleId')::uuid
     AND rule_version.version = (pin.value ->> 'version')::integer
  ) AS pinned_template
  JOIN public.tenant_notification_template_versions AS version
    ON version.tenant_id = context_tenant
   AND version.template_id = pinned_template.template_id
   AND version.version = pinned_template.template_version;

  IF EXISTS (
    SELECT 1
    FROM jsonb_array_elements(selected_snapshot.rule_pins) AS pin(value)
    JOIN public.tenant_notification_rule_versions AS version
      ON version.tenant_id = context_tenant
     AND version.rule_id = (pin.value ->> 'ruleId')::uuid
     AND version.version = (pin.value ->> 'version')::integer
    CROSS JOIN LATERAL jsonb_array_elements(version.recipients)
         AS recipient(value)
    WHERE recipient.value ->> 'kind' NOT IN (
      'assignee', 'previous_assignee', 'operator_team', 'watcher',
      'actor', 'tenant_admin', 'platform_group', 'customer_contacts',
      'contact_group', 'contact_tag', 'explicit_email',
      'custom_email_field'
    )
  ) THEN
    RAISE EXCEPTION 'notification recipient source is unavailable'
      USING ERRCODE = '0A000';
  END IF;

  WITH operator_candidates AS (
    SELECT profile.email AS sort_email,
           identity.id AS sort_principal,
           'operator'::text AS sort_source,
           jsonb_strip_nulls(jsonb_build_object(
      'tenantId', profile.tenant_id,
      'email', profile.email,
      'audience', CASE WHEN membership.role IN (
        'customer_manager', 'customer_user'
      ) THEN 'customer' ELSE 'operator' END,
      'kinds', (CASE WHEN identity.id = source_event.actor_id
        THEN jsonb_build_array('actor') ELSE '[]'::jsonb END)
        || (CASE WHEN identity.id::text =
              source_event.payload #>> '{operatorContext,routing,assigneeUserId}'
          THEN jsonb_build_array('assignee') ELSE '[]'::jsonb END)
        || (CASE WHEN identity.id::text =
              source_event.payload #>> '{operatorContext,routing,previousAssigneeUserId}'
          THEN jsonb_build_array('previous_assignee') ELSE '[]'::jsonb END)
        || (CASE WHEN EXISTS (
          SELECT 1
          FROM public.operator_team_roster_entries AS roster
          WHERE roster.tenant_id = context_tenant
            AND roster.membership_id = membership.id
            AND roster.assignment_epoch_id::text =
              source_event.payload #>> '{operatorContext,routing,operatorTeamEpochId}'
            AND roster.granted_at <= source_event.occurred_at
            AND (roster.expires_at IS NULL
              OR roster.expires_at > source_event.occurred_at)
            AND (roster.revoked_at IS NULL
              OR roster.revoked_at > source_event.occurred_at)
        ) THEN jsonb_build_array('operator_team') ELSE '[]'::jsonb END)
        || (CASE WHEN membership.role = 'tenant_admin'
          THEN jsonb_build_array('tenant_admin') ELSE '[]'::jsonb END),
      'values', CASE WHEN EXISTS (
        SELECT 1
        FROM public.operator_team_roster_entries AS roster
        WHERE roster.tenant_id = context_tenant
          AND roster.membership_id = membership.id
          AND roster.assignment_epoch_id::text =
            source_event.payload #>> '{operatorContext,routing,operatorTeamEpochId}'
          AND source_event.payload #>> '{operatorContext,routing,operatorTeamId}'
            IS NOT NULL
          AND roster.granted_at <= source_event.occurred_at
          AND (roster.expires_at IS NULL
            OR roster.expires_at > source_event.occurred_at)
          AND (roster.revoked_at IS NULL
            OR roster.revoked_at > source_event.occurred_at)
      ) THEN jsonb_build_object(
        'operator_team', jsonb_build_array(
          source_event.payload #>> '{operatorContext,routing,operatorTeamId}'
        )
      ) ELSE '{}'::jsonb END,
      'principalId', identity.id,
      'enabled', true,
      'emailAllowed', true
    )) AS value
    FROM public.tenant_user_profiles AS profile
    JOIN public.tenant_memberships AS membership
      ON membership.tenant_id = profile.tenant_id
     AND membership.id = profile.membership_id
    JOIN public.users AS identity ON identity.id = profile.user_id
    WHERE profile.tenant_id = context_tenant
      AND profile.email IS NOT NULL
      AND membership.status = 'active' AND identity.active
  ), customer_candidates AS (
    SELECT contact.email AS sort_email,
           contact.id AS sort_principal,
           'customer'::text AS sort_source,
           jsonb_strip_nulls(jsonb_build_object(
      'tenantId', contact.tenant_id,
      'email', contact.email,
      'audience', 'customer',
      'kinds', jsonb_build_array('customer_contacts')
        || CASE WHEN cardinality(matched_group.keys) > 0
          THEN jsonb_build_array('contact_group') ELSE '[]'::jsonb END
        || CASE WHEN cardinality(contact.tags) > 0
          THEN jsonb_build_array('contact_tag') ELSE '[]'::jsonb END,
      'values', jsonb_strip_nulls(jsonb_build_object(
        'contact_group', CASE WHEN cardinality(matched_group.keys) > 0
          THEN to_jsonb(matched_group.keys) END,
        'contact_tag', CASE WHEN cardinality(contact.tags) > 0
          THEN to_jsonb(contact.tags) END
      )),
      'principalId', contact.linked_user_id,
      'enabled', contact.active,
      'emailAllowed', contact.email_allowed
    )) AS value
    FROM public.customer_contacts AS contact
    LEFT JOIN LATERAL (
      SELECT array_agg(group_row.key ORDER BY group_row.key COLLATE "C") AS keys
      FROM public.customer_contact_groups AS group_row
      JOIN public.customer_contact_group_versions AS group_version
        ON group_version.tenant_id = group_row.tenant_id
       AND group_version.group_id = group_row.id
       AND group_version.version = group_row.current_version
      WHERE group_row.tenant_id = contact.tenant_id
        AND group_row.archived_at IS NULL
        AND (
          group_version.mode = 'manual' AND EXISTS (
            SELECT 1
            FROM public.customer_contact_group_version_members AS member
            WHERE member.tenant_id = group_version.tenant_id
              AND member.group_id = group_version.group_id
              AND member.group_version = group_version.version
              AND member.contact_id = contact.id
          )
          OR group_version.mode = 'dynamic'
             AND app.private_contact_rule_matches_v1(
               group_version.rule, contact
             )
        )
    ) AS matched_group ON true
    WHERE contact.tenant_id = context_tenant
      AND contact.active AND contact.archived_at IS NULL
      AND contact.email_allowed
      AND contact.notification_categories @> ARRAY[
        substring(source_event.event_type from 14)
      ]::text[]
      AND (
        NOT EXISTS (
          SELECT 1
          FROM public.customer_contact_notification_windows AS any_window
          WHERE any_window.tenant_id = contact.tenant_id
            AND any_window.contact_id = contact.id
        )
        OR EXISTS (
          SELECT 1
          FROM public.customer_contact_notification_windows AS allowed_window
          CROSS JOIN LATERAL (
            SELECT source_event.occurred_at AT TIME ZONE contact.timezone
              AS local_time
          ) AS local_event
          WHERE allowed_window.tenant_id = contact.tenant_id
            AND allowed_window.contact_id = contact.id
            AND allowed_window.iso_weekday = extract(
              isodow FROM local_event.local_time
            )::integer
            AND extract(hour FROM local_event.local_time)::integer * 60
              + extract(minute FROM local_event.local_time)::integer
                >= allowed_window.start_minute
            AND extract(hour FROM local_event.local_time)::integer * 60
              + extract(minute FROM local_event.local_time)::integer
                < allowed_window.end_minute
        )
      )
      AND (
        source_event.aggregate_type = 'alert' AND EXISTS (
          SELECT 1 FROM public.ticket_customer_contacts AS link
          WHERE link.tenant_id = context_tenant
            AND link.alert_id = source_event.aggregate_id
            AND link.contact_id = contact.id
            AND link.archived_at IS NULL
        )
        OR source_event.aggregate_type = 'case' AND EXISTS (
          SELECT 1 FROM public.ticket_customer_contacts AS link
          WHERE link.tenant_id = context_tenant
            AND link.case_id = source_event.aggregate_id
            AND link.contact_id = contact.id
            AND link.archived_at IS NULL
        )
        OR source_event.aggregate_type = 'contact'
           AND contact.id = source_event.aggregate_id
      )
  ), all_candidates AS (
    SELECT * FROM operator_candidates
    UNION ALL
    SELECT * FROM customer_candidates
  )
  SELECT count(*)::integer,
         coalesce(jsonb_agg(candidate.value ORDER BY
           candidate.sort_email COLLATE "C", candidate.sort_source COLLATE "C",
           candidate.sort_principal
         ), '[]'::jsonb)
  INTO candidate_count, candidates_value
  FROM all_candidates AS candidate;
  IF candidate_count > 10000 THEN
    RAISE EXCEPTION 'notification recipient inventory is oversized'
      USING ERRCODE = '54000';
  END IF;

  RETURN jsonb_build_object(
    'rules', rules_value,
    'candidates', candidates_value,
    'templates', templates_value,
    'smtpConfiguration', CASE
      WHEN selected_snapshot.smtp_configuration_id IS NULL THEN NULL
      ELSE jsonb_build_object(
        'scope', selected_snapshot.smtp_configuration_scope,
        'id', selected_snapshot.smtp_configuration_id,
        'version', selected_snapshot.smtp_configuration_version
      ) END
  );
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.load_notification_fanout_inputs_v2(uuid, uuid)
  OWNER TO periapsis_notification_dispatch_owner;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.load_notification_fanout_inputs_v2(uuid, uuid)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.load_notification_fanout_inputs_v2(uuid, uuid)
  TO periapsis_notifier;--> statement-breakpoint
REVOKE EXECUTE ON FUNCTION app.load_notification_fanout_inputs_v1(uuid, uuid)
  FROM periapsis_notifier;

CREATE FUNCTION app.schema_compatibility_v18()
RETURNS TABLE(
  applied_count bigint,
  latest_created_at bigint,
  latest_hash text,
  migration_fingerprint text
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
  journal_count bigint;
  journal_latest_created_at bigint;
  migration_0101_rows bigint;
BEGIN
  EXECUTE $query$
    SELECT count(*)::bigint, max(migration.created_at)::bigint,
           count(*) FILTER (
             WHERE migration.created_at = 1787689670779
           )::bigint
    FROM drizzle.__drizzle_migrations AS migration
  $query$ INTO journal_count, journal_latest_created_at, migration_0101_rows;
  IF journal_count = 102
     AND journal_latest_created_at = 1787689670779
     AND migration_0101_rows = 1 THEN
    RETURN QUERY EXECUTE $query$
      SELECT count(*)::bigint, max(migration.created_at)::bigint,
             (SELECT lower(latest.hash::text)
              FROM drizzle.__drizzle_migrations AS latest
              ORDER BY latest.created_at DESC, latest.id DESC LIMIT 1),
             string_agg(
               migration.created_at::text || '@' || lower(migration.hash::text),
               ':' ORDER BY migration.created_at, migration.id
             )
      FROM drizzle.__drizzle_migrations AS migration
    $query$;
    RETURN;
  END IF;
  RETURN QUERY SELECT 0::bigint, 0::bigint,
                      'UNSUPPORTED'::text, 'UNSUPPORTED'::text;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.schema_compatibility_v18()
  OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.schema_compatibility_v18()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v18()
  TO periapsis_api, periapsis_worker;--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.schema_compatibility_v17()
RETURNS TABLE(
  applied_count bigint,
  latest_created_at bigint,
  latest_hash text,
  migration_fingerprint text
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
SET app.schema_compatibility_fingerprint = 'UNSEALED'
AS $function$
DECLARE
  full_count bigint;
  full_latest_created_at bigint;
  full_fingerprint text;
BEGIN
  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.migration_fingerprint
  INTO full_count, full_latest_created_at, full_fingerprint
  FROM app.schema_compatibility_v18() AS compatibility;
  IF full_count = 102
     AND full_latest_created_at = 1787689670779
     AND full_fingerprint = current_setting(
       'app.schema_compatibility_fingerprint', true
     ) THEN
    RETURN QUERY EXECUTE $query$
      WITH ordered_migrations AS (
        SELECT migration.id, migration.created_at,
               lower(migration.hash::text) AS migration_hash,
               row_number() OVER (
                 ORDER BY migration.created_at, migration.id
               ) AS migration_ordinal
        FROM drizzle.__drizzle_migrations AS migration
      )
      SELECT count(*)::bigint, max(migration.created_at)::bigint,
             (SELECT prefix.migration_hash
              FROM ordered_migrations AS prefix
              WHERE prefix.migration_ordinal = 101),
             string_agg(
               migration.created_at::text || '@' || migration.migration_hash,
               ':' ORDER BY migration.created_at, migration.id
             )
      FROM ordered_migrations AS migration
      WHERE migration.migration_ordinal <= 101
    $query$;
    RETURN;
  END IF;
  RETURN QUERY SELECT 0::bigint, 0::bigint,
                      'UNSUPPORTED'::text, 'UNSUPPORTED'::text;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.schema_compatibility_v17()
  OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.schema_compatibility_v17()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v17()
  TO periapsis_api, periapsis_worker;--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.schema_compatibility_v16()
RETURNS TABLE(
  applied_count bigint,
  latest_created_at bigint,
  latest_hash text,
  migration_fingerprint text
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
  RETURN QUERY SELECT 0::bigint, 0::bigint,
                      'UNSUPPORTED'::text, 'UNSUPPORTED'::text;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.schema_compatibility_v16()
  OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.schema_compatibility_v16()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v16()
  TO periapsis_api, periapsis_worker;--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.seal_schema_compatibility_manifest(
  p_expected_count bigint,
  p_expected_latest_created_at bigint,
  p_expected_latest_hash text,
  p_expected_migration_fingerprint text
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
  fingerprint_entries text[];
  fingerprint_created_at bigint[];
  actual_count bigint;
  actual_latest_created_at bigint;
  actual_latest_hash text;
  actual_fingerprint text;
  predecessor_count bigint;
  predecessor_latest_created_at bigint;
  predecessor_latest_hash text;
  predecessor_fingerprint text;
  expected_predecessor_hash text;
  expected_predecessor_fingerprint text;
  retired_count bigint;
BEGIN
  fingerprint_entries := string_to_array(
    p_expected_migration_fingerprint, ':'
  );
  IF p_expected_count IS DISTINCT FROM 102
     OR p_expected_latest_created_at IS DISTINCT FROM 1787689670779
     OR p_expected_latest_hash IS NULL
     OR p_expected_latest_hash !~ '^[0-9a-f]{64}$'
     OR p_expected_migration_fingerprint IS NULL
     OR p_expected_migration_fingerprint !~
          '^[1-9][0-9]*@[0-9a-f]{64}(:[1-9][0-9]*@[0-9a-f]{64})*$'
     OR cardinality(fingerprint_entries) IS DISTINCT FROM 102
     OR fingerprint_entries[102] IS DISTINCT FROM (
       p_expected_latest_created_at::text || '@' || p_expected_latest_hash
     ) THEN
    RAISE EXCEPTION 'invalid schema compatibility v18 manifest'
      USING ERRCODE = '22023';
  END IF;

  SELECT array_agg(
    split_part(entry.value, '@', 1)::bigint ORDER BY entry.ordinality
  ) INTO fingerprint_created_at
  FROM unnest(fingerprint_entries) WITH ORDINALITY
       AS entry(value, ordinality);
  IF fingerprint_created_at IS DISTINCT FROM ARRAY[
    1787472409685, 1787472415216, 1787473527702, 1787473536723,
    1787474082034, 1787474089267, 1787475027656, 1787475184077,
    1787488565252, 1787488569966, 1787492910536, 1787493031146,
    1787494284382, 1787495115125, 1787495293635, 1787495819997,
    1787495999394, 1787496124539, 1787496880587, 1787496982733,
    1787496987011, 1787501702276, 1787506296280, 1787507888755,
    1787508523197, 1787516694668, 1787571776845, 1787581350373,
    1787581530382, 1787582150087, 1787591930962, 1787591938733,
    1787592230466, 1787612620574, 1787613580320, 1787613592459,
    1787613744526, 1787613746038, 1787613747552, 1787613749000,
    1787635396524, 1787635417084, 1787635433516, 1787635452090,
    1787635459707, 1787635471570, 1787635525474, 1787635788324,
    1787635828723, 1787637794128, 1787637795761, 1787643146844,
    1787643153628, 1787643609827, 1787648180127, 1787648190820,
    1787648201836, 1787648215689, 1787648225321, 1787649465766,
    1787649478666, 1787649523649, 1787649541586, 1787650610199,
    1787650730983, 1787653130160, 1787653143051, 1787653149806,
    1787653151267, 1787653305313, 1787655186569, 1787655192148,
    1787655197869, 1787655813403, 1787655819028, 1787655824109,
    1787657661213, 1787657666680, 1787658281433, 1787658434202,
    1787659622481, 1787659623982, 1787664581262, 1787664767505,
    1787664955067, 1787665119323, 1787665128173, 1787672101246,
    1787672114811, 1787672134042, 1787673489517, 1787677373554,
    1787677383849, 1787677403239, 1787677416302, 1787677427915,
    1787679172524, 1787680410777, 1787680424626, 1787682162037,
    1787686749137, 1787689670779
  ]::bigint[] THEN
    RAISE EXCEPTION 'invalid schema compatibility v18 timestamp sequence'
      USING ERRCODE = '22023';
  END IF;

  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
  INTO actual_count, actual_latest_created_at, actual_latest_hash,
       actual_fingerprint
  FROM app.schema_compatibility_v18() AS compatibility;
  IF actual_count IS DISTINCT FROM p_expected_count
     OR actual_latest_created_at IS DISTINCT FROM p_expected_latest_created_at
     OR actual_latest_hash IS DISTINCT FROM p_expected_latest_hash
     OR actual_fingerprint IS DISTINCT FROM p_expected_migration_fingerprint THEN
    RAISE EXCEPTION 'schema compatibility v18 manifest does not match the applied journal'
      USING ERRCODE = '55000';
  END IF;

  PERFORM set_config(
    'app.schema_compatibility_fingerprint',
    p_expected_migration_fingerprint, true
  );
  EXECUTE $statement$
    ALTER FUNCTION app.schema_compatibility_v17()
      SET app.schema_compatibility_fingerprint FROM CURRENT
  $statement$;
  expected_predecessor_hash := split_part(fingerprint_entries[101], '@', 2);
  expected_predecessor_fingerprint := array_to_string(
    fingerprint_entries[1:101], ':'
  );
  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
  INTO predecessor_count, predecessor_latest_created_at,
       predecessor_latest_hash, predecessor_fingerprint
  FROM app.schema_compatibility_v17() AS compatibility;
  IF predecessor_count IS DISTINCT FROM 101
     OR predecessor_latest_created_at IS DISTINCT FROM 1787686749137
     OR predecessor_latest_hash IS DISTINCT FROM expected_predecessor_hash
     OR predecessor_fingerprint IS DISTINCT FROM expected_predecessor_fingerprint THEN
    RAISE EXCEPTION 'sealed schema compatibility v17 prefix is not exact'
      USING ERRCODE = '55000';
  END IF;
  SELECT compatibility.applied_count INTO retired_count
  FROM app.schema_compatibility_v16() AS compatibility;
  IF retired_count IS DISTINCT FROM 0 THEN
    RAISE EXCEPTION 'schema compatibility v16 must be retired'
      USING ERRCODE = '55000';
  END IF;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.seal_schema_compatibility_manifest(
  bigint, bigint, text, text
) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.seal_schema_compatibility_manifest(
  bigint, bigint, text, text
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;

CREATE FUNCTION app.contacts_portal_schema_readiness_v1()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  relation_name text;
  expected_function record;
  function_oid regprocedure;
  function_owner text;
  function_security_definer boolean;
  function_configuration text[];
  current_count bigint;
  predecessor_count bigint;
  retired_count bigint;
BEGIN
  FOREACH relation_name IN ARRAY ARRAY[
    'customer_contacts',
    'customer_contact_notification_windows',
    'customer_contact_groups',
    'customer_contact_group_versions',
    'customer_contact_group_version_members',
    'ticket_customer_contacts',
    'ticket_comment_author_snapshots',
    'ticket_activity_author_snapshots',
    'customer_contact_commands'
  ] LOOP
    IF NOT EXISTS (
      SELECT 1 FROM pg_class AS class
      JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
      JOIN pg_attribute AS tenant_column
        ON tenant_column.attrelid = class.oid
       AND tenant_column.attname = 'tenant_id'
       AND tenant_column.attnotnull AND NOT tenant_column.attisdropped
      WHERE namespace.nspname = 'public'
        AND class.relname = relation_name AND class.relkind = 'r'
        AND pg_get_userbyid(class.relowner) = 'periapsis_migrator'
        AND class.relrowsecurity AND class.relforcerowsecurity
    ) OR has_table_privilege(
      'periapsis_notifier', format('public.%I', relation_name),
      'SELECT,INSERT,UPDATE,DELETE'
    ) OR has_table_privilege(
      'periapsis_worker', format('public.%I', relation_name),
      'SELECT,INSERT,UPDATE,DELETE'
    ) THEN
      RETURN false;
    END IF;
  END LOOP;

  IF (
    SELECT count(*)
    FROM public.tenant_permissions AS permission
    WHERE permission.key IN (
      'contact.read', 'contact.manage', 'contact.preference.manage',
      'contact.group.read', 'contact.group.manage',
      'portal.alert.read', 'portal.case.read', 'portal.comment.public',
      'portal.attachment.read', 'portal.contact.preference.manage'
    )
  ) <> 10 OR (
    SELECT count(*)
    FROM pg_trigger AS trigger
    JOIN pg_class AS class ON class.oid = trigger.tgrelid
    JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
    WHERE namespace.nspname = 'public'
      AND trigger.tgname IN (
        'ticket_comments_capture_author_snapshot_v1',
        'ticket_activities_capture_author_snapshot_v1'
      ) AND NOT trigger.tgisinternal AND trigger.tgenabled = 'O'
  ) <> 2 OR EXISTS (
    SELECT 1 FROM public.ticket_comments AS comment
    WHERE NOT EXISTS (
      SELECT 1 FROM public.ticket_comment_author_snapshots AS snapshot
      WHERE snapshot.tenant_id = comment.tenant_id
        AND snapshot.comment_id = comment.id
    )
  ) OR EXISTS (
    SELECT 1 FROM public.ticket_activities AS activity
    WHERE NOT EXISTS (
      SELECT 1 FROM public.ticket_activity_author_snapshots AS snapshot
      WHERE snapshot.tenant_id = activity.tenant_id
        AND snapshot.activity_id = activity.id
    )
  ) THEN
    RETURN false;
  END IF;

  FOR expected_function IN
    SELECT * FROM (VALUES
      ('app.commit_customer_contact_v1(text,uuid,bigint,jsonb,bytea,bytea,text,uuid,uuid,uuid,inet,text,text)', 'periapsis_migrator', true, false),
      ('app.commit_customer_contact_group_v1(text,uuid,bigint,jsonb,bytea,bytea,uuid,uuid,uuid,inet,text,text)', 'periapsis_migrator', true, false),
      ('app.commit_ticket_customer_contact_v1(text,uuid,bigint,bigint,jsonb,bytea,bytea,text,uuid,uuid,uuid,inet,text,text)', 'periapsis_migrator', true, false),
      ('app.create_customer_portal_ticket_comment_v1(public.ticket_aggregate_kind,uuid,uuid,text,text,bytea,bytea,uuid,uuid,inet,text,text)', 'periapsis_migrator', true, false),
      ('app.commit_tenant_ticket_escalation_v2(uuid,uuid,boolean,jsonb,jsonb,text,text,bytea,bytea,text[],uuid,uuid,inet,text,text)', 'periapsis_migrator', true, false),
      ('app.load_notification_fanout_inputs_v2(uuid,uuid)', 'periapsis_notification_dispatch_owner', false, true),
      ('app.schema_compatibility_v18()', 'periapsis_migrator', true, false),
      ('app.schema_compatibility_v17()', 'periapsis_migrator', true, false),
      ('app.schema_compatibility_v16()', 'periapsis_migrator', true, false)
    ) AS expected(signature, expected_owner, api_execute, notifier_execute)
  LOOP
    function_oid := to_regprocedure(expected_function.signature);
    IF function_oid IS NULL THEN
      RETURN false;
    END IF;
    SELECT pg_get_userbyid(procedure.proowner), procedure.prosecdef,
           procedure.proconfig
    INTO function_owner, function_security_definer, function_configuration
    FROM pg_proc AS procedure WHERE procedure.oid = function_oid;
    IF function_owner IS DISTINCT FROM expected_function.expected_owner
       OR function_security_definer IS NOT TRUE
       OR function_configuration[1] NOT LIKE 'search_path=pg_catalog%'
       OR EXISTS (
         SELECT 1 FROM pg_proc AS procedure
         CROSS JOIN LATERAL aclexplode(
           coalesce(procedure.proacl, acldefault('f', procedure.proowner))
         ) AS privilege
         WHERE procedure.oid = function_oid AND privilege.grantee = 0
           AND privilege.privilege_type = 'EXECUTE'
       ) OR has_function_privilege(
         'periapsis_api', function_oid, 'EXECUTE'
       ) IS DISTINCT FROM expected_function.api_execute
       OR has_function_privilege(
         'periapsis_notifier', function_oid, 'EXECUTE'
       ) IS DISTINCT FROM expected_function.notifier_execute THEN
      RETURN false;
    END IF;
  END LOOP;
  IF has_function_privilege(
    'periapsis_notifier',
    'app.load_notification_fanout_inputs_v1(uuid,uuid)', 'EXECUTE'
  ) THEN
    RETURN false;
  END IF;

  SELECT compatibility.applied_count INTO current_count
  FROM app.schema_compatibility_v18() AS compatibility;
  SELECT compatibility.applied_count INTO predecessor_count
  FROM app.schema_compatibility_v17() AS compatibility;
  SELECT compatibility.applied_count INTO retired_count
  FROM app.schema_compatibility_v16() AS compatibility;
  RETURN current_count = 102 AND predecessor_count = 101
    AND retired_count = 0;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.contacts_portal_schema_readiness_v1()
  OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.contacts_portal_schema_readiness_v1()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.contacts_portal_schema_readiness_v1()
  TO periapsis_api, periapsis_worker;--> statement-breakpoint

CREATE FUNCTION app.notification_schema_readiness_v2()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  relation_name text;
  expected_function record;
  function_oid regprocedure;
  function_owner text;
  function_security_definer boolean;
  function_configuration text[];
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_roles AS role
    WHERE role.rolname IN (
      'periapsis_notification_admin_owner',
      'periapsis_notification_dispatch_owner',
      'periapsis_notification_readiness_owner'
    ) AND (role.rolcanlogin OR role.rolsuper OR role.rolcreatedb
      OR role.rolcreaterole OR role.rolinherit OR role.rolreplication
      OR role.rolbypassrls)
  ) OR (
    SELECT count(*) FROM pg_roles AS role
    WHERE role.rolname IN (
      'periapsis_notification_admin_owner',
      'periapsis_notification_dispatch_owner',
      'periapsis_notification_readiness_owner'
    )
  ) <> 3 THEN
    RETURN false;
  END IF;

  FOREACH relation_name IN ARRAY ARRAY[
    'tenant_notification_templates',
    'tenant_notification_template_versions',
    'tenant_notification_rules',
    'tenant_notification_rule_versions',
    'tenant_notification_secret_versions',
    'tenant_notification_smtp_configurations',
    'tenant_notification_smtp_configuration_versions',
    'tenant_notification_webhook_configurations',
    'tenant_notification_webhook_configuration_versions',
    'tenant_notification_fanout_snapshots',
    'tenant_notification_deliveries',
    'tenant_notification_delivery_attempts',
    'tenant_notification_commands'
  ] LOOP
    IF NOT EXISTS (
      SELECT 1 FROM pg_class AS class
      JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
      WHERE namespace.nspname = 'public' AND class.relname = relation_name
        AND class.relkind = 'r'
        AND pg_get_userbyid(class.relowner) = 'periapsis_migrator'
        AND class.relrowsecurity AND class.relforcerowsecurity
    ) OR has_table_privilege(
      'periapsis_api', format('public.%I', relation_name),
      'SELECT,INSERT,UPDATE,DELETE'
    ) OR has_table_privilege(
      'periapsis_notifier', format('public.%I', relation_name),
      'SELECT,INSERT,UPDATE,DELETE'
    ) THEN
      RETURN false;
    END IF;
  END LOOP;

  FOR expected_function IN
    SELECT * FROM (VALUES
      ('app.claim_notification_fanout_batch_v1(text,integer,integer,timestamp with time zone)', 'periapsis_notification_dispatch_owner', false, true),
      ('app.load_notification_fanout_inputs_v1(uuid,uuid)', 'periapsis_notification_dispatch_owner', false, false),
      ('app.load_notification_fanout_inputs_v2(uuid,uuid)', 'periapsis_notification_dispatch_owner', false, true),
      ('app.commit_notification_fanout_v1(uuid,uuid,jsonb,timestamp with time zone)', 'periapsis_notification_dispatch_owner', false, true),
      ('app.claim_notification_delivery_batch_v1(text,integer,integer,timestamp with time zone)', 'periapsis_notification_dispatch_owner', false, true),
      ('app.claim_notification_webhook_delivery_batch_v1(text,integer,integer,timestamp with time zone)', 'periapsis_notification_dispatch_owner', false, true),
      ('app.load_pinned_smtp_configuration_v1(uuid,text,uuid,integer)', 'periapsis_notification_dispatch_owner', false, true),
      ('app.private_require_notification_admin_v1()', 'periapsis_notification_admin_owner', false, false),
      ('app.verify_notification_keyring_v1(smallint[])', 'periapsis_notification_readiness_owner', true, false),
      ('app.schema_compatibility_v18()', 'periapsis_migrator', true, false),
      ('app.schema_compatibility_v17()', 'periapsis_migrator', true, false),
      ('app.schema_compatibility_v16()', 'periapsis_migrator', true, false)
    ) AS expected(signature, expected_owner, api_execute, notifier_execute)
  LOOP
    function_oid := to_regprocedure(expected_function.signature);
    IF function_oid IS NULL THEN
      RETURN false;
    END IF;
    SELECT pg_get_userbyid(procedure.proowner), procedure.prosecdef,
           procedure.proconfig
    INTO function_owner, function_security_definer, function_configuration
    FROM pg_proc AS procedure WHERE procedure.oid = function_oid;
    IF function_owner IS DISTINCT FROM expected_function.expected_owner
       OR function_security_definer IS NOT TRUE
       OR function_configuration[1] NOT LIKE 'search_path=pg_catalog%'
       OR EXISTS (
         SELECT 1 FROM pg_proc AS procedure
         CROSS JOIN LATERAL aclexplode(
           coalesce(procedure.proacl, acldefault('f', procedure.proowner))
         ) AS privilege
         WHERE procedure.oid = function_oid AND privilege.grantee = 0
           AND privilege.privilege_type = 'EXECUTE'
       ) OR has_function_privilege(
         'periapsis_api', function_oid, 'EXECUTE'
       ) IS DISTINCT FROM expected_function.api_execute
       OR has_function_privilege(
         'periapsis_notifier', function_oid, 'EXECUTE'
       ) IS DISTINCT FROM expected_function.notifier_execute THEN
      RETURN false;
    END IF;
  END LOOP;
  RETURN app.contacts_portal_schema_readiness_v1();
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.notification_schema_readiness_v2()
  OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.notification_schema_readiness_v2()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.notification_schema_readiness_v2()
  TO periapsis_api, periapsis_worker,
     periapsis_notification_readiness_owner;--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.notification_dispatch_readiness_v2()
RETURNS TABLE(
  queue_depth bigint,
  role_safe boolean,
  schema_safe boolean,
  oldest_pending_seconds bigint
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  SELECT readiness.queue_depth, readiness.role_safe
  INTO queue_depth, role_safe
  FROM app.notification_dispatch_readiness_v1() AS readiness;
  schema_safe := app.notification_schema_readiness_v2();
  SELECT coalesce(greatest(
    0,
    floor(extract(epoch FROM transaction_timestamp() - min(event.occurred_at)))
  )::bigint, 0::bigint)
  INTO oldest_pending_seconds
  FROM public.outbox_events AS event
  WHERE event.event_type LIKE 'notification.%'
    AND event.schema_version = 2
    AND event.processed_at IS NULL
    AND event.dead_lettered_at IS NULL
    AND event.available_at <= transaction_timestamp()
    AND event.attempts < event.max_attempts
    AND (event.lease_until IS NULL
      OR event.lease_until <= transaction_timestamp());
  RETURN NEXT;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.notification_dispatch_readiness_v2()
  OWNER TO periapsis_notification_readiness_owner;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.notification_dispatch_readiness_v2()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.notification_dispatch_readiness_v2()
  TO periapsis_notifier;
