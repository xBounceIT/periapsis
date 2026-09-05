CREATE ROLE "periapsis_ticket_saved_view_owner" WITH NOINHERIT;--> statement-breakpoint
CREATE TABLE "ticket_saved_view_commands" (
	"id" uuid NOT NULL,
	"tenant_id" uuid NOT NULL,
	"actor_user_id" uuid NOT NULL,
	"owner_membership_id" uuid NOT NULL,
	"aggregate_kind" "ticket_aggregate_kind" NOT NULL,
	"action" text NOT NULL,
	"idempotency_key_digest" "bytea" NOT NULL,
	"request_fingerprint_digest" "bytea" NOT NULL,
	"expected_revision" integer NOT NULL,
	"next_revision" integer NOT NULL,
	"result_view_id" uuid NOT NULL,
	"result_name" text COLLATE "C" NOT NULL,
	"result_spec_canonical" text COLLATE "C" NOT NULL,
	"result_spec_digest" "bytea" NOT NULL,
	"result_status" text NOT NULL,
	"result_created_at" timestamp with time zone NOT NULL,
	"result_updated_at" timestamp with time zone NOT NULL,
	"result_archived_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone DEFAULT now() + interval '30 days' NOT NULL,
	CONSTRAINT "ticket_saved_view_commands_pkey" PRIMARY KEY("id"),
	CONSTRAINT "ticket_saved_view_commands_tenant_id_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "ticket_saved_view_commands_replay_key" UNIQUE("tenant_id","actor_user_id","owner_membership_id","aggregate_kind","action","idempotency_key_digest"),
	CONSTRAINT "ticket_saved_view_commands_id_uuidv7_check" CHECK ((uuid_extract_version("ticket_saved_view_commands"."id") = 7) is true),
	CONSTRAINT "ticket_saved_view_commands_action_check" CHECK ("ticket_saved_view_commands"."action" in ('create', 'replace', 'archive', 'restore')
        and "ticket_saved_view_commands"."expected_revision" between 0 and 2147483646
        and "ticket_saved_view_commands"."next_revision" = "ticket_saved_view_commands"."expected_revision" + 1
        and ("ticket_saved_view_commands"."action" = 'create') = ("ticket_saved_view_commands"."expected_revision" = 0)),
	CONSTRAINT "ticket_saved_view_commands_digest_check" CHECK (octet_length("ticket_saved_view_commands"."idempotency_key_digest") = 32
        and octet_length("ticket_saved_view_commands"."request_fingerprint_digest") = 32
        and octet_length("ticket_saved_view_commands"."result_spec_digest") = 32),
	CONSTRAINT "ticket_saved_view_commands_result_check" CHECK ((uuid_extract_version("ticket_saved_view_commands"."result_view_id") = 7) is true
        and btrim("ticket_saved_view_commands"."result_name") <> ''
        and octet_length("ticket_saved_view_commands"."result_name") <= 120
        and "ticket_saved_view_commands"."result_name" !~ '[[:cntrl:]‎‏‪-‮⁦-⁩]'
        and octet_length("ticket_saved_view_commands"."result_spec_canonical") between 1 and 262144
        and "ticket_saved_view_commands"."result_status" in ('active', 'archived')
        and "ticket_saved_view_commands"."next_revision" between 1 and 2147483647
        and "ticket_saved_view_commands"."result_updated_at" >= "ticket_saved_view_commands"."result_created_at"
        and ("ticket_saved_view_commands"."result_status" = 'archived') = ("ticket_saved_view_commands"."result_archived_at" is not null)
        and ("ticket_saved_view_commands"."result_archived_at" is null
          or "ticket_saved_view_commands"."result_archived_at" between "ticket_saved_view_commands"."result_created_at" and "ticket_saved_view_commands"."result_updated_at")
        and ("ticket_saved_view_commands"."action" = 'archive') = ("ticket_saved_view_commands"."result_status" = 'archived')),
	CONSTRAINT "ticket_saved_view_commands_retention_check" CHECK ("ticket_saved_view_commands"."expires_at" >= "ticket_saved_view_commands"."created_at" + interval '24 hours'
        and "ticket_saved_view_commands"."expires_at" <= "ticket_saved_view_commands"."created_at" + interval '90 days')
);
--> statement-breakpoint
ALTER TABLE "ticket_saved_view_commands" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "ticket_saved_views" (
	"id" uuid NOT NULL,
	"tenant_id" uuid NOT NULL,
	"owner_membership_id" uuid NOT NULL,
	"aggregate_kind" "ticket_aggregate_kind" NOT NULL,
	"name" text COLLATE "C" NOT NULL,
	"spec_canonical" text COLLATE "C" NOT NULL,
	"spec_digest" "bytea" NOT NULL,
	"status" text NOT NULL,
	"revision" integer NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"archived_at" timestamp with time zone,
	CONSTRAINT "ticket_saved_views_pkey" PRIMARY KEY("id"),
	CONSTRAINT "ticket_saved_views_tenant_id_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "ticket_saved_views_id_uuidv7_check" CHECK ((uuid_extract_version("ticket_saved_views"."id") = 7) is true),
	CONSTRAINT "ticket_saved_views_name_check" CHECK (btrim("ticket_saved_views"."name") <> ''
        and octet_length("ticket_saved_views"."name") <= 120
        and "ticket_saved_views"."name" !~ '[[:cntrl:]‎‏‪-‮⁦-⁩]'),
	CONSTRAINT "ticket_saved_views_spec_check" CHECK (octet_length("ticket_saved_views"."spec_canonical") between 1 and 262144
        and octet_length("ticket_saved_views"."spec_digest") = 32),
	CONSTRAINT "ticket_saved_views_lifecycle_check" CHECK ("ticket_saved_views"."status" in ('active', 'archived')
        and "ticket_saved_views"."revision" between 1 and 2147483647
        and "ticket_saved_views"."updated_at" >= "ticket_saved_views"."created_at"
        and ("ticket_saved_views"."status" = 'archived') = ("ticket_saved_views"."archived_at" is not null)
        and ("ticket_saved_views"."archived_at" is null
          or "ticket_saved_views"."archived_at" between "ticket_saved_views"."created_at" and "ticket_saved_views"."updated_at"))
);
--> statement-breakpoint
ALTER TABLE "ticket_saved_views" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "ticket_saved_view_commands" ADD CONSTRAINT "ticket_saved_view_commands_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ticket_saved_view_commands" ADD CONSTRAINT "ticket_saved_view_commands_actor_owner_fk" FOREIGN KEY ("tenant_id","owner_membership_id","actor_user_id") REFERENCES "public"."tenant_memberships"("tenant_id","id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "ticket_saved_view_commands" ADD CONSTRAINT "ticket_saved_view_commands_result_fk" FOREIGN KEY ("tenant_id","result_view_id") REFERENCES "public"."ticket_saved_views"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "ticket_saved_views" ADD CONSTRAINT "ticket_saved_views_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ticket_saved_views" ADD CONSTRAINT "ticket_saved_views_owner_fk" FOREIGN KEY ("tenant_id","owner_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
CREATE INDEX "ticket_saved_view_commands_expiry_idx" ON "ticket_saved_view_commands" USING btree ("expires_at","tenant_id","id");--> statement-breakpoint
CREATE INDEX "ticket_saved_views_owner_list_idx" ON "ticket_saved_views" USING btree ("tenant_id","owner_membership_id","aggregate_kind","id");--> statement-breakpoint
CREATE INDEX "custom_field_values_saved_sort_boolean_idx" ON "custom_field_values" USING btree ("tenant_id","object_type","definition_id","definition_schema_version","boolean_value","alert_id","case_id");--> statement-breakpoint
CREATE INDEX "custom_field_values_saved_sort_date_idx" ON "custom_field_values" USING btree ("tenant_id","object_type","definition_id","definition_schema_version","date_value","alert_id","case_id");--> statement-breakpoint
CREATE INDEX "custom_field_values_saved_sort_ip_idx" ON "custom_field_values" USING btree ("tenant_id","object_type","definition_id","definition_schema_version","ip_value","alert_id","case_id");--> statement-breakpoint
CREATE INDEX "custom_field_values_saved_sort_cidr_idx" ON "custom_field_values" USING btree ("tenant_id","object_type","definition_id","definition_schema_version","cidr_value","alert_id","case_id");--> statement-breakpoint
CREATE INDEX "custom_field_values_saved_sort_reference_idx" ON "custom_field_values" USING btree ("tenant_id","object_type","definition_id","definition_schema_version","reference_id","alert_id","case_id");--> statement-breakpoint
CREATE INDEX "custom_field_values_saved_sort_single_select_idx" ON "custom_field_values" USING btree ("tenant_id","object_type","definition_id","definition_schema_version",("option_keys"[1]),"alert_id","case_id");--> statement-breakpoint
CREATE POLICY "ticket_saved_view_commands_owner_access" ON "ticket_saved_view_commands" AS PERMISSIVE FOR ALL TO "periapsis_ticket_saved_view_owner" USING (true) WITH CHECK (true);--> statement-breakpoint
CREATE POLICY "ticket_saved_views_owner_access" ON "ticket_saved_views" AS PERMISSIVE FOR ALL TO "periapsis_ticket_saved_view_owner" USING (true) WITH CHECK (true);