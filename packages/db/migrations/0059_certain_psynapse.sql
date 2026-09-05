CREATE TYPE "public"."ldap_directory_operation_kind" AS ENUM('search_user', 'filter_user', 'filter_group');--> statement-breakpoint
CREATE TABLE "tenant_ldap_directory_operation_runs" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"provider_id" uuid NOT NULL,
	"provider_kind" "auth_provider_kind" DEFAULT 'ldap' NOT NULL,
	"operation_kind" "ldap_directory_operation_kind" NOT NULL,
	"binding_id" uuid,
	"provider_version" integer NOT NULL,
	"configuration_version" integer NOT NULL,
	"endpoint_snapshot_digest" "bytea" NOT NULL,
	"bind_secret_id" uuid NOT NULL,
	"bind_secret_version" integer NOT NULL,
	"bind_secret_key_version" integer NOT NULL,
	"bind_secret_algorithm" text NOT NULL,
	"binding_version" integer,
	"binding_auth_revision" integer,
	"binding_access_epoch_id" uuid,
	"rule_set_revision" integer,
	"authorization_revision" integer,
	"status" "ldap_provider_test_status" DEFAULT 'started' NOT NULL,
	"outcome" "ldap_provider_test_outcome",
	"category" "ldap_provider_test_category",
	"endpoint_priority" integer,
	"duration_ms" integer,
	"matched_entry_count" integer,
	"result_truncated" boolean,
	"reason" text NOT NULL,
	"started_by_membership_id" uuid NOT NULL,
	"completed_by_membership_id" uuid,
	"request_id" uuid NOT NULL,
	"correlation_id" uuid NOT NULL,
	"started_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"completed_at" timestamp with time zone,
	"version" integer DEFAULT 1 NOT NULL,
	CONSTRAINT "tenant_ldap_directory_runs_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "tenant_ldap_directory_runs_exact_binding_key" UNIQUE("tenant_id","id","binding_id"),
	CONSTRAINT "tenant_ldap_directory_runs_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_ldap_directory_operation_runs"."id") = 7) is true),
	CONSTRAINT "tenant_ldap_directory_runs_kind_check" CHECK ("tenant_ldap_directory_operation_runs"."provider_kind" = 'ldap'),
	CONSTRAINT "tenant_ldap_directory_runs_revision_check" CHECK ("tenant_ldap_directory_operation_runs"."provider_version" > 0
        and "tenant_ldap_directory_operation_runs"."configuration_version" > 0
        and "tenant_ldap_directory_operation_runs"."bind_secret_version" > 0
        and "tenant_ldap_directory_operation_runs"."bind_secret_key_version" > 0),
	CONSTRAINT "tenant_ldap_directory_runs_secret_check" CHECK ((uuid_extract_version("tenant_ldap_directory_operation_runs"."bind_secret_id") = 7) is true
        and octet_length("tenant_ldap_directory_operation_runs"."endpoint_snapshot_digest") = 32
        and "tenant_ldap_directory_operation_runs"."bind_secret_algorithm" = 'aes-256-gcm'),
	CONSTRAINT "tenant_ldap_directory_runs_planning_check" CHECK (("tenant_ldap_directory_operation_runs"."binding_id" is null
          and "tenant_ldap_directory_operation_runs"."binding_version" is null
          and "tenant_ldap_directory_operation_runs"."binding_auth_revision" is null
          and "tenant_ldap_directory_operation_runs"."binding_access_epoch_id" is null
          and "tenant_ldap_directory_operation_runs"."rule_set_revision" is null
          and "tenant_ldap_directory_operation_runs"."authorization_revision" is null)
        or ("tenant_ldap_directory_operation_runs"."operation_kind" = 'search_user'
          and "tenant_ldap_directory_operation_runs"."binding_id" is not null
          and "tenant_ldap_directory_operation_runs"."binding_version" > 0
          and "tenant_ldap_directory_operation_runs"."binding_auth_revision" > 0
          and "tenant_ldap_directory_operation_runs"."binding_access_epoch_id" is not null
          and "tenant_ldap_directory_operation_runs"."rule_set_revision" > 0
          and "tenant_ldap_directory_operation_runs"."authorization_revision" > 0)),
	CONSTRAINT "tenant_ldap_directory_runs_reason_check" CHECK (btrim("tenant_ldap_directory_operation_runs"."reason") <> ''
        and char_length("tenant_ldap_directory_operation_runs"."reason") <= 500
        and "tenant_ldap_directory_operation_runs"."reason" !~ '[[:cntrl:]]'),
	CONSTRAINT "tenant_ldap_directory_runs_result_bounds_check" CHECK (("tenant_ldap_directory_operation_runs"."endpoint_priority" is null
          or "tenant_ldap_directory_operation_runs"."endpoint_priority" between 1 and 8)
        and ("tenant_ldap_directory_operation_runs"."duration_ms" is null
          or "tenant_ldap_directory_operation_runs"."duration_ms" between 0 and 120000)
        and ("tenant_ldap_directory_operation_runs"."matched_entry_count" is null
          or "tenant_ldap_directory_operation_runs"."matched_entry_count" between 0 and 10)),
	CONSTRAINT "tenant_ldap_directory_runs_lifetime_check" CHECK ("tenant_ldap_directory_operation_runs"."expires_at" > "tenant_ldap_directory_operation_runs"."started_at"
        and "tenant_ldap_directory_operation_runs"."expires_at" <= "tenant_ldap_directory_operation_runs"."started_at" + interval '2 minutes'),
	CONSTRAINT "tenant_ldap_directory_runs_lifecycle_check" CHECK ((("tenant_ldap_directory_operation_runs"."status" = 'started'
          and "tenant_ldap_directory_operation_runs"."outcome" is null
          and "tenant_ldap_directory_operation_runs"."category" is null
          and "tenant_ldap_directory_operation_runs"."endpoint_priority" is null
          and "tenant_ldap_directory_operation_runs"."duration_ms" is null
          and "tenant_ldap_directory_operation_runs"."matched_entry_count" is null
          and "tenant_ldap_directory_operation_runs"."result_truncated" is null
          and "tenant_ldap_directory_operation_runs"."completed_by_membership_id" is null
          and "tenant_ldap_directory_operation_runs"."completed_at" is null
          and "tenant_ldap_directory_operation_runs"."version" = 1)
        or ("tenant_ldap_directory_operation_runs"."status" = 'completed'
          and "tenant_ldap_directory_operation_runs"."outcome" is not null
          and "tenant_ldap_directory_operation_runs"."category" is not null
          and "tenant_ldap_directory_operation_runs"."duration_ms" is not null
          and "tenant_ldap_directory_operation_runs"."matched_entry_count" is not null
          and "tenant_ldap_directory_operation_runs"."result_truncated" is not null
          and "tenant_ldap_directory_operation_runs"."completed_by_membership_id" is not null
          and "tenant_ldap_directory_operation_runs"."completed_by_membership_id" = "tenant_ldap_directory_operation_runs"."started_by_membership_id"
          and "tenant_ldap_directory_operation_runs"."completed_at" >= "tenant_ldap_directory_operation_runs"."started_at"
          and "tenant_ldap_directory_operation_runs"."version" = 2)) is true)
);
--> statement-breakpoint
ALTER TABLE "tenant_ldap_directory_operation_runs" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_ldap_directory_run_mappings" (
	"tenant_id" uuid NOT NULL,
	"operation_run_id" uuid NOT NULL,
	"binding_id" uuid NOT NULL,
	"mapping_rule_id" uuid NOT NULL,
	"mapping_version" integer NOT NULL,
	"configuration_revision" integer NOT NULL,
	"source_epoch_id" uuid,
	"source_epoch_sequence" integer,
	"authorization_source_id" uuid,
	"planning_epoch_id" uuid NOT NULL,
	"planning_source_id" uuid NOT NULL,
	"included_disabled" boolean NOT NULL,
	"priority" integer NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_ldap_directory_run_mappings_pkey" PRIMARY KEY("tenant_id","operation_run_id","mapping_rule_id"),
	CONSTRAINT "tenant_ldap_directory_run_mappings_epoch_key" UNIQUE("tenant_id","operation_run_id","planning_epoch_id"),
	CONSTRAINT "tenant_ldap_directory_run_mappings_source_key" UNIQUE("tenant_id","operation_run_id","planning_source_id"),
	CONSTRAINT "tenant_ldap_directory_run_mappings_revision_check" CHECK ("tenant_ldap_directory_run_mappings"."mapping_version" > 0
        and "tenant_ldap_directory_run_mappings"."configuration_revision" > 0
        and "tenant_ldap_directory_run_mappings"."priority" between 0 and 1000000),
	CONSTRAINT "tenant_ldap_directory_run_mappings_planning_id_check" CHECK ((uuid_extract_version("tenant_ldap_directory_run_mappings"."planning_epoch_id") = 7) is true
        and (uuid_extract_version("tenant_ldap_directory_run_mappings"."planning_source_id") = 7) is true),
	CONSTRAINT "tenant_ldap_directory_run_mappings_source_check" CHECK ((not "tenant_ldap_directory_run_mappings"."included_disabled"
          and "tenant_ldap_directory_run_mappings"."source_epoch_id" is not null
          and "tenant_ldap_directory_run_mappings"."source_epoch_sequence" > 0
          and "tenant_ldap_directory_run_mappings"."authorization_source_id" is not null
          and "tenant_ldap_directory_run_mappings"."planning_epoch_id" = "tenant_ldap_directory_run_mappings"."source_epoch_id"
          and "tenant_ldap_directory_run_mappings"."planning_source_id" = "tenant_ldap_directory_run_mappings"."authorization_source_id")
        or ("tenant_ldap_directory_run_mappings"."included_disabled"
          and "tenant_ldap_directory_run_mappings"."source_epoch_id" is null
          and "tenant_ldap_directory_run_mappings"."source_epoch_sequence" is null
          and "tenant_ldap_directory_run_mappings"."authorization_source_id" is null))
);
--> statement-breakpoint
ALTER TABLE "tenant_ldap_directory_run_mappings" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "tenant_auth_provider_bindings" DROP CONSTRAINT "tenant_auth_provider_bindings_revision_check";--> statement-breakpoint
ALTER TABLE "tenant_auth_provider_bindings" ADD COLUMN "mapping_revision" integer DEFAULT 1 NOT NULL;--> statement-breakpoint
ALTER TABLE "tenant_ldap_directory_operation_runs" ADD CONSTRAINT "tenant_ldap_directory_operation_runs_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_ldap_directory_operation_runs" ADD CONSTRAINT "tenant_ldap_directory_operation_runs_bind_secret_key_version_identity_keyring_versions_key_version_fk" FOREIGN KEY ("bind_secret_key_version") REFERENCES "public"."identity_keyring_versions"("key_version") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_ldap_directory_operation_runs" ADD CONSTRAINT "tenant_ldap_directory_runs_provider_fk" FOREIGN KEY ("tenant_id","provider_id","provider_kind") REFERENCES "public"."tenant_auth_providers"("tenant_id","id","kind") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_directory_operation_runs" ADD CONSTRAINT "tenant_ldap_directory_runs_binding_fk" FOREIGN KEY ("tenant_id","binding_id","provider_id") REFERENCES "public"."tenant_auth_provider_bindings"("tenant_id","id","provider_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_directory_operation_runs" ADD CONSTRAINT "tenant_ldap_directory_runs_access_epoch_fk" FOREIGN KEY ("tenant_id","binding_access_epoch_id","binding_id","provider_id") REFERENCES "public"."tenant_identity_provider_access_epochs"("tenant_id","id","binding_id","provider_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_directory_operation_runs" ADD CONSTRAINT "tenant_ldap_directory_runs_starter_fk" FOREIGN KEY ("tenant_id","started_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_directory_operation_runs" ADD CONSTRAINT "tenant_ldap_directory_runs_completer_fk" FOREIGN KEY ("tenant_id","completed_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_directory_run_mappings" ADD CONSTRAINT "tenant_ldap_directory_run_mappings_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_ldap_directory_run_mappings" ADD CONSTRAINT "tenant_ldap_directory_run_mappings_run_fk" FOREIGN KEY ("tenant_id","operation_run_id","binding_id") REFERENCES "public"."tenant_ldap_directory_operation_runs"("tenant_id","id","binding_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_directory_run_mappings" ADD CONSTRAINT "tenant_ldap_directory_run_mappings_rule_fk" FOREIGN KEY ("tenant_id","mapping_rule_id","binding_id") REFERENCES "public"."tenant_ldap_mapping_rules"("tenant_id","id","binding_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_directory_run_mappings" ADD CONSTRAINT "tenant_ldap_directory_run_mappings_epoch_fk" FOREIGN KEY ("tenant_id","source_epoch_id","mapping_rule_id","binding_id","configuration_revision") REFERENCES "public"."tenant_ldap_mapping_rule_epochs"("tenant_id","id","mapping_rule_id","binding_id","configuration_revision") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
CREATE INDEX "tenant_ldap_directory_runs_provider_started_idx" ON "tenant_ldap_directory_operation_runs" USING btree ("tenant_id","provider_id","started_at","id");--> statement-breakpoint
CREATE INDEX "tenant_ldap_directory_runs_actor_started_idx" ON "tenant_ldap_directory_operation_runs" USING btree ("tenant_id","started_by_membership_id","started_at","id");--> statement-breakpoint
CREATE INDEX "tenant_ldap_directory_runs_status_started_idx" ON "tenant_ldap_directory_operation_runs" USING btree ("tenant_id","status","started_at","id");--> statement-breakpoint
CREATE INDEX "tenant_ldap_directory_runs_key_version_idx" ON "tenant_ldap_directory_operation_runs" USING btree ("bind_secret_key_version","tenant_id","status","expires_at");--> statement-breakpoint
CREATE INDEX "tenant_ldap_directory_run_mappings_order_idx" ON "tenant_ldap_directory_run_mappings" USING btree ("tenant_id","operation_run_id","priority","mapping_rule_id");--> statement-breakpoint
ALTER TABLE "tenant_auth_provider_bindings" ADD CONSTRAINT "tenant_auth_provider_bindings_revision_check" CHECK ("tenant_auth_provider_bindings"."auth_revision" > 0
        and "tenant_auth_provider_bindings"."mapping_revision" > 0
        and "tenant_auth_provider_bindings"."version" > 0);