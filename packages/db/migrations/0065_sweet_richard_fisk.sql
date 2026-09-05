CREATE TYPE "public"."ldap_identity_apply_decision" AS ENUM('admitted', 'denied');--> statement-breakpoint
CREATE TYPE "public"."ldap_identity_apply_mode" AS ENUM('jit', 'sync');--> statement-breakpoint
CREATE TYPE "public"."ldap_sync_absence_status" AS ENUM('pending', 'cleared', 'applied');--> statement-breakpoint
CREATE TYPE "public"."ldap_sync_run_status" AS ENUM('queued', 'enumerating', 'applying', 'succeeded', 'failed', 'cancelled', 'stale');--> statement-breakpoint
CREATE TYPE "public"."ldap_sync_trigger" AS ENUM('scheduled', 'manual');--> statement-breakpoint
CREATE TABLE "tenant_ldap_identity_plan_applications" (
	"id" uuid PRIMARY KEY NOT NULL,
	"tenant_id" uuid NOT NULL,
	"plan_digest" "bytea" NOT NULL,
	"apply_mode" "ldap_identity_apply_mode" NOT NULL,
	"decision" "ldap_identity_apply_decision" NOT NULL,
	"denial_category" text,
	"provider_id" uuid NOT NULL,
	"binding_id" uuid NOT NULL,
	"sync_run_id" uuid,
	"sync_observation_id" uuid,
	"provider_version" integer NOT NULL,
	"configuration_version" integer NOT NULL,
	"binding_version" integer NOT NULL,
	"binding_auth_revision" integer NOT NULL,
	"binding_access_epoch_id" uuid NOT NULL,
	"rule_set_revision" bigint NOT NULL,
	"authorization_revision" bigint NOT NULL,
	"external_identity_id" uuid,
	"user_id" uuid,
	"membership_id" uuid,
	"access_grant_id" uuid,
	"ensured_edge_count" integer DEFAULT 0 NOT NULL,
	"revoked_edge_count" integer DEFAULT 0 NOT NULL,
	"audit_event_id" uuid NOT NULL,
	"request_id" uuid NOT NULL,
	"correlation_id" uuid NOT NULL,
	"observed_at" timestamp with time zone NOT NULL,
	"applied_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_ldap_identity_plan_applications_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "tenant_ldap_identity_plan_applications_audit_key" UNIQUE("tenant_id","audit_event_id"),
	CONSTRAINT "tenant_ldap_identity_plan_applications_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_ldap_identity_plan_applications"."id") = 7) is true),
	CONSTRAINT "tenant_ldap_identity_plan_applications_digest_check" CHECK (octet_length("tenant_ldap_identity_plan_applications"."plan_digest") = 32),
	CONSTRAINT "tenant_ldap_identity_plan_applications_revision_check" CHECK ("tenant_ldap_identity_plan_applications"."provider_version" > 0 and "tenant_ldap_identity_plan_applications"."configuration_version" > 0
        and "tenant_ldap_identity_plan_applications"."binding_version" > 0 and "tenant_ldap_identity_plan_applications"."binding_auth_revision" > 0
        and "tenant_ldap_identity_plan_applications"."rule_set_revision" > 0 and "tenant_ldap_identity_plan_applications"."authorization_revision" > 0),
	CONSTRAINT "tenant_ldap_identity_plan_applications_mode_check" CHECK (("tenant_ldap_identity_plan_applications"."apply_mode" = 'jit'
          and "tenant_ldap_identity_plan_applications"."sync_run_id" is null and "tenant_ldap_identity_plan_applications"."sync_observation_id" is null)
        or ("tenant_ldap_identity_plan_applications"."apply_mode" = 'sync'
          and "tenant_ldap_identity_plan_applications"."sync_run_id" is not null and "tenant_ldap_identity_plan_applications"."sync_observation_id" is not null)),
	CONSTRAINT "tenant_ldap_identity_plan_applications_decision_check" CHECK (("tenant_ldap_identity_plan_applications"."decision" = 'denied'
          and "tenant_ldap_identity_plan_applications"."denial_category" is not null
          and "tenant_ldap_identity_plan_applications"."external_identity_id" is null and "tenant_ldap_identity_plan_applications"."user_id" is null
          and "tenant_ldap_identity_plan_applications"."membership_id" is null and "tenant_ldap_identity_plan_applications"."access_grant_id" is null
          and "tenant_ldap_identity_plan_applications"."ensured_edge_count" = 0 and "tenant_ldap_identity_plan_applications"."revoked_edge_count" = 0)
        or ("tenant_ldap_identity_plan_applications"."decision" = 'admitted'
          and "tenant_ldap_identity_plan_applications"."denial_category" is null
          and "tenant_ldap_identity_plan_applications"."external_identity_id" is not null and "tenant_ldap_identity_plan_applications"."user_id" is not null
          and "tenant_ldap_identity_plan_applications"."membership_id" is not null and "tenant_ldap_identity_plan_applications"."access_grant_id" is not null)),
	CONSTRAINT "tenant_ldap_identity_plan_applications_denial_check" CHECK ("tenant_ldap_identity_plan_applications"."denial_category" is null or (
        btrim("tenant_ldap_identity_plan_applications"."denial_category") <> ''
        and char_length("tenant_ldap_identity_plan_applications"."denial_category") <= 64
        and "tenant_ldap_identity_plan_applications"."denial_category" ~ '^[a-z][a-z0-9_]{1,63}$'
      )),
	CONSTRAINT "tenant_ldap_identity_plan_applications_counts_check" CHECK ("tenant_ldap_identity_plan_applications"."ensured_edge_count" between 0 and 10000
        and "tenant_ldap_identity_plan_applications"."revoked_edge_count" between 0 and 10000
        and "tenant_ldap_identity_plan_applications"."applied_at" >= "tenant_ldap_identity_plan_applications"."observed_at")
);
--> statement-breakpoint
ALTER TABLE "tenant_ldap_identity_plan_applications" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_ldap_sync_absences" (
	"tenant_id" uuid NOT NULL,
	"binding_id" uuid NOT NULL,
	"external_identity_id" uuid NOT NULL,
	"membership_id" uuid NOT NULL,
	"first_missing_run_id" uuid NOT NULL,
	"latest_missing_run_id" uuid NOT NULL,
	"status" "ldap_sync_absence_status" DEFAULT 'pending' NOT NULL,
	"first_missing_at" timestamp with time zone NOT NULL,
	"apply_after" timestamp with time zone NOT NULL,
	"resolved_at" timestamp with time zone,
	"version" integer DEFAULT 1 NOT NULL,
	CONSTRAINT "tenant_ldap_sync_absences_pkey" PRIMARY KEY("tenant_id","binding_id","external_identity_id"),
	CONSTRAINT "tenant_ldap_sync_absences_lifecycle_check" CHECK ("tenant_ldap_sync_absences"."apply_after" >= "tenant_ldap_sync_absences"."first_missing_at"
        and (("tenant_ldap_sync_absences"."status" = 'pending' and "tenant_ldap_sync_absences"."resolved_at" is null)
          or ("tenant_ldap_sync_absences"."status" in ('cleared', 'applied')
            and "tenant_ldap_sync_absences"."resolved_at" >= "tenant_ldap_sync_absences"."first_missing_at"))
        and "tenant_ldap_sync_absences"."version" > 0)
);
--> statement-breakpoint
ALTER TABLE "tenant_ldap_sync_absences" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_ldap_sync_run_mappings" (
	"tenant_id" uuid NOT NULL,
	"sync_run_id" uuid NOT NULL,
	"binding_id" uuid NOT NULL,
	"mapping_rule_id" uuid NOT NULL,
	"mapping_version" integer NOT NULL,
	"configuration_revision" integer NOT NULL,
	"source_epoch_id" uuid NOT NULL,
	"source_id" uuid NOT NULL,
	"priority" integer NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_ldap_sync_run_mappings_pkey" PRIMARY KEY("tenant_id","sync_run_id","mapping_rule_id"),
	CONSTRAINT "tenant_ldap_sync_run_mappings_epoch_key" UNIQUE("tenant_id","sync_run_id","source_epoch_id"),
	CONSTRAINT "tenant_ldap_sync_run_mappings_revision_check" CHECK ("tenant_ldap_sync_run_mappings"."mapping_version" > 0 and "tenant_ldap_sync_run_mappings"."configuration_revision" > 0
        and "tenant_ldap_sync_run_mappings"."priority" between 0 and 1000000)
);
--> statement-breakpoint
ALTER TABLE "tenant_ldap_sync_run_mappings" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_ldap_sync_runs" (
	"id" uuid PRIMARY KEY NOT NULL,
	"tenant_id" uuid NOT NULL,
	"provider_id" uuid NOT NULL,
	"provider_kind" "auth_provider_kind" DEFAULT 'ldap' NOT NULL,
	"binding_id" uuid NOT NULL,
	"trigger" "ldap_sync_trigger" NOT NULL,
	"status" "ldap_sync_run_status" DEFAULT 'queued' NOT NULL,
	"provider_version" integer NOT NULL,
	"configuration_version" integer NOT NULL,
	"binding_version" integer NOT NULL,
	"binding_auth_revision" integer NOT NULL,
	"binding_access_epoch_id" uuid NOT NULL,
	"rule_set_revision" bigint NOT NULL,
	"authorization_revision" bigint NOT NULL,
	"endpoint_snapshot_digest" "bytea" NOT NULL,
	"enumeration_complete" boolean,
	"result_truncated" boolean,
	"cursor_digest" "bytea",
	"observed_count" integer DEFAULT 0 NOT NULL,
	"applied_count" integer DEFAULT 0 NOT NULL,
	"revoked_count" integer DEFAULT 0 NOT NULL,
	"failure_category" text,
	"reason" text NOT NULL,
	"started_by_membership_id" uuid,
	"request_id" uuid NOT NULL,
	"correlation_id" uuid NOT NULL,
	"queued_at" timestamp with time zone DEFAULT now() NOT NULL,
	"enumeration_started_at" timestamp with time zone,
	"enumeration_completed_at" timestamp with time zone,
	"completed_at" timestamp with time zone,
	"version" integer DEFAULT 1 NOT NULL,
	CONSTRAINT "tenant_ldap_sync_runs_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "tenant_ldap_sync_runs_exact_binding_key" UNIQUE("tenant_id","id","binding_id"),
	CONSTRAINT "tenant_ldap_sync_runs_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_ldap_sync_runs"."id") = 7) is true),
	CONSTRAINT "tenant_ldap_sync_runs_kind_check" CHECK ("tenant_ldap_sync_runs"."provider_kind" = 'ldap'),
	CONSTRAINT "tenant_ldap_sync_runs_revision_check" CHECK ("tenant_ldap_sync_runs"."provider_version" > 0
        and "tenant_ldap_sync_runs"."configuration_version" > 0
        and "tenant_ldap_sync_runs"."binding_version" > 0
        and "tenant_ldap_sync_runs"."binding_auth_revision" > 0
        and "tenant_ldap_sync_runs"."rule_set_revision" > 0
        and "tenant_ldap_sync_runs"."authorization_revision" > 0
        and "tenant_ldap_sync_runs"."version" between 1 and 5),
	CONSTRAINT "tenant_ldap_sync_runs_digest_check" CHECK (octet_length("tenant_ldap_sync_runs"."endpoint_snapshot_digest") = 32
        and ("tenant_ldap_sync_runs"."cursor_digest" is null or octet_length("tenant_ldap_sync_runs"."cursor_digest") = 32)),
	CONSTRAINT "tenant_ldap_sync_runs_actor_check" CHECK (("tenant_ldap_sync_runs"."trigger" = 'scheduled' and "tenant_ldap_sync_runs"."started_by_membership_id" is null)
        or ("tenant_ldap_sync_runs"."trigger" = 'manual' and "tenant_ldap_sync_runs"."started_by_membership_id" is not null)),
	CONSTRAINT "tenant_ldap_sync_runs_reason_check" CHECK (btrim("tenant_ldap_sync_runs"."reason") <> '' and char_length("tenant_ldap_sync_runs"."reason") <= 500
        and "tenant_ldap_sync_runs"."reason" !~ '[[:cntrl:]]'),
	CONSTRAINT "tenant_ldap_sync_runs_counts_check" CHECK ("tenant_ldap_sync_runs"."observed_count" between 0 and 5000
        and "tenant_ldap_sync_runs"."applied_count" between 0 and "tenant_ldap_sync_runs"."observed_count"
        and "tenant_ldap_sync_runs"."revoked_count" between 0 and 5000),
	CONSTRAINT "tenant_ldap_sync_runs_failure_check" CHECK ("tenant_ldap_sync_runs"."failure_category" is null or (
        btrim("tenant_ldap_sync_runs"."failure_category") <> ''
        and char_length("tenant_ldap_sync_runs"."failure_category") <= 64
        and "tenant_ldap_sync_runs"."failure_category" ~ '^[a-z][a-z0-9_]{1,63}$'
      )),
	CONSTRAINT "tenant_ldap_sync_runs_lifecycle_check" CHECK ((
          "tenant_ldap_sync_runs"."status" = 'queued'
          and "tenant_ldap_sync_runs"."enumeration_complete" is null
          and "tenant_ldap_sync_runs"."result_truncated" is null
          and "tenant_ldap_sync_runs"."enumeration_started_at" is null
          and "tenant_ldap_sync_runs"."enumeration_completed_at" is null
          and "tenant_ldap_sync_runs"."completed_at" is null
          and "tenant_ldap_sync_runs"."failure_category" is null
          and "tenant_ldap_sync_runs"."version" = 1
        ) or (
          "tenant_ldap_sync_runs"."status" = 'enumerating'
          and "tenant_ldap_sync_runs"."enumeration_complete" is null
          and "tenant_ldap_sync_runs"."result_truncated" is null
          and "tenant_ldap_sync_runs"."enumeration_started_at" >= "tenant_ldap_sync_runs"."queued_at"
          and "tenant_ldap_sync_runs"."enumeration_completed_at" is null
          and "tenant_ldap_sync_runs"."completed_at" is null
          and "tenant_ldap_sync_runs"."failure_category" is null
          and "tenant_ldap_sync_runs"."version" = 2
        ) or (
          "tenant_ldap_sync_runs"."status" = 'applying'
          and "tenant_ldap_sync_runs"."enumeration_complete" is true
          and "tenant_ldap_sync_runs"."result_truncated" is false
          and "tenant_ldap_sync_runs"."enumeration_started_at" >= "tenant_ldap_sync_runs"."queued_at"
          and "tenant_ldap_sync_runs"."enumeration_completed_at" >= "tenant_ldap_sync_runs"."enumeration_started_at"
          and "tenant_ldap_sync_runs"."completed_at" is null
          and "tenant_ldap_sync_runs"."failure_category" is null
          and "tenant_ldap_sync_runs"."version" = 3
        ) or (
          "tenant_ldap_sync_runs"."status" = 'succeeded'
          and "tenant_ldap_sync_runs"."enumeration_complete" is true
          and "tenant_ldap_sync_runs"."result_truncated" is false
          and "tenant_ldap_sync_runs"."enumeration_completed_at" >= "tenant_ldap_sync_runs"."enumeration_started_at"
          and "tenant_ldap_sync_runs"."completed_at" >= "tenant_ldap_sync_runs"."enumeration_completed_at"
          and "tenant_ldap_sync_runs"."failure_category" is null
          and "tenant_ldap_sync_runs"."applied_count" = "tenant_ldap_sync_runs"."observed_count"
          and "tenant_ldap_sync_runs"."version" = 4
        ) or (
          "tenant_ldap_sync_runs"."status" in ('failed', 'cancelled', 'stale')
          and "tenant_ldap_sync_runs"."completed_at" >= coalesce("tenant_ldap_sync_runs"."enumeration_started_at", "tenant_ldap_sync_runs"."queued_at")
          and "tenant_ldap_sync_runs"."failure_category" is not null
          and "tenant_ldap_sync_runs"."version" between 2 and 5
        ))
);
--> statement-breakpoint
ALTER TABLE "tenant_ldap_sync_runs" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_ldap_sync_staged_observations" (
	"id" uuid NOT NULL,
	"tenant_id" uuid NOT NULL,
	"sync_run_id" uuid NOT NULL,
	"provider_id" uuid NOT NULL,
	"ordinal" integer NOT NULL,
	"digest_key_version" integer NOT NULL,
	"subject_digest" "bytea" NOT NULL,
	"observation_digest" "bytea" NOT NULL,
	"external_identity_id" uuid,
	"staged_at" timestamp with time zone DEFAULT now() NOT NULL,
	"applied_at" timestamp with time zone,
	"apply_attempt" integer DEFAULT 0 NOT NULL,
	CONSTRAINT "tenant_ldap_sync_staged_observations_pkey" PRIMARY KEY("tenant_id","sync_run_id","id"),
	CONSTRAINT "tenant_ldap_sync_staged_observations_ordinal_key" UNIQUE("tenant_id","sync_run_id","ordinal"),
	CONSTRAINT "tenant_ldap_sync_staged_observations_subject_key" UNIQUE("tenant_id","sync_run_id","digest_key_version","subject_digest"),
	CONSTRAINT "tenant_ldap_sync_staged_observations_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_ldap_sync_staged_observations"."id") = 7) is true),
	CONSTRAINT "tenant_ldap_sync_staged_observations_bounds_check" CHECK ("tenant_ldap_sync_staged_observations"."ordinal" between 1 and 5000
        and "tenant_ldap_sync_staged_observations"."digest_key_version" between 1 and 32767
        and octet_length("tenant_ldap_sync_staged_observations"."subject_digest") = 32
        and octet_length("tenant_ldap_sync_staged_observations"."observation_digest") = 32
        and "tenant_ldap_sync_staged_observations"."apply_attempt" between 0 and 10
        and ("tenant_ldap_sync_staged_observations"."applied_at" is null or "tenant_ldap_sync_staged_observations"."applied_at" >= "tenant_ldap_sync_staged_observations"."staged_at"))
);
--> statement-breakpoint
ALTER TABLE "tenant_ldap_sync_staged_observations" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "tenant_ldap_provider_access_grants" ADD COLUMN "owns_membership" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "tenant_ldap_identity_plan_applications" ADD CONSTRAINT "tenant_ldap_identity_plan_applications_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_ldap_identity_plan_applications" ADD CONSTRAINT "tenant_ldap_identity_plan_applications_binding_fk" FOREIGN KEY ("tenant_id","binding_id","provider_id") REFERENCES "public"."tenant_auth_provider_bindings"("tenant_id","id","provider_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_identity_plan_applications" ADD CONSTRAINT "tenant_ldap_identity_plan_applications_access_epoch_fk" FOREIGN KEY ("tenant_id","binding_access_epoch_id","binding_id","provider_id") REFERENCES "public"."tenant_identity_provider_access_epochs"("tenant_id","id","binding_id","provider_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_identity_plan_applications" ADD CONSTRAINT "tenant_ldap_identity_plan_applications_sync_observation_fk" FOREIGN KEY ("tenant_id","sync_run_id","sync_observation_id") REFERENCES "public"."tenant_ldap_sync_staged_observations"("tenant_id","sync_run_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_identity_plan_applications" ADD CONSTRAINT "tenant_ldap_identity_plan_applications_identity_fk" FOREIGN KEY ("tenant_id","provider_id","external_identity_id","user_id") REFERENCES "public"."tenant_ldap_external_identities"("tenant_id","provider_id","id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_identity_plan_applications" ADD CONSTRAINT "tenant_ldap_identity_plan_applications_membership_fk" FOREIGN KEY ("tenant_id","membership_id","user_id") REFERENCES "public"."tenant_memberships"("tenant_id","id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_identity_plan_applications" ADD CONSTRAINT "tenant_ldap_identity_plan_applications_access_grant_fk" FOREIGN KEY ("tenant_id","access_grant_id") REFERENCES "public"."tenant_ldap_provider_access_grants"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_sync_absences" ADD CONSTRAINT "tenant_ldap_sync_absences_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_ldap_sync_absences" ADD CONSTRAINT "tenant_ldap_sync_absences_binding_fk" FOREIGN KEY ("tenant_id","binding_id") REFERENCES "public"."tenant_auth_provider_bindings"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_sync_absences" ADD CONSTRAINT "tenant_ldap_sync_absences_identity_fk" FOREIGN KEY ("tenant_id","external_identity_id") REFERENCES "public"."tenant_ldap_external_identities"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_sync_absences" ADD CONSTRAINT "tenant_ldap_sync_absences_membership_fk" FOREIGN KEY ("tenant_id","membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_sync_absences" ADD CONSTRAINT "tenant_ldap_sync_absences_first_run_fk" FOREIGN KEY ("tenant_id","first_missing_run_id","binding_id") REFERENCES "public"."tenant_ldap_sync_runs"("tenant_id","id","binding_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_sync_absences" ADD CONSTRAINT "tenant_ldap_sync_absences_latest_run_fk" FOREIGN KEY ("tenant_id","latest_missing_run_id","binding_id") REFERENCES "public"."tenant_ldap_sync_runs"("tenant_id","id","binding_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_sync_run_mappings" ADD CONSTRAINT "tenant_ldap_sync_run_mappings_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_ldap_sync_run_mappings" ADD CONSTRAINT "tenant_ldap_sync_run_mappings_run_fk" FOREIGN KEY ("tenant_id","sync_run_id","binding_id") REFERENCES "public"."tenant_ldap_sync_runs"("tenant_id","id","binding_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_sync_run_mappings" ADD CONSTRAINT "tenant_ldap_sync_run_mappings_rule_fk" FOREIGN KEY ("tenant_id","mapping_rule_id","binding_id") REFERENCES "public"."tenant_ldap_mapping_rules"("tenant_id","id","binding_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_sync_run_mappings" ADD CONSTRAINT "tenant_ldap_sync_run_mappings_epoch_fk" FOREIGN KEY ("tenant_id","source_epoch_id","mapping_rule_id","binding_id","source_id") REFERENCES "public"."tenant_ldap_mapping_rule_epochs"("tenant_id","id","mapping_rule_id","binding_id","source_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_sync_runs" ADD CONSTRAINT "tenant_ldap_sync_runs_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_ldap_sync_runs" ADD CONSTRAINT "tenant_ldap_sync_runs_provider_fk" FOREIGN KEY ("tenant_id","provider_id","provider_kind") REFERENCES "public"."tenant_auth_providers"("tenant_id","id","kind") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_sync_runs" ADD CONSTRAINT "tenant_ldap_sync_runs_binding_fk" FOREIGN KEY ("tenant_id","binding_id","provider_id") REFERENCES "public"."tenant_auth_provider_bindings"("tenant_id","id","provider_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_sync_runs" ADD CONSTRAINT "tenant_ldap_sync_runs_access_epoch_fk" FOREIGN KEY ("tenant_id","binding_access_epoch_id","binding_id","provider_id") REFERENCES "public"."tenant_identity_provider_access_epochs"("tenant_id","id","binding_id","provider_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_sync_runs" ADD CONSTRAINT "tenant_ldap_sync_runs_starter_fk" FOREIGN KEY ("tenant_id","started_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_sync_staged_observations" ADD CONSTRAINT "tenant_ldap_sync_staged_observations_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_ldap_sync_staged_observations" ADD CONSTRAINT "tenant_ldap_sync_staged_observations_run_fk" FOREIGN KEY ("tenant_id","sync_run_id") REFERENCES "public"."tenant_ldap_sync_runs"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_sync_staged_observations" ADD CONSTRAINT "tenant_ldap_sync_staged_observations_identity_fk" FOREIGN KEY ("tenant_id","provider_id","external_identity_id") REFERENCES "public"."tenant_ldap_external_identities"("tenant_id","provider_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
CREATE INDEX "tenant_ldap_identity_plan_applications_binding_idx" ON "tenant_ldap_identity_plan_applications" USING btree ("tenant_id","binding_id","applied_at","id");--> statement-breakpoint
CREATE INDEX "tenant_ldap_identity_plan_applications_identity_idx" ON "tenant_ldap_identity_plan_applications" USING btree ("tenant_id","external_identity_id","applied_at","id");--> statement-breakpoint
CREATE INDEX "tenant_ldap_sync_absences_due_idx" ON "tenant_ldap_sync_absences" USING btree ("tenant_id","status","apply_after","binding_id");--> statement-breakpoint
CREATE INDEX "tenant_ldap_sync_run_mappings_order_idx" ON "tenant_ldap_sync_run_mappings" USING btree ("tenant_id","sync_run_id","priority","mapping_rule_id");--> statement-breakpoint
CREATE UNIQUE INDEX "tenant_ldap_sync_runs_live_binding_key" ON "tenant_ldap_sync_runs" USING btree ("tenant_id","binding_id") WHERE "tenant_ldap_sync_runs"."status" in ('queued', 'enumerating', 'applying');--> statement-breakpoint
CREATE INDEX "tenant_ldap_sync_runs_binding_queued_idx" ON "tenant_ldap_sync_runs" USING btree ("tenant_id","binding_id","queued_at","id");--> statement-breakpoint
CREATE INDEX "tenant_ldap_sync_runs_status_queued_idx" ON "tenant_ldap_sync_runs" USING btree ("tenant_id","status","queued_at","id");--> statement-breakpoint
CREATE INDEX "tenant_ldap_sync_staged_observations_apply_idx" ON "tenant_ldap_sync_staged_observations" USING btree ("tenant_id","sync_run_id","applied_at","ordinal");