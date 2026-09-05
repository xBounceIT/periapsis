CREATE TYPE "public"."ldap_provider_test_category" AS ENUM('success', 'dns_failed', 'destination_blocked', 'connect_timeout', 'connect_failed', 'tls_failed', 'certificate_rejected', 'bind_rejected', 'protocol_failed', 'cancelled', 'stale_configuration');--> statement-breakpoint
CREATE TYPE "public"."ldap_provider_test_kind" AS ENUM('connection', 'bind');--> statement-breakpoint
CREATE TYPE "public"."ldap_provider_test_outcome" AS ENUM('success', 'failure', 'inconclusive');--> statement-breakpoint
CREATE TYPE "public"."ldap_provider_test_status" AS ENUM('started', 'completed');--> statement-breakpoint
CREATE TABLE "tenant_ldap_provider_test_runs" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"provider_id" uuid NOT NULL,
	"provider_kind" "auth_provider_kind" DEFAULT 'ldap' NOT NULL,
	"test_kind" "ldap_provider_test_kind" NOT NULL,
	"status" "ldap_provider_test_status" DEFAULT 'started' NOT NULL,
	"outcome" "ldap_provider_test_outcome",
	"category" "ldap_provider_test_category",
	"endpoint_priority" integer,
	"duration_ms" integer,
	"provider_version" integer NOT NULL,
	"configuration_version" integer NOT NULL,
	"secret_version" integer,
	"started_by_membership_id" uuid NOT NULL,
	"completed_by_membership_id" uuid,
	"request_id" uuid NOT NULL,
	"correlation_id" uuid NOT NULL,
	"started_at" timestamp with time zone DEFAULT now() NOT NULL,
	"completed_at" timestamp with time zone,
	"version" integer DEFAULT 1 NOT NULL,
	CONSTRAINT "tenant_ldap_provider_test_runs_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_ldap_provider_test_runs"."id") = 7) is true),
	CONSTRAINT "tenant_ldap_provider_test_runs_kind_check" CHECK ("tenant_ldap_provider_test_runs"."provider_kind" = 'ldap'),
	CONSTRAINT "tenant_ldap_provider_test_runs_revision_check" CHECK ("tenant_ldap_provider_test_runs"."provider_version" > 0
        and "tenant_ldap_provider_test_runs"."configuration_version" > 0
        and ("tenant_ldap_provider_test_runs"."secret_version" is null or "tenant_ldap_provider_test_runs"."secret_version" > 0)),
	CONSTRAINT "tenant_ldap_provider_test_runs_secret_check" CHECK ((("tenant_ldap_provider_test_runs"."test_kind" = 'connection' and "tenant_ldap_provider_test_runs"."secret_version" is null)
        or ("tenant_ldap_provider_test_runs"."test_kind" = 'bind' and "tenant_ldap_provider_test_runs"."secret_version" is not null)) is true),
	CONSTRAINT "tenant_ldap_provider_test_runs_result_bounds_check" CHECK (("tenant_ldap_provider_test_runs"."endpoint_priority" is null or "tenant_ldap_provider_test_runs"."endpoint_priority" between 1 and 8)
        and ("tenant_ldap_provider_test_runs"."duration_ms" is null or "tenant_ldap_provider_test_runs"."duration_ms" between 0 and 120000)),
	CONSTRAINT "tenant_ldap_provider_test_runs_result_semantics_check" CHECK ((("tenant_ldap_provider_test_runs"."outcome" is null and "tenant_ldap_provider_test_runs"."category" is null)
        or ("tenant_ldap_provider_test_runs"."outcome" = 'success' and "tenant_ldap_provider_test_runs"."category" = 'success')
        or ("tenant_ldap_provider_test_runs"."outcome" = 'inconclusive' and "tenant_ldap_provider_test_runs"."category" = 'stale_configuration')
        or ("tenant_ldap_provider_test_runs"."outcome" = 'failure' and "tenant_ldap_provider_test_runs"."category" not in ('success', 'stale_configuration'))) is true),
	CONSTRAINT "tenant_ldap_provider_test_runs_lifecycle_check" CHECK ((("tenant_ldap_provider_test_runs"."status" = 'started'
          and "tenant_ldap_provider_test_runs"."outcome" is null
          and "tenant_ldap_provider_test_runs"."category" is null
          and "tenant_ldap_provider_test_runs"."endpoint_priority" is null
          and "tenant_ldap_provider_test_runs"."duration_ms" is null
          and "tenant_ldap_provider_test_runs"."completed_by_membership_id" is null
          and "tenant_ldap_provider_test_runs"."completed_at" is null
          and "tenant_ldap_provider_test_runs"."version" = 1)
        or ("tenant_ldap_provider_test_runs"."status" = 'completed'
          and "tenant_ldap_provider_test_runs"."outcome" is not null
          and "tenant_ldap_provider_test_runs"."category" is not null
          and "tenant_ldap_provider_test_runs"."duration_ms" is not null
          and "tenant_ldap_provider_test_runs"."completed_by_membership_id" is not null
          and "tenant_ldap_provider_test_runs"."completed_at" >= "tenant_ldap_provider_test_runs"."started_at"
          and "tenant_ldap_provider_test_runs"."version" = 2)) is true)
);
--> statement-breakpoint
ALTER TABLE "tenant_ldap_provider_test_runs" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "tenant_ldap_provider_test_runs" ADD CONSTRAINT "tenant_ldap_provider_test_runs_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_ldap_provider_test_runs" ADD CONSTRAINT "tenant_ldap_provider_test_runs_provider_fk" FOREIGN KEY ("tenant_id","provider_id","provider_kind") REFERENCES "public"."tenant_auth_providers"("tenant_id","id","kind") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_provider_test_runs" ADD CONSTRAINT "tenant_ldap_provider_test_runs_starter_fk" FOREIGN KEY ("tenant_id","started_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_provider_test_runs" ADD CONSTRAINT "tenant_ldap_provider_test_runs_completer_fk" FOREIGN KEY ("tenant_id","completed_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
CREATE INDEX "tenant_ldap_provider_test_runs_provider_started_idx" ON "tenant_ldap_provider_test_runs" USING btree ("tenant_id","provider_id","started_at","id");--> statement-breakpoint
CREATE INDEX "tenant_ldap_provider_test_runs_actor_started_idx" ON "tenant_ldap_provider_test_runs" USING btree ("tenant_id","started_by_membership_id","started_at","id");--> statement-breakpoint
CREATE INDEX "tenant_ldap_provider_test_runs_status_started_idx" ON "tenant_ldap_provider_test_runs" USING btree ("tenant_id","status","started_at","id");