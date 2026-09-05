CREATE TYPE "public"."ldap_jit_run_status" AS ENUM('network_pending', 'planning', 'succeeded', 'denied', 'failed', 'stale', 'expired');--> statement-breakpoint
ALTER TYPE "public"."auth_rate_limit_scope" ADD VALUE 'ldap_network' BEFORE 'mfa_challenge';--> statement-breakpoint
ALTER TYPE "public"."auth_rate_limit_scope" ADD VALUE 'ldap_account' BEFORE 'mfa_challenge';--> statement-breakpoint
ALTER TYPE "public"."auth_rate_limit_scope" ADD VALUE 'ldap_provider' BEFORE 'mfa_challenge';--> statement-breakpoint
CREATE TABLE "tenant_ldap_jit_authentication_runs" (
	"id" uuid PRIMARY KEY NOT NULL,
	"tenant_id" uuid NOT NULL,
	"receipt_digest" "bytea" NOT NULL,
	"provider_id" uuid NOT NULL,
	"provider_kind" "auth_provider_kind" DEFAULT 'ldap' NOT NULL,
	"binding_id" uuid NOT NULL,
	"provider_version" integer NOT NULL,
	"configuration_version" integer NOT NULL,
	"bind_secret_id" uuid NOT NULL,
	"bind_secret_version" integer NOT NULL,
	"bind_secret_key_version" integer NOT NULL,
	"bind_secret_algorithm" text NOT NULL,
	"endpoint_snapshot_digest" "bytea" NOT NULL,
	"binding_version" integer NOT NULL,
	"binding_auth_revision" integer NOT NULL,
	"binding_access_epoch_id" uuid NOT NULL,
	"rule_set_revision" bigint NOT NULL,
	"authorization_revision" bigint NOT NULL,
	"network_rate_key_digest" "bytea" NOT NULL,
	"account_rate_key_digest" "bytea" NOT NULL,
	"provider_rate_key_digest" "bytea" NOT NULL,
	"status" "ldap_jit_run_status" DEFAULT 'network_pending' NOT NULL,
	"terminal_category" text,
	"application_id" uuid,
	"plan_digest" "bytea",
	"begin_audit_event_id" uuid NOT NULL,
	"terminal_audit_event_id" uuid,
	"request_id" uuid NOT NULL,
	"correlation_id" uuid NOT NULL,
	"started_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"claimed_at" timestamp with time zone,
	"completed_at" timestamp with time zone,
	"version" integer DEFAULT 1 NOT NULL,
	CONSTRAINT "tenant_ldap_jit_runs_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "tenant_ldap_jit_runs_exact_binding_key" UNIQUE("tenant_id","id","binding_id"),
	CONSTRAINT "tenant_ldap_jit_runs_receipt_key" UNIQUE("receipt_digest"),
	CONSTRAINT "tenant_ldap_jit_runs_begin_audit_key" UNIQUE("tenant_id","begin_audit_event_id"),
	CONSTRAINT "tenant_ldap_jit_runs_terminal_audit_key" UNIQUE("tenant_id","terminal_audit_event_id"),
	CONSTRAINT "tenant_ldap_jit_runs_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_ldap_jit_authentication_runs"."id") = 7) is true),
	CONSTRAINT "tenant_ldap_jit_runs_kind_check" CHECK ("tenant_ldap_jit_authentication_runs"."provider_kind" = 'ldap'),
	CONSTRAINT "tenant_ldap_jit_runs_revision_check" CHECK ("tenant_ldap_jit_authentication_runs"."provider_version" > 0
        and "tenant_ldap_jit_authentication_runs"."configuration_version" > 0
        and "tenant_ldap_jit_authentication_runs"."bind_secret_version" > 0
        and "tenant_ldap_jit_authentication_runs"."bind_secret_key_version" > 0
        and "tenant_ldap_jit_authentication_runs"."binding_version" > 0
        and "tenant_ldap_jit_authentication_runs"."binding_auth_revision" > 0
        and "tenant_ldap_jit_authentication_runs"."rule_set_revision" > 0
        and "tenant_ldap_jit_authentication_runs"."authorization_revision" > 0
        and "tenant_ldap_jit_authentication_runs"."version" between 1 and 3),
	CONSTRAINT "tenant_ldap_jit_runs_digest_check" CHECK (octet_length("tenant_ldap_jit_authentication_runs"."receipt_digest") = 32
        and octet_length("tenant_ldap_jit_authentication_runs"."endpoint_snapshot_digest") = 32
        and octet_length("tenant_ldap_jit_authentication_runs"."network_rate_key_digest") = 32
        and octet_length("tenant_ldap_jit_authentication_runs"."account_rate_key_digest") = 32
        and octet_length("tenant_ldap_jit_authentication_runs"."provider_rate_key_digest") = 32
        and ("tenant_ldap_jit_authentication_runs"."plan_digest" is null or octet_length("tenant_ldap_jit_authentication_runs"."plan_digest") = 32)),
	CONSTRAINT "tenant_ldap_jit_runs_secret_check" CHECK ((uuid_extract_version("tenant_ldap_jit_authentication_runs"."bind_secret_id") = 7) is true
        and "tenant_ldap_jit_authentication_runs"."bind_secret_algorithm" = 'aes-256-gcm'),
	CONSTRAINT "tenant_ldap_jit_runs_lifetime_check" CHECK ("tenant_ldap_jit_authentication_runs"."expires_at" > "tenant_ldap_jit_authentication_runs"."started_at"
        and "tenant_ldap_jit_authentication_runs"."expires_at" <= "tenant_ldap_jit_authentication_runs"."started_at" + interval '2 minutes'),
	CONSTRAINT "tenant_ldap_jit_runs_terminal_category_check" CHECK ("tenant_ldap_jit_authentication_runs"."terminal_category" is null or (
        char_length("tenant_ldap_jit_authentication_runs"."terminal_category") between 2 and 64
        and "tenant_ldap_jit_authentication_runs"."terminal_category" ~ '^[a-z][a-z0-9_]{1,63}$'
      )),
	CONSTRAINT "tenant_ldap_jit_runs_lifecycle_check" CHECK ((
          "tenant_ldap_jit_authentication_runs"."status" = 'network_pending'
          and "tenant_ldap_jit_authentication_runs"."terminal_category" is null
          and "tenant_ldap_jit_authentication_runs"."application_id" is null and "tenant_ldap_jit_authentication_runs"."plan_digest" is null
          and "tenant_ldap_jit_authentication_runs"."terminal_audit_event_id" is null
          and "tenant_ldap_jit_authentication_runs"."claimed_at" is null and "tenant_ldap_jit_authentication_runs"."completed_at" is null
          and "tenant_ldap_jit_authentication_runs"."version" = 1
        ) or (
          "tenant_ldap_jit_authentication_runs"."status" = 'planning'
          and "tenant_ldap_jit_authentication_runs"."terminal_category" is null
          and "tenant_ldap_jit_authentication_runs"."application_id" is null and "tenant_ldap_jit_authentication_runs"."plan_digest" is null
          and "tenant_ldap_jit_authentication_runs"."terminal_audit_event_id" is null
          and "tenant_ldap_jit_authentication_runs"."claimed_at" >= "tenant_ldap_jit_authentication_runs"."started_at"
          and "tenant_ldap_jit_authentication_runs"."completed_at" is null and "tenant_ldap_jit_authentication_runs"."version" = 2
        ) or (
          "tenant_ldap_jit_authentication_runs"."status" in ('succeeded', 'denied')
          and "tenant_ldap_jit_authentication_runs"."terminal_category" is null
          and "tenant_ldap_jit_authentication_runs"."application_id" is not null and "tenant_ldap_jit_authentication_runs"."plan_digest" is not null
          and "tenant_ldap_jit_authentication_runs"."terminal_audit_event_id" is not null
          and "tenant_ldap_jit_authentication_runs"."claimed_at" >= "tenant_ldap_jit_authentication_runs"."started_at"
          and "tenant_ldap_jit_authentication_runs"."completed_at" >= "tenant_ldap_jit_authentication_runs"."claimed_at"
          and "tenant_ldap_jit_authentication_runs"."version" = 3
        ) or (
          "tenant_ldap_jit_authentication_runs"."status" in ('failed', 'stale', 'expired')
          and "tenant_ldap_jit_authentication_runs"."terminal_category" is not null
          and "tenant_ldap_jit_authentication_runs"."application_id" is null and "tenant_ldap_jit_authentication_runs"."plan_digest" is null
          and "tenant_ldap_jit_authentication_runs"."terminal_audit_event_id" is not null
          and "tenant_ldap_jit_authentication_runs"."completed_at" >= coalesce("tenant_ldap_jit_authentication_runs"."claimed_at", "tenant_ldap_jit_authentication_runs"."started_at")
          and (("tenant_ldap_jit_authentication_runs"."version" = 2 and "tenant_ldap_jit_authentication_runs"."claimed_at" is null)
            or ("tenant_ldap_jit_authentication_runs"."version" = 3 and "tenant_ldap_jit_authentication_runs"."claimed_at" is not null))
        ))
);
--> statement-breakpoint
ALTER TABLE "tenant_ldap_jit_authentication_runs" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_ldap_jit_run_mappings" (
	"tenant_id" uuid NOT NULL,
	"jit_run_id" uuid NOT NULL,
	"binding_id" uuid NOT NULL,
	"mapping_rule_id" uuid NOT NULL,
	"mapping_version" integer NOT NULL,
	"configuration_revision" integer NOT NULL,
	"source_epoch_id" uuid NOT NULL,
	"source_id" uuid NOT NULL,
	"priority" integer NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_ldap_jit_run_mappings_pkey" PRIMARY KEY("tenant_id","jit_run_id","mapping_rule_id"),
	CONSTRAINT "tenant_ldap_jit_run_mappings_epoch_key" UNIQUE("tenant_id","jit_run_id","source_epoch_id"),
	CONSTRAINT "tenant_ldap_jit_run_mappings_revision_check" CHECK ("tenant_ldap_jit_run_mappings"."mapping_version" > 0 and "tenant_ldap_jit_run_mappings"."configuration_revision" > 0
        and "tenant_ldap_jit_run_mappings"."priority" between 0 and 1000000)
);
--> statement-breakpoint
ALTER TABLE "tenant_ldap_jit_run_mappings" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "tenant_ldap_jit_authentication_runs" ADD CONSTRAINT "tenant_ldap_jit_authentication_runs_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_ldap_jit_authentication_runs" ADD CONSTRAINT "tenant_ldap_jit_authentication_runs_bind_secret_key_version_identity_keyring_versions_key_version_fk" FOREIGN KEY ("bind_secret_key_version") REFERENCES "public"."identity_keyring_versions"("key_version") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_ldap_jit_authentication_runs" ADD CONSTRAINT "tenant_ldap_jit_runs_provider_fk" FOREIGN KEY ("tenant_id","provider_id","provider_kind") REFERENCES "public"."tenant_auth_providers"("tenant_id","id","kind") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_jit_authentication_runs" ADD CONSTRAINT "tenant_ldap_jit_runs_binding_fk" FOREIGN KEY ("tenant_id","binding_id","provider_id") REFERENCES "public"."tenant_auth_provider_bindings"("tenant_id","id","provider_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_jit_authentication_runs" ADD CONSTRAINT "tenant_ldap_jit_runs_secret_id_fk" FOREIGN KEY ("tenant_id","bind_secret_id") REFERENCES "public"."tenant_ldap_provider_secrets"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_jit_authentication_runs" ADD CONSTRAINT "tenant_ldap_jit_runs_secret_provider_fk" FOREIGN KEY ("tenant_id","provider_id") REFERENCES "public"."tenant_ldap_provider_secrets"("tenant_id","provider_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_jit_authentication_runs" ADD CONSTRAINT "tenant_ldap_jit_runs_access_epoch_fk" FOREIGN KEY ("tenant_id","binding_access_epoch_id","binding_id","provider_id") REFERENCES "public"."tenant_identity_provider_access_epochs"("tenant_id","id","binding_id","provider_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_jit_authentication_runs" ADD CONSTRAINT "tenant_ldap_jit_runs_application_fk" FOREIGN KEY ("tenant_id","application_id") REFERENCES "public"."tenant_ldap_identity_plan_applications"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_jit_run_mappings" ADD CONSTRAINT "tenant_ldap_jit_run_mappings_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_ldap_jit_run_mappings" ADD CONSTRAINT "tenant_ldap_jit_run_mappings_run_fk" FOREIGN KEY ("tenant_id","jit_run_id","binding_id") REFERENCES "public"."tenant_ldap_jit_authentication_runs"("tenant_id","id","binding_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_jit_run_mappings" ADD CONSTRAINT "tenant_ldap_jit_run_mappings_rule_fk" FOREIGN KEY ("tenant_id","mapping_rule_id","binding_id") REFERENCES "public"."tenant_ldap_mapping_rules"("tenant_id","id","binding_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_jit_run_mappings" ADD CONSTRAINT "tenant_ldap_jit_run_mappings_epoch_fk" FOREIGN KEY ("tenant_id","source_epoch_id","mapping_rule_id","binding_id","source_id") REFERENCES "public"."tenant_ldap_mapping_rule_epochs"("tenant_id","id","mapping_rule_id","binding_id","source_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
CREATE INDEX "tenant_ldap_jit_runs_expiry_idx" ON "tenant_ldap_jit_authentication_runs" USING btree ("status","expires_at","id");--> statement-breakpoint
CREATE INDEX "tenant_ldap_jit_runs_binding_started_idx" ON "tenant_ldap_jit_authentication_runs" USING btree ("tenant_id","binding_id","started_at","id");--> statement-breakpoint
CREATE INDEX "tenant_ldap_jit_run_mappings_order_idx" ON "tenant_ldap_jit_run_mappings" USING btree ("tenant_id","jit_run_id","priority","mapping_rule_id");