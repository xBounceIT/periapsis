CREATE TABLE "alert_activities" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"alert_id" uuid NOT NULL,
	"sequence" integer NOT NULL,
	"activity_type" text NOT NULL,
	"actor_principal_kind" "tenant_principal_kind" NOT NULL,
	"actor_membership_id" uuid,
	"actor_service_account_id" uuid,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"occurred_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "alert_activities_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "alert_activities_alert_sequence_key" UNIQUE("tenant_id","alert_id","sequence"),
	CONSTRAINT "alert_activities_id_uuidv7_check" CHECK ((uuid_extract_version("alert_activities"."id") = 7) is true),
	CONSTRAINT "alert_activities_sequence_check" CHECK ("alert_activities"."sequence" > 0),
	CONSTRAINT "alert_activities_type_check" CHECK ("alert_activities"."activity_type" ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'),
	CONSTRAINT "alert_activities_actor_check" CHECK (("alert_activities"."actor_principal_kind" = 'human'
          and "alert_activities"."actor_membership_id" is not null
          and "alert_activities"."actor_service_account_id" is null)
        or ("alert_activities"."actor_principal_kind" = 'service_account'
          and "alert_activities"."actor_membership_id" is null
          and "alert_activities"."actor_service_account_id" is not null)),
	CONSTRAINT "alert_activities_metadata_object_check" CHECK (jsonb_typeof("alert_activities"."metadata") = 'object')
);
--> statement-breakpoint
ALTER TABLE "alert_activities" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "alert_commands" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"operation" text NOT NULL,
	"principal_kind" "tenant_principal_kind" NOT NULL,
	"actor_membership_id" uuid,
	"actor_service_account_id" uuid,
	"key_digest" "bytea" NOT NULL,
	"request_digest" "bytea" NOT NULL,
	"result_alert_id" uuid NOT NULL,
	"result_version" integer NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "alert_commands_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "alert_commands_id_uuidv7_check" CHECK ((uuid_extract_version("alert_commands"."id") = 7) is true),
	CONSTRAINT "alert_commands_operation_check" CHECK ("alert_commands"."operation" = 'alert.create'),
	CONSTRAINT "alert_commands_actor_check" CHECK (("alert_commands"."principal_kind" = 'human'
          and "alert_commands"."actor_membership_id" is not null
          and "alert_commands"."actor_service_account_id" is null)
        or ("alert_commands"."principal_kind" = 'service_account'
          and "alert_commands"."actor_membership_id" is null
          and "alert_commands"."actor_service_account_id" is not null)),
	CONSTRAINT "alert_commands_digest_check" CHECK (octet_length("alert_commands"."key_digest") = 32 and octet_length("alert_commands"."request_digest") = 32),
	CONSTRAINT "alert_commands_result_version_check" CHECK ("alert_commands"."result_version" > 0)
);
--> statement-breakpoint
ALTER TABLE "alert_commands" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_api_credential_commands" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"service_account_id" uuid NOT NULL,
	"actor_membership_id" uuid NOT NULL,
	"operation" text NOT NULL,
	"key_digest" "bytea" NOT NULL,
	"request_digest" "bytea" NOT NULL,
	"result_credential_id" uuid NOT NULL,
	"result_version" integer NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_api_credential_commands_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "tenant_api_credential_commands_replay_key" UNIQUE("tenant_id","actor_membership_id","service_account_id","operation","key_digest"),
	CONSTRAINT "tenant_api_credential_commands_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_api_credential_commands"."id") = 7) is true),
	CONSTRAINT "tenant_api_credential_commands_operation_check" CHECK ("tenant_api_credential_commands"."operation" in ('service_account.credential.issue', 'service_account.credential.rotate')),
	CONSTRAINT "tenant_api_credential_commands_digest_check" CHECK (octet_length("tenant_api_credential_commands"."key_digest") = 32 and octet_length("tenant_api_credential_commands"."request_digest") = 32),
	CONSTRAINT "tenant_api_credential_commands_result_version_check" CHECK ("tenant_api_credential_commands"."result_version" > 0)
);
--> statement-breakpoint
ALTER TABLE "tenant_api_credential_commands" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_api_credential_networks" (
	"tenant_id" uuid NOT NULL,
	"credential_id" uuid NOT NULL,
	"network" "cidr" NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_api_credential_networks_pkey" PRIMARY KEY("tenant_id","credential_id","network")
);
--> statement-breakpoint
ALTER TABLE "tenant_api_credential_networks" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_api_credential_permissions" (
	"tenant_id" uuid NOT NULL,
	"credential_id" uuid NOT NULL,
	"permission_id" uuid NOT NULL,
	"permission_service_account_allowed" boolean DEFAULT true NOT NULL,
	"scope" "authorization_scope" NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_api_credential_permissions_pkey" PRIMARY KEY("tenant_id","credential_id","permission_id","scope"),
	CONSTRAINT "tenant_api_credential_permissions_allowed_check" CHECK ("tenant_api_credential_permissions"."permission_service_account_allowed" is true),
	CONSTRAINT "tenant_api_credential_permissions_not_platform_check" CHECK ("tenant_api_credential_permissions"."scope" <> 'platform')
);
--> statement-breakpoint
ALTER TABLE "tenant_api_credential_permissions" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_api_credentials" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"service_account_id" uuid NOT NULL,
	"label" text NOT NULL,
	"format_version" integer DEFAULT 1 NOT NULL,
	"locator" "bytea" NOT NULL,
	"key_version" integer NOT NULL,
	"secret_digest" "bytea" NOT NULL,
	"issued_by_membership_id" uuid NOT NULL,
	"issued_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"rotated_from_credential_id" uuid,
	"revoked_at" timestamp with time zone,
	"revoked_by_membership_id" uuid,
	"revoke_reason" text,
	"last_used_at" timestamp with time zone,
	"last_used_ip" "inet",
	"version" integer DEFAULT 1 NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_api_credentials_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "tenant_api_credentials_account_id_key" UNIQUE("tenant_id","service_account_id","id"),
	CONSTRAINT "tenant_api_credentials_locator_key" UNIQUE("locator"),
	CONSTRAINT "tenant_api_credentials_rotated_from_key" UNIQUE("tenant_id","service_account_id","rotated_from_credential_id"),
	CONSTRAINT "tenant_api_credentials_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_api_credentials"."id") = 7) is true),
	CONSTRAINT "tenant_api_credentials_label_check" CHECK (btrim("tenant_api_credentials"."label") <> '' and char_length("tenant_api_credentials"."label") <= 120 and "tenant_api_credentials"."label" !~ '[[:cntrl:]]'),
	CONSTRAINT "tenant_api_credentials_format_version_check" CHECK ("tenant_api_credentials"."format_version" > 0),
	CONSTRAINT "tenant_api_credentials_key_version_check" CHECK ("tenant_api_credentials"."key_version" > 0),
	CONSTRAINT "tenant_api_credentials_secret_material_check" CHECK (octet_length("tenant_api_credentials"."locator") = 16 and octet_length("tenant_api_credentials"."secret_digest") = 32),
	CONSTRAINT "tenant_api_credentials_expiry_check" CHECK ("tenant_api_credentials"."expires_at" > "tenant_api_credentials"."issued_at" and "tenant_api_credentials"."expires_at" <= "tenant_api_credentials"."issued_at" + interval '90 days'),
	CONSTRAINT "tenant_api_credentials_rotation_check" CHECK ("tenant_api_credentials"."rotated_from_credential_id" is null or "tenant_api_credentials"."rotated_from_credential_id" <> "tenant_api_credentials"."id"),
	CONSTRAINT "tenant_api_credentials_revocation_check" CHECK (("tenant_api_credentials"."revoked_at" is null and "tenant_api_credentials"."revoked_by_membership_id" is null and "tenant_api_credentials"."revoke_reason" is null)
        or ("tenant_api_credentials"."revoked_at" is not null
          and "tenant_api_credentials"."revoked_by_membership_id" is not null
          and "tenant_api_credentials"."revoke_reason" is not null
          and "tenant_api_credentials"."revoked_at" >= "tenant_api_credentials"."issued_at"
          and btrim("tenant_api_credentials"."revoke_reason") <> ''
          and char_length("tenant_api_credentials"."revoke_reason") <= 500
          and "tenant_api_credentials"."revoke_reason" !~ '[[:cntrl:]]')),
	CONSTRAINT "tenant_api_credentials_last_used_check" CHECK (("tenant_api_credentials"."last_used_at" is null and "tenant_api_credentials"."last_used_ip" is null)
        or ("tenant_api_credentials"."last_used_at" is not null and "tenant_api_credentials"."last_used_ip" is not null and "tenant_api_credentials"."last_used_at" >= "tenant_api_credentials"."issued_at")),
	CONSTRAINT "tenant_api_credentials_version_check" CHECK ("tenant_api_credentials"."version" > 0),
	CONSTRAINT "tenant_api_credentials_updated_check" CHECK ("tenant_api_credentials"."updated_at" >= "tenant_api_credentials"."issued_at"
        and ("tenant_api_credentials"."revoked_at" is null or "tenant_api_credentials"."updated_at" >= "tenant_api_credentials"."revoked_at")
        and ("tenant_api_credentials"."last_used_at" is null or "tenant_api_credentials"."updated_at" >= "tenant_api_credentials"."last_used_at"))
);
--> statement-breakpoint
ALTER TABLE "tenant_api_credentials" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_service_account_role_grants" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"service_account_id" uuid NOT NULL,
	"role_id" uuid NOT NULL,
	"role_principal_kind" "tenant_principal_kind" DEFAULT 'service_account' NOT NULL,
	"source_id" uuid NOT NULL,
	"granted_by_membership_id" uuid NOT NULL,
	"grant_reason" text NOT NULL,
	"granted_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone,
	"revoked_at" timestamp with time zone,
	"revoked_by_membership_id" uuid,
	"revoke_reason" text,
	"version" integer DEFAULT 1 NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_service_account_role_grants_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "tenant_service_account_role_grants_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_service_account_role_grants"."id") = 7) is true),
	CONSTRAINT "tenant_service_account_role_grants_role_kind_check" CHECK ("tenant_service_account_role_grants"."role_principal_kind" = 'service_account'),
	CONSTRAINT "tenant_service_account_role_grants_expiry_check" CHECK ("tenant_service_account_role_grants"."expires_at" is null or "tenant_service_account_role_grants"."expires_at" > "tenant_service_account_role_grants"."granted_at"),
	CONSTRAINT "tenant_service_account_role_grants_reason_check" CHECK (btrim("tenant_service_account_role_grants"."grant_reason") <> '' and char_length("tenant_service_account_role_grants"."grant_reason") <= 500 and "tenant_service_account_role_grants"."grant_reason" !~ '[[:cntrl:]]'),
	CONSTRAINT "tenant_service_account_role_grants_revocation_check" CHECK (("tenant_service_account_role_grants"."revoked_at" is null and "tenant_service_account_role_grants"."revoked_by_membership_id" is null and "tenant_service_account_role_grants"."revoke_reason" is null)
        or ("tenant_service_account_role_grants"."revoked_at" is not null
          and "tenant_service_account_role_grants"."revoked_by_membership_id" is not null
          and "tenant_service_account_role_grants"."revoke_reason" is not null
          and "tenant_service_account_role_grants"."revoked_at" >= "tenant_service_account_role_grants"."granted_at"
          and btrim("tenant_service_account_role_grants"."revoke_reason") <> ''
          and char_length("tenant_service_account_role_grants"."revoke_reason") <= 500
          and "tenant_service_account_role_grants"."revoke_reason" !~ '[[:cntrl:]]')),
	CONSTRAINT "tenant_service_account_role_grants_version_check" CHECK ("tenant_service_account_role_grants"."version" > 0),
	CONSTRAINT "tenant_service_account_role_grants_updated_check" CHECK ("tenant_service_account_role_grants"."updated_at" >= "tenant_service_account_role_grants"."granted_at" and ("tenant_service_account_role_grants"."revoked_at" is null or "tenant_service_account_role_grants"."updated_at" >= "tenant_service_account_role_grants"."revoked_at"))
);
--> statement-breakpoint
ALTER TABLE "tenant_service_account_role_grants" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_service_accounts" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"key" text NOT NULL,
	"display_name" text NOT NULL,
	"description" text DEFAULT '' NOT NULL,
	"created_by_membership_id" uuid NOT NULL,
	"archived_at" timestamp with time zone,
	"archived_by_membership_id" uuid,
	"archive_reason" text,
	"version" integer DEFAULT 1 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_service_accounts_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "tenant_service_accounts_tenant_key_key" UNIQUE("tenant_id","key"),
	CONSTRAINT "tenant_service_accounts_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_service_accounts"."id") = 7) is true),
	CONSTRAINT "tenant_service_accounts_key_check" CHECK ("tenant_service_accounts"."key" ~ '^[a-z][a-z0-9_]{2,63}$'),
	CONSTRAINT "tenant_service_accounts_display_name_check" CHECK (btrim("tenant_service_accounts"."display_name") <> '' and char_length("tenant_service_accounts"."display_name") <= 120 and "tenant_service_accounts"."display_name" !~ '[[:cntrl:]]'),
	CONSTRAINT "tenant_service_accounts_description_check" CHECK (char_length("tenant_service_accounts"."description") <= 500 and "tenant_service_accounts"."description" !~ '[[:cntrl:]]'),
	CONSTRAINT "tenant_service_accounts_archive_check" CHECK (("tenant_service_accounts"."archived_at" is null and "tenant_service_accounts"."archived_by_membership_id" is null and "tenant_service_accounts"."archive_reason" is null)
        or ("tenant_service_accounts"."archived_at" is not null
          and "tenant_service_accounts"."archived_by_membership_id" is not null
          and "tenant_service_accounts"."archive_reason" is not null
          and "tenant_service_accounts"."archived_at" >= "tenant_service_accounts"."created_at"
          and btrim("tenant_service_accounts"."archive_reason") <> ''
          and char_length("tenant_service_accounts"."archive_reason") <= 500
          and "tenant_service_accounts"."archive_reason" !~ '[[:cntrl:]]')),
	CONSTRAINT "tenant_service_accounts_version_check" CHECK ("tenant_service_accounts"."version" > 0),
	CONSTRAINT "tenant_service_accounts_updated_check" CHECK ("tenant_service_accounts"."updated_at" >= "tenant_service_accounts"."created_at" and ("tenant_service_accounts"."archived_at" is null or "tenant_service_accounts"."updated_at" >= "tenant_service_accounts"."archived_at"))
);
--> statement-breakpoint
ALTER TABLE "tenant_service_accounts" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "alerts" DROP CONSTRAINT "alerts_title_not_blank_check";--> statement-breakpoint
ALTER TABLE "audit_events" DROP CONSTRAINT "audit_events_actor_consistency_check";--> statement-breakpoint
ALTER TABLE "alerts" ALTER COLUMN "created_by" DROP NOT NULL;--> statement-breakpoint
ALTER TABLE "alert_activities" ADD CONSTRAINT "alert_activities_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "alert_activities" ADD CONSTRAINT "alert_activities_alert_fk" FOREIGN KEY ("tenant_id","alert_id") REFERENCES "public"."alerts"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "alert_activities" ADD CONSTRAINT "alert_activities_actor_membership_fk" FOREIGN KEY ("tenant_id","actor_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "alert_activities" ADD CONSTRAINT "alert_activities_actor_service_account_fk" FOREIGN KEY ("tenant_id","actor_service_account_id") REFERENCES "public"."tenant_service_accounts"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "alert_commands" ADD CONSTRAINT "alert_commands_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "alert_commands" ADD CONSTRAINT "alert_commands_actor_membership_fk" FOREIGN KEY ("tenant_id","actor_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "alert_commands" ADD CONSTRAINT "alert_commands_actor_service_account_fk" FOREIGN KEY ("tenant_id","actor_service_account_id") REFERENCES "public"."tenant_service_accounts"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "alert_commands" ADD CONSTRAINT "alert_commands_result_fk" FOREIGN KEY ("tenant_id","result_alert_id") REFERENCES "public"."alerts"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_api_credential_commands" ADD CONSTRAINT "tenant_api_credential_commands_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_api_credential_commands" ADD CONSTRAINT "tenant_api_credential_commands_account_fk" FOREIGN KEY ("tenant_id","service_account_id") REFERENCES "public"."tenant_service_accounts"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_api_credential_commands" ADD CONSTRAINT "tenant_api_credential_commands_actor_fk" FOREIGN KEY ("tenant_id","actor_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_api_credential_commands" ADD CONSTRAINT "tenant_api_credential_commands_result_fk" FOREIGN KEY ("tenant_id","service_account_id","result_credential_id") REFERENCES "public"."tenant_api_credentials"("tenant_id","service_account_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_api_credential_networks" ADD CONSTRAINT "tenant_api_credential_networks_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_api_credential_networks" ADD CONSTRAINT "tenant_api_credential_networks_credential_fk" FOREIGN KEY ("tenant_id","credential_id") REFERENCES "public"."tenant_api_credentials"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_api_credential_permissions" ADD CONSTRAINT "tenant_api_credential_permissions_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_api_credential_permissions" ADD CONSTRAINT "tenant_api_credential_permissions_credential_fk" FOREIGN KEY ("tenant_id","credential_id") REFERENCES "public"."tenant_api_credentials"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_api_credential_permissions" ADD CONSTRAINT "tenant_api_credential_permissions_catalog_fk" FOREIGN KEY ("permission_id","permission_service_account_allowed") REFERENCES "public"."tenant_permissions"("id","service_account_allowed") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_api_credential_permissions" ADD CONSTRAINT "tenant_api_credential_permissions_scope_fk" FOREIGN KEY ("permission_id","scope") REFERENCES "public"."tenant_permission_scopes"("permission_id","scope") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_api_credentials" ADD CONSTRAINT "tenant_api_credentials_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_api_credentials" ADD CONSTRAINT "tenant_api_credentials_account_fk" FOREIGN KEY ("tenant_id","service_account_id") REFERENCES "public"."tenant_service_accounts"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_api_credentials" ADD CONSTRAINT "tenant_api_credentials_issuer_fk" FOREIGN KEY ("tenant_id","issued_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_api_credentials" ADD CONSTRAINT "tenant_api_credentials_revoker_fk" FOREIGN KEY ("tenant_id","revoked_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_api_credentials" ADD CONSTRAINT "tenant_api_credentials_rotated_from_fk" FOREIGN KEY ("tenant_id","service_account_id","rotated_from_credential_id") REFERENCES "public"."tenant_api_credentials"("tenant_id","service_account_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_service_account_role_grants" ADD CONSTRAINT "tenant_service_account_role_grants_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_service_account_role_grants" ADD CONSTRAINT "tenant_service_account_role_grants_account_fk" FOREIGN KEY ("tenant_id","service_account_id") REFERENCES "public"."tenant_service_accounts"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_service_account_role_grants" ADD CONSTRAINT "tenant_service_account_role_grants_role_principal_fk" FOREIGN KEY ("tenant_id","role_id","role_principal_kind") REFERENCES "public"."tenant_roles"("tenant_id","id","principal_kind") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_service_account_role_grants" ADD CONSTRAINT "tenant_service_account_role_grants_source_fk" FOREIGN KEY ("tenant_id","source_id") REFERENCES "public"."tenant_authorization_sources"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_service_account_role_grants" ADD CONSTRAINT "tenant_service_account_role_grants_grantor_fk" FOREIGN KEY ("tenant_id","granted_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_service_account_role_grants" ADD CONSTRAINT "tenant_service_account_role_grants_revoker_fk" FOREIGN KEY ("tenant_id","revoked_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_service_accounts" ADD CONSTRAINT "tenant_service_accounts_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_service_accounts" ADD CONSTRAINT "tenant_service_accounts_creator_membership_fk" FOREIGN KEY ("tenant_id","created_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_service_accounts" ADD CONSTRAINT "tenant_service_accounts_archiver_membership_fk" FOREIGN KEY ("tenant_id","archived_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
CREATE INDEX "alert_activities_alert_time_idx" ON "alert_activities" USING btree ("tenant_id","alert_id","occurred_at","id");--> statement-breakpoint
CREATE UNIQUE INDEX "alert_commands_human_replay_key" ON "alert_commands" USING btree ("tenant_id","operation","actor_membership_id","key_digest") WHERE "alert_commands"."principal_kind" = 'human';--> statement-breakpoint
CREATE UNIQUE INDEX "alert_commands_service_account_replay_key" ON "alert_commands" USING btree ("tenant_id","operation","actor_service_account_id","key_digest") WHERE "alert_commands"."principal_kind" = 'service_account';--> statement-breakpoint
CREATE INDEX "tenant_api_credential_permissions_authority_idx" ON "tenant_api_credential_permissions" USING btree ("tenant_id","permission_id","scope","credential_id");--> statement-breakpoint
CREATE INDEX "tenant_api_credentials_account_active_idx" ON "tenant_api_credentials" USING btree ("tenant_id","service_account_id","expires_at","id") WHERE "tenant_api_credentials"."revoked_at" is null;--> statement-breakpoint
CREATE INDEX "tenant_api_credentials_live_key_version_idx" ON "tenant_api_credentials" USING btree ("key_version","expires_at","id") WHERE "tenant_api_credentials"."revoked_at" is null;--> statement-breakpoint
CREATE UNIQUE INDEX "tenant_service_account_role_grants_active_key" ON "tenant_service_account_role_grants" USING btree ("tenant_id","service_account_id","role_id","source_id") WHERE "tenant_service_account_role_grants"."revoked_at" is null;--> statement-breakpoint
CREATE INDEX "tenant_service_account_role_grants_effective_idx" ON "tenant_service_account_role_grants" USING btree ("tenant_id","service_account_id","role_id","expires_at") WHERE "tenant_service_account_role_grants"."revoked_at" is null;--> statement-breakpoint
CREATE INDEX "tenant_service_account_role_grants_role_idx" ON "tenant_service_account_role_grants" USING btree ("tenant_id","role_id","id");--> statement-breakpoint
CREATE INDEX "tenant_service_accounts_tenant_active_idx" ON "tenant_service_accounts" USING btree ("tenant_id","id") WHERE "tenant_service_accounts"."archived_at" is null;--> statement-breakpoint
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_creator_membership_id_fk" FOREIGN KEY ("tenant_id","created_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_creator_human_attribution_fk" FOREIGN KEY ("tenant_id","created_by_membership_id","created_by") REFERENCES "public"."tenant_memberships"("tenant_id","id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_creator_service_account_fk" FOREIGN KEY ("tenant_id","created_by_service_account_id") REFERENCES "public"."tenant_service_accounts"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "audit_events" ADD CONSTRAINT "audit_events_actor_service_account_fk" FOREIGN KEY ("tenant_id","actor_service_account_id") REFERENCES "public"."tenant_service_accounts"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_creator_attribution_check" CHECK (("alerts"."created_by_membership_id" is not null
          and "alerts"."created_by" is not null
          and "alerts"."created_by_service_account_id" is null)
        or ("alerts"."created_by_membership_id" is null
          and "alerts"."created_by" is null
          and "alerts"."created_by_service_account_id" is not null));--> statement-breakpoint
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_external_id_check" CHECK ("alerts"."external_id" is null or (char_length("alerts"."external_id") <= 200 and "alerts"."external_id" !~ '[[:cntrl:]]'));--> statement-breakpoint
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_description_check" CHECK ("alerts"."description" is null or (char_length("alerts"."description") <= 10000 and "alerts"."description" !~ '[[:cntrl:]]'));--> statement-breakpoint
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_title_not_blank_check" CHECK (btrim("alerts"."title") <> '' and char_length("alerts"."title") <= 240 and "alerts"."title" !~ '[[:cntrl:]]');--> statement-breakpoint
ALTER TABLE "audit_events" ADD CONSTRAINT "audit_events_actor_consistency_check" CHECK (("audit_events"."actor_type" = 'user'
          and "audit_events"."actor_user_id" is not null
          and "audit_events"."actor_service_account_id" is null)
        or ("audit_events"."actor_type" = 'service_account'
          and "audit_events"."actor_user_id" is null
          and "audit_events"."actor_service_account_id" is not null
          and "audit_events"."impersonated_by_user_id" is null)
        or ("audit_events"."actor_type" = 'system'
          and "audit_events"."actor_user_id" is null
          and "audit_events"."actor_service_account_id" is null
          and "audit_events"."impersonated_by_user_id" is null));