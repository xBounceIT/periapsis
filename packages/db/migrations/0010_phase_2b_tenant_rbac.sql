CREATE TYPE "public"."authorization_scope" AS ENUM('own', 'assigned', 'operator_team', 'tenant', 'platform');--> statement-breakpoint
CREATE TYPE "public"."authorization_source_kind" AS ENUM('system', 'tenant_creation', 'manual', 'identity_mapping', 'platform_recovery');--> statement-breakpoint
CREATE TABLE "tenant_authorization_commands" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"actor_membership_id" uuid NOT NULL,
	"operation" text NOT NULL,
	"key_digest" "bytea" NOT NULL,
	"request_digest" "bytea" NOT NULL,
	"result_resource_id" uuid NOT NULL,
	"result_version" integer NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone DEFAULT now() + interval '24 hours' NOT NULL,
	CONSTRAINT "tenant_authorization_commands_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "tenant_authorization_commands_replay_key" UNIQUE("tenant_id","actor_membership_id","operation","key_digest"),
	CONSTRAINT "tenant_authorization_commands_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_authorization_commands"."id") = 7) is true),
	CONSTRAINT "tenant_authorization_commands_operation_check" CHECK ("tenant_authorization_commands"."operation" in ('tenant_role.create', 'tenant_role_grant.create')),
	CONSTRAINT "tenant_authorization_commands_digest_check" CHECK (octet_length("tenant_authorization_commands"."key_digest") = 32 and octet_length("tenant_authorization_commands"."request_digest") = 32),
	CONSTRAINT "tenant_authorization_commands_result_version_check" CHECK ("tenant_authorization_commands"."result_version" > 0),
	CONSTRAINT "tenant_authorization_commands_retention_check" CHECK ("tenant_authorization_commands"."expires_at" > "tenant_authorization_commands"."created_at" and "tenant_authorization_commands"."expires_at" <= "tenant_authorization_commands"."created_at" + interval '7 days')
);
--> statement-breakpoint
ALTER TABLE "tenant_authorization_commands" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_authorization_sources" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"kind" "authorization_source_kind" NOT NULL,
	"key" text NOT NULL,
	"authoritative" boolean DEFAULT false NOT NULL,
	"protected" boolean DEFAULT false NOT NULL,
	"retired_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_authorization_sources_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "tenant_authorization_sources_tenant_key_key" UNIQUE("tenant_id","key"),
	CONSTRAINT "tenant_authorization_sources_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_authorization_sources"."id") = 7) is true),
	CONSTRAINT "tenant_authorization_sources_key_check" CHECK ("tenant_authorization_sources"."key" ~ '^[a-z][a-z0-9_.:-]{0,126}[a-z0-9]$'),
	CONSTRAINT "tenant_authorization_sources_retirement_check" CHECK ("tenant_authorization_sources"."retired_at" is null or ("tenant_authorization_sources"."protected" is false and "tenant_authorization_sources"."retired_at" >= "tenant_authorization_sources"."created_at"))
);
--> statement-breakpoint
ALTER TABLE "tenant_authorization_sources" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_authorization_states" (
	"tenant_id" uuid PRIMARY KEY NOT NULL,
	"initialized_at" timestamp with time zone,
	"revision" bigint DEFAULT 0 NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_authorization_states_revision_check" CHECK ("tenant_authorization_states"."revision" >= 0),
	CONSTRAINT "tenant_authorization_states_initialized_check" CHECK ("tenant_authorization_states"."initialized_at" is null or "tenant_authorization_states"."updated_at" >= "tenant_authorization_states"."initialized_at")
);
--> statement-breakpoint
ALTER TABLE "tenant_authorization_states" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_membership_role_grants" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"membership_id" uuid NOT NULL,
	"role_id" uuid NOT NULL,
	"source_id" uuid NOT NULL,
	"granted_by_membership_id" uuid,
	"grant_reason" text NOT NULL,
	"granted_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone,
	"revoked_at" timestamp with time zone,
	"revoked_by_membership_id" uuid,
	"revoke_reason" text,
	"version" integer DEFAULT 1 NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_membership_role_grants_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "tenant_membership_role_grants_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_membership_role_grants"."id") = 7) is true),
	CONSTRAINT "tenant_membership_role_grants_expiry_check" CHECK ("tenant_membership_role_grants"."expires_at" is null or "tenant_membership_role_grants"."expires_at" > "tenant_membership_role_grants"."granted_at"),
	CONSTRAINT "tenant_membership_role_grants_reason_check" CHECK (btrim("tenant_membership_role_grants"."grant_reason") <> '' and char_length("tenant_membership_role_grants"."grant_reason") <= 500 and "tenant_membership_role_grants"."grant_reason" !~ '[[:cntrl:]]'),
	CONSTRAINT "tenant_membership_role_grants_revocation_check" CHECK (("tenant_membership_role_grants"."revoked_at" is null and "tenant_membership_role_grants"."revoked_by_membership_id" is null and "tenant_membership_role_grants"."revoke_reason" is null)
        or ("tenant_membership_role_grants"."revoked_at" is not null
          and "tenant_membership_role_grants"."revoked_by_membership_id" is not null
          and "tenant_membership_role_grants"."revoke_reason" is not null
          and "tenant_membership_role_grants"."revoked_at" >= "tenant_membership_role_grants"."granted_at"
          and btrim("tenant_membership_role_grants"."revoke_reason") <> ''
          and char_length("tenant_membership_role_grants"."revoke_reason") <= 500
          and "tenant_membership_role_grants"."revoke_reason" !~ '[[:cntrl:]]')),
	CONSTRAINT "tenant_membership_role_grants_version_check" CHECK ("tenant_membership_role_grants"."version" > 0),
	CONSTRAINT "tenant_membership_role_grants_updated_check" CHECK ("tenant_membership_role_grants"."updated_at" >= "tenant_membership_role_grants"."granted_at" and ("tenant_membership_role_grants"."revoked_at" is null or "tenant_membership_role_grants"."updated_at" >= "tenant_membership_role_grants"."revoked_at"))
);
--> statement-breakpoint
ALTER TABLE "tenant_membership_role_grants" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_permission_scopes" (
	"permission_id" uuid NOT NULL,
	"scope" "authorization_scope" NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_permission_scopes_pkey" PRIMARY KEY("permission_id","scope"),
	CONSTRAINT "tenant_permission_scopes_not_platform_check" CHECK ("tenant_permission_scopes"."scope" <> 'platform')
);
--> statement-breakpoint
ALTER TABLE "tenant_permission_scopes" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_permissions" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"key" text NOT NULL,
	"display_name" text NOT NULL,
	"description" text NOT NULL,
	"service_account_allowed" boolean DEFAULT false NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_permissions_key_key" UNIQUE("key"),
	CONSTRAINT "tenant_permissions_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_permissions"."id") = 7) is true),
	CONSTRAINT "tenant_permissions_key_canonical_check" CHECK ("tenant_permissions"."key" ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'),
	CONSTRAINT "tenant_permissions_display_name_check" CHECK (btrim("tenant_permissions"."display_name") <> '' and char_length("tenant_permissions"."display_name") <= 120 and "tenant_permissions"."display_name" !~ '[[:cntrl:]]'),
	CONSTRAINT "tenant_permissions_description_check" CHECK (btrim("tenant_permissions"."description") <> '' and char_length("tenant_permissions"."description") <= 500)
);
--> statement-breakpoint
ALTER TABLE "tenant_permissions" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_role_delegation_ceilings" (
	"tenant_id" uuid NOT NULL,
	"role_id" uuid NOT NULL,
	"permission_id" uuid NOT NULL,
	"scope" "authorization_scope" NOT NULL,
	"created_by_membership_id" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_role_delegation_ceilings_pkey" PRIMARY KEY("tenant_id","role_id","permission_id","scope"),
	CONSTRAINT "tenant_role_delegation_not_platform_check" CHECK ("tenant_role_delegation_ceilings"."scope" <> 'platform')
);
--> statement-breakpoint
ALTER TABLE "tenant_role_delegation_ceilings" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_role_permissions" (
	"tenant_id" uuid NOT NULL,
	"role_id" uuid NOT NULL,
	"permission_id" uuid NOT NULL,
	"scope" "authorization_scope" NOT NULL,
	"created_by_membership_id" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_role_permissions_pkey" PRIMARY KEY("tenant_id","role_id","permission_id","scope"),
	CONSTRAINT "tenant_role_permissions_not_platform_check" CHECK ("tenant_role_permissions"."scope" <> 'platform')
);
--> statement-breakpoint
ALTER TABLE "tenant_role_permissions" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_roles" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"key" text NOT NULL,
	"display_name" text NOT NULL,
	"description" text NOT NULL,
	"system_role" boolean DEFAULT false NOT NULL,
	"protected_role" boolean DEFAULT false NOT NULL,
	"version" integer DEFAULT 1 NOT NULL,
	"created_by_membership_id" uuid,
	"archived_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_roles_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "tenant_roles_tenant_key_key" UNIQUE("tenant_id","key"),
	CONSTRAINT "tenant_roles_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_roles"."id") = 7) is true),
	CONSTRAINT "tenant_roles_key_canonical_check" CHECK ("tenant_roles"."key" ~ '^[a-z][a-z0-9_]{0,62}[a-z0-9]$'),
	CONSTRAINT "tenant_roles_display_name_check" CHECK (btrim("tenant_roles"."display_name") <> '' and char_length("tenant_roles"."display_name") <= 160 and "tenant_roles"."display_name" !~ '[[:cntrl:]]'),
	CONSTRAINT "tenant_roles_description_check" CHECK (char_length("tenant_roles"."description") <= 1000 and "tenant_roles"."description" !~ '[[:cntrl:]]'),
	CONSTRAINT "tenant_roles_protected_check" CHECK ("tenant_roles"."protected_role" is false or "tenant_roles"."system_role" is true),
	CONSTRAINT "tenant_roles_version_check" CHECK ("tenant_roles"."version" > 0),
	CONSTRAINT "tenant_roles_timestamps_check" CHECK ("tenant_roles"."updated_at" >= "tenant_roles"."created_at" and ("tenant_roles"."archived_at" is null or "tenant_roles"."archived_at" >= "tenant_roles"."created_at"))
);
--> statement-breakpoint
ALTER TABLE "tenant_roles" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "tenant_authorization_commands" ADD CONSTRAINT "tenant_authorization_commands_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_authorization_sources" ADD CONSTRAINT "tenant_authorization_sources_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_authorization_states" ADD CONSTRAINT "tenant_authorization_states_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_membership_role_grants" ADD CONSTRAINT "tenant_membership_role_grants_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_membership_role_grants" ADD CONSTRAINT "tenant_membership_role_grants_role_fk" FOREIGN KEY ("tenant_id","role_id") REFERENCES "public"."tenant_roles"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_membership_role_grants" ADD CONSTRAINT "tenant_membership_role_grants_source_fk" FOREIGN KEY ("tenant_id","source_id") REFERENCES "public"."tenant_authorization_sources"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_permission_scopes" ADD CONSTRAINT "tenant_permission_scopes_permission_id_tenant_permissions_id_fk" FOREIGN KEY ("permission_id") REFERENCES "public"."tenant_permissions"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_role_delegation_ceilings" ADD CONSTRAINT "tenant_role_delegation_ceilings_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_role_delegation_ceilings" ADD CONSTRAINT "tenant_role_delegation_permission_fk" FOREIGN KEY ("tenant_id","role_id","permission_id","scope") REFERENCES "public"."tenant_role_permissions"("tenant_id","role_id","permission_id","scope") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_role_permissions" ADD CONSTRAINT "tenant_role_permissions_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_role_permissions" ADD CONSTRAINT "tenant_role_permissions_role_fk" FOREIGN KEY ("tenant_id","role_id") REFERENCES "public"."tenant_roles"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_role_permissions" ADD CONSTRAINT "tenant_role_permissions_scope_fk" FOREIGN KEY ("permission_id","scope") REFERENCES "public"."tenant_permission_scopes"("permission_id","scope") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_roles" ADD CONSTRAINT "tenant_roles_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "tenant_authorization_commands_expiry_idx" ON "tenant_authorization_commands" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "tenant_authorization_sources_tenant_kind_idx" ON "tenant_authorization_sources" USING btree ("tenant_id","kind","id");--> statement-breakpoint
CREATE UNIQUE INDEX "tenant_membership_role_grants_active_key" ON "tenant_membership_role_grants" USING btree ("tenant_id","membership_id","role_id","source_id") WHERE "tenant_membership_role_grants"."revoked_at" is null;--> statement-breakpoint
CREATE INDEX "tenant_membership_role_grants_effective_idx" ON "tenant_membership_role_grants" USING btree ("tenant_id","membership_id","role_id","expires_at") WHERE "tenant_membership_role_grants"."revoked_at" is null;--> statement-breakpoint
CREATE INDEX "tenant_membership_role_grants_role_idx" ON "tenant_membership_role_grants" USING btree ("tenant_id","role_id","id");--> statement-breakpoint
CREATE INDEX "tenant_role_permissions_catalog_idx" ON "tenant_role_permissions" USING btree ("permission_id","scope","tenant_id","role_id");--> statement-breakpoint
CREATE INDEX "tenant_roles_tenant_active_idx" ON "tenant_roles" USING btree ("tenant_id","id") WHERE "tenant_roles"."archived_at" is null;--> statement-breakpoint
ALTER TABLE "tenant_memberships" ADD CONSTRAINT "tenant_memberships_tenant_id_key" UNIQUE("tenant_id","id");