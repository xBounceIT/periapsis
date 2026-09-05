CREATE TABLE "tenant_security_group_memberships" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"group_id" uuid NOT NULL,
	"membership_id" uuid NOT NULL,
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
	CONSTRAINT "tenant_security_group_memberships_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "tenant_security_group_memberships_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_security_group_memberships"."id") = 7) is true),
	CONSTRAINT "tenant_security_group_memberships_expiry_check" CHECK ("tenant_security_group_memberships"."expires_at" is null or "tenant_security_group_memberships"."expires_at" > "tenant_security_group_memberships"."granted_at"),
	CONSTRAINT "tenant_security_group_memberships_reason_check" CHECK (btrim("tenant_security_group_memberships"."grant_reason") <> '' and char_length("tenant_security_group_memberships"."grant_reason") <= 500 and "tenant_security_group_memberships"."grant_reason" !~ '[[:cntrl:]]'),
	CONSTRAINT "tenant_security_group_memberships_revocation_check" CHECK (("tenant_security_group_memberships"."revoked_at" is null and "tenant_security_group_memberships"."revoked_by_membership_id" is null and "tenant_security_group_memberships"."revoke_reason" is null)
        or ("tenant_security_group_memberships"."revoked_at" is not null
          and "tenant_security_group_memberships"."revoked_by_membership_id" is not null
          and "tenant_security_group_memberships"."revoke_reason" is not null
          and "tenant_security_group_memberships"."revoked_at" >= "tenant_security_group_memberships"."granted_at"
          and btrim("tenant_security_group_memberships"."revoke_reason") <> ''
          and char_length("tenant_security_group_memberships"."revoke_reason") <= 500
          and "tenant_security_group_memberships"."revoke_reason" !~ '[[:cntrl:]]')),
	CONSTRAINT "tenant_security_group_memberships_version_check" CHECK ("tenant_security_group_memberships"."version" > 0),
	CONSTRAINT "tenant_security_group_memberships_updated_check" CHECK ("tenant_security_group_memberships"."updated_at" >= "tenant_security_group_memberships"."granted_at" and ("tenant_security_group_memberships"."revoked_at" is null or "tenant_security_group_memberships"."updated_at" >= "tenant_security_group_memberships"."revoked_at"))
);
--> statement-breakpoint
ALTER TABLE "tenant_security_group_memberships" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_security_group_role_grants" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"group_id" uuid NOT NULL,
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
	CONSTRAINT "tenant_security_group_role_grants_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "tenant_security_group_role_grants_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_security_group_role_grants"."id") = 7) is true),
	CONSTRAINT "tenant_security_group_role_grants_expiry_check" CHECK ("tenant_security_group_role_grants"."expires_at" is null or "tenant_security_group_role_grants"."expires_at" > "tenant_security_group_role_grants"."granted_at"),
	CONSTRAINT "tenant_security_group_role_grants_reason_check" CHECK (btrim("tenant_security_group_role_grants"."grant_reason") <> '' and char_length("tenant_security_group_role_grants"."grant_reason") <= 500 and "tenant_security_group_role_grants"."grant_reason" !~ '[[:cntrl:]]'),
	CONSTRAINT "tenant_security_group_role_grants_revocation_check" CHECK (("tenant_security_group_role_grants"."revoked_at" is null and "tenant_security_group_role_grants"."revoked_by_membership_id" is null and "tenant_security_group_role_grants"."revoke_reason" is null)
        or ("tenant_security_group_role_grants"."revoked_at" is not null
          and "tenant_security_group_role_grants"."revoked_by_membership_id" is not null
          and "tenant_security_group_role_grants"."revoke_reason" is not null
          and "tenant_security_group_role_grants"."revoked_at" >= "tenant_security_group_role_grants"."granted_at"
          and btrim("tenant_security_group_role_grants"."revoke_reason") <> ''
          and char_length("tenant_security_group_role_grants"."revoke_reason") <= 500
          and "tenant_security_group_role_grants"."revoke_reason" !~ '[[:cntrl:]]')),
	CONSTRAINT "tenant_security_group_role_grants_version_check" CHECK ("tenant_security_group_role_grants"."version" > 0),
	CONSTRAINT "tenant_security_group_role_grants_updated_check" CHECK ("tenant_security_group_role_grants"."updated_at" >= "tenant_security_group_role_grants"."granted_at" and ("tenant_security_group_role_grants"."revoked_at" is null or "tenant_security_group_role_grants"."updated_at" >= "tenant_security_group_role_grants"."revoked_at"))
);
--> statement-breakpoint
ALTER TABLE "tenant_security_group_role_grants" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_security_groups" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"key" text NOT NULL,
	"display_name" text NOT NULL,
	"description" text NOT NULL,
	"version" integer DEFAULT 1 NOT NULL,
	"created_by_membership_id" uuid,
	"archived_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_security_groups_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "tenant_security_groups_tenant_key_key" UNIQUE("tenant_id","key"),
	CONSTRAINT "tenant_security_groups_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_security_groups"."id") = 7) is true),
	CONSTRAINT "tenant_security_groups_key_canonical_check" CHECK ("tenant_security_groups"."key" ~ '^[a-z][a-z0-9_]{2,63}$'),
	CONSTRAINT "tenant_security_groups_display_name_check" CHECK (btrim("tenant_security_groups"."display_name") <> '' and char_length("tenant_security_groups"."display_name") <= 120 and "tenant_security_groups"."display_name" !~ '[[:cntrl:]]'),
	CONSTRAINT "tenant_security_groups_description_check" CHECK (char_length("tenant_security_groups"."description") <= 500 and "tenant_security_groups"."description" !~ '[[:cntrl:]]'),
	CONSTRAINT "tenant_security_groups_version_check" CHECK ("tenant_security_groups"."version" > 0),
	CONSTRAINT "tenant_security_groups_timestamps_check" CHECK ("tenant_security_groups"."updated_at" >= "tenant_security_groups"."created_at" and ("tenant_security_groups"."archived_at" is null or "tenant_security_groups"."archived_at" >= "tenant_security_groups"."created_at"))
);
--> statement-breakpoint
ALTER TABLE "tenant_security_groups" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "tenant_security_group_memberships" ADD CONSTRAINT "tenant_security_group_memberships_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_security_group_memberships" ADD CONSTRAINT "tenant_security_group_memberships_group_fk" FOREIGN KEY ("tenant_id","group_id") REFERENCES "public"."tenant_security_groups"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_security_group_memberships" ADD CONSTRAINT "tenant_security_group_memberships_membership_fk" FOREIGN KEY ("tenant_id","membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_security_group_memberships" ADD CONSTRAINT "tenant_security_group_memberships_source_fk" FOREIGN KEY ("tenant_id","source_id") REFERENCES "public"."tenant_authorization_sources"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_security_group_memberships" ADD CONSTRAINT "tenant_security_group_memberships_grantor_fk" FOREIGN KEY ("tenant_id","granted_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_security_group_memberships" ADD CONSTRAINT "tenant_security_group_memberships_revoker_fk" FOREIGN KEY ("tenant_id","revoked_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_security_group_role_grants" ADD CONSTRAINT "tenant_security_group_role_grants_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_security_group_role_grants" ADD CONSTRAINT "tenant_security_group_role_grants_group_fk" FOREIGN KEY ("tenant_id","group_id") REFERENCES "public"."tenant_security_groups"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_security_group_role_grants" ADD CONSTRAINT "tenant_security_group_role_grants_role_fk" FOREIGN KEY ("tenant_id","role_id") REFERENCES "public"."tenant_roles"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_security_group_role_grants" ADD CONSTRAINT "tenant_security_group_role_grants_source_fk" FOREIGN KEY ("tenant_id","source_id") REFERENCES "public"."tenant_authorization_sources"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_security_group_role_grants" ADD CONSTRAINT "tenant_security_group_role_grants_grantor_fk" FOREIGN KEY ("tenant_id","granted_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_security_group_role_grants" ADD CONSTRAINT "tenant_security_group_role_grants_revoker_fk" FOREIGN KEY ("tenant_id","revoked_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_security_groups" ADD CONSTRAINT "tenant_security_groups_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_security_groups" ADD CONSTRAINT "tenant_security_groups_creator_membership_fk" FOREIGN KEY ("tenant_id","created_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
CREATE UNIQUE INDEX "tenant_security_group_memberships_active_key" ON "tenant_security_group_memberships" USING btree ("tenant_id","group_id","membership_id","source_id") WHERE "tenant_security_group_memberships"."revoked_at" is null;--> statement-breakpoint
CREATE INDEX "tenant_security_group_memberships_effective_idx" ON "tenant_security_group_memberships" USING btree ("tenant_id","membership_id","group_id","expires_at") WHERE "tenant_security_group_memberships"."revoked_at" is null;--> statement-breakpoint
CREATE INDEX "tenant_security_group_memberships_group_idx" ON "tenant_security_group_memberships" USING btree ("tenant_id","group_id","id");--> statement-breakpoint
CREATE UNIQUE INDEX "tenant_security_group_role_grants_active_key" ON "tenant_security_group_role_grants" USING btree ("tenant_id","group_id","role_id","source_id") WHERE "tenant_security_group_role_grants"."revoked_at" is null;--> statement-breakpoint
CREATE INDEX "tenant_security_group_role_grants_effective_idx" ON "tenant_security_group_role_grants" USING btree ("tenant_id","group_id","role_id","expires_at") WHERE "tenant_security_group_role_grants"."revoked_at" is null;--> statement-breakpoint
CREATE INDEX "tenant_security_group_role_grants_role_idx" ON "tenant_security_group_role_grants" USING btree ("tenant_id","role_id","id");--> statement-breakpoint
CREATE INDEX "tenant_security_groups_tenant_active_idx" ON "tenant_security_groups" USING btree ("tenant_id","id") WHERE "tenant_security_groups"."archived_at" is null;