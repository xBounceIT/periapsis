CREATE TABLE "operator_team_assignment_epochs" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"operator_team_id" uuid NOT NULL,
	"assigned_by_membership_id" uuid NOT NULL,
	"assignment_reason" text NOT NULL,
	"assigned_at" timestamp with time zone DEFAULT now() NOT NULL,
	"ended_at" timestamp with time zone,
	"ended_by_membership_id" uuid,
	"end_reason" text,
	"version" integer DEFAULT 1 NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "operator_team_assignment_epochs_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "operator_team_assignment_epochs_id_uuidv7_check" CHECK ((uuid_extract_version("operator_team_assignment_epochs"."id") = 7) is true),
	CONSTRAINT "operator_team_assignment_epochs_assignment_reason_check" CHECK (btrim("operator_team_assignment_epochs"."assignment_reason") <> '' and char_length("operator_team_assignment_epochs"."assignment_reason") <= 500 and "operator_team_assignment_epochs"."assignment_reason" !~ '[[:cntrl:]]'),
	CONSTRAINT "operator_team_assignment_epochs_end_check" CHECK (("operator_team_assignment_epochs"."ended_at" is null and "operator_team_assignment_epochs"."ended_by_membership_id" is null and "operator_team_assignment_epochs"."end_reason" is null)
        or ("operator_team_assignment_epochs"."ended_at" is not null
          and "operator_team_assignment_epochs"."ended_by_membership_id" is not null
          and "operator_team_assignment_epochs"."end_reason" is not null
          and "operator_team_assignment_epochs"."ended_at" >= "operator_team_assignment_epochs"."assigned_at"
          and btrim("operator_team_assignment_epochs"."end_reason") <> ''
          and char_length("operator_team_assignment_epochs"."end_reason") <= 500
          and "operator_team_assignment_epochs"."end_reason" !~ '[[:cntrl:]]')),
	CONSTRAINT "operator_team_assignment_epochs_version_check" CHECK ("operator_team_assignment_epochs"."version" > 0),
	CONSTRAINT "operator_team_assignment_epochs_updated_check" CHECK ("operator_team_assignment_epochs"."updated_at" >= "operator_team_assignment_epochs"."assigned_at" and ("operator_team_assignment_epochs"."ended_at" is null or "operator_team_assignment_epochs"."updated_at" >= "operator_team_assignment_epochs"."ended_at"))
);
--> statement-breakpoint
ALTER TABLE "operator_team_assignment_epochs" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "operator_team_roster_entries" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"assignment_epoch_id" uuid NOT NULL,
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
	CONSTRAINT "operator_team_roster_entries_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "operator_team_roster_entries_id_uuidv7_check" CHECK ((uuid_extract_version("operator_team_roster_entries"."id") = 7) is true),
	CONSTRAINT "operator_team_roster_entries_expiry_check" CHECK ("operator_team_roster_entries"."expires_at" is null or "operator_team_roster_entries"."expires_at" > "operator_team_roster_entries"."granted_at"),
	CONSTRAINT "operator_team_roster_entries_reason_check" CHECK (btrim("operator_team_roster_entries"."grant_reason") <> '' and char_length("operator_team_roster_entries"."grant_reason") <= 500 and "operator_team_roster_entries"."grant_reason" !~ '[[:cntrl:]]'),
	CONSTRAINT "operator_team_roster_entries_revocation_check" CHECK (("operator_team_roster_entries"."revoked_at" is null and "operator_team_roster_entries"."revoked_by_membership_id" is null and "operator_team_roster_entries"."revoke_reason" is null)
        or ("operator_team_roster_entries"."revoked_at" is not null
          and "operator_team_roster_entries"."revoked_by_membership_id" is not null
          and "operator_team_roster_entries"."revoke_reason" is not null
          and "operator_team_roster_entries"."revoked_at" >= "operator_team_roster_entries"."granted_at"
          and btrim("operator_team_roster_entries"."revoke_reason") <> ''
          and char_length("operator_team_roster_entries"."revoke_reason") <= 500
          and "operator_team_roster_entries"."revoke_reason" !~ '[[:cntrl:]]')),
	CONSTRAINT "operator_team_roster_entries_version_check" CHECK ("operator_team_roster_entries"."version" > 0),
	CONSTRAINT "operator_team_roster_entries_updated_check" CHECK ("operator_team_roster_entries"."updated_at" >= "operator_team_roster_entries"."granted_at" and ("operator_team_roster_entries"."revoked_at" is null or "operator_team_roster_entries"."updated_at" >= "operator_team_roster_entries"."revoked_at"))
);
--> statement-breakpoint
ALTER TABLE "operator_team_roster_entries" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "operator_teams" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"key" text NOT NULL,
	"display_name" text NOT NULL,
	"description" text NOT NULL,
	"version" integer DEFAULT 1 NOT NULL,
	"created_by_user_id" uuid,
	"archived_at" timestamp with time zone,
	"archived_by_user_id" uuid,
	"archive_reason" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "operator_teams_key_key" UNIQUE("key"),
	CONSTRAINT "operator_teams_id_uuidv7_check" CHECK ((uuid_extract_version("operator_teams"."id") = 7) is true),
	CONSTRAINT "operator_teams_key_canonical_check" CHECK ("operator_teams"."key" ~ '^[a-z][a-z0-9_]{2,63}$'),
	CONSTRAINT "operator_teams_display_name_check" CHECK (btrim("operator_teams"."display_name") <> '' and char_length("operator_teams"."display_name") <= 120 and "operator_teams"."display_name" !~ '[[:cntrl:]]'),
	CONSTRAINT "operator_teams_description_check" CHECK (char_length("operator_teams"."description") <= 500 and "operator_teams"."description" !~ '[[:cntrl:]]'),
	CONSTRAINT "operator_teams_version_check" CHECK ("operator_teams"."version" > 0),
	CONSTRAINT "operator_teams_archive_check" CHECK (("operator_teams"."archived_at" is null and "operator_teams"."archived_by_user_id" is null and "operator_teams"."archive_reason" is null)
        or ("operator_teams"."archived_at" is not null
          and "operator_teams"."archived_by_user_id" is not null
          and "operator_teams"."archive_reason" is not null
          and "operator_teams"."archived_at" >= "operator_teams"."created_at"
          and btrim("operator_teams"."archive_reason") <> ''
          and char_length("operator_teams"."archive_reason") <= 500
          and "operator_teams"."archive_reason" !~ '[[:cntrl:]]')),
	CONSTRAINT "operator_teams_timestamps_check" CHECK ("operator_teams"."updated_at" >= "operator_teams"."created_at" and ("operator_teams"."archived_at" is null or "operator_teams"."updated_at" >= "operator_teams"."archived_at"))
);
--> statement-breakpoint
ALTER TABLE "operator_teams" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "platform_commands" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"actor_user_id" uuid NOT NULL,
	"operation" text NOT NULL,
	"key_digest" "bytea" NOT NULL,
	"request_digest" "bytea" NOT NULL,
	"result_resource_id" uuid NOT NULL,
	"result_version" integer NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone DEFAULT now() + interval '24 hours' NOT NULL,
	CONSTRAINT "platform_commands_replay_key" UNIQUE("actor_user_id","operation","key_digest"),
	CONSTRAINT "platform_commands_id_uuidv7_check" CHECK ((uuid_extract_version("platform_commands"."id") = 7) is true),
	CONSTRAINT "platform_commands_operation_check" CHECK ("platform_commands"."operation" = 'operator_team.create'),
	CONSTRAINT "platform_commands_digest_check" CHECK (octet_length("platform_commands"."key_digest") = 32 and octet_length("platform_commands"."request_digest") = 32),
	CONSTRAINT "platform_commands_result_version_check" CHECK ("platform_commands"."result_version" > 0),
	CONSTRAINT "platform_commands_retention_check" CHECK ("platform_commands"."expires_at" > "platform_commands"."created_at" and "platform_commands"."expires_at" <= "platform_commands"."created_at" + interval '7 days')
);
--> statement-breakpoint
ALTER TABLE "platform_commands" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "tenant_authorization_commands" DROP CONSTRAINT "tenant_authorization_commands_operation_check";--> statement-breakpoint
ALTER TABLE "operator_team_assignment_epochs" ADD CONSTRAINT "operator_team_assignment_epochs_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "operator_team_assignment_epochs" ADD CONSTRAINT "operator_team_assignment_epochs_operator_team_id_operator_teams_id_fk" FOREIGN KEY ("operator_team_id") REFERENCES "public"."operator_teams"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "operator_team_assignment_epochs" ADD CONSTRAINT "operator_team_assignment_epochs_assigner_fk" FOREIGN KEY ("tenant_id","assigned_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "operator_team_assignment_epochs" ADD CONSTRAINT "operator_team_assignment_epochs_ender_fk" FOREIGN KEY ("tenant_id","ended_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "operator_team_roster_entries" ADD CONSTRAINT "operator_team_roster_entries_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "operator_team_roster_entries" ADD CONSTRAINT "operator_team_roster_entries_epoch_fk" FOREIGN KEY ("tenant_id","assignment_epoch_id") REFERENCES "public"."operator_team_assignment_epochs"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "operator_team_roster_entries" ADD CONSTRAINT "operator_team_roster_entries_membership_fk" FOREIGN KEY ("tenant_id","membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "operator_team_roster_entries" ADD CONSTRAINT "operator_team_roster_entries_source_fk" FOREIGN KEY ("tenant_id","source_id") REFERENCES "public"."tenant_authorization_sources"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "operator_team_roster_entries" ADD CONSTRAINT "operator_team_roster_entries_grantor_fk" FOREIGN KEY ("tenant_id","granted_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "operator_team_roster_entries" ADD CONSTRAINT "operator_team_roster_entries_revoker_fk" FOREIGN KEY ("tenant_id","revoked_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "operator_teams" ADD CONSTRAINT "operator_teams_created_by_user_id_users_id_fk" FOREIGN KEY ("created_by_user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "operator_teams" ADD CONSTRAINT "operator_teams_archived_by_user_id_users_id_fk" FOREIGN KEY ("archived_by_user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "platform_commands" ADD CONSTRAINT "platform_commands_actor_user_id_users_id_fk" FOREIGN KEY ("actor_user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "operator_team_assignment_epochs_active_key" ON "operator_team_assignment_epochs" USING btree ("tenant_id","operator_team_id") WHERE "operator_team_assignment_epochs"."ended_at" is null;--> statement-breakpoint
CREATE INDEX "operator_team_assignment_epochs_tenant_team_idx" ON "operator_team_assignment_epochs" USING btree ("tenant_id","operator_team_id","assigned_at","id");--> statement-breakpoint
CREATE UNIQUE INDEX "operator_team_roster_entries_active_key" ON "operator_team_roster_entries" USING btree ("tenant_id","assignment_epoch_id","membership_id","source_id") WHERE "operator_team_roster_entries"."revoked_at" is null;--> statement-breakpoint
CREATE INDEX "operator_team_roster_entries_effective_idx" ON "operator_team_roster_entries" USING btree ("tenant_id","membership_id","assignment_epoch_id","expires_at") WHERE "operator_team_roster_entries"."revoked_at" is null;--> statement-breakpoint
CREATE INDEX "operator_team_roster_entries_epoch_idx" ON "operator_team_roster_entries" USING btree ("tenant_id","assignment_epoch_id","id");--> statement-breakpoint
CREATE INDEX "operator_team_roster_entries_source_idx" ON "operator_team_roster_entries" USING btree ("tenant_id","source_id","assignment_epoch_id","id");--> statement-breakpoint
CREATE INDEX "operator_teams_active_idx" ON "operator_teams" USING btree ("id") WHERE "operator_teams"."archived_at" is null;--> statement-breakpoint
CREATE INDEX "platform_commands_expiry_idx" ON "platform_commands" USING btree ("expires_at");--> statement-breakpoint
ALTER TABLE "tenant_authorization_commands" ADD CONSTRAINT "tenant_authorization_commands_operation_check" CHECK ("tenant_authorization_commands"."operation" in (
        'tenant_role.create',
        'tenant_role_grant.create',
        'tenant_security_group.create',
        'tenant_security_group_membership.create',
        'tenant_security_group_role_grant.create',
        'operator_team_assignment.create',
        'operator_team_roster_entry.create'
      ));