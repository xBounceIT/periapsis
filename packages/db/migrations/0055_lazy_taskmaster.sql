CREATE TABLE "tenant_ldap_mapping_rule_epochs" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"mapping_rule_id" uuid NOT NULL,
	"binding_id" uuid NOT NULL,
	"source_id" uuid NOT NULL,
	"sequence" integer NOT NULL,
	"configuration_revision" integer NOT NULL,
	"matcher_type" "ldap_mapping_matcher_type" NOT NULL,
	"matcher_value" text NOT NULL,
	"case_mode" "ldap_mapping_case_mode" NOT NULL,
	"priority" integer NOT NULL,
	"tenant_security_group_id" uuid NOT NULL,
	"reconciliation_mode" "ldap_mapping_reconciliation_mode" NOT NULL,
	"operator_team_id" uuid,
	"operator_team_assignment_epoch_id" uuid,
	"activated_by_membership_id" uuid NOT NULL,
	"activated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"ended_at" timestamp with time zone,
	"ended_by_membership_id" uuid,
	"end_reason" text,
	"version" integer DEFAULT 1 NOT NULL,
	CONSTRAINT "tenant_ldap_mapping_rule_epochs_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "tenant_ldap_mapping_rule_epochs_current_key" UNIQUE("tenant_id","id","mapping_rule_id","binding_id","configuration_revision"),
	CONSTRAINT "tenant_ldap_mapping_rule_epochs_exact_source_key" UNIQUE("tenant_id","id","mapping_rule_id","binding_id","source_id"),
	CONSTRAINT "tenant_ldap_mapping_rule_epochs_rule_sequence_key" UNIQUE("tenant_id","mapping_rule_id","sequence"),
	CONSTRAINT "tenant_ldap_mapping_rule_epochs_source_key" UNIQUE("tenant_id","source_id"),
	CONSTRAINT "tenant_ldap_mapping_rule_epochs_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_ldap_mapping_rule_epochs"."id") = 7) is true),
	CONSTRAINT "tenant_ldap_mapping_rule_epochs_sequence_check" CHECK ("tenant_ldap_mapping_rule_epochs"."sequence" > 0 and "tenant_ldap_mapping_rule_epochs"."configuration_revision" > 0),
	CONSTRAINT "tenant_ldap_mapping_rule_epochs_matcher_check" CHECK (btrim("tenant_ldap_mapping_rule_epochs"."matcher_value") <> ''
        and "tenant_ldap_mapping_rule_epochs"."matcher_value" !~ '[[:cntrl:]]'
        and (("tenant_ldap_mapping_rule_epochs"."matcher_type" = 'exact_dn'
            and char_length("tenant_ldap_mapping_rule_epochs"."matcher_value") <= 2048
            and octet_length("tenant_ldap_mapping_rule_epochs"."matcher_value") <= 8192)
          or ("tenant_ldap_mapping_rule_epochs"."matcher_type" in ('exact_cn', 'regex')
            and char_length("tenant_ldap_mapping_rule_epochs"."matcher_value") <= 512))),
	CONSTRAINT "tenant_ldap_mapping_rule_epochs_priority_check" CHECK ("tenant_ldap_mapping_rule_epochs"."priority" between 0 and 1000000),
	CONSTRAINT "tenant_ldap_mapping_rule_epochs_operator_target_check" CHECK (("tenant_ldap_mapping_rule_epochs"."operator_team_id" is null
          and "tenant_ldap_mapping_rule_epochs"."operator_team_assignment_epoch_id" is null)
        or ("tenant_ldap_mapping_rule_epochs"."operator_team_id" is not null
          and "tenant_ldap_mapping_rule_epochs"."operator_team_assignment_epoch_id" is not null)),
	CONSTRAINT "tenant_ldap_mapping_rule_epochs_lifecycle_check" CHECK (("tenant_ldap_mapping_rule_epochs"."ended_at" is null
          and "tenant_ldap_mapping_rule_epochs"."ended_by_membership_id" is null
          and "tenant_ldap_mapping_rule_epochs"."end_reason" is null
          and "tenant_ldap_mapping_rule_epochs"."version" = 1)
        or ("tenant_ldap_mapping_rule_epochs"."ended_at" is not null
          and "tenant_ldap_mapping_rule_epochs"."ended_by_membership_id" is not null
          and "tenant_ldap_mapping_rule_epochs"."end_reason" is not null
          and "tenant_ldap_mapping_rule_epochs"."ended_at" >= "tenant_ldap_mapping_rule_epochs"."activated_at"
          and btrim("tenant_ldap_mapping_rule_epochs"."end_reason") <> ''
          and char_length("tenant_ldap_mapping_rule_epochs"."end_reason") <= 500
          and "tenant_ldap_mapping_rule_epochs"."end_reason" !~ '[[:cntrl:]]'
          and "tenant_ldap_mapping_rule_epochs"."version" = 2))
);
--> statement-breakpoint
ALTER TABLE "tenant_ldap_mapping_rule_epochs" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_ldap_mapping_rule_role_targets" (
	"tenant_id" uuid NOT NULL,
	"mapping_rule_id" uuid NOT NULL,
	"configuration_revision" integer NOT NULL,
	"role_id" uuid NOT NULL,
	"role_principal_kind" "tenant_principal_kind" DEFAULT 'human' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_ldap_mapping_rule_role_targets_pkey" PRIMARY KEY("tenant_id","mapping_rule_id","configuration_revision","role_id"),
	CONSTRAINT "tenant_ldap_mapping_rule_role_targets_revision_check" CHECK ("tenant_ldap_mapping_rule_role_targets"."configuration_revision" > 0),
	CONSTRAINT "tenant_ldap_mapping_rule_role_targets_human_check" CHECK ("tenant_ldap_mapping_rule_role_targets"."role_principal_kind" = 'human')
);
--> statement-breakpoint
ALTER TABLE "tenant_ldap_mapping_rule_role_targets" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_ldap_mapping_rules" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"binding_id" uuid NOT NULL,
	"matcher_type" "ldap_mapping_matcher_type" NOT NULL,
	"matcher_value" text NOT NULL,
	"case_mode" "ldap_mapping_case_mode" NOT NULL,
	"priority" integer DEFAULT 100 NOT NULL,
	"tenant_security_group_id" uuid NOT NULL,
	"reconciliation_mode" "ldap_mapping_reconciliation_mode" NOT NULL,
	"operator_team_id" uuid,
	"operator_team_assignment_epoch_id" uuid,
	"configuration_revision" integer DEFAULT 1 NOT NULL,
	"enabled" boolean DEFAULT false NOT NULL,
	"current_source_epoch_id" uuid,
	"notes" text DEFAULT '' NOT NULL,
	"last_matched_at" timestamp with time zone,
	"created_by_membership_id" uuid NOT NULL,
	"updated_by_membership_id" uuid NOT NULL,
	"archived_at" timestamp with time zone,
	"archived_by_membership_id" uuid,
	"archive_reason" text,
	"version" integer DEFAULT 1 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_ldap_mapping_rules_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "tenant_ldap_mapping_rules_exact_binding_key" UNIQUE("tenant_id","id","binding_id"),
	CONSTRAINT "tenant_ldap_mapping_rules_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_ldap_mapping_rules"."id") = 7) is true),
	CONSTRAINT "tenant_ldap_mapping_rules_matcher_check" CHECK (btrim("tenant_ldap_mapping_rules"."matcher_value") <> ''
        and "tenant_ldap_mapping_rules"."matcher_value" !~ '[[:cntrl:]]'
        and (("tenant_ldap_mapping_rules"."matcher_type" = 'exact_dn'
            and char_length("tenant_ldap_mapping_rules"."matcher_value") <= 2048
            and octet_length("tenant_ldap_mapping_rules"."matcher_value") <= 8192)
          or ("tenant_ldap_mapping_rules"."matcher_type" in ('exact_cn', 'regex')
            and char_length("tenant_ldap_mapping_rules"."matcher_value") <= 512))),
	CONSTRAINT "tenant_ldap_mapping_rules_priority_check" CHECK ("tenant_ldap_mapping_rules"."priority" between 0 and 1000000),
	CONSTRAINT "tenant_ldap_mapping_rules_configuration_check" CHECK ("tenant_ldap_mapping_rules"."configuration_revision" > 0 and "tenant_ldap_mapping_rules"."version" > 0),
	CONSTRAINT "tenant_ldap_mapping_rules_operator_target_check" CHECK (("tenant_ldap_mapping_rules"."operator_team_id" is null
          and "tenant_ldap_mapping_rules"."operator_team_assignment_epoch_id" is null)
        or ("tenant_ldap_mapping_rules"."operator_team_id" is not null
          and "tenant_ldap_mapping_rules"."operator_team_assignment_epoch_id" is not null)),
	CONSTRAINT "tenant_ldap_mapping_rules_enabled_epoch_check" CHECK (("tenant_ldap_mapping_rules"."enabled" and "tenant_ldap_mapping_rules"."archived_at" is null
          and "tenant_ldap_mapping_rules"."current_source_epoch_id" is not null)
        or (not "tenant_ldap_mapping_rules"."enabled" and "tenant_ldap_mapping_rules"."current_source_epoch_id" is null)),
	CONSTRAINT "tenant_ldap_mapping_rules_notes_check" CHECK (char_length("tenant_ldap_mapping_rules"."notes") <= 2000
        and "tenant_ldap_mapping_rules"."notes" !~ '[[:cntrl:]]'),
	CONSTRAINT "tenant_ldap_mapping_rules_archive_check" CHECK (("tenant_ldap_mapping_rules"."archived_at" is null
          and "tenant_ldap_mapping_rules"."archived_by_membership_id" is null
          and "tenant_ldap_mapping_rules"."archive_reason" is null)
        or ("tenant_ldap_mapping_rules"."archived_at" is not null
          and "tenant_ldap_mapping_rules"."archived_by_membership_id" is not null
          and "tenant_ldap_mapping_rules"."archive_reason" is not null
          and not "tenant_ldap_mapping_rules"."enabled"
          and "tenant_ldap_mapping_rules"."current_source_epoch_id" is null
          and "tenant_ldap_mapping_rules"."archived_at" >= "tenant_ldap_mapping_rules"."created_at"
          and btrim("tenant_ldap_mapping_rules"."archive_reason") <> ''
          and char_length("tenant_ldap_mapping_rules"."archive_reason") <= 500
          and "tenant_ldap_mapping_rules"."archive_reason" !~ '[[:cntrl:]]')),
	CONSTRAINT "tenant_ldap_mapping_rules_timestamps_check" CHECK ("tenant_ldap_mapping_rules"."updated_at" >= "tenant_ldap_mapping_rules"."created_at"
        and ("tenant_ldap_mapping_rules"."last_matched_at" is null
          or "tenant_ldap_mapping_rules"."last_matched_at" >= "tenant_ldap_mapping_rules"."created_at")
        and ("tenant_ldap_mapping_rules"."archived_at" is null
          or "tenant_ldap_mapping_rules"."updated_at" >= "tenant_ldap_mapping_rules"."archived_at"))
);
--> statement-breakpoint
ALTER TABLE "tenant_ldap_mapping_rules" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "tenant_ldap_mapping_rule_epochs" ADD CONSTRAINT "tenant_ldap_mapping_rule_epochs_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_ldap_mapping_rule_epochs" ADD CONSTRAINT "tenant_ldap_mapping_rule_epochs_rule_fk" FOREIGN KEY ("tenant_id","mapping_rule_id","binding_id") REFERENCES "public"."tenant_ldap_mapping_rules"("tenant_id","id","binding_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_mapping_rule_epochs" ADD CONSTRAINT "tenant_ldap_mapping_rule_epochs_source_fk" FOREIGN KEY ("tenant_id","source_id") REFERENCES "public"."tenant_authorization_sources"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_mapping_rule_epochs" ADD CONSTRAINT "tenant_ldap_mapping_rule_epochs_group_fk" FOREIGN KEY ("tenant_id","tenant_security_group_id") REFERENCES "public"."tenant_security_groups"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_mapping_rule_epochs" ADD CONSTRAINT "tenant_ldap_mapping_rule_epochs_team_assignment_fk" FOREIGN KEY ("tenant_id","operator_team_assignment_epoch_id","operator_team_id") REFERENCES "public"."operator_team_assignment_epochs"("tenant_id","id","operator_team_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_mapping_rule_epochs" ADD CONSTRAINT "tenant_ldap_mapping_rule_epochs_activator_fk" FOREIGN KEY ("tenant_id","activated_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_mapping_rule_epochs" ADD CONSTRAINT "tenant_ldap_mapping_rule_epochs_ender_fk" FOREIGN KEY ("tenant_id","ended_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_mapping_rule_role_targets" ADD CONSTRAINT "tenant_ldap_mapping_rule_role_targets_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_ldap_mapping_rule_role_targets" ADD CONSTRAINT "tenant_ldap_mapping_rule_role_targets_rule_fk" FOREIGN KEY ("tenant_id","mapping_rule_id") REFERENCES "public"."tenant_ldap_mapping_rules"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_mapping_rule_role_targets" ADD CONSTRAINT "tenant_ldap_mapping_rule_role_targets_role_fk" FOREIGN KEY ("tenant_id","role_id","role_principal_kind") REFERENCES "public"."tenant_roles"("tenant_id","id","principal_kind") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_mapping_rules" ADD CONSTRAINT "tenant_ldap_mapping_rules_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_ldap_mapping_rules" ADD CONSTRAINT "tenant_ldap_mapping_rules_binding_fk" FOREIGN KEY ("tenant_id","binding_id") REFERENCES "public"."tenant_auth_provider_bindings"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_mapping_rules" ADD CONSTRAINT "tenant_ldap_mapping_rules_group_fk" FOREIGN KEY ("tenant_id","tenant_security_group_id") REFERENCES "public"."tenant_security_groups"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_mapping_rules" ADD CONSTRAINT "tenant_ldap_mapping_rules_team_assignment_fk" FOREIGN KEY ("tenant_id","operator_team_assignment_epoch_id","operator_team_id") REFERENCES "public"."operator_team_assignment_epochs"("tenant_id","id","operator_team_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_mapping_rules" ADD CONSTRAINT "tenant_ldap_mapping_rules_creator_fk" FOREIGN KEY ("tenant_id","created_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_mapping_rules" ADD CONSTRAINT "tenant_ldap_mapping_rules_updater_fk" FOREIGN KEY ("tenant_id","updated_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_mapping_rules" ADD CONSTRAINT "tenant_ldap_mapping_rules_archiver_fk" FOREIGN KEY ("tenant_id","archived_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_mapping_rules" ADD CONSTRAINT "tenant_ldap_mapping_rules_current_epoch_fk" FOREIGN KEY ("tenant_id","current_source_epoch_id","id","binding_id","configuration_revision") REFERENCES "public"."tenant_ldap_mapping_rule_epochs"("tenant_id","id","mapping_rule_id","binding_id","configuration_revision") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
CREATE UNIQUE INDEX "tenant_ldap_mapping_rule_epochs_live_rule_key" ON "tenant_ldap_mapping_rule_epochs" USING btree ("tenant_id","mapping_rule_id") WHERE "tenant_ldap_mapping_rule_epochs"."ended_at" is null;--> statement-breakpoint
CREATE INDEX "tenant_ldap_mapping_rule_epochs_tenant_binding_idx" ON "tenant_ldap_mapping_rule_epochs" USING btree ("tenant_id","binding_id","mapping_rule_id","sequence");--> statement-breakpoint
CREATE INDEX "tenant_ldap_mapping_rule_role_targets_role_idx" ON "tenant_ldap_mapping_rule_role_targets" USING btree ("tenant_id","role_id","mapping_rule_id","configuration_revision");--> statement-breakpoint
CREATE INDEX "tenant_ldap_mapping_rules_tenant_binding_order_idx" ON "tenant_ldap_mapping_rules" USING btree ("tenant_id","binding_id","enabled","priority","id");--> statement-breakpoint
CREATE INDEX "tenant_ldap_mapping_rules_tenant_group_idx" ON "tenant_ldap_mapping_rules" USING btree ("tenant_id","tenant_security_group_id","id");--> statement-breakpoint
CREATE INDEX "tenant_ldap_mapping_rules_tenant_team_idx" ON "tenant_ldap_mapping_rules" USING btree ("tenant_id","operator_team_assignment_epoch_id","id");