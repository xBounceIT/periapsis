ALTER TYPE "public"."authorization_source_kind" ADD VALUE 'identity_provider_access' BEFORE 'identity_mapping';--> statement-breakpoint
CREATE TABLE "tenant_auth_provider_bindings" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"provider_id" uuid NOT NULL,
	"key" text NOT NULL,
	"enabled" boolean DEFAULT false NOT NULL,
	"profile_priority" integer DEFAULT 100 NOT NULL,
	"auth_revision" integer DEFAULT 1 NOT NULL,
	"current_access_epoch_id" uuid,
	"created_by_membership_id" uuid NOT NULL,
	"updated_by_membership_id" uuid NOT NULL,
	"archived_at" timestamp with time zone,
	"archived_by_membership_id" uuid,
	"archive_reason" text,
	"version" integer DEFAULT 1 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_auth_provider_bindings_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "tenant_auth_provider_bindings_tenant_id_provider_id_key" UNIQUE("tenant_id","id","provider_id"),
	CONSTRAINT "tenant_auth_provider_bindings_tenant_provider_key" UNIQUE("tenant_id","provider_id"),
	CONSTRAINT "tenant_auth_provider_bindings_tenant_login_key" UNIQUE("tenant_id","key"),
	CONSTRAINT "tenant_auth_provider_bindings_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_auth_provider_bindings"."id") = 7) is true),
	CONSTRAINT "tenant_auth_provider_bindings_key_check" CHECK ("tenant_auth_provider_bindings"."key" = lower(btrim("tenant_auth_provider_bindings"."key"))
        and "tenant_auth_provider_bindings"."key" ~ '^[a-z][a-z0-9_-]{2,63}$'),
	CONSTRAINT "tenant_auth_provider_bindings_priority_check" CHECK ("tenant_auth_provider_bindings"."profile_priority" between 0 and 1000000),
	CONSTRAINT "tenant_auth_provider_bindings_revision_check" CHECK ("tenant_auth_provider_bindings"."auth_revision" > 0 and "tenant_auth_provider_bindings"."version" > 0),
	CONSTRAINT "tenant_auth_provider_bindings_live_epoch_check" CHECK (("tenant_auth_provider_bindings"."enabled" and "tenant_auth_provider_bindings"."archived_at" is null
          and "tenant_auth_provider_bindings"."current_access_epoch_id" is not null)
        or (not "tenant_auth_provider_bindings"."enabled" and "tenant_auth_provider_bindings"."current_access_epoch_id" is null)),
	CONSTRAINT "tenant_auth_provider_bindings_archive_check" CHECK (("tenant_auth_provider_bindings"."archived_at" is null
          and "tenant_auth_provider_bindings"."archived_by_membership_id" is null
          and "tenant_auth_provider_bindings"."archive_reason" is null)
        or ("tenant_auth_provider_bindings"."archived_at" is not null
          and "tenant_auth_provider_bindings"."archived_by_membership_id" is not null
          and "tenant_auth_provider_bindings"."archive_reason" is not null
          and not "tenant_auth_provider_bindings"."enabled"
          and "tenant_auth_provider_bindings"."current_access_epoch_id" is null
          and "tenant_auth_provider_bindings"."archived_at" >= "tenant_auth_provider_bindings"."created_at"
          and btrim("tenant_auth_provider_bindings"."archive_reason") <> ''
          and char_length("tenant_auth_provider_bindings"."archive_reason") <= 500
          and "tenant_auth_provider_bindings"."archive_reason" !~ '[[:cntrl:]]')),
	CONSTRAINT "tenant_auth_provider_bindings_updated_check" CHECK ("tenant_auth_provider_bindings"."updated_at" >= "tenant_auth_provider_bindings"."created_at"
        and ("tenant_auth_provider_bindings"."archived_at" is null or "tenant_auth_provider_bindings"."updated_at" >= "tenant_auth_provider_bindings"."archived_at"))
);
--> statement-breakpoint
ALTER TABLE "tenant_auth_provider_bindings" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_identity_provider_access_epochs" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"binding_id" uuid NOT NULL,
	"provider_id" uuid NOT NULL,
	"source_id" uuid NOT NULL,
	"sequence" integer NOT NULL,
	"started_by_membership_id" uuid NOT NULL,
	"started_at" timestamp with time zone DEFAULT now() NOT NULL,
	"ended_at" timestamp with time zone,
	"ended_by_membership_id" uuid,
	"end_reason" text,
	"version" integer DEFAULT 1 NOT NULL,
	CONSTRAINT "tenant_identity_provider_access_epochs_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "tenant_identity_provider_access_epochs_exact_key" UNIQUE("tenant_id","id","binding_id","provider_id","source_id"),
	CONSTRAINT "tenant_identity_provider_access_epochs_current_key" UNIQUE("tenant_id","id","binding_id","provider_id"),
	CONSTRAINT "tenant_identity_provider_access_epochs_binding_sequence_key" UNIQUE("tenant_id","binding_id","sequence"),
	CONSTRAINT "tenant_identity_provider_access_epochs_source_key" UNIQUE("tenant_id","source_id"),
	CONSTRAINT "tenant_identity_provider_access_epochs_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_identity_provider_access_epochs"."id") = 7) is true),
	CONSTRAINT "tenant_identity_provider_access_epochs_sequence_check" CHECK ("tenant_identity_provider_access_epochs"."sequence" > 0),
	CONSTRAINT "tenant_identity_provider_access_epochs_lifecycle_check" CHECK (("tenant_identity_provider_access_epochs"."ended_at" is null
          and "tenant_identity_provider_access_epochs"."ended_by_membership_id" is null
          and "tenant_identity_provider_access_epochs"."end_reason" is null
          and "tenant_identity_provider_access_epochs"."version" = 1)
        or ("tenant_identity_provider_access_epochs"."ended_at" is not null
          and "tenant_identity_provider_access_epochs"."ended_by_membership_id" is not null
          and "tenant_identity_provider_access_epochs"."end_reason" is not null
          and "tenant_identity_provider_access_epochs"."ended_at" >= "tenant_identity_provider_access_epochs"."started_at"
          and btrim("tenant_identity_provider_access_epochs"."end_reason") <> ''
          and char_length("tenant_identity_provider_access_epochs"."end_reason") <= 500
          and "tenant_identity_provider_access_epochs"."end_reason" !~ '[[:cntrl:]]'
          and "tenant_identity_provider_access_epochs"."version" = 2))
);
--> statement-breakpoint
ALTER TABLE "tenant_identity_provider_access_epochs" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_ldap_external_identities" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"provider_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"subject_format" "identity_subject_format" NOT NULL,
	"subject_ciphertext" "bytea" NOT NULL,
	"subject_nonce" "bytea" NOT NULL,
	"key_version" integer NOT NULL,
	"encryption_algorithm" text DEFAULT 'aes-256-gcm' NOT NULL,
	"admitted_configuration_version" integer NOT NULL,
	"admitted_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_observed_at" timestamp with time zone DEFAULT now() NOT NULL,
	"retired_at" timestamp with time zone,
	"retired_by_membership_id" uuid,
	"retire_reason" text,
	"version" integer DEFAULT 1 NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_ldap_external_identities_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "tenant_ldap_external_identities_exact_key" UNIQUE("tenant_id","provider_id","id","user_id"),
	CONSTRAINT "tenant_ldap_external_identities_provider_id_key" UNIQUE("tenant_id","provider_id","id"),
	CONSTRAINT "tenant_ldap_external_identities_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_ldap_external_identities"."id") = 7) is true),
	CONSTRAINT "tenant_ldap_external_identities_ciphertext_check" CHECK (octet_length("tenant_ldap_external_identities"."subject_ciphertext") between 17 and 4112
        and octet_length("tenant_ldap_external_identities"."subject_nonce") = 12),
	CONSTRAINT "tenant_ldap_external_identities_algorithm_check" CHECK ("tenant_ldap_external_identities"."encryption_algorithm" = 'aes-256-gcm'),
	CONSTRAINT "tenant_ldap_external_identities_revision_check" CHECK ("tenant_ldap_external_identities"."admitted_configuration_version" > 0 and "tenant_ldap_external_identities"."version" > 0),
	CONSTRAINT "tenant_ldap_external_identities_lifecycle_check" CHECK ("tenant_ldap_external_identities"."last_observed_at" >= "tenant_ldap_external_identities"."admitted_at"
        and "tenant_ldap_external_identities"."updated_at" >= "tenant_ldap_external_identities"."admitted_at"
        and (("tenant_ldap_external_identities"."retired_at" is null
            and "tenant_ldap_external_identities"."retired_by_membership_id" is null
            and "tenant_ldap_external_identities"."retire_reason" is null)
          or ("tenant_ldap_external_identities"."retired_at" is not null
            and "tenant_ldap_external_identities"."retire_reason" is not null
            and "tenant_ldap_external_identities"."retired_at" >= "tenant_ldap_external_identities"."admitted_at"
            and "tenant_ldap_external_identities"."updated_at" >= "tenant_ldap_external_identities"."retired_at"
            and btrim("tenant_ldap_external_identities"."retire_reason") <> ''
            and char_length("tenant_ldap_external_identities"."retire_reason") <= 500
            and "tenant_ldap_external_identities"."retire_reason" !~ '[[:cntrl:]]')))
);
--> statement-breakpoint
ALTER TABLE "tenant_ldap_external_identities" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_ldap_external_identity_subject_aliases" (
	"id" uuid DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"provider_id" uuid NOT NULL,
	"external_identity_id" uuid NOT NULL,
	"digest_key_version" integer NOT NULL,
	"subject_digest" "bytea" NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"retired_at" timestamp with time zone,
	"retire_reason" text,
	CONSTRAINT "tenant_ldap_external_identity_subject_aliases_pkey" PRIMARY KEY("tenant_id","id"),
	CONSTRAINT "tenant_ldap_external_identity_subject_aliases_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_ldap_external_identity_subject_aliases"."id") = 7) is true),
	CONSTRAINT "tenant_ldap_external_identity_subject_aliases_digest_check" CHECK (octet_length("tenant_ldap_external_identity_subject_aliases"."subject_digest") = 32),
	CONSTRAINT "tenant_ldap_external_identity_subject_aliases_lifecycle_check" CHECK (("tenant_ldap_external_identity_subject_aliases"."retired_at" is null and "tenant_ldap_external_identity_subject_aliases"."retire_reason" is null)
        or ("tenant_ldap_external_identity_subject_aliases"."retired_at" is not null
          and "tenant_ldap_external_identity_subject_aliases"."retire_reason" is not null
          and "tenant_ldap_external_identity_subject_aliases"."retired_at" >= "tenant_ldap_external_identity_subject_aliases"."created_at"
          and btrim("tenant_ldap_external_identity_subject_aliases"."retire_reason") <> ''
          and char_length("tenant_ldap_external_identity_subject_aliases"."retire_reason") <= 500
          and "tenant_ldap_external_identity_subject_aliases"."retire_reason" !~ '[[:cntrl:]]'))
);
--> statement-breakpoint
ALTER TABLE "tenant_ldap_external_identity_subject_aliases" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_ldap_provider_access_grants" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"provider_id" uuid NOT NULL,
	"binding_id" uuid NOT NULL,
	"access_epoch_id" uuid NOT NULL,
	"source_id" uuid NOT NULL,
	"external_identity_id" uuid NOT NULL,
	"membership_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"configuration_version" integer NOT NULL,
	"started_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_observed_at" timestamp with time zone DEFAULT now() NOT NULL,
	"ended_at" timestamp with time zone,
	"end_reason" text,
	"version" integer DEFAULT 1 NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_ldap_provider_access_grants_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "tenant_ldap_provider_access_grants_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_ldap_provider_access_grants"."id") = 7) is true),
	CONSTRAINT "tenant_ldap_provider_access_grants_revision_check" CHECK ("tenant_ldap_provider_access_grants"."configuration_version" > 0 and "tenant_ldap_provider_access_grants"."version" > 0),
	CONSTRAINT "tenant_ldap_provider_access_grants_lifecycle_check" CHECK ("tenant_ldap_provider_access_grants"."last_observed_at" >= "tenant_ldap_provider_access_grants"."started_at"
        and "tenant_ldap_provider_access_grants"."updated_at" >= "tenant_ldap_provider_access_grants"."started_at"
        and (("tenant_ldap_provider_access_grants"."ended_at" is null and "tenant_ldap_provider_access_grants"."end_reason" is null)
          or ("tenant_ldap_provider_access_grants"."ended_at" is not null
            and "tenant_ldap_provider_access_grants"."end_reason" is not null
            and "tenant_ldap_provider_access_grants"."ended_at" >= "tenant_ldap_provider_access_grants"."started_at"
            and "tenant_ldap_provider_access_grants"."updated_at" >= "tenant_ldap_provider_access_grants"."ended_at"
            and btrim("tenant_ldap_provider_access_grants"."end_reason") <> ''
            and char_length("tenant_ldap_provider_access_grants"."end_reason") <= 500
            and "tenant_ldap_provider_access_grants"."end_reason" !~ '[[:cntrl:]]')))
);
--> statement-breakpoint
ALTER TABLE "tenant_ldap_provider_access_grants" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_ldap_provider_profile_contributions" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"access_grant_id" uuid NOT NULL,
	"display_name" text,
	"first_name" text,
	"last_name" text,
	"username" text,
	"email" text,
	"configuration_version" integer NOT NULL,
	"observed_at" timestamp with time zone DEFAULT now() NOT NULL,
	"retired_at" timestamp with time zone,
	"retire_reason" text,
	"version" integer DEFAULT 1 NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_ldap_provider_profile_contributions_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "tenant_ldap_provider_profile_contributions_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_ldap_provider_profile_contributions"."id") = 7) is true),
	CONSTRAINT "tenant_ldap_provider_profile_contributions_present_check" CHECK ("tenant_ldap_provider_profile_contributions"."display_name" is not null
        or "tenant_ldap_provider_profile_contributions"."first_name" is not null
        or "tenant_ldap_provider_profile_contributions"."last_name" is not null
        or "tenant_ldap_provider_profile_contributions"."username" is not null
        or "tenant_ldap_provider_profile_contributions"."email" is not null),
	CONSTRAINT "tenant_ldap_provider_profile_contributions_name_check" CHECK (("tenant_ldap_provider_profile_contributions"."display_name" is null or (
          btrim("tenant_ldap_provider_profile_contributions"."display_name") <> ''
          and char_length("tenant_ldap_provider_profile_contributions"."display_name") <= 160
          and "tenant_ldap_provider_profile_contributions"."display_name" !~ '[[:cntrl:]]'
        )) and ("tenant_ldap_provider_profile_contributions"."first_name" is null or (
          btrim("tenant_ldap_provider_profile_contributions"."first_name") <> ''
          and char_length("tenant_ldap_provider_profile_contributions"."first_name") <= 160
          and "tenant_ldap_provider_profile_contributions"."first_name" !~ '[[:cntrl:]]'
        )) and ("tenant_ldap_provider_profile_contributions"."last_name" is null or (
          btrim("tenant_ldap_provider_profile_contributions"."last_name") <> ''
          and char_length("tenant_ldap_provider_profile_contributions"."last_name") <= 160
          and "tenant_ldap_provider_profile_contributions"."last_name" !~ '[[:cntrl:]]'
        ))),
	CONSTRAINT "tenant_ldap_provider_profile_contributions_username_check" CHECK ("tenant_ldap_provider_profile_contributions"."username" is null or (
        btrim("tenant_ldap_provider_profile_contributions"."username") <> ''
        and char_length("tenant_ldap_provider_profile_contributions"."username") <= 320
        and "tenant_ldap_provider_profile_contributions"."username" !~ '[[:cntrl:]]'
      )),
	CONSTRAINT "tenant_ldap_provider_profile_contributions_email_check" CHECK ("tenant_ldap_provider_profile_contributions"."email" is null or (
        "tenant_ldap_provider_profile_contributions"."email" = lower(btrim("tenant_ldap_provider_profile_contributions"."email"))
        and position('@' in "tenant_ldap_provider_profile_contributions"."email") > 1
        and char_length("tenant_ldap_provider_profile_contributions"."email") <= 320
        and "tenant_ldap_provider_profile_contributions"."email" !~ '[[:cntrl:]]'
      )),
	CONSTRAINT "tenant_ldap_provider_profile_contributions_lifecycle_check" CHECK ("tenant_ldap_provider_profile_contributions"."configuration_version" > 0
        and "tenant_ldap_provider_profile_contributions"."version" > 0
        and "tenant_ldap_provider_profile_contributions"."updated_at" >= "tenant_ldap_provider_profile_contributions"."observed_at"
        and (("tenant_ldap_provider_profile_contributions"."retired_at" is null and "tenant_ldap_provider_profile_contributions"."retire_reason" is null)
          or ("tenant_ldap_provider_profile_contributions"."retired_at" is not null
            and "tenant_ldap_provider_profile_contributions"."retire_reason" is not null
            and "tenant_ldap_provider_profile_contributions"."retired_at" >= "tenant_ldap_provider_profile_contributions"."observed_at"
            and "tenant_ldap_provider_profile_contributions"."updated_at" >= "tenant_ldap_provider_profile_contributions"."retired_at"
            and btrim("tenant_ldap_provider_profile_contributions"."retire_reason") <> ''
            and char_length("tenant_ldap_provider_profile_contributions"."retire_reason") <= 500
            and "tenant_ldap_provider_profile_contributions"."retire_reason" !~ '[[:cntrl:]]')))
);
--> statement-breakpoint
ALTER TABLE "tenant_ldap_provider_profile_contributions" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_user_manual_profile_overrides" (
	"tenant_id" uuid NOT NULL,
	"membership_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"display_name" text,
	"first_name" text,
	"last_name" text,
	"username" text,
	"email" text,
	"reason" text NOT NULL,
	"updated_by_membership_id" uuid NOT NULL,
	"version" integer DEFAULT 1 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_user_manual_profile_overrides_pkey" PRIMARY KEY("tenant_id","membership_id"),
	CONSTRAINT "tenant_user_manual_profile_overrides_tenant_user_key" UNIQUE("tenant_id","user_id"),
	CONSTRAINT "tenant_user_manual_profile_overrides_present_check" CHECK ("tenant_user_manual_profile_overrides"."display_name" is not null
        or "tenant_user_manual_profile_overrides"."first_name" is not null
        or "tenant_user_manual_profile_overrides"."last_name" is not null
        or "tenant_user_manual_profile_overrides"."username" is not null
        or "tenant_user_manual_profile_overrides"."email" is not null),
	CONSTRAINT "tenant_user_manual_profile_overrides_name_check" CHECK (("tenant_user_manual_profile_overrides"."display_name" is null or (
          btrim("tenant_user_manual_profile_overrides"."display_name") <> ''
          and char_length("tenant_user_manual_profile_overrides"."display_name") <= 160
          and "tenant_user_manual_profile_overrides"."display_name" !~ '[[:cntrl:]]'
        )) and ("tenant_user_manual_profile_overrides"."first_name" is null or (
          btrim("tenant_user_manual_profile_overrides"."first_name") <> ''
          and char_length("tenant_user_manual_profile_overrides"."first_name") <= 160
          and "tenant_user_manual_profile_overrides"."first_name" !~ '[[:cntrl:]]'
        )) and ("tenant_user_manual_profile_overrides"."last_name" is null or (
          btrim("tenant_user_manual_profile_overrides"."last_name") <> ''
          and char_length("tenant_user_manual_profile_overrides"."last_name") <= 160
          and "tenant_user_manual_profile_overrides"."last_name" !~ '[[:cntrl:]]'
        ))),
	CONSTRAINT "tenant_user_manual_profile_overrides_username_check" CHECK ("tenant_user_manual_profile_overrides"."username" is null or (
        btrim("tenant_user_manual_profile_overrides"."username") <> ''
        and char_length("tenant_user_manual_profile_overrides"."username") <= 320
        and "tenant_user_manual_profile_overrides"."username" !~ '[[:cntrl:]]'
      )),
	CONSTRAINT "tenant_user_manual_profile_overrides_email_check" CHECK ("tenant_user_manual_profile_overrides"."email" is null or (
        "tenant_user_manual_profile_overrides"."email" = lower(btrim("tenant_user_manual_profile_overrides"."email"))
        and position('@' in "tenant_user_manual_profile_overrides"."email") > 1
        and char_length("tenant_user_manual_profile_overrides"."email") <= 320
        and "tenant_user_manual_profile_overrides"."email" !~ '[[:cntrl:]]'
      )),
	CONSTRAINT "tenant_user_manual_profile_overrides_reason_check" CHECK (btrim("tenant_user_manual_profile_overrides"."reason") <> ''
        and char_length("tenant_user_manual_profile_overrides"."reason") <= 500
        and "tenant_user_manual_profile_overrides"."reason" !~ '[[:cntrl:]]'),
	CONSTRAINT "tenant_user_manual_profile_overrides_version_check" CHECK ("tenant_user_manual_profile_overrides"."version" > 0 and "tenant_user_manual_profile_overrides"."updated_at" >= "tenant_user_manual_profile_overrides"."created_at")
);
--> statement-breakpoint
ALTER TABLE "tenant_user_manual_profile_overrides" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "tenant_auth_provider_bindings" ADD CONSTRAINT "tenant_auth_provider_bindings_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_auth_provider_bindings" ADD CONSTRAINT "tenant_auth_provider_bindings_provider_fk" FOREIGN KEY ("tenant_id","provider_id") REFERENCES "public"."tenant_auth_providers"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_auth_provider_bindings" ADD CONSTRAINT "tenant_auth_provider_bindings_creator_fk" FOREIGN KEY ("tenant_id","created_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_auth_provider_bindings" ADD CONSTRAINT "tenant_auth_provider_bindings_updater_fk" FOREIGN KEY ("tenant_id","updated_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_auth_provider_bindings" ADD CONSTRAINT "tenant_auth_provider_bindings_archiver_fk" FOREIGN KEY ("tenant_id","archived_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_auth_provider_bindings" ADD CONSTRAINT "tenant_auth_provider_bindings_current_epoch_fk" FOREIGN KEY ("tenant_id","current_access_epoch_id","id","provider_id") REFERENCES "public"."tenant_identity_provider_access_epochs"("tenant_id","id","binding_id","provider_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_identity_provider_access_epochs" ADD CONSTRAINT "tenant_identity_provider_access_epochs_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_identity_provider_access_epochs" ADD CONSTRAINT "tenant_identity_provider_access_epochs_binding_fk" FOREIGN KEY ("tenant_id","binding_id","provider_id") REFERENCES "public"."tenant_auth_provider_bindings"("tenant_id","id","provider_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_identity_provider_access_epochs" ADD CONSTRAINT "tenant_identity_provider_access_epochs_source_fk" FOREIGN KEY ("tenant_id","source_id") REFERENCES "public"."tenant_authorization_sources"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_identity_provider_access_epochs" ADD CONSTRAINT "tenant_identity_provider_access_epochs_starter_fk" FOREIGN KEY ("tenant_id","started_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_identity_provider_access_epochs" ADD CONSTRAINT "tenant_identity_provider_access_epochs_ender_fk" FOREIGN KEY ("tenant_id","ended_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_external_identities" ADD CONSTRAINT "tenant_ldap_external_identities_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_ldap_external_identities" ADD CONSTRAINT "tenant_ldap_external_identities_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_ldap_external_identities" ADD CONSTRAINT "tenant_ldap_external_identities_key_version_identity_keyring_versions_key_version_fk" FOREIGN KEY ("key_version") REFERENCES "public"."identity_keyring_versions"("key_version") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_ldap_external_identities" ADD CONSTRAINT "tenant_ldap_external_identities_provider_fk" FOREIGN KEY ("tenant_id","provider_id") REFERENCES "public"."tenant_auth_providers"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_external_identities" ADD CONSTRAINT "tenant_ldap_external_identities_retired_by_fk" FOREIGN KEY ("tenant_id","retired_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_external_identity_subject_aliases" ADD CONSTRAINT "tenant_ldap_external_identity_subject_aliases_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_ldap_external_identity_subject_aliases" ADD CONSTRAINT "tenant_ldap_external_identity_subject_aliases_digest_key_version_identity_keyring_versions_key_version_fk" FOREIGN KEY ("digest_key_version") REFERENCES "public"."identity_keyring_versions"("key_version") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_ldap_external_identity_subject_aliases" ADD CONSTRAINT "tenant_ldap_external_identity_subject_aliases_identity_fk" FOREIGN KEY ("tenant_id","provider_id","external_identity_id") REFERENCES "public"."tenant_ldap_external_identities"("tenant_id","provider_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_provider_access_grants" ADD CONSTRAINT "tenant_ldap_provider_access_grants_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_ldap_provider_access_grants" ADD CONSTRAINT "tenant_ldap_provider_access_grants_epoch_source_fk" FOREIGN KEY ("tenant_id","access_epoch_id","binding_id","provider_id","source_id") REFERENCES "public"."tenant_identity_provider_access_epochs"("tenant_id","id","binding_id","provider_id","source_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_provider_access_grants" ADD CONSTRAINT "tenant_ldap_provider_access_grants_identity_user_fk" FOREIGN KEY ("tenant_id","provider_id","external_identity_id","user_id") REFERENCES "public"."tenant_ldap_external_identities"("tenant_id","provider_id","id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_provider_access_grants" ADD CONSTRAINT "tenant_ldap_provider_access_grants_membership_user_fk" FOREIGN KEY ("tenant_id","membership_id","user_id") REFERENCES "public"."tenant_memberships"("tenant_id","id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_provider_profile_contributions" ADD CONSTRAINT "tenant_ldap_provider_profile_contributions_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_ldap_provider_profile_contributions" ADD CONSTRAINT "tenant_ldap_provider_profile_contributions_grant_fk" FOREIGN KEY ("tenant_id","access_grant_id") REFERENCES "public"."tenant_ldap_provider_access_grants"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_user_manual_profile_overrides" ADD CONSTRAINT "tenant_user_manual_profile_overrides_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_user_manual_profile_overrides" ADD CONSTRAINT "tenant_user_manual_profile_overrides_membership_user_fk" FOREIGN KEY ("tenant_id","membership_id","user_id") REFERENCES "public"."tenant_memberships"("tenant_id","id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_user_manual_profile_overrides" ADD CONSTRAINT "tenant_user_manual_profile_overrides_updater_fk" FOREIGN KEY ("tenant_id","updated_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
CREATE INDEX "tenant_auth_provider_bindings_tenant_enabled_idx" ON "tenant_auth_provider_bindings" USING btree ("tenant_id","enabled","key","id");--> statement-breakpoint
CREATE INDEX "tenant_auth_provider_bindings_tenant_profile_priority_idx" ON "tenant_auth_provider_bindings" USING btree ("tenant_id","profile_priority","id");--> statement-breakpoint
CREATE UNIQUE INDEX "tenant_identity_provider_access_epochs_live_binding_key" ON "tenant_identity_provider_access_epochs" USING btree ("tenant_id","binding_id") WHERE "tenant_identity_provider_access_epochs"."ended_at" is null;--> statement-breakpoint
CREATE INDEX "tenant_identity_provider_access_epochs_tenant_provider_idx" ON "tenant_identity_provider_access_epochs" USING btree ("tenant_id","provider_id","binding_id","sequence");--> statement-breakpoint
CREATE UNIQUE INDEX "tenant_ldap_external_identities_live_provider_user_key" ON "tenant_ldap_external_identities" USING btree ("tenant_id","provider_id","user_id") WHERE "tenant_ldap_external_identities"."retired_at" is null;--> statement-breakpoint
CREATE INDEX "tenant_ldap_external_identities_tenant_user_idx" ON "tenant_ldap_external_identities" USING btree ("tenant_id","user_id","provider_id","id");--> statement-breakpoint
CREATE INDEX "tenant_ldap_external_identities_tenant_key_version_idx" ON "tenant_ldap_external_identities" USING btree ("tenant_id","key_version","provider_id","id");--> statement-breakpoint
CREATE UNIQUE INDEX "tenant_ldap_external_identity_subject_aliases_live_digest_key" ON "tenant_ldap_external_identity_subject_aliases" USING btree ("tenant_id","provider_id","digest_key_version","subject_digest") WHERE "tenant_ldap_external_identity_subject_aliases"."retired_at" is null;--> statement-breakpoint
CREATE UNIQUE INDEX "tenant_ldap_external_identity_subject_aliases_live_version_key" ON "tenant_ldap_external_identity_subject_aliases" USING btree ("tenant_id","external_identity_id","digest_key_version") WHERE "tenant_ldap_external_identity_subject_aliases"."retired_at" is null;--> statement-breakpoint
CREATE INDEX "tenant_ldap_external_identity_subject_aliases_identity_idx" ON "tenant_ldap_external_identity_subject_aliases" USING btree ("tenant_id","external_identity_id","digest_key_version","id");--> statement-breakpoint
CREATE INDEX "tenant_ldap_external_identity_subject_aliases_key_version_idx" ON "tenant_ldap_external_identity_subject_aliases" USING btree ("tenant_id","digest_key_version","provider_id","id");--> statement-breakpoint
CREATE UNIQUE INDEX "tenant_ldap_provider_access_grants_live_binding_member_key" ON "tenant_ldap_provider_access_grants" USING btree ("tenant_id","binding_id","membership_id") WHERE "tenant_ldap_provider_access_grants"."ended_at" is null;--> statement-breakpoint
CREATE UNIQUE INDEX "tenant_ldap_provider_access_grants_live_epoch_identity_key" ON "tenant_ldap_provider_access_grants" USING btree ("tenant_id","access_epoch_id","external_identity_id") WHERE "tenant_ldap_provider_access_grants"."ended_at" is null;--> statement-breakpoint
CREATE INDEX "tenant_ldap_provider_access_grants_tenant_membership_idx" ON "tenant_ldap_provider_access_grants" USING btree ("tenant_id","membership_id","binding_id","id");--> statement-breakpoint
CREATE INDEX "tenant_ldap_provider_access_grants_tenant_source_idx" ON "tenant_ldap_provider_access_grants" USING btree ("tenant_id","source_id","membership_id","id");--> statement-breakpoint
CREATE UNIQUE INDEX "tenant_ldap_provider_profile_contributions_live_grant_key" ON "tenant_ldap_provider_profile_contributions" USING btree ("tenant_id","access_grant_id") WHERE "tenant_ldap_provider_profile_contributions"."retired_at" is null;--> statement-breakpoint
CREATE INDEX "tenant_ldap_provider_profile_contributions_tenant_observed_idx" ON "tenant_ldap_provider_profile_contributions" USING btree ("tenant_id","observed_at","id");--> statement-breakpoint
CREATE INDEX "tenant_user_manual_profile_overrides_tenant_updater_idx" ON "tenant_user_manual_profile_overrides" USING btree ("tenant_id","updated_by_membership_id","membership_id");