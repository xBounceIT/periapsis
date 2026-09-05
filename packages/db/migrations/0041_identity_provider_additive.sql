CREATE TYPE "public"."auth_provider_kind" AS ENUM('ldap', 'oidc', 'saml');--> statement-breakpoint
CREATE TYPE "public"."identity_deprovision_mode" AS ENUM('retain', 'immediate', 'grace');--> statement-breakpoint
CREATE TYPE "public"."identity_jit_mode" AS ENUM('disabled', 'existing_identity', 'create');--> statement-breakpoint
CREATE TYPE "public"."identity_no_match_policy" AS ENUM('deny', 'provider_access_only');--> statement-breakpoint
CREATE TYPE "public"."identity_subject_format" AS ENUM('ad_object_guid', 'entry_uuid', 'utf8_exact', 'utf8_casefold');--> statement-breakpoint
CREATE TYPE "public"."ldap_account_status_mode" AS ENUM('none', 'active_directory_uac', 'attribute_equals');--> statement-breakpoint
CREATE TYPE "public"."ldap_nested_group_mode" AS ENUM('disabled', 'active_directory', 'reverse_search', 'posix_member_uid');--> statement-breakpoint
CREATE TYPE "public"."ldap_provider_template" AS ENUM('active_directory', 'openldap', 'posix', 'custom');--> statement-breakpoint
CREATE TYPE "public"."ldap_referral_mode" AS ENUM('disabled', 'configured_endpoints');--> statement-breakpoint
CREATE TYPE "public"."ldap_transport" AS ENUM('ldaps', 'starttls');--> statement-breakpoint
CREATE TYPE "public"."login_identifier_kind" AS ENUM('local_email');--> statement-breakpoint
CREATE TABLE "tenant_user_profiles" (
	"tenant_id" uuid NOT NULL,
	"membership_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"display_name" text NOT NULL,
	"first_name" text,
	"last_name" text,
	"username" text,
	"email" text,
	"version" integer DEFAULT 1 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_user_profiles_pkey" PRIMARY KEY("tenant_id","membership_id"),
	CONSTRAINT "tenant_user_profiles_tenant_user_key" UNIQUE("tenant_id","user_id"),
	CONSTRAINT "tenant_user_profiles_display_name_check" CHECK (btrim("tenant_user_profiles"."display_name") <> ''
        and char_length("tenant_user_profiles"."display_name") <= 160
        and "tenant_user_profiles"."display_name" !~ '[[:cntrl:]]'),
	CONSTRAINT "tenant_user_profiles_name_check" CHECK (("tenant_user_profiles"."first_name" is null or (
          btrim("tenant_user_profiles"."first_name") <> ''
          and char_length("tenant_user_profiles"."first_name") <= 160
          and "tenant_user_profiles"."first_name" !~ '[[:cntrl:]]'
        )) and ("tenant_user_profiles"."last_name" is null or (
          btrim("tenant_user_profiles"."last_name") <> ''
          and char_length("tenant_user_profiles"."last_name") <= 160
          and "tenant_user_profiles"."last_name" !~ '[[:cntrl:]]'
        ))),
	CONSTRAINT "tenant_user_profiles_username_check" CHECK ("tenant_user_profiles"."username" is null or (
        btrim("tenant_user_profiles"."username") <> ''
        and char_length("tenant_user_profiles"."username") <= 320
        and "tenant_user_profiles"."username" !~ '[[:cntrl:]]'
      )),
	CONSTRAINT "tenant_user_profiles_email_check" CHECK ("tenant_user_profiles"."email" is null or (
        "tenant_user_profiles"."email" = lower(btrim("tenant_user_profiles"."email"))
        and position('@' in "tenant_user_profiles"."email") > 1
        and char_length("tenant_user_profiles"."email") <= 320
        and "tenant_user_profiles"."email" !~ '[[:cntrl:]]'
      )),
	CONSTRAINT "tenant_user_profiles_version_check" CHECK ("tenant_user_profiles"."version" > 0),
	CONSTRAINT "tenant_user_profiles_updated_check" CHECK ("tenant_user_profiles"."updated_at" >= "tenant_user_profiles"."created_at")
);
--> statement-breakpoint
ALTER TABLE "tenant_user_profiles" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "user_login_identifiers" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"user_id" uuid NOT NULL,
	"kind" "login_identifier_kind" NOT NULL,
	"canonical_value" text NOT NULL,
	"verified_at" timestamp with time zone,
	"retired_at" timestamp with time zone,
	"retire_reason" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "user_login_identifiers_id_user_key" UNIQUE("id","user_id"),
	CONSTRAINT "user_login_identifiers_kind_value_key" UNIQUE("kind","canonical_value"),
	CONSTRAINT "user_login_identifiers_id_uuidv7_check" CHECK ((uuid_extract_version("user_login_identifiers"."id") = 7) is true),
	CONSTRAINT "user_login_identifiers_local_email_check" CHECK ("user_login_identifiers"."kind" <> 'local_email' or (
        "user_login_identifiers"."canonical_value" = lower(btrim("user_login_identifiers"."canonical_value"))
        and position('@' in "user_login_identifiers"."canonical_value") > 1
        and char_length("user_login_identifiers"."canonical_value") <= 320
        and "user_login_identifiers"."canonical_value" !~ '[[:cntrl:]]'
      )),
	CONSTRAINT "user_login_identifiers_retirement_check" CHECK (("user_login_identifiers"."retired_at" is null and "user_login_identifiers"."retire_reason" is null)
        or ("user_login_identifiers"."retired_at" is not null
          and "user_login_identifiers"."retire_reason" is not null
          and "user_login_identifiers"."retired_at" >= "user_login_identifiers"."created_at"
          and btrim("user_login_identifiers"."retire_reason") <> ''
          and char_length("user_login_identifiers"."retire_reason") <= 500
          and "user_login_identifiers"."retire_reason" !~ '[[:cntrl:]]')),
	CONSTRAINT "user_login_identifiers_timestamps_check" CHECK ("user_login_identifiers"."updated_at" >= "user_login_identifiers"."created_at"
        and ("user_login_identifiers"."verified_at" is null or "user_login_identifiers"."verified_at" >= "user_login_identifiers"."created_at")
        and ("user_login_identifiers"."retired_at" is null or "user_login_identifiers"."updated_at" >= "user_login_identifiers"."retired_at"))
);
--> statement-breakpoint
ALTER TABLE "user_login_identifiers" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "identity_keyring_versions" (
	"key_version" integer PRIMARY KEY NOT NULL,
	"verifier" "bytea" NOT NULL,
	"bound_at" timestamp with time zone DEFAULT now() NOT NULL,
	"retired_at" timestamp with time zone,
	CONSTRAINT "identity_keyring_versions_verifier_key" UNIQUE("verifier"),
	CONSTRAINT "identity_keyring_versions_version_check" CHECK ("identity_keyring_versions"."key_version" between 1 and 32767),
	CONSTRAINT "identity_keyring_versions_verifier_check" CHECK (octet_length("identity_keyring_versions"."verifier") = 32),
	CONSTRAINT "identity_keyring_versions_retirement_check" CHECK ("identity_keyring_versions"."retired_at" is null or "identity_keyring_versions"."retired_at" >= "identity_keyring_versions"."bound_at")
);
--> statement-breakpoint
ALTER TABLE "identity_keyring_versions" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_auth_providers" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"key" text NOT NULL,
	"display_name" text NOT NULL,
	"description" text DEFAULT '' NOT NULL,
	"kind" "auth_provider_kind" NOT NULL,
	"enabled" boolean DEFAULT false NOT NULL,
	"created_by_membership_id" uuid NOT NULL,
	"updated_by_membership_id" uuid NOT NULL,
	"archived_at" timestamp with time zone,
	"archived_by_membership_id" uuid,
	"archive_reason" text,
	"version" integer DEFAULT 1 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_auth_providers_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "tenant_auth_providers_tenant_id_kind_key" UNIQUE("tenant_id","id","kind"),
	CONSTRAINT "tenant_auth_providers_tenant_key_key" UNIQUE("tenant_id","key"),
	CONSTRAINT "tenant_auth_providers_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_auth_providers"."id") = 7) is true),
	CONSTRAINT "tenant_auth_providers_implemented_kind_check" CHECK ("tenant_auth_providers"."kind" = 'ldap'),
	CONSTRAINT "tenant_auth_providers_key_check" CHECK ("tenant_auth_providers"."key" ~ '^[a-z][a-z0-9_-]{2,63}$'),
	CONSTRAINT "tenant_auth_providers_display_name_check" CHECK (btrim("tenant_auth_providers"."display_name") <> ''
        and char_length("tenant_auth_providers"."display_name") <= 120
        and "tenant_auth_providers"."display_name" !~ '[[:cntrl:]]'),
	CONSTRAINT "tenant_auth_providers_description_check" CHECK (char_length("tenant_auth_providers"."description") <= 1000
        and "tenant_auth_providers"."description" !~ '[[:cntrl:]]'),
	CONSTRAINT "tenant_auth_providers_archive_check" CHECK (("tenant_auth_providers"."archived_at" is null
          and "tenant_auth_providers"."archived_by_membership_id" is null
          and "tenant_auth_providers"."archive_reason" is null)
        or ("tenant_auth_providers"."archived_at" is not null
          and "tenant_auth_providers"."archived_by_membership_id" is not null
          and "tenant_auth_providers"."archive_reason" is not null
          and "tenant_auth_providers"."enabled" is false
          and "tenant_auth_providers"."archived_at" >= "tenant_auth_providers"."created_at"
          and btrim("tenant_auth_providers"."archive_reason") <> ''
          and char_length("tenant_auth_providers"."archive_reason") <= 500
          and "tenant_auth_providers"."archive_reason" !~ '[[:cntrl:]]')),
	CONSTRAINT "tenant_auth_providers_version_check" CHECK ("tenant_auth_providers"."version" > 0),
	CONSTRAINT "tenant_auth_providers_updated_check" CHECK ("tenant_auth_providers"."updated_at" >= "tenant_auth_providers"."created_at"
        and ("tenant_auth_providers"."archived_at" is null or "tenant_auth_providers"."updated_at" >= "tenant_auth_providers"."archived_at"))
);
--> statement-breakpoint
ALTER TABLE "tenant_auth_providers" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_ldap_provider_configs" (
	"tenant_id" uuid NOT NULL,
	"provider_id" uuid NOT NULL,
	"provider_kind" "auth_provider_kind" DEFAULT 'ldap' NOT NULL,
	"template" "ldap_provider_template" NOT NULL,
	"verify_certificate" boolean DEFAULT true NOT NULL,
	"custom_ca_pem" text,
	"connect_timeout_ms" integer DEFAULT 3000 NOT NULL,
	"operation_timeout_ms" integer DEFAULT 10000 NOT NULL,
	"bind_dn" text NOT NULL,
	"user_base_dn" text NOT NULL,
	"group_base_dn" text,
	"user_search_filter" text NOT NULL,
	"group_search_filter" text,
	"user_dn_template" text,
	"page_size" integer DEFAULT 200 NOT NULL,
	"max_pages" integer DEFAULT 100 NOT NULL,
	"max_entries" integer DEFAULT 5000 NOT NULL,
	"max_response_bytes" integer DEFAULT 10485760 NOT NULL,
	"referral_mode" "ldap_referral_mode" DEFAULT 'disabled' NOT NULL,
	"max_referral_hops" integer DEFAULT 0 NOT NULL,
	"nested_group_mode" "ldap_nested_group_mode" DEFAULT 'disabled' NOT NULL,
	"max_nested_group_depth" integer DEFAULT 0 NOT NULL,
	"max_groups" integer DEFAULT 1000 NOT NULL,
	"first_name_attribute" text NOT NULL,
	"last_name_attribute" text NOT NULL,
	"display_name_attribute" text NOT NULL,
	"username_attribute" text NOT NULL,
	"alternate_username_attribute" text,
	"email_attribute" text,
	"immutable_subject_attribute" text NOT NULL,
	"immutable_subject_format" "identity_subject_format" NOT NULL,
	"group_membership_attribute" text,
	"posix_member_uid_attribute" text,
	"posix_gid_number_attribute" text,
	"account_status_mode" "ldap_account_status_mode" DEFAULT 'none' NOT NULL,
	"account_status_attribute" text,
	"account_disabled_value" text,
	"jit_mode" "identity_jit_mode" DEFAULT 'disabled' NOT NULL,
	"no_match_policy" "identity_no_match_policy" DEFAULT 'deny' NOT NULL,
	"deprovision_mode" "identity_deprovision_mode" DEFAULT 'retain' NOT NULL,
	"deprovision_grace_seconds" integer DEFAULT 0 NOT NULL,
	"sync_interval_seconds" integer,
	"updated_by_membership_id" uuid NOT NULL,
	"version" integer DEFAULT 1 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_ldap_provider_configs_pkey" PRIMARY KEY("tenant_id","provider_id"),
	CONSTRAINT "tenant_ldap_provider_configs_kind_check" CHECK ("tenant_ldap_provider_configs"."provider_kind" = 'ldap'),
	CONSTRAINT "tenant_ldap_provider_configs_ca_check" CHECK ("tenant_ldap_provider_configs"."custom_ca_pem" is null
        or char_length("tenant_ldap_provider_configs"."custom_ca_pem") between 1 and 131072),
	CONSTRAINT "tenant_ldap_provider_configs_timeout_check" CHECK ("tenant_ldap_provider_configs"."connect_timeout_ms" between 100 and 30000
        and "tenant_ldap_provider_configs"."operation_timeout_ms" between 100 and 60000
        and "tenant_ldap_provider_configs"."connect_timeout_ms" <= "tenant_ldap_provider_configs"."operation_timeout_ms"),
	CONSTRAINT "tenant_ldap_provider_configs_dn_check" CHECK (btrim("tenant_ldap_provider_configs"."bind_dn") <> ''
        and char_length("tenant_ldap_provider_configs"."bind_dn") <= 2048
        and btrim("tenant_ldap_provider_configs"."user_base_dn") <> ''
        and char_length("tenant_ldap_provider_configs"."user_base_dn") <= 2048
        and ("tenant_ldap_provider_configs"."group_base_dn" is null or (
          btrim("tenant_ldap_provider_configs"."group_base_dn") <> ''
          and char_length("tenant_ldap_provider_configs"."group_base_dn") <= 2048
        ))),
	CONSTRAINT "tenant_ldap_provider_configs_filter_check" CHECK (btrim("tenant_ldap_provider_configs"."user_search_filter") <> ''
        and char_length("tenant_ldap_provider_configs"."user_search_filter") <= 4096
        and ("tenant_ldap_provider_configs"."group_search_filter" is null or (
          btrim("tenant_ldap_provider_configs"."group_search_filter") <> ''
          and char_length("tenant_ldap_provider_configs"."group_search_filter") <= 4096
        ))
        and ("tenant_ldap_provider_configs"."user_dn_template" is null or (
          btrim("tenant_ldap_provider_configs"."user_dn_template") <> ''
          and char_length("tenant_ldap_provider_configs"."user_dn_template") <= 2048
        ))),
	CONSTRAINT "tenant_ldap_provider_configs_budget_check" CHECK ("tenant_ldap_provider_configs"."page_size" between 1 and 1000
        and "tenant_ldap_provider_configs"."max_pages" between 1 and 1000
        and "tenant_ldap_provider_configs"."max_entries" between 1 and 100000
        and "tenant_ldap_provider_configs"."max_response_bytes" between 1024 and 52428800
        and "tenant_ldap_provider_configs"."max_groups" between 1 and 10000),
	CONSTRAINT "tenant_ldap_provider_configs_referral_check" CHECK (("tenant_ldap_provider_configs"."referral_mode" = 'disabled' and "tenant_ldap_provider_configs"."max_referral_hops" = 0)
        or ("tenant_ldap_provider_configs"."referral_mode" = 'configured_endpoints'
          and "tenant_ldap_provider_configs"."max_referral_hops" between 1 and 3)),
	CONSTRAINT "tenant_ldap_provider_configs_nested_group_check" CHECK (("tenant_ldap_provider_configs"."nested_group_mode" = 'disabled' and "tenant_ldap_provider_configs"."max_nested_group_depth" = 0)
        or ("tenant_ldap_provider_configs"."nested_group_mode" <> 'disabled'
          and "tenant_ldap_provider_configs"."max_nested_group_depth" between 1 and 20)),
	CONSTRAINT "tenant_ldap_provider_configs_attribute_check" CHECK (btrim("tenant_ldap_provider_configs"."first_name_attribute") <> ''
        and btrim("tenant_ldap_provider_configs"."last_name_attribute") <> ''
        and btrim("tenant_ldap_provider_configs"."display_name_attribute") <> ''
        and btrim("tenant_ldap_provider_configs"."username_attribute") <> ''
        and btrim("tenant_ldap_provider_configs"."immutable_subject_attribute") <> ''
        and char_length("tenant_ldap_provider_configs"."first_name_attribute") <= 128
        and char_length("tenant_ldap_provider_configs"."last_name_attribute") <= 128
        and char_length("tenant_ldap_provider_configs"."display_name_attribute") <= 128
        and char_length("tenant_ldap_provider_configs"."username_attribute") <= 128
        and char_length("tenant_ldap_provider_configs"."immutable_subject_attribute") <= 128
        and ("tenant_ldap_provider_configs"."alternate_username_attribute" is null or (
          btrim("tenant_ldap_provider_configs"."alternate_username_attribute") <> ''
          and char_length("tenant_ldap_provider_configs"."alternate_username_attribute") <= 128
        ))
        and ("tenant_ldap_provider_configs"."email_attribute" is null or (
          btrim("tenant_ldap_provider_configs"."email_attribute") <> ''
          and char_length("tenant_ldap_provider_configs"."email_attribute") <= 128
        ))
        and ("tenant_ldap_provider_configs"."group_membership_attribute" is null or (
          btrim("tenant_ldap_provider_configs"."group_membership_attribute") <> ''
          and char_length("tenant_ldap_provider_configs"."group_membership_attribute") <= 128
        ))
        and ("tenant_ldap_provider_configs"."posix_member_uid_attribute" is null or (
          btrim("tenant_ldap_provider_configs"."posix_member_uid_attribute") <> ''
          and char_length("tenant_ldap_provider_configs"."posix_member_uid_attribute") <= 128
        ))
        and ("tenant_ldap_provider_configs"."posix_gid_number_attribute" is null or (
          btrim("tenant_ldap_provider_configs"."posix_gid_number_attribute") <> ''
          and char_length("tenant_ldap_provider_configs"."posix_gid_number_attribute") <= 128
        ))),
	CONSTRAINT "tenant_ldap_provider_configs_status_attribute_check" CHECK (("tenant_ldap_provider_configs"."account_status_mode" = 'none'
          and "tenant_ldap_provider_configs"."account_status_attribute" is null
          and "tenant_ldap_provider_configs"."account_disabled_value" is null)
        or ("tenant_ldap_provider_configs"."account_status_mode" = 'active_directory_uac'
          and "tenant_ldap_provider_configs"."account_status_attribute" is not null
          and btrim("tenant_ldap_provider_configs"."account_status_attribute") <> ''
          and char_length("tenant_ldap_provider_configs"."account_status_attribute") <= 128
          and "tenant_ldap_provider_configs"."account_disabled_value" is null)
        or ("tenant_ldap_provider_configs"."account_status_mode" = 'attribute_equals'
          and "tenant_ldap_provider_configs"."account_status_attribute" is not null
          and btrim("tenant_ldap_provider_configs"."account_status_attribute") <> ''
          and char_length("tenant_ldap_provider_configs"."account_status_attribute") <= 128
          and "tenant_ldap_provider_configs"."account_disabled_value" is not null
          and btrim("tenant_ldap_provider_configs"."account_disabled_value") <> ''
          and char_length("tenant_ldap_provider_configs"."account_disabled_value") <= 256)),
	CONSTRAINT "tenant_ldap_provider_configs_deprovision_check" CHECK (("tenant_ldap_provider_configs"."deprovision_mode" <> 'grace' and "tenant_ldap_provider_configs"."deprovision_grace_seconds" = 0)
        or ("tenant_ldap_provider_configs"."deprovision_mode" = 'grace'
          and "tenant_ldap_provider_configs"."deprovision_grace_seconds" between 60 and 2592000)),
	CONSTRAINT "tenant_ldap_provider_configs_sync_check" CHECK ("tenant_ldap_provider_configs"."sync_interval_seconds" is null
        or "tenant_ldap_provider_configs"."sync_interval_seconds" between 300 and 2592000),
	CONSTRAINT "tenant_ldap_provider_configs_version_check" CHECK ("tenant_ldap_provider_configs"."version" > 0),
	CONSTRAINT "tenant_ldap_provider_configs_updated_check" CHECK ("tenant_ldap_provider_configs"."updated_at" >= "tenant_ldap_provider_configs"."created_at")
);
--> statement-breakpoint
ALTER TABLE "tenant_ldap_provider_configs" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_ldap_provider_secrets" (
	"id" uuid DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"provider_id" uuid NOT NULL,
	"provider_kind" "auth_provider_kind" DEFAULT 'ldap' NOT NULL,
	"secret_ciphertext" "bytea" NOT NULL,
	"secret_nonce" "bytea" NOT NULL,
	"key_version" integer NOT NULL,
	"encryption_algorithm" text DEFAULT 'aes-256-gcm' NOT NULL,
	"rotated_by_membership_id" uuid NOT NULL,
	"rotated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"version" integer DEFAULT 1 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_ldap_provider_secrets_pkey" PRIMARY KEY("tenant_id","provider_id"),
	CONSTRAINT "tenant_ldap_provider_secrets_tenant_id_id_unique" UNIQUE("tenant_id","id"),
	CONSTRAINT "tenant_ldap_provider_secrets_kind_check" CHECK ("tenant_ldap_provider_secrets"."provider_kind" = 'ldap'),
	CONSTRAINT "tenant_ldap_provider_secrets_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_ldap_provider_secrets"."id") = 7) is true),
	CONSTRAINT "tenant_ldap_provider_secrets_ciphertext_check" CHECK (octet_length("tenant_ldap_provider_secrets"."secret_ciphertext") between 17 and 8192
        and octet_length("tenant_ldap_provider_secrets"."secret_nonce") = 12),
	CONSTRAINT "tenant_ldap_provider_secrets_algorithm_check" CHECK ("tenant_ldap_provider_secrets"."encryption_algorithm" = 'aes-256-gcm'),
	CONSTRAINT "tenant_ldap_provider_secrets_version_check" CHECK ("tenant_ldap_provider_secrets"."version" > 0),
	CONSTRAINT "tenant_ldap_provider_secrets_updated_check" CHECK ("tenant_ldap_provider_secrets"."rotated_at" >= "tenant_ldap_provider_secrets"."created_at"
        and "tenant_ldap_provider_secrets"."updated_at" >= "tenant_ldap_provider_secrets"."rotated_at")
);
--> statement-breakpoint
ALTER TABLE "tenant_ldap_provider_secrets" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_ldap_provider_urls" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"provider_id" uuid NOT NULL,
	"provider_kind" "auth_provider_kind" DEFAULT 'ldap' NOT NULL,
	"priority" integer NOT NULL,
	"host" text NOT NULL,
	"port" integer NOT NULL,
	"transport" "ldap_transport" NOT NULL,
	"tls_server_name" text NOT NULL,
	"referral_allowed" boolean DEFAULT false NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_ldap_provider_urls_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "tenant_ldap_provider_urls_provider_priority_key" UNIQUE("tenant_id","provider_id","priority"),
	CONSTRAINT "tenant_ldap_provider_urls_provider_endpoint_key" UNIQUE("tenant_id","provider_id","transport","host","port"),
	CONSTRAINT "tenant_ldap_provider_urls_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_ldap_provider_urls"."id") = 7) is true),
	CONSTRAINT "tenant_ldap_provider_urls_kind_check" CHECK ("tenant_ldap_provider_urls"."provider_kind" = 'ldap'),
	CONSTRAINT "tenant_ldap_provider_urls_priority_check" CHECK ("tenant_ldap_provider_urls"."priority" between 1 and 8),
	CONSTRAINT "tenant_ldap_provider_urls_host_check" CHECK (btrim("tenant_ldap_provider_urls"."host") <> ''
        and "tenant_ldap_provider_urls"."host" = lower("tenant_ldap_provider_urls"."host")
        and char_length("tenant_ldap_provider_urls"."host") <= 253
        and "tenant_ldap_provider_urls"."host" !~ '[[:space:][:cntrl:]/@?#]'),
	CONSTRAINT "tenant_ldap_provider_urls_port_check" CHECK ("tenant_ldap_provider_urls"."port" between 1 and 65535),
	CONSTRAINT "tenant_ldap_provider_urls_tls_name_check" CHECK (btrim("tenant_ldap_provider_urls"."tls_server_name") <> ''
        and "tenant_ldap_provider_urls"."tls_server_name" = lower("tenant_ldap_provider_urls"."tls_server_name")
        and char_length("tenant_ldap_provider_urls"."tls_server_name") <= 253
        and "tenant_ldap_provider_urls"."tls_server_name" !~ '[[:space:][:cntrl:]/@?#]'),
	CONSTRAINT "tenant_ldap_provider_urls_updated_check" CHECK ("tenant_ldap_provider_urls"."updated_at" >= "tenant_ldap_provider_urls"."created_at")
);
--> statement-breakpoint
ALTER TABLE "tenant_ldap_provider_urls" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "tenant_authorization_commands" DROP CONSTRAINT "tenant_authorization_commands_operation_check";--> statement-breakpoint
ALTER TABLE "users" DROP CONSTRAINT "users_email_canonical_check";--> statement-breakpoint
ALTER TABLE "users" DROP CONSTRAINT "users_email_shape_check";--> statement-breakpoint
ALTER TABLE "users" ALTER COLUMN "email" DROP NOT NULL;--> statement-breakpoint
ALTER TABLE "local_break_glass_credentials" ADD COLUMN "login_identifier_id" uuid;--> statement-breakpoint
ALTER TABLE "tenant_user_profiles" ADD CONSTRAINT "tenant_user_profiles_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_user_profiles" ADD CONSTRAINT "tenant_user_profiles_membership_fk" FOREIGN KEY ("tenant_id","membership_id","user_id") REFERENCES "public"."tenant_memberships"("tenant_id","id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "user_login_identifiers" ADD CONSTRAINT "user_login_identifiers_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_auth_providers" ADD CONSTRAINT "tenant_auth_providers_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_auth_providers" ADD CONSTRAINT "tenant_auth_providers_creator_membership_fk" FOREIGN KEY ("tenant_id","created_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_auth_providers" ADD CONSTRAINT "tenant_auth_providers_updater_membership_fk" FOREIGN KEY ("tenant_id","updated_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_auth_providers" ADD CONSTRAINT "tenant_auth_providers_archiver_membership_fk" FOREIGN KEY ("tenant_id","archived_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_provider_configs" ADD CONSTRAINT "tenant_ldap_provider_configs_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_ldap_provider_configs" ADD CONSTRAINT "tenant_ldap_provider_configs_provider_fk" FOREIGN KEY ("tenant_id","provider_id","provider_kind") REFERENCES "public"."tenant_auth_providers"("tenant_id","id","kind") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_provider_configs" ADD CONSTRAINT "tenant_ldap_provider_configs_updater_fk" FOREIGN KEY ("tenant_id","updated_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_provider_secrets" ADD CONSTRAINT "tenant_ldap_provider_secrets_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_ldap_provider_secrets" ADD CONSTRAINT "tenant_ldap_provider_secrets_key_version_identity_keyring_versions_key_version_fk" FOREIGN KEY ("key_version") REFERENCES "public"."identity_keyring_versions"("key_version") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_ldap_provider_secrets" ADD CONSTRAINT "tenant_ldap_provider_secrets_provider_fk" FOREIGN KEY ("tenant_id","provider_id","provider_kind") REFERENCES "public"."tenant_auth_providers"("tenant_id","id","kind") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_provider_secrets" ADD CONSTRAINT "tenant_ldap_provider_secrets_rotator_fk" FOREIGN KEY ("tenant_id","rotated_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_provider_urls" ADD CONSTRAINT "tenant_ldap_provider_urls_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_ldap_provider_urls" ADD CONSTRAINT "tenant_ldap_provider_urls_provider_fk" FOREIGN KEY ("tenant_id","provider_id","provider_kind") REFERENCES "public"."tenant_auth_providers"("tenant_id","id","kind") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
CREATE INDEX "tenant_user_profiles_tenant_display_idx" ON "tenant_user_profiles" USING btree ("tenant_id","display_name","membership_id");--> statement-breakpoint
CREATE INDEX "tenant_user_profiles_tenant_username_idx" ON "tenant_user_profiles" USING btree ("tenant_id","username","membership_id");--> statement-breakpoint
CREATE UNIQUE INDEX "user_login_identifiers_user_active_kind_key" ON "user_login_identifiers" USING btree ("user_id","kind") WHERE "user_login_identifiers"."retired_at" is null;--> statement-breakpoint
CREATE INDEX "user_login_identifiers_user_idx" ON "user_login_identifiers" USING btree ("user_id","id");--> statement-breakpoint
CREATE INDEX "tenant_auth_providers_tenant_kind_idx" ON "tenant_auth_providers" USING btree ("tenant_id","kind","id");--> statement-breakpoint
CREATE UNIQUE INDEX "tenant_auth_providers_tenant_active_display_key" ON "tenant_auth_providers" USING btree ("tenant_id","display_name") WHERE "tenant_auth_providers"."archived_at" is null;--> statement-breakpoint
CREATE INDEX "tenant_ldap_provider_secrets_live_key_version_idx" ON "tenant_ldap_provider_secrets" USING btree ("key_version","tenant_id","provider_id");--> statement-breakpoint
CREATE INDEX "tenant_ldap_provider_urls_provider_enabled_idx" ON "tenant_ldap_provider_urls" USING btree ("tenant_id","provider_id","enabled","priority");--> statement-breakpoint
ALTER TABLE "local_break_glass_credentials" ADD CONSTRAINT "local_break_glass_credentials_login_identifier_fk" FOREIGN KEY ("login_identifier_id","user_id") REFERENCES "public"."user_login_identifiers"("id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "local_break_glass_credentials" ADD CONSTRAINT "local_break_glass_credentials_login_identifier_key" UNIQUE("login_identifier_id");--> statement-breakpoint
ALTER TABLE "tenant_authorization_commands" ADD CONSTRAINT "tenant_authorization_commands_operation_check" CHECK ("tenant_authorization_commands"."operation" in (
        'tenant_role.create',
        'tenant_role_grant.create',
        'tenant_security_group.create',
        'tenant_security_group_membership.create',
        'tenant_security_group_role_grant.create',
        'operator_team_assignment.create',
        'operator_team_roster_entry.create',
        'identity_provider.create'
      ));--> statement-breakpoint
ALTER TABLE "users" ADD CONSTRAINT "users_email_canonical_check" CHECK ("users"."email" is null or "users"."email" = lower(btrim("users"."email")));--> statement-breakpoint
ALTER TABLE "users" ADD CONSTRAINT "users_email_shape_check" CHECK ("users"."email" is null or (
        position('@' in "users"."email") > 1
        and char_length("users"."email") <= 320
        and "users"."email" !~ '[[:cntrl:]]'
      ));