-- Platform-global LDAP identity provider. This slice deliberately uses a
-- physically separate provider family: no nullable tenant discriminator exists
-- anywhere in the global trust, mapping, identity, login, or provenance state.
ALTER TABLE public.platform_auth_providers
  DROP CONSTRAINT platform_auth_providers_kind_check;
ALTER TABLE public.platform_auth_providers
  ADD CONSTRAINT platform_auth_providers_kind_check
  CHECK (kind IN ('ldap','oidc','saml'));
ALTER TABLE public.platform_federated_provider_policies
  DROP CONSTRAINT platform_federated_provider_policies_kind_check;
ALTER TABLE public.platform_federated_provider_policies
  ADD CONSTRAINT platform_federated_provider_policies_kind_check
  CHECK (provider_kind IN ('ldap','oidc','saml'));
--> statement-breakpoint

CREATE TABLE "platform_ldap_authentication_runs" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"provider_id" uuid NOT NULL,
	"receipt_digest" "bytea" NOT NULL,
	"network_rate_digest" "bytea" NOT NULL,
	"account_rate_digest" "bytea" NOT NULL,
	"provider_rate_digest" "bytea" NOT NULL,
	"provider_version" bigint NOT NULL,
	"configuration_revision" bigint NOT NULL,
	"security_revision" bigint NOT NULL,
	"mapping_revision" bigint NOT NULL,
	"state" text DEFAULT 'pending' NOT NULL,
	"failure_category" text,
	"external_identity_id" uuid,
	"user_id" uuid,
	"session_id" uuid,
	"result_digest" "bytea",
	"started_at" timestamp with time zone NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"completed_at" timestamp with time zone,
	CONSTRAINT "platform_ldap_authentication_runs_receipt_key" UNIQUE("receipt_digest"),
	CONSTRAINT "platform_ldap_authentication_runs_value_check" CHECK ((uuid_extract_version("platform_ldap_authentication_runs"."id") = 7) is true
        and octet_length("platform_ldap_authentication_runs"."receipt_digest") = 32
        and octet_length("platform_ldap_authentication_runs"."network_rate_digest") = 32
        and octet_length("platform_ldap_authentication_runs"."account_rate_digest") = 32
        and octet_length("platform_ldap_authentication_runs"."provider_rate_digest") = 32
        and "platform_ldap_authentication_runs"."provider_version" between 1 and 2147483647
        and "platform_ldap_authentication_runs"."configuration_revision" between 1 and 9007199254740991
        and "platform_ldap_authentication_runs"."security_revision" between 1 and 9007199254740991
        and "platform_ldap_authentication_runs"."mapping_revision" between 1 and 9007199254740991
        and "platform_ldap_authentication_runs"."expires_at" between "platform_ldap_authentication_runs"."started_at" + interval '30 seconds'
          and "platform_ldap_authentication_runs"."started_at" + interval '5 minutes'
        and (("platform_ldap_authentication_runs"."state" = 'pending'
          and "platform_ldap_authentication_runs"."failure_category" is null
          and "platform_ldap_authentication_runs"."external_identity_id" is null
          and "platform_ldap_authentication_runs"."user_id" is null and "platform_ldap_authentication_runs"."session_id" is null
          and "platform_ldap_authentication_runs"."result_digest" is null and "platform_ldap_authentication_runs"."completed_at" is null)
        or ("platform_ldap_authentication_runs"."state" = 'succeeded'
          and "platform_ldap_authentication_runs"."failure_category" is null
          and "platform_ldap_authentication_runs"."external_identity_id" is not null
          and "platform_ldap_authentication_runs"."user_id" is not null and "platform_ldap_authentication_runs"."session_id" is not null
          and octet_length("platform_ldap_authentication_runs"."result_digest") = 32
          and "platform_ldap_authentication_runs"."completed_at" between "platform_ldap_authentication_runs"."started_at" and "platform_ldap_authentication_runs"."expires_at")
        or ("platform_ldap_authentication_runs"."state" in ('denied','failed','stale')
          and "platform_ldap_authentication_runs"."failure_category" is not null
          and "platform_ldap_authentication_runs"."external_identity_id" is null
          and "platform_ldap_authentication_runs"."user_id" is null and "platform_ldap_authentication_runs"."session_id" is null
          and "platform_ldap_authentication_runs"."result_digest" is null
          and "platform_ldap_authentication_runs"."completed_at" between "platform_ldap_authentication_runs"."started_at" and "platform_ldap_authentication_runs"."expires_at")))
);

ALTER TABLE "platform_ldap_authentication_runs" ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
CREATE TABLE "platform_ldap_bind_secrets" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"provider_id" uuid NOT NULL,
	"provider_kind" "auth_provider_kind" DEFAULT 'ldap' NOT NULL,
	"revision" bigint NOT NULL,
	"key_version" integer NOT NULL,
	"nonce" "bytea" NOT NULL,
	"ciphertext" "bytea" NOT NULL,
	"rotated_by_user_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"retired_at" timestamp with time zone,
	CONSTRAINT "platform_ldap_bind_secrets_provider_revision_key" UNIQUE("provider_id","revision"),
	CONSTRAINT "platform_ldap_bind_secrets_value_check" CHECK ((uuid_extract_version("platform_ldap_bind_secrets"."id") = 7) is true
        and "platform_ldap_bind_secrets"."provider_kind" = 'ldap'
        and "platform_ldap_bind_secrets"."revision" between 1 and 9007199254740991
        and "platform_ldap_bind_secrets"."key_version" between 1 and 32767
        and octet_length("platform_ldap_bind_secrets"."nonce") = 12
        and octet_length("platform_ldap_bind_secrets"."ciphertext") between 17 and 8192
        and ("platform_ldap_bind_secrets"."retired_at" is null or "platform_ldap_bind_secrets"."retired_at" >= "platform_ldap_bind_secrets"."created_at"))
);

ALTER TABLE "platform_ldap_bind_secrets" ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
CREATE TABLE "platform_ldap_external_identities" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"provider_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"subject_format" "identity_subject_format" NOT NULL,
	"subject_ciphertext" "bytea" NOT NULL,
	"subject_nonce" "bytea" NOT NULL,
	"key_version" integer NOT NULL,
	"username" text NOT NULL,
	"email" text,
	"display_name" text NOT NULL,
	"first_name" text,
	"last_name" text,
	"groups_digest" "bytea" NOT NULL,
	"configuration_revision" bigint NOT NULL,
	"security_revision" bigint NOT NULL,
	"mapping_revision" bigint NOT NULL,
	"last_observed_at" timestamp with time zone NOT NULL,
	"disabled_at" timestamp with time zone,
	"retired_at" timestamp with time zone,
	"version" bigint DEFAULT 1 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "platform_ldap_external_identities_provider_key" UNIQUE("provider_id","id"),
	CONSTRAINT "platform_ldap_external_identities_value_check" CHECK ((uuid_extract_version("platform_ldap_external_identities"."id") = 7) is true
        and octet_length("platform_ldap_external_identities"."subject_ciphertext") between 17 and 4112
        and octet_length("platform_ldap_external_identities"."subject_nonce") = 12
        and "platform_ldap_external_identities"."key_version" between 1 and 32767
        and "platform_ldap_external_identities"."username" = btrim("platform_ldap_external_identities"."username")
        and octet_length(convert_to("platform_ldap_external_identities"."username", 'UTF8')) between 1 and 1280
        and ("platform_ldap_external_identities"."email" is null or (
          "platform_ldap_external_identities"."email" = lower(btrim("platform_ldap_external_identities"."email"))
          and position('@' in "platform_ldap_external_identities"."email") > 1
          and char_length("platform_ldap_external_identities"."email") <= 320))
        and "platform_ldap_external_identities"."display_name" = btrim("platform_ldap_external_identities"."display_name")
        and char_length("platform_ldap_external_identities"."display_name") between 1 and 160
        and octet_length("platform_ldap_external_identities"."groups_digest") = 32
        and "platform_ldap_external_identities"."configuration_revision" between 1 and 9007199254740991
        and "platform_ldap_external_identities"."security_revision" between 1 and 9007199254740991
        and "platform_ldap_external_identities"."mapping_revision" between 1 and 9007199254740991
        and "platform_ldap_external_identities"."version" between 1 and 2147483647
        and "platform_ldap_external_identities"."last_observed_at" >= "platform_ldap_external_identities"."created_at"
        and "platform_ldap_external_identities"."updated_at" >= "platform_ldap_external_identities"."created_at"
        and ("platform_ldap_external_identities"."disabled_at" is null or "platform_ldap_external_identities"."disabled_at" >= "platform_ldap_external_identities"."created_at")
        and ("platform_ldap_external_identities"."retired_at" is null or "platform_ldap_external_identities"."retired_at" >= "platform_ldap_external_identities"."created_at"))
);

ALTER TABLE "platform_ldap_external_identities" ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
CREATE TABLE "platform_ldap_external_identity_aliases" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"provider_id" uuid NOT NULL,
	"external_identity_id" uuid NOT NULL,
	"key_version" integer NOT NULL,
	"subject_digest" "bytea" NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"retired_at" timestamp with time zone,
	CONSTRAINT "platform_ldap_external_identity_aliases_digest_key" UNIQUE("provider_id","key_version","subject_digest"),
	CONSTRAINT "platform_ldap_external_identity_aliases_version_key" UNIQUE("external_identity_id","key_version"),
	CONSTRAINT "platform_ldap_external_identity_aliases_value_check" CHECK ((uuid_extract_version("platform_ldap_external_identity_aliases"."id") = 7) is true
        and "platform_ldap_external_identity_aliases"."key_version" between 1 and 32767
        and octet_length("platform_ldap_external_identity_aliases"."subject_digest") = 32
        and ("platform_ldap_external_identity_aliases"."retired_at" is null or "platform_ldap_external_identity_aliases"."retired_at" >= "platform_ldap_external_identity_aliases"."created_at"))
);

ALTER TABLE "platform_ldap_external_identity_aliases" ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
CREATE TABLE "platform_ldap_mapping_rules" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"provider_id" uuid NOT NULL,
	"matcher_type" text NOT NULL,
	"matcher_value" text NOT NULL,
	"case_sensitive" boolean DEFAULT false NOT NULL,
	"priority" integer NOT NULL,
	"platform_role_id" uuid NOT NULL,
	"reconciliation_mode" text NOT NULL,
	"enabled" boolean DEFAULT false NOT NULL,
	"notes" text DEFAULT '' NOT NULL,
	"last_matched_at" timestamp with time zone,
	"version" bigint DEFAULT 1 NOT NULL,
	"created_by_user_id" uuid NOT NULL,
	"updated_by_user_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"archived_at" timestamp with time zone,
	CONSTRAINT "platform_ldap_mapping_rules_provider_priority_key" UNIQUE("provider_id","priority"),
	CONSTRAINT "platform_ldap_mapping_rules_value_check" CHECK ((uuid_extract_version("platform_ldap_mapping_rules"."id") = 7) is true
        and "platform_ldap_mapping_rules"."matcher_type" in ('exact_dn','exact_cn','regex')
        and "platform_ldap_mapping_rules"."matcher_value" = btrim("platform_ldap_mapping_rules"."matcher_value")
        and octet_length(convert_to("platform_ldap_mapping_rules"."matcher_value", 'UTF8')) between 1 and 2048
        and "platform_ldap_mapping_rules"."matcher_value" !~ '[[:cntrl:]]'
        and "platform_ldap_mapping_rules"."priority" between 0 and 1000000
        and "platform_ldap_mapping_rules"."reconciliation_mode" in ('additive','authoritative')
        and "platform_ldap_mapping_rules"."notes" = btrim("platform_ldap_mapping_rules"."notes")
        and octet_length(convert_to("platform_ldap_mapping_rules"."notes", 'UTF8')) <= 2048
        and "platform_ldap_mapping_rules"."notes" !~ '[[:cntrl:]]'
        and "platform_ldap_mapping_rules"."version" between 1 and 2147483647
        and "platform_ldap_mapping_rules"."updated_at" >= "platform_ldap_mapping_rules"."created_at"
        and ("platform_ldap_mapping_rules"."last_matched_at" is null or "platform_ldap_mapping_rules"."last_matched_at" >= "platform_ldap_mapping_rules"."created_at")
        and ("platform_ldap_mapping_rules"."archived_at" is null or (
          not "platform_ldap_mapping_rules"."enabled" and "platform_ldap_mapping_rules"."archived_at" >= "platform_ldap_mapping_rules"."created_at")))
);

ALTER TABLE "platform_ldap_mapping_rules" ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
CREATE TABLE "platform_ldap_provider_configurations" (
	"provider_id" uuid PRIMARY KEY NOT NULL,
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
	"jit_mode" "identity_jit_mode" DEFAULT 'existing_identity' NOT NULL,
	"no_match_policy" "identity_no_match_policy" DEFAULT 'deny' NOT NULL,
	"deprovision_mode" "identity_deprovision_mode" DEFAULT 'immediate' NOT NULL,
	"deprovision_grace_seconds" integer DEFAULT 0 NOT NULL,
	"sync_interval_seconds" integer,
	"configuration_revision" bigint DEFAULT 1 NOT NULL,
	"security_revision" bigint DEFAULT 1 NOT NULL,
	"mapping_revision" bigint DEFAULT 1 NOT NULL,
	"updated_by_user_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "platform_ldap_provider_configurations_kind_key" UNIQUE("provider_id","provider_kind"),
	CONSTRAINT "platform_ldap_provider_configurations_kind_check" CHECK ("platform_ldap_provider_configurations"."provider_kind" = 'ldap'),
	CONSTRAINT "platform_ldap_provider_configurations_ca_check" CHECK ("platform_ldap_provider_configurations"."custom_ca_pem" is null
        or char_length("platform_ldap_provider_configurations"."custom_ca_pem") between 1 and 131072),
	CONSTRAINT "platform_ldap_provider_configurations_timeout_check" CHECK ("platform_ldap_provider_configurations"."connect_timeout_ms" between 100 and 30000
        and "platform_ldap_provider_configurations"."operation_timeout_ms" between 100 and 60000
        and "platform_ldap_provider_configurations"."connect_timeout_ms" <= "platform_ldap_provider_configurations"."operation_timeout_ms"),
	CONSTRAINT "platform_ldap_provider_configurations_dn_check" CHECK ("platform_ldap_provider_configurations"."bind_dn" = btrim("platform_ldap_provider_configurations"."bind_dn")
        and char_length("platform_ldap_provider_configurations"."bind_dn") between 1 and 2048
        and "platform_ldap_provider_configurations"."user_base_dn" = btrim("platform_ldap_provider_configurations"."user_base_dn")
        and char_length("platform_ldap_provider_configurations"."user_base_dn") between 1 and 2048
        and ("platform_ldap_provider_configurations"."group_base_dn" is null or (
          "platform_ldap_provider_configurations"."group_base_dn" = btrim("platform_ldap_provider_configurations"."group_base_dn")
          and char_length("platform_ldap_provider_configurations"."group_base_dn") between 1 and 2048))),
	CONSTRAINT "platform_ldap_provider_configurations_filter_check" CHECK ("platform_ldap_provider_configurations"."user_search_filter" = btrim("platform_ldap_provider_configurations"."user_search_filter")
        and char_length("platform_ldap_provider_configurations"."user_search_filter") between 1 and 4096
        and ("platform_ldap_provider_configurations"."group_search_filter" is null or (
          "platform_ldap_provider_configurations"."group_search_filter" = btrim("platform_ldap_provider_configurations"."group_search_filter")
          and char_length("platform_ldap_provider_configurations"."group_search_filter") between 1 and 4096))
        and ("platform_ldap_provider_configurations"."user_dn_template" is null or (
          "platform_ldap_provider_configurations"."user_dn_template" = btrim("platform_ldap_provider_configurations"."user_dn_template")
          and char_length("platform_ldap_provider_configurations"."user_dn_template") between 1 and 2048))),
	CONSTRAINT "platform_ldap_provider_configurations_budget_check" CHECK ("platform_ldap_provider_configurations"."page_size" between 1 and 1000
        and "platform_ldap_provider_configurations"."max_pages" between 1 and 1000
        and "platform_ldap_provider_configurations"."max_entries" between 1 and 100000
        and "platform_ldap_provider_configurations"."max_response_bytes" between 1024 and 52428800
        and "platform_ldap_provider_configurations"."max_groups" between 1 and 10000),
	CONSTRAINT "platform_ldap_provider_configurations_referral_check" CHECK (("platform_ldap_provider_configurations"."referral_mode" = 'disabled' and "platform_ldap_provider_configurations"."max_referral_hops" = 0)
        or ("platform_ldap_provider_configurations"."referral_mode" = 'configured_endpoints'
          and "platform_ldap_provider_configurations"."max_referral_hops" between 1 and 3)),
	CONSTRAINT "platform_ldap_provider_configurations_nested_group_check" CHECK (("platform_ldap_provider_configurations"."nested_group_mode" = 'disabled' and "platform_ldap_provider_configurations"."max_nested_group_depth" = 0)
        or ("platform_ldap_provider_configurations"."nested_group_mode" <> 'disabled'
          and "platform_ldap_provider_configurations"."max_nested_group_depth" between 1 and 20)),
	CONSTRAINT "platform_ldap_provider_configurations_attribute_check" CHECK ("platform_ldap_provider_configurations"."first_name_attribute" = btrim("platform_ldap_provider_configurations"."first_name_attribute")
        and char_length("platform_ldap_provider_configurations"."first_name_attribute") between 1 and 128
        and "platform_ldap_provider_configurations"."last_name_attribute" = btrim("platform_ldap_provider_configurations"."last_name_attribute")
        and char_length("platform_ldap_provider_configurations"."last_name_attribute") between 1 and 128
        and "platform_ldap_provider_configurations"."display_name_attribute" = btrim("platform_ldap_provider_configurations"."display_name_attribute")
        and char_length("platform_ldap_provider_configurations"."display_name_attribute") between 1 and 128
        and "platform_ldap_provider_configurations"."username_attribute" = btrim("platform_ldap_provider_configurations"."username_attribute")
        and char_length("platform_ldap_provider_configurations"."username_attribute") between 1 and 128
        and "platform_ldap_provider_configurations"."immutable_subject_attribute" = btrim("platform_ldap_provider_configurations"."immutable_subject_attribute")
        and char_length("platform_ldap_provider_configurations"."immutable_subject_attribute") between 1 and 128
        and ("platform_ldap_provider_configurations"."alternate_username_attribute" is null or char_length(btrim("platform_ldap_provider_configurations"."alternate_username_attribute")) between 1 and 128)
        and ("platform_ldap_provider_configurations"."email_attribute" is null or char_length(btrim("platform_ldap_provider_configurations"."email_attribute")) between 1 and 128)
        and ("platform_ldap_provider_configurations"."group_membership_attribute" is null or char_length(btrim("platform_ldap_provider_configurations"."group_membership_attribute")) between 1 and 128)
        and ("platform_ldap_provider_configurations"."posix_member_uid_attribute" is null or char_length(btrim("platform_ldap_provider_configurations"."posix_member_uid_attribute")) between 1 and 128)
        and ("platform_ldap_provider_configurations"."posix_gid_number_attribute" is null or char_length(btrim("platform_ldap_provider_configurations"."posix_gid_number_attribute")) between 1 and 128)),
	CONSTRAINT "platform_ldap_provider_configurations_status_check" CHECK (("platform_ldap_provider_configurations"."account_status_mode" = 'none'
          and "platform_ldap_provider_configurations"."account_status_attribute" is null
          and "platform_ldap_provider_configurations"."account_disabled_value" is null)
        or ("platform_ldap_provider_configurations"."account_status_mode" = 'active_directory_uac'
          and char_length(btrim("platform_ldap_provider_configurations"."account_status_attribute")) between 1 and 128
          and "platform_ldap_provider_configurations"."account_disabled_value" is null)
        or ("platform_ldap_provider_configurations"."account_status_mode" = 'attribute_equals'
          and char_length(btrim("platform_ldap_provider_configurations"."account_status_attribute")) between 1 and 128
          and char_length(btrim("platform_ldap_provider_configurations"."account_disabled_value")) between 1 and 256)),
	CONSTRAINT "platform_ldap_provider_configurations_policy_check" CHECK ("platform_ldap_provider_configurations"."jit_mode" in ('disabled','existing_identity')
        and "platform_ldap_provider_configurations"."no_match_policy" = 'deny'
        and (("platform_ldap_provider_configurations"."deprovision_mode" <> 'grace' and "platform_ldap_provider_configurations"."deprovision_grace_seconds" = 0)
          or ("platform_ldap_provider_configurations"."deprovision_mode" = 'grace'
            and "platform_ldap_provider_configurations"."deprovision_grace_seconds" between 60 and 2592000))
        and ("platform_ldap_provider_configurations"."sync_interval_seconds" is null
          or "platform_ldap_provider_configurations"."sync_interval_seconds" between 300 and 2592000)),
	CONSTRAINT "platform_ldap_provider_configurations_revision_check" CHECK ("platform_ldap_provider_configurations"."configuration_revision" between 1 and 9007199254740991
        and "platform_ldap_provider_configurations"."security_revision" between 1 and 9007199254740991
        and "platform_ldap_provider_configurations"."mapping_revision" between 1 and 9007199254740991
        and "platform_ldap_provider_configurations"."updated_at" >= "platform_ldap_provider_configurations"."created_at")
);

ALTER TABLE "platform_ldap_provider_configurations" ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
CREATE TABLE "platform_ldap_provider_endpoints" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
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
	CONSTRAINT "platform_ldap_provider_endpoints_provider_priority_key" UNIQUE("provider_id","priority"),
	CONSTRAINT "platform_ldap_provider_endpoints_provider_endpoint_key" UNIQUE("provider_id","transport","host","port"),
	CONSTRAINT "platform_ldap_provider_endpoints_value_check" CHECK ((uuid_extract_version("platform_ldap_provider_endpoints"."id") = 7) is true
        and "platform_ldap_provider_endpoints"."provider_kind" = 'ldap'
        and "platform_ldap_provider_endpoints"."priority" between 1 and 8
        and "platform_ldap_provider_endpoints"."host" = lower(btrim("platform_ldap_provider_endpoints"."host"))
        and char_length("platform_ldap_provider_endpoints"."host") between 1 and 253
        and "platform_ldap_provider_endpoints"."host" !~ '[[:space:][:cntrl:]/@?#]'
        and "platform_ldap_provider_endpoints"."port" between 1 and 65535
        and "platform_ldap_provider_endpoints"."tls_server_name" = lower(btrim("platform_ldap_provider_endpoints"."tls_server_name"))
        and char_length("platform_ldap_provider_endpoints"."tls_server_name") between 1 and 253
        and "platform_ldap_provider_endpoints"."tls_server_name" !~ '[[:space:][:cntrl:]/@?#]'
        and "platform_ldap_provider_endpoints"."updated_at" >= "platform_ldap_provider_endpoints"."created_at")
);

ALTER TABLE "platform_ldap_provider_endpoints" ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
CREATE TABLE "platform_ldap_role_grants" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"provider_id" uuid NOT NULL,
	"external_identity_id" uuid NOT NULL,
	"mapping_rule_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"platform_role_id" uuid NOT NULL,
	"user_platform_role_id" uuid NOT NULL,
	"source_mapping_revision" bigint NOT NULL,
	"granted_at" timestamp with time zone NOT NULL,
	"refreshed_at" timestamp with time zone NOT NULL,
	"revoked_at" timestamp with time zone,
	CONSTRAINT "platform_ldap_role_grants_value_check" CHECK ((uuid_extract_version("platform_ldap_role_grants"."id") = 7) is true
        and "platform_ldap_role_grants"."source_mapping_revision" between 1 and 9007199254740991
        and "platform_ldap_role_grants"."refreshed_at" >= "platform_ldap_role_grants"."granted_at"
        and ("platform_ldap_role_grants"."revoked_at" is null or "platform_ldap_role_grants"."revoked_at" >= "platform_ldap_role_grants"."granted_at"))
);

ALTER TABLE "platform_ldap_role_grants" ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
CREATE TABLE "platform_ldap_session_provenance" (
	"session_id" uuid PRIMARY KEY NOT NULL,
	"user_id" uuid NOT NULL,
	"provider_id" uuid NOT NULL,
	"external_identity_id" uuid NOT NULL,
	"authentication_run_id" uuid NOT NULL,
	"provider_version" bigint NOT NULL,
	"configuration_revision" bigint NOT NULL,
	"security_revision" bigint NOT NULL,
	"mapping_revision" bigint NOT NULL,
	"identity_version" bigint NOT NULL,
	"totp_credential_id" uuid NOT NULL,
	"totp_security_revision" bigint NOT NULL,
	"authenticated_at" timestamp with time zone NOT NULL,
	CONSTRAINT "platform_ldap_session_provenance_exact_key" UNIQUE("session_id","user_id","provider_id","external_identity_id"),
	CONSTRAINT "platform_ldap_session_provenance_value_check" CHECK ("platform_ldap_session_provenance"."provider_version" between 1 and 2147483647
        and "platform_ldap_session_provenance"."configuration_revision" between 1 and 9007199254740991
        and "platform_ldap_session_provenance"."security_revision" between 1 and 9007199254740991
        and "platform_ldap_session_provenance"."mapping_revision" between 1 and 9007199254740991
        and "platform_ldap_session_provenance"."identity_version" between 1 and 2147483647
        and "platform_ldap_session_provenance"."totp_security_revision" between 1 and 9007199254740991)
);

ALTER TABLE "platform_ldap_session_provenance" ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
CREATE TABLE "platform_ldap_test_runs" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"provider_id" uuid NOT NULL,
	"actor_user_id" uuid NOT NULL,
	"kind" text NOT NULL,
	"state" text DEFAULT 'pending' NOT NULL,
	"outcome" text,
	"category" text,
	"endpoint_priority" integer,
	"duration_ms" integer,
	"matched_entry_count" integer,
	"attributes" jsonb,
	"provider_version" bigint NOT NULL,
	"configuration_revision" bigint NOT NULL,
	"mapping_revision" bigint NOT NULL,
	"secret_revision" bigint,
	"request_id" uuid NOT NULL,
	"correlation_id" uuid NOT NULL,
	"started_at" timestamp with time zone NOT NULL,
	"completed_at" timestamp with time zone,
	CONSTRAINT "platform_ldap_test_runs_value_check" CHECK ((uuid_extract_version("platform_ldap_test_runs"."id") = 7) is true
        and "platform_ldap_test_runs"."kind" in ('connection','bind','search_user','filter','mapping_dry_run')
        and "platform_ldap_test_runs"."state" in ('pending','completed')
        and "platform_ldap_test_runs"."provider_version" between 1 and 2147483647
        and "platform_ldap_test_runs"."configuration_revision" between 1 and 9007199254740991
        and "platform_ldap_test_runs"."mapping_revision" between 1 and 9007199254740991
        and ("platform_ldap_test_runs"."secret_revision" is null
          or "platform_ldap_test_runs"."secret_revision" between 1 and 9007199254740991)
        and (("platform_ldap_test_runs"."state" = 'pending'
          and "platform_ldap_test_runs"."outcome" is null and "platform_ldap_test_runs"."category" is null
          and "platform_ldap_test_runs"."endpoint_priority" is null and "platform_ldap_test_runs"."duration_ms" is null
          and "platform_ldap_test_runs"."matched_entry_count" is null and "platform_ldap_test_runs"."attributes" is null
          and "platform_ldap_test_runs"."completed_at" is null)
        or ("platform_ldap_test_runs"."state" = 'completed'
          and "platform_ldap_test_runs"."outcome" in ('success','failure','inconclusive')
          and "platform_ldap_test_runs"."category" in (
            'success','cancelled','configuration_invalid','destination_blocked',
            'dns_failed','connect_failed','connect_timeout','tls_failed',
            'certificate_rejected','bind_rejected','user_not_found',
            'user_ambiguous','mapping_denied','stale_configuration','protocol_failed')
          and "platform_ldap_test_runs"."duration_ms" between 0 and 120000
          and ("platform_ldap_test_runs"."matched_entry_count" is null
            or "platform_ldap_test_runs"."matched_entry_count" between 0 and 1000)
          and ("platform_ldap_test_runs"."attributes" is null or (
            jsonb_typeof("platform_ldap_test_runs"."attributes") = 'array'
            and pg_column_size("platform_ldap_test_runs"."attributes") between 2 and 32768))
          and "platform_ldap_test_runs"."completed_at" >= "platform_ldap_test_runs"."started_at")))
);

ALTER TABLE "platform_ldap_test_runs" ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
ALTER TABLE "platform_ldap_authentication_runs" ADD CONSTRAINT "platform_ldap_authentication_runs_provider_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."platform_ldap_provider_configurations"("provider_id") ON DELETE restrict ON UPDATE cascade;
--> statement-breakpoint
ALTER TABLE "platform_ldap_bind_secrets" ADD CONSTRAINT "platform_ldap_bind_secrets_key_version_identity_keyring_versions_key_version_fk" FOREIGN KEY ("key_version") REFERENCES "public"."identity_keyring_versions"("key_version") ON DELETE restrict ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "platform_ldap_bind_secrets" ADD CONSTRAINT "platform_ldap_bind_secrets_rotated_by_user_id_users_id_fk" FOREIGN KEY ("rotated_by_user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "platform_ldap_bind_secrets" ADD CONSTRAINT "platform_ldap_bind_secrets_provider_fk" FOREIGN KEY ("provider_id","provider_kind") REFERENCES "public"."platform_ldap_provider_configurations"("provider_id","provider_kind") ON DELETE restrict ON UPDATE cascade;
--> statement-breakpoint
ALTER TABLE "platform_ldap_external_identities" ADD CONSTRAINT "platform_ldap_external_identities_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "platform_ldap_external_identities" ADD CONSTRAINT "platform_ldap_external_identities_key_version_identity_keyring_versions_key_version_fk" FOREIGN KEY ("key_version") REFERENCES "public"."identity_keyring_versions"("key_version") ON DELETE restrict ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "platform_ldap_external_identities" ADD CONSTRAINT "platform_ldap_external_identities_provider_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."platform_ldap_provider_configurations"("provider_id") ON DELETE restrict ON UPDATE cascade;
--> statement-breakpoint
ALTER TABLE "platform_ldap_external_identity_aliases" ADD CONSTRAINT "platform_ldap_external_identity_aliases_identity_fk" FOREIGN KEY ("provider_id","external_identity_id") REFERENCES "public"."platform_ldap_external_identities"("provider_id","id") ON DELETE restrict ON UPDATE cascade;
--> statement-breakpoint
ALTER TABLE "platform_ldap_mapping_rules" ADD CONSTRAINT "platform_ldap_mapping_rules_platform_role_id_platform_roles_id_fk" FOREIGN KEY ("platform_role_id") REFERENCES "public"."platform_roles"("id") ON DELETE restrict ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "platform_ldap_mapping_rules" ADD CONSTRAINT "platform_ldap_mapping_rules_created_by_user_id_users_id_fk" FOREIGN KEY ("created_by_user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "platform_ldap_mapping_rules" ADD CONSTRAINT "platform_ldap_mapping_rules_updated_by_user_id_users_id_fk" FOREIGN KEY ("updated_by_user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "platform_ldap_mapping_rules" ADD CONSTRAINT "platform_ldap_mapping_rules_provider_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."platform_ldap_provider_configurations"("provider_id") ON DELETE restrict ON UPDATE cascade;
--> statement-breakpoint
ALTER TABLE "platform_ldap_provider_configurations" ADD CONSTRAINT "platform_ldap_provider_configurations_updated_by_user_id_users_id_fk" FOREIGN KEY ("updated_by_user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "platform_ldap_provider_configurations" ADD CONSTRAINT "platform_ldap_provider_configurations_provider_fk" FOREIGN KEY ("provider_id","provider_kind") REFERENCES "public"."platform_auth_providers"("id","kind") ON DELETE restrict ON UPDATE cascade;
--> statement-breakpoint
ALTER TABLE "platform_ldap_provider_configurations" ADD CONSTRAINT "platform_ldap_provider_configurations_policy_fk" FOREIGN KEY ("provider_id","provider_kind") REFERENCES "public"."platform_federated_provider_policies"("provider_id","provider_kind") ON DELETE restrict ON UPDATE cascade;
--> statement-breakpoint
ALTER TABLE "platform_ldap_provider_endpoints" ADD CONSTRAINT "platform_ldap_provider_endpoints_provider_fk" FOREIGN KEY ("provider_id","provider_kind") REFERENCES "public"."platform_ldap_provider_configurations"("provider_id","provider_kind") ON DELETE restrict ON UPDATE cascade;
--> statement-breakpoint
ALTER TABLE "platform_ldap_role_grants" ADD CONSTRAINT "platform_ldap_role_grants_identity_fk" FOREIGN KEY ("provider_id","external_identity_id") REFERENCES "public"."platform_ldap_external_identities"("provider_id","id") ON DELETE restrict ON UPDATE cascade;
--> statement-breakpoint
ALTER TABLE "platform_ldap_role_grants" ADD CONSTRAINT "platform_ldap_role_grants_mapping_fk" FOREIGN KEY ("mapping_rule_id") REFERENCES "public"."platform_ldap_mapping_rules"("id") ON DELETE restrict ON UPDATE cascade;
--> statement-breakpoint
ALTER TABLE "platform_ldap_role_grants" ADD CONSTRAINT "platform_ldap_role_grants_user_role_fk" FOREIGN KEY ("user_platform_role_id") REFERENCES "public"."user_platform_roles"("id") ON DELETE restrict ON UPDATE cascade;
--> statement-breakpoint
ALTER TABLE "platform_ldap_session_provenance" ADD CONSTRAINT "platform_ldap_session_provenance_session_fk" FOREIGN KEY ("session_id") REFERENCES "public"."auth_sessions"("id") ON DELETE restrict ON UPDATE cascade;
--> statement-breakpoint
ALTER TABLE "platform_ldap_session_provenance" ADD CONSTRAINT "platform_ldap_session_provenance_identity_fk" FOREIGN KEY ("provider_id","external_identity_id") REFERENCES "public"."platform_ldap_external_identities"("provider_id","id") ON DELETE restrict ON UPDATE cascade;
--> statement-breakpoint
ALTER TABLE "platform_ldap_session_provenance" ADD CONSTRAINT "platform_ldap_session_provenance_run_fk" FOREIGN KEY ("authentication_run_id") REFERENCES "public"."platform_ldap_authentication_runs"("id") ON DELETE restrict ON UPDATE cascade;
--> statement-breakpoint
ALTER TABLE "platform_ldap_session_provenance" ADD CONSTRAINT "platform_ldap_session_provenance_totp_fk" FOREIGN KEY ("totp_credential_id","user_id") REFERENCES "public"."totp_credentials"("id","user_id") ON DELETE restrict ON UPDATE cascade;
--> statement-breakpoint
ALTER TABLE "platform_ldap_test_runs" ADD CONSTRAINT "platform_ldap_test_runs_actor_user_id_users_id_fk" FOREIGN KEY ("actor_user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "platform_ldap_test_runs" ADD CONSTRAINT "platform_ldap_test_runs_provider_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."platform_ldap_provider_configurations"("provider_id") ON DELETE restrict ON UPDATE cascade;
--> statement-breakpoint
CREATE INDEX "platform_ldap_authentication_runs_expiry_idx" ON "platform_ldap_authentication_runs" USING btree ("state","expires_at","id");
--> statement-breakpoint
CREATE UNIQUE INDEX "platform_ldap_bind_secrets_live_key" ON "platform_ldap_bind_secrets" USING btree ("provider_id") WHERE "platform_ldap_bind_secrets"."retired_at" is null;
--> statement-breakpoint
CREATE UNIQUE INDEX "platform_ldap_external_identities_live_user_key" ON "platform_ldap_external_identities" USING btree ("provider_id","user_id") WHERE "platform_ldap_external_identities"."retired_at" is null;
--> statement-breakpoint
CREATE INDEX "platform_ldap_mapping_rules_provider_live_idx" ON "platform_ldap_mapping_rules" USING btree ("provider_id","enabled","priority","id") WHERE "platform_ldap_mapping_rules"."archived_at" is null;
--> statement-breakpoint
CREATE INDEX "platform_ldap_provider_endpoints_live_idx" ON "platform_ldap_provider_endpoints" USING btree ("provider_id","enabled","priority");
--> statement-breakpoint
CREATE UNIQUE INDEX "platform_ldap_role_grants_live_key" ON "platform_ldap_role_grants" USING btree ("provider_id","external_identity_id","mapping_rule_id","platform_role_id") WHERE "platform_ldap_role_grants"."revoked_at" is null;
--> statement-breakpoint
CREATE INDEX "platform_ldap_test_runs_provider_idx" ON "platform_ldap_test_runs" USING btree ("provider_id","started_at","id");

-- Global LDAP data is reachable only through narrowly scoped SECURITY DEFINER
-- functions. Runtime roles never receive direct table privileges.
ALTER TABLE public.platform_ldap_provider_configurations OWNER TO periapsis_migrator;
ALTER TABLE public.platform_ldap_provider_endpoints OWNER TO periapsis_migrator;
ALTER TABLE public.platform_ldap_bind_secrets OWNER TO periapsis_migrator;
ALTER TABLE public.platform_ldap_mapping_rules OWNER TO periapsis_migrator;
ALTER TABLE public.platform_ldap_external_identities OWNER TO periapsis_migrator;
ALTER TABLE public.platform_ldap_external_identity_aliases OWNER TO periapsis_migrator;
ALTER TABLE public.platform_ldap_role_grants OWNER TO periapsis_migrator;
ALTER TABLE public.platform_ldap_authentication_runs OWNER TO periapsis_migrator;
ALTER TABLE public.platform_ldap_session_provenance OWNER TO periapsis_migrator;
ALTER TABLE public.platform_ldap_test_runs OWNER TO periapsis_migrator;
--> statement-breakpoint
ALTER TABLE public.platform_ldap_provider_configurations FORCE ROW LEVEL SECURITY;
ALTER TABLE public.platform_ldap_provider_endpoints FORCE ROW LEVEL SECURITY;
ALTER TABLE public.platform_ldap_bind_secrets FORCE ROW LEVEL SECURITY;
ALTER TABLE public.platform_ldap_mapping_rules FORCE ROW LEVEL SECURITY;
ALTER TABLE public.platform_ldap_external_identities FORCE ROW LEVEL SECURITY;
ALTER TABLE public.platform_ldap_external_identity_aliases FORCE ROW LEVEL SECURITY;
ALTER TABLE public.platform_ldap_role_grants FORCE ROW LEVEL SECURITY;
ALTER TABLE public.platform_ldap_authentication_runs FORCE ROW LEVEL SECURITY;
ALTER TABLE public.platform_ldap_session_provenance FORCE ROW LEVEL SECURITY;
ALTER TABLE public.platform_ldap_test_runs FORCE ROW LEVEL SECURITY;
--> statement-breakpoint
REVOKE ALL ON TABLE
  public.platform_ldap_provider_configurations,
  public.platform_ldap_provider_endpoints,
  public.platform_ldap_bind_secrets,
  public.platform_ldap_mapping_rules,
  public.platform_ldap_external_identities,
  public.platform_ldap_external_identity_aliases,
  public.platform_ldap_role_grants,
  public.platform_ldap_authentication_runs,
  public.platform_ldap_session_provenance,
  public.platform_ldap_test_runs
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner;
--> statement-breakpoint
CREATE POLICY platform_ldap_provider_configurations_migrator_all ON public.platform_ldap_provider_configurations
  AS PERMISSIVE FOR ALL TO periapsis_migrator
  USING (true) WITH CHECK (true);
CREATE POLICY platform_ldap_provider_endpoints_migrator_all ON public.platform_ldap_provider_endpoints
  AS PERMISSIVE FOR ALL TO periapsis_migrator
  USING (true) WITH CHECK (true);
CREATE POLICY platform_ldap_bind_secrets_migrator_all ON public.platform_ldap_bind_secrets
  AS PERMISSIVE FOR ALL TO periapsis_migrator
  USING (true) WITH CHECK (true);
CREATE POLICY platform_ldap_mapping_rules_migrator_all ON public.platform_ldap_mapping_rules
  AS PERMISSIVE FOR ALL TO periapsis_migrator
  USING (true) WITH CHECK (true);
CREATE POLICY platform_ldap_external_identities_migrator_all ON public.platform_ldap_external_identities
  AS PERMISSIVE FOR ALL TO periapsis_migrator
  USING (true) WITH CHECK (true);
CREATE POLICY platform_ldap_external_identity_aliases_migrator_all ON public.platform_ldap_external_identity_aliases
  AS PERMISSIVE FOR ALL TO periapsis_migrator
  USING (true) WITH CHECK (true);
CREATE POLICY platform_ldap_role_grants_migrator_all ON public.platform_ldap_role_grants
  AS PERMISSIVE FOR ALL TO periapsis_migrator
  USING (true) WITH CHECK (true);
CREATE POLICY platform_ldap_authentication_runs_migrator_all ON public.platform_ldap_authentication_runs
  AS PERMISSIVE FOR ALL TO periapsis_migrator
  USING (true) WITH CHECK (true);
CREATE POLICY platform_ldap_session_provenance_migrator_all ON public.platform_ldap_session_provenance
  AS PERMISSIVE FOR ALL TO periapsis_migrator
  USING (true) WITH CHECK (true);
CREATE POLICY platform_ldap_test_runs_migrator_all ON public.platform_ldap_test_runs
  AS PERMISSIVE FOR ALL TO periapsis_migrator
  USING (true) WITH CHECK (true);
--> statement-breakpoint

CREATE FUNCTION app.private_platform_ldap_assert_object_v1(
  p_value jsonb,
  p_allowed_keys text[],
  p_required_keys text[],
  p_max_bytes integer
)
RETURNS void
LANGUAGE plpgsql
IMMUTABLE
SECURITY DEFINER
SET search_path = pg_catalog, app
AS $function$
BEGIN
  IF p_value IS NULL
     OR jsonb_typeof(p_value) <> 'object'
     OR pg_column_size(p_value) NOT BETWEEN 2 AND p_max_bytes
     OR EXISTS (
       SELECT 1 FROM jsonb_object_keys(p_value) AS key
       WHERE key <> ALL (p_allowed_keys)
     )
     OR EXISTS (
       SELECT 1 FROM unnest(p_required_keys) AS key
       WHERE NOT p_value ? key
     ) THEN
    RAISE EXCEPTION 'invalid platform LDAP request'
      USING ERRCODE = '22023';
  END IF;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_require_platform_ldap_permission_v1(
  p_session_id uuid,
  p_permission text,
  p_authentication_method text
)
RETURNS uuid
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor_id uuid := app.context_user_id();
BEGIN
  IF p_authentication_method <> 'ldap' THEN
    RETURN app.private_require_platform_identity_permission_v1(
      p_session_id,p_permission,p_authentication_method
    );
  END IF;
  IF p_session_id IS NULL
     OR uuid_extract_version(p_session_id) IS DISTINCT FROM 7
     OR p_permission <> ALL (ARRAY[
       'platform.identity_provider.read',
       'platform.identity_provider.manage',
       'platform.identity_provider.test',
       'platform.identity_policy.read',
       'platform.identity_policy.manage',
       'platform.identity_account.read',
       'platform.identity_account.manage'
     ]::text[]) THEN
    RAISE EXCEPTION 'invalid platform LDAP authorization request'
      USING ERRCODE = '22023';
  END IF;
  PERFORM 1
  FROM ONLY public.auth_sessions AS session
  JOIN ONLY public.users AS actor ON actor.id=session.user_id
  JOIN ONLY public.platform_ldap_session_provenance AS provenance
    ON provenance.session_id=session.id AND provenance.user_id=session.user_id
  JOIN ONLY public.platform_auth_providers AS provider
    ON provider.id=provenance.provider_id
  JOIN ONLY public.platform_ldap_provider_configurations AS configuration
    ON configuration.provider_id=provider.id
  JOIN ONLY public.platform_ldap_external_identities AS identity
    ON identity.provider_id=provider.id
   AND identity.id=provenance.external_identity_id
   AND identity.user_id=session.user_id
  JOIN ONLY public.totp_credentials AS factor
    ON factor.id=provenance.totp_credential_id
   AND factor.user_id=session.user_id
  WHERE session.id=p_session_id
    AND session.user_id=actor_id
    AND session.active_tenant_id IS NULL
    AND session.authentication_method='ldap'
    AND session.mfa_satisfied_at IS NOT NULL
    AND session.revoked_at IS NULL
    AND session.idle_expires_at>transaction_timestamp()
    AND session.absolute_expires_at>transaction_timestamp()
    AND actor.active
    AND provider.kind='ldap' AND provider.enabled
    AND provider.archived_at IS NULL
    AND provider.version=provenance.provider_version
    AND configuration.configuration_revision=provenance.configuration_revision
    AND configuration.security_revision=provenance.security_revision
    AND configuration.mapping_revision=provenance.mapping_revision
    AND identity.version=provenance.identity_version
    AND identity.disabled_at IS NULL AND identity.retired_at IS NULL
    AND factor.confirmed_at IS NOT NULL AND factor.disabled_at IS NULL
    AND factor.security_revision=provenance.totp_security_revision
  FOR SHARE OF session,actor,provenance,provider,configuration,identity,factor;
  IF NOT FOUND
     OR NOT app.platform_user_has_permission(actor_id,p_permission) THEN
    RAISE EXCEPTION 'required platform LDAP permission is missing'
      USING ERRCODE = '42501';
  END IF;
  RETURN actor_id;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_platform_ldap_audit_v1(
  p_audit jsonb,
  p_actor_user_id uuid,
  p_action text,
  p_resource_type text,
  p_resource_id uuid,
  p_outcome public.audit_outcome,
  p_metadata jsonb
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  event_id uuid;
  request_id uuid;
  correlation_id uuid;
  ip_address inet;
  actor_type public.audit_actor_type := 'system';
BEGIN
  PERFORM app.private_platform_ldap_assert_object_v1(
    p_audit,
    ARRAY['eventId','requestId','correlationId','ipAddress','userAgent',
      'authenticationMethod','reason'],
    ARRAY['eventId','requestId','correlationId','authenticationMethod'],8192
  );
  event_id := (p_audit->>'eventId')::uuid;
  request_id := (p_audit->>'requestId')::uuid;
  correlation_id := (p_audit->>'correlationId')::uuid;
  IF uuid_extract_version(event_id) IS DISTINCT FROM 7
     OR uuid_extract_version(request_id) IS DISTINCT FROM 7
     OR uuid_extract_version(correlation_id) IS DISTINCT FROM 7
     OR p_audit->>'authenticationMethod' NOT IN (
       'bootstrap_totp','ldap','oidc','passkey','recovery_code','saml','totp'
     )
     OR coalesce(p_metadata,'{}'::jsonb) ?| ARRAY[
       'password','bindPassword','bindSecret','secret','token','totpCode',
       'subject','subjectCiphertext','subjectDigest','receiptDigest'
     ] THEN
    RAISE EXCEPTION 'unsafe platform LDAP audit envelope'
      USING ERRCODE = '22023';
  END IF;
  IF p_audit ? 'ipAddress' AND p_audit->>'ipAddress' <> '' THEN
    ip_address := (p_audit->>'ipAddress')::inet;
  END IF;
  IF p_actor_user_id IS NOT NULL THEN actor_type := 'user'; END IF;
  PERFORM app.append_platform_audit_event(
    event_id,actor_type,p_actor_user_id,p_action,p_resource_type,p_resource_id,
    request_id,correlation_id,ip_address,p_audit->>'userAgent',
    p_audit->>'authenticationMethod',p_outcome,p_audit->>'reason',
    coalesce(p_metadata,'{}'::jsonb)
  );
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_platform_ldap_provider_document_v1(p_provider_id uuid)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
SELECT jsonb_build_object(
  'id',provider.id,'key',provider.key,'displayName',provider.display_name,
  'description',provider.description,'kind','ldap','enabled',provider.enabled,
  'platformLoginEnabled',provider.enabled,
  'platformLoginActivationAvailable',NOT provider.enabled
    AND provider.archived_at IS NULL
    AND EXISTS (
      SELECT 1 FROM ONLY public.platform_ldap_provider_endpoints AS ready_endpoint
      WHERE ready_endpoint.provider_id=provider.id AND ready_endpoint.enabled
    )
    AND EXISTS (
      SELECT 1 FROM ONLY public.platform_ldap_bind_secrets AS ready_secret
      WHERE ready_secret.provider_id=provider.id AND ready_secret.retired_at IS NULL
    )
    AND EXISTS (
      SELECT 1
      FROM ONLY public.platform_ldap_mapping_rules AS ready_mapping
      JOIN ONLY public.platform_roles AS ready_role
        ON ready_role.id=ready_mapping.platform_role_id
      WHERE ready_mapping.provider_id=provider.id AND ready_mapping.enabled
        AND ready_mapping.archived_at IS NULL
        AND ready_role.key<>'platform_super_admin'
    ),
  'activationAvailable',false,'configured',true,
  'secretPresent',EXISTS (
    SELECT 1 FROM ONLY public.platform_ldap_bind_secrets AS projected_secret
    WHERE projected_secret.provider_id=provider.id
      AND projected_secret.retired_at IS NULL
  ),
  'configurationRevision',configuration.configuration_revision,
  'securityRevision',configuration.security_revision,
  'planRevision',policy.plan_revision,
  'assurancePolicyRevision',policy.assurance_policy_revision,
  'accountMode',CASE WHEN provider.enabled THEN 'existing_identity' ELSE 'disabled' END,
  'version',provider.version,'archivedAt',provider.archived_at,
  'createdAt',provider.created_at,'updatedAt',provider.updated_at,
  'configuration',jsonb_build_object(
    'template',configuration.template,
    'verifyCertificate',configuration.verify_certificate,
    'customCaPem',configuration.custom_ca_pem,
    'connectTimeoutMs',configuration.connect_timeout_ms,
    'operationTimeoutMs',configuration.operation_timeout_ms,
    'bindDn',configuration.bind_dn,
    'userBaseDn',configuration.user_base_dn,
    'groupBaseDn',configuration.group_base_dn,
    'userSearchFilter',configuration.user_search_filter,
    'groupSearchFilter',configuration.group_search_filter,
    'userDnTemplate',configuration.user_dn_template,
    'pageSize',configuration.page_size,'maxPages',configuration.max_pages,
    'maxEntries',configuration.max_entries,
    'maxResponseBytes',configuration.max_response_bytes,
    'referralMode',configuration.referral_mode,
    'maxReferralHops',configuration.max_referral_hops,
    'nestedGroupMode',configuration.nested_group_mode,
    'maxNestedGroupDepth',configuration.max_nested_group_depth,
    'maxGroups',configuration.max_groups,
    'firstNameAttribute',configuration.first_name_attribute,
    'lastNameAttribute',configuration.last_name_attribute,
    'displayNameAttribute',configuration.display_name_attribute,
    'usernameAttribute',configuration.username_attribute,
    'alternateUsernameAttribute',configuration.alternate_username_attribute,
    'emailAttribute',configuration.email_attribute,
    'immutableSubjectAttribute',configuration.immutable_subject_attribute,
    'immutableSubjectFormat',configuration.immutable_subject_format,
    'groupMembershipAttribute',configuration.group_membership_attribute,
    'posixMemberUidAttribute',configuration.posix_member_uid_attribute,
    'posixGidNumberAttribute',configuration.posix_gid_number_attribute,
    'accountStatusMode',configuration.account_status_mode,
    'accountStatusAttribute',configuration.account_status_attribute,
    'accountDisabledValue',configuration.account_disabled_value,
    'jitMode',configuration.jit_mode,'noMatchPolicy',configuration.no_match_policy,
    'deprovisionMode',configuration.deprovision_mode,
    'deprovisionGraceSeconds',configuration.deprovision_grace_seconds,
    'syncIntervalSeconds',configuration.sync_interval_seconds
  ),
  'endpoints',coalesce((
    SELECT jsonb_agg(jsonb_build_object(
      'id',endpoint.id,'priority',endpoint.priority,'host',endpoint.host,
      'port',endpoint.port,'transport',endpoint.transport,
      'tlsServerName',endpoint.tls_server_name,
      'referralAllowed',endpoint.referral_allowed,'enabled',endpoint.enabled
    ) ORDER BY endpoint.priority,endpoint.id)
    FROM ONLY public.platform_ldap_provider_endpoints AS endpoint
    WHERE endpoint.provider_id=provider.id
  ),'[]'::jsonb),
  'mappings',coalesce((
    SELECT jsonb_agg(jsonb_build_object(
      'id',mapping.id,'matcherType',mapping.matcher_type,
      'matcherValue',mapping.matcher_value,
      'caseSensitive',mapping.case_sensitive,'priority',mapping.priority,
      'platformRoleId',mapping.platform_role_id,
      'reconciliationMode',mapping.reconciliation_mode,
      'enabled',mapping.enabled,'notes',mapping.notes,
      'lastMatchedAt',mapping.last_matched_at,'version',mapping.version,
      'archivedAt',mapping.archived_at
    ) ORDER BY mapping.priority,mapping.id)
    FROM ONLY public.platform_ldap_mapping_rules AS mapping
    WHERE mapping.provider_id=provider.id
  ),'[]'::jsonb)
)
FROM ONLY public.platform_auth_providers AS provider
JOIN ONLY public.platform_federated_provider_policies AS policy
  ON policy.provider_id=provider.id AND policy.provider_kind='ldap'
JOIN ONLY public.platform_ldap_provider_configurations AS configuration
  ON configuration.provider_id=provider.id
WHERE provider.id=p_provider_id AND provider.kind='ldap';
$function$;
--> statement-breakpoint

-- The platform provider catalog remains the single API source for every
-- protocol. V2 preserves the OIDC/SAML V1 projections byte-for-byte and adds
-- only the physically separate platform LDAP arm.
CREATE FUNCTION app.private_platform_auth_provider_document_v2(p_provider_id uuid)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT CASE provider.kind
    WHEN 'ldap' THEN app.private_platform_ldap_provider_document_v1(provider.id)
    ELSE app.private_platform_auth_provider_document_v1(provider.id)
  END
  FROM ONLY public.platform_auth_providers AS provider
  WHERE provider.id=p_provider_id;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.list_platform_auth_providers_v2(
  p_session_id uuid,p_authentication_method text,p_after uuid DEFAULT NULL,
  p_limit integer DEFAULT 50,p_include_archived boolean DEFAULT false
)
RETURNS TABLE(document jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 200
     OR p_include_archived IS NULL
     OR (p_after IS NOT NULL
       AND uuid_extract_version(p_after) IS DISTINCT FROM 7) THEN
    RAISE EXCEPTION 'invalid platform identity provider list request'
      USING ERRCODE='22023';
  END IF;
  PERFORM app.private_require_platform_ldap_permission_v1(
    p_session_id,'platform.identity_provider.read',p_authentication_method
  );
  RETURN QUERY
  SELECT jsonb_build_object(
    'id',provider.id,'key',provider.key,'displayName',provider.display_name,
    'description',provider.description,'kind',provider.kind,
    'enabled',provider.enabled,
    'activationAvailable',CASE provider.kind
      WHEN 'ldap' THEN false
      ELSE app.private_platform_oidc_provider_activation_available_v1(provider.id)
    END,
    'platformLoginEnabled',CASE provider.kind
      WHEN 'oidc' THEN coalesce(oidc_login.enabled,false)
      WHEN 'saml' THEN coalesce(saml_login.enabled,false)
      WHEN 'ldap' THEN provider.enabled
      ELSE false END,
    'platformLoginActivationAvailable',CASE provider.kind
      WHEN 'oidc' THEN app.private_platform_oidc_direct_activation_available_v1(provider.id)
      WHEN 'saml' THEN app.private_platform_saml_direct_activation_available_v1(provider.id)
      WHEN 'ldap' THEN NOT provider.enabled
        AND provider.archived_at IS NULL
        AND ldap_configuration.provider_id IS NOT NULL
        AND EXISTS (
          SELECT 1 FROM ONLY public.platform_ldap_provider_endpoints AS endpoint
          WHERE endpoint.provider_id=provider.id AND endpoint.enabled
        )
        AND EXISTS (
          SELECT 1 FROM ONLY public.platform_ldap_bind_secrets AS bind_secret
          WHERE bind_secret.provider_id=provider.id
            AND bind_secret.retired_at IS NULL
        )
        AND EXISTS (
          SELECT 1
          FROM ONLY public.platform_ldap_mapping_rules AS mapping
          JOIN ONLY public.platform_roles AS mapped_role
            ON mapped_role.id=mapping.platform_role_id
          WHERE mapping.provider_id=provider.id AND mapping.enabled
            AND mapping.archived_at IS NULL
            AND mapped_role.key<>'platform_super_admin'
        )
      ELSE false END,
    'configured',CASE provider.kind
      WHEN 'oidc' THEN oidc.provider_id IS NOT NULL
      WHEN 'saml' THEN saml.provider_id IS NOT NULL
      WHEN 'ldap' THEN ldap_configuration.provider_id IS NOT NULL
      ELSE false END,
    'secretPresent',CASE provider.kind
      WHEN 'oidc' THEN EXISTS (
        SELECT 1 FROM ONLY public.platform_oidc_client_secrets AS oidc_secret
        WHERE oidc_secret.provider_id=provider.id
          AND oidc_secret.retired_at IS NULL
      )
      WHEN 'saml' THEN EXISTS (
        SELECT 1 FROM ONLY public.platform_saml_sp_keys AS sp_key
        WHERE sp_key.provider_id=provider.id AND sp_key.retired_at IS NULL
      )
      WHEN 'ldap' THEN EXISTS (
        SELECT 1 FROM ONLY public.platform_ldap_bind_secrets AS bind_secret
        WHERE bind_secret.provider_id=provider.id
          AND bind_secret.retired_at IS NULL
      )
      ELSE false END,
    'archivedAt',provider.archived_at,'version',provider.version,
    'createdAt',provider.created_at,'updatedAt',provider.updated_at
  )
  FROM ONLY public.platform_auth_providers AS provider
  JOIN ONLY public.platform_federated_provider_policies AS policy
    ON policy.provider_id=provider.id
  LEFT JOIN ONLY public.platform_oidc_login_policies AS oidc_login
    ON oidc_login.provider_id=provider.id AND provider.kind='oidc'
  LEFT JOIN ONLY public.platform_saml_login_policies AS saml_login
    ON saml_login.provider_id=provider.id AND provider.kind='saml'
  LEFT JOIN ONLY public.platform_oidc_provider_configurations AS oidc
    ON oidc.provider_id=provider.id AND provider.kind='oidc'
  LEFT JOIN ONLY public.platform_saml_provider_configurations AS saml
    ON saml.provider_id=provider.id AND provider.kind='saml'
  LEFT JOIN ONLY public.platform_ldap_provider_configurations AS ldap_configuration
    ON ldap_configuration.provider_id=provider.id AND provider.kind='ldap'
  WHERE (p_after IS NULL OR provider.id>p_after)
    AND (p_include_archived OR provider.archived_at IS NULL)
  ORDER BY provider.id
  LIMIT p_limit;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.get_platform_auth_provider_v2(
  p_session_id uuid,p_provider_id uuid,p_authentication_method text
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE result jsonb;
BEGIN
  IF p_provider_id IS NULL
     OR uuid_extract_version(p_provider_id) IS DISTINCT FROM 7 THEN
    RAISE EXCEPTION 'invalid platform identity provider identifier'
      USING ERRCODE='22023';
  END IF;
  PERFORM app.private_require_platform_ldap_permission_v1(
    p_session_id,'platform.identity_provider.read',p_authentication_method
  );
  result:=app.private_platform_auth_provider_document_v2(p_provider_id);
  IF result IS NULL THEN
    RAISE EXCEPTION 'platform identity provider does not exist'
      USING ERRCODE='P0002';
  END IF;
  RETURN result;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_replace_platform_ldap_configuration_v1(
  p_provider_id uuid,
  p_actor_user_id uuid,
  p_configuration jsonb,
  p_endpoints jsonb,
  p_create boolean
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  endpoint jsonb;
  endpoint_id uuid;
BEGIN
  PERFORM app.private_platform_ldap_assert_object_v1(
    p_configuration,
    ARRAY[
      'template','verifyCertificate','customCaPem','connectTimeoutMs',
      'operationTimeoutMs','bindDn','userBaseDn','groupBaseDn',
      'userSearchFilter','groupSearchFilter','userDnTemplate','pageSize',
      'maxPages','maxEntries','maxResponseBytes','referralMode',
      'maxReferralHops','nestedGroupMode','maxNestedGroupDepth','maxGroups',
      'firstNameAttribute','lastNameAttribute','displayNameAttribute',
      'usernameAttribute','alternateUsernameAttribute','emailAttribute',
      'immutableSubjectAttribute','immutableSubjectFormat',
      'groupMembershipAttribute','posixMemberUidAttribute',
      'posixGidNumberAttribute','accountStatusMode','accountStatusAttribute',
      'accountDisabledValue','jitMode','noMatchPolicy','deprovisionMode',
      'deprovisionGraceSeconds','syncIntervalSeconds'
    ],
    ARRAY[
      'template','verifyCertificate','connectTimeoutMs','operationTimeoutMs',
      'bindDn','userBaseDn','userSearchFilter','pageSize','maxPages',
      'maxEntries','maxResponseBytes','referralMode','maxReferralHops',
      'nestedGroupMode','maxNestedGroupDepth','maxGroups',
      'firstNameAttribute','lastNameAttribute','displayNameAttribute',
      'usernameAttribute','immutableSubjectAttribute','immutableSubjectFormat',
      'accountStatusMode','jitMode','noMatchPolicy','deprovisionMode',
      'deprovisionGraceSeconds'
    ],262144
  );
  IF p_endpoints IS NULL OR jsonb_typeof(p_endpoints)<>'array'
     OR jsonb_array_length(p_endpoints) NOT BETWEEN 1 AND 8
     OR pg_column_size(p_endpoints)>65536 THEN
    RAISE EXCEPTION 'invalid platform LDAP endpoints'
      USING ERRCODE='22023';
  END IF;
  FOR endpoint IN SELECT value FROM jsonb_array_elements(p_endpoints)
  LOOP
    PERFORM app.private_platform_ldap_assert_object_v1(
      endpoint,
      ARRAY['id','priority','host','port','transport','tlsServerName',
        'referralAllowed','enabled'],
      ARRAY['id','priority','host','port','transport','tlsServerName',
        'referralAllowed','enabled'],4096
    );
    endpoint_id := (endpoint->>'id')::uuid;
    IF uuid_extract_version(endpoint_id) IS DISTINCT FROM 7 THEN
      RAISE EXCEPTION 'invalid platform LDAP endpoint id'
        USING ERRCODE='22023';
    END IF;
  END LOOP;

  INSERT INTO public.platform_ldap_provider_configurations (
    provider_id,provider_kind,template,verify_certificate,custom_ca_pem,
    connect_timeout_ms,operation_timeout_ms,bind_dn,user_base_dn,group_base_dn,
    user_search_filter,group_search_filter,user_dn_template,page_size,max_pages,
    max_entries,max_response_bytes,referral_mode,max_referral_hops,
    nested_group_mode,max_nested_group_depth,max_groups,first_name_attribute,
    last_name_attribute,display_name_attribute,username_attribute,
    alternate_username_attribute,email_attribute,immutable_subject_attribute,
    immutable_subject_format,group_membership_attribute,
    posix_member_uid_attribute,posix_gid_number_attribute,account_status_mode,
    account_status_attribute,account_disabled_value,jit_mode,no_match_policy,
    deprovision_mode,deprovision_grace_seconds,sync_interval_seconds,
    configuration_revision,security_revision,mapping_revision,
    updated_by_user_id,created_at,updated_at
  ) VALUES (
    p_provider_id,'ldap',(p_configuration->>'template')::public.ldap_provider_template,
    (p_configuration->>'verifyCertificate')::boolean,
    nullif(p_configuration->>'customCaPem',''),
    (p_configuration->>'connectTimeoutMs')::integer,
    (p_configuration->>'operationTimeoutMs')::integer,
    p_configuration->>'bindDn',p_configuration->>'userBaseDn',
    nullif(p_configuration->>'groupBaseDn',''),
    p_configuration->>'userSearchFilter',
    nullif(p_configuration->>'groupSearchFilter',''),
    nullif(p_configuration->>'userDnTemplate',''),
    (p_configuration->>'pageSize')::integer,
    (p_configuration->>'maxPages')::integer,
    (p_configuration->>'maxEntries')::integer,
    (p_configuration->>'maxResponseBytes')::integer,
    (p_configuration->>'referralMode')::public.ldap_referral_mode,
    (p_configuration->>'maxReferralHops')::integer,
    (p_configuration->>'nestedGroupMode')::public.ldap_nested_group_mode,
    (p_configuration->>'maxNestedGroupDepth')::integer,
    (p_configuration->>'maxGroups')::integer,
    p_configuration->>'firstNameAttribute',
    p_configuration->>'lastNameAttribute',
    p_configuration->>'displayNameAttribute',
    p_configuration->>'usernameAttribute',
    nullif(p_configuration->>'alternateUsernameAttribute',''),
    nullif(p_configuration->>'emailAttribute',''),
    p_configuration->>'immutableSubjectAttribute',
    (p_configuration->>'immutableSubjectFormat')::public.identity_subject_format,
    nullif(p_configuration->>'groupMembershipAttribute',''),
    nullif(p_configuration->>'posixMemberUidAttribute',''),
    nullif(p_configuration->>'posixGidNumberAttribute',''),
    (p_configuration->>'accountStatusMode')::public.ldap_account_status_mode,
    nullif(p_configuration->>'accountStatusAttribute',''),
    nullif(p_configuration->>'accountDisabledValue',''),
    (p_configuration->>'jitMode')::public.identity_jit_mode,
    (p_configuration->>'noMatchPolicy')::public.identity_no_match_policy,
    (p_configuration->>'deprovisionMode')::public.identity_deprovision_mode,
    (p_configuration->>'deprovisionGraceSeconds')::integer,
    nullif(p_configuration->>'syncIntervalSeconds','')::integer,
    1,1,1,p_actor_user_id,transaction_timestamp(),transaction_timestamp()
  )
  ON CONFLICT (provider_id) DO UPDATE SET
    template=excluded.template,verify_certificate=excluded.verify_certificate,
    custom_ca_pem=excluded.custom_ca_pem,
    connect_timeout_ms=excluded.connect_timeout_ms,
    operation_timeout_ms=excluded.operation_timeout_ms,bind_dn=excluded.bind_dn,
    user_base_dn=excluded.user_base_dn,group_base_dn=excluded.group_base_dn,
    user_search_filter=excluded.user_search_filter,
    group_search_filter=excluded.group_search_filter,
    user_dn_template=excluded.user_dn_template,page_size=excluded.page_size,
    max_pages=excluded.max_pages,max_entries=excluded.max_entries,
    max_response_bytes=excluded.max_response_bytes,
    referral_mode=excluded.referral_mode,
    max_referral_hops=excluded.max_referral_hops,
    nested_group_mode=excluded.nested_group_mode,
    max_nested_group_depth=excluded.max_nested_group_depth,
    max_groups=excluded.max_groups,
    first_name_attribute=excluded.first_name_attribute,
    last_name_attribute=excluded.last_name_attribute,
    display_name_attribute=excluded.display_name_attribute,
    username_attribute=excluded.username_attribute,
    alternate_username_attribute=excluded.alternate_username_attribute,
    email_attribute=excluded.email_attribute,
    immutable_subject_attribute=excluded.immutable_subject_attribute,
    immutable_subject_format=excluded.immutable_subject_format,
    group_membership_attribute=excluded.group_membership_attribute,
    posix_member_uid_attribute=excluded.posix_member_uid_attribute,
    posix_gid_number_attribute=excluded.posix_gid_number_attribute,
    account_status_mode=excluded.account_status_mode,
    account_status_attribute=excluded.account_status_attribute,
    account_disabled_value=excluded.account_disabled_value,
    jit_mode=excluded.jit_mode,no_match_policy=excluded.no_match_policy,
    deprovision_mode=excluded.deprovision_mode,
    deprovision_grace_seconds=excluded.deprovision_grace_seconds,
    sync_interval_seconds=excluded.sync_interval_seconds,
    configuration_revision=public.platform_ldap_provider_configurations.configuration_revision+1,
    security_revision=public.platform_ldap_provider_configurations.security_revision+1,
    updated_by_user_id=p_actor_user_id,updated_at=transaction_timestamp();

  IF NOT p_create AND NOT FOUND THEN
    RAISE EXCEPTION 'platform LDAP provider configuration not found'
      USING ERRCODE='P0002';
  END IF;
  DELETE FROM public.platform_ldap_provider_endpoints
  WHERE provider_id=p_provider_id;
  INSERT INTO public.platform_ldap_provider_endpoints (
    id,provider_id,provider_kind,priority,host,port,transport,tls_server_name,
    referral_allowed,enabled,created_at,updated_at
  )
  SELECT (value->>'id')::uuid,p_provider_id,'ldap',
    (value->>'priority')::integer,lower(btrim(value->>'host')),
    (value->>'port')::integer,(value->>'transport')::public.ldap_transport,
    lower(btrim(value->>'tlsServerName')),
    (value->>'referralAllowed')::boolean,(value->>'enabled')::boolean,
    transaction_timestamp(),transaction_timestamp()
  FROM jsonb_array_elements(p_endpoints);
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.create_platform_ldap_provider_v1(p_request jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor_id uuid;
  provider_id uuid := (p_request->>'providerId')::uuid;
  command_id uuid := (p_request->>'commandId')::uuid;
  command_key_digest bytea := decode(p_request->>'keyDigest','hex');
  command_request_digest bytea := decode(p_request->>'requestDigest','hex');
  existing public.platform_identity_provider_commands%ROWTYPE;
BEGIN
  PERFORM app.private_platform_ldap_assert_object_v1(
    p_request,
    ARRAY['sessionId','authenticationMethod','providerId','commandId',
      'keyDigest','requestDigest','key','displayName','description',
      'configuration','endpoints','audit'],
    ARRAY['sessionId','authenticationMethod','providerId','commandId',
      'keyDigest','requestDigest','key','displayName','description',
      'configuration','endpoints','audit'],524288
  );
  actor_id := app.private_require_platform_ldap_permission_v1(
    (p_request->>'sessionId')::uuid,'platform.identity_provider.manage',
    p_request->>'authenticationMethod'
  );
  IF uuid_extract_version(provider_id) IS DISTINCT FROM 7
     OR uuid_extract_version(command_id) IS DISTINCT FROM 7
     OR octet_length(command_key_digest)<>32
     OR octet_length(command_request_digest)<>32 THEN
    RAISE EXCEPTION 'invalid platform LDAP create command'
      USING ERRCODE='22023';
  END IF;
  SELECT * INTO existing
  FROM ONLY public.platform_identity_provider_commands AS command
  WHERE command.actor_user_id=actor_id AND command.operation='provider.create'
    AND command.key_digest=command_key_digest
  FOR UPDATE;
  IF FOUND THEN
    IF existing.request_digest<>command_request_digest THEN
      RAISE EXCEPTION 'platform LDAP create replay mismatch'
        USING ERRCODE='23505';
    END IF;
    RETURN jsonb_build_object(
      'providerId',existing.result_provider_id,
      'version',existing.result_version,'replayed',true,
      'document',app.private_platform_ldap_provider_document_v1(
        existing.result_provider_id
      )
    );
  END IF;

  INSERT INTO public.platform_auth_providers (
    id,key,display_name,description,kind,enabled,
    created_by_user_id,updated_by_user_id,version,created_at,updated_at
  ) VALUES (
    provider_id,lower(btrim(p_request->>'key')),btrim(p_request->>'displayName'),
    btrim(p_request->>'description'),'ldap',false,actor_id,actor_id,1,
    transaction_timestamp(),transaction_timestamp()
  );
  INSERT INTO public.platform_federated_provider_policies (
    provider_id,provider_kind,configuration_revision,security_revision,
    plan_revision,assurance_policy_revision,account_mode,
    platform_login_enabled,enabled,created_at,updated_at
  ) VALUES (
    provider_id,'ldap',1,1,1,1,'disabled',false,false,
    transaction_timestamp(),transaction_timestamp()
  );
  PERFORM app.private_replace_platform_ldap_configuration_v1(
    provider_id,actor_id,p_request->'configuration',p_request->'endpoints',true
  );
  INSERT INTO public.platform_identity_provider_commands (
    id,actor_user_id,operation,key_digest,request_digest,
    result_provider_id,result_version,created_at,expires_at
  ) VALUES (
    command_id,actor_id,'provider.create',command_key_digest,command_request_digest,
    provider_id,1,transaction_timestamp(),transaction_timestamp()+interval '24 hours'
  );
  PERFORM app.private_platform_ldap_audit_v1(
    p_request->'audit',actor_id,'platform.ldap_provider.created',
    'platform_ldap_provider',provider_id,'success',
    jsonb_build_object('key',lower(btrim(p_request->>'key')),
      'enabled',false,'secretConfigured',false)
  );
  RETURN jsonb_build_object(
    'providerId',provider_id,'version',1,'replayed',false,
    'document',app.private_platform_ldap_provider_document_v1(provider_id)
  );
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.get_platform_ldap_provider_v1(
  p_session_id uuid,p_authentication_method text,p_provider_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE result jsonb;
BEGIN
  PERFORM app.private_require_platform_ldap_permission_v1(
    p_session_id,'platform.identity_provider.read',p_authentication_method
  );
  result:=app.private_platform_ldap_provider_document_v1(p_provider_id);
  IF result IS NULL THEN
    RAISE EXCEPTION 'platform LDAP provider not found' USING ERRCODE='P0002';
  END IF;
  RETURN result;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.list_platform_ldap_providers_v1(
  p_session_id uuid,p_authentication_method text,p_include_archived boolean
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  PERFORM app.private_require_platform_ldap_permission_v1(
    p_session_id,'platform.identity_provider.read',p_authentication_method
  );
  RETURN coalesce((
    SELECT jsonb_agg(app.private_platform_ldap_provider_document_v1(provider.id)
      ORDER BY provider.id)
    FROM ONLY public.platform_auth_providers AS provider
    WHERE provider.kind='ldap'
      AND (p_include_archived OR provider.archived_at IS NULL)
  ),'[]'::jsonb);
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.update_platform_ldap_provider_v1(p_request jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor_id uuid;
  provider_id uuid := (p_request->>'providerId')::uuid;
  expected_version bigint := (p_request->>'expectedVersion')::bigint;
BEGIN
  PERFORM app.private_platform_ldap_assert_object_v1(
    p_request,
    ARRAY['sessionId','authenticationMethod','providerId','expectedVersion',
      'key','displayName','description','configuration','endpoints','audit'],
    ARRAY['sessionId','authenticationMethod','providerId','expectedVersion',
      'key','displayName','description','configuration','endpoints','audit'],524288
  );
  actor_id:=app.private_require_platform_ldap_permission_v1(
    (p_request->>'sessionId')::uuid,'platform.identity_provider.manage',
    p_request->>'authenticationMethod'
  );
  UPDATE ONLY public.platform_auth_providers AS provider
  SET key=lower(btrim(p_request->>'key')),
      display_name=btrim(p_request->>'displayName'),
      description=btrim(p_request->>'description'),
      updated_by_user_id=actor_id,version=version+1,
      updated_at=transaction_timestamp()
  WHERE provider.id=provider_id AND provider.kind='ldap'
    AND provider.archived_at IS NULL AND provider.version=expected_version;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'platform LDAP provider version conflict'
      USING ERRCODE='40001';
  END IF;
  PERFORM app.private_replace_platform_ldap_configuration_v1(
    provider_id,actor_id,p_request->'configuration',p_request->'endpoints',false
  );
  UPDATE ONLY public.platform_federated_provider_policies AS policy
  SET configuration_revision=configuration_revision+1,
      security_revision=security_revision+1,
      updated_at=transaction_timestamp()
  WHERE policy.provider_id=provider_id AND policy.provider_kind='ldap';
  PERFORM app.private_platform_ldap_audit_v1(
    p_request->'audit',actor_id,'platform.ldap_provider.updated',
    'platform_ldap_provider',provider_id,'success',
    jsonb_build_object('version',expected_version+1)
  );
  RETURN app.private_platform_ldap_provider_document_v1(provider_id);
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.rotate_platform_ldap_bind_secret_v1(p_request jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor_id uuid;
  provider_id uuid := (p_request->>'providerId')::uuid;
  expected_version bigint := (p_request->>'expectedVersion')::bigint;
  next_revision bigint;
  secret_id uuid := (p_request->>'secretId')::uuid;
  nonce bytea := decode(p_request->>'nonce','hex');
  ciphertext bytea := decode(p_request->>'ciphertext','hex');
BEGIN
  PERFORM app.private_platform_ldap_assert_object_v1(
    p_request,
    ARRAY['sessionId','authenticationMethod','providerId',
      'expectedVersion','secretId','keyVersion','nonce','ciphertext',
      'audit'],
    ARRAY['sessionId','authenticationMethod','providerId',
      'expectedVersion','secretId','keyVersion','nonce','ciphertext',
      'audit'],32768
  );
  actor_id:=app.private_require_platform_ldap_permission_v1(
    (p_request->>'sessionId')::uuid,'platform.identity_provider.manage',
    p_request->>'authenticationMethod'
  );
  IF uuid_extract_version(secret_id) IS DISTINCT FROM 7
     OR octet_length(nonce)<>12
     OR octet_length(ciphertext) NOT BETWEEN 17 AND 8192 THEN
    RAISE EXCEPTION 'invalid platform LDAP bind secret'
      USING ERRCODE='22023';
  END IF;
  PERFORM 1
  FROM ONLY public.platform_auth_providers AS provider
  WHERE provider.id=provider_id AND provider.kind='ldap'
    AND provider.archived_at IS NULL AND provider.version=expected_version
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'platform LDAP provider version conflict'
      USING ERRCODE='40001';
  END IF;
  PERFORM 1
  FROM ONLY public.platform_ldap_provider_configurations AS configuration
  WHERE configuration.provider_id=provider_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'platform LDAP provider not found' USING ERRCODE='P0002';
  END IF;
  SELECT coalesce(max(secret.revision),1)+1 INTO next_revision
  FROM ONLY public.platform_ldap_bind_secrets AS secret
  WHERE secret.provider_id=provider_id;
  UPDATE ONLY public.platform_ldap_bind_secrets AS bind_secret
  SET retired_at=transaction_timestamp()
  WHERE bind_secret.provider_id=provider_id AND bind_secret.retired_at IS NULL;
  INSERT INTO public.platform_ldap_bind_secrets (
    id,provider_id,provider_kind,revision,key_version,nonce,ciphertext,
    rotated_by_user_id,created_at
  ) VALUES (
    secret_id,provider_id,'ldap',next_revision,
    (p_request->>'keyVersion')::integer,nonce,ciphertext,actor_id,
    transaction_timestamp()
  );
  UPDATE ONLY public.platform_ldap_provider_configurations AS configuration
  SET security_revision=security_revision+1,updated_by_user_id=actor_id,
      updated_at=transaction_timestamp()
  WHERE configuration.provider_id=provider_id;
  UPDATE ONLY public.platform_federated_provider_policies AS policy
  SET security_revision=security_revision+1,updated_at=transaction_timestamp()
  WHERE policy.provider_id=provider_id AND policy.provider_kind='ldap';
  UPDATE ONLY public.platform_auth_providers AS provider
  SET version=version+1,updated_by_user_id=actor_id,
      updated_at=transaction_timestamp()
  WHERE provider.id=provider_id AND provider.kind='ldap';
  PERFORM app.private_platform_ldap_audit_v1(
    p_request->'audit',actor_id,'platform.ldap_provider.bind_secret_rotated',
    'platform_ldap_provider',provider_id,'success',
    jsonb_build_object('secretRevision',next_revision)
  );
  RETURN jsonb_build_object(
    'providerId',provider_id,'secretConfigured',true,
    'version',expected_version+1,'secretRevision',next_revision
  );
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.put_platform_ldap_mapping_rule_v1(p_request jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor_id uuid;
  provider_id uuid := (p_request->>'providerId')::uuid;
  mapping_id uuid := (p_request->>'mappingId')::uuid;
  expected_version bigint;
  mapping_version bigint;
  role_key text;
BEGIN
  PERFORM app.private_platform_ldap_assert_object_v1(
    p_request,
    ARRAY['sessionId','authenticationMethod','providerId','mappingId',
      'expectedVersion','matcherType','matcherValue','caseSensitive','priority',
      'platformRoleId','reconciliationMode','enabled','notes','audit'],
    ARRAY['sessionId','authenticationMethod','providerId','mappingId',
      'matcherType','matcherValue','caseSensitive','priority','platformRoleId',
      'reconciliationMode','enabled','notes','audit'],32768
  );
  actor_id:=app.private_require_platform_ldap_permission_v1(
    (p_request->>'sessionId')::uuid,'platform.identity_policy.manage',
    p_request->>'authenticationMethod'
  );
  IF uuid_extract_version(mapping_id) IS DISTINCT FROM 7 THEN
    RAISE EXCEPTION 'invalid platform LDAP mapping id'
      USING ERRCODE='22023';
  END IF;
  SELECT role.key INTO role_key
  FROM ONLY public.platform_roles AS role
  WHERE role.id=(p_request->>'platformRoleId')::uuid
  FOR SHARE;
  IF NOT FOUND OR role_key='platform_super_admin' THEN
    RAISE EXCEPTION 'platform LDAP mappings cannot grant this role'
      USING ERRCODE='42501';
  END IF;
  PERFORM 1
  FROM ONLY public.platform_ldap_provider_configurations AS configuration
  WHERE configuration.provider_id=provider_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'platform LDAP provider not found' USING ERRCODE='P0002';
  END IF;
  IF p_request ? 'expectedVersion' THEN
    expected_version:=(p_request->>'expectedVersion')::bigint;
    UPDATE ONLY public.platform_ldap_mapping_rules AS mapping
    SET matcher_type=p_request->>'matcherType',
        matcher_value=btrim(p_request->>'matcherValue'),
        case_sensitive=(p_request->>'caseSensitive')::boolean,
        priority=(p_request->>'priority')::integer,
        platform_role_id=(p_request->>'platformRoleId')::uuid,
        reconciliation_mode=p_request->>'reconciliationMode',
        enabled=(p_request->>'enabled')::boolean,
        notes=btrim(p_request->>'notes'),version=version+1,
        updated_by_user_id=actor_id,updated_at=transaction_timestamp()
    WHERE mapping.id=mapping_id AND mapping.provider_id=provider_id
      AND mapping.archived_at IS NULL AND mapping.version=expected_version
    RETURNING mapping.version INTO mapping_version;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'platform LDAP mapping version conflict'
        USING ERRCODE='40001';
    END IF;
  ELSE
    INSERT INTO public.platform_ldap_mapping_rules (
      id,provider_id,matcher_type,matcher_value,case_sensitive,priority,
      platform_role_id,reconciliation_mode,enabled,notes,version,
      created_by_user_id,updated_by_user_id,created_at,updated_at
    ) VALUES (
      mapping_id,provider_id,p_request->>'matcherType',
      btrim(p_request->>'matcherValue'),
      (p_request->>'caseSensitive')::boolean,
      (p_request->>'priority')::integer,
      (p_request->>'platformRoleId')::uuid,
      p_request->>'reconciliationMode',(p_request->>'enabled')::boolean,
      btrim(p_request->>'notes'),1,actor_id,actor_id,
      transaction_timestamp(),transaction_timestamp()
    )
    RETURNING version INTO mapping_version;
  END IF;
  UPDATE ONLY public.platform_ldap_provider_configurations AS configuration
  SET mapping_revision=mapping_revision+1,updated_by_user_id=actor_id,
      updated_at=transaction_timestamp()
  WHERE configuration.provider_id=provider_id;
  UPDATE ONLY public.platform_federated_provider_policies AS policy
  SET plan_revision=plan_revision+1,updated_at=transaction_timestamp()
  WHERE policy.provider_id=provider_id AND policy.provider_kind='ldap';
  UPDATE ONLY public.platform_auth_providers AS provider
  SET version=version+1,updated_by_user_id=actor_id,
      updated_at=transaction_timestamp()
  WHERE provider.id=provider_id AND provider.kind='ldap';
  PERFORM app.private_platform_ldap_audit_v1(
    p_request->'audit',actor_id,'platform.ldap_mapping.saved',
    'platform_ldap_mapping',mapping_id,'success',
    jsonb_build_object('providerId',provider_id,'roleKey',role_key,
      'enabled',(p_request->>'enabled')::boolean,'version',mapping_version)
  );
  RETURN app.private_platform_ldap_provider_document_v1(provider_id);
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.set_platform_ldap_provider_enabled_v1(p_request jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor_id uuid;
  provider_id uuid := (p_request->>'providerId')::uuid;
  expected_version bigint := (p_request->>'expectedVersion')::bigint;
  target_enabled boolean := (p_request->>'enabled')::boolean;
BEGIN
  PERFORM app.private_platform_ldap_assert_object_v1(
    p_request,
    ARRAY['sessionId','authenticationMethod','providerId','expectedVersion',
      'enabled','audit'],
    ARRAY['sessionId','authenticationMethod','providerId','expectedVersion',
      'enabled','audit'],16384
  );
  actor_id:=app.private_require_platform_ldap_permission_v1(
    (p_request->>'sessionId')::uuid,'platform.identity_policy.manage',
    p_request->>'authenticationMethod'
  );
  IF target_enabled AND (
    NOT EXISTS (
      SELECT 1
      FROM ONLY public.platform_ldap_provider_configurations AS configuration
      WHERE configuration.provider_id=provider_id
        AND configuration.jit_mode='existing_identity'
        AND configuration.no_match_policy='deny'
    )
    OR NOT EXISTS (
      SELECT 1 FROM ONLY public.platform_ldap_provider_endpoints AS endpoint
      WHERE endpoint.provider_id=provider_id AND endpoint.enabled
    )
    OR NOT EXISTS (
      SELECT 1 FROM ONLY public.platform_ldap_bind_secrets AS bind_secret
      WHERE bind_secret.provider_id=provider_id
        AND bind_secret.retired_at IS NULL
    )
    OR NOT EXISTS (
      SELECT 1 FROM ONLY public.platform_ldap_mapping_rules AS mapping
      JOIN ONLY public.platform_roles AS role ON role.id=mapping.platform_role_id
      WHERE mapping.provider_id=provider_id AND mapping.enabled
        AND mapping.archived_at IS NULL AND role.key<>'platform_super_admin'
    )
  ) THEN
    RAISE EXCEPTION 'platform LDAP provider is not ready'
      USING ERRCODE='55000';
  END IF;
  UPDATE ONLY public.platform_auth_providers AS provider
  SET enabled=target_enabled,version=version+1,updated_by_user_id=actor_id,
      updated_at=transaction_timestamp()
  WHERE provider.id=provider_id AND provider.kind='ldap'
    AND provider.archived_at IS NULL AND provider.version=expected_version;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'platform LDAP provider version conflict'
      USING ERRCODE='40001';
  END IF;
  UPDATE ONLY public.platform_federated_provider_policies AS policy
  SET account_mode=CASE WHEN target_enabled THEN 'existing_identity' ELSE 'disabled' END,
      enabled=target_enabled,security_revision=security_revision+1,
      updated_at=transaction_timestamp()
  WHERE policy.provider_id=provider_id AND policy.provider_kind='ldap';
  UPDATE ONLY public.platform_ldap_provider_configurations AS configuration
  SET security_revision=security_revision+1,updated_by_user_id=actor_id,
      updated_at=transaction_timestamp()
  WHERE configuration.provider_id=provider_id;
  PERFORM app.private_platform_ldap_audit_v1(
    p_request->'audit',actor_id,
    CASE WHEN target_enabled THEN 'platform.ldap_provider.enabled'
      ELSE 'platform.ldap_provider.disabled' END,
    'platform_ldap_provider',provider_id,'success',
    jsonb_build_object('enabled',target_enabled,'version',expected_version+1)
  );
  RETURN app.private_platform_ldap_provider_document_v1(provider_id);
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.begin_platform_ldap_test_v1(p_request jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor_id uuid;
  provider_id uuid := (p_request->>'providerId')::uuid;
  test_id uuid := (p_request->>'testId')::uuid;
  provider public.platform_auth_providers%ROWTYPE;
  configuration public.platform_ldap_provider_configurations%ROWTYPE;
  secret public.platform_ldap_bind_secrets%ROWTYPE;
BEGIN
  PERFORM app.private_platform_ldap_assert_object_v1(
    p_request,
    ARRAY['sessionId','authenticationMethod','providerId','testId','kind',
      'requestId','correlationId'],
    ARRAY['sessionId','authenticationMethod','providerId','testId','kind',
      'requestId','correlationId'],16384
  );
  actor_id:=app.private_require_platform_ldap_permission_v1(
    (p_request->>'sessionId')::uuid,'platform.identity_provider.test',
    p_request->>'authenticationMethod'
  );
  IF p_request->>'kind' NOT IN (
       'connection','bind','search_user','filter','mapping_dry_run'
     ) OR uuid_extract_version(test_id) IS DISTINCT FROM 7 THEN
    RAISE EXCEPTION 'invalid platform LDAP test' USING ERRCODE='22023';
  END IF;
  SELECT * INTO STRICT provider
  FROM ONLY public.platform_auth_providers AS selected_provider
  WHERE selected_provider.id=provider_id AND selected_provider.kind='ldap'
    AND selected_provider.archived_at IS NULL
  FOR SHARE;
  SELECT * INTO STRICT configuration
  FROM ONLY public.platform_ldap_provider_configurations AS selected_configuration
  WHERE selected_configuration.provider_id=provider_id
  FOR SHARE;
  IF p_request->>'kind'<>'connection' THEN
    SELECT * INTO STRICT secret
    FROM ONLY public.platform_ldap_bind_secrets AS selected_secret
    WHERE selected_secret.provider_id=provider_id
      AND selected_secret.retired_at IS NULL
    FOR SHARE;
  END IF;
  INSERT INTO public.platform_ldap_test_runs (
    id,provider_id,actor_user_id,kind,state,provider_version,
    configuration_revision,mapping_revision,secret_revision,
    request_id,correlation_id,started_at
  ) VALUES (
    test_id,provider_id,actor_id,p_request->>'kind','pending',provider.version,
    configuration.configuration_revision,configuration.mapping_revision,
    CASE WHEN p_request->>'kind'='connection' THEN NULL ELSE secret.revision END,
    (p_request->>'requestId')::uuid,(p_request->>'correlationId')::uuid,
    transaction_timestamp()
  );
  RETURN jsonb_build_object(
    'testId',test_id,'providerId',provider_id,'kind',p_request->>'kind',
    'providerVersion',provider.version,
    'configurationRevision',configuration.configuration_revision,
    'mappingRevision',configuration.mapping_revision,
    'configuration',app.private_platform_ldap_provider_document_v1(provider_id)->'configuration',
    'endpoints',app.private_platform_ldap_provider_document_v1(provider_id)->'endpoints',
    'mappings',app.private_platform_ldap_provider_document_v1(provider_id)->'mappings',
    'bindSecret',CASE WHEN p_request->>'kind'='connection' THEN NULL ELSE
      jsonb_build_object('secretId',secret.id,'revision',secret.revision,
        'keyVersion',secret.key_version,
        'nonce',encode(secret.nonce,'hex'),'ciphertext',encode(secret.ciphertext,'hex'))
      END
  );
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.complete_platform_ldap_test_v1(p_request jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor_id uuid;
  test public.platform_ldap_test_runs%ROWTYPE;
  command_completed_at timestamptz := (p_request->>'completedAt')::timestamptz;
BEGIN
  PERFORM app.private_platform_ldap_assert_object_v1(
    p_request,
    ARRAY['sessionId','authenticationMethod','testId','outcome','category',
      'endpointPriority','durationMs','matchedEntryCount','attributes',
      'completedAt','audit'],
    ARRAY['sessionId','authenticationMethod','testId','outcome','category',
      'durationMs','completedAt','audit'],65536
  );
  actor_id:=app.private_require_platform_ldap_permission_v1(
    (p_request->>'sessionId')::uuid,'platform.identity_provider.test',
    p_request->>'authenticationMethod'
  );
  SELECT * INTO STRICT test FROM ONLY public.platform_ldap_test_runs
  WHERE id=(p_request->>'testId')::uuid AND actor_user_id=actor_id FOR UPDATE;
  IF test.state<>'pending' THEN
    RAISE EXCEPTION 'platform LDAP test is terminal' USING ERRCODE='55000';
  END IF;
  IF p_request ? 'attributes' AND (
    jsonb_typeof(p_request->'attributes')<>'array'
    OR EXISTS (
      SELECT 1 FROM jsonb_array_elements_text(p_request->'attributes') AS name
      WHERE char_length(name) NOT BETWEEN 1 AND 128 OR name!~'^[A-Za-z][A-Za-z0-9;._-]*$'
    )
  ) THEN
    RAISE EXCEPTION 'unsafe platform LDAP test attributes'
      USING ERRCODE='22023';
  END IF;
  IF NOT EXISTS (
    SELECT 1
    FROM ONLY public.platform_auth_providers AS provider
    JOIN ONLY public.platform_ldap_provider_configurations AS configuration
      ON configuration.provider_id=provider.id
    WHERE provider.id=test.provider_id
      AND provider.version=test.provider_version
      AND configuration.configuration_revision=test.configuration_revision
      AND configuration.mapping_revision=test.mapping_revision
      AND (test.secret_revision IS NULL OR EXISTS (
        SELECT 1
        FROM ONLY public.platform_ldap_bind_secrets AS current_secret
        WHERE current_secret.provider_id=test.provider_id
          AND current_secret.revision=test.secret_revision
          AND current_secret.retired_at IS NULL
      ))
  ) THEN
    p_request:=jsonb_set(jsonb_set(p_request,'{outcome}','"inconclusive"'),
      '{category}','"stale_configuration"');
  END IF;
  UPDATE ONLY public.platform_ldap_test_runs
  SET state='completed',outcome=p_request->>'outcome',
      category=p_request->>'category',
      endpoint_priority=nullif(p_request->>'endpointPriority','')::integer,
      duration_ms=(p_request->>'durationMs')::integer,
      matched_entry_count=nullif(p_request->>'matchedEntryCount','')::integer,
       attributes=p_request->'attributes',completed_at=command_completed_at
  WHERE id=test.id;
  PERFORM app.private_platform_ldap_audit_v1(
    p_request->'audit',actor_id,'platform.ldap_provider.tested',
    'platform_ldap_provider',test.provider_id,
    CASE WHEN p_request->>'outcome'='success' THEN 'success' ELSE 'failure' END,
    jsonb_build_object('kind',test.kind,'outcome',p_request->>'outcome',
      'category',p_request->>'category','durationMs',(p_request->>'durationMs')::integer)
  );
  RETURN jsonb_build_object(
    'testId',test.id,'providerId',test.provider_id,'kind',test.kind,
    'outcome',p_request->>'outcome','category',p_request->>'category',
    'endpointPriority',nullif(p_request->>'endpointPriority','')::integer,
    'durationMs',(p_request->>'durationMs')::integer,
    'matchedEntryCount',nullif(p_request->>'matchedEntryCount','')::integer,
    'attributes',coalesce(p_request->'attributes','[]'::jsonb)
  );
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.begin_platform_ldap_authentication_v1(p_request jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  run_id uuid := (p_request->>'runId')::uuid;
  receipt_digest bytea := decode(p_request->>'receiptDigest','hex');
  network_digest bytea := decode(p_request->>'networkRateDigest','hex');
  account_digest bytea := decode(p_request->>'accountRateDigest','hex');
  provider_digest bytea := decode(p_request->>'providerRateDigest','hex');
  provider public.platform_auth_providers%ROWTYPE;
  configuration public.platform_ldap_provider_configurations%ROWTYPE;
  secret public.platform_ldap_bind_secrets%ROWTYPE;
  existing public.platform_ldap_authentication_runs%ROWTYPE;
  admitted boolean;
  maximum_attempt_count integer;
  blocked_until timestamptz;
BEGIN
  PERFORM app.private_platform_ldap_assert_object_v1(
    p_request,
    ARRAY['runId','providerKey','receiptDigest','networkRateDigest',
      'accountRateDigest','providerRateDigest','audit'],
    ARRAY['runId','providerKey','receiptDigest','networkRateDigest',
      'accountRateDigest','providerRateDigest','audit'],32768
  );
  IF uuid_extract_version(run_id) IS DISTINCT FROM 7
     OR octet_length(receipt_digest)<>32
     OR octet_length(network_digest)<>32
     OR octet_length(account_digest)<>32
     OR octet_length(provider_digest)<>32 THEN
    RAISE EXCEPTION 'invalid platform LDAP authentication request'
      USING ERRCODE='22023';
  END IF;
  SELECT * INTO existing
  FROM ONLY public.platform_ldap_authentication_runs AS candidate
  WHERE candidate.receipt_digest=begin_platform_ldap_authentication_v1.receipt_digest
  FOR UPDATE;
  IF FOUND THEN
    IF existing.network_rate_digest<>network_digest
       OR existing.account_rate_digest<>account_digest
       OR existing.provider_rate_digest<>provider_digest THEN
      RAISE EXCEPTION 'platform LDAP authentication replay mismatch'
        USING ERRCODE='23505';
    END IF;
    IF existing.state='pending' THEN
      SELECT * INTO STRICT provider
      FROM ONLY public.platform_auth_providers AS replay_provider
      WHERE replay_provider.id=existing.provider_id
        AND replay_provider.kind='ldap'
        AND replay_provider.version=existing.provider_version
        AND replay_provider.enabled
        AND replay_provider.archived_at IS NULL
      FOR SHARE;
      SELECT * INTO STRICT configuration
      FROM ONLY public.platform_ldap_provider_configurations AS replay_configuration
      WHERE replay_configuration.provider_id=existing.provider_id
        AND replay_configuration.configuration_revision=existing.configuration_revision
        AND replay_configuration.security_revision=existing.security_revision
        AND replay_configuration.mapping_revision=existing.mapping_revision
      FOR SHARE;
      SELECT * INTO STRICT secret
      FROM ONLY public.platform_ldap_bind_secrets AS replay_secret
      WHERE replay_secret.provider_id=existing.provider_id
        AND replay_secret.retired_at IS NULL
      FOR SHARE;
      RETURN jsonb_build_object(
        'runId',existing.id,'state','pending','allowed',true,
        'providerId',provider.id,'providerVersion',provider.version,
        'configurationRevision',configuration.configuration_revision,
        'securityRevision',configuration.security_revision,
        'mappingRevision',configuration.mapping_revision,
        'configuration',app.private_platform_ldap_provider_document_v1(provider.id)->'configuration',
        'endpoints',app.private_platform_ldap_provider_document_v1(provider.id)->'endpoints',
        'bindSecret',jsonb_build_object(
          'id',secret.id,'revision',secret.revision,
          'keyVersion',secret.key_version,
          'nonce',encode(secret.nonce,'hex'),
          'ciphertext',encode(secret.ciphertext,'hex')
        )
      );
    END IF;
    RETURN jsonb_build_object(
      'runId',existing.id,'state',existing.state,
      'allowed',false,
      'failureCategory',existing.failure_category,
      'sessionId',existing.session_id,'userId',existing.user_id,
      'completedAt',existing.completed_at
    );
  END IF;

  SELECT * INTO provider
  FROM ONLY public.platform_auth_providers
  WHERE key=lower(btrim(p_request->>'providerKey')) AND kind='ldap'
    AND enabled AND archived_at IS NULL
  FOR SHARE;
  SELECT rate.admitted,rate.maximum_attempt_count,rate.blocked_until
    INTO admitted,maximum_attempt_count,blocked_until
  FROM app.admit_auth_attempts(
    ARRAY['ldap_network','ldap_account','ldap_provider']::public.auth_rate_limit_scope[],
    ARRAY[network_digest,account_digest,provider_digest],
    ARRAY[60,300,60],ARRAY[20,8,100],ARRAY[300,900,300]
  ) AS rate;
  IF NOT admitted OR provider.id IS NULL THEN
    PERFORM app.private_platform_ldap_audit_v1(
      p_request->'audit',NULL,'platform.ldap_login.denied',
      'platform_ldap_provider',provider.id,'failure',
      jsonb_build_object('category',
        CASE WHEN NOT admitted THEN 'rate_limited' ELSE 'credentials_rejected' END)
    );
    RETURN jsonb_build_object('runId',run_id,'state','denied','allowed',false,
      'retryAfter',blocked_until);
  END IF;
  SELECT * INTO STRICT configuration
  FROM ONLY public.platform_ldap_provider_configurations
  WHERE provider_id=provider.id AND jit_mode='existing_identity'
    AND no_match_policy='deny'
  FOR SHARE;
  SELECT * INTO STRICT secret
  FROM ONLY public.platform_ldap_bind_secrets
  WHERE provider_id=provider.id AND retired_at IS NULL
  FOR SHARE;
  INSERT INTO public.platform_ldap_authentication_runs (
    id,provider_id,receipt_digest,network_rate_digest,account_rate_digest,
    provider_rate_digest,provider_version,configuration_revision,
    security_revision,mapping_revision,state,started_at,expires_at
  ) VALUES (
    run_id,provider.id,receipt_digest,network_digest,account_digest,
    provider_digest,provider.version,configuration.configuration_revision,
    configuration.security_revision,configuration.mapping_revision,'pending',
    transaction_timestamp(),transaction_timestamp()+interval '5 minutes'
  );
  RETURN jsonb_build_object(
    'runId',run_id,'state','pending','allowed',true,
    'providerId',provider.id,'providerVersion',provider.version,
    'configurationRevision',configuration.configuration_revision,
    'securityRevision',configuration.security_revision,
    'mappingRevision',configuration.mapping_revision,
    'configuration',app.private_platform_ldap_provider_document_v1(provider.id)->'configuration',
    'endpoints',app.private_platform_ldap_provider_document_v1(provider.id)->'endpoints',
    'bindSecret',jsonb_build_object(
      'id',secret.id,'revision',secret.revision,
      'keyVersion',secret.key_version,
      'nonce',encode(secret.nonce,'hex'),'ciphertext',encode(secret.ciphertext,'hex')
    )
  );
EXCEPTION
  WHEN no_data_found THEN
    PERFORM app.private_platform_ldap_audit_v1(
      p_request->'audit',NULL,'platform.ldap_login.denied',
      'platform_ldap_provider',provider.id,'failure',
      jsonb_build_object('category','provider_unavailable')
    );
    RETURN jsonb_build_object(
      'runId',run_id,'state','denied','allowed',false
    );
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.load_platform_ldap_mfa_v1(p_request jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  run public.platform_ldap_authentication_runs%ROWTYPE;
  configuration public.platform_ldap_provider_configurations%ROWTYPE;
  identity public.platform_ldap_external_identities%ROWTYPE;
  user_record public.users%ROWTYPE;
  factor public.totp_credentials%ROWTYPE;
  alias_record public.platform_ldap_external_identity_aliases%ROWTYPE;
  subject_digest bytea := decode(p_request->>'subjectDigest','hex');
  requested_identity_id uuid := (p_request->>'externalIdentityId')::uuid;
BEGIN
  PERFORM app.private_platform_ldap_assert_object_v1(
    p_request,
    ARRAY['runId','providerId','providerVersion','configurationRevision',
      'securityRevision','mappingRevision','externalIdentityId','subjectDigest',
      'subjectKeyVersion','email'],
    ARRAY['runId','providerId','providerVersion','configurationRevision',
      'securityRevision','mappingRevision','externalIdentityId','subjectDigest',
      'subjectKeyVersion'],32768
  );
  IF uuid_extract_version(requested_identity_id) IS DISTINCT FROM 7
     OR octet_length(subject_digest)<>32 THEN
    RAISE EXCEPTION 'invalid platform LDAP identity preparation'
      USING ERRCODE='22023';
  END IF;
  SELECT * INTO STRICT run
  FROM ONLY public.platform_ldap_authentication_runs
  WHERE id=(p_request->>'runId')::uuid
    AND provider_id=(p_request->>'providerId')::uuid
    AND provider_version=(p_request->>'providerVersion')::bigint
    AND configuration_revision=(p_request->>'configurationRevision')::bigint
    AND security_revision=(p_request->>'securityRevision')::bigint
    AND mapping_revision=(p_request->>'mappingRevision')::bigint
    AND state='pending' AND expires_at>transaction_timestamp()
  FOR UPDATE;
  SELECT * INTO STRICT configuration
  FROM ONLY public.platform_ldap_provider_configurations
  WHERE provider_id=run.provider_id
    AND configuration_revision=run.configuration_revision
    AND security_revision=run.security_revision
    AND mapping_revision=run.mapping_revision
  FOR SHARE;
  SELECT * INTO alias_record
  FROM ONLY public.platform_ldap_external_identity_aliases
  WHERE provider_id=run.provider_id
    AND key_version=(p_request->>'subjectKeyVersion')::integer
    AND subject_digest=load_platform_ldap_mfa_v1.subject_digest
    AND retired_at IS NULL
  FOR SHARE;
  IF FOUND THEN
    SELECT * INTO STRICT identity
    FROM ONLY public.platform_ldap_external_identities
    WHERE provider_id=run.provider_id
      AND id=alias_record.external_identity_id
      AND disabled_at IS NULL AND retired_at IS NULL
    FOR SHARE;
    SELECT * INTO STRICT user_record FROM ONLY public.users
    WHERE id=identity.user_id AND active FOR SHARE;
    requested_identity_id:=identity.id;
  ELSE
    IF configuration.jit_mode<>'existing_identity'
       OR nullif(lower(btrim(p_request->>'email')),'') IS NULL THEN
      RAISE EXCEPTION 'platform LDAP identity is not admitted'
        USING ERRCODE='42501';
    END IF;
    SELECT * INTO user_record FROM ONLY public.users
    WHERE email=lower(btrim(p_request->>'email')) AND active
    FOR SHARE;
    IF NOT FOUND OR EXISTS (
      SELECT 1 FROM ONLY public.platform_ldap_external_identities
      WHERE provider_id=run.provider_id AND user_id=user_record.id
        AND retired_at IS NULL
    ) THEN
      RAISE EXCEPTION 'platform LDAP identity is not admitted'
        USING ERRCODE='42501';
    END IF;
  END IF;
  SELECT * INTO factor FROM ONLY public.totp_credentials
  WHERE user_id=user_record.id AND confirmed_at IS NOT NULL
    AND disabled_at IS NULL
  FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'platform LDAP login requires an active TOTP factor'
      USING ERRCODE='42501';
  END IF;
  RETURN jsonb_build_object(
    'runId',run.id,'userId',user_record.id,
    'userAuthenticationRevision',user_record.authentication_revision,
    'externalIdentityId',requested_identity_id,
    'identityVersion',coalesce(identity.version,0),
    'totpCredential',jsonb_build_object(
      'id',factor.id,'securityRevision',factor.security_revision,
      'keyVersion',factor.key_version,
      'encryptionAlgorithm',factor.encryption_algorithm,
      'otpAlgorithm',factor.otp_algorithm,'digits',factor.digits,
      'periodSeconds',factor.period_seconds,
      'secretCiphertext',encode(factor.secret_ciphertext,'hex'),
      'secretNonce',encode(factor.secret_nonce,'hex'),
      'secretAad',encode(factor.secret_aad,'hex'),
      'lastAcceptedCounter',factor.last_accepted_counter
    ),
    'mappings',coalesce((
      SELECT jsonb_agg(jsonb_build_object(
        'id',mapping.id,'matcherType',mapping.matcher_type,
        'matcherValue',mapping.matcher_value,
        'caseSensitive',mapping.case_sensitive,
        'priority',mapping.priority,'platformRoleId',mapping.platform_role_id,
        'platformRoleKey',role.key,
        'reconciliationMode',mapping.reconciliation_mode
      ) ORDER BY mapping.priority,mapping.id)
      FROM ONLY public.platform_ldap_mapping_rules AS mapping
      JOIN ONLY public.platform_roles AS role ON role.id=mapping.platform_role_id
      WHERE mapping.provider_id=run.provider_id AND mapping.enabled
        AND mapping.archived_at IS NULL AND role.key<>'platform_super_admin'
    ),'[]'::jsonb)
  );
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.fail_platform_ldap_authentication_v1(p_request jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  run public.platform_ldap_authentication_runs%ROWTYPE;
  category text := p_request->>'category';
BEGIN
  PERFORM app.private_platform_ldap_assert_object_v1(
    p_request,ARRAY['runId','category','audit'],
    ARRAY['runId','category','audit'],16384
  );
  IF category NOT IN (
    'credentials_rejected','account_disabled','identity_unmatched',
    'mapping_unmatched','mfa_required','mfa_rejected','rate_limited',
    'provider_unavailable','protocol_failed','stale_configuration'
  ) THEN
    RAISE EXCEPTION 'invalid platform LDAP failure category'
      USING ERRCODE='22023';
  END IF;
  SELECT * INTO STRICT run
  FROM ONLY public.platform_ldap_authentication_runs
  WHERE id=(p_request->>'runId')::uuid FOR UPDATE;
  IF run.state<>'pending' THEN
    RETURN jsonb_build_object('runId',run.id,'state',run.state,
      'category',run.failure_category);
  END IF;
  UPDATE ONLY public.platform_ldap_authentication_runs
  SET state=CASE WHEN category IN (
        'provider_unavailable','protocol_failed'
      ) THEN 'failed' ELSE 'denied' END,
      failure_category=category,
      completed_at=least(transaction_timestamp(),run.expires_at)
  WHERE id=run.id;
  PERFORM app.private_platform_ldap_audit_v1(
    p_request->'audit',NULL,'platform.ldap_login.denied',
    'platform_ldap_provider',run.provider_id,'failure',
    jsonb_build_object('category',category)
  );
  RETURN jsonb_build_object('runId',run.id,'state',
    CASE WHEN category IN ('provider_unavailable','protocol_failed')
      THEN 'failed' ELSE 'denied' END,'category',category);
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.apply_platform_ldap_authentication_v1(p_request jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  run public.platform_ldap_authentication_runs%ROWTYPE;
  provider public.platform_auth_providers%ROWTYPE;
  configuration public.platform_ldap_provider_configurations%ROWTYPE;
  user_record public.users%ROWTYPE;
  factor public.totp_credentials%ROWTYPE;
  identity public.platform_ldap_external_identities%ROWTYPE;
  alias_record public.platform_ldap_external_identity_aliases%ROWTYPE;
  mapping record;
  stale record;
  user_role public.user_platform_roles%ROWTYPE;
  identity_id uuid := (p_request->>'externalIdentityId')::uuid;
  subject_digest bytea := decode(p_request->>'subjectDigest','hex');
  command_subject_ciphertext bytea := decode(p_request->>'subjectCiphertext','hex');
  command_subject_nonce bytea := decode(p_request->>'subjectNonce','hex');
  command_groups_digest bytea := decode(p_request->>'groupsDigest','hex');
  command_result_digest bytea := decode(p_request->>'resultDigest','hex');
  command_session_id uuid := (p_request->>'sessionId')::uuid;
  family_id uuid := (p_request->>'rotationFamilyId')::uuid;
  token_digest bytea := decode(p_request->>'tokenDigest','hex');
  csrf_digest bytea := decode(p_request->>'csrfDigest','hex');
  command_completed_at timestamptz := (p_request->>'completedAt')::timestamptz;
  selected_ids uuid[];
  source_grant_id uuid;
BEGIN
  PERFORM app.private_platform_ldap_assert_object_v1(
    p_request,
    ARRAY['runId','providerId','providerVersion','configurationRevision',
      'securityRevision','mappingRevision','userId',
      'userAuthenticationRevision','externalIdentityId','identityVersion',
      'subjectKeyVersion','subjectDigest','subjectCiphertext','subjectNonce',
      'username','email','displayName','firstName','lastName','groupsDigest',
      'selectedMappingIds','totpCredentialId','totpSecurityRevision',
      'totpCounter','sessionId','rotationFamilyId','tokenDigest','csrfDigest',
      'idleExpiresAt','absoluteExpiresAt','completedAt','resultDigest','audit'],
    ARRAY['runId','providerId','providerVersion','configurationRevision',
      'securityRevision','mappingRevision','userId',
      'userAuthenticationRevision','externalIdentityId','identityVersion',
      'subjectKeyVersion','subjectDigest','subjectCiphertext','subjectNonce',
      'username','displayName','groupsDigest','selectedMappingIds',
      'totpCredentialId','totpSecurityRevision','totpCounter','sessionId',
      'rotationFamilyId','tokenDigest','csrfDigest','idleExpiresAt',
      'absoluteExpiresAt','completedAt','resultDigest','audit'],262144
  );
  IF jsonb_typeof(p_request->'selectedMappingIds')<>'array'
     OR jsonb_array_length(p_request->'selectedMappingIds') NOT BETWEEN 1 AND 128
     OR uuid_extract_version(command_session_id) IS DISTINCT FROM 7
     OR uuid_extract_version(family_id) IS DISTINCT FROM 7
     OR octet_length(subject_digest)<>32
     OR octet_length(command_subject_ciphertext) NOT BETWEEN 17 AND 4112
     OR octet_length(command_subject_nonce)<>12
     OR octet_length(command_groups_digest)<>32
     OR octet_length(command_result_digest)<>32 OR octet_length(token_digest)<>32
     OR octet_length(csrf_digest)<>32 THEN
    RAISE EXCEPTION 'invalid platform LDAP completion'
      USING ERRCODE='22023';
  END IF;
  SELECT array_agg(value::uuid ORDER BY value::uuid) INTO selected_ids
  FROM jsonb_array_elements_text(p_request->'selectedMappingIds') AS value;
  IF cardinality(selected_ids)<>(
       SELECT count(DISTINCT value::uuid)
       FROM jsonb_array_elements_text(p_request->'selectedMappingIds') AS value
     ) THEN
    RAISE EXCEPTION 'duplicate platform LDAP mappings'
      USING ERRCODE='22023';
  END IF;

  SELECT * INTO STRICT provider FROM ONLY public.platform_auth_providers
  WHERE id=(p_request->>'providerId')::uuid AND kind='ldap' AND enabled
    AND archived_at IS NULL AND version=(p_request->>'providerVersion')::bigint
  FOR SHARE;
  SELECT * INTO STRICT configuration
  FROM ONLY public.platform_ldap_provider_configurations
  WHERE provider_id=provider.id
    AND configuration_revision=(p_request->>'configurationRevision')::bigint
    AND security_revision=(p_request->>'securityRevision')::bigint
    AND mapping_revision=(p_request->>'mappingRevision')::bigint
  FOR SHARE;
  SELECT * INTO STRICT user_record FROM ONLY public.users
  WHERE id=(p_request->>'userId')::uuid AND active
    AND authentication_revision=(p_request->>'userAuthenticationRevision')::bigint
  FOR UPDATE;
  SELECT * INTO STRICT run
  FROM ONLY public.platform_ldap_authentication_runs
  WHERE id=(p_request->>'runId')::uuid AND provider_id=provider.id
  FOR UPDATE;
  IF run.state='succeeded' THEN
    IF run.result_digest<>command_result_digest
       OR run.session_id<>command_session_id
       OR run.user_id<>user_record.id THEN
      RAISE EXCEPTION 'platform LDAP completion replay mismatch'
        USING ERRCODE='23505';
    END IF;
    RETURN jsonb_build_object('runId',run.id,'state','succeeded',
      'sessionId',run.session_id,'userId',run.user_id);
  END IF;
  SELECT * INTO STRICT factor FROM ONLY public.totp_credentials
  WHERE id=(p_request->>'totpCredentialId')::uuid
    AND user_id=user_record.id AND confirmed_at IS NOT NULL
    AND disabled_at IS NULL
    AND security_revision=(p_request->>'totpSecurityRevision')::bigint
    AND coalesce(last_accepted_counter,-1)<(p_request->>'totpCounter')::bigint
  FOR UPDATE;
  IF run.state<>'pending' OR run.expires_at<command_completed_at
     OR command_completed_at<run.started_at
     OR command_completed_at>transaction_timestamp()+interval '5 seconds'
     OR run.provider_version<>provider.version
     OR run.configuration_revision<>configuration.configuration_revision
     OR run.security_revision<>configuration.security_revision
     OR run.mapping_revision<>configuration.mapping_revision THEN
    RAISE EXCEPTION 'stale platform LDAP completion'
      USING ERRCODE='40001';
  END IF;
  IF (SELECT count(*) FROM ONLY public.platform_ldap_mapping_rules
      WHERE provider_id=provider.id AND id=ANY(selected_ids)
        AND enabled AND archived_at IS NULL)<>cardinality(selected_ids)
     OR EXISTS (
       SELECT 1 FROM ONLY public.platform_ldap_mapping_rules AS candidate
       JOIN ONLY public.platform_roles AS role
         ON role.id=candidate.platform_role_id
       WHERE candidate.id=ANY(selected_ids)
         AND role.key='platform_super_admin'
     )
     OR EXISTS (
       SELECT 1 FROM ONLY public.platform_ldap_mapping_rules
       WHERE id=ANY(selected_ids)
       GROUP BY platform_role_id HAVING count(*)>1
     ) THEN
    RAISE EXCEPTION 'invalid platform LDAP mapping plan'
      USING ERRCODE='42501';
  END IF;

  SELECT * INTO alias_record
  FROM ONLY public.platform_ldap_external_identity_aliases
  WHERE provider_id=provider.id
    AND key_version=(p_request->>'subjectKeyVersion')::integer
    AND subject_digest=apply_platform_ldap_authentication_v1.subject_digest
    AND retired_at IS NULL
  FOR UPDATE;
  IF FOUND AND alias_record.external_identity_id<>identity_id THEN
    RAISE EXCEPTION 'platform LDAP subject collision'
      USING ERRCODE='23505';
  END IF;
  SELECT * INTO identity
  FROM ONLY public.platform_ldap_external_identities
  WHERE provider_id=provider.id AND id=identity_id FOR UPDATE;
  IF FOUND THEN
    IF identity.user_id<>user_record.id OR identity.disabled_at IS NOT NULL
       OR identity.retired_at IS NOT NULL
       OR identity.version<>(p_request->>'identityVersion')::bigint THEN
      RAISE EXCEPTION 'platform LDAP identity version conflict'
        USING ERRCODE='40001';
    END IF;
    UPDATE ONLY public.platform_ldap_external_identities AS external_identity
    SET subject_format=configuration.immutable_subject_format,
        subject_ciphertext=command_subject_ciphertext,
        subject_nonce=command_subject_nonce,
        key_version=(p_request->>'subjectKeyVersion')::integer,
        username=btrim(p_request->>'username'),
        email=nullif(lower(btrim(p_request->>'email')),''),
        display_name=btrim(p_request->>'displayName'),
        first_name=nullif(btrim(p_request->>'firstName'),''),
        last_name=nullif(btrim(p_request->>'lastName'),''),
        groups_digest=command_groups_digest,
        configuration_revision=configuration.configuration_revision,
        security_revision=configuration.security_revision,
        mapping_revision=configuration.mapping_revision,
        last_observed_at=command_completed_at,version=version+1,
        updated_at=command_completed_at
    WHERE external_identity.id=identity.id
    RETURNING * INTO identity;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'platform LDAP identity disappeared'
        USING ERRCODE='40001';
    END IF;
    IF alias_record.id IS NULL THEN
      INSERT INTO public.platform_ldap_external_identity_aliases (
        id,provider_id,external_identity_id,key_version,subject_digest,created_at
      ) VALUES (
        uuidv7(),provider.id,identity.id,
        (p_request->>'subjectKeyVersion')::integer,subject_digest,
        command_completed_at
      );
    END IF;
  ELSE
    IF (p_request->>'identityVersion')::bigint<>0 OR FOUND THEN
      RAISE EXCEPTION 'invalid platform LDAP identity creation'
        USING ERRCODE='40001';
    END IF;
    INSERT INTO public.platform_ldap_external_identities (
      id,provider_id,user_id,subject_format,subject_ciphertext,subject_nonce,
      key_version,username,email,display_name,first_name,last_name,groups_digest,
      configuration_revision,security_revision,mapping_revision,last_observed_at,
      version,created_at,updated_at
    ) VALUES (
      identity_id,provider.id,user_record.id,configuration.immutable_subject_format,
      command_subject_ciphertext,command_subject_nonce,
      (p_request->>'subjectKeyVersion')::integer,
      btrim(p_request->>'username'),nullif(lower(btrim(p_request->>'email')),''),
      btrim(p_request->>'displayName'),nullif(btrim(p_request->>'firstName'),''),
      nullif(btrim(p_request->>'lastName'),''),command_groups_digest,
      configuration.configuration_revision,configuration.security_revision,
      configuration.mapping_revision,command_completed_at,1,
      command_completed_at,command_completed_at
    ) RETURNING * INTO identity;
    INSERT INTO public.platform_ldap_external_identity_aliases (
      id,provider_id,external_identity_id,key_version,subject_digest,created_at
    ) VALUES (
      uuidv7(),provider.id,identity.id,
      (p_request->>'subjectKeyVersion')::integer,subject_digest,
      command_completed_at
    );
  END IF;

  FOR mapping IN
    SELECT rule.*
    FROM ONLY public.platform_ldap_mapping_rules AS rule
    WHERE rule.provider_id=provider.id AND rule.id=ANY(selected_ids)
    ORDER BY rule.platform_role_id,rule.priority,rule.id
  LOOP
    SELECT * INTO user_role FROM ONLY public.user_platform_roles
    WHERE user_id=user_record.id AND role_id=mapping.platform_role_id
      AND revoked_at IS NULL
    FOR UPDATE;
    IF NOT FOUND THEN
      INSERT INTO public.user_platform_roles (
        id,user_id,role_id,granted_by_user_id,granted_at
      ) VALUES (
        uuidv7(),user_record.id,mapping.platform_role_id,NULL,
        command_completed_at
      ) RETURNING * INTO user_role;
    END IF;
    INSERT INTO public.platform_ldap_role_grants (
      id,provider_id,external_identity_id,mapping_rule_id,user_id,
      platform_role_id,user_platform_role_id,source_mapping_revision,
      granted_at,refreshed_at
    ) VALUES (
      uuidv7(),provider.id,identity.id,mapping.id,user_record.id,
      mapping.platform_role_id,user_role.id,configuration.mapping_revision,
      command_completed_at,command_completed_at
    )
    ON CONFLICT (provider_id,external_identity_id,mapping_rule_id,platform_role_id)
      WHERE revoked_at IS NULL
    DO UPDATE SET refreshed_at=excluded.refreshed_at,
      source_mapping_revision=excluded.source_mapping_revision;
    UPDATE ONLY public.platform_ldap_mapping_rules
    SET last_matched_at=command_completed_at
    WHERE id=mapping.id;
  END LOOP;

  FOR stale IN
    SELECT grant_row.id,grant_row.user_platform_role_id
    FROM ONLY public.platform_ldap_role_grants AS grant_row
    JOIN ONLY public.platform_ldap_mapping_rules AS rule
      ON rule.id=grant_row.mapping_rule_id
    WHERE grant_row.provider_id=provider.id
      AND grant_row.external_identity_id=identity.id
      AND grant_row.revoked_at IS NULL
      AND grant_row.mapping_rule_id<>ALL(selected_ids)
      AND rule.reconciliation_mode='authoritative'
    ORDER BY grant_row.id
    FOR UPDATE OF grant_row
  LOOP
    UPDATE ONLY public.platform_ldap_role_grants
    SET revoked_at=command_completed_at WHERE id=stale.id;
    IF NOT EXISTS (
      SELECT 1 FROM ONLY public.platform_ldap_role_grants
      WHERE user_platform_role_id=stale.user_platform_role_id
        AND revoked_at IS NULL
    ) THEN
      UPDATE ONLY public.user_platform_roles
      SET revoked_at=command_completed_at,revoked_by_user_id=user_record.id
      WHERE id=stale.user_platform_role_id AND revoked_at IS NULL
        AND granted_by_user_id IS NULL;
    END IF;
  END LOOP;

  UPDATE ONLY public.totp_credentials
  SET last_accepted_counter=(p_request->>'totpCounter')::bigint,
      updated_at=command_completed_at
  WHERE id=factor.id;
  INSERT INTO public.auth_sessions (
    id,user_id,rotation_family_id,active_tenant_id,token_digest,
    csrf_secret_digest,authentication_method,mfa_satisfied_at,last_seen_at,
    idle_expires_at,absolute_expires_at,created_at
  ) VALUES (
    command_session_id,user_record.id,family_id,NULL,token_digest,csrf_digest,'ldap',
    command_completed_at,command_completed_at,
    (p_request->>'idleExpiresAt')::timestamptz,
    (p_request->>'absoluteExpiresAt')::timestamptz,command_completed_at
  );
  INSERT INTO public.platform_ldap_session_provenance (
    session_id,user_id,provider_id,external_identity_id,authentication_run_id,
    provider_version,configuration_revision,security_revision,mapping_revision,
    identity_version,totp_credential_id,totp_security_revision,authenticated_at
  ) VALUES (
    command_session_id,user_record.id,provider.id,identity.id,run.id,provider.version,
    configuration.configuration_revision,configuration.security_revision,
    configuration.mapping_revision,identity.version,factor.id,
    factor.security_revision,command_completed_at
  );
  UPDATE ONLY public.platform_ldap_authentication_runs AS authentication_run
  SET state='succeeded',external_identity_id=identity.id,user_id=user_record.id,
      session_id=command_session_id,result_digest=command_result_digest,
      completed_at=command_completed_at
  WHERE authentication_run.id=run.id;
  PERFORM app.private_platform_ldap_audit_v1(
    p_request->'audit',user_record.id,'platform.ldap_login.succeeded',
    'auth_session',command_session_id,'success',
    jsonb_build_object('providerId',provider.id,'userId',user_record.id,
      'mfa','totp','mappingCount',cardinality(selected_ids))
  );
  RETURN jsonb_build_object('runId',run.id,'state','succeeded',
    'sessionId',command_session_id,'userId',user_record.id,
    'idleExpiresAt',p_request->>'idleExpiresAt',
    'absoluteExpiresAt',p_request->>'absoluteExpiresAt');
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.revalidate_platform_ldap_session_v1(
  p_session_id uuid,p_user_id uuid,p_audience text
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  allowed boolean;
  family_id uuid;
BEGIN
  IF p_audience<>'platform' OR uuid_extract_version(p_session_id) IS DISTINCT FROM 7
     OR uuid_extract_version(p_user_id) IS DISTINCT FROM 7 THEN
    RAISE EXCEPTION 'invalid platform LDAP session lookup'
      USING ERRCODE='22023';
  END IF;
  SELECT session.rotation_family_id,
    provider.enabled AND provider.archived_at IS NULL
    AND provider.version=provenance.provider_version
    AND configuration.configuration_revision=provenance.configuration_revision
    AND configuration.security_revision=provenance.security_revision
    AND configuration.mapping_revision=provenance.mapping_revision
    AND identity.version=provenance.identity_version
    AND identity.disabled_at IS NULL AND identity.retired_at IS NULL
    AND factor.confirmed_at IS NOT NULL AND factor.disabled_at IS NULL
    AND factor.security_revision=provenance.totp_security_revision
    AND EXISTS (
      SELECT 1
      FROM ONLY public.platform_ldap_role_grants AS source_grant
      JOIN ONLY public.user_platform_roles AS user_role
        ON user_role.id=source_grant.user_platform_role_id
      JOIN ONLY public.platform_roles AS role
        ON role.id=source_grant.platform_role_id
      WHERE source_grant.provider_id=provider.id
        AND source_grant.external_identity_id=identity.id
        AND source_grant.user_id=p_user_id
        AND source_grant.revoked_at IS NULL
        AND user_role.revoked_at IS NULL
        AND role.key<>'platform_super_admin'
    )
  INTO family_id,allowed
  FROM ONLY public.auth_sessions AS session
  JOIN ONLY public.platform_ldap_session_provenance AS provenance
    ON provenance.session_id=session.id AND provenance.user_id=session.user_id
  JOIN ONLY public.platform_auth_providers AS provider
    ON provider.id=provenance.provider_id AND provider.kind='ldap'
  JOIN ONLY public.platform_ldap_provider_configurations AS configuration
    ON configuration.provider_id=provider.id
  JOIN ONLY public.platform_ldap_external_identities AS identity
    ON identity.provider_id=provider.id
   AND identity.id=provenance.external_identity_id
   AND identity.user_id=session.user_id
  JOIN ONLY public.totp_credentials AS factor
    ON factor.id=provenance.totp_credential_id
   AND factor.user_id=session.user_id
  JOIN ONLY public.users AS user_record ON user_record.id=session.user_id
  WHERE session.id=p_session_id AND session.user_id=p_user_id
    AND session.active_tenant_id IS NULL
    AND session.authentication_method='ldap'
    AND session.mfa_satisfied_at IS NOT NULL
    AND session.revoked_at IS NULL
    AND session.idle_expires_at>transaction_timestamp()
    AND session.absolute_expires_at>transaction_timestamp()
    AND user_record.active
  FOR SHARE OF session,provenance,provider,configuration,identity,factor,user_record;
  IF coalesce(allowed,false) THEN
    RETURN jsonb_build_object('sessionId',p_session_id,'userId',p_user_id,
      'allowed',true,'idleTouchAllowed',true);
  END IF;
  IF family_id IS NOT NULL THEN
    UPDATE ONLY public.auth_sessions
    SET revoked_at=transaction_timestamp(),revoke_reason='platform_ldap_authority_drift'
    WHERE user_id=p_user_id AND rotation_family_id=family_id
      AND active_tenant_id IS NULL AND authentication_method='ldap'
      AND revoked_at IS NULL;
  END IF;
  RETURN jsonb_build_object('sessionId',p_session_id,'userId',p_user_id,
    'allowed',false,'idleTouchAllowed',false);
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.guard_platform_ldap_immutable_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE old_row jsonb:=to_jsonb(OLD); new_row jsonb:=to_jsonb(NEW);
BEGIN
  IF TG_OP='DELETE' THEN
    RAISE EXCEPTION 'platform LDAP evidence is immutable'
      USING ERRCODE='42501';
  ELSIF TG_TABLE_NAME='platform_ldap_session_provenance' THEN
    RAISE EXCEPTION 'platform LDAP session provenance is immutable'
      USING ERRCODE='42501';
  ELSIF TG_TABLE_NAME IN (
    'platform_ldap_bind_secrets','platform_ldap_external_identity_aliases'
  ) THEN
    IF old_row->'retired_at'<>'null'::jsonb
       OR new_row->'retired_at'='null'::jsonb
       OR old_row-'retired_at'<>new_row-'retired_at' THEN
      RAISE EXCEPTION 'invalid platform LDAP retirement transition'
        USING ERRCODE='23514';
    END IF;
  ELSIF TG_TABLE_NAME='platform_ldap_authentication_runs' THEN
    IF old_row->>'state'<>'pending'
       OR new_row->>'state' NOT IN ('succeeded','denied','failed','stale')
       OR old_row-ARRAY[
         'state','failure_category','external_identity_id','user_id','session_id',
         'result_digest','completed_at'
       ]<>new_row-ARRAY[
         'state','failure_category','external_identity_id','user_id','session_id',
         'result_digest','completed_at'
       ] THEN
      RAISE EXCEPTION 'invalid platform LDAP authentication transition'
        USING ERRCODE='23514';
    END IF;
  ELSIF TG_TABLE_NAME='platform_ldap_test_runs' THEN
    IF old_row->>'state'<>'pending' OR new_row->>'state'<>'completed'
       OR old_row-ARRAY[
         'state','outcome','category','endpoint_priority','duration_ms',
         'matched_entry_count','attributes','completed_at'
       ]<>new_row-ARRAY[
         'state','outcome','category','endpoint_priority','duration_ms',
         'matched_entry_count','attributes','completed_at'
       ] THEN
      RAISE EXCEPTION 'invalid platform LDAP test transition'
        USING ERRCODE='23514';
    END IF;
  ELSIF TG_TABLE_NAME='platform_ldap_role_grants' THEN
    IF old_row->'revoked_at'<>'null'::jsonb
       OR old_row-ARRAY['source_mapping_revision','refreshed_at','revoked_at']
          <>new_row-ARRAY['source_mapping_revision','refreshed_at','revoked_at']
       OR (
         new_row->'revoked_at'<>'null'::jsonb
         AND (
           new_row->'source_mapping_revision'<>old_row->'source_mapping_revision'
           OR new_row->'refreshed_at'<>old_row->'refreshed_at'
         )
       ) THEN
      RAISE EXCEPTION 'invalid platform LDAP role-source transition'
        USING ERRCODE='23514';
    END IF;
  ELSE
    RAISE EXCEPTION 'unexpected platform LDAP guarded relation'
      USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END;
$function$;
--> statement-breakpoint

CREATE TRIGGER platform_ldap_bind_secrets_guard
BEFORE UPDATE OR DELETE ON public.platform_ldap_bind_secrets
FOR EACH ROW EXECUTE FUNCTION app.guard_platform_ldap_immutable_v1();
CREATE TRIGGER platform_ldap_external_identity_aliases_guard
BEFORE UPDATE OR DELETE ON public.platform_ldap_external_identity_aliases
FOR EACH ROW EXECUTE FUNCTION app.guard_platform_ldap_immutable_v1();
CREATE TRIGGER platform_ldap_role_grants_guard
BEFORE UPDATE OR DELETE ON public.platform_ldap_role_grants
FOR EACH ROW EXECUTE FUNCTION app.guard_platform_ldap_immutable_v1();
CREATE TRIGGER platform_ldap_authentication_runs_guard
BEFORE UPDATE OR DELETE ON public.platform_ldap_authentication_runs
FOR EACH ROW EXECUTE FUNCTION app.guard_platform_ldap_immutable_v1();
CREATE TRIGGER platform_ldap_session_provenance_guard
BEFORE UPDATE OR DELETE ON public.platform_ldap_session_provenance
FOR EACH ROW EXECUTE FUNCTION app.guard_platform_ldap_immutable_v1();
CREATE TRIGGER platform_ldap_test_runs_guard
BEFORE UPDATE OR DELETE ON public.platform_ldap_test_runs
FOR EACH ROW EXECUTE FUNCTION app.guard_platform_ldap_immutable_v1();
--> statement-breakpoint

CREATE FUNCTION app.platform_global_ldap_runtime_schema_readiness_v1()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE candidate_table text; function_name text;
BEGIN
  FOREACH candidate_table IN ARRAY ARRAY[
    'platform_ldap_provider_configurations',
    'platform_ldap_provider_endpoints','platform_ldap_bind_secrets',
    'platform_ldap_mapping_rules','platform_ldap_external_identities',
    'platform_ldap_external_identity_aliases','platform_ldap_role_grants',
    'platform_ldap_authentication_runs','platform_ldap_session_provenance',
    'platform_ldap_test_runs'
  ] LOOP
    IF NOT EXISTS (
      SELECT 1 FROM pg_class relation
      JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
      WHERE namespace.nspname='public' AND relation.relname=candidate_table
        AND relation.relkind='r' AND relation.relrowsecurity
        AND relation.relforcerowsecurity
        AND pg_get_userbyid(relation.relowner)='periapsis_migrator'
    ) OR EXISTS (
      SELECT 1 FROM information_schema.columns AS column_definition
      WHERE column_definition.table_schema='public'
        AND column_definition.table_name=candidate_table
        AND column_definition.column_name='tenant_id'
    ) OR has_table_privilege('periapsis_api',
      format('public.%I',candidate_table),'SELECT,INSERT,UPDATE,DELETE')
       OR has_table_privilege('periapsis_worker',
      format('public.%I',candidate_table),'SELECT,INSERT,UPDATE,DELETE') THEN
      RETURN false;
    END IF;
  END LOOP;
  FOREACH function_name IN ARRAY ARRAY[
    'app.create_platform_ldap_provider_v1(jsonb)',
    'app.get_platform_ldap_provider_v1(uuid,text,uuid)',
    'app.list_platform_ldap_providers_v1(uuid,text,boolean)',
    'app.get_platform_auth_provider_v2(uuid,uuid,text)',
    'app.list_platform_auth_providers_v2(uuid,text,uuid,integer,boolean)',
    'app.update_platform_ldap_provider_v1(jsonb)',
    'app.rotate_platform_ldap_bind_secret_v1(jsonb)',
    'app.put_platform_ldap_mapping_rule_v1(jsonb)',
    'app.set_platform_ldap_provider_enabled_v1(jsonb)',
    'app.begin_platform_ldap_test_v1(jsonb)',
    'app.complete_platform_ldap_test_v1(jsonb)',
    'app.begin_platform_ldap_authentication_v1(jsonb)',
    'app.load_platform_ldap_mfa_v1(jsonb)',
    'app.fail_platform_ldap_authentication_v1(jsonb)',
    'app.apply_platform_ldap_authentication_v1(jsonb)',
    'app.revalidate_platform_ldap_session_v1(uuid,uuid,text)'
  ] LOOP
    IF to_regprocedure(function_name) IS NULL
       OR NOT has_function_privilege('periapsis_api',function_name,'EXECUTE')
       OR has_function_privilege('public',function_name,'EXECUTE') THEN
      RETURN false;
    END IF;
  END LOOP;
  IF EXISTS (
    SELECT 1
    FROM ONLY public.platform_ldap_mapping_rules AS mapping
    JOIN ONLY public.platform_roles AS role ON role.id=mapping.platform_role_id
    WHERE mapping.enabled AND mapping.archived_at IS NULL
      AND role.key='platform_super_admin'
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid='public.platform_auth_providers'::regclass
      AND conname='platform_auth_providers_kind_check'
      AND pg_get_constraintdef(oid) LIKE '%ldap%'
  ) THEN
    RETURN false;
  END IF;
  RETURN true;
EXCEPTION WHEN OTHERS THEN
  RETURN false;
END;
$function$;
--> statement-breakpoint

ALTER FUNCTION app.private_platform_ldap_assert_object_v1(jsonb,text[],text[],integer)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_require_platform_ldap_permission_v1(uuid,text,text)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_platform_ldap_audit_v1(jsonb,uuid,text,text,uuid,public.audit_outcome,jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_platform_ldap_provider_document_v1(uuid)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_platform_auth_provider_document_v2(uuid)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.list_platform_auth_providers_v2(uuid,text,uuid,integer,boolean)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.get_platform_auth_provider_v2(uuid,uuid,text)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_replace_platform_ldap_configuration_v1(uuid,uuid,jsonb,jsonb,boolean)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.guard_platform_ldap_immutable_v1()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.create_platform_ldap_provider_v1(jsonb) OWNER TO periapsis_migrator;
ALTER FUNCTION app.get_platform_ldap_provider_v1(uuid,text,uuid) OWNER TO periapsis_migrator;
ALTER FUNCTION app.list_platform_ldap_providers_v1(uuid,text,boolean) OWNER TO periapsis_migrator;
ALTER FUNCTION app.update_platform_ldap_provider_v1(jsonb) OWNER TO periapsis_migrator;
ALTER FUNCTION app.rotate_platform_ldap_bind_secret_v1(jsonb) OWNER TO periapsis_migrator;
ALTER FUNCTION app.put_platform_ldap_mapping_rule_v1(jsonb) OWNER TO periapsis_migrator;
ALTER FUNCTION app.set_platform_ldap_provider_enabled_v1(jsonb) OWNER TO periapsis_migrator;
ALTER FUNCTION app.begin_platform_ldap_test_v1(jsonb) OWNER TO periapsis_migrator;
ALTER FUNCTION app.complete_platform_ldap_test_v1(jsonb) OWNER TO periapsis_migrator;
ALTER FUNCTION app.begin_platform_ldap_authentication_v1(jsonb) OWNER TO periapsis_migrator;
ALTER FUNCTION app.load_platform_ldap_mfa_v1(jsonb) OWNER TO periapsis_migrator;
ALTER FUNCTION app.fail_platform_ldap_authentication_v1(jsonb) OWNER TO periapsis_migrator;
ALTER FUNCTION app.apply_platform_ldap_authentication_v1(jsonb) OWNER TO periapsis_migrator;
ALTER FUNCTION app.revalidate_platform_ldap_session_v1(uuid,uuid,text) OWNER TO periapsis_migrator;
ALTER FUNCTION app.platform_global_ldap_runtime_schema_readiness_v1() OWNER TO periapsis_migrator;
--> statement-breakpoint

REVOKE ALL ON FUNCTION
  app.private_platform_ldap_assert_object_v1(jsonb,text[],text[],integer),
  app.private_require_platform_ldap_permission_v1(uuid,text,text),
  app.private_platform_ldap_audit_v1(jsonb,uuid,text,text,uuid,public.audit_outcome,jsonb),
  app.private_platform_ldap_provider_document_v1(uuid),
  app.private_platform_auth_provider_document_v2(uuid),
  app.private_replace_platform_ldap_configuration_v1(uuid,uuid,jsonb,jsonb,boolean),
  app.guard_platform_ldap_immutable_v1()
FROM periapsis_api,periapsis_worker,periapsis_notifier,periapsis_auditor,
  periapsis_audit_reader_owner,PUBLIC;
REVOKE ALL ON FUNCTION
  app.create_platform_ldap_provider_v1(jsonb),
  app.get_platform_ldap_provider_v1(uuid,text,uuid),
  app.list_platform_ldap_providers_v1(uuid,text,boolean),
  app.get_platform_auth_provider_v2(uuid,uuid,text),
  app.list_platform_auth_providers_v2(uuid,text,uuid,integer,boolean),
  app.update_platform_ldap_provider_v1(jsonb),
  app.rotate_platform_ldap_bind_secret_v1(jsonb),
  app.put_platform_ldap_mapping_rule_v1(jsonb),
  app.set_platform_ldap_provider_enabled_v1(jsonb),
  app.begin_platform_ldap_test_v1(jsonb),
  app.complete_platform_ldap_test_v1(jsonb),
  app.begin_platform_ldap_authentication_v1(jsonb),
  app.load_platform_ldap_mfa_v1(jsonb),
  app.fail_platform_ldap_authentication_v1(jsonb),
  app.apply_platform_ldap_authentication_v1(jsonb),
  app.revalidate_platform_ldap_session_v1(uuid,uuid,text),
  app.platform_global_ldap_runtime_schema_readiness_v1()
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_audit_reader_owner;
GRANT EXECUTE ON FUNCTION
  app.create_platform_ldap_provider_v1(jsonb),
  app.get_platform_ldap_provider_v1(uuid,text,uuid),
  app.list_platform_ldap_providers_v1(uuid,text,boolean),
  app.get_platform_auth_provider_v2(uuid,uuid,text),
  app.list_platform_auth_providers_v2(uuid,text,uuid,integer,boolean),
  app.update_platform_ldap_provider_v1(jsonb),
  app.rotate_platform_ldap_bind_secret_v1(jsonb),
  app.put_platform_ldap_mapping_rule_v1(jsonb),
  app.set_platform_ldap_provider_enabled_v1(jsonb),
  app.begin_platform_ldap_test_v1(jsonb),
  app.complete_platform_ldap_test_v1(jsonb),
  app.begin_platform_ldap_authentication_v1(jsonb),
  app.load_platform_ldap_mfa_v1(jsonb),
  app.fail_platform_ldap_authentication_v1(jsonb),
  app.apply_platform_ldap_authentication_v1(jsonb),
  app.revalidate_platform_ldap_session_v1(uuid,uuid,text)
TO periapsis_api;
GRANT EXECUTE ON FUNCTION app.platform_global_ldap_runtime_schema_readiness_v1()
  TO periapsis_migrator,periapsis_api,periapsis_worker;
--> statement-breakpoint
