CREATE TABLE "tenant_post_primary_federated_provenance" (
	"tenant_id" uuid NOT NULL,
	"continuation_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"origin" text NOT NULL,
	"primary_kind" text DEFAULT 'tenant_provider' NOT NULL,
	"authentication_method" text NOT NULL,
	"provider_id" uuid NOT NULL,
	"binding_id" uuid NOT NULL,
	"provider_kind" "auth_provider_kind" NOT NULL,
	"access_epoch_id" uuid NOT NULL,
	"access_source_id" uuid NOT NULL,
	"access_grant_id" uuid NOT NULL,
	"membership_id" uuid NOT NULL,
	"external_identity_id" uuid NOT NULL,
	"external_identity_revision" bigint NOT NULL,
	"provider_revision" bigint NOT NULL,
	"binding_revision" bigint NOT NULL,
	"configuration_revision" bigint NOT NULL,
	"security_revision" bigint NOT NULL,
	"plan_revision" bigint NOT NULL,
	"mapping_revision" bigint NOT NULL,
	"authorization_revision" bigint NOT NULL,
	"assurance_policy_revision" bigint NOT NULL,
	"authenticated_at" timestamp with time zone NOT NULL,
	"source_session_id" uuid,
	"source_session_family_id" uuid,
	"source_session_version" bigint,
	"source_absolute_expires_at" timestamp with time zone,
	CONSTRAINT "tenant_post_primary_federated_provenance_pkey" PRIMARY KEY("tenant_id","continuation_id"),
	CONSTRAINT "tenant_post_primary_federated_provenance_exact_key" UNIQUE("tenant_id","continuation_id","user_id","provider_id","binding_id","provider_kind","external_identity_id"),
	CONSTRAINT "tenant_post_primary_federated_provenance_value_check" CHECK ("tenant_post_primary_federated_provenance"."origin" in ('initial_login','session_revalidation')
        and "tenant_post_primary_federated_provenance"."primary_kind" = 'tenant_provider'
        and "tenant_post_primary_federated_provenance"."authentication_method" in ('oidc','saml')
        and "tenant_post_primary_federated_provenance"."provider_kind"::text = "tenant_post_primary_federated_provenance"."authentication_method"
        and "tenant_post_primary_federated_provenance"."external_identity_revision" between 1 and 9007199254740991
        and "tenant_post_primary_federated_provenance"."provider_revision" between 1 and 9007199254740991
        and "tenant_post_primary_federated_provenance"."binding_revision" between 1 and 9007199254740991
        and "tenant_post_primary_federated_provenance"."configuration_revision" between 1 and 9007199254740991
        and "tenant_post_primary_federated_provenance"."security_revision" between 1 and 9007199254740991
        and "tenant_post_primary_federated_provenance"."plan_revision" between 1 and 9007199254740991
        and "tenant_post_primary_federated_provenance"."mapping_revision" between 1 and 9007199254740991
        and "tenant_post_primary_federated_provenance"."authorization_revision" between 1 and 9007199254740991
        and "tenant_post_primary_federated_provenance"."assurance_policy_revision" between 1 and 9007199254740991
        and (("tenant_post_primary_federated_provenance"."origin" = 'initial_login'
          and "tenant_post_primary_federated_provenance"."source_session_id" is null
          and "tenant_post_primary_federated_provenance"."source_session_family_id" is null
          and "tenant_post_primary_federated_provenance"."source_session_version" is null
          and "tenant_post_primary_federated_provenance"."source_absolute_expires_at" is null)
        or ("tenant_post_primary_federated_provenance"."origin" = 'session_revalidation'
          and "tenant_post_primary_federated_provenance"."source_session_id" is not null
          and "tenant_post_primary_federated_provenance"."source_session_family_id" is not null
          and (uuid_extract_version("tenant_post_primary_federated_provenance"."source_session_family_id") = 7) is true
          and "tenant_post_primary_federated_provenance"."source_session_version" between 1 and 9007199254740991
          and "tenant_post_primary_federated_provenance"."source_absolute_expires_at" > "tenant_post_primary_federated_provenance"."authenticated_at")))
);
--> statement-breakpoint
ALTER TABLE "tenant_post_primary_federated_provenance" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_mfa_webauthn_evidence_copy_capabilities" (
	"tenant_id" uuid NOT NULL,
	"source_anchor_id" uuid NOT NULL,
	"source_evidence_id" uuid NOT NULL,
	"destination_session_id" uuid NOT NULL,
	"backend_pid" integer NOT NULL,
	"transaction_id" bigint NOT NULL,
	"user_id" uuid NOT NULL,
	"factor_kind" text DEFAULT 'webauthn' NOT NULL,
	"credential_id" uuid NOT NULL,
	"source_revision" bigint NOT NULL,
	"target_revision" bigint NOT NULL,
	"source_level" text NOT NULL,
	"target_level" text NOT NULL,
	"source_authenticated_at" timestamp with time zone NOT NULL,
	"source_expires_at" timestamp with time zone,
	"target_authenticated_at" timestamp with time zone NOT NULL,
	"consumed_evidence_id" uuid,
	"consumed_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_mfa_webauthn_evidence_copy_capabilities_pkey" PRIMARY KEY("tenant_id","source_anchor_id","destination_session_id","backend_pid","transaction_id"),
	CONSTRAINT "tenant_mfa_webauthn_evidence_copy_capabilities_destination_key" UNIQUE("backend_pid","transaction_id","tenant_id","destination_session_id","credential_id"),
	CONSTRAINT "tenant_mfa_webauthn_evidence_copy_capabilities_value_check" CHECK ("tenant_mfa_webauthn_evidence_copy_capabilities"."backend_pid" > 0
        and "tenant_mfa_webauthn_evidence_copy_capabilities"."transaction_id" > 0
        and (uuid_extract_version("tenant_mfa_webauthn_evidence_copy_capabilities"."destination_session_id") = 7) is true
        and "tenant_mfa_webauthn_evidence_copy_capabilities"."factor_kind" = 'webauthn'
        and "tenant_mfa_webauthn_evidence_copy_capabilities"."source_revision" between 1 and 9007199254740991
        and "tenant_mfa_webauthn_evidence_copy_capabilities"."target_revision" between "tenant_mfa_webauthn_evidence_copy_capabilities"."source_revision"
          and least("tenant_mfa_webauthn_evidence_copy_capabilities"."source_revision" + 1, 9007199254740991)
        and "tenant_mfa_webauthn_evidence_copy_capabilities"."source_level" in ('primary', 'mfa', 'phishing_resistant')
        and "tenant_mfa_webauthn_evidence_copy_capabilities"."target_level" in ('primary', 'mfa', 'phishing_resistant')
        and "tenant_mfa_webauthn_evidence_copy_capabilities"."target_authenticated_at" >= "tenant_mfa_webauthn_evidence_copy_capabilities"."source_authenticated_at"
        and ("tenant_mfa_webauthn_evidence_copy_capabilities"."source_expires_at" is null
          or "tenant_mfa_webauthn_evidence_copy_capabilities"."source_expires_at" > "tenant_mfa_webauthn_evidence_copy_capabilities"."source_authenticated_at")
        and (("tenant_mfa_webauthn_evidence_copy_capabilities"."consumed_evidence_id" is null and "tenant_mfa_webauthn_evidence_copy_capabilities"."consumed_at" is null)
          or ("tenant_mfa_webauthn_evidence_copy_capabilities"."consumed_evidence_id" is not null
            and (uuid_extract_version("tenant_mfa_webauthn_evidence_copy_capabilities"."consumed_evidence_id") = 7) is true
            and "tenant_mfa_webauthn_evidence_copy_capabilities"."consumed_at" is not null
            and "tenant_mfa_webauthn_evidence_copy_capabilities"."consumed_at" >= "tenant_mfa_webauthn_evidence_copy_capabilities"."created_at")))
);
--> statement-breakpoint
ALTER TABLE "tenant_mfa_webauthn_evidence_copy_capabilities" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_post_primary_passkey_provenance" (
	"tenant_id" uuid NOT NULL,
	"continuation_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"origin" text NOT NULL,
	"primary_kind" text DEFAULT 'passkey' NOT NULL,
	"authentication_method" text DEFAULT 'passkey' NOT NULL,
	"credential_id" uuid NOT NULL,
	"credential_revision" bigint NOT NULL,
	"authenticated_at" timestamp with time zone NOT NULL,
	"source_session_id" uuid,
	"source_session_family_id" uuid,
	"source_session_version" bigint,
	"source_absolute_expires_at" timestamp with time zone,
	CONSTRAINT "tenant_post_primary_passkey_provenance_pkey" PRIMARY KEY("tenant_id","continuation_id"),
	CONSTRAINT "tenant_post_primary_passkey_provenance_value_check" CHECK ("tenant_post_primary_passkey_provenance"."primary_kind" = 'passkey'
        and "tenant_post_primary_passkey_provenance"."authentication_method" = 'passkey'
        and "tenant_post_primary_passkey_provenance"."credential_revision" between 1 and 9007199254740991
        and (("tenant_post_primary_passkey_provenance"."origin" = 'initial_login'
          and "tenant_post_primary_passkey_provenance"."source_session_id" is null
          and "tenant_post_primary_passkey_provenance"."source_session_family_id" is null
          and "tenant_post_primary_passkey_provenance"."source_session_version" is null
          and "tenant_post_primary_passkey_provenance"."source_absolute_expires_at" is null)
        or ("tenant_post_primary_passkey_provenance"."origin" = 'session_revalidation'
          and "tenant_post_primary_passkey_provenance"."source_session_id" is not null
          and "tenant_post_primary_passkey_provenance"."source_session_family_id" is not null
          and (uuid_extract_version("tenant_post_primary_passkey_provenance"."source_session_family_id") = 7) is true
          and "tenant_post_primary_passkey_provenance"."source_session_version" between 1 and 9007199254740991
          and "tenant_post_primary_passkey_provenance"."source_absolute_expires_at" > "tenant_post_primary_passkey_provenance"."authenticated_at"
          and date_trunc('milliseconds', "tenant_post_primary_passkey_provenance"."source_absolute_expires_at") =
            "tenant_post_primary_passkey_provenance"."source_absolute_expires_at")))
);
--> statement-breakpoint
ALTER TABLE "tenant_post_primary_passkey_provenance" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "auth_session_tenant_platform_federated_evidence" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"session_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"platform_provider_id" uuid NOT NULL,
	"binding_id" uuid NOT NULL,
	"external_identity_id" uuid NOT NULL,
	"level" text NOT NULL,
	"authenticated_at" timestamp with time zone NOT NULL,
	"expires_at" timestamp with time zone,
	"trust_rule_revision" bigint NOT NULL,
	CONSTRAINT "auth_session_tenant_platform_federated_evidence_exact_key" UNIQUE("tenant_id","session_id","id"),
	CONSTRAINT "auth_session_tenant_platform_federated_evidence_id_uuidv7_check" CHECK ((uuid_extract_version("auth_session_tenant_platform_federated_evidence"."id") = 7) is true),
	CONSTRAINT "auth_session_tenant_platform_federated_evidence_value_check" CHECK ("auth_session_tenant_platform_federated_evidence"."level" in ('primary','mfa','phishing_resistant')
        and "auth_session_tenant_platform_federated_evidence"."trust_rule_revision" between 1 and 9007199254740991
        and ("auth_session_tenant_platform_federated_evidence"."expires_at" is null or "auth_session_tenant_platform_federated_evidence"."expires_at" > "auth_session_tenant_platform_federated_evidence"."authenticated_at"))
);
--> statement-breakpoint
ALTER TABLE "auth_session_tenant_platform_federated_evidence" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "auth_session_tenant_platform_federated_provenance" (
	"tenant_id" uuid NOT NULL,
	"session_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"primary_kind" text DEFAULT 'tenant_platform_provider' NOT NULL,
	"authentication_method" text DEFAULT 'oidc' NOT NULL,
	"platform_provider_id" uuid NOT NULL,
	"binding_id" uuid NOT NULL,
	"access_epoch_id" uuid NOT NULL,
	"access_source_id" uuid NOT NULL,
	"access_grant_id" uuid NOT NULL,
	"membership_id" uuid NOT NULL,
	"external_identity_id" uuid NOT NULL,
	"external_identity_revision" bigint NOT NULL,
	"provider_revision" bigint NOT NULL,
	"binding_revision" bigint NOT NULL,
	"security_revision" bigint NOT NULL,
	"mapping_revision" bigint NOT NULL,
	"authorization_revision" bigint NOT NULL,
	"subject_alias_key_version" integer NOT NULL,
	"trust_rule_revision" bigint NOT NULL,
	"authenticated_at" timestamp with time zone NOT NULL,
	CONSTRAINT "auth_session_tenant_platform_federated_provenance_pkey" PRIMARY KEY("tenant_id","session_id"),
	CONSTRAINT "auth_session_tenant_platform_federated_provenance_exact_key" UNIQUE("tenant_id","session_id","user_id","platform_provider_id","binding_id","external_identity_id"),
	CONSTRAINT "auth_session_tenant_platform_federated_provenance_value_check" CHECK ("auth_session_tenant_platform_federated_provenance"."primary_kind" = 'tenant_platform_provider'
        and "auth_session_tenant_platform_federated_provenance"."authentication_method" = 'oidc'
        and "auth_session_tenant_platform_federated_provenance"."external_identity_revision" between 1 and 2147483647
        and "auth_session_tenant_platform_federated_provenance"."provider_revision" between 1 and 2147483647
        and "auth_session_tenant_platform_federated_provenance"."binding_revision" between 1 and 2147483647
        and "auth_session_tenant_platform_federated_provenance"."security_revision" between 1 and 9007199254740991
        and "auth_session_tenant_platform_federated_provenance"."mapping_revision" between 1 and 9007199254740991
        and "auth_session_tenant_platform_federated_provenance"."authorization_revision" between 1 and 9007199254740991
        and "auth_session_tenant_platform_federated_provenance"."subject_alias_key_version" between 1 and 32767
        and "auth_session_tenant_platform_federated_provenance"."trust_rule_revision" between 1 and 9007199254740991)
);
--> statement-breakpoint
ALTER TABLE "auth_session_tenant_platform_federated_provenance" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "platform_federated_external_identities" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"platform_provider_id" uuid NOT NULL,
	"provider_kind" "auth_provider_kind" DEFAULT 'oidc' NOT NULL,
	"user_id" uuid NOT NULL,
	"subject_format" "identity_subject_format" NOT NULL,
	"subject_ciphertext" "bytea" NOT NULL,
	"subject_nonce" "bytea" NOT NULL,
	"key_version" integer NOT NULL,
	"admitted_configuration_revision" bigint NOT NULL,
	"admitted_security_revision" bigint NOT NULL,
	"last_observed_at" timestamp with time zone NOT NULL,
	"retired_at" timestamp with time zone,
	"version" bigint DEFAULT 1 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "platform_federated_external_identities_provider_key" UNIQUE("platform_provider_id","id"),
	CONSTRAINT "platform_federated_external_identities_exact_key" UNIQUE("platform_provider_id","id","user_id"),
	CONSTRAINT "platform_federated_external_identities_id_uuidv7_check" CHECK ((uuid_extract_version("platform_federated_external_identities"."id") = 7) is true),
	CONSTRAINT "platform_federated_external_identities_subject_check" CHECK ("platform_federated_external_identities"."provider_kind" = 'oidc'
        and "platform_federated_external_identities"."subject_format" = 'utf8_exact'
        and octet_length("platform_federated_external_identities"."subject_ciphertext") between 17 and 4112
        and octet_length("platform_federated_external_identities"."subject_nonce") = 12
        and "platform_federated_external_identities"."key_version" between 1 and 32767),
	CONSTRAINT "platform_federated_external_identities_lifecycle_check" CHECK ("platform_federated_external_identities"."admitted_configuration_revision" between 1 and 9007199254740991
        and "platform_federated_external_identities"."admitted_security_revision" between 1 and 9007199254740991
        and "platform_federated_external_identities"."version" between 1 and 2147483647
        and "platform_federated_external_identities"."last_observed_at" >= "platform_federated_external_identities"."created_at"
        and "platform_federated_external_identities"."updated_at" >= "platform_federated_external_identities"."created_at"
        and ("platform_federated_external_identities"."retired_at" is null or (
          "platform_federated_external_identities"."retired_at" >= "platform_federated_external_identities"."created_at"
          and "platform_federated_external_identities"."updated_at" >= "platform_federated_external_identities"."retired_at")))
);
--> statement-breakpoint
ALTER TABLE "platform_federated_external_identities" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "platform_federated_external_identity_aliases" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"platform_provider_id" uuid NOT NULL,
	"external_identity_id" uuid NOT NULL,
	"key_version" integer NOT NULL,
	"subject_digest" "bytea" NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"retired_at" timestamp with time zone,
	CONSTRAINT "platform_federated_external_identity_aliases_digest_key" UNIQUE("platform_provider_id","key_version","subject_digest"),
	CONSTRAINT "platform_federated_external_identity_aliases_version_key" UNIQUE("external_identity_id","key_version"),
	CONSTRAINT "platform_federated_external_identity_aliases_id_uuidv7_check" CHECK ((uuid_extract_version("platform_federated_external_identity_aliases"."id") = 7) is true),
	CONSTRAINT "platform_federated_external_identity_aliases_digest_check" CHECK ("platform_federated_external_identity_aliases"."key_version" between 1 and 32767
        and octet_length("platform_federated_external_identity_aliases"."subject_digest") = 32),
	CONSTRAINT "platform_federated_external_identity_aliases_lifecycle_check" CHECK ("platform_federated_external_identity_aliases"."retired_at" is null or "platform_federated_external_identity_aliases"."retired_at" >= "platform_federated_external_identity_aliases"."created_at")
);
--> statement-breakpoint
ALTER TABLE "platform_federated_external_identity_aliases" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_mfa_authority_platform_federated_evidence" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"anchor_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"platform_provider_id" uuid NOT NULL,
	"binding_id" uuid NOT NULL,
	"external_identity_id" uuid NOT NULL,
	"level" text NOT NULL,
	"authenticated_at" timestamp with time zone NOT NULL,
	"expires_at" timestamp with time zone,
	"trust_rule_revision" bigint NOT NULL,
	CONSTRAINT "tenant_mfa_authority_platform_federated_evidence_exact_key" UNIQUE("tenant_id","anchor_id","id"),
	CONSTRAINT "tenant_mfa_authority_platform_federated_evidence_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_mfa_authority_platform_federated_evidence"."id") = 7) is true),
	CONSTRAINT "tenant_mfa_authority_platform_federated_evidence_value_check" CHECK ("tenant_mfa_authority_platform_federated_evidence"."level" in ('primary','mfa','phishing_resistant')
        and "tenant_mfa_authority_platform_federated_evidence"."trust_rule_revision" between 1 and 9007199254740991
        and ("tenant_mfa_authority_platform_federated_evidence"."expires_at" is null or "tenant_mfa_authority_platform_federated_evidence"."expires_at" > "tenant_mfa_authority_platform_federated_evidence"."authenticated_at"))
);
--> statement-breakpoint
ALTER TABLE "tenant_mfa_authority_platform_federated_evidence" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_platform_federated_provider_access_grants" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"platform_provider_id" uuid NOT NULL,
	"binding_id" uuid NOT NULL,
	"access_epoch_id" uuid NOT NULL,
	"source_id" uuid NOT NULL,
	"external_identity_id" uuid NOT NULL,
	"membership_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"owns_membership" boolean DEFAULT false NOT NULL,
	"started_at" timestamp with time zone NOT NULL,
	"last_observed_at" timestamp with time zone NOT NULL,
	"ended_at" timestamp with time zone,
	"version" bigint DEFAULT 1 NOT NULL,
	CONSTRAINT "tenant_platform_federated_provider_access_grants_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "tenant_platform_federated_provider_access_grants_exact_key" UNIQUE("tenant_id","id","platform_provider_id","binding_id","access_epoch_id","source_id","external_identity_id","membership_id","user_id"),
	CONSTRAINT "tenant_platform_federated_provider_access_grants_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_platform_federated_provider_access_grants"."id") = 7) is true),
	CONSTRAINT "tenant_platform_federated_provider_access_grants_lifecycle_check" CHECK ("tenant_platform_federated_provider_access_grants"."version" between 1 and 2147483647
        and "tenant_platform_federated_provider_access_grants"."last_observed_at" >= "tenant_platform_federated_provider_access_grants"."started_at"
        and ("tenant_platform_federated_provider_access_grants"."ended_at" is null or "tenant_platform_federated_provider_access_grants"."ended_at" >= "tenant_platform_federated_provider_access_grants"."started_at"))
);
--> statement-breakpoint
ALTER TABLE "tenant_platform_federated_provider_access_grants" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_platform_federated_provider_profile_contributions" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"access_grant_id" uuid NOT NULL,
	"display_name" text,
	"username" text,
	"email" text,
	"mapping_revision" bigint NOT NULL,
	"observed_at" timestamp with time zone NOT NULL,
	"retired_at" timestamp with time zone,
	"version" bigint DEFAULT 1 NOT NULL,
	CONSTRAINT "tenant_platform_profile_contributions_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "tenant_platform_federated_provider_profile_contributions_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_platform_federated_provider_profile_contributions"."id") = 7) is true),
	CONSTRAINT "tenant_platform_federated_provider_profile_contributions_present_check" CHECK ("tenant_platform_federated_provider_profile_contributions"."display_name" is not null
        or "tenant_platform_federated_provider_profile_contributions"."username" is not null or "tenant_platform_federated_provider_profile_contributions"."email" is not null),
	CONSTRAINT "tenant_platform_federated_provider_profile_contributions_value_check" CHECK ("tenant_platform_federated_provider_profile_contributions"."mapping_revision" between 1 and 9007199254740991
        and "tenant_platform_federated_provider_profile_contributions"."version" between 1 and 2147483647
        and ("tenant_platform_federated_provider_profile_contributions"."display_name" is null or (
          btrim("tenant_platform_federated_provider_profile_contributions"."display_name") <> '' and char_length("tenant_platform_federated_provider_profile_contributions"."display_name") <= 160
          and "tenant_platform_federated_provider_profile_contributions"."display_name" !~ '[[:cntrl:]]'))
        and ("tenant_platform_federated_provider_profile_contributions"."username" is null or (
          btrim("tenant_platform_federated_provider_profile_contributions"."username") <> '' and char_length("tenant_platform_federated_provider_profile_contributions"."username") <= 320
          and "tenant_platform_federated_provider_profile_contributions"."username" !~ '[[:cntrl:]]'))
        and ("tenant_platform_federated_provider_profile_contributions"."email" is null or (
          "tenant_platform_federated_provider_profile_contributions"."email" = lower(btrim("tenant_platform_federated_provider_profile_contributions"."email"))
          and position('@' in "tenant_platform_federated_provider_profile_contributions"."email") > 1
          and char_length("tenant_platform_federated_provider_profile_contributions"."email") <= 320
          and "tenant_platform_federated_provider_profile_contributions"."email" !~ '[[:cntrl:]]'))),
	CONSTRAINT "tenant_platform_federated_provider_profile_contributions_lifecycle_check" CHECK ("tenant_platform_federated_provider_profile_contributions"."retired_at" is null or "tenant_platform_federated_provider_profile_contributions"."retired_at" >= "tenant_platform_federated_provider_profile_contributions"."observed_at")
);
--> statement-breakpoint
ALTER TABLE "tenant_platform_federated_provider_profile_contributions" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_platform_federated_session_revalidation_commands" (
	"tenant_id" uuid NOT NULL,
	"session_id" uuid NOT NULL,
	"expected_version" bigint NOT NULL,
	"request_digest" "bytea" NOT NULL,
	"decision" text NOT NULL,
	"result_snapshot" jsonb NOT NULL,
	"applied_at" timestamp with time zone NOT NULL,
	CONSTRAINT "tenant_platform_federated_session_revalidation_commands_pkey" PRIMARY KEY("tenant_id","session_id","expected_version"),
	CONSTRAINT "tenant_platform_federated_session_revalidation_commands_value_check" CHECK ("tenant_platform_federated_session_revalidation_commands"."expected_version" between 1 and 2147483647
        and octet_length("tenant_platform_federated_session_revalidation_commands"."request_digest") = 32
        and "tenant_platform_federated_session_revalidation_commands"."decision" in ('usable', 'rotate', 'step_up', 'revoke', 'deny')
        and jsonb_typeof("tenant_platform_federated_session_revalidation_commands"."result_snapshot") = 'object'
        and pg_column_size("tenant_platform_federated_session_revalidation_commands"."result_snapshot") between 2 and 65536)
);
--> statement-breakpoint
ALTER TABLE "tenant_platform_federated_session_revalidation_commands" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_platform_oidc_authentication_applications" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"transaction_id" "bytea" NOT NULL,
	"operation_digest" "bytea" NOT NULL,
	"platform_provider_id" uuid NOT NULL,
	"binding_id" uuid NOT NULL,
	"external_identity_id" uuid,
	"category" text NOT NULL,
	"primary_kind" text,
	"user_id" uuid,
	"session_id" uuid,
	"continuation_id" uuid,
	"request_snapshot" jsonb NOT NULL,
	"result_snapshot" jsonb NOT NULL,
	"applied_at" timestamp with time zone NOT NULL,
	CONSTRAINT "tenant_platform_oidc_authentication_applications_operation_key" UNIQUE("tenant_id","operation_digest"),
	CONSTRAINT "tenant_platform_oidc_authentication_applications_transaction_key" UNIQUE("tenant_id","transaction_id"),
	CONSTRAINT "tenant_platform_oidc_authentication_applications_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_platform_oidc_authentication_applications"."id") = 7) is true),
	CONSTRAINT "tenant_platform_oidc_authentication_applications_digest_check" CHECK (octet_length("tenant_platform_oidc_authentication_applications"."transaction_id") = 32
        and octet_length("tenant_platform_oidc_authentication_applications"."operation_digest") = 32),
	CONSTRAINT "tenant_platform_oidc_authentication_applications_result_check" CHECK ("tenant_platform_oidc_authentication_applications"."category" in ('success', 'identity_collision', 'stale', 'denied')
        and jsonb_typeof("tenant_platform_oidc_authentication_applications"."request_snapshot") = 'object'
        and pg_column_size("tenant_platform_oidc_authentication_applications"."request_snapshot") between 2 and 2097152
        and jsonb_typeof("tenant_platform_oidc_authentication_applications"."result_snapshot") = 'object'
        and pg_column_size("tenant_platform_oidc_authentication_applications"."result_snapshot") between 2 and 65536
        and (("tenant_platform_oidc_authentication_applications"."category" = 'success'
          and "tenant_platform_oidc_authentication_applications"."primary_kind" = 'tenant_platform_provider'
          and "tenant_platform_oidc_authentication_applications"."user_id" is not null and "tenant_platform_oidc_authentication_applications"."external_identity_id" is not null
          and (("tenant_platform_oidc_authentication_applications"."session_id" is null) <> ("tenant_platform_oidc_authentication_applications"."continuation_id" is null)))
        or ("tenant_platform_oidc_authentication_applications"."category" <> 'success'
          and "tenant_platform_oidc_authentication_applications"."primary_kind" is null and "tenant_platform_oidc_authentication_applications"."user_id" is null
          and "tenant_platform_oidc_authentication_applications"."external_identity_id" is null
          and "tenant_platform_oidc_authentication_applications"."session_id" is null and "tenant_platform_oidc_authentication_applications"."continuation_id" is null)))
);
--> statement-breakpoint
ALTER TABLE "tenant_platform_oidc_authentication_applications" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_platform_oidc_authentication_transactions" (
	"transaction_id" "bytea" NOT NULL,
	"tenant_id" uuid NOT NULL,
	"platform_provider_id" uuid NOT NULL,
	"binding_id" uuid NOT NULL,
	"provider_kind" "auth_provider_kind" DEFAULT 'oidc' NOT NULL,
	"protocol" text DEFAULT 'oidc' NOT NULL,
	"access_epoch_id" uuid NOT NULL,
	"access_source_id" uuid NOT NULL,
	"operation_run_id" uuid NOT NULL,
	"operation_digest" "bytea" NOT NULL,
	"receipt_digest" "bytea" NOT NULL,
	"network_digest" "bytea" NOT NULL,
	"account_digest" "bytea" NOT NULL,
	"provider_digest" "bytea" NOT NULL,
	"state_digest" "bytea" NOT NULL,
	"browser_digest" "bytea" NOT NULL,
	"nonce_digest" "bytea" NOT NULL,
	"provider_revision" bigint NOT NULL,
	"binding_revision" bigint NOT NULL,
	"configuration_revision" bigint NOT NULL,
	"security_revision" bigint NOT NULL,
	"plan_revision" bigint NOT NULL,
	"mapping_revision" bigint NOT NULL,
	"authorization_revision" bigint NOT NULL,
	"assurance_policy_revision" bigint NOT NULL,
	"client_secret_revision" bigint NOT NULL,
	"discovery_revision" bigint NOT NULL,
	"discovery_digest" "bytea" NOT NULL,
	"jwks_revision" bigint NOT NULL,
	"jwks_digest" "bytea" NOT NULL,
	"verifier_key_version" integer NOT NULL,
	"verifier_ciphertext" "bytea" NOT NULL,
	"client_id" text NOT NULL,
	"tenant_redirect_uri" text NOT NULL,
	"post_logout_redirect_uri" text NOT NULL,
	"scopes" text[] NOT NULL,
	"allow_refresh_token" boolean NOT NULL,
	"use_user_info" boolean NOT NULL,
	"return_path" text NOT NULL,
	"state" text DEFAULT 'pending' NOT NULL,
	"version" bigint DEFAULT 1 NOT NULL,
	"claim_attempt_id" "bytea",
	"created_at" timestamp with time zone NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"claimed_at" timestamp with time zone,
	"completed_at" timestamp with time zone,
	"failure_reason" text,
	CONSTRAINT "tenant_platform_oidc_authentication_transactions_pkey" PRIMARY KEY("tenant_id","transaction_id"),
	CONSTRAINT "tenant_platform_oidc_authentication_transactions_operation_key" UNIQUE("operation_run_id"),
	CONSTRAINT "tenant_platform_oidc_authentication_transactions_receipt_key" UNIQUE("receipt_digest"),
	CONSTRAINT "tenant_platform_oidc_authentication_transactions_state_key" UNIQUE("state_digest"),
	CONSTRAINT "tenant_platform_oidc_authentication_transactions_exact_key" UNIQUE("tenant_id","transaction_id","platform_provider_id","binding_id"),
	CONSTRAINT "tenant_platform_oidc_authentication_transactions_id_check" CHECK (octet_length("tenant_platform_oidc_authentication_transactions"."transaction_id") = 32
        and (uuid_extract_version("tenant_platform_oidc_authentication_transactions"."operation_run_id") = 7) is true),
	CONSTRAINT "tenant_platform_oidc_authentication_transactions_digest_check" CHECK (octet_length("tenant_platform_oidc_authentication_transactions"."operation_digest") = 32
        and octet_length("tenant_platform_oidc_authentication_transactions"."receipt_digest") = 32
        and octet_length("tenant_platform_oidc_authentication_transactions"."network_digest") = 32
        and octet_length("tenant_platform_oidc_authentication_transactions"."account_digest") = 32
        and octet_length("tenant_platform_oidc_authentication_transactions"."provider_digest") = 32
        and octet_length("tenant_platform_oidc_authentication_transactions"."state_digest") = 32
        and octet_length("tenant_platform_oidc_authentication_transactions"."browser_digest") = 32
        and octet_length("tenant_platform_oidc_authentication_transactions"."nonce_digest") = 32
        and octet_length("tenant_platform_oidc_authentication_transactions"."discovery_digest") = 32
        and octet_length("tenant_platform_oidc_authentication_transactions"."jwks_digest") = 32),
	CONSTRAINT "tenant_platform_oidc_authentication_transactions_pin_check" CHECK ("tenant_platform_oidc_authentication_transactions"."provider_kind" = 'oidc' and "tenant_platform_oidc_authentication_transactions"."protocol" = 'oidc'
        and "tenant_platform_oidc_authentication_transactions"."provider_revision" between 1 and 2147483647
        and "tenant_platform_oidc_authentication_transactions"."binding_revision" between 1 and 2147483647
        and "tenant_platform_oidc_authentication_transactions"."configuration_revision" between 1 and 9007199254740991
        and "tenant_platform_oidc_authentication_transactions"."security_revision" between 1 and 9007199254740991
        and "tenant_platform_oidc_authentication_transactions"."plan_revision" between 1 and 9007199254740991
        and "tenant_platform_oidc_authentication_transactions"."mapping_revision" between 1 and 9007199254740991
        and "tenant_platform_oidc_authentication_transactions"."authorization_revision" between 1 and 9007199254740991
        and "tenant_platform_oidc_authentication_transactions"."assurance_policy_revision" between 1 and 9007199254740991
        and "tenant_platform_oidc_authentication_transactions"."client_secret_revision" between 1 and 9007199254740991
        and "tenant_platform_oidc_authentication_transactions"."discovery_revision" between 1 and 9007199254740991
        and "tenant_platform_oidc_authentication_transactions"."jwks_revision" between 1 and 9007199254740991
        and "tenant_platform_oidc_authentication_transactions"."verifier_key_version" between 1 and 32767
        and octet_length("tenant_platform_oidc_authentication_transactions"."verifier_ciphertext") between 16 and 4096
        and octet_length(convert_to("tenant_platform_oidc_authentication_transactions"."client_id", 'UTF8')) between 1 and 512
        and "tenant_platform_oidc_authentication_transactions"."tenant_redirect_uri" ~ '^https://[^/?#@]+/api/v1/auth/federated/oidc/callback$'
        and char_length("tenant_platform_oidc_authentication_transactions"."tenant_redirect_uri") between 1 and 4096
        and char_length("tenant_platform_oidc_authentication_transactions"."post_logout_redirect_uri") between 1 and 4096
        and cardinality("tenant_platform_oidc_authentication_transactions"."scopes") between 1 and 64
        and array_position("tenant_platform_oidc_authentication_transactions"."scopes", null) is null
        and char_length("tenant_platform_oidc_authentication_transactions"."return_path") between 1 and 2048
        and left("tenant_platform_oidc_authentication_transactions"."return_path", 1) = '/'
        and "tenant_platform_oidc_authentication_transactions"."client_id" !~ '[[:cntrl:]]'
        and "tenant_platform_oidc_authentication_transactions"."tenant_redirect_uri" !~ '[[:cntrl:]]'
        and "tenant_platform_oidc_authentication_transactions"."post_logout_redirect_uri" !~ '[[:cntrl:]]'
        and "tenant_platform_oidc_authentication_transactions"."return_path" !~ '[[:cntrl:]]'),
	CONSTRAINT "tenant_platform_oidc_authentication_transactions_lifecycle_check" CHECK ("tenant_platform_oidc_authentication_transactions"."version" between 1 and 2147483647
        and "tenant_platform_oidc_authentication_transactions"."expires_at" between "tenant_platform_oidc_authentication_transactions"."created_at" + interval '1 minute'
          and "tenant_platform_oidc_authentication_transactions"."created_at" + interval '15 minutes'
        and ((
          "tenant_platform_oidc_authentication_transactions"."state" = 'pending' and "tenant_platform_oidc_authentication_transactions"."claim_attempt_id" is null
          and "tenant_platform_oidc_authentication_transactions"."claimed_at" is null and "tenant_platform_oidc_authentication_transactions"."completed_at" is null
          and "tenant_platform_oidc_authentication_transactions"."failure_reason" is null
        ) or (
          "tenant_platform_oidc_authentication_transactions"."state" = 'claimed' and octet_length("tenant_platform_oidc_authentication_transactions"."claim_attempt_id") = 32
          and "tenant_platform_oidc_authentication_transactions"."claimed_at" is not null and "tenant_platform_oidc_authentication_transactions"."completed_at" is null
          and "tenant_platform_oidc_authentication_transactions"."failure_reason" is null
        ) or (
          "tenant_platform_oidc_authentication_transactions"."state" in ('completed', 'failed', 'expired')
          and "tenant_platform_oidc_authentication_transactions"."completed_at" is not null
          and "tenant_platform_oidc_authentication_transactions"."completed_at" >= "tenant_platform_oidc_authentication_transactions"."created_at"
          and ("tenant_platform_oidc_authentication_transactions"."claim_attempt_id" is null) = ("tenant_platform_oidc_authentication_transactions"."claimed_at" is null)
          and ("tenant_platform_oidc_authentication_transactions"."state" <> 'completed'
            or ("tenant_platform_oidc_authentication_transactions"."claim_attempt_id" is not null and "tenant_platform_oidc_authentication_transactions"."failure_reason" is null))
          and ("tenant_platform_oidc_authentication_transactions"."state" = 'completed') = ("tenant_platform_oidc_authentication_transactions"."failure_reason" is null)
        )))
);
--> statement-breakpoint
ALTER TABLE "tenant_platform_oidc_authentication_transactions" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_post_primary_platform_federated_evidence" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"continuation_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"platform_provider_id" uuid NOT NULL,
	"binding_id" uuid NOT NULL,
	"external_identity_id" uuid NOT NULL,
	"level" text NOT NULL,
	"authenticated_at" timestamp with time zone NOT NULL,
	"expires_at" timestamp with time zone,
	"trust_rule_revision" bigint NOT NULL,
	CONSTRAINT "tenant_post_primary_platform_federated_evidence_exact_key" UNIQUE("tenant_id","continuation_id","id"),
	CONSTRAINT "tenant_post_primary_platform_federated_evidence_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_post_primary_platform_federated_evidence"."id") = 7) is true),
	CONSTRAINT "tenant_post_primary_platform_federated_evidence_value_check" CHECK ("tenant_post_primary_platform_federated_evidence"."level" in ('primary','mfa','phishing_resistant')
        and "tenant_post_primary_platform_federated_evidence"."trust_rule_revision" between 1 and 9007199254740991
        and ("tenant_post_primary_platform_federated_evidence"."expires_at" is null or "tenant_post_primary_platform_federated_evidence"."expires_at" > "tenant_post_primary_platform_federated_evidence"."authenticated_at"))
);
--> statement-breakpoint
ALTER TABLE "tenant_post_primary_platform_federated_evidence" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_post_primary_platform_federated_provenance" (
	"tenant_id" uuid NOT NULL,
	"continuation_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"origin" text NOT NULL,
	"platform_provider_id" uuid NOT NULL,
	"binding_id" uuid NOT NULL,
	"access_epoch_id" uuid NOT NULL,
	"access_source_id" uuid NOT NULL,
	"access_grant_id" uuid NOT NULL,
	"membership_id" uuid NOT NULL,
	"external_identity_id" uuid NOT NULL,
	"external_identity_revision" bigint NOT NULL,
	"provider_revision" bigint NOT NULL,
	"binding_revision" bigint NOT NULL,
	"security_revision" bigint NOT NULL,
	"mapping_revision" bigint NOT NULL,
	"authorization_revision" bigint NOT NULL,
	"subject_alias_key_version" integer NOT NULL,
	"trust_rule_revision" bigint NOT NULL,
	"authenticated_at" timestamp with time zone NOT NULL,
	"source_session_id" uuid,
	"source_session_family_id" uuid,
	"source_session_version" bigint,
	"source_absolute_expires_at" timestamp with time zone,
	CONSTRAINT "tenant_post_primary_platform_federated_provenance_pkey" PRIMARY KEY("tenant_id","continuation_id"),
	CONSTRAINT "tenant_post_primary_platform_federated_provenance_exact_key" UNIQUE("tenant_id","continuation_id","user_id","platform_provider_id","binding_id","external_identity_id"),
	CONSTRAINT "tenant_post_primary_platform_federated_provenance_value_check" CHECK ("tenant_post_primary_platform_federated_provenance"."origin" in ('initial_login','session_revalidation')
        and "tenant_post_primary_platform_federated_provenance"."external_identity_revision" between 1 and 2147483647
        and "tenant_post_primary_platform_federated_provenance"."provider_revision" between 1 and 2147483647
        and "tenant_post_primary_platform_federated_provenance"."binding_revision" between 1 and 2147483647
        and "tenant_post_primary_platform_federated_provenance"."security_revision" between 1 and 9007199254740991
        and "tenant_post_primary_platform_federated_provenance"."mapping_revision" between 1 and 9007199254740991
        and "tenant_post_primary_platform_federated_provenance"."authorization_revision" between 1 and 9007199254740991
        and "tenant_post_primary_platform_federated_provenance"."subject_alias_key_version" between 1 and 32767
        and "tenant_post_primary_platform_federated_provenance"."trust_rule_revision" between 1 and 9007199254740991
        and (("tenant_post_primary_platform_federated_provenance"."origin" = 'initial_login'
          and "tenant_post_primary_platform_federated_provenance"."source_session_id" is null
          and "tenant_post_primary_platform_federated_provenance"."source_session_family_id" is null
          and "tenant_post_primary_platform_federated_provenance"."source_session_version" is null
          and "tenant_post_primary_platform_federated_provenance"."source_absolute_expires_at" is null)
        or ("tenant_post_primary_platform_federated_provenance"."origin" = 'session_revalidation'
          and "tenant_post_primary_platform_federated_provenance"."source_session_id" is not null
          and "tenant_post_primary_platform_federated_provenance"."source_session_family_id" is not null
          and (uuid_extract_version("tenant_post_primary_platform_federated_provenance"."source_session_family_id") = 7) is true
          and "tenant_post_primary_platform_federated_provenance"."source_session_version" between 1 and 9007199254740991
          and "tenant_post_primary_platform_federated_provenance"."source_absolute_expires_at" > "tenant_post_primary_platform_federated_provenance"."authenticated_at")))
);
--> statement-breakpoint
ALTER TABLE "tenant_post_primary_platform_federated_provenance" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "auth_session_mfa_states" DROP CONSTRAINT "auth_session_mfa_states_primary_kind_check";--> statement-breakpoint
ALTER TABLE "tenant_mfa_step_up_challenges" DROP CONSTRAINT "tenant_mfa_step_up_challenges_lifecycle_check";--> statement-breakpoint
ALTER TABLE "tenant_post_primary_continuations" DROP CONSTRAINT "tenant_post_primary_continuations_primary_check";--> statement-breakpoint
ALTER TABLE "tenant_post_primary_continuations" DROP CONSTRAINT "tenant_post_primary_continuations_lifecycle_check";--> statement-breakpoint
ALTER TABLE "tenant_webauthn_credentials" DROP CONSTRAINT "tenant_webauthn_credentials_timestamps_check";--> statement-breakpoint
ALTER TABLE "platform_federated_provider_policies" DROP CONSTRAINT "platform_federated_provider_policies_login_check";--> statement-breakpoint
ALTER TABLE "platform_oidc_provider_configurations" DROP CONSTRAINT "platform_oidc_provider_configurations_text_check";--> statement-breakpoint
ALTER TABLE "tenant_platform_auth_provider_bindings" DROP CONSTRAINT "tenant_platform_auth_provider_bindings_disabled_check";--> statement-breakpoint
ALTER TABLE "tenant_platform_identity_provider_access_epochs" DROP CONSTRAINT "tenant_platform_identity_provider_access_epochs_staging_check";--> statement-breakpoint
ALTER TABLE "tenant_federated_authentication_transactions" ADD COLUMN "plan_revision" bigint NOT NULL;--> statement-breakpoint
ALTER TABLE "tenant_mfa_step_up_challenges" ADD COLUMN "claimed_factor_kind" text;--> statement-breakpoint
ALTER TABLE "tenant_post_primary_continuations" ADD COLUMN "platform_provider_id" uuid;--> statement-breakpoint
ALTER TABLE "tenant_webauthn_credentials" ADD COLUMN "security_revision" bigint DEFAULT 1 NOT NULL;--> statement-breakpoint
ALTER TABLE "platform_oidc_provider_configurations" ADD COLUMN "tenant_redirect_uri" text NOT NULL;--> statement-breakpoint
ALTER TABLE "tenant_platform_auth_provider_bindings" ADD COLUMN "jit_mode" text DEFAULT 'disabled' NOT NULL;--> statement-breakpoint
ALTER TABLE "tenant_platform_auth_provider_bindings" ADD COLUMN "no_match_policy" text DEFAULT 'deny' NOT NULL;--> statement-breakpoint
ALTER TABLE "tenant_post_primary_continuations" ADD CONSTRAINT "tenant_post_primary_continuations_exact_passkey_key" UNIQUE("tenant_id","id","user_id","passkey_credential_id");--> statement-breakpoint
ALTER TABLE "tenant_post_primary_continuations" ADD CONSTRAINT "tenant_post_primary_continuations_exact_platform_provider_key" UNIQUE("tenant_id","id","user_id","platform_provider_id","binding_id","external_identity_id");--> statement-breakpoint
ALTER TABLE "tenant_post_primary_federated_provenance" ADD CONSTRAINT "tenant_post_primary_federated_provenance_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_post_primary_federated_provenance" ADD CONSTRAINT "tenant_post_primary_federated_provenance_source_session_id_auth_sessions_id_fk" FOREIGN KEY ("source_session_id") REFERENCES "public"."auth_sessions"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_post_primary_federated_provenance" ADD CONSTRAINT "tenant_post_primary_federated_provenance_continuation_fk" FOREIGN KEY ("tenant_id","continuation_id","user_id","provider_id","binding_id","provider_kind","external_identity_id") REFERENCES "public"."tenant_post_primary_continuations"("tenant_id","id","user_id","provider_id","binding_id","provider_kind","external_identity_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_post_primary_federated_provenance" ADD CONSTRAINT "tenant_post_primary_federated_provenance_identity_fk" FOREIGN KEY ("tenant_id","provider_id","external_identity_id","user_id") REFERENCES "public"."tenant_federated_external_identities"("tenant_id","provider_id","id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_post_primary_federated_provenance" ADD CONSTRAINT "tenant_post_primary_federated_provenance_binding_fk" FOREIGN KEY ("tenant_id","binding_id","provider_id") REFERENCES "public"."tenant_auth_provider_bindings"("tenant_id","id","provider_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_post_primary_federated_provenance" ADD CONSTRAINT "tenant_post_primary_federated_provenance_access_grant_fk" FOREIGN KEY ("tenant_id","access_grant_id") REFERENCES "public"."tenant_federated_provider_access_grants"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_post_primary_federated_provenance" ADD CONSTRAINT "tenant_post_primary_federated_provenance_membership_fk" FOREIGN KEY ("tenant_id","membership_id","user_id") REFERENCES "public"."tenant_memberships"("tenant_id","id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_mfa_webauthn_evidence_copy_capabilities" ADD CONSTRAINT "tenant_mfa_webauthn_evidence_copy_capabilities_tenant_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_mfa_webauthn_evidence_copy_capabilities" ADD CONSTRAINT "tenant_mfa_webauthn_evidence_copy_capabilities_source_fk" FOREIGN KEY ("tenant_id","source_anchor_id","source_evidence_id") REFERENCES "public"."tenant_mfa_authority_evidence"("tenant_id","anchor_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_mfa_webauthn_evidence_copy_capabilities" ADD CONSTRAINT "tenant_mfa_webauthn_evidence_copy_capabilities_credential_fk" FOREIGN KEY ("tenant_id","user_id","credential_id") REFERENCES "public"."tenant_webauthn_credentials"("tenant_id","user_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_post_primary_passkey_provenance" ADD CONSTRAINT "tenant_post_primary_passkey_provenance_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_post_primary_passkey_provenance" ADD CONSTRAINT "tenant_post_primary_passkey_provenance_source_session_id_auth_sessions_id_fk" FOREIGN KEY ("source_session_id") REFERENCES "public"."auth_sessions"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_post_primary_passkey_provenance" ADD CONSTRAINT "tenant_post_primary_passkey_provenance_continuation_fk" FOREIGN KEY ("tenant_id","continuation_id","user_id","credential_id") REFERENCES "public"."tenant_post_primary_continuations"("tenant_id","id","user_id","passkey_credential_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_post_primary_passkey_provenance" ADD CONSTRAINT "tenant_post_primary_passkey_provenance_credential_fk" FOREIGN KEY ("tenant_id","user_id","credential_id") REFERENCES "public"."tenant_webauthn_credentials"("tenant_id","user_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "auth_session_tenant_platform_federated_evidence" ADD CONSTRAINT "auth_session_tenant_platform_federated_evidence_provenance_fk" FOREIGN KEY ("tenant_id","session_id","user_id","platform_provider_id","binding_id","external_identity_id") REFERENCES "public"."auth_session_tenant_platform_federated_provenance"("tenant_id","session_id","user_id","platform_provider_id","binding_id","external_identity_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "auth_session_tenant_platform_federated_provenance" ADD CONSTRAINT "auth_session_tenant_platform_federated_provenance_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "auth_session_tenant_platform_federated_provenance" ADD CONSTRAINT "auth_session_tenant_platform_federated_provenance_state_fk" FOREIGN KEY ("tenant_id","session_id","primary_kind","user_id") REFERENCES "public"."auth_session_mfa_states"("tenant_id","session_id","primary_kind","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "auth_session_tenant_platform_federated_provenance" ADD CONSTRAINT "auth_session_tenant_platform_federated_provenance_identity_fk" FOREIGN KEY ("platform_provider_id","external_identity_id","user_id") REFERENCES "public"."platform_federated_external_identities"("platform_provider_id","id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "auth_session_tenant_platform_federated_provenance" ADD CONSTRAINT "auth_session_tenant_platform_federated_provenance_binding_fk" FOREIGN KEY ("tenant_id","binding_id","platform_provider_id") REFERENCES "public"."tenant_platform_auth_provider_bindings"("tenant_id","id","platform_provider_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "auth_session_tenant_platform_federated_provenance" ADD CONSTRAINT "auth_session_tenant_platform_federated_provenance_access_grant_fk" FOREIGN KEY ("tenant_id","access_grant_id","platform_provider_id","binding_id","access_epoch_id","access_source_id","external_identity_id","membership_id","user_id") REFERENCES "public"."tenant_platform_federated_provider_access_grants"("tenant_id","id","platform_provider_id","binding_id","access_epoch_id","source_id","external_identity_id","membership_id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_federated_external_identities" ADD CONSTRAINT "platform_federated_external_identities_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "platform_federated_external_identities" ADD CONSTRAINT "platform_federated_external_identities_provider_fk" FOREIGN KEY ("platform_provider_id","provider_kind") REFERENCES "public"."platform_auth_providers"("id","kind") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_federated_external_identities" ADD CONSTRAINT "platform_federated_external_identities_policy_fk" FOREIGN KEY ("platform_provider_id","provider_kind") REFERENCES "public"."platform_federated_provider_policies"("provider_id","provider_kind") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_federated_external_identities" ADD CONSTRAINT "platform_federated_external_identities_keyring_fk" FOREIGN KEY ("key_version") REFERENCES "public"."identity_keyring_versions"("key_version") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_federated_external_identity_aliases" ADD CONSTRAINT "platform_federated_external_identity_aliases_identity_fk" FOREIGN KEY ("platform_provider_id","external_identity_id") REFERENCES "public"."platform_federated_external_identities"("platform_provider_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_federated_external_identity_aliases" ADD CONSTRAINT "platform_federated_external_identity_aliases_keyring_fk" FOREIGN KEY ("key_version") REFERENCES "public"."identity_keyring_versions"("key_version") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_mfa_authority_platform_federated_evidence" ADD CONSTRAINT "tenant_mfa_authority_platform_federated_evidence_anchor_fk" FOREIGN KEY ("tenant_id","anchor_id") REFERENCES "public"."tenant_mfa_authority_anchors"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_mfa_authority_platform_federated_evidence" ADD CONSTRAINT "tenant_mfa_authority_platform_federated_evidence_identity_fk" FOREIGN KEY ("platform_provider_id","external_identity_id","user_id") REFERENCES "public"."platform_federated_external_identities"("platform_provider_id","id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_mfa_authority_platform_federated_evidence" ADD CONSTRAINT "tenant_mfa_authority_platform_federated_evidence_binding_fk" FOREIGN KEY ("tenant_id","binding_id","platform_provider_id") REFERENCES "public"."tenant_platform_auth_provider_bindings"("tenant_id","id","platform_provider_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_platform_federated_provider_access_grants" ADD CONSTRAINT "tenant_platform_federated_provider_access_grants_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_platform_federated_provider_access_grants" ADD CONSTRAINT "tenant_platform_federated_provider_access_grants_epoch_fk" FOREIGN KEY ("tenant_id","access_epoch_id","binding_id","platform_provider_id","source_id") REFERENCES "public"."tenant_platform_identity_provider_access_epochs"("tenant_id","id","binding_id","platform_provider_id","source_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_platform_federated_provider_access_grants" ADD CONSTRAINT "tenant_platform_federated_provider_access_grants_identity_fk" FOREIGN KEY ("platform_provider_id","external_identity_id","user_id") REFERENCES "public"."platform_federated_external_identities"("platform_provider_id","id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_platform_federated_provider_access_grants" ADD CONSTRAINT "tenant_platform_federated_provider_access_grants_membership_fk" FOREIGN KEY ("tenant_id","membership_id","user_id") REFERENCES "public"."tenant_memberships"("tenant_id","id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_platform_federated_provider_access_grants" ADD CONSTRAINT "tenant_platform_federated_provider_access_grants_source_fk" FOREIGN KEY ("tenant_id","source_id") REFERENCES "public"."tenant_authorization_sources"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_platform_federated_provider_profile_contributions" ADD CONSTRAINT "tenant_platform_federated_provider_profile_contributions_grant_fk" FOREIGN KEY ("tenant_id","access_grant_id") REFERENCES "public"."tenant_platform_federated_provider_access_grants"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_platform_federated_provider_profile_contributions" ADD CONSTRAINT "tenant_platform_profile_contributions_tenant_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_platform_federated_session_revalidation_commands" ADD CONSTRAINT "tenant_platform_federated_session_revalidation_commands_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_platform_federated_session_revalidation_commands" ADD CONSTRAINT "tenant_platform_federated_session_revalidation_commands_session_fk" FOREIGN KEY ("tenant_id","session_id") REFERENCES "public"."auth_session_tenant_platform_federated_provenance"("tenant_id","session_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_platform_oidc_authentication_applications" ADD CONSTRAINT "tenant_platform_oidc_authentication_applications_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_platform_oidc_authentication_applications" ADD CONSTRAINT "tenant_platform_oidc_authentication_applications_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_platform_oidc_authentication_applications" ADD CONSTRAINT "tenant_platform_oidc_authentication_applications_session_id_auth_sessions_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."auth_sessions"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_platform_oidc_authentication_applications" ADD CONSTRAINT "tenant_platform_oidc_authentication_applications_transaction_fk" FOREIGN KEY ("tenant_id","transaction_id","platform_provider_id","binding_id") REFERENCES "public"."tenant_platform_oidc_authentication_transactions"("tenant_id","transaction_id","platform_provider_id","binding_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_platform_oidc_authentication_applications" ADD CONSTRAINT "tenant_platform_oidc_authentication_applications_session_fk" FOREIGN KEY ("tenant_id","session_id","primary_kind","user_id") REFERENCES "public"."auth_session_mfa_states"("tenant_id","session_id","primary_kind","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_platform_oidc_authentication_applications" ADD CONSTRAINT "tenant_platform_oidc_authentication_applications_continuation_fk" FOREIGN KEY ("tenant_id","continuation_id","user_id") REFERENCES "public"."tenant_post_primary_continuations"("tenant_id","id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_platform_oidc_authentication_applications" ADD CONSTRAINT "tenant_platform_oidc_authentication_applications_identity_fk" FOREIGN KEY ("platform_provider_id","external_identity_id","user_id") REFERENCES "public"."platform_federated_external_identities"("platform_provider_id","id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_platform_oidc_authentication_transactions" ADD CONSTRAINT "tenant_platform_oidc_authentication_transactions_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_platform_oidc_authentication_transactions" ADD CONSTRAINT "tenant_platform_oidc_authentication_transactions_binding_fk" FOREIGN KEY ("tenant_id","binding_id","platform_provider_id") REFERENCES "public"."tenant_platform_auth_provider_bindings"("tenant_id","id","platform_provider_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_platform_oidc_authentication_transactions" ADD CONSTRAINT "tenant_platform_oidc_authentication_transactions_epoch_fk" FOREIGN KEY ("tenant_id","access_epoch_id","binding_id","platform_provider_id","access_source_id") REFERENCES "public"."tenant_platform_identity_provider_access_epochs"("tenant_id","id","binding_id","platform_provider_id","source_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_platform_oidc_authentication_transactions" ADD CONSTRAINT "tenant_platform_oidc_authentication_transactions_policy_fk" FOREIGN KEY ("platform_provider_id","provider_kind") REFERENCES "public"."platform_federated_provider_policies"("provider_id","provider_kind") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_platform_oidc_authentication_transactions" ADD CONSTRAINT "tenant_platform_oidc_authentication_transactions_configuration_fk" FOREIGN KEY ("platform_provider_id") REFERENCES "public"."platform_oidc_provider_configurations"("provider_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_platform_oidc_authentication_transactions" ADD CONSTRAINT "tenant_platform_oidc_authentication_transactions_keyring_fk" FOREIGN KEY ("verifier_key_version") REFERENCES "public"."identity_keyring_versions"("key_version") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_post_primary_platform_federated_evidence" ADD CONSTRAINT "tenant_post_primary_platform_federated_evidence_continuation_fk" FOREIGN KEY ("tenant_id","continuation_id","user_id") REFERENCES "public"."tenant_post_primary_continuations"("tenant_id","id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_post_primary_platform_federated_evidence" ADD CONSTRAINT "tenant_post_primary_platform_federated_evidence_identity_fk" FOREIGN KEY ("platform_provider_id","external_identity_id","user_id") REFERENCES "public"."platform_federated_external_identities"("platform_provider_id","id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_post_primary_platform_federated_provenance" ADD CONSTRAINT "tenant_post_primary_platform_federated_provenance_source_session_id_auth_sessions_id_fk" FOREIGN KEY ("source_session_id") REFERENCES "public"."auth_sessions"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_post_primary_platform_federated_provenance" ADD CONSTRAINT "tenant_post_primary_platform_federated_provenance_continuation_fk" FOREIGN KEY ("tenant_id","continuation_id","user_id","platform_provider_id","binding_id","external_identity_id") REFERENCES "public"."tenant_post_primary_continuations"("tenant_id","id","user_id","platform_provider_id","binding_id","external_identity_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_post_primary_platform_federated_provenance" ADD CONSTRAINT "tenant_post_primary_platform_federated_provenance_identity_fk" FOREIGN KEY ("platform_provider_id","external_identity_id","user_id") REFERENCES "public"."platform_federated_external_identities"("platform_provider_id","id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_post_primary_platform_federated_provenance" ADD CONSTRAINT "tenant_post_primary_platform_federated_provenance_binding_fk" FOREIGN KEY ("tenant_id","binding_id","platform_provider_id") REFERENCES "public"."tenant_platform_auth_provider_bindings"("tenant_id","id","platform_provider_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_post_primary_platform_federated_provenance" ADD CONSTRAINT "tenant_post_primary_platform_federated_provenance_access_grant_fk" FOREIGN KEY ("tenant_id","access_grant_id","platform_provider_id","binding_id","access_epoch_id","access_source_id","external_identity_id","membership_id","user_id") REFERENCES "public"."tenant_platform_federated_provider_access_grants"("tenant_id","id","platform_provider_id","binding_id","access_epoch_id","source_id","external_identity_id","membership_id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
CREATE INDEX "tenant_post_primary_passkey_provenance_credential_idx" ON "tenant_post_primary_passkey_provenance" USING btree ("tenant_id","user_id","credential_id","continuation_id");--> statement-breakpoint
CREATE INDEX "tenant_post_primary_passkey_provenance_source_session_idx" ON "tenant_post_primary_passkey_provenance" USING btree ("tenant_id","source_session_id","continuation_id") WHERE "tenant_post_primary_passkey_provenance"."origin" = 'session_revalidation';--> statement-breakpoint
CREATE UNIQUE INDEX "platform_federated_external_identities_live_provider_user_key" ON "platform_federated_external_identities" USING btree ("platform_provider_id","user_id") WHERE "platform_federated_external_identities"."retired_at" is null;--> statement-breakpoint
CREATE INDEX "tenant_mfa_authority_platform_federated_evidence_anchor_idx" ON "tenant_mfa_authority_platform_federated_evidence" USING btree ("tenant_id","anchor_id","authenticated_at","id");--> statement-breakpoint
CREATE UNIQUE INDEX "tenant_platform_federated_provider_access_grants_live_binding_member_key" ON "tenant_platform_federated_provider_access_grants" USING btree ("tenant_id","binding_id","membership_id") WHERE "tenant_platform_federated_provider_access_grants"."ended_at" is null;--> statement-breakpoint
CREATE UNIQUE INDEX "tenant_platform_federated_provider_profile_contributions_live_grant_key" ON "tenant_platform_federated_provider_profile_contributions" USING btree ("tenant_id","access_grant_id") WHERE "tenant_platform_federated_provider_profile_contributions"."retired_at" is null;--> statement-breakpoint
CREATE UNIQUE INDEX "tenant_platform_oidc_authentication_transactions_live_browser_key" ON "tenant_platform_oidc_authentication_transactions" USING btree ("browser_digest") WHERE "tenant_platform_oidc_authentication_transactions"."state" in ('pending', 'claimed');--> statement-breakpoint
CREATE INDEX "tenant_platform_oidc_authentication_transactions_expiry_idx" ON "tenant_platform_oidc_authentication_transactions" USING btree ("state","expires_at","transaction_id");--> statement-breakpoint
ALTER TABLE "tenant_post_primary_continuations" ADD CONSTRAINT "tenant_post_primary_continuations_platform_binding_fk" FOREIGN KEY ("tenant_id","binding_id","platform_provider_id") REFERENCES "public"."tenant_platform_auth_provider_bindings"("tenant_id","id","platform_provider_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "auth_sessions" ADD CONSTRAINT "auth_sessions_live_expiry_precision_check" CHECK ("auth_sessions"."revoked_at" is not null
        or (date_trunc('milliseconds', "auth_sessions"."idle_expires_at") = "auth_sessions"."idle_expires_at"
          and date_trunc('milliseconds', "auth_sessions"."absolute_expires_at") = "auth_sessions"."absolute_expires_at"));--> statement-breakpoint
ALTER TABLE "auth_session_mfa_states" ADD CONSTRAINT "auth_session_mfa_states_primary_kind_check" CHECK ("auth_session_mfa_states"."primary_kind" in (
        'local_credential', 'passkey', 'tenant_provider', 'tenant_platform_provider'
      ));--> statement-breakpoint
ALTER TABLE "tenant_mfa_step_up_challenges" ADD CONSTRAINT "tenant_mfa_step_up_challenges_claimed_factor_check" CHECK ("tenant_mfa_step_up_challenges"."claimed_factor_kind" is null
        or ("tenant_mfa_step_up_challenges"."claimed_factor_kind" in ('totp', 'recovery_code')
          and "tenant_mfa_step_up_challenges"."claimed_factor_kind" = any("tenant_mfa_step_up_challenges"."allowed_factors")));--> statement-breakpoint
UPDATE ONLY "tenant_mfa_step_up_challenges" AS "challenge"
SET "state" = 'expired',
    "version" = "challenge"."version" + 1,
    "failure_reason" = 'factor_selector_unavailable',
    "failed_at" = greatest(transaction_timestamp(),"challenge"."claimed_at")
WHERE "challenge"."state" = 'claimed'
  AND "challenge"."claimed_factor_kind" IS NULL;--> statement-breakpoint
ALTER TABLE "tenant_mfa_step_up_challenges" ADD CONSTRAINT "tenant_mfa_step_up_challenges_claimed_factor_live_check" CHECK ("tenant_mfa_step_up_challenges"."state" <> 'claimed' or "tenant_mfa_step_up_challenges"."claimed_factor_kind" is not null);--> statement-breakpoint
ALTER TABLE "tenant_mfa_step_up_challenges" ADD CONSTRAINT "tenant_mfa_step_up_challenges_lifecycle_check" CHECK ((("tenant_mfa_step_up_challenges"."state" = 'pending'
          and "tenant_mfa_step_up_challenges"."version" = 1
          and "tenant_mfa_step_up_challenges"."claimed_factor_kind" is null
          and "tenant_mfa_step_up_challenges"."claimed_at" is null
          and "tenant_mfa_step_up_challenges"."completed_at" is null
          and "tenant_mfa_step_up_challenges"."failed_at" is null
          and "tenant_mfa_step_up_challenges"."failure_reason" is null
          and "tenant_mfa_step_up_challenges"."completion_request_digest" is null
          and "tenant_mfa_step_up_challenges"."result_snapshot" is null)
        or ("tenant_mfa_step_up_challenges"."state" = 'claimed'
          and "tenant_mfa_step_up_challenges"."version" >= 2
          and "tenant_mfa_step_up_challenges"."claimed_at" is not null
          and "tenant_mfa_step_up_challenges"."completed_at" is null
          and "tenant_mfa_step_up_challenges"."failed_at" is null
          and "tenant_mfa_step_up_challenges"."failure_reason" is null
          and "tenant_mfa_step_up_challenges"."completion_request_digest" is null
          and "tenant_mfa_step_up_challenges"."result_snapshot" is null)
        or ("tenant_mfa_step_up_challenges"."state" = 'completed'
          and "tenant_mfa_step_up_challenges"."version" >= 3
          and "tenant_mfa_step_up_challenges"."claimed_at" is not null
          and "tenant_mfa_step_up_challenges"."completed_at" is not null
          and "tenant_mfa_step_up_challenges"."failed_at" is null
          and "tenant_mfa_step_up_challenges"."failure_reason" is null
          and "tenant_mfa_step_up_challenges"."completion_request_digest" is not null
          and "tenant_mfa_step_up_challenges"."result_snapshot" is not null)
        or ("tenant_mfa_step_up_challenges"."state" in ('failed', 'expired')
          and "tenant_mfa_step_up_challenges"."version" >= 3
          and "tenant_mfa_step_up_challenges"."claimed_at" is not null
          and "tenant_mfa_step_up_challenges"."completed_at" is null
          and "tenant_mfa_step_up_challenges"."failed_at" is not null
          and "tenant_mfa_step_up_challenges"."failure_reason" in (
            'factor_rejected', 'expired', 'factor_selector_unavailable'
          )
          and "tenant_mfa_step_up_challenges"."completion_request_digest" is null
          and "tenant_mfa_step_up_challenges"."result_snapshot" is null)));--> statement-breakpoint
ALTER TABLE "tenant_post_primary_continuations" ADD CONSTRAINT "tenant_post_primary_continuations_pending_expiry_precision_check" CHECK ("tenant_post_primary_continuations"."state" <> 'pending'
        or date_trunc('milliseconds', "tenant_post_primary_continuations"."expires_at") = "tenant_post_primary_continuations"."expires_at");--> statement-breakpoint
ALTER TABLE "tenant_post_primary_continuations" ADD CONSTRAINT "tenant_post_primary_continuations_primary_check" CHECK (("tenant_post_primary_continuations"."primary_kind" = 'local_credential'
          and "tenant_post_primary_continuations"."local_credential_id" is not null
          and "tenant_post_primary_continuations"."passkey_credential_id" is null
          and "tenant_post_primary_continuations"."provider_id" is null and "tenant_post_primary_continuations"."platform_provider_id" is null
          and "tenant_post_primary_continuations"."binding_id" is null
          and "tenant_post_primary_continuations"."provider_kind" is null
          and "tenant_post_primary_continuations"."external_identity_id" is null)
        or ("tenant_post_primary_continuations"."primary_kind" = 'passkey'
          and "tenant_post_primary_continuations"."local_credential_id" is null
          and "tenant_post_primary_continuations"."passkey_credential_id" is not null
          and "tenant_post_primary_continuations"."provider_id" is null and "tenant_post_primary_continuations"."platform_provider_id" is null
          and "tenant_post_primary_continuations"."binding_id" is null
          and "tenant_post_primary_continuations"."provider_kind" is null
          and "tenant_post_primary_continuations"."external_identity_id" is null)
        or ("tenant_post_primary_continuations"."primary_kind" = 'tenant_provider'
          and "tenant_post_primary_continuations"."local_credential_id" is null
          and "tenant_post_primary_continuations"."passkey_credential_id" is null
          and "tenant_post_primary_continuations"."provider_id" is not null and "tenant_post_primary_continuations"."platform_provider_id" is null
          and "tenant_post_primary_continuations"."binding_id" is not null
          and "tenant_post_primary_continuations"."provider_kind" in ('oidc', 'saml')
          and "tenant_post_primary_continuations"."external_identity_id" is not null)
        or ("tenant_post_primary_continuations"."primary_kind" = 'tenant_platform_provider'
          and "tenant_post_primary_continuations"."local_credential_id" is null
          and "tenant_post_primary_continuations"."passkey_credential_id" is null
          and "tenant_post_primary_continuations"."provider_id" is null and "tenant_post_primary_continuations"."platform_provider_id" is not null
          and "tenant_post_primary_continuations"."binding_id" is not null
          and "tenant_post_primary_continuations"."provider_kind" = 'oidc'
          and "tenant_post_primary_continuations"."external_identity_id" is not null));--> statement-breakpoint
ALTER TABLE "tenant_post_primary_continuations" ADD CONSTRAINT "tenant_post_primary_continuations_lifecycle_check" CHECK ((("tenant_post_primary_continuations"."state" = 'pending'
          and "tenant_post_primary_continuations"."version" >= 1
          and "tenant_post_primary_continuations"."consumed_at" is null
          and "tenant_post_primary_continuations"."revoked_at" is null
          and "tenant_post_primary_continuations"."revoke_reason" is null)
        or ("tenant_post_primary_continuations"."state" = 'consumed'
          and "tenant_post_primary_continuations"."version" >= 2
          and "tenant_post_primary_continuations"."consumed_at" is not null
          and "tenant_post_primary_continuations"."revoked_at" is null
          and "tenant_post_primary_continuations"."revoke_reason" is null)
        or ("tenant_post_primary_continuations"."state" in ('revoked', 'expired')
          and "tenant_post_primary_continuations"."version" >= 2
          and "tenant_post_primary_continuations"."consumed_at" is null
          and "tenant_post_primary_continuations"."revoked_at" is not null
          and "tenant_post_primary_continuations"."revoke_reason" is not null
          and btrim("tenant_post_primary_continuations"."revoke_reason") <> ''
          and char_length("tenant_post_primary_continuations"."revoke_reason") <= 500
          and "tenant_post_primary_continuations"."revoke_reason" !~ '[[:cntrl:]]')));--> statement-breakpoint
ALTER TABLE "tenant_webauthn_credentials" ADD CONSTRAINT "tenant_webauthn_credentials_timestamps_check" CHECK ("tenant_webauthn_credentials"."version" between 1 and 9007199254740991
        and "tenant_webauthn_credentials"."security_revision" between 1 and 9007199254740991
        and "tenant_webauthn_credentials"."security_revision" <= "tenant_webauthn_credentials"."version"
        and "tenant_webauthn_credentials"."updated_at" >= "tenant_webauthn_credentials"."created_at"
        and ("tenant_webauthn_credentials"."last_used_at" is null
          or ("tenant_webauthn_credentials"."last_used_at" >= "tenant_webauthn_credentials"."created_at"
            and "tenant_webauthn_credentials"."updated_at" >= "tenant_webauthn_credentials"."last_used_at"))
        and ("tenant_webauthn_credentials"."revoked_at" is null or "tenant_webauthn_credentials"."updated_at" >= "tenant_webauthn_credentials"."revoked_at"));--> statement-breakpoint
ALTER TABLE "platform_federated_provider_policies" ADD CONSTRAINT "platform_federated_provider_policies_login_check" CHECK (not "platform_federated_provider_policies"."platform_login_enabled");--> statement-breakpoint
ALTER TABLE "platform_oidc_provider_configurations" ADD CONSTRAINT "platform_oidc_provider_configurations_text_check" CHECK ("platform_oidc_provider_configurations"."issuer" = btrim("platform_oidc_provider_configurations"."issuer")
        and "platform_oidc_provider_configurations"."issuer" ~ '^https://[^/?#@]+[^#?]*$'
        and char_length("platform_oidc_provider_configurations"."issuer") between 1 and 4096
        and octet_length(convert_to("platform_oidc_provider_configurations"."client_id", 'UTF8')) between 1 and 512
        and "platform_oidc_provider_configurations"."client_id" = btrim("platform_oidc_provider_configurations"."client_id")
        and "platform_oidc_provider_configurations"."redirect_uri" ~ '^https://[^/?#@]+'
        and "platform_oidc_provider_configurations"."tenant_redirect_uri" ~ '^https://[^/?#@]+/api/v1/auth/federated/oidc/callback$'
        and "platform_oidc_provider_configurations"."post_logout_redirect_uri" ~ '^https://[^/?#@]+'
        and char_length("platform_oidc_provider_configurations"."redirect_uri") between 1 and 4096
        and char_length("platform_oidc_provider_configurations"."tenant_redirect_uri") between 1 and 4096
        and char_length("platform_oidc_provider_configurations"."post_logout_redirect_uri") between 1 and 4096
        and "platform_oidc_provider_configurations"."issuer" !~ '[[:cntrl:]]'
        and "platform_oidc_provider_configurations"."client_id" !~ '[[:cntrl:]]'
        and "platform_oidc_provider_configurations"."redirect_uri" !~ '[[:cntrl:]]'
        and "platform_oidc_provider_configurations"."tenant_redirect_uri" !~ '[[:cntrl:]]'
        and "platform_oidc_provider_configurations"."post_logout_redirect_uri" !~ '[[:cntrl:]]');--> statement-breakpoint
ALTER TABLE "tenant_platform_auth_provider_bindings" ADD CONSTRAINT "tenant_platform_auth_provider_bindings_admission_check" CHECK ("tenant_platform_auth_provider_bindings"."jit_mode" in ('disabled', 'create')
        and "tenant_platform_auth_provider_bindings"."no_match_policy" in ('deny', 'provider_access_only'));--> statement-breakpoint
ALTER TABLE "tenant_platform_auth_provider_bindings" ADD CONSTRAINT "tenant_platform_auth_provider_bindings_activation_check" CHECK ("tenant_platform_auth_provider_bindings"."enabled" = ("tenant_platform_auth_provider_bindings"."current_access_epoch_id" is not null));
