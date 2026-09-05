CREATE TABLE "platform_auth_providers" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"key" text NOT NULL,
	"display_name" text NOT NULL,
	"description" text DEFAULT '' NOT NULL,
	"kind" "auth_provider_kind" NOT NULL,
	"enabled" boolean DEFAULT false NOT NULL,
	"created_by_user_id" uuid NOT NULL,
	"updated_by_user_id" uuid NOT NULL,
	"archived_at" timestamp with time zone,
	"archived_by_user_id" uuid,
	"archive_reason" text,
	"version" bigint DEFAULT 1 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "platform_auth_providers_id_kind_key" UNIQUE("id","kind"),
	CONSTRAINT "platform_auth_providers_key_key" UNIQUE("key"),
	CONSTRAINT "platform_auth_providers_id_uuidv7_check" CHECK ((uuid_extract_version("platform_auth_providers"."id") = 7) is true),
	CONSTRAINT "platform_auth_providers_kind_check" CHECK ("platform_auth_providers"."kind" in ('oidc', 'saml')),
	CONSTRAINT "platform_auth_providers_key_check" CHECK ("platform_auth_providers"."key" = lower(btrim("platform_auth_providers"."key"))
        and "platform_auth_providers"."key" ~ '^[a-z][a-z0-9_-]{2,63}$'),
	CONSTRAINT "platform_auth_providers_display_name_check" CHECK (btrim("platform_auth_providers"."display_name") <> ''
        and char_length("platform_auth_providers"."display_name") <= 120
        and "platform_auth_providers"."display_name" !~ '[[:cntrl:]]'),
	CONSTRAINT "platform_auth_providers_description_check" CHECK (char_length("platform_auth_providers"."description") <= 1000
        and "platform_auth_providers"."description" !~ '[[:cntrl:]]'),
	CONSTRAINT "platform_auth_providers_archive_check" CHECK (("platform_auth_providers"."archived_at" is null
          and "platform_auth_providers"."archived_by_user_id" is null
          and "platform_auth_providers"."archive_reason" is null)
        or ("platform_auth_providers"."archived_at" is not null
          and "platform_auth_providers"."archived_by_user_id" is not null
          and "platform_auth_providers"."archive_reason" is not null
          and not "platform_auth_providers"."enabled"
          and "platform_auth_providers"."archived_at" >= "platform_auth_providers"."created_at"
          and btrim("platform_auth_providers"."archive_reason") <> ''
          and octet_length(convert_to("platform_auth_providers"."archive_reason", 'UTF8')) <= 2048
          and "platform_auth_providers"."archive_reason" !~ '[[:cntrl:]]')),
	CONSTRAINT "platform_auth_providers_lifecycle_check" CHECK ("platform_auth_providers"."version" > 0
        and "platform_auth_providers"."updated_at" >= "platform_auth_providers"."created_at"
        and ("platform_auth_providers"."archived_at" is null or "platform_auth_providers"."updated_at" >= "platform_auth_providers"."archived_at"))
);
--> statement-breakpoint
ALTER TABLE "platform_auth_providers" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "platform_federated_provider_policies" (
	"provider_id" uuid PRIMARY KEY NOT NULL,
	"provider_kind" "auth_provider_kind" NOT NULL,
	"configuration_revision" bigint NOT NULL,
	"security_revision" bigint NOT NULL,
	"plan_revision" bigint NOT NULL,
	"assurance_policy_revision" bigint NOT NULL,
	"account_mode" text DEFAULT 'disabled' NOT NULL,
	"platform_login_enabled" boolean DEFAULT false NOT NULL,
	"enabled" boolean DEFAULT false NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "platform_federated_provider_policies_kind_key" UNIQUE("provider_id","provider_kind"),
	CONSTRAINT "platform_federated_provider_policies_kind_check" CHECK ("platform_federated_provider_policies"."provider_kind" in ('oidc', 'saml')),
	CONSTRAINT "platform_federated_provider_policies_revision_check" CHECK ("platform_federated_provider_policies"."configuration_revision" > 0
        and "platform_federated_provider_policies"."security_revision" > 0
        and "platform_federated_provider_policies"."plan_revision" > 0
        and "platform_federated_provider_policies"."assurance_policy_revision" > 0),
	CONSTRAINT "platform_federated_provider_policies_account_check" CHECK ("platform_federated_provider_policies"."account_mode" in ('disabled', 'existing_identity', 'create')),
	CONSTRAINT "platform_federated_provider_policies_login_check" CHECK (not "platform_federated_provider_policies"."platform_login_enabled" or "platform_federated_provider_policies"."enabled"),
	CONSTRAINT "platform_federated_provider_policies_timestamp_check" CHECK ("platform_federated_provider_policies"."updated_at" >= "platform_federated_provider_policies"."created_at")
);
--> statement-breakpoint
ALTER TABLE "platform_federated_provider_policies" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "platform_federated_trust_rules" (
	"id" uuid DEFAULT uuidv7() NOT NULL,
	"provider_id" uuid NOT NULL,
	"provider_kind" "auth_provider_kind" NOT NULL,
	"revision" bigint NOT NULL,
	"enabled" boolean DEFAULT false NOT NULL,
	"level" text NOT NULL,
	"exact_value" text,
	"required_values" text[] DEFAULT ARRAY[]::text[] NOT NULL,
	"maximum_authentication_age_seconds" integer NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"retired_at" timestamp with time zone,
	CONSTRAINT "platform_federated_trust_rules_pkey" PRIMARY KEY("id","revision"),
	CONSTRAINT "platform_federated_trust_rules_id_uuidv7_check" CHECK ((uuid_extract_version("platform_federated_trust_rules"."id") = 7) is true),
	CONSTRAINT "platform_federated_trust_rules_value_check" CHECK ("platform_federated_trust_rules"."provider_kind" in ('oidc','saml')
        and "platform_federated_trust_rules"."revision" > 0
        and "platform_federated_trust_rules"."level" in ('mfa','phishing_resistant')
        and "platform_federated_trust_rules"."maximum_authentication_age_seconds" between 60 and 2592000
        and cardinality("platform_federated_trust_rules"."required_values") <= 128
        and (("platform_federated_trust_rules"."provider_kind" = 'oidc'
            and ("platform_federated_trust_rules"."exact_value" is not null or cardinality("platform_federated_trust_rules"."required_values") > 0))
          or ("platform_federated_trust_rules"."provider_kind" = 'saml'
            and "platform_federated_trust_rules"."exact_value" is not null
            and cardinality("platform_federated_trust_rules"."required_values") = 0))),
	CONSTRAINT "platform_federated_trust_rules_retirement_check" CHECK ("platform_federated_trust_rules"."retired_at" is null or "platform_federated_trust_rules"."retired_at" >= "platform_federated_trust_rules"."created_at")
);
--> statement-breakpoint
ALTER TABLE "platform_federated_trust_rules" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "platform_oidc_claim_rules" (
	"provider_id" uuid NOT NULL,
	"source" text NOT NULL,
	"sequence" integer NOT NULL,
	"kind" text NOT NULL,
	"claim_name" text NOT NULL,
	"profile_field" text,
	"required" boolean DEFAULT false NOT NULL,
	CONSTRAINT "platform_oidc_claim_rules_pkey" PRIMARY KEY("provider_id","source","sequence"),
	CONSTRAINT "platform_oidc_claim_rules_claim_key" UNIQUE("provider_id","source","claim_name"),
	CONSTRAINT "platform_oidc_claim_rules_value_check" CHECK ("platform_oidc_claim_rules"."source" in ('id_token', 'userinfo')
        and "platform_oidc_claim_rules"."sequence" between 0 and 1023
        and "platform_oidc_claim_rules"."kind" in ('scalar', 'profile', 'groups', 'acr', 'amr')
        and char_length("platform_oidc_claim_rules"."claim_name") between 1 and 256
        and "platform_oidc_claim_rules"."claim_name" ~ '^[!-~]+$'
        and "platform_oidc_claim_rules"."claim_name" !~ '["\\]'
        and (("platform_oidc_claim_rules"."kind" = 'profile'
            and "platform_oidc_claim_rules"."profile_field" in ('username', 'email', 'display_name'))
          or ("platform_oidc_claim_rules"."kind" <> 'profile' and "platform_oidc_claim_rules"."profile_field" is null))
        and ("platform_oidc_claim_rules"."kind" not in ('acr', 'amr')
          or ("platform_oidc_claim_rules"."claim_name" = "platform_oidc_claim_rules"."kind" and not "platform_oidc_claim_rules"."required")))
);
--> statement-breakpoint
ALTER TABLE "platform_oidc_claim_rules" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "platform_oidc_client_secrets" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"provider_id" uuid NOT NULL,
	"revision" bigint NOT NULL,
	"key_version" integer NOT NULL,
	"nonce" "bytea" NOT NULL,
	"ciphertext" "bytea" NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"retired_at" timestamp with time zone,
	CONSTRAINT "platform_oidc_client_secrets_revision_key" UNIQUE("provider_id","revision"),
	CONSTRAINT "platform_oidc_client_secrets_id_uuidv7_check" CHECK ((uuid_extract_version("platform_oidc_client_secrets"."id") = 7) is true),
	CONSTRAINT "platform_oidc_client_secrets_envelope_check" CHECK ("platform_oidc_client_secrets"."revision" > 0 and "platform_oidc_client_secrets"."key_version" between 1 and 32767
        and octet_length("platform_oidc_client_secrets"."nonce") = 12
        and octet_length("platform_oidc_client_secrets"."ciphertext") between 17 and 8208),
	CONSTRAINT "platform_oidc_client_secrets_retirement_check" CHECK ("platform_oidc_client_secrets"."retired_at" is null or "platform_oidc_client_secrets"."retired_at" >= "platform_oidc_client_secrets"."created_at")
);
--> statement-breakpoint
ALTER TABLE "platform_oidc_client_secrets" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "platform_oidc_discovery_snapshots" (
	"provider_id" uuid NOT NULL,
	"revision" bigint NOT NULL,
	"issuer" text NOT NULL,
	"document" "bytea" NOT NULL,
	"document_digest" "bytea" NOT NULL,
	"retrieved_at" timestamp with time zone NOT NULL,
	"fresh_until" timestamp with time zone NOT NULL,
	"cacheable" boolean NOT NULL,
	"must_revalidate" boolean NOT NULL,
	"client_authentication" text NOT NULL,
	"signing_algorithms" text[] NOT NULL,
	CONSTRAINT "platform_oidc_discovery_snapshots_pkey" PRIMARY KEY("provider_id","revision"),
	CONSTRAINT "platform_oidc_discovery_snapshots_value_check" CHECK ("platform_oidc_discovery_snapshots"."revision" > 0
        and octet_length("platform_oidc_discovery_snapshots"."document") between 2 and 1048576
        and octet_length("platform_oidc_discovery_snapshots"."document_digest") = 32
        and "platform_oidc_discovery_snapshots"."fresh_until" between "platform_oidc_discovery_snapshots"."retrieved_at" and "platform_oidc_discovery_snapshots"."retrieved_at" + interval '7 days'
        and ("platform_oidc_discovery_snapshots"."cacheable" or ("platform_oidc_discovery_snapshots"."must_revalidate" and "platform_oidc_discovery_snapshots"."fresh_until" = "platform_oidc_discovery_snapshots"."retrieved_at"))
        and "platform_oidc_discovery_snapshots"."client_authentication" in ('client_secret_basic', 'client_secret_post')
        and cardinality("platform_oidc_discovery_snapshots"."signing_algorithms") between 1 and 16)
);
--> statement-breakpoint
ALTER TABLE "platform_oidc_discovery_snapshots" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "platform_oidc_jwks_snapshots" (
	"provider_id" uuid NOT NULL,
	"revision" bigint NOT NULL,
	"document" "bytea" NOT NULL,
	"document_digest" "bytea" NOT NULL,
	"retrieved_at" timestamp with time zone NOT NULL,
	"fresh_until" timestamp with time zone NOT NULL,
	"cacheable" boolean NOT NULL,
	"must_revalidate" boolean NOT NULL,
	CONSTRAINT "platform_oidc_jwks_snapshots_pkey" PRIMARY KEY("provider_id","revision"),
	CONSTRAINT "platform_oidc_jwks_snapshots_value_check" CHECK ("platform_oidc_jwks_snapshots"."revision" > 0
        and octet_length("platform_oidc_jwks_snapshots"."document") between 2 and 1048576
        and octet_length("platform_oidc_jwks_snapshots"."document_digest") = 32
        and "platform_oidc_jwks_snapshots"."fresh_until" between "platform_oidc_jwks_snapshots"."retrieved_at" and "platform_oidc_jwks_snapshots"."retrieved_at" + interval '7 days'
        and ("platform_oidc_jwks_snapshots"."cacheable" or ("platform_oidc_jwks_snapshots"."must_revalidate" and "platform_oidc_jwks_snapshots"."fresh_until" = "platform_oidc_jwks_snapshots"."retrieved_at")))
);
--> statement-breakpoint
ALTER TABLE "platform_oidc_jwks_snapshots" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "platform_oidc_provider_configurations" (
	"provider_id" uuid PRIMARY KEY NOT NULL,
	"provider_kind" "auth_provider_kind" DEFAULT 'oidc' NOT NULL,
	"issuer" text NOT NULL,
	"client_id" text NOT NULL,
	"redirect_uri" text NOT NULL,
	"post_logout_redirect_uri" text NOT NULL,
	"extra_scopes" text[] DEFAULT ARRAY[]::text[] NOT NULL,
	"allow_refresh_token" boolean DEFAULT false NOT NULL,
	"use_user_info" boolean DEFAULT false NOT NULL,
	"client_secret_revision" bigint NOT NULL,
	"discovery_revision" bigint NOT NULL,
	"jwks_revision" bigint NOT NULL,
	"version" bigint DEFAULT 1 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "platform_oidc_provider_configurations_kind_check" CHECK ("platform_oidc_provider_configurations"."provider_kind" = 'oidc'),
	CONSTRAINT "platform_oidc_provider_configurations_revision_check" CHECK ("platform_oidc_provider_configurations"."client_secret_revision" > 0
        and "platform_oidc_provider_configurations"."discovery_revision" > 0
        and "platform_oidc_provider_configurations"."jwks_revision" > 0
        and "platform_oidc_provider_configurations"."version" > 0),
	CONSTRAINT "platform_oidc_provider_configurations_text_check" CHECK (char_length("platform_oidc_provider_configurations"."issuer") between 1 and 4096
        and octet_length(convert_to("platform_oidc_provider_configurations"."client_id", 'UTF8')) between 1 and 512
        and char_length("platform_oidc_provider_configurations"."redirect_uri") between 1 and 4096
        and char_length("platform_oidc_provider_configurations"."post_logout_redirect_uri") between 1 and 4096
        and "platform_oidc_provider_configurations"."issuer" !~ '[[:cntrl:]]'
        and "platform_oidc_provider_configurations"."client_id" !~ '[[:cntrl:]]'
        and "platform_oidc_provider_configurations"."redirect_uri" !~ '[[:cntrl:]]'
        and "platform_oidc_provider_configurations"."post_logout_redirect_uri" !~ '[[:cntrl:]]'),
	CONSTRAINT "platform_oidc_provider_configurations_scope_check" CHECK (cardinality("platform_oidc_provider_configurations"."extra_scopes") <= 32
        and array_position("platform_oidc_provider_configurations"."extra_scopes", null) is null),
	CONSTRAINT "platform_oidc_provider_configurations_timestamp_check" CHECK ("platform_oidc_provider_configurations"."updated_at" >= "platform_oidc_provider_configurations"."created_at")
);
--> statement-breakpoint
ALTER TABLE "platform_oidc_provider_configurations" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "platform_saml_attribute_rules" (
	"provider_id" uuid NOT NULL,
	"sequence" integer NOT NULL,
	"kind" text NOT NULL,
	"attribute_name" text NOT NULL,
	"attribute_name_format" text NOT NULL,
	"profile_field" text,
	"required" boolean DEFAULT false NOT NULL,
	CONSTRAINT "platform_saml_attribute_rules_pkey" PRIMARY KEY("provider_id","sequence"),
	CONSTRAINT "platform_saml_attribute_rules_value_check" CHECK ("platform_saml_attribute_rules"."sequence" between 0 and 1023
        and "platform_saml_attribute_rules"."kind" in ('scalar','profile','groups')
        and octet_length(convert_to("platform_saml_attribute_rules"."attribute_name", 'UTF8')) between 1 and 512
        and octet_length(convert_to("platform_saml_attribute_rules"."attribute_name_format", 'UTF8')) between 1 and 512
        and "platform_saml_attribute_rules"."attribute_name" !~ '[[:cntrl:]]'
        and "platform_saml_attribute_rules"."attribute_name_format" !~ '[[:cntrl:]]'
        and (("platform_saml_attribute_rules"."kind" = 'profile'
            and "platform_saml_attribute_rules"."profile_field" in ('username','email','display_name'))
          or ("platform_saml_attribute_rules"."kind" <> 'profile' and "platform_saml_attribute_rules"."profile_field" is null)))
);
--> statement-breakpoint
ALTER TABLE "platform_saml_attribute_rules" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "platform_saml_metadata_snapshots" (
	"provider_id" uuid NOT NULL,
	"revision" bigint NOT NULL,
	"document" "bytea" NOT NULL,
	"document_digest" "bytea" NOT NULL,
	"retrieved_at" timestamp with time zone NOT NULL,
	"maximum_valid_until" timestamp with time zone NOT NULL,
	CONSTRAINT "platform_saml_metadata_snapshots_pkey" PRIMARY KEY("provider_id","revision"),
	CONSTRAINT "platform_saml_metadata_snapshots_value_check" CHECK ("platform_saml_metadata_snapshots"."revision" > 0
        and octet_length("platform_saml_metadata_snapshots"."document") between 1 and 524288
        and octet_length("platform_saml_metadata_snapshots"."document_digest") = 32
        and "platform_saml_metadata_snapshots"."maximum_valid_until" > "platform_saml_metadata_snapshots"."retrieved_at")
);
--> statement-breakpoint
ALTER TABLE "platform_saml_metadata_snapshots" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "platform_saml_provider_configurations" (
	"provider_id" uuid PRIMARY KEY NOT NULL,
	"provider_kind" "auth_provider_kind" DEFAULT 'saml' NOT NULL,
	"expected_entity_id" text NOT NULL,
	"sp_entity_id" text NOT NULL,
	"acs_url" text NOT NULL,
	"sp_key_revision" bigint NOT NULL,
	"metadata_revision" bigint NOT NULL,
	"redirect_signature_algorithm" text NOT NULL,
	"signature_policy" text NOT NULL,
	"encryption_policy" text NOT NULL,
	"decryption_key_versions" integer[] NOT NULL,
	"requested_authn_contexts" text[] NOT NULL,
	"subject_source" text NOT NULL,
	"subject_attribute_name" text,
	"subject_attribute_name_format" text,
	"clock_skew_nanoseconds" bigint NOT NULL,
	"max_authentication_age_nanoseconds" bigint NOT NULL,
	"version" bigint DEFAULT 1 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "platform_saml_provider_configurations_kind_check" CHECK ("platform_saml_provider_configurations"."provider_kind" = 'saml'),
	CONSTRAINT "platform_saml_provider_configurations_revision_check" CHECK ("platform_saml_provider_configurations"."sp_key_revision" > 0
        and "platform_saml_provider_configurations"."metadata_revision" > 0
        and "platform_saml_provider_configurations"."version" > 0),
	CONSTRAINT "platform_saml_provider_configurations_policy_check" CHECK ("platform_saml_provider_configurations"."redirect_signature_algorithm" in (
          'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
          'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384',
          'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512',
          'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256',
          'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384',
          'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512')
        and "platform_saml_provider_configurations"."signature_policy" in ('signed_assertion','signed_response','both')
        and "platform_saml_provider_configurations"."encryption_policy" in ('disabled','optional','required')
        and (("platform_saml_provider_configurations"."encryption_policy" = 'disabled'
            and cardinality("platform_saml_provider_configurations"."decryption_key_versions") = 0)
          or ("platform_saml_provider_configurations"."encryption_policy" in ('optional','required')
            and cardinality("platform_saml_provider_configurations"."decryption_key_versions") between 1 and 8))
        and array_position("platform_saml_provider_configurations"."decryption_key_versions", null) is null
        and cardinality("platform_saml_provider_configurations"."requested_authn_contexts") between 1 and 32
        and array_position("platform_saml_provider_configurations"."requested_authn_contexts", null) is null
        and "platform_saml_provider_configurations"."clock_skew_nanoseconds" between 0 and 300000000000
        and "platform_saml_provider_configurations"."max_authentication_age_nanoseconds" between 60000000000 and 86400000000000),
	CONSTRAINT "platform_saml_provider_configurations_subject_check" CHECK (("platform_saml_provider_configurations"."subject_source" = 'persistent_nameid'
          and "platform_saml_provider_configurations"."subject_attribute_name" is null
          and "platform_saml_provider_configurations"."subject_attribute_name_format" is null)
        or ("platform_saml_provider_configurations"."subject_source" = 'immutable_attribute'
          and octet_length(convert_to("platform_saml_provider_configurations"."subject_attribute_name", 'UTF8')) between 1 and 512
          and octet_length(convert_to("platform_saml_provider_configurations"."subject_attribute_name_format", 'UTF8')) between 1 and 512)),
	CONSTRAINT "platform_saml_provider_configurations_text_check" CHECK (octet_length(convert_to("platform_saml_provider_configurations"."expected_entity_id", 'UTF8')) between 1 and 2048
        and octet_length(convert_to("platform_saml_provider_configurations"."sp_entity_id", 'UTF8')) between 1 and 2048
        and octet_length(convert_to("platform_saml_provider_configurations"."acs_url", 'UTF8')) between 1 and 4096
        and "platform_saml_provider_configurations"."expected_entity_id" !~ '[[:cntrl:]]'
        and "platform_saml_provider_configurations"."sp_entity_id" !~ '[[:cntrl:]]'
        and "platform_saml_provider_configurations"."acs_url" !~ '[[:cntrl:]]'),
	CONSTRAINT "platform_saml_provider_configurations_timestamp_check" CHECK ("platform_saml_provider_configurations"."updated_at" >= "platform_saml_provider_configurations"."created_at")
);
--> statement-breakpoint
ALTER TABLE "platform_saml_provider_configurations" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "platform_saml_sp_certificates" (
	"key_id" uuid NOT NULL,
	"sequence" integer NOT NULL,
	"certificate_der" "bytea" NOT NULL,
	CONSTRAINT "platform_saml_sp_certificates_pkey" PRIMARY KEY("key_id","sequence"),
	CONSTRAINT "platform_saml_sp_certificates_value_key" UNIQUE("key_id","certificate_der"),
	CONSTRAINT "platform_saml_sp_certificates_value_check" CHECK ("platform_saml_sp_certificates"."sequence" between 0 and 7
        and octet_length("platform_saml_sp_certificates"."certificate_der") between 1 and 65536)
);
--> statement-breakpoint
ALTER TABLE "platform_saml_sp_certificates" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "platform_saml_sp_keys" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"provider_id" uuid NOT NULL,
	"revision" bigint NOT NULL,
	"key_version" integer NOT NULL,
	"ciphertext" "bytea" NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"retired_at" timestamp with time zone,
	CONSTRAINT "platform_saml_sp_keys_revision_key" UNIQUE("provider_id","revision"),
	CONSTRAINT "platform_saml_sp_keys_id_uuidv7_check" CHECK ((uuid_extract_version("platform_saml_sp_keys"."id") = 7) is true),
	CONSTRAINT "platform_saml_sp_keys_envelope_check" CHECK ("platform_saml_sp_keys"."revision" > 0 and "platform_saml_sp_keys"."key_version" between 1 and 32767
        and octet_length("platform_saml_sp_keys"."ciphertext") between 17 and 131072),
	CONSTRAINT "platform_saml_sp_keys_retirement_check" CHECK ("platform_saml_sp_keys"."retired_at" is null or "platform_saml_sp_keys"."retired_at" >= "platform_saml_sp_keys"."created_at")
);
--> statement-breakpoint
ALTER TABLE "platform_saml_sp_keys" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "platform_auth_providers" ADD CONSTRAINT "platform_auth_providers_created_by_user_id_users_id_fk" FOREIGN KEY ("created_by_user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "platform_auth_providers" ADD CONSTRAINT "platform_auth_providers_updated_by_user_id_users_id_fk" FOREIGN KEY ("updated_by_user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "platform_auth_providers" ADD CONSTRAINT "platform_auth_providers_archived_by_user_id_users_id_fk" FOREIGN KEY ("archived_by_user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "platform_federated_provider_policies" ADD CONSTRAINT "platform_federated_provider_policies_provider_fk" FOREIGN KEY ("provider_id","provider_kind") REFERENCES "public"."platform_auth_providers"("id","kind") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_federated_trust_rules" ADD CONSTRAINT "platform_federated_trust_rules_policy_fk" FOREIGN KEY ("provider_id","provider_kind") REFERENCES "public"."platform_federated_provider_policies"("provider_id","provider_kind") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_oidc_claim_rules" ADD CONSTRAINT "platform_oidc_claim_rules_configuration_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."platform_oidc_provider_configurations"("provider_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_oidc_client_secrets" ADD CONSTRAINT "platform_oidc_client_secrets_configuration_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."platform_oidc_provider_configurations"("provider_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_oidc_client_secrets" ADD CONSTRAINT "platform_oidc_client_secrets_keyring_fk" FOREIGN KEY ("key_version") REFERENCES "public"."identity_keyring_versions"("key_version") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_oidc_discovery_snapshots" ADD CONSTRAINT "platform_oidc_discovery_snapshots_configuration_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."platform_oidc_provider_configurations"("provider_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_oidc_jwks_snapshots" ADD CONSTRAINT "platform_oidc_jwks_snapshots_configuration_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."platform_oidc_provider_configurations"("provider_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_oidc_provider_configurations" ADD CONSTRAINT "platform_oidc_provider_configurations_provider_fk" FOREIGN KEY ("provider_id","provider_kind") REFERENCES "public"."platform_auth_providers"("id","kind") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_saml_attribute_rules" ADD CONSTRAINT "platform_saml_attribute_rules_configuration_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."platform_saml_provider_configurations"("provider_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_saml_metadata_snapshots" ADD CONSTRAINT "platform_saml_metadata_snapshots_configuration_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."platform_saml_provider_configurations"("provider_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_saml_provider_configurations" ADD CONSTRAINT "platform_saml_provider_configurations_provider_fk" FOREIGN KEY ("provider_id","provider_kind") REFERENCES "public"."platform_auth_providers"("id","kind") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_saml_sp_certificates" ADD CONSTRAINT "platform_saml_sp_certificates_key_fk" FOREIGN KEY ("key_id") REFERENCES "public"."platform_saml_sp_keys"("id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_saml_sp_keys" ADD CONSTRAINT "platform_saml_sp_keys_configuration_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."platform_saml_provider_configurations"("provider_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_saml_sp_keys" ADD CONSTRAINT "platform_saml_sp_keys_keyring_fk" FOREIGN KEY ("key_version") REFERENCES "public"."identity_keyring_versions"("key_version") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
CREATE INDEX "platform_auth_providers_kind_idx" ON "platform_auth_providers" USING btree ("kind","id");--> statement-breakpoint
CREATE UNIQUE INDEX "platform_auth_providers_active_display_key" ON "platform_auth_providers" USING btree ("display_name") WHERE "platform_auth_providers"."archived_at" is null;--> statement-breakpoint
CREATE UNIQUE INDEX "platform_federated_trust_rules_live_key" ON "platform_federated_trust_rules" USING btree ("id") WHERE "platform_federated_trust_rules"."retired_at" is null;--> statement-breakpoint
CREATE INDEX "platform_federated_trust_rules_provider_idx" ON "platform_federated_trust_rules" USING btree ("provider_id","id");