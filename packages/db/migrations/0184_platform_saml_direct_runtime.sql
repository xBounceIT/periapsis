-- Direct platform SAML is a distinct authority and persistence family.  No
-- table or ABI below is shared with the direct platform OIDC runtime.
ALTER TYPE public.auth_rate_limit_scope ADD VALUE IF NOT EXISTS 'platform_saml_network';
ALTER TYPE public.auth_rate_limit_scope ADD VALUE IF NOT EXISTS 'platform_saml_account';
ALTER TYPE public.auth_rate_limit_scope ADD VALUE IF NOT EXISTS 'platform_saml_provider';
--> statement-breakpoint
ALTER TABLE ONLY public.platform_federated_external_identities
  DROP CONSTRAINT platform_federated_external_identities_subject_check;
ALTER TABLE ONLY public.platform_federated_external_identities
  ADD CONSTRAINT platform_federated_external_identities_subject_check CHECK (
    provider_kind IN ('oidc','saml')
    AND subject_format = 'utf8_exact'
    AND octet_length(subject_ciphertext) BETWEEN 17 AND 4112
    AND octet_length(subject_nonce) = 12
    AND key_version BETWEEN 1 AND 32767
  );
--> statement-breakpoint
CREATE TABLE "auth_session_platform_saml_evidence" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"session_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"kind" text NOT NULL,
	"level" text NOT NULL,
	"platform_provider_id" uuid,
	"external_identity_id" uuid,
	"totp_credential_id" uuid,
	"factor_revision" bigint,
	"trust_rule_id" uuid,
	"trust_rule_revision" bigint,
	"authenticated_at" timestamp with time zone NOT NULL,
	"expires_at" timestamp with time zone,
	CONSTRAINT "auth_session_platform_saml_evidence_key" UNIQUE("session_id","id"),
	CONSTRAINT "auth_session_platform_saml_evidence_value_check" CHECK ((uuid_extract_version("auth_session_platform_saml_evidence"."id") = 7) is true
        and "auth_session_platform_saml_evidence"."level" in ('primary','mfa','phishing_resistant')
        and ("auth_session_platform_saml_evidence"."expires_at" is null or "auth_session_platform_saml_evidence"."expires_at" > "auth_session_platform_saml_evidence"."authenticated_at")
        and (("auth_session_platform_saml_evidence"."kind" = 'platform_provider' and "auth_session_platform_saml_evidence"."platform_provider_id" is not null
          and "auth_session_platform_saml_evidence"."external_identity_id" is not null and "auth_session_platform_saml_evidence"."totp_credential_id" is null
          and "auth_session_platform_saml_evidence"."factor_revision" is null)
        or ("auth_session_platform_saml_evidence"."kind" = 'totp' and "auth_session_platform_saml_evidence"."level" = 'mfa'
          and "auth_session_platform_saml_evidence"."platform_provider_id" is null and "auth_session_platform_saml_evidence"."external_identity_id" is null
          and "auth_session_platform_saml_evidence"."totp_credential_id" is not null
          and "auth_session_platform_saml_evidence"."factor_revision" between 1 and 9007199254740991
          and "auth_session_platform_saml_evidence"."trust_rule_id" is null and "auth_session_platform_saml_evidence"."trust_rule_revision" is null)))
);
--> statement-breakpoint
ALTER TABLE "auth_session_platform_saml_evidence" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "auth_session_platform_saml_policy_pins" (
	"session_id" uuid NOT NULL,
	"policy_kind" text NOT NULL,
	"policy_id" uuid NOT NULL,
	"policy_revision" bigint NOT NULL,
	CONSTRAINT "auth_session_platform_saml_policy_pins_pkey" PRIMARY KEY("session_id","policy_kind","policy_id"),
	CONSTRAINT "auth_session_platform_saml_policy_pins_value_check" CHECK ("auth_session_platform_saml_policy_pins"."policy_kind" in ('login','assurance','platform_floor')
        and "auth_session_platform_saml_policy_pins"."policy_revision" between 1 and 9007199254740991)
);
--> statement-breakpoint
ALTER TABLE "auth_session_platform_saml_policy_pins" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "auth_session_platform_saml_provenance" (
	"session_id" uuid PRIMARY KEY NOT NULL,
	"user_id" uuid NOT NULL,
	"authority" text DEFAULT 'direct_platform_saml' NOT NULL,
	"authentication_method" text DEFAULT 'saml' NOT NULL,
	"primary_kind" text DEFAULT 'platform_provider' NOT NULL,
	"platform_provider_id" uuid NOT NULL,
	"external_identity_id" uuid NOT NULL,
	"provider_revision" bigint NOT NULL,
	"login_policy_revision" bigint NOT NULL,
	"configuration_revision" bigint NOT NULL,
	"security_revision" bigint NOT NULL,
	"plan_revision" bigint NOT NULL,
	"assurance_policy_revision" bigint NOT NULL,
	"metadata_revision" bigint NOT NULL,
	"metadata_digest" "bytea" NOT NULL,
	"sp_key_revision" bigint NOT NULL,
	"configuration_digest" "bytea" NOT NULL,
	"user_authentication_revision" bigint NOT NULL,
	"identity_version" bigint NOT NULL,
	"alias_key_version" integer NOT NULL,
	"platform_authority_id" uuid NOT NULL,
	"platform_authority_revision" bigint NOT NULL,
	"platform_floor_policy_id" uuid NOT NULL,
	"platform_floor_policy_revision" bigint NOT NULL,
	"trust_rule_id" uuid,
	"trust_rule_revision" bigint,
	"authenticated_at" timestamp with time zone NOT NULL,
	CONSTRAINT "auth_session_platform_saml_provenance_exact_key" UNIQUE("session_id","user_id","platform_provider_id","external_identity_id"),
	CONSTRAINT "auth_session_platform_saml_provenance_value_check" CHECK ("auth_session_platform_saml_provenance"."authority" = 'direct_platform_saml'
        and "auth_session_platform_saml_provenance"."authentication_method" = 'saml' and "auth_session_platform_saml_provenance"."primary_kind" = 'platform_provider'
        and "auth_session_platform_saml_provenance"."provider_revision" between 1 and 2147483647
        and "auth_session_platform_saml_provenance"."login_policy_revision" between 1 and 9007199254740991
        and "auth_session_platform_saml_provenance"."configuration_revision" between 1 and 9007199254740991
        and "auth_session_platform_saml_provenance"."security_revision" between 1 and 9007199254740991
        and "auth_session_platform_saml_provenance"."plan_revision" between 1 and 9007199254740991
        and "auth_session_platform_saml_provenance"."assurance_policy_revision" between 1 and 9007199254740991
        and "auth_session_platform_saml_provenance"."metadata_revision" between 1 and 9007199254740991
        and octet_length("auth_session_platform_saml_provenance"."metadata_digest") = 32
        and "auth_session_platform_saml_provenance"."sp_key_revision" between 1 and 9007199254740991
        and octet_length("auth_session_platform_saml_provenance"."configuration_digest") = 32
        and "auth_session_platform_saml_provenance"."user_authentication_revision" between 1 and 9007199254740991
        and "auth_session_platform_saml_provenance"."identity_version" between 1 and 2147483647
        and "auth_session_platform_saml_provenance"."alias_key_version" between 1 and 32767
        and (uuid_extract_version("auth_session_platform_saml_provenance"."platform_authority_id") = 7) is true
        and "auth_session_platform_saml_provenance"."platform_authority_revision" between 1 and 9007199254740991
        and (uuid_extract_version("auth_session_platform_saml_provenance"."platform_floor_policy_id") = 7) is true
        and "auth_session_platform_saml_provenance"."platform_floor_policy_revision" between 1 and 9007199254740991
        and (("auth_session_platform_saml_provenance"."trust_rule_id" is null and "auth_session_platform_saml_provenance"."trust_rule_revision" is null)
          or ((uuid_extract_version("auth_session_platform_saml_provenance"."trust_rule_id") = 7) is true
            and "auth_session_platform_saml_provenance"."trust_rule_revision" between 1 and 9007199254740991)))
);
--> statement-breakpoint
ALTER TABLE "auth_session_platform_saml_provenance" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "auth_session_platform_saml_states" (
	"session_id" uuid PRIMARY KEY NOT NULL,
	"user_id" uuid NOT NULL,
	"authority" text DEFAULT 'direct_platform_saml' NOT NULL,
	"authentication_method" text DEFAULT 'saml' NOT NULL,
	"session_version" bigint NOT NULL,
	"user_authentication_revision" bigint NOT NULL,
	"recovery_restricted" boolean NOT NULL,
	"audience" text NOT NULL,
	"primary_kind" text DEFAULT 'platform_provider' NOT NULL,
	"issued_at" timestamp with time zone NOT NULL,
	CONSTRAINT "auth_session_platform_saml_states_exact_key" UNIQUE("session_id","user_id","authority","authentication_method","primary_kind"),
	CONSTRAINT "auth_session_platform_saml_states_user_key" UNIQUE("session_id","user_id"),
	CONSTRAINT "auth_session_platform_saml_states_value_check" CHECK ("auth_session_platform_saml_states"."authority" = 'direct_platform_saml'
        and "auth_session_platform_saml_states"."authentication_method" = 'saml'
        and "auth_session_platform_saml_states"."session_version" between 1 and 2147483647
        and "auth_session_platform_saml_states"."user_authentication_revision" between 1 and 9007199254740991
        and "auth_session_platform_saml_states"."primary_kind" = 'platform_provider'
        and btrim("auth_session_platform_saml_states"."audience") = "auth_session_platform_saml_states"."audience"
        and char_length("auth_session_platform_saml_states"."audience") between 1 and 256
        and "auth_session_platform_saml_states"."audience" !~ '[[:cntrl:]]')
);
--> statement-breakpoint
ALTER TABLE "auth_session_platform_saml_states" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "platform_saml_authentication_applications" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"transaction_id" "bytea" NOT NULL,
	"proof_digest" "bytea" NOT NULL,
	"platform_provider_id" uuid NOT NULL,
	"response_id_digest" "bytea" NOT NULL,
	"assertion_id_digest" "bytea" NOT NULL,
	"session_index_digest" "bytea",
	"category" text NOT NULL,
	"user_id" uuid,
	"external_identity_id" uuid,
	"session_id" uuid,
	"continuation_id" uuid,
	"request_snapshot" jsonb NOT NULL,
	"result_snapshot" jsonb NOT NULL,
	"applied_at" timestamp with time zone NOT NULL,
	"cleanup_reason" text,
	"cleaned_up_at" timestamp with time zone,
	CONSTRAINT "platform_saml_auth_applications_proof_key" UNIQUE("proof_digest"),
	CONSTRAINT "platform_saml_auth_applications_transaction_key" UNIQUE("transaction_id"),
	CONSTRAINT "platform_saml_auth_applications_response_key" UNIQUE("platform_provider_id","response_id_digest"),
	CONSTRAINT "platform_saml_auth_applications_assertion_key" UNIQUE("platform_provider_id","assertion_id_digest"),
	CONSTRAINT "platform_saml_auth_applications_value_check" CHECK ((uuid_extract_version("platform_saml_authentication_applications"."id") = 7) is true
        and octet_length("platform_saml_authentication_applications"."transaction_id") = 32
        and octet_length("platform_saml_authentication_applications"."proof_digest") = 32
        and octet_length("platform_saml_authentication_applications"."response_id_digest") = 32
        and octet_length("platform_saml_authentication_applications"."assertion_id_digest") = 32
        and ("platform_saml_authentication_applications"."session_index_digest" is null or octet_length("platform_saml_authentication_applications"."session_index_digest") = 32)
        and "platform_saml_authentication_applications"."category" in ('success','identity_collision','stale','denied')
        and jsonb_typeof("platform_saml_authentication_applications"."request_snapshot") = 'object'
        and pg_column_size("platform_saml_authentication_applications"."request_snapshot") between 2 and 2097152
        and jsonb_typeof("platform_saml_authentication_applications"."result_snapshot") = 'object'
        and pg_column_size("platform_saml_authentication_applications"."result_snapshot") between 2 and 65536
        and (("platform_saml_authentication_applications"."category" = 'success' and "platform_saml_authentication_applications"."user_id" is not null
          and "platform_saml_authentication_applications"."external_identity_id" is not null
          and (("platform_saml_authentication_applications"."session_id" is null) <> ("platform_saml_authentication_applications"."continuation_id" is null)))
        or ("platform_saml_authentication_applications"."category" <> 'success' and "platform_saml_authentication_applications"."user_id" is null
          and "platform_saml_authentication_applications"."external_identity_id" is null and "platform_saml_authentication_applications"."session_id" is null
          and "platform_saml_authentication_applications"."continuation_id" is null))
        and (("platform_saml_authentication_applications"."cleanup_reason" is null and "platform_saml_authentication_applications"."cleaned_up_at" is null)
          or ("platform_saml_authentication_applications"."category" = 'success'
            and "platform_saml_authentication_applications"."cleanup_reason" in ('credential_release_failed','protocol_failed','invalid_outcome','delivery_failed')
            and "platform_saml_authentication_applications"."cleaned_up_at" >= "platform_saml_authentication_applications"."applied_at")))
);
--> statement-breakpoint
ALTER TABLE "platform_saml_authentication_applications" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "platform_saml_authentication_transactions" (
	"transaction_id" "bytea" PRIMARY KEY NOT NULL,
	"platform_provider_id" uuid NOT NULL,
	"provider_kind" "auth_provider_kind" DEFAULT 'saml' NOT NULL,
	"protocol" text DEFAULT 'saml' NOT NULL,
	"operation_run_id" uuid NOT NULL,
	"operation_digest" "bytea" NOT NULL,
	"receipt_digest" "bytea" NOT NULL,
	"network_digest" "bytea" NOT NULL,
	"account_digest" "bytea" NOT NULL,
	"provider_digest" "bytea" NOT NULL,
	"relay_state_digest" "bytea" NOT NULL,
	"browser_digest" "bytea" NOT NULL,
	"request_id" text NOT NULL,
	"provider_revision" bigint NOT NULL,
	"login_policy_revision" bigint NOT NULL,
	"configuration_revision" bigint NOT NULL,
	"security_revision" bigint NOT NULL,
	"plan_revision" bigint NOT NULL,
	"assurance_policy_revision" bigint NOT NULL,
	"metadata_revision" bigint NOT NULL,
	"metadata_digest" "bytea" NOT NULL,
	"sp_key_revision" bigint NOT NULL,
	"configuration_digest" "bytea" NOT NULL,
	"platform_floor_policy_id" uuid NOT NULL,
	"platform_floor_policy_revision" bigint NOT NULL,
	"return_path" text NOT NULL,
	"state" text DEFAULT 'pending' NOT NULL,
	"version" bigint DEFAULT 1 NOT NULL,
	"created_at" timestamp with time zone NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"completed_at" timestamp with time zone,
	"failure_reason" text,
	CONSTRAINT "platform_saml_auth_transactions_operation_key" UNIQUE("operation_run_id"),
	CONSTRAINT "platform_saml_auth_transactions_receipt_key" UNIQUE("receipt_digest"),
	CONSTRAINT "platform_saml_auth_transactions_relay_key" UNIQUE("relay_state_digest"),
	CONSTRAINT "platform_saml_auth_transactions_request_key" UNIQUE("platform_provider_id","request_id"),
	CONSTRAINT "platform_saml_auth_transactions_exact_key" UNIQUE("transaction_id","platform_provider_id"),
	CONSTRAINT "platform_saml_auth_transactions_digest_check" CHECK (octet_length("platform_saml_authentication_transactions"."transaction_id") = 32
        and (uuid_extract_version("platform_saml_authentication_transactions"."operation_run_id") = 7) is true
        and octet_length("platform_saml_authentication_transactions"."operation_digest") = 32
        and octet_length("platform_saml_authentication_transactions"."receipt_digest") = 32
        and octet_length("platform_saml_authentication_transactions"."network_digest") = 32
        and octet_length("platform_saml_authentication_transactions"."account_digest") = 32
        and octet_length("platform_saml_authentication_transactions"."provider_digest") = 32
        and octet_length("platform_saml_authentication_transactions"."relay_state_digest") = 32
        and octet_length("platform_saml_authentication_transactions"."browser_digest") = 32
        and octet_length("platform_saml_authentication_transactions"."metadata_digest") = 32
        and octet_length("platform_saml_authentication_transactions"."configuration_digest") = 32),
	CONSTRAINT "platform_saml_auth_transactions_pin_check" CHECK ("platform_saml_authentication_transactions"."provider_kind" = 'saml' and "platform_saml_authentication_transactions"."protocol" = 'saml'
        and "platform_saml_authentication_transactions"."provider_revision" between 1 and 2147483647
        and "platform_saml_authentication_transactions"."login_policy_revision" between 1 and 9007199254740991
        and "platform_saml_authentication_transactions"."configuration_revision" between 1 and 9007199254740991
        and "platform_saml_authentication_transactions"."security_revision" between 1 and 9007199254740991
        and "platform_saml_authentication_transactions"."plan_revision" between 1 and 9007199254740991
        and "platform_saml_authentication_transactions"."assurance_policy_revision" between 1 and 9007199254740991
        and "platform_saml_authentication_transactions"."metadata_revision" between 1 and 9007199254740991
        and "platform_saml_authentication_transactions"."sp_key_revision" between 1 and 9007199254740991
        and (uuid_extract_version("platform_saml_authentication_transactions"."platform_floor_policy_id") = 7) is true
        and "platform_saml_authentication_transactions"."platform_floor_policy_revision" between 1 and 9007199254740991
        and char_length("platform_saml_authentication_transactions"."request_id") between 1 and 1024
        and "platform_saml_authentication_transactions"."request_id" !~ '[[:cntrl:]]'
        and "platform_saml_authentication_transactions"."return_path" ~ '^/[^[:cntrl:]]*$'
        and left("platform_saml_authentication_transactions"."return_path",2) <> '//'),
	CONSTRAINT "platform_saml_auth_transactions_lifecycle_check" CHECK ("platform_saml_authentication_transactions"."version" between 1 and 2147483647
        and "platform_saml_authentication_transactions"."expires_at" between "platform_saml_authentication_transactions"."created_at" + interval '1 minute'
          and "platform_saml_authentication_transactions"."created_at" + interval '15 minutes'
        and (("platform_saml_authentication_transactions"."state" = 'pending' and "platform_saml_authentication_transactions"."version" = 1
          and "platform_saml_authentication_transactions"."completed_at" is null and "platform_saml_authentication_transactions"."failure_reason" is null)
        or ("platform_saml_authentication_transactions"."state" in ('completed','failed','expired')
          and "platform_saml_authentication_transactions"."version" >= 2 and "platform_saml_authentication_transactions"."completed_at" >= "platform_saml_authentication_transactions"."created_at"
          and ("platform_saml_authentication_transactions"."state" = 'completed') = ("platform_saml_authentication_transactions"."failure_reason" is null))))
);
--> statement-breakpoint
ALTER TABLE "platform_saml_authentication_transactions" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "platform_saml_login_policies" (
	"provider_id" uuid PRIMARY KEY NOT NULL,
	"provider_kind" "auth_provider_kind" DEFAULT 'saml' NOT NULL,
	"account_mode" text DEFAULT 'disabled' NOT NULL,
	"enabled" boolean DEFAULT false NOT NULL,
	"revision" bigint DEFAULT 1 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "platform_saml_login_policies_kind_key" UNIQUE("provider_id","provider_kind"),
	CONSTRAINT "platform_saml_login_policies_value_check" CHECK ("platform_saml_login_policies"."provider_kind" = 'saml'
        and "platform_saml_login_policies"."account_mode" in ('disabled','existing_identity')
        and (not "platform_saml_login_policies"."enabled" or "platform_saml_login_policies"."account_mode" = 'existing_identity')
        and "platform_saml_login_policies"."revision" between 1 and 9007199254740991
        and "platform_saml_login_policies"."updated_at" >= "platform_saml_login_policies"."created_at")
);
--> statement-breakpoint
ALTER TABLE "platform_saml_login_policies" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "platform_saml_post_primary_continuation_evidence" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"continuation_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"kind" text NOT NULL,
	"level" text NOT NULL,
	"platform_provider_id" uuid,
	"external_identity_id" uuid,
	"totp_credential_id" uuid,
	"factor_revision" bigint,
	"trust_rule_id" uuid,
	"trust_rule_revision" bigint,
	"authenticated_at" timestamp with time zone NOT NULL,
	"expires_at" timestamp with time zone,
	CONSTRAINT "platform_saml_post_primary_continuation_evidence_key" UNIQUE("continuation_id","id"),
	CONSTRAINT "platform_saml_post_primary_continuation_evidence_value_check" CHECK ((uuid_extract_version("platform_saml_post_primary_continuation_evidence"."id") = 7) is true
        and "platform_saml_post_primary_continuation_evidence"."level" in ('primary','mfa','phishing_resistant')
        and ("platform_saml_post_primary_continuation_evidence"."expires_at" is null or "platform_saml_post_primary_continuation_evidence"."expires_at" > "platform_saml_post_primary_continuation_evidence"."authenticated_at")
        and (("platform_saml_post_primary_continuation_evidence"."kind" = 'platform_provider' and "platform_saml_post_primary_continuation_evidence"."platform_provider_id" is not null
          and "platform_saml_post_primary_continuation_evidence"."external_identity_id" is not null and "platform_saml_post_primary_continuation_evidence"."totp_credential_id" is null
          and "platform_saml_post_primary_continuation_evidence"."factor_revision" is null)
        or ("platform_saml_post_primary_continuation_evidence"."kind" = 'totp' and "platform_saml_post_primary_continuation_evidence"."level" = 'mfa'
          and "platform_saml_post_primary_continuation_evidence"."platform_provider_id" is null and "platform_saml_post_primary_continuation_evidence"."external_identity_id" is null
          and "platform_saml_post_primary_continuation_evidence"."totp_credential_id" is not null
          and "platform_saml_post_primary_continuation_evidence"."factor_revision" between 1 and 9007199254740991
          and "platform_saml_post_primary_continuation_evidence"."trust_rule_id" is null and "platform_saml_post_primary_continuation_evidence"."trust_rule_revision" is null)))
);
--> statement-breakpoint
ALTER TABLE "platform_saml_post_primary_continuation_evidence" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "platform_saml_post_primary_continuation_policy_pins" (
	"continuation_id" uuid NOT NULL,
	"policy_kind" text NOT NULL,
	"policy_id" uuid NOT NULL,
	"policy_revision" bigint NOT NULL,
	CONSTRAINT "platform_saml_post_primary_continuation_policy_pins_pkey" PRIMARY KEY("continuation_id","policy_kind","policy_id"),
	CONSTRAINT "platform_saml_post_primary_continuation_policy_pins_value_check" CHECK ("platform_saml_post_primary_continuation_policy_pins"."policy_kind" in ('login','assurance','platform_floor')
        and "platform_saml_post_primary_continuation_policy_pins"."policy_revision" between 1 and 9007199254740991)
);
--> statement-breakpoint
ALTER TABLE "platform_saml_post_primary_continuation_policy_pins" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "platform_saml_post_primary_continuations" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"user_id" uuid NOT NULL,
	"receipt_digest" "bytea" NOT NULL,
	"authority" text DEFAULT 'direct_platform_saml' NOT NULL,
	"authentication_method" text DEFAULT 'saml' NOT NULL,
	"action" text NOT NULL,
	"audience" text NOT NULL,
	"platform_provider_id" uuid NOT NULL,
	"external_identity_id" uuid NOT NULL,
	"provider_revision" bigint NOT NULL,
	"login_policy_revision" bigint NOT NULL,
	"configuration_revision" bigint NOT NULL,
	"security_revision" bigint NOT NULL,
	"plan_revision" bigint NOT NULL,
	"assurance_policy_revision" bigint NOT NULL,
	"metadata_revision" bigint NOT NULL,
	"metadata_digest" "bytea" NOT NULL,
	"sp_key_revision" bigint NOT NULL,
	"configuration_digest" "bytea" NOT NULL,
	"user_authentication_revision" bigint NOT NULL,
	"identity_version" bigint NOT NULL,
	"alias_key_version" integer NOT NULL,
	"platform_authority_id" uuid NOT NULL,
	"platform_authority_revision" bigint NOT NULL,
	"platform_floor_policy_id" uuid NOT NULL,
	"platform_floor_policy_revision" bigint NOT NULL,
	"selected_totp_credential_id" uuid NOT NULL,
	"selected_totp_security_revision" bigint NOT NULL,
	"trust_rule_id" uuid,
	"trust_rule_revision" bigint,
	"state" text DEFAULT 'pending' NOT NULL,
	"version" bigint DEFAULT 1 NOT NULL,
	"created_at" timestamp with time zone NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"consumed_at" timestamp with time zone,
	"revoked_at" timestamp with time zone,
	"revoke_reason" text,
	CONSTRAINT "platform_saml_post_primary_continuations_receipt_key" UNIQUE("receipt_digest"),
	CONSTRAINT "platform_saml_post_primary_continuations_user_key" UNIQUE("id","user_id"),
	CONSTRAINT "platform_saml_post_primary_continuations_exact_key" UNIQUE("id","user_id","platform_provider_id","external_identity_id"),
	CONSTRAINT "platform_saml_post_primary_continuations_value_check" CHECK ((uuid_extract_version("platform_saml_post_primary_continuations"."id") = 7) is true
        and octet_length("platform_saml_post_primary_continuations"."receipt_digest") = 32
        and "platform_saml_post_primary_continuations"."authority" = 'direct_platform_saml'
        and "platform_saml_post_primary_continuations"."authentication_method" = 'saml'
        and "platform_saml_post_primary_continuations"."provider_revision" between 1 and 2147483647
        and "platform_saml_post_primary_continuations"."login_policy_revision" between 1 and 9007199254740991
        and "platform_saml_post_primary_continuations"."configuration_revision" between 1 and 9007199254740991
        and "platform_saml_post_primary_continuations"."security_revision" between 1 and 9007199254740991
        and "platform_saml_post_primary_continuations"."plan_revision" between 1 and 9007199254740991
        and "platform_saml_post_primary_continuations"."assurance_policy_revision" between 1 and 9007199254740991
        and "platform_saml_post_primary_continuations"."metadata_revision" between 1 and 9007199254740991
        and octet_length("platform_saml_post_primary_continuations"."metadata_digest") = 32
        and "platform_saml_post_primary_continuations"."sp_key_revision" between 1 and 9007199254740991
        and octet_length("platform_saml_post_primary_continuations"."configuration_digest") = 32
        and "platform_saml_post_primary_continuations"."user_authentication_revision" between 1 and 9007199254740991
        and "platform_saml_post_primary_continuations"."identity_version" between 1 and 2147483647
        and "platform_saml_post_primary_continuations"."alias_key_version" between 1 and 32767
        and (uuid_extract_version("platform_saml_post_primary_continuations"."platform_authority_id") = 7) is true
        and "platform_saml_post_primary_continuations"."platform_authority_revision" between 1 and 9007199254740991
        and (uuid_extract_version("platform_saml_post_primary_continuations"."platform_floor_policy_id") = 7) is true
        and "platform_saml_post_primary_continuations"."platform_floor_policy_revision" between 1 and 9007199254740991
        and (uuid_extract_version("platform_saml_post_primary_continuations"."selected_totp_credential_id") = 7) is true
        and "platform_saml_post_primary_continuations"."selected_totp_security_revision" between 1 and 9007199254740991
        and (("platform_saml_post_primary_continuations"."trust_rule_id" is null and "platform_saml_post_primary_continuations"."trust_rule_revision" is null)
          or ((uuid_extract_version("platform_saml_post_primary_continuations"."trust_rule_id") = 7) is true
            and "platform_saml_post_primary_continuations"."trust_rule_revision" between 1 and 9007199254740991))
        and btrim("platform_saml_post_primary_continuations"."action") = "platform_saml_post_primary_continuations"."action"
        and char_length("platform_saml_post_primary_continuations"."action") between 1 and 256
        and "platform_saml_post_primary_continuations"."action" !~ '[[:cntrl:]]'
        and btrim("platform_saml_post_primary_continuations"."audience") = "platform_saml_post_primary_continuations"."audience"
        and char_length("platform_saml_post_primary_continuations"."audience") between 1 and 256
        and "platform_saml_post_primary_continuations"."audience" !~ '[[:cntrl:]]'),
	CONSTRAINT "platform_saml_post_primary_continuations_lifecycle_check" CHECK ("platform_saml_post_primary_continuations"."expires_at" > "platform_saml_post_primary_continuations"."created_at"
        and (("platform_saml_post_primary_continuations"."state" = 'pending' and "platform_saml_post_primary_continuations"."version" = 1
          and "platform_saml_post_primary_continuations"."consumed_at" is null and "platform_saml_post_primary_continuations"."revoked_at" is null and "platform_saml_post_primary_continuations"."revoke_reason" is null)
        or ("platform_saml_post_primary_continuations"."state" = 'consumed' and "platform_saml_post_primary_continuations"."version" >= 2
          and "platform_saml_post_primary_continuations"."consumed_at" between "platform_saml_post_primary_continuations"."created_at" and "platform_saml_post_primary_continuations"."expires_at"
          and "platform_saml_post_primary_continuations"."revoked_at" is null and "platform_saml_post_primary_continuations"."revoke_reason" is null)
        or ("platform_saml_post_primary_continuations"."state" in ('revoked','expired') and "platform_saml_post_primary_continuations"."version" >= 2
          and "platform_saml_post_primary_continuations"."consumed_at" is null and "platform_saml_post_primary_continuations"."revoked_at" >= "platform_saml_post_primary_continuations"."created_at"
          and btrim("platform_saml_post_primary_continuations"."revoke_reason") <> '' and char_length("platform_saml_post_primary_continuations"."revoke_reason") <= 500
          and "platform_saml_post_primary_continuations"."revoke_reason" !~ '[[:cntrl:]]')))
);
--> statement-breakpoint
ALTER TABLE "platform_saml_post_primary_continuations" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "platform_saml_post_primary_totp_challenges" (
	"id" "bytea" PRIMARY KEY NOT NULL,
	"continuation_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"totp_credential_id" uuid NOT NULL,
	"browser_digest" "bytea" NOT NULL,
	"expected_continuation_version" bigint NOT NULL,
	"user_authentication_revision" bigint NOT NULL,
	"totp_security_revision" bigint NOT NULL,
	"failure_count" integer DEFAULT 0 NOT NULL,
	"state" text DEFAULT 'pending' NOT NULL,
	"version" bigint DEFAULT 1 NOT NULL,
	"completion_request_digest" "bytea",
	"completion_request_snapshot" jsonb,
	"result_snapshot" jsonb,
	"created_at" timestamp with time zone NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"completed_at" timestamp with time zone,
	"abandoned_at" timestamp with time zone,
	CONSTRAINT "platform_saml_post_primary_totp_challenges_value_check" CHECK (octet_length("platform_saml_post_primary_totp_challenges"."id") = 32 and octet_length("platform_saml_post_primary_totp_challenges"."browser_digest") = 32
        and "platform_saml_post_primary_totp_challenges"."expected_continuation_version" between 1 and 2147483647
        and "platform_saml_post_primary_totp_challenges"."user_authentication_revision" between 1 and 9007199254740991
        and "platform_saml_post_primary_totp_challenges"."totp_security_revision" between 1 and 9007199254740991
        and "platform_saml_post_primary_totp_challenges"."failure_count" between 0 and 5
        and "platform_saml_post_primary_totp_challenges"."version" between 1 and 2147483647
        and "platform_saml_post_primary_totp_challenges"."expires_at" between "platform_saml_post_primary_totp_challenges"."created_at" + interval '1 minute'
          and "platform_saml_post_primary_totp_challenges"."created_at" + interval '10 minutes'
        and (("platform_saml_post_primary_totp_challenges"."state" = 'pending' and "platform_saml_post_primary_totp_challenges"."completed_at" is null
          and "platform_saml_post_primary_totp_challenges"."abandoned_at" is null and "platform_saml_post_primary_totp_challenges"."completion_request_digest" is null
          and "platform_saml_post_primary_totp_challenges"."completion_request_snapshot" is null
          and "platform_saml_post_primary_totp_challenges"."result_snapshot" is null)
        or ("platform_saml_post_primary_totp_challenges"."state" = 'completed' and "platform_saml_post_primary_totp_challenges"."completed_at" >= "platform_saml_post_primary_totp_challenges"."created_at"
          and "platform_saml_post_primary_totp_challenges"."abandoned_at" is null and octet_length("platform_saml_post_primary_totp_challenges"."completion_request_digest") = 32
          and jsonb_typeof("platform_saml_post_primary_totp_challenges"."completion_request_snapshot") = 'object'
          and pg_column_size("platform_saml_post_primary_totp_challenges"."completion_request_snapshot") between 2 and 131072
          and jsonb_typeof("platform_saml_post_primary_totp_challenges"."result_snapshot") = 'object'
          and pg_column_size("platform_saml_post_primary_totp_challenges"."result_snapshot") between 2 and 65536)
        or ("platform_saml_post_primary_totp_challenges"."state" in ('abandoned','expired','failed') and "platform_saml_post_primary_totp_challenges"."completed_at" is null
          and "platform_saml_post_primary_totp_challenges"."abandoned_at" >= "platform_saml_post_primary_totp_challenges"."created_at"
          and "platform_saml_post_primary_totp_challenges"."completion_request_digest" is null
          and "platform_saml_post_primary_totp_challenges"."completion_request_snapshot" is null and "platform_saml_post_primary_totp_challenges"."result_snapshot" is null)))
);
--> statement-breakpoint
ALTER TABLE "platform_saml_post_primary_totp_challenges" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "platform_saml_session_materials" (
	"id" uuid PRIMARY KEY NOT NULL,
	"session_id" uuid,
	"continuation_id" uuid,
	"user_id" uuid NOT NULL,
	"platform_provider_id" uuid NOT NULL,
	"external_identity_id" uuid NOT NULL,
	"login_policy_revision" bigint NOT NULL,
	"session_index_digest" "bytea",
	"key_version" integer NOT NULL,
	"nonce" "bytea" NOT NULL,
	"ciphertext" "bytea" NOT NULL,
	"created_at" timestamp with time zone NOT NULL,
	CONSTRAINT "platform_saml_session_materials_value_check" CHECK ((uuid_extract_version("platform_saml_session_materials"."id") = 7) is true
        and (("platform_saml_session_materials"."session_id" is null) <> ("platform_saml_session_materials"."continuation_id" is null))
        and "platform_saml_session_materials"."id" <> coalesce("platform_saml_session_materials"."session_id","platform_saml_session_materials"."continuation_id")
        and "platform_saml_session_materials"."login_policy_revision" between 1 and 9007199254740991
        and ("platform_saml_session_materials"."session_index_digest" is null or octet_length("platform_saml_session_materials"."session_index_digest") = 32)
        and "platform_saml_session_materials"."key_version" between 1 and 32767
        and octet_length("platform_saml_session_materials"."nonce") = 12
        and octet_length("platform_saml_session_materials"."ciphertext") between 17 and 16384)
);
--> statement-breakpoint
ALTER TABLE "platform_saml_session_materials" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "platform_saml_session_revalidation_commands" (
	"session_id" uuid NOT NULL,
	"expected_version" bigint NOT NULL,
	"request_digest" "bytea" NOT NULL,
	"decision" text NOT NULL,
	"result_snapshot" jsonb NOT NULL,
	"applied_at" timestamp with time zone NOT NULL,
	CONSTRAINT "platform_saml_session_revalidation_commands_pkey" PRIMARY KEY("session_id","expected_version"),
	CONSTRAINT "platform_saml_session_revalidation_commands_value_check" CHECK ("platform_saml_session_revalidation_commands"."expected_version" between 1 and 2147483647
        and octet_length("platform_saml_session_revalidation_commands"."request_digest") = 32
        and "platform_saml_session_revalidation_commands"."decision" in ('usable','rotate','step_up','revoke','deny')
        and jsonb_typeof("platform_saml_session_revalidation_commands"."result_snapshot") = 'object'
        and pg_column_size("platform_saml_session_revalidation_commands"."result_snapshot") between 2 and 65536)
);
--> statement-breakpoint
ALTER TABLE "platform_saml_session_revalidation_commands" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "platform_saml_sp_keys" DROP CONSTRAINT "platform_saml_sp_keys_envelope_check";--> statement-breakpoint
DO $split_legacy_platform_saml_sp_key_envelopes$
BEGIN
  -- The predecessor column stored nonce || AES-GCM ciphertext.  Refuse to
  -- invent material for a malformed legacy row: every migrated envelope must
  -- contain a 12-byte nonce and at least a 17-byte authenticated ciphertext.
  IF EXISTS (
    SELECT 1
    FROM ONLY public.platform_saml_sp_keys AS sp_key
    WHERE octet_length(sp_key.ciphertext) < 29
  ) THEN
    RAISE EXCEPTION 'legacy platform SAML SP-key envelope is malformed'
      USING ERRCODE = '55000';
  END IF;
END;
$split_legacy_platform_saml_sp_key_envelopes$;--> statement-breakpoint
ALTER TABLE "platform_saml_sp_keys" ADD COLUMN "nonce" "bytea";--> statement-breakpoint
UPDATE ONLY public.platform_saml_sp_keys
SET nonce = substring(ciphertext FROM 1 FOR 12),
    ciphertext = substring(ciphertext FROM 13);--> statement-breakpoint
ALTER TABLE "platform_saml_sp_keys" ALTER COLUMN "nonce" SET NOT NULL;--> statement-breakpoint
ALTER TABLE "auth_session_platform_saml_evidence" ADD CONSTRAINT "auth_session_platform_saml_evidence_state_fk" FOREIGN KEY ("session_id","user_id") REFERENCES "public"."auth_session_platform_saml_states"("session_id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "auth_session_platform_saml_evidence" ADD CONSTRAINT "auth_session_platform_saml_evidence_identity_fk" FOREIGN KEY ("platform_provider_id","external_identity_id","user_id") REFERENCES "public"."platform_federated_external_identities"("platform_provider_id","id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "auth_session_platform_saml_evidence" ADD CONSTRAINT "auth_session_platform_saml_evidence_totp_fk" FOREIGN KEY ("totp_credential_id","user_id") REFERENCES "public"."totp_credentials"("id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "auth_session_platform_saml_policy_pins" ADD CONSTRAINT "auth_session_platform_saml_policy_pins_state_fk" FOREIGN KEY ("session_id") REFERENCES "public"."auth_session_platform_saml_states"("session_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "auth_session_platform_saml_provenance" ADD CONSTRAINT "auth_session_platform_saml_provenance_state_fk" FOREIGN KEY ("session_id","user_id","authority","authentication_method","primary_kind") REFERENCES "public"."auth_session_platform_saml_states"("session_id","user_id","authority","authentication_method","primary_kind") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "auth_session_platform_saml_provenance" ADD CONSTRAINT "auth_session_platform_saml_provenance_identity_fk" FOREIGN KEY ("platform_provider_id","external_identity_id","user_id") REFERENCES "public"."platform_federated_external_identities"("platform_provider_id","id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "auth_session_platform_saml_provenance" ADD CONSTRAINT "auth_session_platform_saml_provenance_floor_fk" FOREIGN KEY ("platform_floor_policy_id","platform_floor_policy_revision") REFERENCES "public"."mfa_policy_revisions"("id","revision") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "auth_session_platform_saml_states" ADD CONSTRAINT "auth_session_platform_saml_states_session_id_auth_sessions_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."auth_sessions"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "auth_session_platform_saml_states" ADD CONSTRAINT "auth_session_platform_saml_states_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "platform_saml_authentication_applications" ADD CONSTRAINT "platform_saml_authentication_applications_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "platform_saml_authentication_applications" ADD CONSTRAINT "platform_saml_authentication_applications_session_id_auth_sessions_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."auth_sessions"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "platform_saml_authentication_applications" ADD CONSTRAINT "platform_saml_auth_applications_transaction_fk" FOREIGN KEY ("transaction_id","platform_provider_id") REFERENCES "public"."platform_saml_authentication_transactions"("transaction_id","platform_provider_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_saml_authentication_applications" ADD CONSTRAINT "platform_saml_auth_applications_identity_fk" FOREIGN KEY ("platform_provider_id","external_identity_id","user_id") REFERENCES "public"."platform_federated_external_identities"("platform_provider_id","id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_saml_authentication_applications" ADD CONSTRAINT "platform_saml_auth_applications_continuation_fk" FOREIGN KEY ("continuation_id","user_id") REFERENCES "public"."platform_saml_post_primary_continuations"("id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_saml_authentication_transactions" ADD CONSTRAINT "platform_saml_auth_transactions_provider_fk" FOREIGN KEY ("platform_provider_id","provider_kind") REFERENCES "public"."platform_auth_providers"("id","kind") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_saml_authentication_transactions" ADD CONSTRAINT "platform_saml_auth_transactions_policy_fk" FOREIGN KEY ("platform_provider_id","provider_kind") REFERENCES "public"."platform_federated_provider_policies"("provider_id","provider_kind") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_saml_authentication_transactions" ADD CONSTRAINT "platform_saml_auth_transactions_login_policy_fk" FOREIGN KEY ("platform_provider_id","provider_kind") REFERENCES "public"."platform_saml_login_policies"("provider_id","provider_kind") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_saml_authentication_transactions" ADD CONSTRAINT "platform_saml_auth_transactions_configuration_fk" FOREIGN KEY ("platform_provider_id") REFERENCES "public"."platform_saml_provider_configurations"("provider_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_saml_authentication_transactions" ADD CONSTRAINT "platform_saml_auth_transactions_platform_floor_fk" FOREIGN KEY ("platform_floor_policy_id","platform_floor_policy_revision") REFERENCES "public"."mfa_policy_revisions"("id","revision") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_saml_login_policies" ADD CONSTRAINT "platform_saml_login_policies_provider_fk" FOREIGN KEY ("provider_id","provider_kind") REFERENCES "public"."platform_auth_providers"("id","kind") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_saml_login_policies" ADD CONSTRAINT "platform_saml_login_policies_runtime_policy_fk" FOREIGN KEY ("provider_id","provider_kind") REFERENCES "public"."platform_federated_provider_policies"("provider_id","provider_kind") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_saml_login_policies" ADD CONSTRAINT "platform_saml_login_policies_configuration_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."platform_saml_provider_configurations"("provider_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_saml_post_primary_continuation_evidence" ADD CONSTRAINT "platform_saml_post_primary_continuation_evidence_parent_fk" FOREIGN KEY ("continuation_id","user_id") REFERENCES "public"."platform_saml_post_primary_continuations"("id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_saml_post_primary_continuation_evidence" ADD CONSTRAINT "platform_saml_post_primary_continuation_evidence_identity_fk" FOREIGN KEY ("platform_provider_id","external_identity_id","user_id") REFERENCES "public"."platform_federated_external_identities"("platform_provider_id","id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_saml_post_primary_continuation_evidence" ADD CONSTRAINT "platform_saml_post_primary_continuation_evidence_totp_fk" FOREIGN KEY ("totp_credential_id","user_id") REFERENCES "public"."totp_credentials"("id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_saml_post_primary_continuation_policy_pins" ADD CONSTRAINT "platform_saml_post_primary_continuation_policy_pins_parent_fk" FOREIGN KEY ("continuation_id") REFERENCES "public"."platform_saml_post_primary_continuations"("id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_saml_post_primary_continuations" ADD CONSTRAINT "platform_saml_post_primary_continuations_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "platform_saml_post_primary_continuations" ADD CONSTRAINT "platform_saml_post_primary_continuations_identity_fk" FOREIGN KEY ("platform_provider_id","external_identity_id","user_id") REFERENCES "public"."platform_federated_external_identities"("platform_provider_id","id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_saml_post_primary_continuations" ADD CONSTRAINT "platform_saml_post_primary_continuations_floor_fk" FOREIGN KEY ("platform_floor_policy_id","platform_floor_policy_revision") REFERENCES "public"."mfa_policy_revisions"("id","revision") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_saml_post_primary_continuations" ADD CONSTRAINT "platform_saml_post_primary_continuations_totp_fk" FOREIGN KEY ("selected_totp_credential_id","user_id") REFERENCES "public"."totp_credentials"("id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_saml_post_primary_totp_challenges" ADD CONSTRAINT "platform_saml_post_primary_totp_challenges_parent_fk" FOREIGN KEY ("continuation_id","user_id") REFERENCES "public"."platform_saml_post_primary_continuations"("id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_saml_post_primary_totp_challenges" ADD CONSTRAINT "platform_saml_post_primary_totp_challenges_factor_fk" FOREIGN KEY ("totp_credential_id","user_id") REFERENCES "public"."totp_credentials"("id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_saml_session_materials" ADD CONSTRAINT "platform_saml_session_materials_keyring_fk" FOREIGN KEY ("key_version") REFERENCES "public"."identity_keyring_versions"("key_version") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_saml_session_materials" ADD CONSTRAINT "platform_saml_session_materials_session_fk" FOREIGN KEY ("session_id","user_id","platform_provider_id","external_identity_id") REFERENCES "public"."auth_session_platform_saml_provenance"("session_id","user_id","platform_provider_id","external_identity_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_saml_session_materials" ADD CONSTRAINT "platform_saml_session_materials_continuation_fk" FOREIGN KEY ("continuation_id","user_id","platform_provider_id","external_identity_id") REFERENCES "public"."platform_saml_post_primary_continuations"("id","user_id","platform_provider_id","external_identity_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_saml_session_revalidation_commands" ADD CONSTRAINT "platform_saml_session_revalidation_commands_session_fk" FOREIGN KEY ("session_id") REFERENCES "public"."auth_session_platform_saml_states"("session_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
CREATE INDEX "auth_session_platform_saml_states_user_idx" ON "auth_session_platform_saml_states" USING btree ("user_id","issued_at","session_id");--> statement-breakpoint
CREATE UNIQUE INDEX "platform_saml_auth_applications_session_index_key" ON "platform_saml_authentication_applications" USING btree ("platform_provider_id","session_index_digest") WHERE "platform_saml_authentication_applications"."session_index_digest" is not null;--> statement-breakpoint
CREATE UNIQUE INDEX "platform_saml_auth_transactions_live_browser_key" ON "platform_saml_authentication_transactions" USING btree ("browser_digest") WHERE "platform_saml_authentication_transactions"."state" = 'pending';--> statement-breakpoint
CREATE INDEX "platform_saml_auth_transactions_expiry_idx" ON "platform_saml_authentication_transactions" USING btree ("state","expires_at","transaction_id");--> statement-breakpoint
CREATE INDEX "platform_saml_post_primary_continuations_pending_idx" ON "platform_saml_post_primary_continuations" USING btree ("user_id","expires_at","id") WHERE "platform_saml_post_primary_continuations"."state" = 'pending';--> statement-breakpoint
CREATE INDEX "platform_saml_post_primary_totp_challenges_expiry_idx" ON "platform_saml_post_primary_totp_challenges" USING btree ("expires_at","id") WHERE "platform_saml_post_primary_totp_challenges"."state" = 'pending';--> statement-breakpoint
CREATE UNIQUE INDEX "platform_saml_post_primary_totp_challenges_live_continuation_key" ON "platform_saml_post_primary_totp_challenges" USING btree ("continuation_id") WHERE "platform_saml_post_primary_totp_challenges"."state" = 'pending';--> statement-breakpoint
CREATE UNIQUE INDEX "platform_saml_session_materials_session_key" ON "platform_saml_session_materials" USING btree ("session_id") WHERE "platform_saml_session_materials"."session_id" is not null;--> statement-breakpoint
CREATE UNIQUE INDEX "platform_saml_session_materials_continuation_key" ON "platform_saml_session_materials" USING btree ("continuation_id") WHERE "platform_saml_session_materials"."continuation_id" is not null;--> statement-breakpoint
CREATE UNIQUE INDEX "platform_saml_session_materials_session_index_key" ON "platform_saml_session_materials" USING btree ("platform_provider_id","session_index_digest") WHERE "platform_saml_session_materials"."session_index_digest" is not null;--> statement-breakpoint
ALTER TABLE "platform_saml_sp_keys" ADD CONSTRAINT "platform_saml_sp_keys_envelope_check" CHECK ("platform_saml_sp_keys"."revision" between 1 and 9007199254740991
        and "platform_saml_sp_keys"."key_version" between 1 and 32767
        and octet_length("platform_saml_sp_keys"."nonce") = 12
        and octet_length("platform_saml_sp_keys"."ciphertext") between 17 and 131072);
--> statement-breakpoint

-- All SAML writes flow through transaction-local capabilities owned by the
-- SECURITY DEFINER ABI.  Runtime roles receive no direct table privileges.
CREATE FUNCTION app.private_platform_saml_direct_json_v1(
  p_value jsonb,
  p_allowed text[],
  p_required text[],
  p_maximum_size integer
)
RETURNS void
LANGUAGE plpgsql
IMMUTABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_value IS NULL OR jsonb_typeof(p_value) <> 'object'
     OR pg_column_size(p_value) NOT BETWEEN 2 AND p_maximum_size
     OR EXISTS (
       SELECT 1 FROM jsonb_object_keys(p_value) AS key(name)
       WHERE NOT key.name = ANY(p_allowed)
     ) OR EXISTS (
       SELECT 1 FROM unnest(p_required) AS required(name)
       WHERE NOT p_value ? required.name
     ) THEN
    RAISE EXCEPTION 'invalid direct platform SAML JSON envelope'
      USING ERRCODE = '22023';
  END IF;
END;
$function$;
--> statement-breakpoint

-- Close every runtime object in the same transaction that creates it.  The
-- following migration may add compatibility roots, but it is never relied on
-- to remove PostgreSQL's default PUBLIC EXECUTE grant.
DO $platform_saml_runtime_acl_v1$
DECLARE object_record record;
BEGIN
  FOR object_record IN
    SELECT procedure.oid::regprocedure AS identity
    FROM pg_proc AS procedure
    JOIN pg_namespace AS namespace ON namespace.oid=procedure.pronamespace
    WHERE namespace.nspname='app' AND procedure.proname=ANY(ARRAY[
      'private_platform_saml_direct_json_v1','private_platform_saml_create_session_v1',
      'apply_platform_saml_authentication_v1','recover_platform_saml_authentication_apply_v1',
      'reject_platform_saml_authentication_v1','cleanup_platform_saml_authentication_v1',
      'private_platform_saml_totp_projection_v1','begin_platform_saml_post_primary_totp_v1',
      'load_platform_saml_post_primary_totp_v1','record_platform_saml_post_primary_totp_failure_v1',
      'apply_platform_saml_post_primary_totp_v1','recover_platform_saml_post_primary_totp_apply_v1',
      'abandon_platform_saml_post_primary_totp_v1','cleanup_platform_saml_post_primary_totp_apply_v1',
      'private_platform_saml_administration_fence_v1','replace_platform_saml_sp_key_v1',
      'clear_platform_saml_sp_key_v1','replace_platform_saml_metadata_v1',
      'load_platform_saml_metadata_admin_v1','private_platform_saml_direct_audit_v1',
      'guard_platform_saml_direct_runtime_write_v1','guard_platform_saml_login_policy_v1',
      'private_platform_saml_direct_pins_v1','private_platform_saml_direct_configuration_v1',
      'begin_platform_saml_authentication_v1','load_platform_saml_start_configuration_v1',
      'private_platform_saml_transaction_pins_v1','private_platform_saml_transaction_projection_v1',
      'create_platform_saml_authentication_transaction_v1',
      'recover_platform_saml_authentication_transaction_create_v1',
      'lookup_platform_saml_authentication_transaction_v1',
      'resolve_platform_saml_authentication_configuration_v1',
      'abort_platform_saml_authentication_transaction_v1','load_platform_saml_sp_key_envelope_v1',
      'load_platform_saml_metadata_projection_v1','load_platform_saml_planning_state_v1',
      'ensure_platform_saml_login_policy_v1','private_platform_saml_direct_activation_available_v1',
      'guard_platform_saml_direct_provider_dependency_v1',
      'guard_platform_saml_direct_runtime_dependency_v1',
      'set_platform_saml_direct_login_activation_v1','set_platform_direct_login_activation_v2',
      'activate_platform_direct_login_v2','deactivate_platform_direct_login_v2',
      'update_platform_auth_provider_v2','private_platform_auth_provider_document_v1',
      'list_platform_auth_providers_v1'
    ]::name[])
  LOOP
    EXECUTE format('ALTER FUNCTION %s OWNER TO periapsis_migrator',object_record.identity);
    EXECUTE format(
      'REVOKE ALL PRIVILEGES ON FUNCTION %s FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier',
      object_record.identity
    );
  END LOOP;
  FOR object_record IN
    SELECT table_name
    FROM information_schema.tables
    WHERE table_schema='public' AND table_name=ANY(ARRAY[
      'auth_session_platform_saml_evidence','auth_session_platform_saml_policy_pins',
      'auth_session_platform_saml_provenance','auth_session_platform_saml_states',
      'platform_saml_authentication_applications','platform_saml_authentication_transactions',
      'platform_saml_login_policies','platform_saml_post_primary_continuation_evidence',
      'platform_saml_post_primary_continuation_policy_pins',
      'platform_saml_post_primary_continuations','platform_saml_post_primary_totp_challenges',
      'platform_saml_session_materials','platform_saml_session_revalidation_commands'
    ]::name[])
  LOOP
    EXECUTE format('ALTER TABLE public.%I OWNER TO periapsis_migrator',object_record.table_name);
    EXECUTE format(
      'REVOKE ALL PRIVILEGES ON TABLE public.%I FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier',
      object_record.table_name
    );
  END LOOP;
END;
$platform_saml_runtime_acl_v1$;
--> statement-breakpoint

DO $platform_saml_runtime_api_grants_v1$
DECLARE object_record record;
BEGIN
  FOR object_record IN
    SELECT procedure.oid::regprocedure AS identity
    FROM pg_proc AS procedure
    JOIN pg_namespace AS namespace ON namespace.oid=procedure.pronamespace
    WHERE namespace.nspname='app' AND procedure.proname=ANY(ARRAY[
      'apply_platform_saml_authentication_v1','recover_platform_saml_authentication_apply_v1',
      'reject_platform_saml_authentication_v1','cleanup_platform_saml_authentication_v1',
      'begin_platform_saml_post_primary_totp_v1','load_platform_saml_post_primary_totp_v1',
      'record_platform_saml_post_primary_totp_failure_v1','apply_platform_saml_post_primary_totp_v1',
      'recover_platform_saml_post_primary_totp_apply_v1','abandon_platform_saml_post_primary_totp_v1',
      'cleanup_platform_saml_post_primary_totp_apply_v1','replace_platform_saml_sp_key_v1',
      'clear_platform_saml_sp_key_v1','replace_platform_saml_metadata_v1',
      'load_platform_saml_metadata_admin_v1','begin_platform_saml_authentication_v1',
      'load_platform_saml_start_configuration_v1','create_platform_saml_authentication_transaction_v1',
      'recover_platform_saml_authentication_transaction_create_v1',
      'lookup_platform_saml_authentication_transaction_v1',
      'resolve_platform_saml_authentication_configuration_v1',
      'abort_platform_saml_authentication_transaction_v1','load_platform_saml_sp_key_envelope_v1',
      'load_platform_saml_metadata_projection_v1','load_platform_saml_planning_state_v1',
      'activate_platform_direct_login_v2','deactivate_platform_direct_login_v2',
      'update_platform_auth_provider_v2','list_platform_auth_providers_v1'
    ]::name[])
  LOOP
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO periapsis_api',object_record.identity);
  END LOOP;
END;
$platform_saml_runtime_api_grants_v1$;
--> statement-breakpoint

-- Create one tenantless direct-platform SAML session from an already
-- revalidated, prelinked plan.  The caller supplies only opaque credential
-- digests; NameID and logout material are stored in the separate encrypted
-- SAML material table by the outer apply ABI.
CREATE FUNCTION app.private_platform_saml_create_session_v1(
  p_session jsonb,p_plan jsonb,p_audience text,p_issued_at timestamptz,
  p_totp_id uuid DEFAULT NULL,p_totp_revision bigint DEFAULT NULL,
  p_totp_authenticated_at timestamptz DEFAULT NULL,
  p_rotated_from uuid DEFAULT NULL
)
RETURNS uuid
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  session_id uuid;
  family_id uuid;
  user_id uuid;
  provider_id uuid;
  identity_id uuid;
  token_digest bytea;
  csrf_digest bytea;
  idle_expires timestamptz;
  absolute_expires timestamptz;
  pins jsonb := p_plan -> 'pins';
  protocol_pins jsonb := p_plan #> '{pins,protocol}';
  provenance jsonb := p_plan -> 'provenance';
  assurance jsonb := p_plan #> '{provenance,selectedAssurance}';
  floor jsonb := p_plan -> 'platformFloor';
  trust_id uuid;
  trust_revision bigint;
BEGIN
  PERFORM app.private_platform_saml_direct_json_v1(
    p_session,
    ARRAY['id','rotationFamilyId','tokenDigest','csrfSecretDigest',
      'authenticationMethod','idleExpiresAt','absoluteExpiresAt'],
    ARRAY['id','rotationFamilyId','tokenDigest','csrfSecretDigest',
      'authenticationMethod','idleExpiresAt','absoluteExpiresAt'],32768
  );
  session_id := app.private_mfa_require_uuidv7_v1(p_session ->> 'id');
  family_id := app.private_mfa_require_uuidv7_v1(p_session ->> 'rotationFamilyId');
  user_id := app.private_mfa_require_uuidv7_v1(provenance ->> 'userId');
  provider_id := app.private_mfa_require_uuidv7_v1(provenance #>> '{provider,providerId}');
  identity_id := app.private_mfa_require_uuidv7_v1(provenance ->> 'externalIdentityId');
  token_digest := app.private_mfa_decode_base64_v1(p_session ->> 'tokenDigest',32,32);
  csrf_digest := app.private_mfa_decode_base64_v1(p_session ->> 'csrfSecretDigest',32,32);
  idle_expires := (p_session ->> 'idleExpiresAt')::timestamptz;
  absolute_expires := (p_session ->> 'absoluteExpiresAt')::timestamptz;
  IF assurance ? 'trustRuleId' THEN
    trust_id := app.private_mfa_require_uuidv7_v1(assurance ->> 'trustRuleId');
    trust_revision := (assurance ->> 'trustRuleRevision')::bigint;
  END IF;
  IF p_session ->> 'authenticationMethod' <> 'saml' OR p_audience <> 'api'
     OR session_id=family_id OR token_digest=csrf_digest
     OR encode(token_digest,'hex')=repeat('00',32)
     OR encode(csrf_digest,'hex')=repeat('00',32)
     OR idle_expires<=p_issued_at OR absolute_expires<=idle_expires
     OR absolute_expires>p_issued_at+interval '30 days'
     OR (p_totp_id IS NULL)<>(p_totp_revision IS NULL)
     OR (p_totp_id IS NULL)<>(p_totp_authenticated_at IS NULL) THEN
    RAISE EXCEPTION 'invalid direct platform SAML session envelope'
      USING ERRCODE='22023';
  END IF;
  IF p_rotated_from IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM ONLY public.auth_sessions AS source
    JOIN ONLY public.auth_session_platform_saml_states AS source_state
      ON source_state.session_id=source.id
     AND source_state.authority='direct_platform_saml'
    WHERE source.id=p_rotated_from AND source.user_id=user_id
      AND source.rotation_family_id=family_id
      AND source.absolute_expires_at=absolute_expires
      AND source.revoked_at IS NULL
    FOR UPDATE OF source,source_state
  ) THEN
    RAISE EXCEPTION 'direct platform SAML rotation source is stale'
      USING ERRCODE='40001';
  END IF;
  IF p_totp_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM ONLY public.totp_credentials AS factor
    WHERE factor.id=p_totp_id AND factor.user_id=user_id
      AND factor.security_revision=p_totp_revision
      AND factor.confirmed_at IS NOT NULL AND factor.disabled_at IS NULL
    FOR UPDATE
  ) THEN
    RAISE EXCEPTION 'direct platform SAML TOTP authority is stale'
      USING ERRCODE='40001';
  END IF;
  PERFORM set_config('app.platform_saml_direct_runtime_write_v1','on',true);
  INSERT INTO public.auth_sessions (
    id,user_id,rotation_family_id,active_tenant_id,token_digest,
    csrf_secret_digest,authentication_method,mfa_satisfied_at,last_seen_at,
    idle_expires_at,absolute_expires_at,rotated_from_session_id,created_at
  ) VALUES (
    session_id,user_id,family_id,NULL,token_digest,csrf_digest,'saml',
    CASE WHEN assurance ->> 'level'='primary' AND p_totp_id IS NULL
      THEN NULL ELSE p_issued_at END,p_issued_at,idle_expires,
    absolute_expires,p_rotated_from,p_issued_at
  );
  INSERT INTO public.auth_session_platform_saml_states (
    session_id,user_id,authority,authentication_method,session_version,
    user_authentication_revision,recovery_restricted,audience,primary_kind,issued_at
  ) VALUES (
    session_id,user_id,'direct_platform_saml','saml',1,
    (provenance ->> 'userAuthenticationRevision')::bigint,false,p_audience,
    'platform_provider',p_issued_at
  );
  INSERT INTO public.auth_session_platform_saml_provenance (
    session_id,user_id,authority,authentication_method,primary_kind,
    platform_provider_id,external_identity_id,provider_revision,
    login_policy_revision,configuration_revision,security_revision,
    plan_revision,assurance_policy_revision,metadata_revision,metadata_digest,
    sp_key_revision,configuration_digest,user_authentication_revision,
    identity_version,alias_key_version,platform_authority_id,
    platform_authority_revision,platform_floor_policy_id,
    platform_floor_policy_revision,trust_rule_id,trust_rule_revision,authenticated_at
  ) VALUES (
    session_id,user_id,'direct_platform_saml','saml','platform_provider',
    provider_id,identity_id,(protocol_pins ->> 'providerRevision')::bigint,
    (protocol_pins ->> 'platformLoginRevision')::bigint,
    (protocol_pins ->> 'configurationRevision')::bigint,
    (protocol_pins ->> 'securityRevision')::bigint,
    (protocol_pins ->> 'planRevision')::bigint,
    (protocol_pins ->> 'assurancePolicyRevision')::bigint,
    (protocol_pins ->> 'metadataRevision')::bigint,
    app.private_mfa_decode_base64_v1(protocol_pins ->> 'metadataDigest',32,32),
    (protocol_pins ->> 'spKeyRevision')::bigint,
    app.private_mfa_decode_base64_v1(protocol_pins ->> 'configurationDigest',32,32),
    (provenance ->> 'userAuthenticationRevision')::bigint,
    (provenance ->> 'identityRevision')::bigint,
    (provenance ->> 'matchedAliasKeyVersion')::integer,
    app.private_mfa_require_uuidv7_v1(provenance ->> 'platformAuthorityId'),
    (provenance ->> 'platformAuthorityRevision')::bigint,
    app.private_mfa_require_uuidv7_v1(pins ->> 'platformFloorPolicyId'),
    (pins ->> 'platformFloorPolicyRevision')::bigint,
    trust_id,trust_revision,(provenance ->> 'authenticatedAt')::timestamptz
  );
  INSERT INTO public.auth_session_platform_saml_evidence (
    id,session_id,user_id,kind,level,platform_provider_id,
    external_identity_id,trust_rule_id,trust_rule_revision,authenticated_at,expires_at
  ) VALUES (
    uuidv7(),session_id,user_id,'platform_provider',assurance ->> 'level',
    provider_id,identity_id,trust_id,trust_revision,
    (assurance ->> 'authenticatedAt')::timestamptz,
    (provenance ->> 'validUntil')::timestamptz
  );
  IF p_totp_id IS NOT NULL THEN
    INSERT INTO public.auth_session_platform_saml_evidence (
      id,session_id,user_id,kind,level,totp_credential_id,factor_revision,
      authenticated_at,expires_at
    ) VALUES (
      uuidv7(),session_id,user_id,'totp','mfa',p_totp_id,p_totp_revision,
      p_totp_authenticated_at,
      CASE WHEN (floor ->> 'freshnessNanoseconds')::bigint>0 THEN
        p_totp_authenticated_at+
          ((floor ->> 'freshnessNanoseconds')::numeric/1000000000)*interval '1 second'
      ELSE NULL END
    );
  END IF;
  INSERT INTO public.auth_session_platform_saml_policy_pins (
    session_id,policy_kind,policy_id,policy_revision
  ) VALUES
    (session_id,'login',provider_id,(protocol_pins ->> 'platformLoginRevision')::bigint),
    (session_id,'assurance',provider_id,(protocol_pins ->> 'assurancePolicyRevision')::bigint),
    (session_id,'platform_floor',app.private_mfa_require_uuidv7_v1(pins ->> 'platformFloorPolicyId'),
      (pins ->> 'platformFloorPolicyRevision')::bigint);
  RETURN session_id;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.apply_platform_saml_authentication_v1(p_command jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  semantic jsonb;
  authority jsonb;
  plan jsonb;
  provenance jsonb;
  subject jsonb;
  transaction_id bytea;
  proof_digest bytea;
  response_digest bytea;
  assertion_digest bytea;
  session_index_digest bytea;
  observed_at timestamptz;
  expected_version bigint;
  provider_id uuid;
  user_id uuid;
  identity_id uuid;
  session_id uuid;
  continuation_id uuid;
  material_id uuid;
  disposition text;
  result jsonb;
  transaction_record public.platform_saml_authentication_transactions%ROWTYPE;
  application_record public.platform_saml_authentication_applications%ROWTYPE;
  alias_value jsonb;
  trust_id uuid;
  trust_revision bigint;
BEGIN
  PERFORM app.private_platform_saml_direct_json_v1(
    p_command,ARRAY['authority','plan','session','continuation','sessionAudience',
      'recoveryRestricted','protectedSessionMaterial','appliedAt','audit','proofDigest'],
    ARRAY['authority','plan','sessionAudience','recoveryRestricted','appliedAt','audit','proofDigest'],2097152
  );
  semantic := p_command-'audit';
  authority := p_command->'authority';
  plan := p_command->'plan';
  provenance := plan->'provenance';
  subject := plan->'subject';
  PERFORM app.private_platform_saml_direct_json_v1(
    authority,ARRAY['transactionId','materialId','expectedVersion','pins',
      'responseIdDigest','assertionIdDigest','sessionIndexDigest','hasSessionIndex',
      'hasSessionMaterial','consumedAt','returnPath'],
    ARRAY['transactionId','materialId','expectedVersion','pins','responseIdDigest',
      'assertionIdDigest','hasSessionIndex','hasSessionMaterial','consumedAt','returnPath'],65536
  );
  transaction_id:=app.private_mfa_decode_base64_v1(authority->>'transactionId',32,32);
  proof_digest:=app.private_mfa_decode_base64_v1(p_command->>'proofDigest',32,32);
  response_digest:=app.private_mfa_decode_base64_v1(authority->>'responseIdDigest',32,32);
  assertion_digest:=app.private_mfa_decode_base64_v1(authority->>'assertionIdDigest',32,32);
  IF (authority->>'hasSessionIndex')::boolean THEN
    session_index_digest:=app.private_mfa_decode_base64_v1(authority->>'sessionIndexDigest',32,32);
  ELSIF authority ? 'sessionIndexDigest' THEN
    RAISE EXCEPTION 'invalid direct platform SAML apply authority' USING ERRCODE='22023';
  END IF;
  observed_at:=(p_command->>'appliedAt')::timestamptz;
  expected_version:=(authority->>'expectedVersion')::bigint;
  material_id:=app.private_mfa_require_uuidv7_v1(authority->>'materialId');
  provider_id:=app.private_mfa_require_uuidv7_v1(provenance#>>'{provider,providerId}');
  user_id:=app.private_mfa_require_uuidv7_v1(provenance->>'userId');
  identity_id:=app.private_mfa_require_uuidv7_v1(provenance->>'externalIdentityId');
  disposition:=plan->>'disposition';
  IF disposition NOT IN ('immediate_session','totp_continuation')
     OR p_command->>'sessionAudience'<>'api'
     OR (p_command->>'recoveryRestricted')::boolean
     OR response_digest=assertion_digest
     OR encode(proof_digest,'hex')=repeat('00',32)
     OR observed_at NOT BETWEEN statement_timestamp()-interval '5 minutes'
                              AND statement_timestamp()+interval '30 seconds'
     OR authority->>'returnPath' !~ '^/[^[:cntrl:]\\]*$'
     OR left(authority->>'returnPath',2)='//'
     OR (disposition='immediate_session')<>(p_command ? 'session')
     OR (disposition='totp_continuation')<>(p_command ? 'continuation') THEN
    RAISE EXCEPTION 'invalid direct platform SAML apply command' USING ERRCODE='22023';
  END IF;
  IF disposition='immediate_session' THEN
    session_id:=app.private_mfa_require_uuidv7_v1(p_command#>>'{session,id}');
  ELSE
    continuation_id:=app.private_mfa_require_uuidv7_v1(p_command#>>'{continuation,id}');
  END IF;
  result:=jsonb_strip_nulls(jsonb_build_object(
    'category','stale','transactionId',authority->'transactionId',
    'proofDigest',p_command->'proofDigest','userId',user_id::text,
    'sessionId',CASE WHEN session_id IS NULL THEN NULL ELSE session_id::text END,
    'continuationId',CASE WHEN continuation_id IS NULL THEN NULL ELSE continuation_id::text END,
    'returnPath',authority->>'returnPath','appliedAt',to_jsonb(observed_at)
  ));
  SELECT application.* INTO application_record
  FROM ONLY public.platform_saml_authentication_applications AS application
  WHERE application.transaction_id=transaction_id
  FOR UPDATE;
  IF FOUND THEN
    IF application_record.proof_digest<>proof_digest
       OR application_record.request_snapshot IS DISTINCT FROM semantic THEN
      RAISE EXCEPTION 'direct platform SAML apply replay collision' USING ERRCODE='23505';
    END IF;
    RETURN jsonb_set(application_record.result_snapshot,'{category}','"already_applied"'::jsonb);
  END IF;
  IF EXISTS (
    SELECT 1 FROM ONLY public.platform_saml_authentication_applications AS replay
    WHERE replay.platform_provider_id=provider_id AND (
      replay.response_id_digest=response_digest OR replay.assertion_id_digest=assertion_digest
      OR (session_index_digest IS NOT NULL AND replay.session_index_digest=session_index_digest)
    )
  ) THEN
    RETURN jsonb_set(result,'{category}','"protocol_replay"'::jsonb);
  END IF;
  SELECT transaction.* INTO STRICT transaction_record
  FROM ONLY public.platform_saml_authentication_transactions AS transaction
  WHERE transaction.transaction_id=transaction_id FOR UPDATE;
  IF transaction_record.state<>'pending' OR transaction_record.version<>expected_version
     OR transaction_record.expires_at<=observed_at
     OR transaction_record.platform_provider_id<>provider_id
     OR app.private_platform_saml_transaction_pins_v1(transaction_record)->'protocol'
          IS DISTINCT FROM authority->'pins'
     OR app.private_platform_saml_transaction_pins_v1(transaction_record)
          IS DISTINCT FROM plan->'pins'
     OR authority->>'returnPath'<>transaction_record.return_path
     OR app.private_platform_saml_direct_configuration_v1(provider_id,authority->'pins') IS NULL THEN
    RETURN result;
  END IF;
  -- Recheck the complete prelinked authority under row locks.  No assertion
  -- claim can create an account or grant a platform role.
  PERFORM 1
  FROM ONLY public.platform_auth_providers AS provider
  JOIN ONLY public.platform_federated_provider_policies AS runtime_policy
    ON runtime_policy.provider_id=provider.id AND runtime_policy.provider_kind='saml'
  JOIN ONLY public.platform_saml_login_policies AS login_policy
    ON login_policy.provider_id=provider.id
  JOIN ONLY public.platform_federated_external_identities AS identity
    ON identity.id=identity_id AND identity.platform_provider_id=provider.id
   AND identity.provider_kind='saml' AND identity.user_id=user_id AND identity.retired_at IS NULL
  JOIN ONLY public.users AS local_user
    ON local_user.id=user_id AND local_user.active
  JOIN ONLY public.user_platform_roles AS grant_record
    ON grant_record.id=app.private_mfa_require_uuidv7_v1(provenance->>'platformAuthorityId')
   AND grant_record.user_id=user_id AND grant_record.revoked_at IS NULL
  JOIN ONLY public.platform_roles AS platform_role
    ON platform_role.id=grant_record.role_id AND platform_role.key='platform_super_admin'
  WHERE provider.id=provider_id AND provider.kind='saml' AND provider.enabled
    AND provider.archived_at IS NULL AND provider.version=transaction_record.provider_revision
    AND runtime_policy.enabled AND NOT runtime_policy.platform_login_enabled
    AND runtime_policy.configuration_revision=transaction_record.configuration_revision
    AND runtime_policy.security_revision=transaction_record.security_revision
    AND runtime_policy.plan_revision=transaction_record.plan_revision
    AND runtime_policy.assurance_policy_revision=transaction_record.assurance_policy_revision
    AND login_policy.enabled AND login_policy.account_mode='existing_identity'
    AND login_policy.revision=transaction_record.login_policy_revision
    AND identity.version=(provenance->>'identityRevision')::bigint
    AND local_user.authentication_revision=(provenance->>'userAuthenticationRevision')::bigint
  FOR UPDATE OF provider,runtime_policy,login_policy,identity,local_user,grant_record;
  IF NOT FOUND THEN RETURN result; END IF;
  IF NOT EXISTS (
    SELECT 1 FROM ONLY public.platform_federated_external_identity_aliases AS alias
    JOIN LATERAL jsonb_array_elements(subject->'aliases') AS supplied(value)
      ON alias.key_version=(supplied.value->>'keyVersion')::integer
     AND alias.subject_digest=app.private_mfa_decode_base64_v1(supplied.value->>'digest',32,32)
    WHERE alias.platform_provider_id=provider_id
      AND alias.external_identity_id=identity_id AND alias.retired_at IS NULL
      AND alias.key_version=(provenance->>'matchedAliasKeyVersion')::integer
  ) THEN RETURN jsonb_set(result,'{category}','"collision"'::jsonb); END IF;
  IF jsonb_array_length(subject->'aliases') NOT BETWEEN 1 AND 16
     OR subject->>'subjectFormat'<>'utf8_exact'
     OR subject#>>'{envelope,format}'<>'utf8_exact' THEN
    RAISE EXCEPTION 'invalid direct platform SAML subject observation' USING ERRCODE='22023';
  END IF;
  IF provenance#>>'{selectedAssurance,trustRuleId}' IS NOT NULL THEN
    trust_id:=app.private_mfa_require_uuidv7_v1(provenance#>>'{selectedAssurance,trustRuleId}');
    trust_revision:=(provenance#>>'{selectedAssurance,trustRuleRevision}')::bigint;
    IF NOT EXISTS (
      SELECT 1 FROM ONLY public.platform_federated_trust_rules AS trust
      WHERE trust.id=trust_id AND trust.provider_id=provider_id
        AND trust.provider_kind='saml' AND trust.revision=trust_revision
        AND trust.enabled AND trust.retired_at IS NULL
      FOR SHARE
    ) THEN RETURN result; END IF;
  END IF;
  IF disposition='totp_continuation' AND NOT EXISTS (
    SELECT 1 FROM ONLY public.totp_credentials AS factor
    WHERE factor.id=app.private_mfa_require_uuidv7_v1(plan#>>'{totp,factorId}')
      AND factor.user_id=user_id
      AND factor.security_revision=(plan#>>'{totp,revision}')::bigint
      AND factor.confirmed_at IS NOT NULL AND factor.disabled_at IS NULL
    FOR UPDATE
  ) THEN RETURN result; END IF;
  PERFORM set_config('app.platform_saml_direct_runtime_write_v1','on',true);
  IF disposition='immediate_session' THEN
    PERFORM app.private_platform_saml_create_session_v1(
      p_command->'session',plan,p_command->>'sessionAudience',observed_at
    );
  ELSE
    INSERT INTO public.platform_saml_post_primary_continuations (
      id,user_id,receipt_digest,authority,authentication_method,action,audience,
      platform_provider_id,external_identity_id,provider_revision,
      login_policy_revision,configuration_revision,security_revision,plan_revision,
      assurance_policy_revision,metadata_revision,metadata_digest,sp_key_revision,
      configuration_digest,user_authentication_revision,identity_version,
      alias_key_version,platform_authority_id,platform_authority_revision,
      platform_floor_policy_id,platform_floor_policy_revision,
      selected_totp_credential_id,selected_totp_security_revision,
      trust_rule_id,trust_rule_revision,state,version,created_at,expires_at
    ) VALUES (
      continuation_id,user_id,
      app.private_mfa_decode_base64_v1(p_command#>>'{continuation,receiptDigest}',32,32),
      'direct_platform_saml','saml','session.create',p_command->>'sessionAudience',
      provider_id,identity_id,transaction_record.provider_revision,
      transaction_record.login_policy_revision,transaction_record.configuration_revision,
      transaction_record.security_revision,transaction_record.plan_revision,
      transaction_record.assurance_policy_revision,transaction_record.metadata_revision,
      transaction_record.metadata_digest,transaction_record.sp_key_revision,
      transaction_record.configuration_digest,
      (provenance->>'userAuthenticationRevision')::bigint,
      (provenance->>'identityRevision')::bigint,
      (provenance->>'matchedAliasKeyVersion')::integer,
      app.private_mfa_require_uuidv7_v1(provenance->>'platformAuthorityId'),
      (provenance->>'platformAuthorityRevision')::bigint,
      transaction_record.platform_floor_policy_id,transaction_record.platform_floor_policy_revision,
      app.private_mfa_require_uuidv7_v1(plan#>>'{totp,factorId}'),
      (plan#>>'{totp,revision}')::bigint,trust_id,trust_revision,
      'pending',1,observed_at,(p_command#>>'{continuation,expiresAt}')::timestamptz
    );
    INSERT INTO public.platform_saml_post_primary_continuation_evidence (
      id,continuation_id,user_id,kind,level,platform_provider_id,
      external_identity_id,trust_rule_id,trust_rule_revision,authenticated_at,expires_at
    ) VALUES (
      uuidv7(),continuation_id,user_id,'platform_provider',
      provenance#>>'{selectedAssurance,level}',provider_id,identity_id,
      trust_id,trust_revision,(provenance#>>'{selectedAssurance,authenticatedAt}')::timestamptz,
      (provenance->>'validUntil')::timestamptz
    );
    INSERT INTO public.platform_saml_post_primary_continuation_policy_pins (
      continuation_id,policy_kind,policy_id,policy_revision
    ) VALUES
      (continuation_id,'login',provider_id,transaction_record.login_policy_revision),
      (continuation_id,'assurance',provider_id,transaction_record.assurance_policy_revision),
      (continuation_id,'platform_floor',transaction_record.platform_floor_policy_id,
        transaction_record.platform_floor_policy_revision);
  END IF;
  FOR alias_value IN SELECT value FROM jsonb_array_elements(subject->'aliases') LOOP
    INSERT INTO public.platform_federated_external_identity_aliases (
      id,platform_provider_id,external_identity_id,key_version,subject_digest,created_at
    ) SELECT uuidv7(),provider_id,identity_id,(alias_value->>'keyVersion')::integer,
      app.private_mfa_decode_base64_v1(alias_value->>'digest',32,32),observed_at
    WHERE NOT EXISTS (
      SELECT 1 FROM ONLY public.platform_federated_external_identity_aliases AS alias
      WHERE alias.platform_provider_id=provider_id AND alias.external_identity_id=identity_id
        AND alias.key_version=(alias_value->>'keyVersion')::integer
        AND alias.subject_digest=app.private_mfa_decode_base64_v1(alias_value->>'digest',32,32)
        AND alias.retired_at IS NULL
    );
  END LOOP;
  UPDATE ONLY public.platform_federated_external_identities AS identity
  SET subject_format='utf8_exact',
      subject_ciphertext=app.private_mfa_decode_base64_v1(subject#>>'{envelope,ciphertext}',17,4112),
      subject_nonce=app.private_mfa_decode_base64_v1(subject#>>'{envelope,nonce}',12,12),
      key_version=(subject#>>'{envelope,keyVersion}')::integer,
      last_observed_at=observed_at,last_observation_state='known',updated_at=observed_at
  WHERE identity.id=identity_id AND identity.platform_provider_id=provider_id
    AND identity.user_id=user_id AND identity.version=(provenance->>'identityRevision')::bigint
    AND identity.retired_at IS NULL;
  IF NOT FOUND THEN RAISE EXCEPTION 'direct platform SAML identity CAS lost' USING ERRCODE='40001'; END IF;
  IF (authority->>'hasSessionMaterial')::boolean THEN
    INSERT INTO public.platform_saml_session_materials (
      id,session_id,continuation_id,user_id,platform_provider_id,external_identity_id,
      login_policy_revision,session_index_digest,key_version,nonce,ciphertext,created_at
    ) VALUES (
      material_id,session_id,continuation_id,user_id,provider_id,identity_id,
      transaction_record.login_policy_revision,session_index_digest,
      (p_command#>>'{protectedSessionMaterial,keyVersion}')::integer,
      app.private_mfa_decode_base64_v1(p_command#>>'{protectedSessionMaterial,nonce}',12,12),
      app.private_mfa_decode_base64_v1(p_command#>>'{protectedSessionMaterial,ciphertext}',17,16384),
      observed_at
    );
  ELSIF p_command ? 'protectedSessionMaterial' THEN
    RAISE EXCEPTION 'unexpected direct platform SAML session material' USING ERRCODE='22023';
  END IF;
  result:=jsonb_strip_nulls(jsonb_build_object(
    'category','success','transactionId',authority->'transactionId',
    'proofDigest',p_command->'proofDigest','userId',user_id::text,
    'sessionId',CASE WHEN session_id IS NULL THEN NULL ELSE session_id::text END,
    'continuationId',CASE WHEN continuation_id IS NULL THEN NULL ELSE continuation_id::text END,
    'returnPath',authority->>'returnPath','appliedAt',to_jsonb(observed_at)
  ));
  UPDATE ONLY public.platform_saml_authentication_transactions AS transaction
  SET state='completed',version=transaction.version+1,completed_at=observed_at,failure_reason=NULL
  WHERE transaction.transaction_id=transaction_id AND transaction.state='pending'
    AND transaction.version=expected_version;
  IF NOT FOUND THEN RAISE EXCEPTION 'direct platform SAML apply CAS lost' USING ERRCODE='40001'; END IF;
  INSERT INTO public.platform_saml_authentication_applications (
    id,transaction_id,proof_digest,platform_provider_id,response_id_digest,
    assertion_id_digest,session_index_digest,category,user_id,external_identity_id,
    session_id,continuation_id,request_snapshot,result_snapshot,applied_at
  ) VALUES (
    uuidv7(),transaction_id,proof_digest,provider_id,response_digest,
    assertion_digest,session_index_digest,'success',user_id,identity_id,
    session_id,continuation_id,semantic,result,observed_at
  );
  PERFORM app.private_platform_saml_direct_audit_v1(
    p_command->'audit',uuidv7(),'platform.saml.login.succeeded',
    'platform_identity_account',identity_id,'success',jsonb_build_object(
      'providerId',provider_id,'userId',user_id,'disposition',disposition,
      'providerRevision',transaction_record.provider_revision,
      'loginPolicyRevision',transaction_record.login_policy_revision
    )
  );
  RETURN result;
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RETURN result;
WHEN invalid_text_representation OR numeric_value_out_of_range OR data_exception THEN
  RAISE EXCEPTION 'invalid direct platform SAML apply command' USING ERRCODE='22023';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.recover_platform_saml_authentication_apply_v1(p_command jsonb)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE existing public.platform_saml_authentication_applications%ROWTYPE;
BEGIN
  IF p_command IS NULL OR jsonb_typeof(p_command)<>'object'
     OR pg_column_size(p_command)>2097152 THEN
    RAISE EXCEPTION 'invalid direct platform SAML apply recovery' USING ERRCODE='22023';
  END IF;
  SELECT application.* INTO existing
  FROM ONLY public.platform_saml_authentication_applications AS application
  WHERE application.transaction_id=app.private_mfa_decode_base64_v1(
      p_command#>>'{authority,transactionId}',32,32)
    AND application.proof_digest=app.private_mfa_decode_base64_v1(p_command->>'proofDigest',32,32)
    AND application.request_snapshot IS NOT DISTINCT FROM p_command-'audit';
  IF NOT FOUND THEN RETURN jsonb_build_object('matched',false); END IF;
  RETURN jsonb_build_object('matched',true,'result',
    jsonb_set(existing.result_snapshot,'{category}','"already_applied"'::jsonb));
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.reject_platform_saml_authentication_v1(p_request jsonb)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE existing public.platform_saml_authentication_transactions%ROWTYPE;
DECLARE rejected_at timestamptz;
DECLARE reason text;
BEGIN
  PERFORM app.private_platform_saml_direct_json_v1(
    p_request,ARRAY['authority','reason','rejectedAt','audit'],
    ARRAY['authority','reason','rejectedAt','audit'],131072
  );
  rejected_at:=(p_request->>'rejectedAt')::timestamptz;
  reason:=p_request->>'reason';
  IF reason NOT IN ('malformed','denied','stale','collision','unavailable')
     OR rejected_at NOT BETWEEN statement_timestamp()-interval '5 minutes'
                               AND statement_timestamp()+interval '30 seconds' THEN
    RAISE EXCEPTION 'invalid direct platform SAML rejection' USING ERRCODE='22023';
  END IF;
  SELECT transaction.* INTO STRICT existing
  FROM ONLY public.platform_saml_authentication_transactions AS transaction
  WHERE transaction.transaction_id=app.private_mfa_decode_base64_v1(
    p_request#>>'{authority,transactionId}',32,32) FOR UPDATE;
  IF existing.state='pending'
     AND existing.version=(p_request#>>'{authority,expectedVersion}')::bigint THEN
    PERFORM set_config('app.platform_saml_direct_runtime_write_v1','on',true);
    UPDATE ONLY public.platform_saml_authentication_transactions AS transaction
    SET state='failed',version=transaction.version+1,completed_at=rejected_at,
        failure_reason=reason
    WHERE transaction.transaction_id=existing.transaction_id;
    PERFORM app.private_platform_saml_direct_audit_v1(
      p_request->'audit',uuidv7(),'platform.saml.login.rejected',
      'platform_identity_provider',existing.platform_provider_id,'failure',
      jsonb_build_object('reason',reason,'transactionVersion',existing.version+1)
    );
  ELSIF existing.state NOT IN ('failed','expired','completed') THEN
    RAISE EXCEPTION 'stale direct platform SAML rejection' USING ERRCODE='40001';
  END IF;
  RETURN true;
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN RETURN true;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.cleanup_platform_saml_authentication_v1(p_request jsonb)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE existing public.platform_saml_authentication_applications%ROWTYPE;
DECLARE cleaned_at timestamptz;
DECLARE reason text;
DECLARE result jsonb;
BEGIN
  PERFORM app.private_platform_saml_direct_json_v1(
    p_request,ARRAY['result','reason','cleanedUpAt','audit'],
    ARRAY['result','reason','cleanedUpAt','audit'],131072
  );
  result:=p_request->'result';
  cleaned_at:=(p_request->>'cleanedUpAt')::timestamptz;
  reason:=p_request->>'reason';
  IF reason NOT IN ('credential_release_failed','protocol_failed','invalid_outcome','delivery_failed') THEN
    RAISE EXCEPTION 'invalid direct platform SAML cleanup' USING ERRCODE='22023';
  END IF;
  SELECT application.* INTO existing
  FROM ONLY public.platform_saml_authentication_applications AS application
  WHERE application.transaction_id=app.private_mfa_decode_base64_v1(result->>'transactionId',32,32)
    AND application.proof_digest=app.private_mfa_decode_base64_v1(result->>'proofDigest',32,32)
  FOR UPDATE;
  IF NOT FOUND THEN RETURN true; END IF;
  IF jsonb_set(existing.result_snapshot,'{category}',result->'category') IS DISTINCT FROM result
     OR result->>'category' NOT IN ('success','already_applied')
     OR cleaned_at<existing.applied_at THEN
    RAISE EXCEPTION 'direct platform SAML cleanup proof mismatch' USING ERRCODE='23505';
  END IF;
  IF existing.cleaned_up_at IS NOT NULL THEN
    IF existing.cleanup_reason<>reason THEN
      RAISE EXCEPTION 'direct platform SAML cleanup replay collision' USING ERRCODE='23505';
    END IF;
    RETURN true;
  END IF;
  PERFORM set_config('app.platform_saml_direct_runtime_write_v1','on',true);
  IF existing.session_id IS NOT NULL THEN
    UPDATE ONLY public.auth_sessions AS session
    SET revoked_at=cleaned_at,revoke_reason='saml_'||reason
    WHERE session.id=existing.session_id AND session.revoked_at IS NULL;
  ELSE
    UPDATE ONLY public.platform_saml_post_primary_continuations AS continuation
    SET state='revoked',version=continuation.version+1,revoked_at=cleaned_at,
        revoke_reason=reason
    WHERE continuation.id=existing.continuation_id AND continuation.state='pending';
  END IF;
  UPDATE ONLY public.platform_saml_authentication_applications AS application
  SET cleanup_reason=reason,cleaned_up_at=cleaned_at
  WHERE application.id=existing.id;
  PERFORM app.private_platform_saml_direct_audit_v1(
    p_request->'audit',uuidv7(),'platform.saml.login.delivery_failed',
    'platform_identity_provider',existing.platform_provider_id,'failure',
    jsonb_build_object('reason',reason)
  );
  RETURN true;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_platform_saml_totp_projection_v1(
  p_challenge public.platform_saml_post_primary_totp_challenges
)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT jsonb_build_object(
    'challengeId',replace(encode(p_challenge.id,'base64'),E'\n',''),
    'continuationId',p_challenge.continuation_id::text,
    'userId',p_challenge.user_id::text,
    'factorId',p_challenge.totp_credential_id::text,
    'expectedContinuationVersion',p_challenge.expected_continuation_version,
    'factorRevision',p_challenge.totp_security_revision,
    'userAuthenticationRevision',p_challenge.user_authentication_revision,
    'failureCount',p_challenge.failure_count,'state',p_challenge.state,
    'version',p_challenge.version,'expiresAt',to_jsonb(p_challenge.expires_at)
  );
$function$;
--> statement-breakpoint

CREATE FUNCTION app.begin_platform_saml_post_primary_totp_v1(p_request jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE continuation_id uuid;
DECLARE receipt_digest bytea;
DECLARE challenge_id bytea;
DECLARE browser_digest bytea;
DECLARE expected_version bigint;
DECLARE created_at timestamptz;
DECLARE expires_at timestamptz;
DECLARE continuation public.platform_saml_post_primary_continuations%ROWTYPE;
DECLARE challenge public.platform_saml_post_primary_totp_challenges%ROWTYPE;
BEGIN
  PERFORM app.private_platform_saml_direct_json_v1(
    p_request,ARRAY['continuationId','receiptDigest','expectedContinuationVersion',
      'challengeId','browserDigest','createdAt','expiresAt','audit'],
    ARRAY['continuationId','receiptDigest','expectedContinuationVersion',
      'challengeId','browserDigest','createdAt','expiresAt','audit'],65536
  );
  continuation_id:=app.private_mfa_require_uuidv7_v1(p_request->>'continuationId');
  receipt_digest:=app.private_mfa_decode_base64_v1(p_request->>'receiptDigest',32,32);
  challenge_id:=app.private_mfa_decode_base64_v1(p_request->>'challengeId',32,32);
  browser_digest:=app.private_mfa_decode_base64_v1(p_request->>'browserDigest',32,32);
  expected_version:=(p_request->>'expectedContinuationVersion')::bigint;
  created_at:=(p_request->>'createdAt')::timestamptz;
  expires_at:=(p_request->>'expiresAt')::timestamptz;
  IF encode(challenge_id,'hex')=repeat('00',32) OR encode(browser_digest,'hex')=repeat('00',32)
     OR challenge_id=browser_digest OR created_at NOT BETWEEN statement_timestamp()-interval '5 minutes'
       AND statement_timestamp()+interval '30 seconds'
     OR expires_at-created_at NOT BETWEEN interval '1 minute' AND interval '10 minutes' THEN
    RAISE EXCEPTION 'invalid direct platform SAML TOTP begin' USING ERRCODE='22023';
  END IF;
  SELECT parent.* INTO STRICT continuation
  FROM ONLY public.platform_saml_post_primary_continuations AS parent
  WHERE parent.id=continuation_id FOR UPDATE;
  SELECT existing.* INTO challenge
  FROM ONLY public.platform_saml_post_primary_totp_challenges AS existing
  WHERE existing.id=challenge_id FOR UPDATE;
  IF FOUND THEN
    IF challenge.id<>challenge_id OR challenge.continuation_id<>continuation_id
       OR challenge.browser_digest<>browser_digest
       OR challenge.expected_continuation_version<>expected_version
       OR challenge.expires_at<>expires_at THEN
      RAISE EXCEPTION 'direct platform SAML TOTP begin replay collision' USING ERRCODE='23505';
    END IF;
    RETURN app.private_platform_saml_totp_projection_v1(challenge);
  END IF;
  IF continuation.authority<>'direct_platform_saml'
     OR continuation.authentication_method<>'saml' OR continuation.state<>'pending'
     OR continuation.version<>expected_version OR continuation.receipt_digest<>receipt_digest
     OR continuation.expires_at<=created_at OR expires_at>continuation.expires_at
     OR NOT EXISTS (
       SELECT 1 FROM ONLY public.totp_credentials AS factor
       JOIN ONLY public.users AS local_user ON local_user.id=factor.user_id AND local_user.active
       WHERE factor.id=continuation.selected_totp_credential_id
         AND factor.user_id=continuation.user_id
         AND factor.security_revision=continuation.selected_totp_security_revision
         AND factor.confirmed_at IS NOT NULL AND factor.disabled_at IS NULL
         AND local_user.authentication_revision=continuation.user_authentication_revision
       FOR UPDATE OF factor,local_user
     ) THEN
    RAISE EXCEPTION 'stale direct platform SAML TOTP continuation' USING ERRCODE='40001';
  END IF;
  PERFORM set_config('app.platform_saml_direct_runtime_write_v1','on',true);
  SELECT existing.* INTO challenge
  FROM ONLY public.platform_saml_post_primary_totp_challenges AS existing
  WHERE existing.continuation_id=continuation_id AND existing.state='pending'
  FOR UPDATE;
  IF FOUND THEN
    UPDATE ONLY public.platform_saml_post_primary_totp_challenges AS superseded
    SET state='abandoned',version=superseded.version+1,abandoned_at=created_at
    WHERE superseded.id=challenge.id AND superseded.state='pending';
  END IF;
  INSERT INTO public.platform_saml_post_primary_totp_challenges (
    id,continuation_id,user_id,totp_credential_id,browser_digest,
    expected_continuation_version,user_authentication_revision,
    totp_security_revision,failure_count,state,version,created_at,expires_at
  ) VALUES (
    challenge_id,continuation.id,continuation.user_id,
    continuation.selected_totp_credential_id,browser_digest,expected_version,
    continuation.user_authentication_revision,continuation.selected_totp_security_revision,
    0,'pending',1,created_at,expires_at
  ) RETURNING * INTO challenge;
  PERFORM app.private_platform_saml_direct_audit_v1(
    p_request->'audit',uuidv7(),'platform.saml.totp.started',
    'platform_identity_provider',continuation.platform_provider_id,'success',
    jsonb_build_object('continuationVersion',expected_version,'challengeVersion',1)
  );
  RETURN app.private_platform_saml_totp_projection_v1(challenge);
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'stale direct platform SAML TOTP continuation' USING ERRCODE='40001';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.load_platform_saml_post_primary_totp_v1(p_lookup jsonb)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE challenge_id bytea;
DECLARE continuation_id uuid;
DECLARE receipt_digest bytea;
DECLARE browser_digest bytea;
DECLARE observed_at timestamptz;
DECLARE result jsonb;
BEGIN
  PERFORM app.private_platform_saml_direct_json_v1(
    p_lookup,ARRAY['challengeId','continuationId','receiptDigest','browserDigest','observedAt'],
    ARRAY['challengeId','continuationId','receiptDigest','browserDigest','observedAt'],32768
  );
  challenge_id:=app.private_mfa_decode_base64_v1(p_lookup->>'challengeId',32,32);
  continuation_id:=app.private_mfa_require_uuidv7_v1(p_lookup->>'continuationId');
  receipt_digest:=app.private_mfa_decode_base64_v1(p_lookup->>'receiptDigest',32,32);
  browser_digest:=app.private_mfa_decode_base64_v1(p_lookup->>'browserDigest',32,32);
  observed_at:=(p_lookup->>'observedAt')::timestamptz;
  SELECT app.private_platform_saml_totp_projection_v1(challenge)||jsonb_build_object(
    'receiptDigest',replace(encode(continuation.receipt_digest,'base64'),E'\n',''),
    'secret',jsonb_build_object(
      'ciphertext',replace(encode(factor.secret_ciphertext,'base64'),E'\n',''),
      'nonce',replace(encode(factor.secret_nonce,'base64'),E'\n',''),
      'aad',replace(encode(factor.secret_aad,'base64'),E'\n',''),
      'keyVersion',factor.key_version,'encryptionAlgorithm',factor.encryption_algorithm,
      'otpAlgorithm',factor.otp_algorithm,'digits',factor.digits,
      'periodSeconds',factor.period_seconds
    ),'lastAcceptedCounter',factor.last_accepted_counter
  ) INTO result
  FROM ONLY public.platform_saml_post_primary_totp_challenges AS challenge
  JOIN ONLY public.platform_saml_post_primary_continuations AS continuation
    ON continuation.id=challenge.continuation_id AND continuation.user_id=challenge.user_id
   AND continuation.authority='direct_platform_saml'
   AND continuation.authentication_method='saml'
  JOIN ONLY public.totp_credentials AS factor
    ON factor.id=challenge.totp_credential_id AND factor.user_id=challenge.user_id
  JOIN ONLY public.users AS local_user ON local_user.id=challenge.user_id
  WHERE challenge.id=challenge_id AND challenge.continuation_id=continuation_id
    AND challenge.browser_digest=browser_digest AND continuation.receipt_digest=receipt_digest
    AND challenge.state='pending' AND challenge.expires_at>observed_at
    AND continuation.state='pending' AND continuation.expires_at>observed_at
    AND continuation.version=challenge.expected_continuation_version
    AND factor.security_revision=challenge.totp_security_revision
    AND factor.confirmed_at IS NOT NULL AND factor.disabled_at IS NULL
    AND local_user.active
    AND local_user.authentication_revision=challenge.user_authentication_revision;
  RETURN result;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.record_platform_saml_post_primary_totp_failure_v1(p_request jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE challenge public.platform_saml_post_primary_totp_challenges%ROWTYPE;
DECLARE continuation public.platform_saml_post_primary_continuations%ROWTYPE;
DECLARE observed_at timestamptz;
BEGIN
  observed_at:=(p_request->>'observedAt')::timestamptz;
  SELECT existing.* INTO STRICT challenge
  FROM ONLY public.platform_saml_post_primary_totp_challenges AS existing
  WHERE existing.id=app.private_mfa_decode_base64_v1(p_request->>'challengeId',32,32)
    AND existing.continuation_id=app.private_mfa_require_uuidv7_v1(p_request->>'continuationId')
  FOR UPDATE;
  SELECT parent.* INTO STRICT continuation
  FROM ONLY public.platform_saml_post_primary_continuations AS parent
  WHERE parent.id=challenge.continuation_id FOR UPDATE;
  IF challenge.browser_digest<>app.private_mfa_decode_base64_v1(p_request->>'browserDigest',32,32)
     OR continuation.receipt_digest<>app.private_mfa_decode_base64_v1(p_request->>'receiptDigest',32,32)
     OR challenge.expected_continuation_version<>(p_request->>'expectedContinuationVersion')::bigint
     OR challenge.totp_security_revision<>(p_request->>'expectedFactorRevision')::bigint
     OR challenge.user_authentication_revision<>(p_request->>'expectedUserAuthenticationRevision')::bigint THEN
    RAISE EXCEPTION 'direct platform SAML TOTP failure proof mismatch' USING ERRCODE='23505';
  END IF;
  IF challenge.state<>'pending' OR challenge.version<>(p_request->>'expectedChallengeVersion')::bigint THEN
    RETURN app.private_platform_saml_totp_projection_v1(challenge);
  END IF;
  PERFORM set_config('app.platform_saml_direct_runtime_write_v1','on',true);
  UPDATE ONLY public.platform_saml_post_primary_totp_challenges AS changed
  SET failure_count=changed.failure_count+1,version=changed.version+1,
      state=CASE WHEN changed.failure_count+1>=5 THEN 'failed' ELSE 'pending' END,
      abandoned_at=CASE WHEN changed.failure_count+1>=5 THEN observed_at ELSE NULL END
  WHERE changed.id=challenge.id RETURNING * INTO challenge;
  IF challenge.state='failed' THEN
    UPDATE ONLY public.platform_saml_post_primary_continuations AS parent
    SET state='revoked',version=parent.version+1,revoked_at=observed_at,
        revoke_reason='totp_failed'
    WHERE parent.id=continuation.id AND parent.state='pending';
  END IF;
  PERFORM app.private_platform_saml_direct_audit_v1(
    p_request->'audit',uuidv7(),'platform.saml.totp.failed',
    'platform_identity_provider',continuation.platform_provider_id,'failure',
    jsonb_build_object('failureCount',challenge.failure_count,'terminal',challenge.state='failed')
  );
  RETURN app.private_platform_saml_totp_projection_v1(challenge);
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'stale direct platform SAML TOTP challenge' USING ERRCODE='40001';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.apply_platform_saml_post_primary_totp_v1(p_request jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE challenge public.platform_saml_post_primary_totp_challenges%ROWTYPE;
DECLARE continuation public.platform_saml_post_primary_continuations%ROWTYPE;
DECLARE factor public.totp_credentials%ROWTYPE;
DECLARE completion_digest bytea;
DECLARE observed_at timestamptz;
DECLARE accepted_counter bigint;
DECLARE session_id uuid;
DECLARE result jsonb;
DECLARE plan jsonb;
DECLARE floor public.mfa_policy_revisions%ROWTYPE;
DECLARE provider_evidence public.platform_saml_post_primary_continuation_evidence%ROWTYPE;
BEGIN
  completion_digest:=app.private_mfa_decode_base64_v1(p_request->>'completionRequestDigest',32,32);
  observed_at:=(p_request->>'observedAt')::timestamptz;
  accepted_counter:=(p_request->>'acceptedCounter')::bigint;
  session_id:=app.private_mfa_require_uuidv7_v1(p_request#>>'{session,id}');
  SELECT existing.* INTO STRICT challenge
  FROM ONLY public.platform_saml_post_primary_totp_challenges AS existing
  WHERE existing.id=app.private_mfa_decode_base64_v1(p_request->>'challengeId',32,32)
    AND existing.continuation_id=app.private_mfa_require_uuidv7_v1(p_request->>'continuationId')
  FOR UPDATE;
  SELECT parent.* INTO STRICT continuation FROM ONLY public.platform_saml_post_primary_continuations AS parent
  WHERE parent.id=challenge.continuation_id FOR UPDATE;
  SELECT current_factor.* INTO STRICT factor FROM ONLY public.totp_credentials AS current_factor
  WHERE current_factor.id=challenge.totp_credential_id AND current_factor.user_id=challenge.user_id FOR UPDATE;
  result:=jsonb_build_object(
    'category','stale','sessionId',session_id::text,'userId',challenge.user_id::text,
    'factorId',challenge.totp_credential_id::text,
    'factorRevision',challenge.totp_security_revision,
    'userAuthenticationRevision',challenge.user_authentication_revision,
    'acceptedCounter',accepted_counter,'completedAt',to_jsonb(observed_at)
  );
  IF challenge.state='completed' THEN
    IF challenge.completion_request_digest<>completion_digest
       OR challenge.completion_request_snapshot IS DISTINCT FROM p_request-'audit'
       OR challenge.result_snapshot IS NULL
       OR challenge.result_snapshot-'category' IS DISTINCT FROM result-'category' THEN
      RAISE EXCEPTION 'direct platform SAML TOTP apply replay collision' USING ERRCODE='23505';
    END IF;
    RETURN jsonb_set(challenge.result_snapshot,'{category}','"already_applied"'::jsonb);
  END IF;
  IF challenge.browser_digest<>app.private_mfa_decode_base64_v1(p_request->>'browserDigest',32,32)
     OR continuation.receipt_digest<>app.private_mfa_decode_base64_v1(p_request->>'receiptDigest',32,32)
     OR challenge.expected_continuation_version<>(p_request->>'expectedContinuationVersion')::bigint
     OR challenge.totp_security_revision<>(p_request->>'expectedFactorRevision')::bigint
     OR challenge.user_authentication_revision<>(p_request->>'expectedUserAuthenticationRevision')::bigint
     OR challenge.version<>(p_request->>'expectedChallengeVersion')::bigint
     OR challenge.state<>'pending' OR challenge.expires_at<=observed_at
     OR continuation.state<>'pending' OR continuation.version<>challenge.expected_continuation_version
     OR continuation.expires_at<=observed_at OR factor.security_revision<>challenge.totp_security_revision
     OR factor.confirmed_at IS NULL OR factor.disabled_at IS NOT NULL THEN
    RETURN result;
  END IF;
  IF factor.last_accepted_counter IS NOT NULL AND accepted_counter<=factor.last_accepted_counter THEN
    RETURN jsonb_set(result,'{category}','"replay"'::jsonb);
  END IF;
  SELECT policy.* INTO STRICT floor FROM ONLY public.mfa_policy_revisions AS policy
  WHERE policy.id=continuation.platform_floor_policy_id
    AND policy.revision=continuation.platform_floor_policy_revision
    AND policy.scope='platform_floor' AND policy.tenant_id IS NULL AND policy.retired_at IS NULL FOR SHARE;
  SELECT evidence.* INTO STRICT provider_evidence
  FROM ONLY public.platform_saml_post_primary_continuation_evidence AS evidence
  WHERE evidence.continuation_id=continuation.id AND evidence.kind='platform_provider';
  plan:=jsonb_build_object(
    'pins',jsonb_build_object(
      'protocol',app.private_platform_saml_direct_pins_v1(
        continuation.platform_provider_id,continuation.provider_revision,
        continuation.login_policy_revision,continuation.configuration_revision,
        continuation.security_revision,continuation.plan_revision,
        continuation.assurance_policy_revision,continuation.metadata_revision,
        continuation.metadata_digest,continuation.sp_key_revision,continuation.configuration_digest),
      'platformFloorPolicyId',continuation.platform_floor_policy_id::text,
      'platformFloorPolicyRevision',continuation.platform_floor_policy_revision),
    'provenance',jsonb_build_object(
      'provider',jsonb_build_object('scope','platform','providerId',continuation.platform_provider_id::text),
      'externalIdentityId',continuation.external_identity_id::text,'userId',continuation.user_id::text,
      'identityRevision',continuation.identity_version,
      'userAuthenticationRevision',continuation.user_authentication_revision,
      'platformAuthorityId',continuation.platform_authority_id::text,
      'platformAuthorityRevision',continuation.platform_authority_revision,
      'matchedAliasKeyVersion',continuation.alias_key_version,
      'authenticatedAt',to_jsonb(provider_evidence.authenticated_at),
      'validUntil',to_jsonb(coalesce(provider_evidence.expires_at,continuation.expires_at)),
      'selectedAssurance',jsonb_strip_nulls(jsonb_build_object(
        'level',provider_evidence.level,'authenticatedAt',to_jsonb(provider_evidence.authenticated_at),
        'trustRuleId',CASE WHEN continuation.trust_rule_id IS NULL THEN NULL ELSE continuation.trust_rule_id::text END,
        'trustRuleRevision',continuation.trust_rule_revision))),
    'platformFloor',jsonb_build_object(
      'level',floor.level,'localRequired',floor.local_required,
      'freshnessNanoseconds',floor.freshness_nanoseconds,
      'enrollmentDeadline',to_jsonb(floor.enrollment_deadline))
  );
  PERFORM app.private_platform_saml_create_session_v1(
    p_request->'session',plan,'api',observed_at,challenge.totp_credential_id,
    challenge.totp_security_revision,observed_at
  );
  PERFORM set_config('app.platform_saml_direct_runtime_write_v1','on',true);
  UPDATE ONLY public.totp_credentials AS changed
  SET last_accepted_counter=accepted_counter,updated_at=observed_at
  WHERE changed.id=factor.id AND changed.security_revision=factor.security_revision;
  UPDATE ONLY public.platform_saml_post_primary_continuations AS parent
  SET state='consumed',version=parent.version+1,consumed_at=observed_at
  WHERE parent.id=continuation.id AND parent.state='pending'
    AND parent.version=challenge.expected_continuation_version;
  result:=jsonb_set(result,'{category}','"success"'::jsonb);
  UPDATE ONLY public.platform_saml_post_primary_totp_challenges AS changed
  SET state='completed',version=changed.version+1,
      completion_request_digest=completion_digest,
      completion_request_snapshot=p_request-'audit',result_snapshot=result,
      completed_at=observed_at
  WHERE changed.id=challenge.id AND changed.state='pending'
    AND changed.version=challenge.version;
  PERFORM app.private_platform_saml_direct_audit_v1(
    p_request->'audit',uuidv7(),'platform.saml.totp.completed',
    'platform_identity_provider',continuation.platform_provider_id,'success',
    jsonb_build_object('factorRevision',challenge.totp_security_revision)
  );
  RETURN result;
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RETURN result;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.recover_platform_saml_post_primary_totp_apply_v1(p_request jsonb)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE challenge public.platform_saml_post_primary_totp_challenges%ROWTYPE;
DECLARE expected jsonb;
BEGIN
  SELECT existing.* INTO challenge
  FROM ONLY public.platform_saml_post_primary_totp_challenges AS existing
  WHERE existing.id=app.private_mfa_decode_base64_v1(p_request->>'challengeId',32,32)
    AND existing.continuation_id=app.private_mfa_require_uuidv7_v1(p_request->>'continuationId')
    AND existing.completion_request_digest=app.private_mfa_decode_base64_v1(
      p_request->>'completionRequestDigest',32,32)
    AND existing.completion_request_snapshot IS NOT DISTINCT FROM p_request-'audit'
    AND existing.state='completed';
  IF NOT FOUND THEN RETURN jsonb_build_object('matched',false); END IF;
  expected:=jsonb_build_object(
    'sessionId',p_request#>>'{session,id}','userId',challenge.user_id::text,
    'factorId',challenge.totp_credential_id::text,
    'factorRevision',(p_request->>'expectedFactorRevision')::bigint,
    'userAuthenticationRevision',(p_request->>'expectedUserAuthenticationRevision')::bigint,
    'acceptedCounter',(p_request->>'acceptedCounter')::bigint,
    'completedAt',to_jsonb((p_request->>'observedAt')::timestamptz)
  );
  IF challenge.result_snapshot-'category' IS DISTINCT FROM expected THEN
    RETURN jsonb_build_object('matched',false);
  END IF;
  RETURN jsonb_build_object('matched',true,'result',
    jsonb_set(challenge.result_snapshot,'{category}','"already_applied"'::jsonb));
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.abandon_platform_saml_post_primary_totp_v1(p_request jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE challenge public.platform_saml_post_primary_totp_challenges%ROWTYPE;
DECLARE continuation public.platform_saml_post_primary_continuations%ROWTYPE;
DECLARE observed_at timestamptz;
DECLARE reason text;
BEGIN
  observed_at:=(p_request->>'observedAt')::timestamptz;
  reason:=p_request->>'reason';
  IF reason NOT IN ('cancelled','expired','superseded') THEN
    RAISE EXCEPTION 'invalid direct platform SAML TOTP abandon reason' USING ERRCODE='22023';
  END IF;
  SELECT existing.* INTO STRICT challenge FROM ONLY public.platform_saml_post_primary_totp_challenges AS existing
  WHERE existing.id=app.private_mfa_decode_base64_v1(p_request->>'challengeId',32,32)
    AND existing.continuation_id=app.private_mfa_require_uuidv7_v1(p_request->>'continuationId') FOR UPDATE;
  SELECT parent.* INTO STRICT continuation FROM ONLY public.platform_saml_post_primary_continuations AS parent
  WHERE parent.id=challenge.continuation_id FOR UPDATE;
  IF challenge.state='pending' AND challenge.version=(p_request->>'expectedChallengeVersion')::bigint THEN
    PERFORM set_config('app.platform_saml_direct_runtime_write_v1','on',true);
    UPDATE ONLY public.platform_saml_post_primary_totp_challenges AS changed
    SET state=CASE WHEN reason='expired' THEN 'expired' ELSE 'abandoned' END,
        version=changed.version+1,abandoned_at=observed_at
    WHERE changed.id=challenge.id RETURNING * INTO challenge;
    UPDATE ONLY public.platform_saml_post_primary_continuations AS parent
    SET state=CASE WHEN reason='expired' THEN 'expired' ELSE 'revoked' END,
        version=parent.version+1,revoked_at=observed_at,revoke_reason=reason
    WHERE parent.id=continuation.id AND parent.state='pending';
    PERFORM app.private_platform_saml_direct_audit_v1(
      p_request->'audit',uuidv7(),'platform.saml.totp.abandoned',
      'platform_identity_provider',continuation.platform_provider_id,'failure',
      jsonb_build_object('reason',reason)
    );
  END IF;
  RETURN app.private_platform_saml_totp_projection_v1(challenge);
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.cleanup_platform_saml_post_primary_totp_apply_v1(p_request jsonb)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE challenge public.platform_saml_post_primary_totp_challenges%ROWTYPE;
DECLARE result jsonb:=p_request->'result';
DECLARE original jsonb:=p_request->'request';
DECLARE cleaned_at timestamptz:=(p_request->>'cleanedUpAt')::timestamptz;
DECLARE provider_id uuid;
BEGIN
  IF p_request->>'reason'<>'delivery_failed' THEN
    RAISE EXCEPTION 'invalid direct platform SAML TOTP cleanup reason' USING ERRCODE='22023';
  END IF;
  SELECT existing.* INTO challenge FROM ONLY public.platform_saml_post_primary_totp_challenges AS existing
  WHERE existing.id=app.private_mfa_decode_base64_v1(original->>'challengeId',32,32)
    AND existing.continuation_id=app.private_mfa_require_uuidv7_v1(original->>'continuationId') FOR UPDATE;
  IF NOT FOUND THEN RETURN true; END IF;
  SELECT parent.platform_provider_id INTO provider_id
  FROM ONLY public.platform_saml_post_primary_continuations AS parent
  WHERE parent.id=challenge.continuation_id;
  IF challenge.state='completed' THEN
    IF challenge.completion_request_digest<>app.private_mfa_decode_base64_v1(
         original->>'completionRequestDigest',32,32)
       OR challenge.completion_request_snapshot IS DISTINCT FROM original-'audit'
       OR jsonb_set(challenge.result_snapshot,'{category}',result->'category') IS DISTINCT FROM result THEN
      RAISE EXCEPTION 'direct platform SAML TOTP cleanup proof mismatch' USING ERRCODE='23505';
    END IF;
    UPDATE ONLY public.auth_sessions AS session
    SET revoked_at=coalesce(session.revoked_at,cleaned_at),
        revoke_reason=coalesce(session.revoke_reason,'saml_totp_delivery_failed')
    WHERE session.id=app.private_mfa_require_uuidv7_v1(result->>'sessionId');
    PERFORM set_config('app.platform_saml_direct_runtime_write_v1','on',true);
    UPDATE ONLY public.platform_saml_post_primary_totp_challenges AS changed
    SET state='failed',version=changed.version+1,completed_at=NULL,
        abandoned_at=cleaned_at,completion_request_digest=NULL,
        completion_request_snapshot=NULL,result_snapshot=NULL
    WHERE changed.id=challenge.id AND changed.state='completed';
    PERFORM app.private_platform_saml_direct_audit_v1(
      p_request->'audit',uuidv7(),'platform.saml.totp.delivery_failed',
      'platform_identity_provider',provider_id,'failure','{}'::jsonb
    );
  END IF;
  RETURN true;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_platform_saml_administration_fence_v1(
  p_provider_id uuid,p_changed_at timestamptz
)
RETURNS bigint
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE next_login_revision bigint;
BEGIN
  PERFORM set_config('app.platform_saml_direct_policy_write_v1','on',true);
  UPDATE ONLY public.platform_saml_login_policies AS login_policy
  SET enabled=false,account_mode='disabled',revision=login_policy.revision+1,
      updated_at=p_changed_at
  WHERE login_policy.provider_id=p_provider_id
    AND login_policy.provider_kind='saml' AND login_policy.revision<9007199254740991
  RETURNING login_policy.revision INTO STRICT next_login_revision;
  PERFORM set_config('app.platform_saml_direct_policy_write_v1','',true);
  PERFORM set_config('app.platform_saml_direct_runtime_write_v1','on',true);
  UPDATE ONLY public.platform_saml_authentication_transactions AS transaction
  SET state='failed',version=transaction.version+1,completed_at=p_changed_at,
      failure_reason='configuration_replaced'
  WHERE transaction.platform_provider_id=p_provider_id AND transaction.state='pending';
  UPDATE ONLY public.platform_saml_post_primary_totp_challenges AS challenge
  SET state='abandoned',version=challenge.version+1,abandoned_at=p_changed_at
  FROM ONLY public.platform_saml_post_primary_continuations AS continuation
  WHERE continuation.id=challenge.continuation_id
    AND continuation.platform_provider_id=p_provider_id AND challenge.state='pending';
  UPDATE ONLY public.platform_saml_post_primary_continuations AS continuation
  SET state='revoked',version=continuation.version+1,revoked_at=p_changed_at,
      revoke_reason='configuration_replaced'
  WHERE continuation.platform_provider_id=p_provider_id AND continuation.state='pending';
  UPDATE ONLY public.auth_sessions AS session
  SET revoked_at=p_changed_at,revoke_reason='platform_saml_configuration_replaced'
  FROM ONLY public.auth_session_platform_saml_provenance AS provenance
  WHERE provenance.session_id=session.id
    AND provenance.platform_provider_id=p_provider_id AND session.revoked_at IS NULL;
  RETURN next_login_revision;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.replace_platform_saml_sp_key_v1(
  p_session_id uuid,p_provider_id uuid,p_key_id uuid,p_expected_version bigint,
  p_key_version integer,p_nonce bytea,p_ciphertext bytea,p_certificates bytea[],
  p_audit_event_id uuid,p_request_id uuid,p_correlation_id uuid,p_ip_address inet,
  p_user_agent text,p_authentication_method text,p_reason text
)
RETURNS TABLE(version bigint,key_revision bigint)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE actor_id uuid;
DECLARE read_actor_id uuid;
DECLARE provider_record public.platform_auth_providers%ROWTYPE;
DECLARE runtime_record public.platform_federated_provider_policies%ROWTYPE;
DECLARE configuration_record public.platform_saml_provider_configurations%ROWTYPE;
DECLARE next_revision bigint;
DECLARE changed_at timestamptz:=date_trunc('milliseconds',transaction_timestamp());
DECLARE sequence integer;
BEGIN
  IF uuid_extract_version(p_provider_id) IS DISTINCT FROM 7
     OR uuid_extract_version(p_key_id) IS DISTINCT FROM 7
     OR p_expected_version NOT BETWEEN 1 AND 2147483646
     OR p_key_version NOT BETWEEN 1 AND 32767 OR octet_length(p_nonce)<>12
     OR octet_length(p_ciphertext) NOT BETWEEN 17 AND 131072
     OR cardinality(p_certificates) NOT BETWEEN 1 AND 8
     OR array_position(p_certificates,NULL) IS NOT NULL
     OR EXISTS (SELECT 1 FROM unnest(p_certificates) AS certificate(value)
                WHERE octet_length(certificate.value) NOT BETWEEN 1 AND 65536)
     OR (SELECT count(*) FROM (SELECT DISTINCT value FROM unnest(p_certificates) AS certificate(value)) AS distinct_certificates)
        <> cardinality(p_certificates)
     OR uuid_extract_version(p_audit_event_id) IS DISTINCT FROM 7
     OR uuid_extract_version(p_request_id) IS DISTINCT FROM 7
     OR uuid_extract_version(p_correlation_id) IS DISTINCT FROM 7
     OR p_ip_address IS NULL OR octet_length(p_user_agent) NOT BETWEEN 1 AND 512
     OR NOT app.private_platform_identity_text_is_safe_v1(p_user_agent,false)
     OR NOT app.private_platform_lifecycle_reason_is_valid_v1(p_reason) THEN
    RAISE EXCEPTION 'invalid platform SAML SP-key command' USING ERRCODE='22023';
  END IF;
  actor_id:=app.private_require_platform_identity_permission_v1(
    p_session_id,'platform.identity_provider.manage',p_authentication_method);
  read_actor_id:=app.private_require_platform_identity_permission_v1(
    p_session_id,'platform.identity_provider.read',p_authentication_method);
  IF actor_id IS DISTINCT FROM read_actor_id THEN
    RAISE EXCEPTION 'live platform identity-provider authority is required' USING ERRCODE='42501';
  END IF;
  SELECT provider.* INTO STRICT provider_record FROM ONLY public.platform_auth_providers AS provider
  WHERE provider.id=p_provider_id FOR UPDATE;
  SELECT runtime_policy.* INTO STRICT runtime_record
  FROM ONLY public.platform_federated_provider_policies AS runtime_policy
  WHERE runtime_policy.provider_id=p_provider_id AND runtime_policy.provider_kind='saml' FOR UPDATE;
  SELECT configuration.* INTO STRICT configuration_record
  FROM ONLY public.platform_saml_provider_configurations AS configuration
  WHERE configuration.provider_id=p_provider_id FOR UPDATE;
  IF provider_record.version<>p_expected_version THEN
    RAISE EXCEPTION 'platform identity provider revision conflict' USING ERRCODE='40001';
  END IF;
  IF provider_record.kind<>'saml' OR provider_record.archived_at IS NOT NULL THEN
    RAISE EXCEPTION 'platform identity provider is not a live SAML provider' USING ERRCODE='55000';
  END IF;
  IF configuration_record.sp_key_revision>=9007199254740991
     OR configuration_record.version>=9007199254740991
     OR runtime_record.configuration_revision>=9007199254740991
     OR runtime_record.security_revision>=9007199254740991 THEN
    RAISE EXCEPTION 'platform SAML revision is exhausted' USING ERRCODE='55000';
  END IF;
  PERFORM 1 FROM ONLY public.identity_keyring_versions AS keyring
  WHERE keyring.key_version=p_key_version AND keyring.is_active AND keyring.retired_at IS NULL FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'identity key version is unavailable' USING ERRCODE='55000'; END IF;
  next_revision:=configuration_record.sp_key_revision+1;
  PERFORM app.private_platform_saml_administration_fence_v1(p_provider_id,changed_at);
  UPDATE ONLY public.platform_saml_sp_keys AS old_key
  SET retired_at=changed_at WHERE old_key.provider_id=p_provider_id AND old_key.retired_at IS NULL;
  INSERT INTO public.platform_saml_sp_keys(
    id,provider_id,revision,key_version,nonce,ciphertext,created_at
  ) VALUES (p_key_id,p_provider_id,next_revision,p_key_version,p_nonce,p_ciphertext,changed_at);
  FOR sequence IN 1..cardinality(p_certificates) LOOP
    INSERT INTO public.platform_saml_sp_certificates(key_id,sequence,certificate_der)
    VALUES(p_key_id,sequence-1,p_certificates[sequence]);
  END LOOP;
  UPDATE ONLY public.platform_saml_provider_configurations AS configuration
  SET sp_key_revision=next_revision,version=configuration.version+1,updated_at=changed_at
  WHERE configuration.provider_id=p_provider_id;
  UPDATE ONLY public.platform_federated_provider_policies AS runtime_policy
  SET configuration_revision=runtime_policy.configuration_revision+1,
      security_revision=runtime_policy.security_revision+1,
      platform_login_enabled=false,updated_at=changed_at
  WHERE runtime_policy.provider_id=p_provider_id;
  UPDATE ONLY public.platform_auth_providers AS provider
  SET updated_by_user_id=actor_id,version=provider.version+1,updated_at=changed_at
  WHERE provider.id=p_provider_id AND provider.version=p_expected_version;
  PERFORM app.append_platform_audit_event(
    p_audit_event_id,'user',actor_id,'platform.identity_provider.saml_sp_key_replaced',
    'platform_identity_provider',p_provider_id,p_request_id,p_correlation_id,
    p_ip_address,p_user_agent,p_authentication_method,'success',p_reason,
    jsonb_build_object('kind','saml','previousVersion',provider_record.version,
      'version',provider_record.version+1,'keyRevision',next_revision,
      'certificateCount',cardinality(p_certificates),'protectedMaterialIncluded',true,
      'platformLoginEnabled',false)
  );
  RETURN QUERY SELECT provider_record.version+1,next_revision;
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'platform SAML administration dependency is unavailable' USING ERRCODE='55000';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.clear_platform_saml_sp_key_v1(
  p_session_id uuid,p_provider_id uuid,p_expected_version bigint,
  p_audit_event_id uuid,p_request_id uuid,p_correlation_id uuid,p_ip_address inet,
  p_user_agent text,p_authentication_method text,p_reason text
)
RETURNS TABLE(version bigint,key_revision bigint)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE actor_id uuid;
DECLARE read_actor_id uuid;
DECLARE provider_record public.platform_auth_providers%ROWTYPE;
DECLARE runtime_record public.platform_federated_provider_policies%ROWTYPE;
DECLARE configuration_record public.platform_saml_provider_configurations%ROWTYPE;
DECLARE next_revision bigint;
DECLARE changed_at timestamptz:=date_trunc('milliseconds',transaction_timestamp());
BEGIN
  IF uuid_extract_version(p_provider_id) IS DISTINCT FROM 7
     OR p_expected_version NOT BETWEEN 1 AND 2147483646
     OR uuid_extract_version(p_audit_event_id) IS DISTINCT FROM 7
     OR uuid_extract_version(p_request_id) IS DISTINCT FROM 7
     OR uuid_extract_version(p_correlation_id) IS DISTINCT FROM 7
     OR p_ip_address IS NULL OR octet_length(p_user_agent) NOT BETWEEN 1 AND 512
     OR NOT app.private_platform_identity_text_is_safe_v1(p_user_agent,false)
     OR NOT app.private_platform_lifecycle_reason_is_valid_v1(p_reason) THEN
    RAISE EXCEPTION 'invalid platform SAML SP-key clear command' USING ERRCODE='22023';
  END IF;
  actor_id:=app.private_require_platform_identity_permission_v1(
    p_session_id,'platform.identity_provider.manage',p_authentication_method);
  read_actor_id:=app.private_require_platform_identity_permission_v1(
    p_session_id,'platform.identity_provider.read',p_authentication_method);
  IF actor_id IS DISTINCT FROM read_actor_id THEN RAISE EXCEPTION 'live platform identity-provider authority is required' USING ERRCODE='42501'; END IF;
  SELECT provider.* INTO STRICT provider_record FROM ONLY public.platform_auth_providers AS provider
  WHERE provider.id=p_provider_id FOR UPDATE;
  SELECT runtime_policy.* INTO STRICT runtime_record FROM ONLY public.platform_federated_provider_policies AS runtime_policy
  WHERE runtime_policy.provider_id=p_provider_id AND runtime_policy.provider_kind='saml' FOR UPDATE;
  SELECT configuration.* INTO STRICT configuration_record FROM ONLY public.platform_saml_provider_configurations AS configuration
  WHERE configuration.provider_id=p_provider_id FOR UPDATE;
  IF provider_record.version<>p_expected_version THEN RAISE EXCEPTION 'platform identity provider revision conflict' USING ERRCODE='40001'; END IF;
  IF provider_record.kind<>'saml' OR provider_record.archived_at IS NOT NULL
     OR NOT EXISTS(SELECT 1 FROM ONLY public.platform_saml_sp_keys AS active_key
                   WHERE active_key.provider_id=p_provider_id AND active_key.retired_at IS NULL) THEN
    RAISE EXCEPTION 'platform SAML SP key is unavailable' USING ERRCODE='55000';
  END IF;
  IF configuration_record.sp_key_revision>=9007199254740991
     OR configuration_record.version>=9007199254740991
     OR runtime_record.configuration_revision>=9007199254740991
     OR runtime_record.security_revision>=9007199254740991 THEN
    RAISE EXCEPTION 'platform SAML revision is exhausted' USING ERRCODE='55000';
  END IF;
  next_revision:=configuration_record.sp_key_revision+1;
  PERFORM app.private_platform_saml_administration_fence_v1(p_provider_id,changed_at);
  UPDATE ONLY public.platform_saml_sp_keys AS active_key SET retired_at=changed_at
  WHERE active_key.provider_id=p_provider_id AND active_key.retired_at IS NULL;
  UPDATE ONLY public.platform_saml_provider_configurations AS configuration
  SET sp_key_revision=next_revision,version=configuration.version+1,updated_at=changed_at
  WHERE configuration.provider_id=p_provider_id;
  UPDATE ONLY public.platform_federated_provider_policies AS runtime_policy
  SET configuration_revision=runtime_policy.configuration_revision+1,
      security_revision=runtime_policy.security_revision+1,
      platform_login_enabled=false,updated_at=changed_at
  WHERE runtime_policy.provider_id=p_provider_id;
  UPDATE ONLY public.platform_auth_providers AS provider
  SET updated_by_user_id=actor_id,version=provider.version+1,updated_at=changed_at
  WHERE provider.id=p_provider_id AND provider.version=p_expected_version;
  PERFORM app.append_platform_audit_event(
    p_audit_event_id,'user',actor_id,'platform.identity_provider.saml_sp_key_cleared',
    'platform_identity_provider',p_provider_id,p_request_id,p_correlation_id,
    p_ip_address,p_user_agent,p_authentication_method,'success',p_reason,
    jsonb_build_object('kind','saml','previousVersion',provider_record.version,
      'version',provider_record.version+1,'keyRevision',next_revision,
      'protectedMaterialIncluded',false,'platformLoginEnabled',false)
  );
  RETURN QUERY SELECT provider_record.version+1,next_revision;
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'platform SAML administration dependency is unavailable' USING ERRCODE='55000';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.replace_platform_saml_metadata_v1(
  p_session_id uuid,p_provider_id uuid,p_expected_version bigint,p_document bytea,
  p_document_digest bytea,p_retrieved_at timestamptz,p_maximum_valid_until timestamptz,
  p_protected_approval boolean,p_audit_event_id uuid,p_request_id uuid,p_correlation_id uuid,
  p_ip_address inet,p_user_agent text,p_authentication_method text,p_reason text
)
RETURNS TABLE(version bigint,metadata_revision bigint)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE actor_id uuid;
DECLARE read_actor_id uuid;
DECLARE provider_record public.platform_auth_providers%ROWTYPE;
DECLARE runtime_record public.platform_federated_provider_policies%ROWTYPE;
DECLARE configuration_record public.platform_saml_provider_configurations%ROWTYPE;
DECLARE next_revision bigint;
DECLARE changed_at timestamptz:=date_trunc('milliseconds',transaction_timestamp());
BEGIN
  IF uuid_extract_version(p_provider_id) IS DISTINCT FROM 7
     OR p_expected_version NOT BETWEEN 1 AND 2147483646
     OR octet_length(p_document) NOT BETWEEN 1 AND 524288
     OR octet_length(p_document_digest)<>32 OR sha256(p_document)<>p_document_digest
     OR p_retrieved_at<>date_trunc('milliseconds',p_retrieved_at)
     OR p_maximum_valid_until<>date_trunc('milliseconds',p_maximum_valid_until)
     OR p_retrieved_at NOT BETWEEN statement_timestamp()-interval '1 hour'
                                AND statement_timestamp()+interval '30 seconds'
     OR p_maximum_valid_until<=p_retrieved_at OR p_protected_approval IS NULL
     OR uuid_extract_version(p_audit_event_id) IS DISTINCT FROM 7
     OR uuid_extract_version(p_request_id) IS DISTINCT FROM 7
     OR uuid_extract_version(p_correlation_id) IS DISTINCT FROM 7
     OR p_ip_address IS NULL OR octet_length(p_user_agent) NOT BETWEEN 1 AND 512
     OR NOT app.private_platform_identity_text_is_safe_v1(p_user_agent,false)
     OR NOT app.private_platform_lifecycle_reason_is_valid_v1(p_reason) THEN
    RAISE EXCEPTION 'invalid platform SAML metadata command' USING ERRCODE='22023';
  END IF;
  actor_id:=app.private_require_platform_identity_permission_v1(
    p_session_id,'platform.identity_provider.manage',p_authentication_method);
  read_actor_id:=app.private_require_platform_identity_permission_v1(
    p_session_id,'platform.identity_provider.read',p_authentication_method);
  IF actor_id IS DISTINCT FROM read_actor_id THEN RAISE EXCEPTION 'live platform identity-provider authority is required' USING ERRCODE='42501'; END IF;
  SELECT provider.* INTO STRICT provider_record FROM ONLY public.platform_auth_providers AS provider
  WHERE provider.id=p_provider_id FOR UPDATE;
  SELECT runtime_policy.* INTO STRICT runtime_record FROM ONLY public.platform_federated_provider_policies AS runtime_policy
  WHERE runtime_policy.provider_id=p_provider_id AND runtime_policy.provider_kind='saml' FOR UPDATE;
  SELECT configuration.* INTO STRICT configuration_record FROM ONLY public.platform_saml_provider_configurations AS configuration
  WHERE configuration.provider_id=p_provider_id FOR UPDATE;
  IF provider_record.version<>p_expected_version THEN RAISE EXCEPTION 'platform identity provider revision conflict' USING ERRCODE='40001'; END IF;
  IF provider_record.kind<>'saml' OR provider_record.archived_at IS NOT NULL THEN RAISE EXCEPTION 'platform identity provider is not a live SAML provider' USING ERRCODE='55000'; END IF;
  IF configuration_record.metadata_revision>=9007199254740991
     OR configuration_record.version>=9007199254740991
     OR runtime_record.configuration_revision>=9007199254740991
     OR runtime_record.security_revision>=9007199254740991 THEN
    RAISE EXCEPTION 'platform SAML revision is exhausted' USING ERRCODE='55000';
  END IF;
  next_revision:=configuration_record.metadata_revision+1;
  PERFORM app.private_platform_saml_administration_fence_v1(p_provider_id,changed_at);
  INSERT INTO public.platform_saml_metadata_snapshots(
    provider_id,revision,document,document_digest,retrieved_at,maximum_valid_until
  ) VALUES(p_provider_id,next_revision,p_document,p_document_digest,p_retrieved_at,p_maximum_valid_until);
  UPDATE ONLY public.platform_saml_provider_configurations AS configuration
  SET metadata_revision=next_revision,version=configuration.version+1,updated_at=changed_at
  WHERE configuration.provider_id=p_provider_id;
  UPDATE ONLY public.platform_federated_provider_policies AS runtime_policy
  SET configuration_revision=runtime_policy.configuration_revision+1,
      security_revision=runtime_policy.security_revision+1,
      platform_login_enabled=false,updated_at=changed_at
  WHERE runtime_policy.provider_id=p_provider_id;
  UPDATE ONLY public.platform_auth_providers AS provider
  SET updated_by_user_id=actor_id,version=provider.version+1,updated_at=changed_at
  WHERE provider.id=p_provider_id AND provider.version=p_expected_version;
  PERFORM app.append_platform_audit_event(
    p_audit_event_id,'user',actor_id,'platform.identity_provider.saml_metadata_replaced',
    'platform_identity_provider',p_provider_id,p_request_id,p_correlation_id,
    p_ip_address,p_user_agent,p_authentication_method,'success',p_reason,
    jsonb_build_object('kind','saml','previousVersion',provider_record.version,
      'version',provider_record.version+1,'metadataRevision',next_revision,
      'documentDigest',encode(p_document_digest,'hex'),
      'protectedApproval',p_protected_approval,'platformLoginEnabled',false)
  );
  RETURN QUERY SELECT provider_record.version+1,next_revision;
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'platform SAML administration dependency is unavailable' USING ERRCODE='55000';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.load_platform_saml_metadata_admin_v1(
  p_session_id uuid,p_provider_id uuid,p_authentication_method text
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE actor_id uuid;
DECLARE read_actor_id uuid;
DECLARE result jsonb;
BEGIN
  actor_id:=app.private_require_platform_identity_permission_v1(
    p_session_id,'platform.identity_provider.manage',p_authentication_method);
  read_actor_id:=app.private_require_platform_identity_permission_v1(
    p_session_id,'platform.identity_provider.read',p_authentication_method);
  IF actor_id IS DISTINCT FROM read_actor_id THEN RAISE EXCEPTION 'live platform identity-provider authority is required' USING ERRCODE='42501'; END IF;
  SELECT jsonb_build_object(
    'providerId',provider.id::text,'providerVersion',provider.version,
    'metadataRevision',snapshot.revision,
    'document',replace(encode(snapshot.document,'base64'),E'\n',''),
    'digest',replace(encode(snapshot.document_digest,'base64'),E'\n',''),
    'retrievedAt',to_char(snapshot.retrieved_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    'maximumValidUntil',to_char(snapshot.maximum_valid_until AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
  ) INTO result
  FROM ONLY public.platform_auth_providers AS provider
  JOIN ONLY public.platform_saml_provider_configurations AS configuration
    ON configuration.provider_id=provider.id
  JOIN ONLY public.platform_saml_metadata_snapshots AS snapshot
    ON snapshot.provider_id=provider.id AND snapshot.revision=configuration.metadata_revision
  WHERE provider.id=p_provider_id AND provider.kind='saml';
  IF result IS NULL THEN
    RAISE EXCEPTION 'platform SAML metadata snapshot not found' USING ERRCODE='P0002';
  END IF;
  RETURN result;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_platform_saml_direct_audit_v1(
  p_audit jsonb,
  p_event_id uuid,
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
  request_id uuid;
  correlation_id uuid;
  ip_address inet;
BEGIN
  PERFORM app.private_platform_saml_direct_json_v1(
    p_audit,
    ARRAY['requestId','correlationId','ipAddress','userAgent'],
    ARRAY['requestId','correlationId','ipAddress','userAgent'],8192
  );
  PERFORM app.private_mfa_require_uuidv7_v1(p_event_id::text);
  request_id := app.private_mfa_require_uuidv7_v1(p_audit ->> 'requestId');
  correlation_id := app.private_mfa_require_uuidv7_v1(p_audit ->> 'correlationId');
  ip_address := (p_audit ->> 'ipAddress')::inet;
  IF p_audit ->> 'userAgent' IS NULL
     OR octet_length(convert_to(p_audit ->> 'userAgent','UTF8')) NOT BETWEEN 1 AND 512
     OR p_audit ->> 'userAgent' ~ '[[:cntrl:]]'
     OR coalesce(p_metadata,'{}'::jsonb) ?| ARRAY[
       'assertion','assertionId','responseId','relayState','browserHandle',
       'subject','subjectDigest','sessionIndex','sessionIndexDigest','token',
       'tokenDigest','csrfSecret','csrfSecretDigest','ciphertext','nonce'
     ] THEN
    RAISE EXCEPTION 'direct platform SAML audit envelope is unsafe'
      USING ERRCODE = '22023';
  END IF;
  PERFORM app.append_platform_audit_event(
    p_event_id,'system',NULL,p_action,p_resource_type,p_resource_id,
    request_id,correlation_id,ip_address,p_audit ->> 'userAgent','saml',
    p_outcome,NULL,coalesce(p_metadata,'{}'::jsonb)
  );
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.guard_platform_saml_direct_runtime_write_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF current_setting('app.platform_saml_direct_runtime_write_v1',true) <> 'on' THEN
    RAISE EXCEPTION 'direct platform SAML runtime requires a protected ABI'
      USING ERRCODE = '42501';
  END IF;
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'direct platform SAML runtime is append-only'
      USING ERRCODE = '42501';
  END IF;
  RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.guard_platform_saml_login_policy_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF current_setting('app.platform_saml_direct_policy_write_v1',true) <> 'on' THEN
    RAISE EXCEPTION 'direct platform SAML policy requires a protected ABI'
      USING ERRCODE = '42501';
  END IF;
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'direct platform SAML policy is archival'
      USING ERRCODE = '42501';
  END IF;
  IF TG_OP = 'UPDATE' AND (
    NEW.provider_id IS DISTINCT FROM OLD.provider_id
    OR NEW.provider_kind IS DISTINCT FROM OLD.provider_kind
    OR NEW.created_at IS DISTINCT FROM OLD.created_at
    OR NEW.revision <> OLD.revision + 1
  ) THEN
    RAISE EXCEPTION 'direct platform SAML policy mutation is invalid'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$function$;
--> statement-breakpoint

CREATE TRIGGER platform_saml_login_policies_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.platform_saml_login_policies
FOR EACH ROW EXECUTE FUNCTION app.guard_platform_saml_login_policy_v1();
CREATE TRIGGER platform_saml_authentication_transactions_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.platform_saml_authentication_transactions
FOR EACH ROW EXECUTE FUNCTION app.guard_platform_saml_direct_runtime_write_v1();
CREATE TRIGGER platform_saml_authentication_applications_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.platform_saml_authentication_applications
FOR EACH ROW EXECUTE FUNCTION app.guard_platform_saml_direct_runtime_write_v1();
CREATE TRIGGER platform_saml_post_primary_continuations_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.platform_saml_post_primary_continuations
FOR EACH ROW EXECUTE FUNCTION app.guard_platform_saml_direct_runtime_write_v1();
CREATE TRIGGER platform_saml_post_primary_continuation_evidence_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.platform_saml_post_primary_continuation_evidence
FOR EACH ROW EXECUTE FUNCTION app.guard_platform_saml_direct_runtime_write_v1();
CREATE TRIGGER platform_saml_post_primary_continuation_policy_pins_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.platform_saml_post_primary_continuation_policy_pins
FOR EACH ROW EXECUTE FUNCTION app.guard_platform_saml_direct_runtime_write_v1();
CREATE TRIGGER platform_saml_post_primary_totp_challenges_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.platform_saml_post_primary_totp_challenges
FOR EACH ROW EXECUTE FUNCTION app.guard_platform_saml_direct_runtime_write_v1();
CREATE TRIGGER auth_session_platform_saml_states_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.auth_session_platform_saml_states
FOR EACH ROW EXECUTE FUNCTION app.guard_platform_saml_direct_runtime_write_v1();
CREATE TRIGGER auth_session_platform_saml_provenance_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.auth_session_platform_saml_provenance
FOR EACH ROW EXECUTE FUNCTION app.guard_platform_saml_direct_runtime_write_v1();
CREATE TRIGGER auth_session_platform_saml_evidence_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.auth_session_platform_saml_evidence
FOR EACH ROW EXECUTE FUNCTION app.guard_platform_saml_direct_runtime_write_v1();
CREATE TRIGGER auth_session_platform_saml_policy_pins_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.auth_session_platform_saml_policy_pins
FOR EACH ROW EXECUTE FUNCTION app.guard_platform_saml_direct_runtime_write_v1();
CREATE TRIGGER platform_saml_session_materials_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.platform_saml_session_materials
FOR EACH ROW EXECUTE FUNCTION app.guard_platform_saml_direct_runtime_write_v1();
CREATE TRIGGER platform_saml_session_revalidation_commands_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.platform_saml_session_revalidation_commands
FOR EACH ROW EXECUTE FUNCTION app.guard_platform_saml_direct_runtime_write_v1();
--> statement-breakpoint

CREATE FUNCTION app.private_platform_saml_direct_pins_v1(
  p_provider_id uuid,
  p_provider_revision bigint,
  p_login_revision bigint,
  p_configuration_revision bigint,
  p_security_revision bigint,
  p_plan_revision bigint,
  p_assurance_revision bigint,
  p_metadata_revision bigint,
  p_metadata_digest bytea,
  p_sp_key_revision bigint,
  p_configuration_digest bytea DEFAULT NULL
)
RETURNS jsonb
LANGUAGE sql
IMMUTABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT jsonb_strip_nulls(jsonb_build_object(
    'provider',jsonb_build_object('scope','platform','providerId',p_provider_id::text),
    'providerRevision',p_provider_revision,
    'platformLoginRevision',p_login_revision,
    'configurationRevision',p_configuration_revision,
    'securityRevision',p_security_revision,
    'planRevision',p_plan_revision,
    'assurancePolicyRevision',p_assurance_revision,
    'metadataRevision',p_metadata_revision,
    'metadataDigest',replace(encode(p_metadata_digest,'base64'),E'\n',''),
    'spKeyRevision',p_sp_key_revision,
    'configurationDigest',CASE WHEN p_configuration_digest IS NULL THEN NULL
      ELSE replace(encode(p_configuration_digest,'base64'),E'\n','') END
  ));
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_platform_saml_direct_configuration_v1(
  p_provider_id uuid,
  p_expected_pins jsonb DEFAULT NULL
)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  WITH live AS (
    SELECT provider.id AS provider_id,provider.key AS provider_key,
      provider.version AS provider_revision,login_policy.revision AS login_revision,
      runtime_policy.configuration_revision,runtime_policy.security_revision,
      runtime_policy.plan_revision,runtime_policy.assurance_policy_revision,
      configuration.expected_entity_id,configuration.sp_entity_id,
      configuration.acs_url,configuration.sp_key_revision,
      configuration.metadata_revision,configuration.redirect_signature_algorithm,
      configuration.signature_policy,configuration.encryption_policy,
      configuration.requested_authn_contexts,configuration.subject_source,
      configuration.subject_attribute_name,configuration.subject_attribute_name_format,
      configuration.clock_skew_nanoseconds,
      configuration.max_authentication_age_nanoseconds,
      metadata.document AS metadata_document,
      metadata.document_digest AS metadata_digest,
      metadata.retrieved_at AS metadata_retrieved_at,
      metadata.maximum_valid_until AS metadata_maximum_valid_until,
      platform_floor.id AS floor_id,platform_floor.revision AS floor_revision,
      platform_floor.level AS floor_level,
      platform_floor.local_required AS floor_local_required,
      platform_floor.freshness_nanoseconds AS floor_freshness_nanoseconds,
      platform_floor.enrollment_deadline AS floor_enrollment_deadline
    FROM ONLY public.platform_auth_providers AS provider
    JOIN ONLY public.platform_federated_provider_policies AS runtime_policy
      ON runtime_policy.provider_id = provider.id
     AND runtime_policy.provider_kind = 'saml'
     AND runtime_policy.enabled AND NOT runtime_policy.platform_login_enabled
    JOIN ONLY public.platform_saml_login_policies AS login_policy
      ON login_policy.provider_id = provider.id
     AND login_policy.provider_kind = 'saml'
     AND login_policy.enabled AND login_policy.account_mode = 'existing_identity'
    JOIN ONLY public.platform_saml_provider_configurations AS configuration
      ON configuration.provider_id = provider.id
     AND configuration.version = runtime_policy.configuration_revision
     AND configuration.encryption_policy = 'disabled'
     AND cardinality(configuration.decryption_key_versions) = 0
    JOIN ONLY public.platform_saml_metadata_snapshots AS metadata
      ON metadata.provider_id = provider.id
     AND metadata.revision = configuration.metadata_revision
     AND metadata.document_digest = sha256(metadata.document)
     AND metadata.maximum_valid_until > statement_timestamp()
    JOIN ONLY public.platform_saml_sp_keys AS sp_key
      ON sp_key.provider_id = provider.id
     AND sp_key.revision = configuration.sp_key_revision
     AND sp_key.retired_at IS NULL
    JOIN ONLY public.identity_keyring_versions AS root_key
      ON root_key.key_version = sp_key.key_version
     AND root_key.is_active AND root_key.retired_at IS NULL
    JOIN ONLY public.mfa_policy_revisions AS platform_floor
      ON platform_floor.scope = 'platform_floor'
     AND platform_floor.tenant_id IS NULL
     AND platform_floor.retired_at IS NULL
    WHERE provider.id = p_provider_id AND provider.kind = 'saml'
      AND provider.enabled AND provider.archived_at IS NULL
      AND configuration.sp_entity_id ~ (
        '/api/v1/auth/platform/saml/' || provider.key || '/metadata$'
      )
      AND configuration.acs_url ~ '/api/v1/auth/platform/saml/acs$'
      AND NOT EXISTS (
        SELECT 1 FROM ONLY public.platform_saml_attribute_rules AS rule
        WHERE rule.provider_id = provider.id
      )
      AND (SELECT count(*) FROM ONLY public.platform_saml_sp_certificates AS certificate
           WHERE certificate.key_id = sp_key.id) BETWEEN 1 AND 8
      AND (SELECT count(*) FROM ONLY public.mfa_policy_revisions AS counted_floor
           WHERE counted_floor.scope = 'platform_floor'
             AND counted_floor.tenant_id IS NULL
             AND counted_floor.retired_at IS NULL) = 1
  ), projected AS (
    SELECT live.*,app.private_platform_saml_direct_pins_v1(
      live.provider_id,live.provider_revision,live.login_revision,
      live.configuration_revision,live.security_revision,live.plan_revision,
      live.assurance_policy_revision,live.metadata_revision,
      live.metadata_digest,live.sp_key_revision,
      CASE WHEN p_expected_pins IS NULL THEN NULL
        ELSE app.private_mfa_decode_base64_v1(
          p_expected_pins ->> 'configurationDigest',32,32
        ) END
    ) AS pins
    FROM live
  )
  SELECT jsonb_build_object(
    'providerKey',projected.provider_key,
    'observedAt',to_jsonb(statement_timestamp()),
    'pins',projected.pins,
    'authentication',jsonb_build_object(
      'provider',projected.pins -> 'provider',
      'providerRevision',projected.provider_revision,
      'platformLoginRevision',projected.login_revision,
      'configurationRevision',projected.configuration_revision,
      'securityRevision',projected.security_revision,
      'planRevision',projected.plan_revision,
      'assurancePolicyRevision',projected.assurance_policy_revision,
      'spEntityId',projected.sp_entity_id,'acsUrl',projected.acs_url,
      'spKeyRevision',projected.sp_key_revision,
      'redirectSignatureAlgorithm',projected.redirect_signature_algorithm,
      'signaturePolicy',projected.signature_policy,
      'encryptionPolicy',projected.encryption_policy,
      'directPlatformDecryptionKeyRevisions','[]'::jsonb,
      'requestedAuthnContexts',to_jsonb(projected.requested_authn_contexts),
      'subject',jsonb_build_object(
        'source',projected.subject_source,
        'attributeName',coalesce(projected.subject_attribute_name,''),
        'attributeNameFormat',coalesce(projected.subject_attribute_name_format,'')
      ),
      'mapping',jsonb_build_object('scalars','[]'::jsonb,'profiles','[]'::jsonb),
      'trustRules',coalesce((
        SELECT jsonb_agg(jsonb_build_object(
          'id',rule.id::text,'classRef',rule.exact_value,
          'level',rule.level,'revision',rule.revision,
          'maximumAuthenticationAgeSeconds',rule.maximum_authentication_age_seconds
        ) ORDER BY rule.exact_value,rule.id,rule.revision)
        FROM ONLY public.platform_federated_trust_rules AS rule
        WHERE rule.provider_id = projected.provider_id
          AND rule.provider_kind = 'saml' AND rule.enabled
          AND rule.retired_at IS NULL
      ),'[]'::jsonb),
      'clockSkewNanoseconds',projected.clock_skew_nanoseconds,
      'maxAuthenticationAgeNanoseconds',projected.max_authentication_age_nanoseconds
    ),
    'metadata',jsonb_build_object(
      'expectedEntityId',projected.expected_entity_id,
      'revision',projected.metadata_revision,
      'document',replace(encode(projected.metadata_document,'base64'),E'\n',''),
      'digest',replace(encode(projected.metadata_digest,'base64'),E'\n',''),
      'retrievedAt',to_jsonb(projected.metadata_retrieved_at),
      'maximumValidUntil',to_jsonb(projected.metadata_maximum_valid_until)
    ),
    'platformFloor',jsonb_build_object(
      'id',projected.floor_id::text,'revision',projected.floor_revision,
      'level',projected.floor_level,'localRequired',projected.floor_local_required,
      'freshnessNanoseconds',projected.floor_freshness_nanoseconds,
      'enrollmentDeadline',to_jsonb(projected.floor_enrollment_deadline)
    )
  )
  FROM projected
  WHERE p_expected_pins IS NULL OR projected.pins IS NOT DISTINCT FROM p_expected_pins;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.begin_platform_saml_authentication_v1(p_lookup jsonb)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  login_key text;
  provider_id uuid;
BEGIN
  PERFORM app.private_platform_saml_direct_json_v1(
    p_lookup,ARRAY['loginKey'],ARRAY['loginKey'],4096
  );
  login_key := p_lookup ->> 'loginKey';
  IF login_key IS NULL OR login_key <> lower(btrim(login_key))
     OR login_key !~ '^[a-z][a-z0-9_-]{2,63}$' THEN
    RAISE EXCEPTION 'direct platform SAML login key is invalid'
      USING ERRCODE = '22023';
  END IF;
  SELECT provider.id INTO STRICT provider_id
  FROM ONLY public.platform_auth_providers AS provider
  WHERE provider.key = login_key AND provider.kind = 'saml';
  RETURN app.private_platform_saml_direct_configuration_v1(provider_id,NULL);
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RETURN NULL;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.load_platform_saml_start_configuration_v1(p_lookup jsonb)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  provider_id uuid;
BEGIN
  PERFORM app.private_platform_saml_direct_json_v1(
    p_lookup,ARRAY['providerId','pins'],ARRAY['providerId','pins'],65536
  );
  provider_id := app.private_mfa_require_uuidv7_v1(p_lookup ->> 'providerId');
  RETURN app.private_platform_saml_direct_configuration_v1(
    provider_id,p_lookup -> 'pins'
  );
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_platform_saml_transaction_pins_v1(
  p_transaction public.platform_saml_authentication_transactions
)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT jsonb_build_object(
    'protocol',app.private_platform_saml_direct_pins_v1(
      p_transaction.platform_provider_id,p_transaction.provider_revision,
      p_transaction.login_policy_revision,p_transaction.configuration_revision,
      p_transaction.security_revision,p_transaction.plan_revision,
      p_transaction.assurance_policy_revision,p_transaction.metadata_revision,
      p_transaction.metadata_digest,p_transaction.sp_key_revision,
      p_transaction.configuration_digest
    ),
    'platformFloorPolicyId',p_transaction.platform_floor_policy_id::text,
    'platformFloorPolicyRevision',p_transaction.platform_floor_policy_revision
  );
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_platform_saml_transaction_projection_v1(
  p_transaction public.platform_saml_authentication_transactions
)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT jsonb_build_object(
    'transactionId',replace(encode(p_transaction.transaction_id,'base64'),E'\n',''),
    'operationRunId',p_transaction.operation_run_id::text,
    'requestId',p_transaction.request_id,
    'relayStateDigest',replace(encode(p_transaction.relay_state_digest,'base64'),E'\n',''),
    'browserDigest',replace(encode(p_transaction.browser_digest,'base64'),E'\n',''),
    'pins',app.private_platform_saml_transaction_pins_v1(p_transaction),
    'returnPath',p_transaction.return_path,'state',p_transaction.state,
    'version',p_transaction.version,'createdAt',to_jsonb(p_transaction.created_at),
    'expiresAt',to_jsonb(p_transaction.expires_at)
  );
$function$;
--> statement-breakpoint

CREATE FUNCTION app.create_platform_saml_authentication_transaction_v1(
  p_request jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  begin_request jsonb;
  current_request jsonb;
  pins jsonb;
  protocol_pins jsonb;
  provider_id uuid;
  operation_run_id uuid;
  transaction_id bytea;
  operation_digest bytea;
  receipt_digest bytea;
  network_digest bytea;
  account_digest bytea;
  provider_digest bytea;
  relay_digest bytea;
  browser_digest bytea;
  previous_browser_digest bytea;
  metadata_digest bytea;
  configuration_digest bytea;
  floor_id uuid;
  created_at timestamptz;
  expires_at timestamptz;
  live_record jsonb;
  admission record;
  existing public.platform_saml_authentication_transactions%ROWTYPE;
BEGIN
  PERFORM app.private_platform_saml_direct_json_v1(
    p_request,ARRAY['begin','current','pins','previousBrowserDigest','audit'],
    ARRAY['begin','current','pins','audit'],262144
  );
  begin_request := p_request -> 'begin';
  current_request := p_request -> 'current';
  pins := p_request -> 'pins';
  protocol_pins := pins -> 'protocol';
  PERFORM app.private_platform_saml_direct_json_v1(
    begin_request,
    ARRAY['operationRunId','receiptDigest','networkDigest','accountDigest','providerDigest'],
    ARRAY['operationRunId','receiptDigest','networkDigest','accountDigest','providerDigest'],8192
  );
  PERFORM app.private_platform_saml_direct_json_v1(
    current_request,
    ARRAY['transactionId','materialId','requestId','relayStateDigest','browserDigest',
      'returnPath','state','version','createdAt','expiresAt'],
    ARRAY['transactionId','materialId','requestId','relayStateDigest','browserDigest',
      'returnPath','state','version','createdAt','expiresAt'],32768
  );
  PERFORM app.private_platform_saml_direct_json_v1(
    pins,ARRAY['protocol','platformFloorPolicyId','platformFloorPolicyRevision'],
    ARRAY['protocol','platformFloorPolicyId','platformFloorPolicyRevision'],65536
  );
  PERFORM app.private_platform_saml_direct_json_v1(
    protocol_pins,
    ARRAY['provider','providerRevision','platformLoginRevision','configurationRevision',
      'securityRevision','planRevision','assurancePolicyRevision','metadataRevision',
      'metadataDigest','spKeyRevision','configurationDigest'],
    ARRAY['provider','providerRevision','platformLoginRevision','configurationRevision',
      'securityRevision','planRevision','assurancePolicyRevision','metadataRevision',
      'metadataDigest','spKeyRevision','configurationDigest'],32768
  );
  PERFORM app.private_platform_saml_direct_json_v1(
    protocol_pins -> 'provider',ARRAY['scope','providerId'],
    ARRAY['scope','providerId'],4096
  );
  IF protocol_pins #>> '{provider,scope}' <> 'platform'
     OR current_request ->> 'state' <> 'pending'
     OR (current_request ->> 'version')::bigint <> 1 THEN
    RAISE EXCEPTION 'invalid direct platform SAML transaction request'
      USING ERRCODE = '22023';
  END IF;
  operation_run_id := app.private_mfa_require_uuidv7_v1(begin_request ->> 'operationRunId');
  IF app.private_mfa_require_uuidv7_v1(current_request ->> 'materialId') <> operation_run_id THEN
    RAISE EXCEPTION 'direct platform SAML operation material mismatch'
      USING ERRCODE = '22023';
  END IF;
  provider_id := app.private_mfa_require_uuidv7_v1(protocol_pins #>> '{provider,providerId}');
  floor_id := app.private_mfa_require_uuidv7_v1(pins ->> 'platformFloorPolicyId');
  transaction_id := app.private_mfa_decode_base64_v1(current_request ->> 'transactionId',32,32);
  receipt_digest := app.private_mfa_decode_base64_v1(begin_request ->> 'receiptDigest',32,32);
  network_digest := app.private_mfa_decode_base64_v1(begin_request ->> 'networkDigest',32,32);
  account_digest := app.private_mfa_decode_base64_v1(begin_request ->> 'accountDigest',32,32);
  provider_digest := app.private_mfa_decode_base64_v1(begin_request ->> 'providerDigest',32,32);
  relay_digest := app.private_mfa_decode_base64_v1(current_request ->> 'relayStateDigest',32,32);
  browser_digest := app.private_mfa_decode_base64_v1(current_request ->> 'browserDigest',32,32);
  metadata_digest := app.private_mfa_decode_base64_v1(protocol_pins ->> 'metadataDigest',32,32);
  configuration_digest := app.private_mfa_decode_base64_v1(protocol_pins ->> 'configurationDigest',32,32);
  IF p_request ? 'previousBrowserDigest' THEN
    previous_browser_digest := app.private_mfa_decode_base64_v1(
      p_request ->> 'previousBrowserDigest',32,32
    );
  END IF;
  created_at := (current_request ->> 'createdAt')::timestamptz;
  expires_at := (current_request ->> 'expiresAt')::timestamptz;
  IF encode(transaction_id,'hex') = repeat('00',32)
     OR encode(receipt_digest,'hex') = repeat('00',32)
     OR encode(network_digest,'hex') = repeat('00',32)
     OR encode(account_digest,'hex') = repeat('00',32)
     OR encode(provider_digest,'hex') = repeat('00',32)
     OR encode(relay_digest,'hex') = repeat('00',32)
     OR encode(browser_digest,'hex') = repeat('00',32)
     OR encode(metadata_digest,'hex') = repeat('00',32)
     OR encode(configuration_digest,'hex') = repeat('00',32)
     OR receipt_digest = ANY(ARRAY[network_digest,account_digest,provider_digest,relay_digest,browser_digest]::bytea[])
     OR network_digest = ANY(ARRAY[account_digest,provider_digest,relay_digest,browser_digest]::bytea[])
     OR account_digest = ANY(ARRAY[provider_digest,relay_digest,browser_digest]::bytea[])
     OR provider_digest = ANY(ARRAY[relay_digest,browser_digest]::bytea[])
     OR relay_digest = browser_digest
     OR previous_browser_digest = browser_digest
     OR encode(previous_browser_digest,'hex') = repeat('00',32)
     OR current_request ->> 'requestId' IS NULL
     OR char_length(current_request ->> 'requestId') NOT BETWEEN 1 AND 1024
     OR current_request ->> 'requestId' ~ '[[:cntrl:]]'
     OR current_request ->> 'returnPath' !~ '^/[^[:cntrl:]\\]*$'
     OR left(current_request ->> 'returnPath',2) = '//'
     OR created_at NOT BETWEEN statement_timestamp() - interval '5 minutes'
                              AND statement_timestamp() + interval '30 seconds'
     OR expires_at - created_at NOT BETWEEN interval '1 minute' AND interval '15 minutes'
     OR (protocol_pins ->> 'providerRevision')::bigint NOT BETWEEN 1 AND 2147483647
     OR (protocol_pins ->> 'platformLoginRevision')::bigint NOT BETWEEN 1 AND 9007199254740991
     OR (protocol_pins ->> 'configurationRevision')::bigint NOT BETWEEN 1 AND 9007199254740991
     OR (protocol_pins ->> 'securityRevision')::bigint NOT BETWEEN 1 AND 9007199254740991
     OR (protocol_pins ->> 'planRevision')::bigint NOT BETWEEN 1 AND 9007199254740991
     OR (protocol_pins ->> 'assurancePolicyRevision')::bigint NOT BETWEEN 1 AND 9007199254740991
     OR (protocol_pins ->> 'metadataRevision')::bigint NOT BETWEEN 1 AND 9007199254740991
     OR (protocol_pins ->> 'spKeyRevision')::bigint NOT BETWEEN 1 AND 9007199254740991
     OR (pins ->> 'platformFloorPolicyRevision')::bigint NOT BETWEEN 1 AND 9007199254740991 THEN
    RAISE EXCEPTION 'invalid direct platform SAML transaction request'
      USING ERRCODE = '22023';
  END IF;
  operation_digest := sha256(convert_to((p_request - 'audit')::text,'UTF8'));
  PERFORM pg_advisory_xact_lock(hashtextextended(
    'platform-saml-direct:operation:' || operation_run_id::text,4200184
  ));
  PERFORM pg_advisory_xact_lock(hashtextextended(
    'platform-saml-direct:receipt:' || encode(receipt_digest,'hex'),4200184
  ));
  SELECT transaction.* INTO existing
  FROM ONLY public.platform_saml_authentication_transactions AS transaction
  WHERE transaction.operation_run_id = operation_run_id
     OR transaction.receipt_digest = receipt_digest
     OR transaction.transaction_id = transaction_id
     OR transaction.relay_state_digest = relay_digest
  FOR UPDATE;
  IF FOUND THEN
    IF existing.operation_run_id <> operation_run_id
       OR existing.operation_digest <> operation_digest
       OR existing.transaction_id <> transaction_id
       OR existing.receipt_digest <> receipt_digest THEN
      RAISE EXCEPTION 'direct platform SAML transaction replay collision'
        USING ERRCODE = '23505';
    END IF;
    RETURN app.private_platform_saml_transaction_projection_v1(existing);
  END IF;
  SELECT * INTO STRICT admission
  FROM app.admit_auth_attempts(
    ARRAY['platform_saml_network','platform_saml_account','platform_saml_provider']::public.auth_rate_limit_scope[],
    ARRAY[network_digest,account_digest,provider_digest]::bytea[],
    ARRAY[60,900,60]::integer[],ARRAY[30,10,100]::integer[],
    ARRAY[300,900,300]::integer[]
  );
  IF NOT admission.admitted THEN RETURN NULL; END IF;
  live_record := app.private_platform_saml_direct_configuration_v1(
    provider_id,protocol_pins
  );
  IF live_record IS NULL
     OR live_record #>> '{platformFloor,id}' IS DISTINCT FROM floor_id::text
     OR (live_record #>> '{platformFloor,revision}')::bigint
        IS DISTINCT FROM (pins ->> 'platformFloorPolicyRevision')::bigint THEN
    RETURN NULL;
  END IF;
  PERFORM set_config('app.platform_saml_direct_runtime_write_v1','on',true);
  IF previous_browser_digest IS NOT NULL THEN
    UPDATE ONLY public.platform_saml_authentication_transactions AS previous
    SET state='failed',version=previous.version+1,completed_at=created_at,
        failure_reason='superseded'
    WHERE previous.browser_digest=previous_browser_digest AND previous.state='pending';
  END IF;
  INSERT INTO public.platform_saml_authentication_transactions (
    transaction_id,platform_provider_id,provider_kind,protocol,
    operation_run_id,operation_digest,receipt_digest,network_digest,
    account_digest,provider_digest,relay_state_digest,browser_digest,request_id,
    provider_revision,login_policy_revision,configuration_revision,
    security_revision,plan_revision,assurance_policy_revision,
    metadata_revision,metadata_digest,sp_key_revision,configuration_digest,
    platform_floor_policy_id,platform_floor_policy_revision,return_path,
    state,version,created_at,expires_at
  ) VALUES (
    transaction_id,provider_id,'saml','saml',operation_run_id,operation_digest,
    receipt_digest,network_digest,account_digest,provider_digest,relay_digest,
    browser_digest,current_request ->> 'requestId',
    (protocol_pins ->> 'providerRevision')::bigint,
    (protocol_pins ->> 'platformLoginRevision')::bigint,
    (protocol_pins ->> 'configurationRevision')::bigint,
    (protocol_pins ->> 'securityRevision')::bigint,
    (protocol_pins ->> 'planRevision')::bigint,
    (protocol_pins ->> 'assurancePolicyRevision')::bigint,
    (protocol_pins ->> 'metadataRevision')::bigint,metadata_digest,
    (protocol_pins ->> 'spKeyRevision')::bigint,configuration_digest,
    floor_id,(pins ->> 'platformFloorPolicyRevision')::bigint,
    current_request ->> 'returnPath','pending',1,created_at,expires_at
  ) RETURNING * INTO existing;
  PERFORM app.private_platform_saml_direct_audit_v1(
    p_request -> 'audit',operation_run_id,'platform.saml.login.started',
    'platform_identity_provider',provider_id,'success',
    jsonb_build_object('transactionVersion',1)
  );
  RETURN app.private_platform_saml_transaction_projection_v1(existing);
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid direct platform SAML transaction request'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.recover_platform_saml_authentication_transaction_create_v1(
  p_request jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  operation_run_id uuid;
  receipt_digest bytea;
  operation_digest bytea;
  existing public.platform_saml_authentication_transactions%ROWTYPE;
BEGIN
  PERFORM app.private_platform_saml_direct_json_v1(
    p_request,ARRAY['begin','current','pins','previousBrowserDigest','audit'],
    ARRAY['begin','current','pins','audit'],262144
  );
  operation_run_id := app.private_mfa_require_uuidv7_v1(
    p_request #>> '{begin,operationRunId}'
  );
  receipt_digest := app.private_mfa_decode_base64_v1(
    p_request #>> '{begin,receiptDigest}',32,32
  );
  operation_digest := sha256(convert_to((p_request - 'audit')::text,'UTF8'));
  SELECT transaction.* INTO existing
  FROM ONLY public.platform_saml_authentication_transactions AS transaction
  WHERE transaction.operation_run_id=operation_run_id
    AND transaction.receipt_digest=receipt_digest
    AND transaction.operation_digest=operation_digest;
  IF NOT FOUND THEN RETURN NULL; END IF;
  RETURN app.private_platform_saml_transaction_projection_v1(existing);
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.lookup_platform_saml_authentication_transaction_v1(
  p_lookup jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  relay_digest bytea;
  browser_digest bytea;
  observed_at timestamptz;
  existing public.platform_saml_authentication_transactions%ROWTYPE;
BEGIN
  PERFORM app.private_platform_saml_direct_json_v1(
    p_lookup,ARRAY['relayStateDigest','browserDigest','observedAt'],
    ARRAY['relayStateDigest','browserDigest','observedAt'],8192
  );
  relay_digest := app.private_mfa_decode_base64_v1(p_lookup ->> 'relayStateDigest',32,32);
  browser_digest := app.private_mfa_decode_base64_v1(p_lookup ->> 'browserDigest',32,32);
  observed_at := (p_lookup ->> 'observedAt')::timestamptz;
  IF observed_at NOT BETWEEN statement_timestamp()-interval '5 minutes'
                         AND statement_timestamp()+interval '30 seconds'
     OR relay_digest=browser_digest THEN
    RAISE EXCEPTION 'invalid direct platform SAML transaction lookup'
      USING ERRCODE='22023';
  END IF;
  SELECT transaction.* INTO existing
  FROM ONLY public.platform_saml_authentication_transactions AS transaction
  WHERE transaction.relay_state_digest=relay_digest
    AND transaction.browser_digest=browser_digest
    AND transaction.state='pending' AND transaction.expires_at>observed_at;
  IF NOT FOUND THEN RETURN NULL; END IF;
  RETURN app.private_platform_saml_transaction_projection_v1(existing);
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.resolve_platform_saml_authentication_configuration_v1(
  p_lookup jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  transaction_id bytea;
  expected_version bigint;
  pins jsonb;
  existing public.platform_saml_authentication_transactions%ROWTYPE;
BEGIN
  PERFORM app.private_platform_saml_direct_json_v1(
    p_lookup,ARRAY['transactionId','expectedVersion','pins'],
    ARRAY['transactionId','expectedVersion','pins'],65536
  );
  transaction_id := app.private_mfa_decode_base64_v1(p_lookup ->> 'transactionId',32,32);
  expected_version := (p_lookup ->> 'expectedVersion')::bigint;
  pins := p_lookup -> 'pins';
  SELECT transaction.* INTO existing
  FROM ONLY public.platform_saml_authentication_transactions AS transaction
  WHERE transaction.transaction_id=transaction_id
    AND transaction.version=expected_version
    AND transaction.state='pending'
    AND transaction.expires_at>statement_timestamp();
  IF NOT FOUND OR app.private_platform_saml_transaction_pins_v1(existing) -> 'protocol'
      IS DISTINCT FROM pins THEN RETURN NULL; END IF;
  RETURN app.private_platform_saml_direct_configuration_v1(
    existing.platform_provider_id,pins
  ) || jsonb_build_object(
    'directPins',app.private_platform_saml_transaction_pins_v1(existing)
  );
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.abort_platform_saml_authentication_transaction_v1(
  p_request jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  requested_transaction_id bytea;
  operation_run_id uuid;
  expected_version bigint;
  failed_at timestamptz;
  reason text;
  pins jsonb;
  existing public.platform_saml_authentication_transactions%ROWTYPE;
  disposition text;
BEGIN
  PERFORM app.private_platform_saml_direct_json_v1(
    p_request,ARRAY['transactionId','operationRunId','expectedVersion','pins','reason','failedAt','audit'],
    ARRAY['transactionId','operationRunId','expectedVersion','pins','reason','failedAt','audit'],65536
  );
  requested_transaction_id := app.private_mfa_decode_base64_v1(p_request ->> 'transactionId',32,32);
  operation_run_id := app.private_mfa_require_uuidv7_v1(p_request ->> 'operationRunId');
  expected_version := (p_request ->> 'expectedVersion')::bigint;
  failed_at := (p_request ->> 'failedAt')::timestamptz;
  reason := p_request ->> 'reason';
  pins := p_request -> 'pins';
  IF reason NOT IN ('callback_rejected','application_rejected')
     OR failed_at NOT BETWEEN statement_timestamp()-interval '5 minutes'
                          AND statement_timestamp()+interval '30 seconds' THEN
    RAISE EXCEPTION 'invalid direct platform SAML abort request'
      USING ERRCODE='22023';
  END IF;
  SELECT transaction.* INTO STRICT existing
  FROM ONLY public.platform_saml_authentication_transactions AS transaction
  WHERE transaction.transaction_id=requested_transaction_id
    AND transaction.operation_run_id=operation_run_id
  FOR UPDATE;
  IF app.private_platform_saml_transaction_pins_v1(existing) IS DISTINCT FROM pins THEN
    RAISE EXCEPTION 'stale direct platform SAML abort'
      USING ERRCODE='40001';
  END IF;
  IF existing.state='pending' AND existing.version=expected_version THEN
    PERFORM set_config('app.platform_saml_direct_runtime_write_v1','on',true);
    UPDATE ONLY public.platform_saml_authentication_transactions
    SET state='failed',version=version+1,completed_at=failed_at,failure_reason=reason
    WHERE platform_saml_authentication_transactions.transaction_id=requested_transaction_id
    RETURNING * INTO existing;
    disposition := 'terminalized';
    PERFORM app.private_platform_saml_direct_audit_v1(
      p_request -> 'audit',uuidv7(),'platform.saml.login.aborted',
      'platform_identity_provider',existing.platform_provider_id,'failure',
      jsonb_build_object('reason',reason,'transactionVersion',existing.version)
    );
  ELSIF existing.state IN ('completed','failed','expired') THEN
    disposition := 'already_terminal';
  ELSE
    RAISE EXCEPTION 'stale direct platform SAML abort'
      USING ERRCODE='40001';
  END IF;
  RETURN jsonb_build_object(
    'disposition',disposition,'transactionId',replace(encode(existing.transaction_id,'base64'),E'\n',''),
    'operationRunId',existing.operation_run_id::text,'version',existing.version,
    'state',existing.state,'pins',app.private_platform_saml_transaction_pins_v1(existing)
  );
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.load_platform_saml_sp_key_envelope_v1(p_lookup jsonb)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  provider_id uuid;
  login_revision bigint;
  key_revision bigint;
  result jsonb;
BEGIN
  PERFORM app.private_platform_saml_direct_json_v1(
    p_lookup,ARRAY['provider','platformLoginRevision','keyRevision'],
    ARRAY['provider','platformLoginRevision','keyRevision'],8192
  );
  PERFORM app.private_platform_saml_direct_json_v1(
    p_lookup -> 'provider',ARRAY['scope','providerId'],
    ARRAY['scope','providerId'],4096
  );
  IF p_lookup #>> '{provider,scope}' <> 'platform' THEN
    RAISE EXCEPTION 'invalid direct platform SAML SP-key scope'
      USING ERRCODE='22023';
  END IF;
  provider_id := app.private_mfa_require_uuidv7_v1(
    p_lookup #>> '{provider,providerId}'
  );
  login_revision := (p_lookup ->> 'platformLoginRevision')::bigint;
  key_revision := (p_lookup ->> 'keyRevision')::bigint;
  SELECT jsonb_build_object(
    'request',p_lookup,'platformLoginRevision',login_policy.revision,
    'context',jsonb_build_object(
      'provider',p_lookup -> 'provider','keyId',sp_key.id::text,
      'keyRevision',sp_key.revision
    ),
    'envelope',jsonb_build_object(
      'keyVersion',sp_key.key_version,
      'nonce',replace(encode(sp_key.nonce,'base64'),E'\n',''),
      'ciphertext',replace(encode(sp_key.ciphertext,'base64'),E'\n','')
    ),
    'certificateDer',(
      SELECT coalesce(jsonb_agg(
        replace(encode(certificate.certificate_der,'base64'),E'\n','')
        ORDER BY certificate.sequence
      ),'[]'::jsonb)
      FROM ONLY public.platform_saml_sp_certificates AS certificate
      WHERE certificate.key_id=sp_key.id
    ),'live',true
  ) INTO result
  FROM ONLY public.platform_auth_providers AS provider
  JOIN ONLY public.platform_federated_provider_policies AS runtime_policy
    ON runtime_policy.provider_id=provider.id AND runtime_policy.provider_kind='saml'
   AND runtime_policy.enabled AND NOT runtime_policy.platform_login_enabled
  JOIN ONLY public.platform_saml_login_policies AS login_policy
    ON login_policy.provider_id=provider.id AND login_policy.enabled
   AND login_policy.account_mode='existing_identity'
  JOIN ONLY public.platform_saml_provider_configurations AS configuration
    ON configuration.provider_id=provider.id
   AND configuration.version=runtime_policy.configuration_revision
   AND configuration.sp_key_revision=key_revision
   AND configuration.encryption_policy='disabled'
   AND cardinality(configuration.decryption_key_versions)=0
  JOIN ONLY public.platform_saml_sp_keys AS sp_key
    ON sp_key.provider_id=provider.id AND sp_key.revision=key_revision
   AND sp_key.retired_at IS NULL
  JOIN ONLY public.identity_keyring_versions AS root_key
    ON root_key.key_version=sp_key.key_version
   AND root_key.is_active AND root_key.retired_at IS NULL
  WHERE provider.id=provider_id AND provider.kind='saml'
    AND provider.enabled AND provider.archived_at IS NULL
    AND login_policy.revision=login_revision
    AND (SELECT count(*) FROM ONLY public.platform_saml_sp_certificates AS certificate
         WHERE certificate.key_id=sp_key.id) BETWEEN 1 AND 8;
  RETURN result;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.load_platform_saml_metadata_projection_v1(p_provider_key text)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  provider_id uuid;
  login_revision bigint;
  protocol_pins jsonb;
  configuration_record jsonb;
  result jsonb;
BEGIN
  IF p_provider_key IS NULL OR p_provider_key <> lower(btrim(p_provider_key))
     OR p_provider_key !~ '^[a-z][a-z0-9_-]{2,63}$' THEN
    RAISE EXCEPTION 'invalid direct platform SAML metadata provider key'
      USING ERRCODE='22023';
  END IF;
  SELECT provider.id,login_policy.revision INTO STRICT provider_id,login_revision
  FROM ONLY public.platform_auth_providers AS provider
  JOIN ONLY public.platform_saml_login_policies AS login_policy
    ON login_policy.provider_id=provider.id
  WHERE provider.key=p_provider_key AND provider.kind='saml'
    AND provider.enabled AND provider.archived_at IS NULL;

  -- Metadata remains available while login is disabled so an administrator can
  -- configure the IdP before the guarded activation.  Construct the same safe
  -- projection but never expose the SP private-key envelope.
  SELECT app.private_platform_saml_direct_pins_v1(
      provider.id,provider.version,login_policy.revision,
      runtime_policy.configuration_revision,runtime_policy.security_revision,
      runtime_policy.plan_revision,runtime_policy.assurance_policy_revision,
      configuration.metadata_revision,metadata.document_digest,
      configuration.sp_key_revision,NULL
    ),
    jsonb_build_object(
      'providerKey',provider.key,
      'observedAt',to_jsonb(statement_timestamp()),
      'authentication',jsonb_build_object(
        'provider',jsonb_build_object('scope','platform','providerId',provider.id::text),
        'providerRevision',provider.version,'platformLoginRevision',login_policy.revision,
        'configurationRevision',runtime_policy.configuration_revision,
        'securityRevision',runtime_policy.security_revision,
        'planRevision',runtime_policy.plan_revision,
        'assurancePolicyRevision',runtime_policy.assurance_policy_revision,
        'spEntityId',configuration.sp_entity_id,'acsUrl',configuration.acs_url,
        'spKeyRevision',configuration.sp_key_revision,
        'redirectSignatureAlgorithm',configuration.redirect_signature_algorithm,
        'signaturePolicy',configuration.signature_policy,
        'encryptionPolicy',configuration.encryption_policy,
        'directPlatformDecryptionKeyRevisions','[]'::jsonb,
        'requestedAuthnContexts',to_jsonb(configuration.requested_authn_contexts),
        'subject',jsonb_build_object(
          'source',configuration.subject_source,
          'attributeName',coalesce(configuration.subject_attribute_name,''),
          'attributeNameFormat',coalesce(configuration.subject_attribute_name_format,'')
        ),
        'mapping',jsonb_build_object('scalars','[]'::jsonb,'profiles','[]'::jsonb),
        'trustRules',coalesce((
          SELECT jsonb_agg(jsonb_build_object(
            'id',rule.id::text,'classRef',rule.exact_value,'level',rule.level,
            'revision',rule.revision,
            'maximumAuthenticationAgeSeconds',rule.maximum_authentication_age_seconds
          ) ORDER BY rule.exact_value,rule.id,rule.revision)
          FROM ONLY public.platform_federated_trust_rules AS rule
          WHERE rule.provider_id=provider.id AND rule.provider_kind='saml'
            AND rule.enabled AND rule.retired_at IS NULL
        ),'[]'::jsonb),
        'clockSkewNanoseconds',configuration.clock_skew_nanoseconds,
        'maxAuthenticationAgeNanoseconds',configuration.max_authentication_age_nanoseconds
      ),
      'metadata',jsonb_build_object(
        'expectedEntityId',configuration.expected_entity_id,
        'revision',metadata.revision,
        'document',replace(encode(metadata.document,'base64'),E'\n',''),
        'digest',replace(encode(metadata.document_digest,'base64'),E'\n',''),
        'retrievedAt',to_jsonb(metadata.retrieved_at),
        'maximumValidUntil',to_jsonb(metadata.maximum_valid_until)
      ),
      'platformFloor',jsonb_build_object(
        'id',platform_floor.id::text,'revision',platform_floor.revision,
        'level',platform_floor.level,'localRequired',platform_floor.local_required,
        'freshnessNanoseconds',platform_floor.freshness_nanoseconds,
        'enrollmentDeadline',to_jsonb(platform_floor.enrollment_deadline)
      ),
      'certificates',(
        SELECT coalesce(jsonb_agg(jsonb_build_object(
          'keyId',sp_key.id::text,'keyRevision',sp_key.revision,
          'platformLoginRevision',login_policy.revision,
          'signing',true,'encryption',false,
          'certificateDer',replace(encode(certificate.certificate_der,'base64'),E'\n','')
        ) ORDER BY sp_key.revision,sp_key.id,certificate.sequence),'[]'::jsonb)
        FROM ONLY public.platform_saml_sp_keys AS sp_key
        JOIN ONLY public.platform_saml_sp_certificates AS certificate
          ON certificate.key_id=sp_key.id
        WHERE sp_key.provider_id=provider.id AND sp_key.retired_at IS NULL
          AND sp_key.revision=configuration.sp_key_revision
      )
    )
  INTO protocol_pins,configuration_record
  FROM ONLY public.platform_auth_providers AS provider
  JOIN ONLY public.platform_federated_provider_policies AS runtime_policy
    ON runtime_policy.provider_id=provider.id AND runtime_policy.provider_kind='saml'
  JOIN ONLY public.platform_saml_login_policies AS login_policy
    ON login_policy.provider_id=provider.id
  JOIN ONLY public.platform_saml_provider_configurations AS configuration
    ON configuration.provider_id=provider.id
   AND configuration.version=runtime_policy.configuration_revision
   AND configuration.encryption_policy='disabled'
   AND cardinality(configuration.decryption_key_versions)=0
  JOIN ONLY public.platform_saml_metadata_snapshots AS metadata
    ON metadata.provider_id=provider.id AND metadata.revision=configuration.metadata_revision
   AND metadata.document_digest=sha256(metadata.document)
   AND metadata.maximum_valid_until>statement_timestamp()
  JOIN ONLY public.platform_saml_sp_keys AS selected_key
    ON selected_key.provider_id=provider.id
   AND selected_key.revision=configuration.sp_key_revision
   AND selected_key.retired_at IS NULL
  JOIN ONLY public.identity_keyring_versions AS root_key
    ON root_key.key_version=selected_key.key_version
   AND root_key.is_active AND root_key.retired_at IS NULL
  JOIN ONLY public.mfa_policy_revisions AS platform_floor
    ON platform_floor.scope='platform_floor' AND platform_floor.tenant_id IS NULL
   AND platform_floor.retired_at IS NULL
  WHERE provider.id=provider_id
    AND configuration.sp_entity_id ~ ('/api/v1/auth/platform/saml/' || provider.key || '/metadata$')
    AND configuration.acs_url ~ '/api/v1/auth/platform/saml/acs$'
    AND NOT EXISTS (SELECT 1 FROM ONLY public.platform_saml_attribute_rules AS rule
                    WHERE rule.provider_id=provider.id)
    AND (SELECT count(*) FROM ONLY public.platform_saml_sp_certificates AS certificate
         WHERE certificate.key_id=selected_key.id) BETWEEN 1 AND 8
    AND (SELECT count(*) FROM ONLY public.mfa_policy_revisions AS counted_floor
         WHERE counted_floor.scope='platform_floor' AND counted_floor.tenant_id IS NULL
           AND counted_floor.retired_at IS NULL)=1;
  IF configuration_record IS NULL THEN RETURN NULL; END IF;
  RETURN configuration_record || jsonb_build_object('pins',protocol_pins);
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RETURN NULL;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.load_platform_saml_planning_state_v1(p_lookup jsonb)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  transaction_id bytea;
  observed_at timestamptz;
  pins jsonb;
  protocol_pins jsonb;
  aliases jsonb;
  matching_identity_count integer;
  result jsonb;
BEGIN
  PERFORM app.private_platform_saml_direct_json_v1(
    p_lookup,ARRAY['transactionId','observedAt','pins','subjectFormat','subjectAliases'],
    ARRAY['transactionId','observedAt','pins','subjectFormat','subjectAliases'],131072
  );
  transaction_id := app.private_mfa_decode_base64_v1(p_lookup ->> 'transactionId',32,32);
  observed_at := (p_lookup ->> 'observedAt')::timestamptz;
  pins := p_lookup -> 'pins';
  protocol_pins := pins -> 'protocol';
  aliases := p_lookup -> 'subjectAliases';
  IF (p_lookup ->> 'subjectFormat')::integer <> 3
     OR jsonb_typeof(aliases) <> 'array'
     OR jsonb_array_length(aliases) NOT BETWEEN 1 AND 16
     OR observed_at NOT BETWEEN statement_timestamp()-interval '5 minutes'
                            AND statement_timestamp()+interval '30 seconds'
     OR EXISTS (
       SELECT 1 FROM jsonb_array_elements(aliases) AS alias(value)
       WHERE jsonb_typeof(alias.value) <> 'object'
          OR (alias.value ->> 'keyVersion')::integer NOT BETWEEN 1 AND 32767
          OR octet_length(app.private_mfa_decode_base64_v1(alias.value ->> 'digest',32,32)) <> 32
     ) THEN
    RAISE EXCEPTION 'invalid direct platform SAML planning lookup'
      USING ERRCODE='22023';
  END IF;
  SELECT count(DISTINCT identity.id)::integer INTO matching_identity_count
  FROM ONLY public.platform_saml_authentication_transactions AS transaction
  JOIN ONLY public.platform_federated_external_identity_aliases AS identity_alias
    ON identity_alias.platform_provider_id=transaction.platform_provider_id
   AND identity_alias.retired_at IS NULL
  JOIN ONLY public.platform_federated_external_identities AS identity
    ON identity.platform_provider_id=identity_alias.platform_provider_id
   AND identity.id=identity_alias.external_identity_id
   AND identity.provider_kind='saml' AND identity.retired_at IS NULL
  JOIN LATERAL jsonb_array_elements(aliases) AS supplied(value)
    ON identity_alias.key_version=(supplied.value ->> 'keyVersion')::integer
   AND identity_alias.subject_digest=app.private_mfa_decode_base64_v1(supplied.value ->> 'digest',32,32)
  WHERE transaction.transaction_id=transaction_id
    AND transaction.state='pending' AND transaction.expires_at>observed_at
    AND app.private_platform_saml_transaction_pins_v1(transaction) IS NOT DISTINCT FROM pins;
  IF matching_identity_count <> 1 THEN RETURN NULL; END IF;

  WITH transaction_record AS (
    SELECT transaction.*
    FROM ONLY public.platform_saml_authentication_transactions AS transaction
    WHERE transaction.transaction_id=transaction_id
      AND transaction.state='pending' AND transaction.expires_at>observed_at
      AND app.private_platform_saml_transaction_pins_v1(transaction) IS NOT DISTINCT FROM pins
  ), matched AS (
    SELECT identity.*,identity_alias.key_version,identity_alias.subject_digest,
      row_number() OVER (ORDER BY identity_alias.key_version DESC) AS rank
    FROM transaction_record AS transaction
    JOIN ONLY public.platform_federated_external_identity_aliases AS identity_alias
      ON identity_alias.platform_provider_id=transaction.platform_provider_id
     AND identity_alias.retired_at IS NULL
    JOIN ONLY public.platform_federated_external_identities AS identity
      ON identity.platform_provider_id=identity_alias.platform_provider_id
     AND identity.id=identity_alias.external_identity_id
     AND identity.provider_kind='saml' AND identity.retired_at IS NULL
    JOIN LATERAL jsonb_array_elements(aliases) AS supplied(value)
      ON identity_alias.key_version=(supplied.value ->> 'keyVersion')::integer
     AND identity_alias.subject_digest=app.private_mfa_decode_base64_v1(supplied.value ->> 'digest',32,32)
  )
  SELECT jsonb_build_object(
    'pins',pins,'providerKind','saml','providerEnabled',provider.enabled,
    'platformLoginLive',login_policy.enabled AND login_policy.account_mode='existing_identity',
    'configurationLive',configuration.version=runtime_policy.configuration_revision,
    'assurancePolicyLive',runtime_policy.assurance_policy_revision=transaction.assurance_policy_revision,
    'matches',jsonb_build_array(jsonb_build_object(
      'providerId',provider.id::text,'externalIdentityId',matched.id::text,
      'userId',local_user.id::text,
      'alias',jsonb_build_object(
        'keyVersion',matched.key_version,
        'digest',replace(encode(matched.subject_digest,'base64'),E'\n','')
      ),
      'identityRevision',matched.version,
      'userAuthenticationRevision',local_user.authentication_revision,
      'platformAuthorityId',role_grant.id::text,'platformAuthorityRevision',1,
      'identityLive',matched.retired_at IS NULL,'aliasLive',true,
      'userActive',local_user.active,'protectedPlatformAuthorityLive',role_grant.revoked_at IS NULL
    )),
    'trustRules',coalesce((
      SELECT jsonb_agg(jsonb_build_object(
        'ruleId',rule.id::text,'revision',rule.revision,'enabled',rule.enabled,
        'classRef',rule.exact_value,'level',rule.level,
        'maximumAuthenticationAgeSeconds',rule.maximum_authentication_age_seconds
      ) ORDER BY rule.exact_value,rule.id,rule.revision)
      FROM ONLY public.platform_federated_trust_rules AS rule
      WHERE rule.provider_id=provider.id AND rule.provider_kind='saml'
        AND rule.enabled AND rule.retired_at IS NULL
    ),'[]'::jsonb),
    'platformFloor',jsonb_build_object(
      'level',platform_floor.level,'localRequired',platform_floor.local_required,
      'freshnessNanoseconds',platform_floor.freshness_nanoseconds,
      'enrollmentDeadline',to_jsonb(platform_floor.enrollment_deadline),
      'policyRevisions',jsonb_build_array(jsonb_build_object(
        'policyId',platform_floor.id::text,'revision',platform_floor.revision
      ))
    ),
    'liveConfirmedTotpFactors',coalesce((
      SELECT jsonb_agg(jsonb_build_object(
        'factorId',factor.id::text,'userId',factor.user_id::text,
        'revision',factor.security_revision,'active',true,
        'confirmedAt',to_jsonb(factor.confirmed_at)
      ) ORDER BY factor.id)
      FROM ONLY public.totp_credentials AS factor
      WHERE factor.user_id=local_user.id AND factor.confirmed_at IS NOT NULL
        AND factor.disabled_at IS NULL
    ),'[]'::jsonb)
  ) INTO result
  FROM transaction_record AS transaction
  JOIN matched ON matched.rank=1
  JOIN ONLY public.platform_auth_providers AS provider
    ON provider.id=transaction.platform_provider_id
   AND provider.kind='saml' AND provider.enabled AND provider.archived_at IS NULL
  JOIN ONLY public.platform_federated_provider_policies AS runtime_policy
    ON runtime_policy.provider_id=provider.id AND runtime_policy.provider_kind='saml'
   AND runtime_policy.enabled AND NOT runtime_policy.platform_login_enabled
  JOIN ONLY public.platform_saml_login_policies AS login_policy
    ON login_policy.provider_id=provider.id
   AND login_policy.revision=transaction.login_policy_revision
  JOIN ONLY public.platform_saml_provider_configurations AS configuration
    ON configuration.provider_id=provider.id
  JOIN ONLY public.users AS local_user
    ON local_user.id=matched.user_id AND local_user.active
  JOIN ONLY public.user_platform_roles AS role_grant
    ON role_grant.user_id=local_user.id AND role_grant.revoked_at IS NULL
  JOIN ONLY public.platform_roles AS platform_role
    ON platform_role.id=role_grant.role_id AND platform_role.key='platform_super_admin'
  JOIN ONLY public.mfa_policy_revisions AS platform_floor
    ON platform_floor.id=transaction.platform_floor_policy_id
   AND platform_floor.revision=transaction.platform_floor_policy_revision
   AND platform_floor.scope='platform_floor' AND platform_floor.tenant_id IS NULL
   AND platform_floor.retired_at IS NULL
  WHERE transaction.provider_revision=provider.version
    AND transaction.configuration_revision=runtime_policy.configuration_revision
    AND transaction.security_revision=runtime_policy.security_revision
    AND transaction.plan_revision=runtime_policy.plan_revision
    AND transaction.assurance_policy_revision=runtime_policy.assurance_policy_revision;
  RETURN result;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid direct platform SAML planning lookup'
    USING ERRCODE='22023';
END;
$function$;
--> statement-breakpoint

COMMENT ON TABLE public.platform_saml_login_policies IS
  'Independent prelinked-only direct platform SAML login lifecycle. Only the protected generic V2 lifecycle ABI may mutate it.';
COMMENT ON COLUMN public.platform_federated_provider_policies.platform_login_enabled IS
  'Retired compatibility sentinel, permanently false. Direct login is governed by protocol-specific OIDC or SAML login policies.';
COMMENT ON COLUMN public.platform_saml_sp_keys.nonce IS
  'Twelve-byte AES-GCM nonce stored separately from ciphertext; semantic revision is independent from the int16 root-key version.';
--> statement-breakpoint

DO $seed_platform_saml_login_policies_v1$
BEGIN
  PERFORM set_config('app.platform_saml_direct_policy_write_v1','on',true);
  INSERT INTO public.platform_saml_login_policies (
    provider_id,provider_kind,account_mode,enabled,revision,created_at,updated_at
  )
  SELECT provider.id,'saml','disabled',false,1,
    greatest(provider.created_at,configuration.created_at),transaction_timestamp()
  FROM ONLY public.platform_auth_providers AS provider
  JOIN ONLY public.platform_federated_provider_policies AS runtime_policy
    ON runtime_policy.provider_id=provider.id AND runtime_policy.provider_kind='saml'
  JOIN ONLY public.platform_saml_provider_configurations AS configuration
    ON configuration.provider_id=provider.id
  WHERE provider.kind='saml'
  ON CONFLICT (provider_id) DO NOTHING;
  PERFORM set_config('app.platform_saml_direct_policy_write_v1','',true);
END;
$seed_platform_saml_login_policies_v1$;
--> statement-breakpoint

CREATE FUNCTION app.ensure_platform_saml_login_policy_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  PERFORM set_config('app.platform_saml_direct_policy_write_v1','on',true);
  INSERT INTO public.platform_saml_login_policies (
    provider_id,provider_kind,account_mode,enabled,revision,created_at,updated_at
  ) VALUES (
    NEW.provider_id,'saml','disabled',false,1,
    greatest(NEW.created_at,transaction_timestamp()),transaction_timestamp()
  ) ON CONFLICT (provider_id) DO NOTHING;
  PERFORM set_config('app.platform_saml_direct_policy_write_v1','',true);
  RETURN NEW;
END;
$function$;
CREATE TRIGGER platform_saml_provider_configurations_login_policy_v1
AFTER INSERT ON public.platform_saml_provider_configurations
FOR EACH ROW EXECUTE FUNCTION app.ensure_platform_saml_login_policy_v1();
--> statement-breakpoint

CREATE FUNCTION app.private_platform_saml_direct_activation_available_v1(
  p_provider_id uuid
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT EXISTS (
    SELECT 1
    FROM ONLY public.platform_auth_providers AS provider
    JOIN ONLY public.platform_federated_provider_policies AS runtime_policy
      ON runtime_policy.provider_id=provider.id AND runtime_policy.provider_kind='saml'
     AND runtime_policy.enabled AND NOT runtime_policy.platform_login_enabled
    JOIN ONLY public.platform_saml_login_policies AS login_policy
      ON login_policy.provider_id=provider.id AND login_policy.provider_kind='saml'
     AND NOT login_policy.enabled AND login_policy.account_mode='disabled'
    JOIN ONLY public.platform_saml_provider_configurations AS configuration
      ON configuration.provider_id=provider.id
     AND configuration.version=runtime_policy.configuration_revision
     AND configuration.encryption_policy='disabled'
     AND cardinality(configuration.decryption_key_versions)=0
    JOIN ONLY public.platform_saml_metadata_snapshots AS metadata
      ON metadata.provider_id=provider.id AND metadata.revision=configuration.metadata_revision
     AND metadata.document_digest=sha256(metadata.document)
     AND metadata.maximum_valid_until>statement_timestamp()
    JOIN ONLY public.platform_saml_sp_keys AS sp_key
      ON sp_key.provider_id=provider.id AND sp_key.revision=configuration.sp_key_revision
     AND sp_key.retired_at IS NULL
    JOIN ONLY public.identity_keyring_versions AS root_key
      ON root_key.key_version=sp_key.key_version
     AND root_key.is_active AND root_key.retired_at IS NULL
    WHERE provider.id=p_provider_id AND provider.kind='saml'
      AND provider.enabled AND provider.archived_at IS NULL
      AND configuration.sp_entity_id ~ ('/api/v1/auth/platform/saml/' || provider.key || '/metadata$')
      AND configuration.acs_url ~ '/api/v1/auth/platform/saml/acs$'
      AND NOT EXISTS (
        SELECT 1 FROM ONLY public.platform_saml_attribute_rules AS rule
        WHERE rule.provider_id=provider.id
      )
      AND (SELECT count(*) FROM ONLY public.platform_saml_sp_certificates AS certificate
           WHERE certificate.key_id=sp_key.id) BETWEEN 1 AND 8
      AND (SELECT count(*) FROM ONLY public.mfa_policy_revisions AS platform_floor
           WHERE platform_floor.scope='platform_floor'
             AND platform_floor.tenant_id IS NULL
             AND platform_floor.retired_at IS NULL)=1
  );
$function$;
--> statement-breakpoint

CREATE FUNCTION app.guard_platform_saml_direct_provider_dependency_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF EXISTS (
    SELECT 1 FROM ONLY public.platform_saml_login_policies AS login_policy
    WHERE login_policy.provider_id=OLD.id AND login_policy.enabled
  ) AND (TG_OP='DELETE' OR NOT NEW.enabled OR NEW.archived_at IS NOT NULL
         OR NEW.kind IS DISTINCT FROM OLD.kind OR NEW.key IS DISTINCT FROM OLD.key) THEN
    RAISE EXCEPTION 'active direct platform SAML login protects provider lifecycle and key'
      USING ERRCODE='55000';
  END IF;
  RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
END;
$function$;
CREATE TRIGGER platform_saml_direct_provider_dependency_guard_v1
BEFORE UPDATE OR DELETE ON public.platform_auth_providers
FOR EACH ROW EXECUTE FUNCTION app.guard_platform_saml_direct_provider_dependency_v1();
--> statement-breakpoint

CREATE FUNCTION app.guard_platform_saml_direct_runtime_dependency_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF EXISTS (
    SELECT 1 FROM ONLY public.platform_saml_login_policies AS login_policy
    WHERE login_policy.provider_id=OLD.provider_id AND login_policy.enabled
  ) AND (TG_OP='DELETE' OR NEW.provider_id IS DISTINCT FROM OLD.provider_id
         OR NEW.provider_kind IS DISTINCT FROM OLD.provider_kind
         OR NOT NEW.enabled OR NEW.platform_login_enabled) THEN
    RAISE EXCEPTION 'active direct platform SAML login requires its tenant-execution runtime'
      USING ERRCODE='55000';
  END IF;
  RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
END;
$function$;
CREATE TRIGGER platform_saml_direct_runtime_dependency_guard_v1
BEFORE UPDATE OR DELETE ON public.platform_federated_provider_policies
FOR EACH ROW EXECUTE FUNCTION app.guard_platform_saml_direct_runtime_dependency_v1();
--> statement-breakpoint

CREATE FUNCTION app.set_platform_saml_direct_login_activation_v1(
  p_session_id uuid,p_provider_id uuid,p_expected_version bigint,p_enabled boolean,
  p_audit_event_id uuid,p_request_id uuid,p_correlation_id uuid,p_ip_address inet,
  p_user_agent text,p_authentication_method text,p_reason text
)
RETURNS TABLE(version bigint,document jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor_id uuid;
  read_actor_id uuid;
  provider_record public.platform_auth_providers%ROWTYPE;
  runtime_record public.platform_federated_provider_policies%ROWTYPE;
  login_record public.platform_saml_login_policies%ROWTYPE;
  changed_at timestamptz := date_trunc('milliseconds',transaction_timestamp());
  updated_count integer;
  provider_document jsonb;
BEGIN
  IF p_provider_id IS NULL OR uuid_extract_version(p_provider_id) IS DISTINCT FROM 7
     OR p_expected_version NOT BETWEEN 1 AND 2147483646 OR p_enabled IS NULL
     OR uuid_extract_version(p_audit_event_id) IS DISTINCT FROM 7
     OR p_reason IS NULL OR NOT app.private_platform_lifecycle_reason_is_valid_v1(p_reason) THEN
    RAISE EXCEPTION 'invalid direct platform SAML lifecycle command'
      USING ERRCODE='22023';
  END IF;
  actor_id := app.private_require_platform_identity_permission_v1(
    p_session_id,'platform.identity_provider.manage',p_authentication_method
  );
  read_actor_id := app.private_require_platform_identity_permission_v1(
    p_session_id,'platform.identity_provider.read',p_authentication_method
  );
  IF actor_id IS DISTINCT FROM read_actor_id THEN
    RAISE EXCEPTION 'live platform identity-provider authority is required'
      USING ERRCODE='42501';
  END IF;
  SELECT provider.* INTO STRICT provider_record
  FROM ONLY public.platform_auth_providers AS provider
  WHERE provider.id=p_provider_id FOR UPDATE;
  SELECT runtime_policy.* INTO STRICT runtime_record
  FROM ONLY public.platform_federated_provider_policies AS runtime_policy
  WHERE runtime_policy.provider_id=p_provider_id AND runtime_policy.provider_kind='saml'
  FOR UPDATE;
  SELECT login_policy.* INTO STRICT login_record
  FROM ONLY public.platform_saml_login_policies AS login_policy
  WHERE login_policy.provider_id=p_provider_id AND login_policy.provider_kind='saml'
  FOR UPDATE;
  IF provider_record.version<>p_expected_version THEN
    RAISE EXCEPTION 'platform identity provider revision conflict'
      USING ERRCODE='40001';
  END IF;
  IF login_record.revision>=9007199254740991 THEN
    RAISE EXCEPTION 'direct platform SAML policy revision is exhausted'
      USING ERRCODE='55000';
  END IF;
  IF p_enabled THEN
    IF provider_record.kind<>'saml' OR provider_record.archived_at IS NOT NULL
       OR NOT provider_record.enabled OR NOT runtime_record.enabled
       OR runtime_record.platform_login_enabled OR login_record.enabled
       OR login_record.account_mode<>'disabled'
       OR NOT app.private_platform_saml_direct_activation_available_v1(p_provider_id) THEN
      RAISE EXCEPTION 'direct platform SAML login is not activation-ready'
        USING ERRCODE='55000';
    END IF;
  ELSIF provider_record.kind<>'saml' OR runtime_record.platform_login_enabled
        OR NOT login_record.enabled OR login_record.account_mode<>'existing_identity' THEN
    RAISE EXCEPTION 'direct platform SAML login cannot be deactivated'
      USING ERRCODE='55000';
  END IF;

  UPDATE ONLY public.platform_auth_providers AS provider
  SET updated_by_user_id=actor_id,version=provider.version+1,updated_at=changed_at
  WHERE provider.id=p_provider_id AND provider.version=p_expected_version;
  GET DIAGNOSTICS updated_count=ROW_COUNT;
  IF updated_count<>1 THEN
    RAISE EXCEPTION 'platform identity provider revision conflict'
      USING ERRCODE='40001';
  END IF;
  PERFORM set_config('app.platform_saml_direct_policy_write_v1','on',true);
  UPDATE ONLY public.platform_saml_login_policies AS login_policy
  SET enabled=p_enabled,account_mode=CASE WHEN p_enabled THEN 'existing_identity' ELSE 'disabled' END,
      revision=login_policy.revision+1,updated_at=changed_at
  WHERE login_policy.provider_id=p_provider_id AND login_policy.revision=login_record.revision;
  GET DIAGNOSTICS updated_count=ROW_COUNT;
  PERFORM set_config('app.platform_saml_direct_policy_write_v1','',true);
  IF updated_count<>1 THEN
    RAISE EXCEPTION 'direct platform SAML policy revision conflict'
      USING ERRCODE='40001';
  END IF;
  IF NOT p_enabled THEN
    PERFORM set_config('app.platform_saml_direct_runtime_write_v1','on',true);
    UPDATE ONLY public.platform_saml_authentication_transactions AS transaction
    SET state='failed',version=transaction.version+1,completed_at=changed_at,
        failure_reason='provider_deactivated'
    WHERE transaction.platform_provider_id=p_provider_id AND transaction.state='pending';
    UPDATE ONLY public.platform_saml_post_primary_totp_challenges AS challenge
    SET state='abandoned',version=challenge.version+1,abandoned_at=changed_at
    FROM ONLY public.platform_saml_post_primary_continuations AS continuation
    WHERE continuation.id=challenge.continuation_id
      AND continuation.platform_provider_id=p_provider_id AND challenge.state='pending';
    UPDATE ONLY public.platform_saml_post_primary_continuations AS continuation
    SET state='revoked',version=continuation.version+1,revoked_at=changed_at,
        revoke_reason='provider_deactivated'
    WHERE continuation.platform_provider_id=p_provider_id AND continuation.state='pending';
    UPDATE ONLY public.auth_sessions AS session
    SET revoked_at=coalesce(session.revoked_at,changed_at),
        revoke_reason=coalesce(session.revoke_reason,'provider_deactivated')
    FROM ONLY public.auth_session_platform_saml_provenance AS provenance
    WHERE provenance.session_id=session.id AND provenance.platform_provider_id=p_provider_id
      AND session.revoked_at IS NULL;
  END IF;
  PERFORM app.append_platform_audit_event(
    p_audit_event_id,'user',actor_id,
    CASE WHEN p_enabled THEN 'platform.identity_provider.direct_login.activated'
         ELSE 'platform.identity_provider.direct_login.deactivated' END,
    'platform_identity_provider',p_provider_id,p_request_id,p_correlation_id,
    p_ip_address,p_user_agent,p_authentication_method,'success',p_reason,
    jsonb_build_object(
      'kind','saml','enabled',p_enabled,
      'account_mode',CASE WHEN p_enabled THEN 'existing_identity' ELSE 'disabled' END,
      'previous_provider_version',provider_record.version,
      'provider_version',provider_record.version+1,
      'previous_login_policy_revision',login_record.revision,
      'login_policy_revision',login_record.revision+1
    )
  );
  provider_document := app.private_platform_auth_provider_document_v1(p_provider_id);
  RETURN QUERY SELECT p_expected_version+1,provider_document;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.set_platform_direct_login_activation_v2(
  p_session_id uuid,p_provider_id uuid,p_expected_version bigint,p_enabled boolean,
  p_audit_event_id uuid,p_request_id uuid,p_correlation_id uuid,p_ip_address inet,
  p_user_agent text,p_authentication_method text,p_reason text
)
RETURNS TABLE(version bigint,document jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE provider_kind public.auth_provider_kind;
BEGIN
  SELECT provider.kind INTO STRICT provider_kind
  FROM ONLY public.platform_auth_providers AS provider
  WHERE provider.id=p_provider_id FOR UPDATE;
  CASE provider_kind
  WHEN 'oidc' THEN
    RETURN QUERY SELECT result.version,result.document
    FROM app.set_platform_oidc_direct_login_activation_v1(
      p_session_id,p_provider_id,p_expected_version,p_enabled,p_audit_event_id,
      p_request_id,p_correlation_id,p_ip_address,p_user_agent,p_authentication_method,p_reason
    ) AS result;
  WHEN 'saml' THEN
    RETURN QUERY SELECT result.version,result.document
    FROM app.set_platform_saml_direct_login_activation_v1(
      p_session_id,p_provider_id,p_expected_version,p_enabled,p_audit_event_id,
      p_request_id,p_correlation_id,p_ip_address,p_user_agent,p_authentication_method,p_reason
    ) AS result;
  ELSE
    RAISE EXCEPTION 'platform provider kind has no direct-login authority'
      USING ERRCODE='55000';
  END CASE;
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'platform provider lifecycle is unavailable'
    USING ERRCODE='P0002';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.activate_platform_direct_login_v2(
  p_session_id uuid,p_provider_id uuid,p_expected_version bigint,
  p_audit_event_id uuid,p_request_id uuid,p_correlation_id uuid,p_ip_address inet,
  p_user_agent text,p_authentication_method text,p_reason text
)
RETURNS TABLE(version bigint,document jsonb)
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT result.version,result.document
  FROM app.set_platform_direct_login_activation_v2(
    p_session_id,p_provider_id,p_expected_version,true,p_audit_event_id,
    p_request_id,p_correlation_id,p_ip_address,p_user_agent,p_authentication_method,p_reason
  ) AS result;
$function$;
CREATE FUNCTION app.deactivate_platform_direct_login_v2(
  p_session_id uuid,p_provider_id uuid,p_expected_version bigint,
  p_audit_event_id uuid,p_request_id uuid,p_correlation_id uuid,p_ip_address inet,
  p_user_agent text,p_authentication_method text,p_reason text
)
RETURNS TABLE(version bigint,document jsonb)
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT result.version,result.document
  FROM app.set_platform_direct_login_activation_v2(
    p_session_id,p_provider_id,p_expected_version,false,p_audit_event_id,
    p_request_id,p_correlation_id,p_ip_address,p_user_agent,p_authentication_method,p_reason
  ) AS result;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.update_platform_auth_provider_v2(
  p_session_id uuid,p_provider_id uuid,p_expected_version bigint,p_key text,
  p_display_name text,p_description text,p_audit_event_id uuid,p_request_id uuid,
  p_correlation_id uuid,p_ip_address inet,p_user_agent text,
  p_authentication_method text,p_reason text
)
RETURNS TABLE(version bigint,document jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE current_key text;
BEGIN
  SELECT provider.key INTO STRICT current_key
  FROM ONLY public.platform_auth_providers AS provider
  WHERE provider.id=p_provider_id FOR UPDATE;
  IF p_key IS DISTINCT FROM current_key THEN
    RAISE EXCEPTION 'platform identity provider key is immutable'
      USING ERRCODE='55000';
  END IF;
  RETURN QUERY SELECT result.version,result.document
  FROM app.update_platform_auth_provider_v1(
    p_session_id,p_provider_id,p_expected_version,current_key,p_display_name,
    p_description,p_audit_event_id,p_request_id,p_correlation_id,p_ip_address,
    p_user_agent,p_authentication_method,p_reason
  ) AS result;
END;
$function$;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.private_platform_auth_provider_document_v1(
  p_provider_id uuid
)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT jsonb_build_object(
    'id',provider.id,'key',provider.key,'displayName',provider.display_name,
    'description',provider.description,'kind',provider.kind,'enabled',provider.enabled,
    'activationAvailable',app.private_platform_oidc_provider_activation_available_v1(provider.id),
    'platformLoginEnabled',CASE provider.kind
      WHEN 'oidc' THEN coalesce(oidc_login.enabled,false)
      WHEN 'saml' THEN coalesce(saml_login.enabled,false)
      ELSE false END,
    'platformLoginActivationAvailable',CASE provider.kind
      WHEN 'oidc' THEN app.private_platform_oidc_direct_activation_available_v1(provider.id)
      WHEN 'saml' THEN app.private_platform_saml_direct_activation_available_v1(provider.id)
      ELSE false END,
    'configurationRevision',policy.configuration_revision,
    'securityRevision',policy.security_revision,'planRevision',policy.plan_revision,
    'assurancePolicyRevision',policy.assurance_policy_revision,
    'accountMode',policy.account_mode,
    'configuration',CASE provider.kind WHEN 'oidc' THEN jsonb_build_object(
      'issuer',oidc.issuer,'clientId',oidc.client_id,'redirectUri',oidc.redirect_uri,
      'tenantRedirectUri',oidc.tenant_redirect_uri,
      'postLogoutRedirectUri',oidc.post_logout_redirect_uri,
      'extraScopes',oidc.extra_scopes,'allowRefreshToken',oidc.allow_refresh_token,
      'useUserInfo',oidc.use_user_info,'clientSecretRevision',oidc.client_secret_revision,
      'clientSecretPresent',EXISTS (
        SELECT 1 FROM ONLY public.platform_oidc_client_secrets AS secret
        WHERE secret.provider_id=provider.id AND secret.retired_at IS NULL
      ),'discoveryRevision',oidc.discovery_revision,'jwksRevision',oidc.jwks_revision
    ) WHEN 'saml' THEN jsonb_build_object(
      'expectedEntityId',saml.expected_entity_id,'spEntityId',saml.sp_entity_id,
      'acsUrl',saml.acs_url,'spKeyRevision',saml.sp_key_revision,
      'spKeyPresent',EXISTS (
        SELECT 1 FROM ONLY public.platform_saml_sp_keys AS sp_key
        WHERE sp_key.provider_id=provider.id AND sp_key.retired_at IS NULL
      ),'metadataRevision',saml.metadata_revision,
      'redirectSignatureAlgorithm',saml.redirect_signature_algorithm,
      'signaturePolicy',saml.signature_policy,'encryptionPolicy',saml.encryption_policy,
      'requestedAuthnContexts',saml.requested_authn_contexts,
      'subjectSource',saml.subject_source,
      'clockSkewNanoseconds',saml.clock_skew_nanoseconds,
      'maxAuthenticationAgeNanoseconds',saml.max_authentication_age_nanoseconds
    ) || CASE WHEN saml.subject_source='immutable_attribute' THEN jsonb_build_object(
      'subjectAttributeName',saml.subject_attribute_name,
      'subjectAttributeNameFormat',saml.subject_attribute_name_format
    ) ELSE '{}'::jsonb END ELSE NULL END,
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
  WHERE provider.id=p_provider_id;
$function$;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.list_platform_auth_providers_v1(
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
     OR (p_after IS NOT NULL AND uuid_extract_version(p_after) IS DISTINCT FROM 7) THEN
    RAISE EXCEPTION 'invalid platform identity provider list request'
      USING ERRCODE='22023';
  END IF;
  PERFORM app.private_require_platform_identity_permission_v1(
    p_session_id,'platform.identity_provider.read',p_authentication_method
  );
  RETURN QUERY
  SELECT jsonb_build_object(
    'id',provider.id,'key',provider.key,'displayName',provider.display_name,
    'description',provider.description,'kind',provider.kind,'enabled',provider.enabled,
    'activationAvailable',app.private_platform_oidc_provider_activation_available_v1(provider.id),
    'platformLoginEnabled',CASE provider.kind
      WHEN 'oidc' THEN coalesce(oidc_login.enabled,false)
      WHEN 'saml' THEN coalesce(saml_login.enabled,false)
      ELSE false END,
    'platformLoginActivationAvailable',CASE provider.kind
      WHEN 'oidc' THEN app.private_platform_oidc_direct_activation_available_v1(provider.id)
      WHEN 'saml' THEN app.private_platform_saml_direct_activation_available_v1(provider.id)
      ELSE false END,
    'configured',CASE provider.kind
      WHEN 'oidc' THEN oidc.provider_id IS NOT NULL
      WHEN 'saml' THEN saml.provider_id IS NOT NULL ELSE false END,
    'secretPresent',CASE provider.kind
      WHEN 'oidc' THEN EXISTS (
        SELECT 1 FROM ONLY public.platform_oidc_client_secrets AS secret
        WHERE secret.provider_id=provider.id AND secret.retired_at IS NULL
      )
      WHEN 'saml' THEN EXISTS (
        SELECT 1 FROM ONLY public.platform_saml_sp_keys AS sp_key
        WHERE sp_key.provider_id=provider.id AND sp_key.retired_at IS NULL
      ) ELSE false END,
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
  WHERE (p_after IS NULL OR provider.id>p_after)
    AND (p_include_archived OR provider.archived_at IS NULL)
  ORDER BY provider.id LIMIT p_limit;
END;
$function$;
--> statement-breakpoint

-- Re-run function closure after the final definition. The earlier closure also
-- seals all tables immediately after DDL; this pass covers functions declared
-- later in this same migration.
DO $platform_saml_runtime_final_acl_v1$
DECLARE object_record record;
BEGIN
  FOR object_record IN
    SELECT procedure.oid::regprocedure AS identity,procedure.proname
    FROM pg_proc AS procedure
    JOIN pg_namespace AS namespace ON namespace.oid=procedure.pronamespace
    WHERE namespace.nspname='app' AND procedure.proname=ANY(ARRAY[
      'private_platform_saml_direct_json_v1','private_platform_saml_create_session_v1',
      'apply_platform_saml_authentication_v1','recover_platform_saml_authentication_apply_v1',
      'reject_platform_saml_authentication_v1','cleanup_platform_saml_authentication_v1',
      'private_platform_saml_totp_projection_v1','begin_platform_saml_post_primary_totp_v1',
      'load_platform_saml_post_primary_totp_v1','record_platform_saml_post_primary_totp_failure_v1',
      'apply_platform_saml_post_primary_totp_v1','recover_platform_saml_post_primary_totp_apply_v1',
      'abandon_platform_saml_post_primary_totp_v1','cleanup_platform_saml_post_primary_totp_apply_v1',
      'private_platform_saml_administration_fence_v1','replace_platform_saml_sp_key_v1',
      'clear_platform_saml_sp_key_v1','replace_platform_saml_metadata_v1',
      'load_platform_saml_metadata_admin_v1','private_platform_saml_direct_audit_v1',
      'guard_platform_saml_direct_runtime_write_v1','guard_platform_saml_login_policy_v1',
      'private_platform_saml_direct_pins_v1','private_platform_saml_direct_configuration_v1',
      'begin_platform_saml_authentication_v1','load_platform_saml_start_configuration_v1',
      'private_platform_saml_transaction_pins_v1','private_platform_saml_transaction_projection_v1',
      'create_platform_saml_authentication_transaction_v1',
      'recover_platform_saml_authentication_transaction_create_v1',
      'lookup_platform_saml_authentication_transaction_v1',
      'resolve_platform_saml_authentication_configuration_v1',
      'abort_platform_saml_authentication_transaction_v1','load_platform_saml_sp_key_envelope_v1',
      'load_platform_saml_metadata_projection_v1','load_platform_saml_planning_state_v1',
      'ensure_platform_saml_login_policy_v1','private_platform_saml_direct_activation_available_v1',
      'guard_platform_saml_direct_provider_dependency_v1',
      'guard_platform_saml_direct_runtime_dependency_v1',
      'set_platform_saml_direct_login_activation_v1','set_platform_direct_login_activation_v2',
      'activate_platform_direct_login_v2','deactivate_platform_direct_login_v2',
      'update_platform_auth_provider_v2','private_platform_auth_provider_document_v1',
      'list_platform_auth_providers_v1'
    ]::name[])
  LOOP
    EXECUTE format('ALTER FUNCTION %s OWNER TO periapsis_migrator',object_record.identity);
    EXECUTE format(
      'REVOKE ALL PRIVILEGES ON FUNCTION %s FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier',
      object_record.identity
    );
    IF object_record.proname=ANY(ARRAY[
      'apply_platform_saml_authentication_v1','recover_platform_saml_authentication_apply_v1',
      'reject_platform_saml_authentication_v1','cleanup_platform_saml_authentication_v1',
      'begin_platform_saml_post_primary_totp_v1','load_platform_saml_post_primary_totp_v1',
      'record_platform_saml_post_primary_totp_failure_v1','apply_platform_saml_post_primary_totp_v1',
      'recover_platform_saml_post_primary_totp_apply_v1','abandon_platform_saml_post_primary_totp_v1',
      'cleanup_platform_saml_post_primary_totp_apply_v1','replace_platform_saml_sp_key_v1',
      'clear_platform_saml_sp_key_v1','replace_platform_saml_metadata_v1',
      'load_platform_saml_metadata_admin_v1','begin_platform_saml_authentication_v1',
      'load_platform_saml_start_configuration_v1','create_platform_saml_authentication_transaction_v1',
      'recover_platform_saml_authentication_transaction_create_v1',
      'lookup_platform_saml_authentication_transaction_v1',
      'resolve_platform_saml_authentication_configuration_v1',
      'abort_platform_saml_authentication_transaction_v1','load_platform_saml_sp_key_envelope_v1',
      'load_platform_saml_metadata_projection_v1','load_platform_saml_planning_state_v1',
      'activate_platform_direct_login_v2','deactivate_platform_direct_login_v2',
      'update_platform_auth_provider_v2','list_platform_auth_providers_v1'
    ]::name[]) THEN
      EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO periapsis_api',object_record.identity);
    END IF;
  END LOOP;
END;
$platform_saml_runtime_final_acl_v1$;
--> statement-breakpoint
