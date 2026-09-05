ALTER TYPE "public"."auth_rate_limit_scope" ADD VALUE 'platform_oidc_network' BEFORE 'mfa_challenge';--> statement-breakpoint
ALTER TYPE "public"."auth_rate_limit_scope" ADD VALUE 'platform_oidc_account' BEFORE 'mfa_challenge';--> statement-breakpoint
ALTER TYPE "public"."auth_rate_limit_scope" ADD VALUE 'platform_oidc_provider' BEFORE 'mfa_challenge';--> statement-breakpoint
CREATE TABLE "auth_session_platform_oidc_evidence" (
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
	CONSTRAINT "auth_session_platform_oidc_evidence_key" UNIQUE("session_id","id"),
	CONSTRAINT "auth_session_platform_oidc_evidence_value_check" CHECK ((uuid_extract_version("auth_session_platform_oidc_evidence"."id") = 7) is true
        and "auth_session_platform_oidc_evidence"."level" in ('primary','mfa','phishing_resistant')
        and ("auth_session_platform_oidc_evidence"."expires_at" is null or "auth_session_platform_oidc_evidence"."expires_at" > "auth_session_platform_oidc_evidence"."authenticated_at")
        and (("auth_session_platform_oidc_evidence"."kind" = 'platform_provider'
          and "auth_session_platform_oidc_evidence"."platform_provider_id" is not null
          and "auth_session_platform_oidc_evidence"."external_identity_id" is not null
          and "auth_session_platform_oidc_evidence"."totp_credential_id" is null
          and "auth_session_platform_oidc_evidence"."factor_revision" is null
          and (("auth_session_platform_oidc_evidence"."level" = 'primary'
            and "auth_session_platform_oidc_evidence"."trust_rule_id" is null
            and "auth_session_platform_oidc_evidence"."trust_rule_revision" is null)
          or ("auth_session_platform_oidc_evidence"."level" in ('mfa','phishing_resistant')
            and (uuid_extract_version("auth_session_platform_oidc_evidence"."trust_rule_id") = 7) is true
            and "auth_session_platform_oidc_evidence"."trust_rule_revision" between 1 and 9007199254740991)))
        or ("auth_session_platform_oidc_evidence"."kind" = 'totp' and "auth_session_platform_oidc_evidence"."level" = 'mfa'
          and "auth_session_platform_oidc_evidence"."platform_provider_id" is null
          and "auth_session_platform_oidc_evidence"."external_identity_id" is null
          and "auth_session_platform_oidc_evidence"."totp_credential_id" is not null
          and "auth_session_platform_oidc_evidence"."factor_revision" between 1 and 9007199254740991
          and "auth_session_platform_oidc_evidence"."trust_rule_id" is null
          and "auth_session_platform_oidc_evidence"."trust_rule_revision" is null)))
);
--> statement-breakpoint
ALTER TABLE "auth_session_platform_oidc_evidence" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "auth_session_platform_oidc_policy_pins" (
	"session_id" uuid NOT NULL,
	"policy_kind" text NOT NULL,
	"policy_id" uuid NOT NULL,
	"policy_revision" bigint NOT NULL,
	CONSTRAINT "auth_session_platform_oidc_policy_pins_pkey" PRIMARY KEY("session_id","policy_kind","policy_id"),
	CONSTRAINT "auth_session_platform_oidc_policy_pins_value_check" CHECK ("auth_session_platform_oidc_policy_pins"."policy_kind" in ('login','assurance','platform_floor')
        and "auth_session_platform_oidc_policy_pins"."policy_revision" between 1 and 9007199254740991)
);
--> statement-breakpoint
ALTER TABLE "auth_session_platform_oidc_policy_pins" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "auth_session_platform_oidc_provenance" (
	"session_id" uuid PRIMARY KEY NOT NULL,
	"user_id" uuid NOT NULL,
	"primary_kind" text DEFAULT 'platform_provider' NOT NULL,
	"platform_provider_id" uuid NOT NULL,
	"external_identity_id" uuid NOT NULL,
	"provider_revision" bigint NOT NULL,
	"login_policy_revision" bigint NOT NULL,
	"security_revision" bigint NOT NULL,
	"user_authentication_revision" bigint NOT NULL,
	"identity_version" bigint NOT NULL,
	"alias_key_version" integer NOT NULL,
	"assurance_policy_revision" bigint NOT NULL,
	"platform_floor_policy_id" uuid NOT NULL,
	"platform_floor_policy_revision" bigint NOT NULL,
	"trust_rule_id" uuid,
	"trust_rule_revision" bigint,
	"authenticated_at" timestamp with time zone NOT NULL,
	CONSTRAINT "auth_session_platform_oidc_provenance_exact_key" UNIQUE("session_id","user_id","platform_provider_id","external_identity_id"),
	CONSTRAINT "auth_session_platform_oidc_provenance_value_check" CHECK ("auth_session_platform_oidc_provenance"."primary_kind" = 'platform_provider'
        and "auth_session_platform_oidc_provenance"."provider_revision" between 1 and 2147483647
        and "auth_session_platform_oidc_provenance"."login_policy_revision" between 1 and 9007199254740991
        and "auth_session_platform_oidc_provenance"."security_revision" between 1 and 9007199254740991
        and "auth_session_platform_oidc_provenance"."user_authentication_revision" between 1 and 9007199254740991
        and "auth_session_platform_oidc_provenance"."identity_version" between 1 and 2147483647
        and "auth_session_platform_oidc_provenance"."alias_key_version" between 1 and 32767
        and "auth_session_platform_oidc_provenance"."assurance_policy_revision" between 1 and 9007199254740991
        and (uuid_extract_version("auth_session_platform_oidc_provenance"."platform_floor_policy_id") = 7) is true
        and "auth_session_platform_oidc_provenance"."platform_floor_policy_revision" between 1 and 9007199254740991
        and (("auth_session_platform_oidc_provenance"."trust_rule_id" is null and "auth_session_platform_oidc_provenance"."trust_rule_revision" is null)
          or ((uuid_extract_version("auth_session_platform_oidc_provenance"."trust_rule_id") = 7) is true
            and "auth_session_platform_oidc_provenance"."trust_rule_revision" between 1 and 9007199254740991)))
);
--> statement-breakpoint
ALTER TABLE "auth_session_platform_oidc_provenance" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "auth_session_platform_oidc_states" (
	"session_id" uuid PRIMARY KEY NOT NULL,
	"user_id" uuid NOT NULL,
	"session_version" bigint NOT NULL,
	"user_authentication_revision" bigint NOT NULL,
	"recovery_restricted" boolean NOT NULL,
	"audience" text NOT NULL,
	"primary_kind" text DEFAULT 'platform_provider' NOT NULL,
	"issued_at" timestamp with time zone NOT NULL,
	CONSTRAINT "auth_session_platform_oidc_states_exact_key" UNIQUE("session_id","user_id","primary_kind"),
	CONSTRAINT "auth_session_platform_oidc_states_user_key" UNIQUE("session_id","user_id"),
	CONSTRAINT "auth_session_platform_oidc_states_value_check" CHECK ("auth_session_platform_oidc_states"."session_version" between 1 and 2147483647
        and "auth_session_platform_oidc_states"."user_authentication_revision" between 1 and 9007199254740991
        and "auth_session_platform_oidc_states"."primary_kind" = 'platform_provider'
        and btrim("auth_session_platform_oidc_states"."audience") = "auth_session_platform_oidc_states"."audience"
        and char_length("auth_session_platform_oidc_states"."audience") between 1 and 256
        and "auth_session_platform_oidc_states"."audience" !~ '[[:cntrl:]]')
);
--> statement-breakpoint
ALTER TABLE "auth_session_platform_oidc_states" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "platform_oidc_authentication_applications" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"transaction_id" "bytea" NOT NULL,
	"operation_digest" "bytea" NOT NULL,
	"platform_provider_id" uuid NOT NULL,
	"external_identity_id" uuid,
	"category" text NOT NULL,
	"primary_kind" text,
	"user_id" uuid,
	"session_id" uuid,
	"continuation_id" uuid,
	"request_snapshot" jsonb NOT NULL,
	"result_snapshot" jsonb NOT NULL,
	"applied_at" timestamp with time zone NOT NULL,
	CONSTRAINT "platform_oidc_auth_applications_operation_key" UNIQUE("operation_digest"),
	CONSTRAINT "platform_oidc_auth_applications_transaction_key" UNIQUE("transaction_id"),
	CONSTRAINT "platform_oidc_auth_applications_value_check" CHECK ((uuid_extract_version("platform_oidc_authentication_applications"."id") = 7) is true
        and octet_length("platform_oidc_authentication_applications"."transaction_id") = 32
        and octet_length("platform_oidc_authentication_applications"."operation_digest") = 32
        and "platform_oidc_authentication_applications"."category" in ('success','identity_collision','stale','denied')
        and jsonb_typeof("platform_oidc_authentication_applications"."request_snapshot") = 'object'
        and pg_column_size("platform_oidc_authentication_applications"."request_snapshot") between 2 and 2097152
        and jsonb_typeof("platform_oidc_authentication_applications"."result_snapshot") = 'object'
        and pg_column_size("platform_oidc_authentication_applications"."result_snapshot") between 2 and 65536
        and (("platform_oidc_authentication_applications"."category" = 'success'
          and "platform_oidc_authentication_applications"."primary_kind" = 'platform_provider'
          and "platform_oidc_authentication_applications"."user_id" is not null
          and "platform_oidc_authentication_applications"."external_identity_id" is not null
          and (("platform_oidc_authentication_applications"."session_id" is null) <> ("platform_oidc_authentication_applications"."continuation_id" is null)))
        or ("platform_oidc_authentication_applications"."category" <> 'success'
          and "platform_oidc_authentication_applications"."primary_kind" is null and "platform_oidc_authentication_applications"."user_id" is null
          and "platform_oidc_authentication_applications"."external_identity_id" is null
          and "platform_oidc_authentication_applications"."session_id" is null and "platform_oidc_authentication_applications"."continuation_id" is null)))
);
--> statement-breakpoint
ALTER TABLE "platform_oidc_authentication_applications" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "platform_oidc_authentication_transactions" (
	"transaction_id" "bytea" PRIMARY KEY NOT NULL,
	"platform_provider_id" uuid NOT NULL,
	"provider_kind" "auth_provider_kind" DEFAULT 'oidc' NOT NULL,
	"protocol" text DEFAULT 'oidc' NOT NULL,
	"operation_run_id" uuid NOT NULL,
	"operation_digest" "bytea" NOT NULL,
	"receipt_digest" "bytea" NOT NULL,
	"network_digest" "bytea" NOT NULL,
	"account_digest" "bytea" NOT NULL,
	"provider_digest" "bytea" NOT NULL,
	"state_digest" "bytea" NOT NULL,
	"browser_digest" "bytea" NOT NULL,
	"browser_capability_digest" "bytea" NOT NULL,
	"nonce_digest" "bytea" NOT NULL,
	"authorization_code_digest" "bytea",
	"code_challenge_method" text DEFAULT 'S256' NOT NULL,
	"provider_revision" bigint NOT NULL,
	"login_policy_revision" bigint NOT NULL,
	"configuration_revision" bigint NOT NULL,
	"security_revision" bigint NOT NULL,
	"plan_revision" bigint NOT NULL,
	"assurance_policy_revision" bigint NOT NULL,
	"platform_floor_policy_id" uuid NOT NULL,
	"platform_floor_policy_revision" bigint NOT NULL,
	"client_secret_revision" bigint NOT NULL,
	"discovery_revision" bigint NOT NULL,
	"discovery_digest" "bytea" NOT NULL,
	"jwks_revision" bigint NOT NULL,
	"jwks_digest" "bytea" NOT NULL,
	"verifier_key_version" integer NOT NULL,
	"verifier_ciphertext" "bytea" NOT NULL,
	"client_id" text NOT NULL,
	"redirect_uri" text NOT NULL,
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
	CONSTRAINT "platform_oidc_auth_transactions_operation_key" UNIQUE("operation_run_id"),
	CONSTRAINT "platform_oidc_auth_transactions_receipt_key" UNIQUE("receipt_digest"),
	CONSTRAINT "platform_oidc_auth_transactions_state_key" UNIQUE("state_digest"),
	CONSTRAINT "platform_oidc_auth_transactions_exact_key" UNIQUE("transaction_id","platform_provider_id"),
	CONSTRAINT "platform_oidc_auth_transactions_id_check" CHECK (octet_length("platform_oidc_authentication_transactions"."transaction_id") = 32
        and (uuid_extract_version("platform_oidc_authentication_transactions"."operation_run_id") = 7) is true),
	CONSTRAINT "platform_oidc_auth_transactions_digest_check" CHECK (octet_length("platform_oidc_authentication_transactions"."operation_digest") = 32
        and octet_length("platform_oidc_authentication_transactions"."receipt_digest") = 32
        and octet_length("platform_oidc_authentication_transactions"."network_digest") = 32
        and octet_length("platform_oidc_authentication_transactions"."account_digest") = 32
        and octet_length("platform_oidc_authentication_transactions"."provider_digest") = 32
        and octet_length("platform_oidc_authentication_transactions"."state_digest") = 32
        and octet_length("platform_oidc_authentication_transactions"."browser_digest") = 32
        and octet_length("platform_oidc_authentication_transactions"."browser_capability_digest") = 32
        and "platform_oidc_authentication_transactions"."browser_capability_digest" <> "platform_oidc_authentication_transactions"."browser_digest"
        and octet_length("platform_oidc_authentication_transactions"."nonce_digest") = 32
        and ("platform_oidc_authentication_transactions"."authorization_code_digest" is null
          or octet_length("platform_oidc_authentication_transactions"."authorization_code_digest") = 32)
        and octet_length("platform_oidc_authentication_transactions"."discovery_digest") = 32
        and octet_length("platform_oidc_authentication_transactions"."jwks_digest") = 32),
	CONSTRAINT "platform_oidc_auth_transactions_pin_check" CHECK ("platform_oidc_authentication_transactions"."provider_kind" = 'oidc' and "platform_oidc_authentication_transactions"."protocol" = 'oidc'
        and "platform_oidc_authentication_transactions"."code_challenge_method" = 'S256'
        and "platform_oidc_authentication_transactions"."provider_revision" between 1 and 2147483647
        and "platform_oidc_authentication_transactions"."login_policy_revision" between 1 and 9007199254740991
        and "platform_oidc_authentication_transactions"."configuration_revision" between 1 and 9007199254740991
        and "platform_oidc_authentication_transactions"."security_revision" between 1 and 9007199254740991
        and "platform_oidc_authentication_transactions"."plan_revision" between 1 and 9007199254740991
        and "platform_oidc_authentication_transactions"."assurance_policy_revision" between 1 and 9007199254740991
        and (uuid_extract_version("platform_oidc_authentication_transactions"."platform_floor_policy_id") = 7) is true
        and "platform_oidc_authentication_transactions"."platform_floor_policy_revision" between 1 and 9007199254740991
        and "platform_oidc_authentication_transactions"."client_secret_revision" between 1 and 9007199254740991
        and "platform_oidc_authentication_transactions"."discovery_revision" between 1 and 9007199254740991
        and "platform_oidc_authentication_transactions"."jwks_revision" between 1 and 9007199254740991
        and "platform_oidc_authentication_transactions"."verifier_key_version" between 1 and 32767
        and octet_length("platform_oidc_authentication_transactions"."verifier_ciphertext") between 16 and 4096
        and octet_length(convert_to("platform_oidc_authentication_transactions"."client_id", 'UTF8')) between 1 and 512
        and "platform_oidc_authentication_transactions"."redirect_uri" ~ '^https://[^/?#@]+/api/v1/auth/platform/oidc/callback$'
        and char_length("platform_oidc_authentication_transactions"."redirect_uri") between 1 and 4096
        and char_length("platform_oidc_authentication_transactions"."post_logout_redirect_uri") between 1 and 4096
        and cardinality("platform_oidc_authentication_transactions"."scopes") between 1 and 64
        and array_position("platform_oidc_authentication_transactions"."scopes", null) is null
        and char_length("platform_oidc_authentication_transactions"."return_path") between 1 and 2048
        and left("platform_oidc_authentication_transactions"."return_path", 1) = '/'
        and "platform_oidc_authentication_transactions"."client_id" !~ '[[:cntrl:]]'
        and "platform_oidc_authentication_transactions"."redirect_uri" !~ '[[:cntrl:]]'
        and "platform_oidc_authentication_transactions"."post_logout_redirect_uri" !~ '[[:cntrl:]]'
        and "platform_oidc_authentication_transactions"."return_path" !~ '[[:cntrl:]]'),
	CONSTRAINT "platform_oidc_auth_transactions_refresh_check" CHECK (not "platform_oidc_authentication_transactions"."allow_refresh_token"),
	CONSTRAINT "platform_oidc_auth_transactions_lifecycle_check" CHECK ("platform_oidc_authentication_transactions"."version" between 1 and 2147483647
        and "platform_oidc_authentication_transactions"."expires_at" between "platform_oidc_authentication_transactions"."created_at" + interval '1 minute'
          and "platform_oidc_authentication_transactions"."created_at" + interval '15 minutes'
        and ((
          "platform_oidc_authentication_transactions"."state" = 'pending' and "platform_oidc_authentication_transactions"."version" = 1
          and "platform_oidc_authentication_transactions"."claim_attempt_id" is null
          and "platform_oidc_authentication_transactions"."authorization_code_digest" is null
          and "platform_oidc_authentication_transactions"."claimed_at" is null and "platform_oidc_authentication_transactions"."completed_at" is null
          and "platform_oidc_authentication_transactions"."failure_reason" is null
        ) or (
          "platform_oidc_authentication_transactions"."state" = 'claimed' and "platform_oidc_authentication_transactions"."version" = 2
          and octet_length("platform_oidc_authentication_transactions"."claim_attempt_id") = 32
          and "platform_oidc_authentication_transactions"."authorization_code_digest" is not null
          and "platform_oidc_authentication_transactions"."claimed_at" is not null and "platform_oidc_authentication_transactions"."completed_at" is null
          and "platform_oidc_authentication_transactions"."failure_reason" is null
        ) or (
          "platform_oidc_authentication_transactions"."state" in ('completed', 'failed', 'expired')
          and "platform_oidc_authentication_transactions"."version" >= 2 and "platform_oidc_authentication_transactions"."completed_at" is not null
          and "platform_oidc_authentication_transactions"."completed_at" >= "platform_oidc_authentication_transactions"."created_at"
          and ("platform_oidc_authentication_transactions"."state" <> 'completed'
            or ("platform_oidc_authentication_transactions"."claim_attempt_id" is not null
              and "platform_oidc_authentication_transactions"."authorization_code_digest" is not null
              and "platform_oidc_authentication_transactions"."failure_reason" is null))
          and ("platform_oidc_authentication_transactions"."state" = 'completed') = ("platform_oidc_authentication_transactions"."failure_reason" is null)
        )))
);
--> statement-breakpoint
ALTER TABLE "platform_oidc_authentication_transactions" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "platform_oidc_login_policies" (
	"provider_id" uuid PRIMARY KEY NOT NULL,
	"provider_kind" "auth_provider_kind" DEFAULT 'oidc' NOT NULL,
	"account_mode" text DEFAULT 'disabled' NOT NULL,
	"enabled" boolean DEFAULT false NOT NULL,
	"revision" bigint DEFAULT 1 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "platform_oidc_login_policies_kind_key" UNIQUE("provider_id","provider_kind"),
	CONSTRAINT "platform_oidc_login_policies_value_check" CHECK ("platform_oidc_login_policies"."provider_kind" = 'oidc'
        and "platform_oidc_login_policies"."account_mode" in ('disabled', 'existing_identity')
        and (not "platform_oidc_login_policies"."enabled" or "platform_oidc_login_policies"."account_mode" = 'existing_identity')
        and "platform_oidc_login_policies"."revision" between 1 and 9007199254740991
        and "platform_oidc_login_policies"."updated_at" >= "platform_oidc_login_policies"."created_at")
);
--> statement-breakpoint
ALTER TABLE "platform_oidc_login_policies" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "platform_oidc_session_revalidation_commands" (
	"session_id" uuid NOT NULL,
	"expected_version" bigint NOT NULL,
	"request_digest" "bytea" NOT NULL,
	"decision" text NOT NULL,
	"result_snapshot" jsonb NOT NULL,
	"applied_at" timestamp with time zone NOT NULL,
	CONSTRAINT "platform_oidc_session_revalidation_commands_pkey" PRIMARY KEY("session_id","expected_version"),
	CONSTRAINT "platform_oidc_session_revalidation_commands_value_check" CHECK ("platform_oidc_session_revalidation_commands"."expected_version" between 1 and 2147483647
        and octet_length("platform_oidc_session_revalidation_commands"."request_digest") = 32
        and "platform_oidc_session_revalidation_commands"."decision" in ('usable','rotate','step_up','revoke','deny')
        and jsonb_typeof("platform_oidc_session_revalidation_commands"."result_snapshot") = 'object'
        and pg_column_size("platform_oidc_session_revalidation_commands"."result_snapshot") between 2 and 65536)
);
--> statement-breakpoint
ALTER TABLE "platform_oidc_session_revalidation_commands" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "platform_oidc_tenant_switch_commands" (
	"source_session_id" uuid NOT NULL,
	"expected_version" bigint NOT NULL,
	"target_tenant_id" uuid NOT NULL,
	"target_tenant_version" bigint NOT NULL,
	"membership_id" uuid NOT NULL,
	"binding_id" uuid NOT NULL,
	"binding_version" bigint NOT NULL,
	"mapping_revision" bigint NOT NULL,
	"authorization_revision" bigint NOT NULL,
	"access_epoch_id" uuid NOT NULL,
	"access_epoch_version" bigint NOT NULL,
	"access_source_id" uuid NOT NULL,
	"access_grant_id" uuid NOT NULL,
	"access_grant_version" bigint NOT NULL,
	"request_digest" "bytea" NOT NULL,
	"decision" text NOT NULL,
	"rotated_session_id" uuid,
	"result_snapshot" jsonb NOT NULL,
	"applied_at" timestamp with time zone NOT NULL,
	CONSTRAINT "platform_oidc_tenant_switch_commands_pkey" PRIMARY KEY("source_session_id","expected_version","target_tenant_id"),
	CONSTRAINT "platform_oidc_tenant_switch_commands_value_check" CHECK ("platform_oidc_tenant_switch_commands"."expected_version" between 1 and 2147483647
        and "platform_oidc_tenant_switch_commands"."target_tenant_version" between 1 and 2147483647
        and "platform_oidc_tenant_switch_commands"."binding_version" between 1 and 2147483647
        and "platform_oidc_tenant_switch_commands"."mapping_revision" between 1 and 9007199254740991
        and "platform_oidc_tenant_switch_commands"."authorization_revision" between 1 and 9007199254740991
        and "platform_oidc_tenant_switch_commands"."access_epoch_version" between 1 and 2147483647
        and "platform_oidc_tenant_switch_commands"."access_grant_version" between 1 and 2147483647
        and octet_length("platform_oidc_tenant_switch_commands"."request_digest") = 32
        and "platform_oidc_tenant_switch_commands"."decision" in ('rotated','stale','denied')
        and ("platform_oidc_tenant_switch_commands"."decision" = 'rotated') = ("platform_oidc_tenant_switch_commands"."rotated_session_id" is not null)
        and jsonb_typeof("platform_oidc_tenant_switch_commands"."result_snapshot") = 'object'
        and pg_column_size("platform_oidc_tenant_switch_commands"."result_snapshot") between 2 and 65536)
);
--> statement-breakpoint
ALTER TABLE "platform_oidc_tenant_switch_commands" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "platform_post_primary_continuation_evidence" (
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
	CONSTRAINT "platform_post_primary_continuation_evidence_key" UNIQUE("continuation_id","id"),
	CONSTRAINT "platform_post_primary_continuation_evidence_value_check" CHECK ((uuid_extract_version("platform_post_primary_continuation_evidence"."id") = 7) is true
        and "platform_post_primary_continuation_evidence"."level" in ('primary','mfa','phishing_resistant')
        and ("platform_post_primary_continuation_evidence"."expires_at" is null or "platform_post_primary_continuation_evidence"."expires_at" > "platform_post_primary_continuation_evidence"."authenticated_at")
        and (("platform_post_primary_continuation_evidence"."kind" = 'platform_provider'
          and "platform_post_primary_continuation_evidence"."platform_provider_id" is not null
          and "platform_post_primary_continuation_evidence"."external_identity_id" is not null
          and "platform_post_primary_continuation_evidence"."totp_credential_id" is null
          and "platform_post_primary_continuation_evidence"."factor_revision" is null
          and (("platform_post_primary_continuation_evidence"."level" = 'primary'
            and "platform_post_primary_continuation_evidence"."trust_rule_id" is null
            and "platform_post_primary_continuation_evidence"."trust_rule_revision" is null)
          or ("platform_post_primary_continuation_evidence"."level" in ('mfa','phishing_resistant')
            and (uuid_extract_version("platform_post_primary_continuation_evidence"."trust_rule_id") = 7) is true
            and "platform_post_primary_continuation_evidence"."trust_rule_revision" between 1 and 9007199254740991)))
        or ("platform_post_primary_continuation_evidence"."kind" = 'totp' and "platform_post_primary_continuation_evidence"."level" = 'mfa'
          and "platform_post_primary_continuation_evidence"."platform_provider_id" is null
          and "platform_post_primary_continuation_evidence"."external_identity_id" is null
          and "platform_post_primary_continuation_evidence"."totp_credential_id" is not null
          and "platform_post_primary_continuation_evidence"."factor_revision" between 1 and 9007199254740991
          and "platform_post_primary_continuation_evidence"."trust_rule_id" is null
          and "platform_post_primary_continuation_evidence"."trust_rule_revision" is null)))
);
--> statement-breakpoint
ALTER TABLE "platform_post_primary_continuation_evidence" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "platform_post_primary_continuation_policy_pins" (
	"continuation_id" uuid NOT NULL,
	"policy_kind" text NOT NULL,
	"policy_id" uuid NOT NULL,
	"policy_revision" bigint NOT NULL,
	CONSTRAINT "platform_post_primary_continuation_policy_pins_pkey" PRIMARY KEY("continuation_id","policy_kind","policy_id"),
	CONSTRAINT "platform_post_primary_continuation_policy_pins_value_check" CHECK ("platform_post_primary_continuation_policy_pins"."policy_kind" in ('login','assurance','platform_floor')
        and "platform_post_primary_continuation_policy_pins"."policy_revision" between 1 and 9007199254740991)
);
--> statement-breakpoint
ALTER TABLE "platform_post_primary_continuation_policy_pins" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "platform_post_primary_continuations" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"user_id" uuid NOT NULL,
	"receipt_digest" "bytea" NOT NULL,
	"action" text NOT NULL,
	"audience" text NOT NULL,
	"platform_provider_id" uuid NOT NULL,
	"external_identity_id" uuid NOT NULL,
	"provider_revision" bigint NOT NULL,
	"login_policy_revision" bigint NOT NULL,
	"security_revision" bigint NOT NULL,
	"user_authentication_revision" bigint NOT NULL,
	"identity_version" bigint NOT NULL,
	"alias_key_version" integer NOT NULL,
	"assurance_policy_revision" bigint NOT NULL,
	"platform_floor_policy_id" uuid NOT NULL,
	"platform_floor_policy_revision" bigint NOT NULL,
	"selected_totp_credential_id" uuid NOT NULL,
	"selected_totp_security_revision" bigint NOT NULL,
	"trust_rule_id" uuid,
	"trust_rule_revision" bigint,
	"origin" text DEFAULT 'initial_login' NOT NULL,
	"source_session_id" uuid,
	"source_session_family_id" uuid,
	"source_session_version" bigint,
	"source_absolute_expires_at" timestamp with time zone,
	"state" text DEFAULT 'pending' NOT NULL,
	"version" bigint DEFAULT 1 NOT NULL,
	"created_at" timestamp with time zone NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"consumed_at" timestamp with time zone,
	"revoked_at" timestamp with time zone,
	"revoke_reason" text,
	CONSTRAINT "platform_post_primary_continuations_receipt_key" UNIQUE("receipt_digest"),
	CONSTRAINT "platform_post_primary_continuations_user_key" UNIQUE("id","user_id"),
	CONSTRAINT "platform_post_primary_continuations_exact_key" UNIQUE("id","user_id","platform_provider_id","external_identity_id"),
	CONSTRAINT "platform_post_primary_continuations_id_check" CHECK ((uuid_extract_version("platform_post_primary_continuations"."id") = 7) is true
        and octet_length("platform_post_primary_continuations"."receipt_digest") = 32),
	CONSTRAINT "platform_post_primary_continuations_pin_check" CHECK ("platform_post_primary_continuations"."provider_revision" between 1 and 2147483647
        and "platform_post_primary_continuations"."login_policy_revision" between 1 and 9007199254740991
        and "platform_post_primary_continuations"."security_revision" between 1 and 9007199254740991
        and "platform_post_primary_continuations"."user_authentication_revision" between 1 and 9007199254740991
        and "platform_post_primary_continuations"."identity_version" between 1 and 2147483647
        and "platform_post_primary_continuations"."alias_key_version" between 1 and 32767
        and "platform_post_primary_continuations"."assurance_policy_revision" between 1 and 9007199254740991
        and (uuid_extract_version("platform_post_primary_continuations"."platform_floor_policy_id") = 7) is true
        and "platform_post_primary_continuations"."platform_floor_policy_revision" between 1 and 9007199254740991
        and (uuid_extract_version("platform_post_primary_continuations"."selected_totp_credential_id") = 7) is true
        and "platform_post_primary_continuations"."selected_totp_security_revision" between 1 and 9007199254740991
        and (("platform_post_primary_continuations"."trust_rule_id" is null and "platform_post_primary_continuations"."trust_rule_revision" is null)
          or ((uuid_extract_version("platform_post_primary_continuations"."trust_rule_id") = 7) is true
            and "platform_post_primary_continuations"."trust_rule_revision" between 1 and 9007199254740991))
        and (("platform_post_primary_continuations"."origin" = 'initial_login'
          and "platform_post_primary_continuations"."source_session_id" is null
          and "platform_post_primary_continuations"."source_session_family_id" is null
          and "platform_post_primary_continuations"."source_session_version" is null
          and "platform_post_primary_continuations"."source_absolute_expires_at" is null)
        or ("platform_post_primary_continuations"."origin" = 'session_revalidation'
          and "platform_post_primary_continuations"."source_session_id" is not null
          and (uuid_extract_version("platform_post_primary_continuations"."source_session_family_id") = 7) is true
          and "platform_post_primary_continuations"."source_session_version" between 1 and 2147483647
          and "platform_post_primary_continuations"."source_absolute_expires_at" > "platform_post_primary_continuations"."created_at"))),
	CONSTRAINT "platform_post_primary_continuations_text_check" CHECK (btrim("platform_post_primary_continuations"."action") = "platform_post_primary_continuations"."action"
        and char_length("platform_post_primary_continuations"."action") between 1 and 256
        and "platform_post_primary_continuations"."action" !~ '[[:cntrl:]]'
        and btrim("platform_post_primary_continuations"."audience") = "platform_post_primary_continuations"."audience"
        and char_length("platform_post_primary_continuations"."audience") between 1 and 256
        and "platform_post_primary_continuations"."audience" !~ '[[:cntrl:]]'),
	CONSTRAINT "platform_post_primary_continuations_lifecycle_check" CHECK ("platform_post_primary_continuations"."expires_at" > "platform_post_primary_continuations"."created_at"
        and (( "platform_post_primary_continuations"."state" = 'pending' and "platform_post_primary_continuations"."version" = 1
          and "platform_post_primary_continuations"."consumed_at" is null and "platform_post_primary_continuations"."revoked_at" is null
          and "platform_post_primary_continuations"."revoke_reason" is null)
        or ("platform_post_primary_continuations"."state" = 'consumed' and "platform_post_primary_continuations"."version" >= 2
          and "platform_post_primary_continuations"."consumed_at" between "platform_post_primary_continuations"."created_at" and "platform_post_primary_continuations"."expires_at"
          and "platform_post_primary_continuations"."revoked_at" is null and "platform_post_primary_continuations"."revoke_reason" is null)
        or ("platform_post_primary_continuations"."state" in ('revoked','expired') and "platform_post_primary_continuations"."version" >= 2
          and "platform_post_primary_continuations"."consumed_at" is null and "platform_post_primary_continuations"."revoked_at" >= "platform_post_primary_continuations"."created_at"
          and btrim("platform_post_primary_continuations"."revoke_reason") <> ''
          and char_length("platform_post_primary_continuations"."revoke_reason") <= 500
          and "platform_post_primary_continuations"."revoke_reason" !~ '[[:cntrl:]]')))
);
--> statement-breakpoint
ALTER TABLE "platform_post_primary_continuations" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "platform_post_primary_totp_challenges" (
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
	"result_snapshot" jsonb,
	"created_at" timestamp with time zone NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"completed_at" timestamp with time zone,
	"abandoned_at" timestamp with time zone,
	CONSTRAINT "platform_post_primary_totp_challenges_continuation_key" UNIQUE("continuation_id"),
	CONSTRAINT "platform_post_primary_totp_challenges_value_check" CHECK (octet_length("platform_post_primary_totp_challenges"."id") = 32
        and octet_length("platform_post_primary_totp_challenges"."browser_digest") = 32
        and "platform_post_primary_totp_challenges"."expected_continuation_version" between 1 and 2147483647
        and "platform_post_primary_totp_challenges"."user_authentication_revision" between 1 and 9007199254740991
        and "platform_post_primary_totp_challenges"."totp_security_revision" between 1 and 9007199254740991
        and "platform_post_primary_totp_challenges"."failure_count" between 0 and 5
        and "platform_post_primary_totp_challenges"."version" between 1 and 2147483647
        and "platform_post_primary_totp_challenges"."expires_at" between "platform_post_primary_totp_challenges"."created_at" + interval '1 minute'
          and "platform_post_primary_totp_challenges"."created_at" + interval '10 minutes'
        and (("platform_post_primary_totp_challenges"."state" = 'pending'
          and "platform_post_primary_totp_challenges"."completed_at" is null and "platform_post_primary_totp_challenges"."abandoned_at" is null
          and "platform_post_primary_totp_challenges"."completion_request_digest" is null
          and "platform_post_primary_totp_challenges"."result_snapshot" is null)
        or ("platform_post_primary_totp_challenges"."state" = 'completed'
          and "platform_post_primary_totp_challenges"."completed_at" >= "platform_post_primary_totp_challenges"."created_at"
          and "platform_post_primary_totp_challenges"."abandoned_at" is null
          and octet_length("platform_post_primary_totp_challenges"."completion_request_digest") = 32
          and jsonb_typeof("platform_post_primary_totp_challenges"."result_snapshot") = 'object'
          and pg_column_size("platform_post_primary_totp_challenges"."result_snapshot") between 2 and 65536)
        or ("platform_post_primary_totp_challenges"."state" in ('abandoned','expired','failed')
          and "platform_post_primary_totp_challenges"."completed_at" is null
          and "platform_post_primary_totp_challenges"."abandoned_at" >= "platform_post_primary_totp_challenges"."created_at"
          and "platform_post_primary_totp_challenges"."completion_request_digest" is null
          and "platform_post_primary_totp_challenges"."result_snapshot" is null)))
);
--> statement-breakpoint
ALTER TABLE "platform_post_primary_totp_challenges" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "totp_credentials" ADD COLUMN "security_revision" bigint DEFAULT 1 NOT NULL;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "authentication_revision" bigint DEFAULT 1 NOT NULL;--> statement-breakpoint
ALTER TABLE "auth_session_platform_oidc_evidence" ADD CONSTRAINT "auth_session_platform_oidc_evidence_state_fk" FOREIGN KEY ("session_id","user_id") REFERENCES "public"."auth_session_platform_oidc_states"("session_id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "auth_session_platform_oidc_evidence" ADD CONSTRAINT "auth_session_platform_oidc_evidence_identity_fk" FOREIGN KEY ("platform_provider_id","external_identity_id","user_id") REFERENCES "public"."platform_federated_external_identities"("platform_provider_id","id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "auth_session_platform_oidc_evidence" ADD CONSTRAINT "auth_session_platform_oidc_evidence_totp_fk" FOREIGN KEY ("totp_credential_id","user_id") REFERENCES "public"."totp_credentials"("id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "auth_session_platform_oidc_policy_pins" ADD CONSTRAINT "auth_session_platform_oidc_policy_pins_state_fk" FOREIGN KEY ("session_id") REFERENCES "public"."auth_session_platform_oidc_states"("session_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "auth_session_platform_oidc_provenance" ADD CONSTRAINT "auth_session_platform_oidc_provenance_state_fk" FOREIGN KEY ("session_id","user_id","primary_kind") REFERENCES "public"."auth_session_platform_oidc_states"("session_id","user_id","primary_kind") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "auth_session_platform_oidc_provenance" ADD CONSTRAINT "auth_session_platform_oidc_provenance_identity_fk" FOREIGN KEY ("platform_provider_id","external_identity_id","user_id") REFERENCES "public"."platform_federated_external_identities"("platform_provider_id","id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "auth_session_platform_oidc_provenance" ADD CONSTRAINT "auth_session_platform_oidc_provenance_platform_floor_fk" FOREIGN KEY ("platform_floor_policy_id","platform_floor_policy_revision") REFERENCES "public"."mfa_policy_revisions"("id","revision") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "auth_session_platform_oidc_states" ADD CONSTRAINT "auth_session_platform_oidc_states_session_id_auth_sessions_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."auth_sessions"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "auth_session_platform_oidc_states" ADD CONSTRAINT "auth_session_platform_oidc_states_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "platform_oidc_authentication_applications" ADD CONSTRAINT "platform_oidc_authentication_applications_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "platform_oidc_authentication_applications" ADD CONSTRAINT "platform_oidc_authentication_applications_session_id_auth_sessions_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."auth_sessions"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "platform_oidc_authentication_applications" ADD CONSTRAINT "platform_oidc_authentication_applications_continuation_id_platform_post_primary_continuations_id_fk" FOREIGN KEY ("continuation_id") REFERENCES "public"."platform_post_primary_continuations"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "platform_oidc_authentication_applications" ADD CONSTRAINT "platform_oidc_auth_applications_transaction_fk" FOREIGN KEY ("transaction_id","platform_provider_id") REFERENCES "public"."platform_oidc_authentication_transactions"("transaction_id","platform_provider_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_oidc_authentication_applications" ADD CONSTRAINT "platform_oidc_auth_applications_identity_fk" FOREIGN KEY ("platform_provider_id","external_identity_id","user_id") REFERENCES "public"."platform_federated_external_identities"("platform_provider_id","id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_oidc_authentication_transactions" ADD CONSTRAINT "platform_oidc_auth_transactions_provider_fk" FOREIGN KEY ("platform_provider_id","provider_kind") REFERENCES "public"."platform_auth_providers"("id","kind") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_oidc_authentication_transactions" ADD CONSTRAINT "platform_oidc_auth_transactions_policy_fk" FOREIGN KEY ("platform_provider_id","provider_kind") REFERENCES "public"."platform_federated_provider_policies"("provider_id","provider_kind") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_oidc_authentication_transactions" ADD CONSTRAINT "platform_oidc_auth_transactions_login_policy_fk" FOREIGN KEY ("platform_provider_id","provider_kind") REFERENCES "public"."platform_oidc_login_policies"("provider_id","provider_kind") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_oidc_authentication_transactions" ADD CONSTRAINT "platform_oidc_auth_transactions_configuration_fk" FOREIGN KEY ("platform_provider_id") REFERENCES "public"."platform_oidc_provider_configurations"("provider_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_oidc_authentication_transactions" ADD CONSTRAINT "platform_oidc_auth_transactions_keyring_fk" FOREIGN KEY ("verifier_key_version") REFERENCES "public"."identity_keyring_versions"("key_version") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_oidc_authentication_transactions" ADD CONSTRAINT "platform_oidc_auth_transactions_platform_floor_fk" FOREIGN KEY ("platform_floor_policy_id","platform_floor_policy_revision") REFERENCES "public"."mfa_policy_revisions"("id","revision") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_oidc_login_policies" ADD CONSTRAINT "platform_oidc_login_policies_provider_fk" FOREIGN KEY ("provider_id","provider_kind") REFERENCES "public"."platform_auth_providers"("id","kind") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_oidc_login_policies" ADD CONSTRAINT "platform_oidc_login_policies_runtime_policy_fk" FOREIGN KEY ("provider_id","provider_kind") REFERENCES "public"."platform_federated_provider_policies"("provider_id","provider_kind") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_oidc_login_policies" ADD CONSTRAINT "platform_oidc_login_policies_configuration_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."platform_oidc_provider_configurations"("provider_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_oidc_session_revalidation_commands" ADD CONSTRAINT "platform_oidc_session_revalidation_commands_session_fk" FOREIGN KEY ("session_id") REFERENCES "public"."auth_session_platform_oidc_states"("session_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_oidc_tenant_switch_commands" ADD CONSTRAINT "platform_oidc_tenant_switch_commands_target_tenant_id_tenants_id_fk" FOREIGN KEY ("target_tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "platform_oidc_tenant_switch_commands" ADD CONSTRAINT "platform_oidc_tenant_switch_commands_rotated_session_id_auth_sessions_id_fk" FOREIGN KEY ("rotated_session_id") REFERENCES "public"."auth_sessions"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "platform_oidc_tenant_switch_commands" ADD CONSTRAINT "platform_oidc_tenant_switch_commands_source_fk" FOREIGN KEY ("source_session_id") REFERENCES "public"."auth_session_platform_oidc_states"("session_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_post_primary_continuation_evidence" ADD CONSTRAINT "platform_post_primary_continuation_evidence_parent_fk" FOREIGN KEY ("continuation_id","user_id") REFERENCES "public"."platform_post_primary_continuations"("id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_post_primary_continuation_evidence" ADD CONSTRAINT "platform_post_primary_continuation_evidence_identity_fk" FOREIGN KEY ("platform_provider_id","external_identity_id","user_id") REFERENCES "public"."platform_federated_external_identities"("platform_provider_id","id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_post_primary_continuation_evidence" ADD CONSTRAINT "platform_post_primary_continuation_evidence_totp_fk" FOREIGN KEY ("totp_credential_id","user_id") REFERENCES "public"."totp_credentials"("id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_post_primary_continuation_policy_pins" ADD CONSTRAINT "platform_post_primary_continuation_policy_pins_parent_fk" FOREIGN KEY ("continuation_id") REFERENCES "public"."platform_post_primary_continuations"("id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_post_primary_continuations" ADD CONSTRAINT "platform_post_primary_continuations_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "platform_post_primary_continuations" ADD CONSTRAINT "platform_post_primary_continuations_source_session_id_auth_sessions_id_fk" FOREIGN KEY ("source_session_id") REFERENCES "public"."auth_sessions"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "platform_post_primary_continuations" ADD CONSTRAINT "platform_post_primary_continuations_identity_fk" FOREIGN KEY ("platform_provider_id","external_identity_id","user_id") REFERENCES "public"."platform_federated_external_identities"("platform_provider_id","id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_post_primary_continuations" ADD CONSTRAINT "platform_post_primary_continuations_platform_floor_fk" FOREIGN KEY ("platform_floor_policy_id","platform_floor_policy_revision") REFERENCES "public"."mfa_policy_revisions"("id","revision") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_post_primary_continuations" ADD CONSTRAINT "platform_post_primary_continuations_selected_totp_fk" FOREIGN KEY ("selected_totp_credential_id","user_id") REFERENCES "public"."totp_credentials"("id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_post_primary_totp_challenges" ADD CONSTRAINT "platform_post_primary_totp_challenges_parent_fk" FOREIGN KEY ("continuation_id","user_id") REFERENCES "public"."platform_post_primary_continuations"("id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "platform_post_primary_totp_challenges" ADD CONSTRAINT "platform_post_primary_totp_challenges_factor_fk" FOREIGN KEY ("totp_credential_id","user_id") REFERENCES "public"."totp_credentials"("id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
CREATE INDEX "auth_session_platform_oidc_states_user_idx" ON "auth_session_platform_oidc_states" USING btree ("user_id","issued_at","session_id");--> statement-breakpoint
CREATE UNIQUE INDEX "platform_oidc_auth_transactions_live_browser_key" ON "platform_oidc_authentication_transactions" USING btree ("browser_digest") WHERE "platform_oidc_authentication_transactions"."state" in ('pending', 'claimed');--> statement-breakpoint
CREATE INDEX "platform_oidc_auth_transactions_expiry_idx" ON "platform_oidc_authentication_transactions" USING btree ("state","expires_at","transaction_id");--> statement-breakpoint
CREATE INDEX "platform_post_primary_continuations_pending_idx" ON "platform_post_primary_continuations" USING btree ("user_id","expires_at","id") WHERE "platform_post_primary_continuations"."state" = 'pending';--> statement-breakpoint
CREATE INDEX "platform_post_primary_totp_challenges_expiry_idx" ON "platform_post_primary_totp_challenges" USING btree ("expires_at","id") WHERE "platform_post_primary_totp_challenges"."state" = 'pending';--> statement-breakpoint
ALTER TABLE "totp_credentials" ADD CONSTRAINT "totp_credentials_security_revision_check" CHECK ("totp_credentials"."security_revision" between 1 and 9007199254740991);--> statement-breakpoint
ALTER TABLE "users" ADD CONSTRAINT "users_authentication_revision_check" CHECK ("users"."authentication_revision" between 1 and 9007199254740991);
