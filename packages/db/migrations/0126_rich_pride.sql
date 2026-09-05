CREATE TABLE "auth_session_federated_provenance" (
	"tenant_id" uuid NOT NULL,
	"session_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"primary_kind" text DEFAULT 'tenant_provider' NOT NULL,
	"authentication_method" text NOT NULL,
	"provider_id" uuid NOT NULL,
	"binding_id" uuid NOT NULL,
	"provider_kind" "auth_provider_kind" NOT NULL,
	"external_identity_id" uuid NOT NULL,
	"external_identity_revision" bigint NOT NULL,
	"trust_rule_revision" bigint NOT NULL,
	"authenticated_at" timestamp with time zone NOT NULL,
	CONSTRAINT "auth_session_federated_provenance_pkey" PRIMARY KEY("tenant_id","session_id"),
	CONSTRAINT "auth_session_federated_provenance_provider_key" UNIQUE("tenant_id","session_id","provider_id","binding_id"),
	CONSTRAINT "auth_session_federated_provenance_exact_key" UNIQUE("tenant_id","session_id","user_id","provider_id","binding_id","provider_kind","external_identity_id"),
	CONSTRAINT "auth_session_federated_provenance_value_check" CHECK ("auth_session_federated_provenance"."primary_kind" = 'tenant_provider'
        and "auth_session_federated_provenance"."authentication_method" in ('oidc','saml')
        and "auth_session_federated_provenance"."provider_kind"::text = "auth_session_federated_provenance"."authentication_method"
        and "auth_session_federated_provenance"."external_identity_revision" > 0 and "auth_session_federated_provenance"."trust_rule_revision" > 0)
);
--> statement-breakpoint
ALTER TABLE "auth_session_federated_provenance" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_federated_authentication_applications" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"protocol" text NOT NULL,
	"transaction_id" "bytea",
	"operation_digest" "bytea" NOT NULL,
	"provider_id" uuid,
	"binding_id" uuid,
	"provider_kind" "auth_provider_kind",
	"response_id_digest" "bytea",
	"assertion_id_digest" "bytea",
	"session_index_digest" "bytea",
	"category" text NOT NULL,
	"primary_kind" text,
	"user_id" uuid,
	"session_id" uuid,
	"continuation_id" uuid,
	"request_snapshot" jsonb NOT NULL,
	"result_snapshot" jsonb NOT NULL,
	"applied_at" timestamp with time zone NOT NULL,
	CONSTRAINT "tenant_federated_authentication_applications_operation_key" UNIQUE("tenant_id","operation_digest"),
	CONSTRAINT "tenant_federated_authentication_applications_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_federated_authentication_applications"."id") = 7) is true),
	CONSTRAINT "tenant_federated_authentication_applications_digest_check" CHECK (octet_length("tenant_federated_authentication_applications"."operation_digest") = 32
        and ("tenant_federated_authentication_applications"."transaction_id" is null or octet_length("tenant_federated_authentication_applications"."transaction_id") = 32)),
	CONSTRAINT "tenant_federated_authentication_applications_protocol_check" CHECK ((("tenant_federated_authentication_applications"."protocol" = 'passkey'
          and "tenant_federated_authentication_applications"."transaction_id" is null and "tenant_federated_authentication_applications"."provider_id" is null and "tenant_federated_authentication_applications"."binding_id" is null
          and "tenant_federated_authentication_applications"."provider_kind" is null
          and "tenant_federated_authentication_applications"."response_id_digest" is null and "tenant_federated_authentication_applications"."assertion_id_digest" is null
          and "tenant_federated_authentication_applications"."session_index_digest" is null)
        or ("tenant_federated_authentication_applications"."protocol" = 'oidc'
          and octet_length("tenant_federated_authentication_applications"."transaction_id") = 32
          and "tenant_federated_authentication_applications"."provider_id" is not null and "tenant_federated_authentication_applications"."binding_id" is not null
          and "tenant_federated_authentication_applications"."provider_kind" = 'oidc'
          and "tenant_federated_authentication_applications"."response_id_digest" is null and "tenant_federated_authentication_applications"."assertion_id_digest" is null
          and "tenant_federated_authentication_applications"."session_index_digest" is null)
        or ("tenant_federated_authentication_applications"."protocol" = 'saml'
          and octet_length("tenant_federated_authentication_applications"."transaction_id") = 32
          and "tenant_federated_authentication_applications"."provider_id" is not null and "tenant_federated_authentication_applications"."binding_id" is not null
          and "tenant_federated_authentication_applications"."provider_kind" = 'saml'
          and octet_length("tenant_federated_authentication_applications"."response_id_digest") = 32
          and octet_length("tenant_federated_authentication_applications"."assertion_id_digest") = 32
          and ("tenant_federated_authentication_applications"."session_index_digest" is null
            or octet_length("tenant_federated_authentication_applications"."session_index_digest") = 32))) is true),
	CONSTRAINT "tenant_federated_authentication_applications_result_check" CHECK ("tenant_federated_authentication_applications"."category" in ('success','identity_collision','stale','denied')
        and jsonb_typeof("tenant_federated_authentication_applications"."request_snapshot") = 'object'
        and pg_column_size("tenant_federated_authentication_applications"."request_snapshot") between 2 and 2097152
        and jsonb_typeof("tenant_federated_authentication_applications"."result_snapshot") = 'object'
        and pg_column_size("tenant_federated_authentication_applications"."result_snapshot") between 2 and 65536
        and (("tenant_federated_authentication_applications"."category" = 'success'
            and "tenant_federated_authentication_applications"."user_id" is not null
            and (("tenant_federated_authentication_applications"."protocol" = 'passkey' and "tenant_federated_authentication_applications"."primary_kind" = 'passkey')
              or ("tenant_federated_authentication_applications"."protocol" in ('oidc','saml') and "tenant_federated_authentication_applications"."primary_kind" = 'tenant_provider'))
            and (("tenant_federated_authentication_applications"."session_id" is null) <> ("tenant_federated_authentication_applications"."continuation_id" is null)))
          or ("tenant_federated_authentication_applications"."category" <> 'success'
            and "tenant_federated_authentication_applications"."primary_kind" is null
            and "tenant_federated_authentication_applications"."user_id" is null and "tenant_federated_authentication_applications"."session_id" is null and "tenant_federated_authentication_applications"."continuation_id" is null)))
);
--> statement-breakpoint
ALTER TABLE "tenant_federated_authentication_applications" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_federated_authentication_transactions" (
	"transaction_id" "bytea" NOT NULL,
	"tenant_id" uuid NOT NULL,
	"provider_id" uuid NOT NULL,
	"binding_id" uuid NOT NULL,
	"provider_kind" "auth_provider_kind" NOT NULL,
	"protocol" text NOT NULL,
	"operation_run_id" uuid NOT NULL,
	"operation_digest" "bytea" NOT NULL,
	"receipt_digest" "bytea" NOT NULL,
	"network_digest" "bytea" NOT NULL,
	"account_digest" "bytea" NOT NULL,
	"provider_digest" "bytea" NOT NULL,
	"state_digest" "bytea",
	"relay_state_digest" "bytea",
	"browser_digest" "bytea" NOT NULL,
	"nonce_digest" "bytea",
	"provider_revision" bigint NOT NULL,
	"binding_revision" bigint NOT NULL,
	"configuration_revision" bigint NOT NULL,
	"security_revision" bigint NOT NULL,
	"mapping_revision" bigint NOT NULL,
	"authorization_revision" bigint NOT NULL,
	"assurance_policy_revision" bigint NOT NULL,
	"client_secret_revision" bigint,
	"discovery_revision" bigint,
	"discovery_digest" "bytea",
	"jwks_revision" bigint,
	"jwks_digest" "bytea",
	"verifier_key_version" integer,
	"verifier_ciphertext" "bytea",
	"client_id" text,
	"redirect_uri" text,
	"post_logout_redirect_uri" text,
	"scopes" text[],
	"allow_refresh_token" boolean,
	"use_user_info" boolean,
	"metadata_revision" bigint,
	"metadata_digest" "bytea",
	"sp_key_revision" bigint,
	"configuration_digest" "bytea",
	"request_id" text,
	"return_path" text NOT NULL,
	"state" text DEFAULT 'pending' NOT NULL,
	"version" bigint DEFAULT 1 NOT NULL,
	"claim_attempt_id" "bytea",
	"created_at" timestamp with time zone NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"claimed_at" timestamp with time zone,
	"completed_at" timestamp with time zone,
	"failure_reason" text,
	CONSTRAINT "tenant_federated_authentication_transactions_pkey" PRIMARY KEY("tenant_id","transaction_id"),
	CONSTRAINT "tenant_federated_authentication_transactions_operation_key" UNIQUE("protocol","operation_run_id"),
	CONSTRAINT "tenant_federated_authentication_transactions_receipt_key" UNIQUE("receipt_digest"),
	CONSTRAINT "tenant_federated_authentication_transactions_exact_key" UNIQUE("tenant_id","protocol","transaction_id","provider_id","binding_id","provider_kind"),
	CONSTRAINT "tenant_federated_authentication_transactions_id_check" CHECK (octet_length("tenant_federated_authentication_transactions"."transaction_id") = 32
        and (uuid_extract_version("tenant_federated_authentication_transactions"."operation_run_id") = 7) is true),
	CONSTRAINT "tenant_federated_authentication_transactions_digest_check" CHECK (octet_length("tenant_federated_authentication_transactions"."operation_digest") = 32
        and octet_length("tenant_federated_authentication_transactions"."receipt_digest") = 32
        and octet_length("tenant_federated_authentication_transactions"."network_digest") = 32
        and octet_length("tenant_federated_authentication_transactions"."account_digest") = 32
        and octet_length("tenant_federated_authentication_transactions"."provider_digest") = 32
        and octet_length("tenant_federated_authentication_transactions"."browser_digest") = 32),
	CONSTRAINT "tenant_federated_authentication_transactions_protocol_check" CHECK ((("tenant_federated_authentication_transactions"."protocol" = 'oidc'
          and "tenant_federated_authentication_transactions"."provider_kind" = 'oidc'
          and octet_length("tenant_federated_authentication_transactions"."state_digest") = 32
          and octet_length("tenant_federated_authentication_transactions"."nonce_digest") = 32
          and "tenant_federated_authentication_transactions"."relay_state_digest" is null
          and "tenant_federated_authentication_transactions"."client_secret_revision" > 0
          and "tenant_federated_authentication_transactions"."discovery_revision" > 0 and octet_length("tenant_federated_authentication_transactions"."discovery_digest") = 32
          and "tenant_federated_authentication_transactions"."jwks_revision" > 0 and octet_length("tenant_federated_authentication_transactions"."jwks_digest") = 32
          and "tenant_federated_authentication_transactions"."verifier_key_version" between 1 and 2147483647
          and octet_length("tenant_federated_authentication_transactions"."verifier_ciphertext") between 16 and 4096
          and octet_length(convert_to("tenant_federated_authentication_transactions"."client_id", 'UTF8')) between 1 and 512
          and char_length("tenant_federated_authentication_transactions"."redirect_uri") between 1 and 4096
          and char_length("tenant_federated_authentication_transactions"."post_logout_redirect_uri") between 1 and 4096
          and cardinality("tenant_federated_authentication_transactions"."scopes") between 1 and 64
          and array_position("tenant_federated_authentication_transactions"."scopes", null) is null
          and "tenant_federated_authentication_transactions"."allow_refresh_token" is not null and "tenant_federated_authentication_transactions"."use_user_info" is not null
          and "tenant_federated_authentication_transactions"."metadata_revision" is null and "tenant_federated_authentication_transactions"."metadata_digest" is null
          and "tenant_federated_authentication_transactions"."sp_key_revision" is null and "tenant_federated_authentication_transactions"."configuration_digest" is null
          and "tenant_federated_authentication_transactions"."request_id" is null)
        or ("tenant_federated_authentication_transactions"."protocol" = 'saml'
          and "tenant_federated_authentication_transactions"."provider_kind" = 'saml'
          and octet_length("tenant_federated_authentication_transactions"."relay_state_digest") = 32
          and "tenant_federated_authentication_transactions"."state_digest" is null
          and "tenant_federated_authentication_transactions"."nonce_digest" is null
          and "tenant_federated_authentication_transactions"."client_secret_revision" is null
          and "tenant_federated_authentication_transactions"."discovery_revision" is null and "tenant_federated_authentication_transactions"."discovery_digest" is null
          and "tenant_federated_authentication_transactions"."jwks_revision" is null and "tenant_federated_authentication_transactions"."jwks_digest" is null
          and "tenant_federated_authentication_transactions"."verifier_key_version" is null and "tenant_federated_authentication_transactions"."verifier_ciphertext" is null
          and "tenant_federated_authentication_transactions"."client_id" is null and "tenant_federated_authentication_transactions"."redirect_uri" is null
          and "tenant_federated_authentication_transactions"."post_logout_redirect_uri" is null and "tenant_federated_authentication_transactions"."scopes" is null
          and "tenant_federated_authentication_transactions"."allow_refresh_token" is null and "tenant_federated_authentication_transactions"."use_user_info" is null
          and "tenant_federated_authentication_transactions"."metadata_revision" > 0 and octet_length("tenant_federated_authentication_transactions"."metadata_digest") = 32
          and "tenant_federated_authentication_transactions"."sp_key_revision" > 0 and octet_length("tenant_federated_authentication_transactions"."configuration_digest") = 32
          and char_length("tenant_federated_authentication_transactions"."request_id") between 1 and 1024)) is true),
	CONSTRAINT "tenant_federated_authentication_transactions_pin_check" CHECK ("tenant_federated_authentication_transactions"."provider_revision" > 0 and "tenant_federated_authentication_transactions"."binding_revision" > 0
        and "tenant_federated_authentication_transactions"."configuration_revision" > 0 and "tenant_federated_authentication_transactions"."security_revision" > 0
        and "tenant_federated_authentication_transactions"."mapping_revision" > 0 and "tenant_federated_authentication_transactions"."authorization_revision" > 0
        and "tenant_federated_authentication_transactions"."assurance_policy_revision" > 0
        and char_length("tenant_federated_authentication_transactions"."return_path") between 1 and 2048
        and left("tenant_federated_authentication_transactions"."return_path", 1) = '/'
        and "tenant_federated_authentication_transactions"."return_path" !~ '[[:cntrl:]]'
        and ("tenant_federated_authentication_transactions"."client_id" is null or "tenant_federated_authentication_transactions"."client_id" !~ '[[:cntrl:]]')
        and ("tenant_federated_authentication_transactions"."redirect_uri" is null or "tenant_federated_authentication_transactions"."redirect_uri" !~ '[[:cntrl:]]')
        and ("tenant_federated_authentication_transactions"."post_logout_redirect_uri" is null or "tenant_federated_authentication_transactions"."post_logout_redirect_uri" !~ '[[:cntrl:]]')
        and ("tenant_federated_authentication_transactions"."request_id" is null or "tenant_federated_authentication_transactions"."request_id" !~ '[[:cntrl:]]')),
	CONSTRAINT "tenant_federated_authentication_transactions_lifecycle_check" CHECK (("tenant_federated_authentication_transactions"."version" > 0
        and "tenant_federated_authentication_transactions"."expires_at" between "tenant_federated_authentication_transactions"."created_at" + interval '1 minute'
          and "tenant_federated_authentication_transactions"."created_at" + interval '15 minutes'
        and (("tenant_federated_authentication_transactions"."state" = 'pending'
            and "tenant_federated_authentication_transactions"."claim_attempt_id" is null and "tenant_federated_authentication_transactions"."claimed_at" is null
            and "tenant_federated_authentication_transactions"."completed_at" is null and "tenant_federated_authentication_transactions"."failure_reason" is null)
          or ("tenant_federated_authentication_transactions"."protocol" = 'oidc' and "tenant_federated_authentication_transactions"."state" = 'claimed'
            and octet_length("tenant_federated_authentication_transactions"."claim_attempt_id") = 32 and "tenant_federated_authentication_transactions"."claimed_at" is not null
            and "tenant_federated_authentication_transactions"."completed_at" is null and "tenant_federated_authentication_transactions"."failure_reason" is null)
          or ("tenant_federated_authentication_transactions"."state" in ('completed','failed','expired')
            and "tenant_federated_authentication_transactions"."completed_at" is not null
            and "tenant_federated_authentication_transactions"."completed_at" >= "tenant_federated_authentication_transactions"."created_at"
            and ("tenant_federated_authentication_transactions"."claim_attempt_id" is null) = ("tenant_federated_authentication_transactions"."claimed_at" is null)
            and ("tenant_federated_authentication_transactions"."protocol" <> 'saml'
              or ("tenant_federated_authentication_transactions"."claim_attempt_id" is null and "tenant_federated_authentication_transactions"."claimed_at" is null))
            and ("tenant_federated_authentication_transactions"."state" <> 'completed' or "tenant_federated_authentication_transactions"."protocol" <> 'oidc'
              or ("tenant_federated_authentication_transactions"."claim_attempt_id" is not null and "tenant_federated_authentication_transactions"."claimed_at" is not null))
            and ("tenant_federated_authentication_transactions"."state" = 'completed') = ("tenant_federated_authentication_transactions"."failure_reason" is null)))) is true)
);
--> statement-breakpoint
ALTER TABLE "tenant_federated_authentication_transactions" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_federated_external_identities" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"provider_id" uuid NOT NULL,
	"binding_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"subject_format" "identity_subject_format" NOT NULL,
	"subject_ciphertext" "bytea" NOT NULL,
	"subject_nonce" "bytea" NOT NULL,
	"key_version" integer NOT NULL,
	"admitted_configuration_revision" bigint NOT NULL,
	"last_observed_at" timestamp with time zone NOT NULL,
	"retired_at" timestamp with time zone,
	"version" bigint DEFAULT 1 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_federated_external_identities_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "tenant_federated_external_identities_provider_key" UNIQUE("tenant_id","provider_id","id"),
	CONSTRAINT "tenant_federated_external_identities_exact_key" UNIQUE("tenant_id","provider_id","id","user_id"),
	CONSTRAINT "tenant_federated_external_identities_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_federated_external_identities"."id") = 7) is true),
	CONSTRAINT "tenant_federated_external_identities_subject_check" CHECK ("tenant_federated_external_identities"."subject_format" = 'utf8_exact'
        and octet_length("tenant_federated_external_identities"."subject_ciphertext") between 17 and 4112
        and octet_length("tenant_federated_external_identities"."subject_nonce") = 12
        and "tenant_federated_external_identities"."key_version" between 1 and 32767),
	CONSTRAINT "tenant_federated_external_identities_lifecycle_check" CHECK ("tenant_federated_external_identities"."admitted_configuration_revision" > 0 and "tenant_federated_external_identities"."version" > 0
        and "tenant_federated_external_identities"."last_observed_at" >= "tenant_federated_external_identities"."created_at"
        and "tenant_federated_external_identities"."updated_at" >= "tenant_federated_external_identities"."created_at"
        and ("tenant_federated_external_identities"."retired_at" is null or ("tenant_federated_external_identities"."retired_at" >= "tenant_federated_external_identities"."created_at"
          and "tenant_federated_external_identities"."updated_at" >= "tenant_federated_external_identities"."retired_at")))
);
--> statement-breakpoint
ALTER TABLE "tenant_federated_external_identities" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_federated_external_identity_aliases" (
	"id" uuid DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"provider_id" uuid NOT NULL,
	"external_identity_id" uuid NOT NULL,
	"key_version" integer NOT NULL,
	"subject_digest" "bytea" NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"retired_at" timestamp with time zone,
	CONSTRAINT "tenant_federated_external_identity_aliases_pkey" PRIMARY KEY("tenant_id","id"),
	CONSTRAINT "tenant_federated_external_identity_aliases_digest_key" UNIQUE("tenant_id","provider_id","key_version","subject_digest"),
	CONSTRAINT "tenant_federated_external_identity_aliases_version_key" UNIQUE("tenant_id","external_identity_id","key_version"),
	CONSTRAINT "tenant_federated_external_identity_aliases_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_federated_external_identity_aliases"."id") = 7) is true),
	CONSTRAINT "tenant_federated_external_identity_aliases_digest_check" CHECK ("tenant_federated_external_identity_aliases"."key_version" between 1 and 32767 and octet_length("tenant_federated_external_identity_aliases"."subject_digest") = 32),
	CONSTRAINT "tenant_federated_external_identity_aliases_lifecycle_check" CHECK ("tenant_federated_external_identity_aliases"."retired_at" is null or "tenant_federated_external_identity_aliases"."retired_at" >= "tenant_federated_external_identity_aliases"."created_at")
);
--> statement-breakpoint
ALTER TABLE "tenant_federated_external_identity_aliases" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_federated_mapping_rule_epochs" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"rule_id" uuid NOT NULL,
	"provider_id" uuid NOT NULL,
	"binding_id" uuid NOT NULL,
	"provider_kind" "auth_provider_kind" NOT NULL,
	"source_id" uuid NOT NULL,
	"sequence" integer NOT NULL,
	"revision" bigint NOT NULL,
	"mapping_revision" bigint NOT NULL,
	"priority" integer NOT NULL,
	"matcher_kind" text NOT NULL,
	"claim_name" text,
	"matcher_value" text NOT NULL,
	"reconciliation_mode" text NOT NULL,
	"tenant_security_group_id" uuid NOT NULL,
	"operator_team_id" uuid,
	"operator_team_assignment_epoch_id" uuid,
	"enabled" boolean DEFAULT false NOT NULL,
	"activated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"ended_at" timestamp with time zone,
	CONSTRAINT "tenant_federated_mapping_rule_epochs_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "tenant_federated_mapping_rule_epochs_exact_key" UNIQUE("tenant_id","id","rule_id","binding_id","source_id"),
	CONSTRAINT "tenant_federated_mapping_rule_epochs_source_key" UNIQUE("tenant_id","source_id"),
	CONSTRAINT "tenant_federated_mapping_rule_epochs_sequence_key" UNIQUE("tenant_id","binding_id","mapping_revision","sequence"),
	CONSTRAINT "tenant_federated_mapping_rule_epochs_id_check" CHECK ((uuid_extract_version("tenant_federated_mapping_rule_epochs"."id") = 7) is true
        and (uuid_extract_version("tenant_federated_mapping_rule_epochs"."rule_id") = 7) is true),
	CONSTRAINT "tenant_federated_mapping_rule_epochs_matcher_check" CHECK (("tenant_federated_mapping_rule_epochs"."matcher_kind" = 'group_equals'
          and "tenant_federated_mapping_rule_epochs"."claim_name" is null)
        or ("tenant_federated_mapping_rule_epochs"."matcher_kind" = 'scalar_equals'
          and btrim("tenant_federated_mapping_rule_epochs"."claim_name") = "tenant_federated_mapping_rule_epochs"."claim_name"
          and char_length("tenant_federated_mapping_rule_epochs"."claim_name") between 1 and 256
          and "tenant_federated_mapping_rule_epochs"."claim_name" ~ '^[!-~]+$'
          and "tenant_federated_mapping_rule_epochs"."claim_name" !~ '["\\]')),
	CONSTRAINT "tenant_federated_mapping_rule_epochs_value_check" CHECK ("tenant_federated_mapping_rule_epochs"."sequence" between 1 and 2000
        and "tenant_federated_mapping_rule_epochs"."revision" > 0 and "tenant_federated_mapping_rule_epochs"."mapping_revision" > 0
        and "tenant_federated_mapping_rule_epochs"."priority" between 0 and 1000000
        and "tenant_federated_mapping_rule_epochs"."reconciliation_mode" in ('additive','authoritative')
        and btrim("tenant_federated_mapping_rule_epochs"."matcher_value") <> ''
        and char_length("tenant_federated_mapping_rule_epochs"."matcher_value") <= 1024
        and octet_length("tenant_federated_mapping_rule_epochs"."matcher_value") <= 4096
        and "tenant_federated_mapping_rule_epochs"."matcher_value" !~ '[[:cntrl:]]'),
	CONSTRAINT "tenant_federated_mapping_rule_epochs_team_check" CHECK (("tenant_federated_mapping_rule_epochs"."operator_team_id" is null) = ("tenant_federated_mapping_rule_epochs"."operator_team_assignment_epoch_id" is null)),
	CONSTRAINT "tenant_federated_mapping_rule_epochs_lifecycle_check" CHECK (("tenant_federated_mapping_rule_epochs"."enabled" and "tenant_federated_mapping_rule_epochs"."ended_at" is null)
        or (not "tenant_federated_mapping_rule_epochs"."enabled" and ("tenant_federated_mapping_rule_epochs"."ended_at" is null or "tenant_federated_mapping_rule_epochs"."ended_at" >= "tenant_federated_mapping_rule_epochs"."activated_at")))
);
--> statement-breakpoint
ALTER TABLE "tenant_federated_mapping_rule_epochs" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_federated_mapping_rule_role_targets" (
	"tenant_id" uuid NOT NULL,
	"rule_epoch_id" uuid NOT NULL,
	"role_id" uuid NOT NULL,
	"role_principal_kind" "tenant_principal_kind" DEFAULT 'human' NOT NULL,
	CONSTRAINT "tenant_federated_mapping_rule_role_targets_pkey" PRIMARY KEY("tenant_id","rule_epoch_id","role_id"),
	CONSTRAINT "tenant_federated_mapping_rule_role_targets_human_check" CHECK ("tenant_federated_mapping_rule_role_targets"."role_principal_kind" = 'human')
);
--> statement-breakpoint
ALTER TABLE "tenant_federated_mapping_rule_role_targets" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_federated_provider_access_grants" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"provider_id" uuid NOT NULL,
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
	CONSTRAINT "tenant_federated_provider_access_grants_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "tenant_federated_provider_access_grants_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_federated_provider_access_grants"."id") = 7) is true),
	CONSTRAINT "tenant_federated_provider_access_grants_lifecycle_check" CHECK ("tenant_federated_provider_access_grants"."version" > 0 and "tenant_federated_provider_access_grants"."last_observed_at" >= "tenant_federated_provider_access_grants"."started_at"
        and ("tenant_federated_provider_access_grants"."ended_at" is null or "tenant_federated_provider_access_grants"."ended_at" >= "tenant_federated_provider_access_grants"."started_at"))
);
--> statement-breakpoint
ALTER TABLE "tenant_federated_provider_access_grants" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_federated_provider_policies" (
	"tenant_id" uuid NOT NULL,
	"provider_id" uuid NOT NULL,
	"binding_id" uuid NOT NULL,
	"provider_kind" "auth_provider_kind" NOT NULL,
	"configuration_revision" bigint NOT NULL,
	"security_revision" bigint NOT NULL,
	"plan_revision" bigint NOT NULL,
	"assurance_policy_revision" bigint NOT NULL,
	"jit_mode" text DEFAULT 'disabled' NOT NULL,
	"no_match_policy" text DEFAULT 'deny' NOT NULL,
	"enabled" boolean DEFAULT false NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_federated_provider_policies_pkey" PRIMARY KEY("tenant_id","provider_id"),
	CONSTRAINT "tenant_federated_provider_policies_binding_key" UNIQUE("tenant_id","binding_id","provider_id"),
	CONSTRAINT "tenant_federated_provider_policies_kind_key" UNIQUE("tenant_id","binding_id","provider_id","provider_kind"),
	CONSTRAINT "tenant_federated_provider_policies_kind_check" CHECK ("tenant_federated_provider_policies"."provider_kind" in ('oidc', 'saml')),
	CONSTRAINT "tenant_federated_provider_policies_revision_check" CHECK ("tenant_federated_provider_policies"."configuration_revision" > 0
        and "tenant_federated_provider_policies"."security_revision" > 0
        and "tenant_federated_provider_policies"."plan_revision" > 0
        and "tenant_federated_provider_policies"."assurance_policy_revision" > 0),
	CONSTRAINT "tenant_federated_provider_policies_admission_check" CHECK ("tenant_federated_provider_policies"."jit_mode" in ('disabled', 'create')
        and "tenant_federated_provider_policies"."no_match_policy" in ('deny', 'provider_access_only')),
	CONSTRAINT "tenant_federated_provider_policies_timestamp_check" CHECK ("tenant_federated_provider_policies"."updated_at" >= "tenant_federated_provider_policies"."created_at")
);
--> statement-breakpoint
ALTER TABLE "tenant_federated_provider_policies" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_federated_provider_profile_contributions" (
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
	CONSTRAINT "tenant_federated_provider_profile_contributions_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "tenant_federated_provider_profile_contributions_id_check" CHECK ((uuid_extract_version("tenant_federated_provider_profile_contributions"."id") = 7) is true),
	CONSTRAINT "tenant_federated_provider_profile_contributions_present_check" CHECK ("tenant_federated_provider_profile_contributions"."display_name" is not null or "tenant_federated_provider_profile_contributions"."username" is not null or "tenant_federated_provider_profile_contributions"."email" is not null),
	CONSTRAINT "tenant_federated_provider_profile_contributions_value_check" CHECK ("tenant_federated_provider_profile_contributions"."mapping_revision" > 0 and "tenant_federated_provider_profile_contributions"."version" > 0
        and ("tenant_federated_provider_profile_contributions"."display_name" is null or (
          btrim("tenant_federated_provider_profile_contributions"."display_name") <> '' and char_length("tenant_federated_provider_profile_contributions"."display_name") <= 160
          and "tenant_federated_provider_profile_contributions"."display_name" !~ '[[:cntrl:]]'))
        and ("tenant_federated_provider_profile_contributions"."username" is null or (
          btrim("tenant_federated_provider_profile_contributions"."username") <> '' and char_length("tenant_federated_provider_profile_contributions"."username") <= 320
          and "tenant_federated_provider_profile_contributions"."username" !~ '[[:cntrl:]]'))
        and ("tenant_federated_provider_profile_contributions"."email" is null or (
          "tenant_federated_provider_profile_contributions"."email" = lower(btrim("tenant_federated_provider_profile_contributions"."email"))
          and position('@' in "tenant_federated_provider_profile_contributions"."email") > 1
          and char_length("tenant_federated_provider_profile_contributions"."email") <= 320
          and "tenant_federated_provider_profile_contributions"."email" !~ '[[:cntrl:]]'))),
	CONSTRAINT "tenant_federated_provider_profile_contributions_lifecycle_check" CHECK ("tenant_federated_provider_profile_contributions"."retired_at" is null or "tenant_federated_provider_profile_contributions"."retired_at" >= "tenant_federated_provider_profile_contributions"."observed_at")
);
--> statement-breakpoint
ALTER TABLE "tenant_federated_provider_profile_contributions" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_federated_session_revalidation_commands" (
	"tenant_id" uuid NOT NULL,
	"session_id" uuid NOT NULL,
	"expected_version" bigint NOT NULL,
	"request_digest" "bytea" NOT NULL,
	"decision" text NOT NULL,
	"result_snapshot" jsonb NOT NULL,
	"applied_at" timestamp with time zone NOT NULL,
	CONSTRAINT "tenant_federated_session_revalidation_commands_pkey" PRIMARY KEY("tenant_id","session_id","expected_version"),
	CONSTRAINT "tenant_federated_session_revalidation_commands_value_check" CHECK ("tenant_federated_session_revalidation_commands"."expected_version" > 0
        and octet_length("tenant_federated_session_revalidation_commands"."request_digest") = 32
        and "tenant_federated_session_revalidation_commands"."decision" in ('usable','rotate','step_up','revoke','deny')
        and jsonb_typeof("tenant_federated_session_revalidation_commands"."result_snapshot") = 'object'
        and pg_column_size("tenant_federated_session_revalidation_commands"."result_snapshot") between 2 and 65536)
);
--> statement-breakpoint
ALTER TABLE "tenant_federated_session_revalidation_commands" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_federated_trust_rules" (
	"id" uuid DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"provider_id" uuid NOT NULL,
	"binding_id" uuid NOT NULL,
	"provider_kind" "auth_provider_kind" NOT NULL,
	"revision" bigint NOT NULL,
	"enabled" boolean DEFAULT false NOT NULL,
	"level" text NOT NULL,
	"exact_value" text,
	"required_values" text[] DEFAULT ARRAY[]::text[] NOT NULL,
	"maximum_authentication_age_seconds" integer NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"retired_at" timestamp with time zone,
	CONSTRAINT "tenant_federated_trust_rules_pkey" PRIMARY KEY("tenant_id","id","revision"),
	CONSTRAINT "tenant_federated_trust_rules_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_federated_trust_rules"."id") = 7) is true),
	CONSTRAINT "tenant_federated_trust_rules_value_check" CHECK ("tenant_federated_trust_rules"."provider_kind" in ('oidc','saml')
        and "tenant_federated_trust_rules"."revision" > 0
        and "tenant_federated_trust_rules"."level" in ('mfa','phishing_resistant')
        and "tenant_federated_trust_rules"."maximum_authentication_age_seconds" between 60 and 2592000
        and cardinality("tenant_federated_trust_rules"."required_values") <= 128
        and (("tenant_federated_trust_rules"."provider_kind" = 'oidc'
            and ("tenant_federated_trust_rules"."exact_value" is not null or cardinality("tenant_federated_trust_rules"."required_values") > 0))
          or ("tenant_federated_trust_rules"."provider_kind" = 'saml'
            and "tenant_federated_trust_rules"."exact_value" is not null
            and cardinality("tenant_federated_trust_rules"."required_values") = 0))),
	CONSTRAINT "tenant_federated_trust_rules_retirement_check" CHECK ("tenant_federated_trust_rules"."retired_at" is null or "tenant_federated_trust_rules"."retired_at" >= "tenant_federated_trust_rules"."created_at")
);
--> statement-breakpoint
ALTER TABLE "tenant_federated_trust_rules" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_oidc_claim_rules" (
	"tenant_id" uuid NOT NULL,
	"provider_id" uuid NOT NULL,
	"source" text NOT NULL,
	"sequence" integer NOT NULL,
	"kind" text NOT NULL,
	"claim_name" text NOT NULL,
	"profile_field" text,
	"required" boolean DEFAULT false NOT NULL,
	CONSTRAINT "tenant_oidc_claim_rules_pkey" PRIMARY KEY("tenant_id","provider_id","source","sequence"),
	CONSTRAINT "tenant_oidc_claim_rules_claim_key" UNIQUE("tenant_id","provider_id","source","claim_name"),
	CONSTRAINT "tenant_oidc_claim_rules_value_check" CHECK ("tenant_oidc_claim_rules"."source" in ('id_token', 'userinfo')
        and "tenant_oidc_claim_rules"."sequence" between 0 and 1023
        and "tenant_oidc_claim_rules"."kind" in ('scalar', 'profile', 'groups', 'acr', 'amr')
        and char_length("tenant_oidc_claim_rules"."claim_name") between 1 and 256
        and "tenant_oidc_claim_rules"."claim_name" ~ '^[!-~]+$'
        and "tenant_oidc_claim_rules"."claim_name" !~ '["\\]'
        and (("tenant_oidc_claim_rules"."kind" = 'profile'
            and "tenant_oidc_claim_rules"."profile_field" in ('username', 'email', 'display_name'))
          or ("tenant_oidc_claim_rules"."kind" <> 'profile' and "tenant_oidc_claim_rules"."profile_field" is null))
        and ("tenant_oidc_claim_rules"."kind" not in ('acr', 'amr')
          or ("tenant_oidc_claim_rules"."claim_name" = "tenant_oidc_claim_rules"."kind" and not "tenant_oidc_claim_rules"."required")))
);
--> statement-breakpoint
ALTER TABLE "tenant_oidc_claim_rules" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_oidc_client_secrets" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"provider_id" uuid NOT NULL,
	"revision" bigint NOT NULL,
	"key_version" integer NOT NULL,
	"nonce" "bytea" NOT NULL,
	"ciphertext" "bytea" NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"retired_at" timestamp with time zone,
	CONSTRAINT "tenant_oidc_client_secrets_revision_key" UNIQUE("tenant_id","provider_id","revision"),
	CONSTRAINT "tenant_oidc_client_secrets_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_oidc_client_secrets"."id") = 7) is true),
	CONSTRAINT "tenant_oidc_client_secrets_envelope_check" CHECK ("tenant_oidc_client_secrets"."revision" > 0 and "tenant_oidc_client_secrets"."key_version" between 1 and 32767
        and octet_length("tenant_oidc_client_secrets"."nonce") = 12
        and octet_length("tenant_oidc_client_secrets"."ciphertext") between 17 and 8208),
	CONSTRAINT "tenant_oidc_client_secrets_retirement_check" CHECK ("tenant_oidc_client_secrets"."retired_at" is null or "tenant_oidc_client_secrets"."retired_at" >= "tenant_oidc_client_secrets"."created_at")
);
--> statement-breakpoint
ALTER TABLE "tenant_oidc_client_secrets" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_oidc_discovery_snapshots" (
	"tenant_id" uuid NOT NULL,
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
	CONSTRAINT "tenant_oidc_discovery_snapshots_pkey" PRIMARY KEY("tenant_id","provider_id","revision"),
	CONSTRAINT "tenant_oidc_discovery_snapshots_revision_check" CHECK ("tenant_oidc_discovery_snapshots"."revision" > 0),
	CONSTRAINT "tenant_oidc_discovery_snapshots_document_check" CHECK (octet_length("tenant_oidc_discovery_snapshots"."document") between 2 and 1048576
        and octet_length("tenant_oidc_discovery_snapshots"."document_digest") = 32),
	CONSTRAINT "tenant_oidc_discovery_snapshots_cache_check" CHECK ("tenant_oidc_discovery_snapshots"."fresh_until" between "tenant_oidc_discovery_snapshots"."retrieved_at" and "tenant_oidc_discovery_snapshots"."retrieved_at" + interval '7 days'
        and ("tenant_oidc_discovery_snapshots"."cacheable" or ("tenant_oidc_discovery_snapshots"."must_revalidate" and "tenant_oidc_discovery_snapshots"."fresh_until" = "tenant_oidc_discovery_snapshots"."retrieved_at"))),
	CONSTRAINT "tenant_oidc_discovery_snapshots_policy_check" CHECK ("tenant_oidc_discovery_snapshots"."client_authentication" in ('client_secret_basic', 'client_secret_post')
        and cardinality("tenant_oidc_discovery_snapshots"."signing_algorithms") between 1 and 16)
);
--> statement-breakpoint
ALTER TABLE "tenant_oidc_discovery_snapshots" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_oidc_jwks_snapshots" (
	"tenant_id" uuid NOT NULL,
	"provider_id" uuid NOT NULL,
	"revision" bigint NOT NULL,
	"document" "bytea" NOT NULL,
	"document_digest" "bytea" NOT NULL,
	"retrieved_at" timestamp with time zone NOT NULL,
	"fresh_until" timestamp with time zone NOT NULL,
	"cacheable" boolean NOT NULL,
	"must_revalidate" boolean NOT NULL,
	CONSTRAINT "tenant_oidc_jwks_snapshots_pkey" PRIMARY KEY("tenant_id","provider_id","revision"),
	CONSTRAINT "tenant_oidc_jwks_snapshots_revision_check" CHECK ("tenant_oidc_jwks_snapshots"."revision" > 0),
	CONSTRAINT "tenant_oidc_jwks_snapshots_document_check" CHECK (octet_length("tenant_oidc_jwks_snapshots"."document") between 2 and 1048576
        and octet_length("tenant_oidc_jwks_snapshots"."document_digest") = 32),
	CONSTRAINT "tenant_oidc_jwks_snapshots_cache_check" CHECK ("tenant_oidc_jwks_snapshots"."fresh_until" between "tenant_oidc_jwks_snapshots"."retrieved_at" and "tenant_oidc_jwks_snapshots"."retrieved_at" + interval '7 days'
        and ("tenant_oidc_jwks_snapshots"."cacheable" or ("tenant_oidc_jwks_snapshots"."must_revalidate" and "tenant_oidc_jwks_snapshots"."fresh_until" = "tenant_oidc_jwks_snapshots"."retrieved_at")))
);
--> statement-breakpoint
ALTER TABLE "tenant_oidc_jwks_snapshots" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_oidc_provider_configurations" (
	"tenant_id" uuid NOT NULL,
	"provider_id" uuid NOT NULL,
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
	CONSTRAINT "tenant_oidc_provider_configurations_pkey" PRIMARY KEY("tenant_id","provider_id"),
	CONSTRAINT "tenant_oidc_provider_configurations_kind_check" CHECK ("tenant_oidc_provider_configurations"."provider_kind" = 'oidc'),
	CONSTRAINT "tenant_oidc_provider_configurations_revision_check" CHECK ("tenant_oidc_provider_configurations"."client_secret_revision" > 0
        and "tenant_oidc_provider_configurations"."discovery_revision" > 0
        and "tenant_oidc_provider_configurations"."jwks_revision" > 0
        and "tenant_oidc_provider_configurations"."version" > 0),
	CONSTRAINT "tenant_oidc_provider_configurations_text_check" CHECK (char_length("tenant_oidc_provider_configurations"."issuer") between 1 and 4096
        and octet_length(convert_to("tenant_oidc_provider_configurations"."client_id", 'UTF8')) between 1 and 512
        and char_length("tenant_oidc_provider_configurations"."redirect_uri") between 1 and 4096
        and char_length("tenant_oidc_provider_configurations"."post_logout_redirect_uri") between 1 and 4096
        and "tenant_oidc_provider_configurations"."issuer" !~ '[[:cntrl:]]'
        and "tenant_oidc_provider_configurations"."client_id" !~ '[[:cntrl:]]'
        and "tenant_oidc_provider_configurations"."redirect_uri" !~ '[[:cntrl:]]'
        and "tenant_oidc_provider_configurations"."post_logout_redirect_uri" !~ '[[:cntrl:]]'),
	CONSTRAINT "tenant_oidc_provider_configurations_scope_check" CHECK (cardinality("tenant_oidc_provider_configurations"."extra_scopes") <= 32
        and array_position("tenant_oidc_provider_configurations"."extra_scopes", null) is null),
	CONSTRAINT "tenant_oidc_provider_configurations_timestamp_check" CHECK ("tenant_oidc_provider_configurations"."updated_at" >= "tenant_oidc_provider_configurations"."created_at")
);
--> statement-breakpoint
ALTER TABLE "tenant_oidc_provider_configurations" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_saml_attribute_rules" (
	"tenant_id" uuid NOT NULL,
	"provider_id" uuid NOT NULL,
	"sequence" integer NOT NULL,
	"kind" text NOT NULL,
	"attribute_name" text NOT NULL,
	"attribute_name_format" text NOT NULL,
	"profile_field" text,
	"required" boolean DEFAULT false NOT NULL,
	CONSTRAINT "tenant_saml_attribute_rules_pkey" PRIMARY KEY("tenant_id","provider_id","sequence"),
	CONSTRAINT "tenant_saml_attribute_rules_value_check" CHECK ("tenant_saml_attribute_rules"."sequence" between 0 and 1023
        and "tenant_saml_attribute_rules"."kind" in ('scalar','profile','groups')
        and octet_length(convert_to("tenant_saml_attribute_rules"."attribute_name", 'UTF8')) between 1 and 512
        and octet_length(convert_to("tenant_saml_attribute_rules"."attribute_name_format", 'UTF8')) between 1 and 512
        and "tenant_saml_attribute_rules"."attribute_name" !~ '[[:cntrl:]]'
        and "tenant_saml_attribute_rules"."attribute_name_format" !~ '[[:cntrl:]]'
        and (("tenant_saml_attribute_rules"."kind" = 'profile'
            and "tenant_saml_attribute_rules"."profile_field" in ('username','email','display_name'))
          or ("tenant_saml_attribute_rules"."kind" <> 'profile' and "tenant_saml_attribute_rules"."profile_field" is null)))
);
--> statement-breakpoint
ALTER TABLE "tenant_saml_attribute_rules" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_saml_metadata_snapshots" (
	"tenant_id" uuid NOT NULL,
	"provider_id" uuid NOT NULL,
	"revision" bigint NOT NULL,
	"document" "bytea" NOT NULL,
	"document_digest" "bytea" NOT NULL,
	"retrieved_at" timestamp with time zone NOT NULL,
	"maximum_valid_until" timestamp with time zone NOT NULL,
	CONSTRAINT "tenant_saml_metadata_snapshots_pkey" PRIMARY KEY("tenant_id","provider_id","revision"),
	CONSTRAINT "tenant_saml_metadata_snapshots_revision_check" CHECK ("tenant_saml_metadata_snapshots"."revision" > 0),
	CONSTRAINT "tenant_saml_metadata_snapshots_document_check" CHECK (octet_length("tenant_saml_metadata_snapshots"."document") between 1 and 524288
        and octet_length("tenant_saml_metadata_snapshots"."document_digest") = 32
        and "tenant_saml_metadata_snapshots"."maximum_valid_until" > "tenant_saml_metadata_snapshots"."retrieved_at")
);
--> statement-breakpoint
ALTER TABLE "tenant_saml_metadata_snapshots" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_saml_provider_configurations" (
	"tenant_id" uuid NOT NULL,
	"provider_id" uuid NOT NULL,
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
	CONSTRAINT "tenant_saml_provider_configurations_pkey" PRIMARY KEY("tenant_id","provider_id"),
	CONSTRAINT "tenant_saml_provider_configurations_kind_check" CHECK ("tenant_saml_provider_configurations"."provider_kind" = 'saml'),
	CONSTRAINT "tenant_saml_provider_configurations_revision_check" CHECK ("tenant_saml_provider_configurations"."sp_key_revision" > 0 and "tenant_saml_provider_configurations"."metadata_revision" > 0 and "tenant_saml_provider_configurations"."version" > 0),
	CONSTRAINT "tenant_saml_provider_configurations_policy_check" CHECK ("tenant_saml_provider_configurations"."redirect_signature_algorithm" in (
          'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
          'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384',
          'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512',
          'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256',
          'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384',
          'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512')
        and "tenant_saml_provider_configurations"."signature_policy" in ('signed_assertion','signed_response','both')
        and "tenant_saml_provider_configurations"."encryption_policy" in ('disabled','optional','required')
        and (("tenant_saml_provider_configurations"."encryption_policy" = 'disabled'
            and cardinality("tenant_saml_provider_configurations"."decryption_key_versions") = 0)
          or ("tenant_saml_provider_configurations"."encryption_policy" in ('optional','required')
            and cardinality("tenant_saml_provider_configurations"."decryption_key_versions") between 1 and 8))
        and array_position("tenant_saml_provider_configurations"."decryption_key_versions", null) is null
        and cardinality("tenant_saml_provider_configurations"."requested_authn_contexts") between 1 and 32
        and array_position("tenant_saml_provider_configurations"."requested_authn_contexts", null) is null
        and "tenant_saml_provider_configurations"."clock_skew_nanoseconds" between 0 and 300000000000
        and "tenant_saml_provider_configurations"."max_authentication_age_nanoseconds" between 60000000000 and 86400000000000),
	CONSTRAINT "tenant_saml_provider_configurations_subject_check" CHECK (("tenant_saml_provider_configurations"."subject_source" = 'persistent_nameid'
          and "tenant_saml_provider_configurations"."subject_attribute_name" is null
          and "tenant_saml_provider_configurations"."subject_attribute_name_format" is null)
        or ("tenant_saml_provider_configurations"."subject_source" = 'immutable_attribute'
          and octet_length(convert_to("tenant_saml_provider_configurations"."subject_attribute_name", 'UTF8')) between 1 and 512
          and octet_length(convert_to("tenant_saml_provider_configurations"."subject_attribute_name_format", 'UTF8')) between 1 and 512)),
	CONSTRAINT "tenant_saml_provider_configurations_text_check" CHECK (octet_length(convert_to("tenant_saml_provider_configurations"."expected_entity_id", 'UTF8')) between 1 and 2048
        and octet_length(convert_to("tenant_saml_provider_configurations"."sp_entity_id", 'UTF8')) between 1 and 2048
        and octet_length(convert_to("tenant_saml_provider_configurations"."acs_url", 'UTF8')) between 1 and 4096
        and "tenant_saml_provider_configurations"."expected_entity_id" !~ '[[:cntrl:]]'
        and "tenant_saml_provider_configurations"."sp_entity_id" !~ '[[:cntrl:]]'
        and "tenant_saml_provider_configurations"."acs_url" !~ '[[:cntrl:]]'),
	CONSTRAINT "tenant_saml_provider_configurations_timestamp_check" CHECK ("tenant_saml_provider_configurations"."updated_at" >= "tenant_saml_provider_configurations"."created_at")
);
--> statement-breakpoint
ALTER TABLE "tenant_saml_provider_configurations" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_saml_session_materials" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"session_id" uuid,
	"continuation_id" uuid,
	"user_id" uuid NOT NULL,
	"provider_id" uuid NOT NULL,
	"binding_id" uuid NOT NULL,
	"provider_kind" "auth_provider_kind" DEFAULT 'saml' NOT NULL,
	"external_identity_id" uuid NOT NULL,
	"session_index_digest" "bytea",
	"key_version" integer NOT NULL,
	"ciphertext" "bytea" NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_saml_session_materials_value_check" CHECK ((uuid_extract_version("tenant_saml_session_materials"."id") = 7) is true
        and (("tenant_saml_session_materials"."session_id" is null) <> ("tenant_saml_session_materials"."continuation_id" is null))
        and "tenant_saml_session_materials"."provider_kind" = 'saml'
        and ("tenant_saml_session_materials"."session_index_digest" is null or octet_length("tenant_saml_session_materials"."session_index_digest") = 32)
        and "tenant_saml_session_materials"."key_version" between 1 and 32767
        and octet_length("tenant_saml_session_materials"."ciphertext") between 16 and 16384)
);
--> statement-breakpoint
ALTER TABLE "tenant_saml_session_materials" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_saml_sp_certificates" (
	"tenant_id" uuid NOT NULL,
	"key_id" uuid NOT NULL,
	"sequence" integer NOT NULL,
	"certificate_der" "bytea" NOT NULL,
	CONSTRAINT "tenant_saml_sp_certificates_pkey" PRIMARY KEY("tenant_id","key_id","sequence"),
	CONSTRAINT "tenant_saml_sp_certificates_value_key" UNIQUE("tenant_id","key_id","certificate_der"),
	CONSTRAINT "tenant_saml_sp_certificates_value_check" CHECK ("tenant_saml_sp_certificates"."sequence" between 0 and 7
        and octet_length("tenant_saml_sp_certificates"."certificate_der") between 1 and 65536)
);
--> statement-breakpoint
ALTER TABLE "tenant_saml_sp_certificates" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_saml_sp_keys" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"provider_id" uuid NOT NULL,
	"revision" bigint NOT NULL,
	"key_version" integer NOT NULL,
	"ciphertext" "bytea" NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"retired_at" timestamp with time zone,
	CONSTRAINT "tenant_saml_sp_keys_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "tenant_saml_sp_keys_revision_key" UNIQUE("tenant_id","provider_id","revision"),
	CONSTRAINT "tenant_saml_sp_keys_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_saml_sp_keys"."id") = 7) is true),
	CONSTRAINT "tenant_saml_sp_keys_envelope_check" CHECK ("tenant_saml_sp_keys"."revision" > 0 and "tenant_saml_sp_keys"."key_version" between 1 and 32767
        and octet_length("tenant_saml_sp_keys"."ciphertext") between 17 and 131072),
	CONSTRAINT "tenant_saml_sp_keys_retirement_check" CHECK ("tenant_saml_sp_keys"."retired_at" is null or "tenant_saml_sp_keys"."retired_at" >= "tenant_saml_sp_keys"."created_at")
);
--> statement-breakpoint
ALTER TABLE "tenant_saml_sp_keys" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "auth_sessions" DROP CONSTRAINT "auth_sessions_method_check";--> statement-breakpoint
ALTER TABLE "auth_session_mfa_states" DROP CONSTRAINT "auth_session_mfa_states_primary_kind_check";--> statement-breakpoint
ALTER TABLE "tenant_post_primary_continuations" DROP CONSTRAINT "tenant_post_primary_continuations_primary_check";--> statement-breakpoint
ALTER TABLE "tenant_auth_providers" DROP CONSTRAINT "tenant_auth_providers_implemented_kind_check";--> statement-breakpoint
ALTER TABLE "tenant_post_primary_continuations" ADD COLUMN "provider_id" uuid;--> statement-breakpoint
ALTER TABLE "tenant_post_primary_continuations" ADD COLUMN "binding_id" uuid;--> statement-breakpoint
ALTER TABLE "tenant_post_primary_continuations" ADD COLUMN "provider_kind" "auth_provider_kind";--> statement-breakpoint
ALTER TABLE "tenant_post_primary_continuations" ADD COLUMN "external_identity_id" uuid;--> statement-breakpoint
ALTER TABLE "auth_session_federated_provenance" ADD CONSTRAINT "auth_session_federated_provenance_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "auth_session_federated_provenance" ADD CONSTRAINT "auth_session_federated_provenance_state_fk" FOREIGN KEY ("tenant_id","session_id","primary_kind","user_id") REFERENCES "public"."auth_session_mfa_states"("tenant_id","session_id","primary_kind","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "auth_session_federated_provenance" ADD CONSTRAINT "auth_session_federated_provenance_identity_fk" FOREIGN KEY ("tenant_id","provider_id","external_identity_id","user_id") REFERENCES "public"."tenant_federated_external_identities"("tenant_id","provider_id","id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "auth_session_federated_provenance" ADD CONSTRAINT "auth_session_federated_provenance_policy_fk" FOREIGN KEY ("tenant_id","binding_id","provider_id","provider_kind") REFERENCES "public"."tenant_federated_provider_policies"("tenant_id","binding_id","provider_id","provider_kind") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_federated_authentication_applications" ADD CONSTRAINT "tenant_federated_authentication_applications_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_federated_authentication_applications" ADD CONSTRAINT "tenant_federated_authentication_applications_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_federated_authentication_applications" ADD CONSTRAINT "tenant_federated_authentication_applications_session_id_auth_sessions_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."auth_sessions"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_federated_authentication_applications" ADD CONSTRAINT "tenant_federated_authentication_applications_policy_fk" FOREIGN KEY ("tenant_id","binding_id","provider_id","provider_kind") REFERENCES "public"."tenant_federated_provider_policies"("tenant_id","binding_id","provider_id","provider_kind") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_federated_authentication_applications" ADD CONSTRAINT "tenant_federated_authentication_applications_transaction_fk" FOREIGN KEY ("tenant_id","protocol","transaction_id","provider_id","binding_id","provider_kind") REFERENCES "public"."tenant_federated_authentication_transactions"("tenant_id","protocol","transaction_id","provider_id","binding_id","provider_kind") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_federated_authentication_applications" ADD CONSTRAINT "tenant_federated_authentication_applications_session_fk" FOREIGN KEY ("tenant_id","session_id","primary_kind","user_id") REFERENCES "public"."auth_session_mfa_states"("tenant_id","session_id","primary_kind","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_federated_authentication_transactions" ADD CONSTRAINT "tenant_federated_authentication_transactions_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_federated_authentication_transactions" ADD CONSTRAINT "tenant_federated_authentication_transactions_policy_fk" FOREIGN KEY ("tenant_id","binding_id","provider_id","provider_kind") REFERENCES "public"."tenant_federated_provider_policies"("tenant_id","binding_id","provider_id","provider_kind") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_federated_authentication_transactions" ADD CONSTRAINT "tenant_federated_authentication_transactions_verifier_keyring_fk" FOREIGN KEY ("verifier_key_version") REFERENCES "public"."identity_keyring_versions"("key_version") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_federated_external_identities" ADD CONSTRAINT "tenant_federated_external_identities_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_federated_external_identities" ADD CONSTRAINT "tenant_federated_external_identities_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_federated_external_identities" ADD CONSTRAINT "tenant_federated_external_identities_policy_fk" FOREIGN KEY ("tenant_id","binding_id","provider_id") REFERENCES "public"."tenant_federated_provider_policies"("tenant_id","binding_id","provider_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_federated_external_identities" ADD CONSTRAINT "tenant_federated_external_identities_keyring_fk" FOREIGN KEY ("key_version") REFERENCES "public"."identity_keyring_versions"("key_version") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_federated_external_identities" ADD CONSTRAINT "tenant_federated_external_identities_subject_fk" FOREIGN KEY ("tenant_id","user_id") REFERENCES "public"."tenant_mfa_subjects"("tenant_id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_federated_external_identity_aliases" ADD CONSTRAINT "tenant_federated_external_identity_aliases_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_federated_external_identity_aliases" ADD CONSTRAINT "tenant_federated_external_identity_aliases_identity_fk" FOREIGN KEY ("tenant_id","provider_id","external_identity_id") REFERENCES "public"."tenant_federated_external_identities"("tenant_id","provider_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_federated_external_identity_aliases" ADD CONSTRAINT "tenant_federated_external_identity_aliases_keyring_fk" FOREIGN KEY ("key_version") REFERENCES "public"."identity_keyring_versions"("key_version") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_federated_mapping_rule_epochs" ADD CONSTRAINT "tenant_federated_mapping_rule_epochs_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_federated_mapping_rule_epochs" ADD CONSTRAINT "tenant_federated_mapping_rule_epochs_policy_fk" FOREIGN KEY ("tenant_id","binding_id","provider_id","provider_kind") REFERENCES "public"."tenant_federated_provider_policies"("tenant_id","binding_id","provider_id","provider_kind") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_federated_mapping_rule_epochs" ADD CONSTRAINT "tenant_federated_mapping_rule_epochs_source_fk" FOREIGN KEY ("tenant_id","source_id") REFERENCES "public"."tenant_authorization_sources"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_federated_mapping_rule_epochs" ADD CONSTRAINT "tenant_federated_mapping_rule_epochs_group_fk" FOREIGN KEY ("tenant_id","tenant_security_group_id") REFERENCES "public"."tenant_security_groups"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_federated_mapping_rule_epochs" ADD CONSTRAINT "tenant_federated_mapping_rule_epochs_team_fk" FOREIGN KEY ("tenant_id","operator_team_assignment_epoch_id","operator_team_id") REFERENCES "public"."operator_team_assignment_epochs"("tenant_id","id","operator_team_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_federated_mapping_rule_role_targets" ADD CONSTRAINT "tenant_federated_mapping_rule_role_targets_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_federated_mapping_rule_role_targets" ADD CONSTRAINT "tenant_federated_mapping_rule_role_targets_epoch_fk" FOREIGN KEY ("tenant_id","rule_epoch_id") REFERENCES "public"."tenant_federated_mapping_rule_epochs"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_federated_mapping_rule_role_targets" ADD CONSTRAINT "tenant_federated_mapping_rule_role_targets_role_fk" FOREIGN KEY ("tenant_id","role_id","role_principal_kind") REFERENCES "public"."tenant_roles"("tenant_id","id","principal_kind") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_federated_provider_access_grants" ADD CONSTRAINT "tenant_federated_provider_access_grants_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_federated_provider_access_grants" ADD CONSTRAINT "tenant_federated_provider_access_grants_epoch_fk" FOREIGN KEY ("tenant_id","access_epoch_id","binding_id","provider_id","source_id") REFERENCES "public"."tenant_identity_provider_access_epochs"("tenant_id","id","binding_id","provider_id","source_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_federated_provider_access_grants" ADD CONSTRAINT "tenant_federated_provider_access_grants_identity_fk" FOREIGN KEY ("tenant_id","provider_id","external_identity_id","user_id") REFERENCES "public"."tenant_federated_external_identities"("tenant_id","provider_id","id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_federated_provider_access_grants" ADD CONSTRAINT "tenant_federated_provider_access_grants_membership_fk" FOREIGN KEY ("tenant_id","membership_id","user_id") REFERENCES "public"."tenant_memberships"("tenant_id","id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_federated_provider_access_grants" ADD CONSTRAINT "tenant_federated_provider_access_grants_source_fk" FOREIGN KEY ("tenant_id","source_id") REFERENCES "public"."tenant_authorization_sources"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_federated_provider_policies" ADD CONSTRAINT "tenant_federated_provider_policies_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_federated_provider_policies" ADD CONSTRAINT "tenant_federated_provider_policies_provider_fk" FOREIGN KEY ("tenant_id","provider_id","provider_kind") REFERENCES "public"."tenant_auth_providers"("tenant_id","id","kind") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_federated_provider_policies" ADD CONSTRAINT "tenant_federated_provider_policies_binding_fk" FOREIGN KEY ("tenant_id","binding_id","provider_id") REFERENCES "public"."tenant_auth_provider_bindings"("tenant_id","id","provider_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_federated_provider_profile_contributions" ADD CONSTRAINT "tenant_federated_provider_profile_contributions_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_federated_provider_profile_contributions" ADD CONSTRAINT "tenant_federated_provider_profile_contributions_grant_fk" FOREIGN KEY ("tenant_id","access_grant_id") REFERENCES "public"."tenant_federated_provider_access_grants"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_federated_session_revalidation_commands" ADD CONSTRAINT "tenant_federated_session_revalidation_commands_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_federated_session_revalidation_commands" ADD CONSTRAINT "tenant_federated_session_revalidation_commands_session_fk" FOREIGN KEY ("tenant_id","session_id") REFERENCES "public"."auth_session_mfa_states"("tenant_id","session_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_federated_trust_rules" ADD CONSTRAINT "tenant_federated_trust_rules_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_federated_trust_rules" ADD CONSTRAINT "tenant_federated_trust_rules_policy_fk" FOREIGN KEY ("tenant_id","binding_id","provider_id","provider_kind") REFERENCES "public"."tenant_federated_provider_policies"("tenant_id","binding_id","provider_id","provider_kind") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_oidc_claim_rules" ADD CONSTRAINT "tenant_oidc_claim_rules_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_oidc_claim_rules" ADD CONSTRAINT "tenant_oidc_claim_rules_configuration_fk" FOREIGN KEY ("tenant_id","provider_id") REFERENCES "public"."tenant_oidc_provider_configurations"("tenant_id","provider_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_oidc_client_secrets" ADD CONSTRAINT "tenant_oidc_client_secrets_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_oidc_client_secrets" ADD CONSTRAINT "tenant_oidc_client_secrets_configuration_fk" FOREIGN KEY ("tenant_id","provider_id") REFERENCES "public"."tenant_oidc_provider_configurations"("tenant_id","provider_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_oidc_client_secrets" ADD CONSTRAINT "tenant_oidc_client_secrets_keyring_fk" FOREIGN KEY ("key_version") REFERENCES "public"."identity_keyring_versions"("key_version") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_oidc_discovery_snapshots" ADD CONSTRAINT "tenant_oidc_discovery_snapshots_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_oidc_discovery_snapshots" ADD CONSTRAINT "tenant_oidc_discovery_snapshots_configuration_fk" FOREIGN KEY ("tenant_id","provider_id") REFERENCES "public"."tenant_oidc_provider_configurations"("tenant_id","provider_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_oidc_jwks_snapshots" ADD CONSTRAINT "tenant_oidc_jwks_snapshots_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_oidc_jwks_snapshots" ADD CONSTRAINT "tenant_oidc_jwks_snapshots_configuration_fk" FOREIGN KEY ("tenant_id","provider_id") REFERENCES "public"."tenant_oidc_provider_configurations"("tenant_id","provider_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_oidc_provider_configurations" ADD CONSTRAINT "tenant_oidc_provider_configurations_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_oidc_provider_configurations" ADD CONSTRAINT "tenant_oidc_provider_configurations_policy_fk" FOREIGN KEY ("tenant_id","provider_id","provider_kind") REFERENCES "public"."tenant_auth_providers"("tenant_id","id","kind") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_saml_attribute_rules" ADD CONSTRAINT "tenant_saml_attribute_rules_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_saml_attribute_rules" ADD CONSTRAINT "tenant_saml_attribute_rules_configuration_fk" FOREIGN KEY ("tenant_id","provider_id") REFERENCES "public"."tenant_saml_provider_configurations"("tenant_id","provider_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_saml_metadata_snapshots" ADD CONSTRAINT "tenant_saml_metadata_snapshots_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_saml_metadata_snapshots" ADD CONSTRAINT "tenant_saml_metadata_snapshots_configuration_fk" FOREIGN KEY ("tenant_id","provider_id") REFERENCES "public"."tenant_saml_provider_configurations"("tenant_id","provider_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_saml_provider_configurations" ADD CONSTRAINT "tenant_saml_provider_configurations_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_saml_provider_configurations" ADD CONSTRAINT "tenant_saml_provider_configurations_provider_fk" FOREIGN KEY ("tenant_id","provider_id","provider_kind") REFERENCES "public"."tenant_auth_providers"("tenant_id","id","kind") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_saml_session_materials" ADD CONSTRAINT "tenant_saml_session_materials_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_saml_session_materials" ADD CONSTRAINT "tenant_saml_session_materials_policy_fk" FOREIGN KEY ("tenant_id","binding_id","provider_id","provider_kind") REFERENCES "public"."tenant_federated_provider_policies"("tenant_id","binding_id","provider_id","provider_kind") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_saml_session_materials" ADD CONSTRAINT "tenant_saml_session_materials_keyring_fk" FOREIGN KEY ("key_version") REFERENCES "public"."identity_keyring_versions"("key_version") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_saml_session_materials" ADD CONSTRAINT "tenant_saml_session_materials_session_fk" FOREIGN KEY ("tenant_id","session_id","user_id","provider_id","binding_id","provider_kind","external_identity_id") REFERENCES "public"."auth_session_federated_provenance"("tenant_id","session_id","user_id","provider_id","binding_id","provider_kind","external_identity_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_saml_sp_certificates" ADD CONSTRAINT "tenant_saml_sp_certificates_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_saml_sp_certificates" ADD CONSTRAINT "tenant_saml_sp_certificates_key_fk" FOREIGN KEY ("tenant_id","key_id") REFERENCES "public"."tenant_saml_sp_keys"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_saml_sp_keys" ADD CONSTRAINT "tenant_saml_sp_keys_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_saml_sp_keys" ADD CONSTRAINT "tenant_saml_sp_keys_configuration_fk" FOREIGN KEY ("tenant_id","provider_id") REFERENCES "public"."tenant_saml_provider_configurations"("tenant_id","provider_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_saml_sp_keys" ADD CONSTRAINT "tenant_saml_sp_keys_keyring_fk" FOREIGN KEY ("key_version") REFERENCES "public"."identity_keyring_versions"("key_version") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
CREATE UNIQUE INDEX "tenant_federated_authentication_applications_transaction_key" ON "tenant_federated_authentication_applications" USING btree ("tenant_id","protocol","transaction_id") WHERE "tenant_federated_authentication_applications"."transaction_id" is not null;--> statement-breakpoint
CREATE UNIQUE INDEX "tenant_federated_authentication_applications_saml_response_key" ON "tenant_federated_authentication_applications" USING btree ("tenant_id","provider_id","response_id_digest") WHERE "tenant_federated_authentication_applications"."protocol" = 'saml';--> statement-breakpoint
CREATE UNIQUE INDEX "tenant_federated_authentication_applications_saml_assertion_key" ON "tenant_federated_authentication_applications" USING btree ("tenant_id","provider_id","assertion_id_digest") WHERE "tenant_federated_authentication_applications"."protocol" = 'saml';--> statement-breakpoint
CREATE UNIQUE INDEX "tenant_federated_authentication_applications_saml_session_index_key" ON "tenant_federated_authentication_applications" USING btree ("tenant_id","provider_id","session_index_digest") WHERE "tenant_federated_authentication_applications"."session_index_digest" is not null;--> statement-breakpoint
CREATE UNIQUE INDEX "tenant_federated_authentication_transactions_oidc_state_key" ON "tenant_federated_authentication_transactions" USING btree ("state_digest") WHERE "tenant_federated_authentication_transactions"."protocol" = 'oidc';--> statement-breakpoint
CREATE UNIQUE INDEX "tenant_federated_authentication_transactions_saml_relay_key" ON "tenant_federated_authentication_transactions" USING btree ("relay_state_digest") WHERE "tenant_federated_authentication_transactions"."protocol" = 'saml';--> statement-breakpoint
CREATE UNIQUE INDEX "tenant_federated_authentication_transactions_live_browser_key" ON "tenant_federated_authentication_transactions" USING btree ("protocol","browser_digest") WHERE "tenant_federated_authentication_transactions"."state" in ('pending', 'claimed');--> statement-breakpoint
CREATE INDEX "tenant_federated_authentication_transactions_expiry_idx" ON "tenant_federated_authentication_transactions" USING btree ("state","expires_at","transaction_id");--> statement-breakpoint
CREATE UNIQUE INDEX "tenant_federated_external_identities_live_provider_user_key" ON "tenant_federated_external_identities" USING btree ("tenant_id","provider_id","user_id") WHERE "tenant_federated_external_identities"."retired_at" is null;--> statement-breakpoint
CREATE UNIQUE INDEX "tenant_federated_mapping_rule_epochs_live_rule_key" ON "tenant_federated_mapping_rule_epochs" USING btree ("tenant_id","rule_id") WHERE "tenant_federated_mapping_rule_epochs"."ended_at" is null;--> statement-breakpoint
CREATE INDEX "tenant_federated_mapping_rule_epochs_planning_idx" ON "tenant_federated_mapping_rule_epochs" USING btree ("tenant_id","binding_id","mapping_revision","enabled","priority","rule_id");--> statement-breakpoint
CREATE UNIQUE INDEX "tenant_federated_provider_access_grants_live_binding_member_key" ON "tenant_federated_provider_access_grants" USING btree ("tenant_id","binding_id","membership_id") WHERE "tenant_federated_provider_access_grants"."ended_at" is null;--> statement-breakpoint
CREATE UNIQUE INDEX "tenant_federated_provider_profile_contributions_live_grant_key" ON "tenant_federated_provider_profile_contributions" USING btree ("tenant_id","access_grant_id") WHERE "tenant_federated_provider_profile_contributions"."retired_at" is null;--> statement-breakpoint
CREATE UNIQUE INDEX "tenant_federated_trust_rules_live_key" ON "tenant_federated_trust_rules" USING btree ("tenant_id","id") WHERE "tenant_federated_trust_rules"."retired_at" is null;--> statement-breakpoint
CREATE INDEX "tenant_federated_trust_rules_provider_idx" ON "tenant_federated_trust_rules" USING btree ("tenant_id","provider_id","binding_id","id");--> statement-breakpoint
CREATE UNIQUE INDEX "tenant_saml_session_materials_session_key" ON "tenant_saml_session_materials" USING btree ("tenant_id","session_id") WHERE "tenant_saml_session_materials"."session_id" is not null;--> statement-breakpoint
CREATE UNIQUE INDEX "tenant_saml_session_materials_continuation_key" ON "tenant_saml_session_materials" USING btree ("tenant_id","continuation_id") WHERE "tenant_saml_session_materials"."continuation_id" is not null;--> statement-breakpoint
CREATE UNIQUE INDEX "tenant_saml_session_materials_session_index_key" ON "tenant_saml_session_materials" USING btree ("tenant_id","provider_id","session_index_digest") WHERE "tenant_saml_session_materials"."session_index_digest" is not null;--> statement-breakpoint
ALTER TABLE "tenant_post_primary_continuations" ADD CONSTRAINT "tenant_post_primary_continuations_provider_binding_fk" FOREIGN KEY ("tenant_id","binding_id","provider_id") REFERENCES "public"."tenant_auth_provider_bindings"("tenant_id","id","provider_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "auth_session_mfa_states" ADD CONSTRAINT "auth_session_mfa_states_exact_user_key" UNIQUE("tenant_id","session_id","user_id");--> statement-breakpoint
ALTER TABLE "tenant_post_primary_continuations" ADD CONSTRAINT "tenant_post_primary_continuations_exact_user_key" UNIQUE("tenant_id","id","user_id");--> statement-breakpoint
ALTER TABLE "tenant_post_primary_continuations" ADD CONSTRAINT "tenant_post_primary_continuations_exact_provider_key" UNIQUE("tenant_id","id","user_id","provider_id","binding_id","provider_kind","external_identity_id");--> statement-breakpoint
ALTER TABLE "auth_sessions" ADD CONSTRAINT "auth_sessions_method_check" CHECK ("auth_sessions"."authentication_method" in ('bootstrap_totp', 'passkey', 'totp', 'recovery_code', 'oidc', 'saml'));--> statement-breakpoint
ALTER TABLE "auth_session_mfa_states" ADD CONSTRAINT "auth_session_mfa_states_primary_kind_check" CHECK ("auth_session_mfa_states"."primary_kind" in ('local_credential', 'passkey', 'tenant_provider'));--> statement-breakpoint
ALTER TABLE "tenant_post_primary_continuations" ADD CONSTRAINT "tenant_post_primary_continuations_primary_check" CHECK (("tenant_post_primary_continuations"."primary_kind" = 'local_credential'
          and "tenant_post_primary_continuations"."local_credential_id" is not null
          and "tenant_post_primary_continuations"."passkey_credential_id" is null
          and "tenant_post_primary_continuations"."provider_id" is null and "tenant_post_primary_continuations"."binding_id" is null
          and "tenant_post_primary_continuations"."provider_kind" is null
          and "tenant_post_primary_continuations"."external_identity_id" is null)
        or ("tenant_post_primary_continuations"."primary_kind" = 'passkey'
          and "tenant_post_primary_continuations"."local_credential_id" is null
          and "tenant_post_primary_continuations"."passkey_credential_id" is not null
          and "tenant_post_primary_continuations"."provider_id" is null and "tenant_post_primary_continuations"."binding_id" is null
          and "tenant_post_primary_continuations"."provider_kind" is null
          and "tenant_post_primary_continuations"."external_identity_id" is null)
        or ("tenant_post_primary_continuations"."primary_kind" = 'tenant_provider'
          and "tenant_post_primary_continuations"."local_credential_id" is null
          and "tenant_post_primary_continuations"."passkey_credential_id" is null
          and "tenant_post_primary_continuations"."provider_id" is not null and "tenant_post_primary_continuations"."binding_id" is not null
          and "tenant_post_primary_continuations"."provider_kind" in ('oidc', 'saml')
          and "tenant_post_primary_continuations"."external_identity_id" is not null));--> statement-breakpoint
ALTER TABLE "tenant_auth_providers" ADD CONSTRAINT "tenant_auth_providers_implemented_kind_check" CHECK ("tenant_auth_providers"."kind" in ('ldap', 'oidc', 'saml'));