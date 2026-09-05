CREATE TYPE "public"."auth_challenge_purpose" AS ENUM('local_login', 'mfa_login', 'totp_enrollment', 'step_up');--> statement-breakpoint
CREATE TYPE "public"."auth_rate_limit_scope" AS ENUM('bootstrap_totp', 'local_login', 'mfa_challenge', 'recovery_code', 'tenant_switch');--> statement-breakpoint
CREATE TABLE "auth_challenges" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"user_id" uuid NOT NULL,
	"challenge_rate_key_digest" "bytea" NOT NULL,
	"mfa_rate_key_digest" "bytea" NOT NULL,
	"login_account_rate_key_digest" "bytea" NOT NULL,
	"token_digest" "bytea" NOT NULL,
	"purpose" "auth_challenge_purpose" NOT NULL,
	"attempts" integer DEFAULT 0 NOT NULL,
	"max_attempts" integer DEFAULT 5 NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"consumed_at" timestamp with time zone,
	"last_attempt_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "auth_challenges_token_digest_key" UNIQUE("token_digest"),
	CONSTRAINT "auth_challenges_id_uuidv7_check" CHECK ((uuid_extract_version("auth_challenges"."id") = 7) is true),
	CONSTRAINT "auth_challenges_digest_check" CHECK (octet_length("auth_challenges"."token_digest") = 32),
	CONSTRAINT "auth_challenges_challenge_rate_digest_check" CHECK (octet_length("auth_challenges"."challenge_rate_key_digest") = 32),
	CONSTRAINT "auth_challenges_mfa_rate_digest_check" CHECK (octet_length("auth_challenges"."mfa_rate_key_digest") = 32),
	CONSTRAINT "auth_challenges_login_account_rate_digest_check" CHECK (octet_length("auth_challenges"."login_account_rate_key_digest") = 32),
	CONSTRAINT "auth_challenges_attempts_check" CHECK ("auth_challenges"."attempts" >= 0 and "auth_challenges"."max_attempts" between 1 and 20 and "auth_challenges"."attempts" <= "auth_challenges"."max_attempts"),
	CONSTRAINT "auth_challenges_expiry_check" CHECK ("auth_challenges"."expires_at" > "auth_challenges"."created_at"),
	CONSTRAINT "auth_challenges_consumed_check" CHECK ("auth_challenges"."consumed_at" is null or "auth_challenges"."consumed_at" >= "auth_challenges"."created_at")
);
--> statement-breakpoint
ALTER TABLE "auth_challenges" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "auth_rate_limits" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"scope" "auth_rate_limit_scope" NOT NULL,
	"key_digest" "bytea" NOT NULL,
	"attempt_count" integer DEFAULT 0 NOT NULL,
	"window_started_at" timestamp with time zone NOT NULL,
	"window_expires_at" timestamp with time zone NOT NULL,
	"blocked_until" timestamp with time zone,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "auth_rate_limits_scope_key_key" UNIQUE("scope","key_digest"),
	CONSTRAINT "auth_rate_limits_id_uuidv7_check" CHECK ((uuid_extract_version("auth_rate_limits"."id") = 7) is true),
	CONSTRAINT "auth_rate_limits_digest_check" CHECK (octet_length("auth_rate_limits"."key_digest") = 32),
	CONSTRAINT "auth_rate_limits_attempt_count_check" CHECK ("auth_rate_limits"."attempt_count" >= 0),
	CONSTRAINT "auth_rate_limits_window_check" CHECK ("auth_rate_limits"."window_expires_at" > "auth_rate_limits"."window_started_at")
);
--> statement-breakpoint
ALTER TABLE "auth_rate_limits" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "auth_sessions" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"user_id" uuid NOT NULL,
	"rotation_family_id" uuid NOT NULL,
	"active_tenant_id" uuid,
	"token_digest" "bytea" NOT NULL,
	"csrf_secret_digest" "bytea" NOT NULL,
	"authentication_method" text NOT NULL,
	"mfa_satisfied_at" timestamp with time zone,
	"last_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"idle_expires_at" timestamp with time zone NOT NULL,
	"absolute_expires_at" timestamp with time zone NOT NULL,
	"revoked_at" timestamp with time zone,
	"revoke_reason" text,
	"rotated_from_session_id" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "auth_sessions_token_digest_key" UNIQUE("token_digest"),
	CONSTRAINT "auth_sessions_rotated_from_key" UNIQUE("rotated_from_session_id"),
	CONSTRAINT "auth_sessions_id_uuidv7_check" CHECK ((uuid_extract_version("auth_sessions"."id") = 7) is true),
	CONSTRAINT "auth_sessions_rotation_family_uuidv7_check" CHECK ((uuid_extract_version("auth_sessions"."rotation_family_id") = 7) is true),
	CONSTRAINT "auth_sessions_token_digest_check" CHECK (octet_length("auth_sessions"."token_digest") = 32),
	CONSTRAINT "auth_sessions_csrf_digest_check" CHECK (octet_length("auth_sessions"."csrf_secret_digest") = 32),
	CONSTRAINT "auth_sessions_method_check" CHECK ("auth_sessions"."authentication_method" in ('bootstrap_totp', 'totp', 'recovery_code')),
	CONSTRAINT "auth_sessions_expiry_check" CHECK ("auth_sessions"."last_seen_at" >= "auth_sessions"."created_at"
        and "auth_sessions"."idle_expires_at" > "auth_sessions"."created_at"
        and "auth_sessions"."absolute_expires_at" > "auth_sessions"."created_at"
        and "auth_sessions"."idle_expires_at" <= "auth_sessions"."absolute_expires_at"),
	CONSTRAINT "auth_sessions_revoke_check" CHECK (("auth_sessions"."revoked_at" is null and "auth_sessions"."revoke_reason" is null)
        or ("auth_sessions"."revoked_at" >= "auth_sessions"."created_at" and btrim("auth_sessions"."revoke_reason") <> ''))
);
--> statement-breakpoint
ALTER TABLE "auth_sessions" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "local_break_glass_credentials" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"user_id" uuid NOT NULL,
	"password_phc" text NOT NULL,
	"password_algorithm" text DEFAULT 'argon2id' NOT NULL,
	"password_version" integer DEFAULT 1 NOT NULL,
	"must_rotate" boolean DEFAULT false NOT NULL,
	"changed_at" timestamp with time zone DEFAULT now() NOT NULL,
	"disabled_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "local_break_glass_credentials_user_key" UNIQUE("user_id"),
	CONSTRAINT "local_break_glass_credentials_id_uuidv7_check" CHECK ((uuid_extract_version("local_break_glass_credentials"."id") = 7) is true),
	CONSTRAINT "local_break_glass_credentials_algorithm_check" CHECK ("local_break_glass_credentials"."password_algorithm" = 'argon2id'),
	CONSTRAINT "local_break_glass_credentials_phc_check" CHECK ("local_break_glass_credentials"."password_phc" like '$argon2id$%' and length("local_break_glass_credentials"."password_phc") between 32 and 1024),
	CONSTRAINT "local_break_glass_credentials_version_check" CHECK ("local_break_glass_credentials"."password_version" > 0),
	CONSTRAINT "local_break_glass_credentials_updated_check" CHECK ("local_break_glass_credentials"."updated_at" >= "local_break_glass_credentials"."created_at" and "local_break_glass_credentials"."changed_at" >= "local_break_glass_credentials"."created_at")
);
--> statement-breakpoint
ALTER TABLE "local_break_glass_credentials" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "recovery_codes" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"user_id" uuid NOT NULL,
	"totp_credential_id" uuid NOT NULL,
	"code_digest" "bytea" NOT NULL,
	"key_version" integer NOT NULL,
	"consumed_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "recovery_codes_credential_digest_key" UNIQUE("totp_credential_id","code_digest"),
	CONSTRAINT "recovery_codes_id_uuidv7_check" CHECK ((uuid_extract_version("recovery_codes"."id") = 7) is true),
	CONSTRAINT "recovery_codes_digest_check" CHECK (octet_length("recovery_codes"."code_digest") = 32),
	CONSTRAINT "recovery_codes_key_version_check" CHECK ("recovery_codes"."key_version" > 0),
	CONSTRAINT "recovery_codes_consumed_after_created_check" CHECK ("recovery_codes"."consumed_at" is null or "recovery_codes"."consumed_at" >= "recovery_codes"."created_at")
);
--> statement-breakpoint
ALTER TABLE "recovery_codes" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "totp_credentials" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"user_id" uuid NOT NULL,
	"secret_ciphertext" "bytea" NOT NULL,
	"secret_nonce" "bytea" NOT NULL,
	"secret_aad" "bytea" NOT NULL,
	"key_version" integer NOT NULL,
	"encryption_algorithm" text DEFAULT 'aes-256-gcm' NOT NULL,
	"otp_algorithm" text DEFAULT 'SHA1' NOT NULL,
	"digits" integer DEFAULT 6 NOT NULL,
	"period_seconds" integer DEFAULT 30 NOT NULL,
	"confirmed_at" timestamp with time zone,
	"last_accepted_counter" bigint,
	"disabled_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "totp_credentials_user_key" UNIQUE("user_id"),
	CONSTRAINT "totp_credentials_id_user_key" UNIQUE("id","user_id"),
	CONSTRAINT "totp_credentials_id_uuidv7_check" CHECK ((uuid_extract_version("totp_credentials"."id") = 7) is true),
	CONSTRAINT "totp_credentials_ciphertext_check" CHECK (octet_length("totp_credentials"."secret_ciphertext") > 16),
	CONSTRAINT "totp_credentials_nonce_check" CHECK (octet_length("totp_credentials"."secret_nonce") >= 12),
	CONSTRAINT "totp_credentials_aad_check" CHECK (octet_length("totp_credentials"."secret_aad") > 0),
	CONSTRAINT "totp_credentials_key_version_check" CHECK ("totp_credentials"."key_version" > 0),
	CONSTRAINT "totp_credentials_encryption_algorithm_check" CHECK ("totp_credentials"."encryption_algorithm" in ('aes-256-gcm', 'xchacha20-poly1305')),
	CONSTRAINT "totp_credentials_otp_algorithm_check" CHECK ("totp_credentials"."otp_algorithm" in ('SHA1', 'SHA256', 'SHA512')),
	CONSTRAINT "totp_credentials_digits_check" CHECK ("totp_credentials"."digits" in (6, 8)),
	CONSTRAINT "totp_credentials_period_check" CHECK ("totp_credentials"."period_seconds" between 15 and 120),
	CONSTRAINT "totp_credentials_counter_check" CHECK ("totp_credentials"."last_accepted_counter" is null or "totp_credentials"."last_accepted_counter" >= 0),
	CONSTRAINT "totp_credentials_updated_check" CHECK ("totp_credentials"."updated_at" >= "totp_credentials"."created_at")
);
--> statement-breakpoint
ALTER TABLE "totp_credentials" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "platform_audit_chain_head" (
	"singleton" boolean PRIMARY KEY DEFAULT true NOT NULL,
	"last_sequence" bigint DEFAULT 0 NOT NULL,
	"last_event_hash" char(64) DEFAULT '0000000000000000000000000000000000000000000000000000000000000000' NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "platform_audit_chain_head_singleton_check" CHECK ("platform_audit_chain_head"."singleton" is true),
	CONSTRAINT "platform_audit_chain_head_sequence_check" CHECK ("platform_audit_chain_head"."last_sequence" >= 0),
	CONSTRAINT "platform_audit_chain_head_hash_check" CHECK ("platform_audit_chain_head"."last_event_hash" ~ '^[0-9a-f]{64}$')
);
--> statement-breakpoint
ALTER TABLE "platform_audit_chain_head" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "platform_audit_events" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"sequence" bigint NOT NULL,
	"occurred_at" timestamp with time zone DEFAULT now() NOT NULL,
	"actor_type" "audit_actor_type" NOT NULL,
	"actor_user_id" uuid,
	"action" text NOT NULL,
	"resource_type" text NOT NULL,
	"resource_id" uuid,
	"request_id" uuid,
	"correlation_id" uuid,
	"ip_address" "inet",
	"user_agent" text,
	"authentication_method" text,
	"outcome" "audit_outcome" NOT NULL,
	"reason" text,
	"before" jsonb,
	"after" jsonb,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"previous_hash" char(64) DEFAULT '0000000000000000000000000000000000000000000000000000000000000000' NOT NULL,
	"event_hash" char(64) DEFAULT '0000000000000000000000000000000000000000000000000000000000000000' NOT NULL,
	CONSTRAINT "platform_audit_events_sequence_key" UNIQUE("sequence"),
	CONSTRAINT "platform_audit_events_id_uuidv7_check" CHECK ((uuid_extract_version("platform_audit_events"."id") = 7) is true),
	CONSTRAINT "platform_audit_events_sequence_check" CHECK ("platform_audit_events"."sequence" > 0),
	CONSTRAINT "platform_audit_events_action_check" CHECK (btrim("platform_audit_events"."action") <> ''),
	CONSTRAINT "platform_audit_events_resource_type_check" CHECK (btrim("platform_audit_events"."resource_type") <> ''),
	CONSTRAINT "platform_audit_events_user_agent_check" CHECK ("platform_audit_events"."user_agent" is null or length("platform_audit_events"."user_agent") between 1 and 1024),
	CONSTRAINT "platform_audit_events_authentication_method_check" CHECK ("platform_audit_events"."authentication_method" is null or length("platform_audit_events"."authentication_method") between 1 and 64),
	CONSTRAINT "platform_audit_events_reason_check" CHECK ("platform_audit_events"."reason" is null or length("platform_audit_events"."reason") between 1 and 1024),
	CONSTRAINT "platform_audit_events_actor_check" CHECK (("platform_audit_events"."actor_type" = 'user' and "platform_audit_events"."actor_user_id" is not null)
        or ("platform_audit_events"."actor_type" in ('system', 'service_account') and "platform_audit_events"."actor_user_id" is null)),
	CONSTRAINT "platform_audit_events_previous_hash_check" CHECK ("platform_audit_events"."previous_hash" ~ '^[0-9a-f]{64}$'),
	CONSTRAINT "platform_audit_events_event_hash_check" CHECK ("platform_audit_events"."event_hash" ~ '^[0-9a-f]{64}$')
);
--> statement-breakpoint
ALTER TABLE "platform_audit_events" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "platform_bootstrap_enrollments" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"singleton_slot" boolean DEFAULT true NOT NULL,
	"canonical_email" text NOT NULL,
	"token_digest" "bytea" NOT NULL,
	"enrollment_rate_key_digest" "bytea" NOT NULL,
	"totp_secret_ciphertext" "bytea" NOT NULL,
	"totp_secret_nonce" "bytea" NOT NULL,
	"totp_secret_aad" "bytea" NOT NULL,
	"totp_key_version" integer NOT NULL,
	"attempts" integer DEFAULT 0 NOT NULL,
	"max_attempts" integer DEFAULT 5 NOT NULL,
	"last_attempt_at" timestamp with time zone,
	"expires_at" timestamp with time zone NOT NULL,
	"consumed_at" timestamp with time zone,
	"invalidated_at" timestamp with time zone,
	"consumed_by_user_id" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "platform_bootstrap_enrollments_token_key" UNIQUE("token_digest"),
	CONSTRAINT "platform_bootstrap_enrollments_id_uuidv7_check" CHECK ((uuid_extract_version("platform_bootstrap_enrollments"."id") = 7) is true),
	CONSTRAINT "platform_bootstrap_enrollments_slot_check" CHECK ("platform_bootstrap_enrollments"."singleton_slot" is true),
	CONSTRAINT "platform_bootstrap_enrollments_email_check" CHECK ("platform_bootstrap_enrollments"."canonical_email" = lower(btrim("platform_bootstrap_enrollments"."canonical_email")) and position('@' in "platform_bootstrap_enrollments"."canonical_email") > 1),
	CONSTRAINT "platform_bootstrap_enrollments_token_check" CHECK (octet_length("platform_bootstrap_enrollments"."token_digest") = 32),
	CONSTRAINT "platform_bootstrap_enrollments_rate_digest_check" CHECK (octet_length("platform_bootstrap_enrollments"."enrollment_rate_key_digest") = 32),
	CONSTRAINT "platform_bootstrap_enrollments_ciphertext_check" CHECK (octet_length("platform_bootstrap_enrollments"."totp_secret_ciphertext") > 16),
	CONSTRAINT "platform_bootstrap_enrollments_nonce_check" CHECK (octet_length("platform_bootstrap_enrollments"."totp_secret_nonce") >= 12),
	CONSTRAINT "platform_bootstrap_enrollments_aad_check" CHECK (octet_length("platform_bootstrap_enrollments"."totp_secret_aad") > 0),
	CONSTRAINT "platform_bootstrap_enrollments_key_version_check" CHECK ("platform_bootstrap_enrollments"."totp_key_version" > 0),
	CONSTRAINT "platform_bootstrap_enrollments_attempts_check" CHECK ("platform_bootstrap_enrollments"."attempts" >= 0 and "platform_bootstrap_enrollments"."max_attempts" between 1 and 10 and "platform_bootstrap_enrollments"."attempts" <= "platform_bootstrap_enrollments"."max_attempts"),
	CONSTRAINT "platform_bootstrap_enrollments_expiry_check" CHECK ("platform_bootstrap_enrollments"."expires_at" > "platform_bootstrap_enrollments"."created_at" and "platform_bootstrap_enrollments"."expires_at" <= "platform_bootstrap_enrollments"."created_at" + interval '15 minutes'),
	CONSTRAINT "platform_bootstrap_enrollments_consumption_check" CHECK (("platform_bootstrap_enrollments"."consumed_at" is null and "platform_bootstrap_enrollments"."consumed_by_user_id" is null)
        or ("platform_bootstrap_enrollments"."consumed_at" >= "platform_bootstrap_enrollments"."created_at" and "platform_bootstrap_enrollments"."consumed_by_user_id" is not null and "platform_bootstrap_enrollments"."invalidated_at" is null)),
	CONSTRAINT "platform_bootstrap_enrollments_invalidation_check" CHECK ("platform_bootstrap_enrollments"."invalidated_at" is null
        or ("platform_bootstrap_enrollments"."invalidated_at" >= "platform_bootstrap_enrollments"."created_at" and "platform_bootstrap_enrollments"."consumed_at" is null))
);
--> statement-breakpoint
ALTER TABLE "platform_bootstrap_enrollments" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "platform_bootstrap_state" (
	"singleton" boolean PRIMARY KEY DEFAULT true NOT NULL,
	"authority_token_digest" "bytea",
	"authority_configured_at" timestamp with time zone,
	"master_key_verifier" "bytea",
	"master_key_verifier_bound_at" timestamp with time zone,
	"completed_at" timestamp with time zone,
	"completed_by_user_id" uuid,
	"enrollment_id" uuid,
	CONSTRAINT "platform_bootstrap_state_singleton_check" CHECK ("platform_bootstrap_state"."singleton" is true),
	CONSTRAINT "platform_bootstrap_state_authority_check" CHECK (("platform_bootstrap_state"."authority_token_digest" is null and "platform_bootstrap_state"."authority_configured_at" is null)
        or (octet_length("platform_bootstrap_state"."authority_token_digest") = 32 and "platform_bootstrap_state"."authority_configured_at" is not null)),
	CONSTRAINT "platform_bootstrap_state_master_key_verifier_check" CHECK (("platform_bootstrap_state"."master_key_verifier" is null and "platform_bootstrap_state"."master_key_verifier_bound_at" is null)
        or (octet_length("platform_bootstrap_state"."master_key_verifier") = 32 and "platform_bootstrap_state"."master_key_verifier_bound_at" is not null)),
	CONSTRAINT "platform_bootstrap_state_protected_configuration_check" CHECK (("platform_bootstrap_state"."authority_token_digest" is null
          and "platform_bootstrap_state"."authority_configured_at" is null
          and "platform_bootstrap_state"."master_key_verifier" is null
          and "platform_bootstrap_state"."master_key_verifier_bound_at" is null)
        or ("platform_bootstrap_state"."authority_token_digest" is not null
          and "platform_bootstrap_state"."authority_configured_at" is not null
          and "platform_bootstrap_state"."master_key_verifier" is not null
          and "platform_bootstrap_state"."master_key_verifier_bound_at" is not null)),
	CONSTRAINT "platform_bootstrap_state_completion_check" CHECK (("platform_bootstrap_state"."completed_at" is null and "platform_bootstrap_state"."completed_by_user_id" is null and "platform_bootstrap_state"."enrollment_id" is null)
        or ("platform_bootstrap_state"."completed_at" is not null
          and "platform_bootstrap_state"."completed_by_user_id" is not null
          and "platform_bootstrap_state"."enrollment_id" is not null
          and "platform_bootstrap_state"."master_key_verifier" is not null
          and "platform_bootstrap_state"."master_key_verifier_bound_at" <= "platform_bootstrap_state"."completed_at"))
);
--> statement-breakpoint
ALTER TABLE "platform_bootstrap_state" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "platform_permissions" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"key" text NOT NULL,
	"description" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "platform_permissions_key_key" UNIQUE("key"),
	CONSTRAINT "platform_permissions_id_uuidv7_check" CHECK ((uuid_extract_version("platform_permissions"."id") = 7) is true),
	CONSTRAINT "platform_permissions_key_canonical_check" CHECK ("platform_permissions"."key" ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'),
	CONSTRAINT "platform_permissions_description_check" CHECK (btrim("platform_permissions"."description") <> '')
);
--> statement-breakpoint
ALTER TABLE "platform_permissions" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "platform_role_permissions" (
	"role_id" uuid NOT NULL,
	"permission_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "platform_role_permissions_pkey" PRIMARY KEY("role_id","permission_id")
);
--> statement-breakpoint
ALTER TABLE "platform_role_permissions" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "platform_roles" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"key" text NOT NULL,
	"display_name" text NOT NULL,
	"system" boolean DEFAULT true NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "platform_roles_key_key" UNIQUE("key"),
	CONSTRAINT "platform_roles_id_uuidv7_check" CHECK ((uuid_extract_version("platform_roles"."id") = 7) is true),
	CONSTRAINT "platform_roles_key_canonical_check" CHECK ("platform_roles"."key" ~ '^[a-z][a-z0-9_]*$'),
	CONSTRAINT "platform_roles_display_name_check" CHECK (btrim("platform_roles"."display_name") <> '')
);
--> statement-breakpoint
ALTER TABLE "platform_roles" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "user_platform_roles" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"user_id" uuid NOT NULL,
	"role_id" uuid NOT NULL,
	"granted_by_user_id" uuid,
	"granted_at" timestamp with time zone DEFAULT now() NOT NULL,
	"revoked_at" timestamp with time zone,
	"revoked_by_user_id" uuid,
	CONSTRAINT "user_platform_roles_id_uuidv7_check" CHECK ((uuid_extract_version("user_platform_roles"."id") = 7) is true),
	CONSTRAINT "user_platform_roles_revocation_check" CHECK (("user_platform_roles"."revoked_at" is null and "user_platform_roles"."revoked_by_user_id" is null)
        or ("user_platform_roles"."revoked_at" >= "user_platform_roles"."granted_at" and "user_platform_roles"."revoked_by_user_id" is not null))
);
--> statement-breakpoint
ALTER TABLE "user_platform_roles" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "users" DROP CONSTRAINT "users_email_canonical_check";--> statement-breakpoint
ALTER TABLE "users" DROP CONSTRAINT "users_email_shape_check";--> statement-breakpoint
ALTER TABLE "users" DROP CONSTRAINT "users_display_name_not_blank_check";--> statement-breakpoint
ALTER TABLE "tenants" DROP CONSTRAINT "tenants_slug_not_blank_check";--> statement-breakpoint
ALTER TABLE "tenants" DROP CONSTRAINT "tenants_name_not_blank_check";--> statement-breakpoint
ALTER TABLE "auth_challenges" ADD CONSTRAINT "auth_challenges_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "auth_sessions" ADD CONSTRAINT "auth_sessions_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "auth_sessions" ADD CONSTRAINT "auth_sessions_active_tenant_id_tenants_id_fk" FOREIGN KEY ("active_tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "auth_sessions" ADD CONSTRAINT "auth_sessions_rotated_from_fk" FOREIGN KEY ("rotated_from_session_id") REFERENCES "public"."auth_sessions"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "local_break_glass_credentials" ADD CONSTRAINT "local_break_glass_credentials_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "recovery_codes" ADD CONSTRAINT "recovery_codes_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "recovery_codes" ADD CONSTRAINT "recovery_codes_credential_user_fk" FOREIGN KEY ("totp_credential_id","user_id") REFERENCES "public"."totp_credentials"("id","user_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "totp_credentials" ADD CONSTRAINT "totp_credentials_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "platform_audit_events" ADD CONSTRAINT "platform_audit_events_actor_user_id_users_id_fk" FOREIGN KEY ("actor_user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "platform_bootstrap_enrollments" ADD CONSTRAINT "platform_bootstrap_enrollments_consumed_by_user_id_users_id_fk" FOREIGN KEY ("consumed_by_user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "platform_bootstrap_state" ADD CONSTRAINT "platform_bootstrap_state_completed_by_user_id_users_id_fk" FOREIGN KEY ("completed_by_user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "platform_bootstrap_state" ADD CONSTRAINT "platform_bootstrap_state_enrollment_id_platform_bootstrap_enrollments_id_fk" FOREIGN KEY ("enrollment_id") REFERENCES "public"."platform_bootstrap_enrollments"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "platform_role_permissions" ADD CONSTRAINT "platform_role_permissions_role_id_platform_roles_id_fk" FOREIGN KEY ("role_id") REFERENCES "public"."platform_roles"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "platform_role_permissions" ADD CONSTRAINT "platform_role_permissions_permission_id_platform_permissions_id_fk" FOREIGN KEY ("permission_id") REFERENCES "public"."platform_permissions"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_platform_roles" ADD CONSTRAINT "user_platform_roles_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_platform_roles" ADD CONSTRAINT "user_platform_roles_role_id_platform_roles_id_fk" FOREIGN KEY ("role_id") REFERENCES "public"."platform_roles"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_platform_roles" ADD CONSTRAINT "user_platform_roles_granted_by_user_id_users_id_fk" FOREIGN KEY ("granted_by_user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_platform_roles" ADD CONSTRAINT "user_platform_roles_revoked_by_user_id_users_id_fk" FOREIGN KEY ("revoked_by_user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "auth_challenges_user_unconsumed_key" ON "auth_challenges" USING btree ("user_id","purpose") WHERE "auth_challenges"."consumed_at" is null;--> statement-breakpoint
CREATE INDEX "auth_rate_limits_expiry_idx" ON "auth_rate_limits" USING btree ("window_expires_at");--> statement-breakpoint
CREATE INDEX "auth_sessions_user_active_idx" ON "auth_sessions" USING btree ("user_id","absolute_expires_at") WHERE "auth_sessions"."revoked_at" is null;--> statement-breakpoint
CREATE INDEX "auth_sessions_user_family_idx" ON "auth_sessions" USING btree ("user_id","rotation_family_id","created_at");--> statement-breakpoint
CREATE INDEX "recovery_codes_user_available_idx" ON "recovery_codes" USING btree ("user_id","created_at") WHERE "recovery_codes"."consumed_at" is null;--> statement-breakpoint
CREATE INDEX "platform_audit_events_time_idx" ON "platform_audit_events" USING btree ("occurred_at","id");--> statement-breakpoint
CREATE INDEX "platform_audit_events_resource_idx" ON "platform_audit_events" USING btree ("resource_type","resource_id");--> statement-breakpoint
CREATE UNIQUE INDEX "platform_bootstrap_enrollments_active_slot_key" ON "platform_bootstrap_enrollments" USING btree ("singleton_slot") WHERE "platform_bootstrap_enrollments"."consumed_at" is null and "platform_bootstrap_enrollments"."invalidated_at" is null;--> statement-breakpoint
CREATE UNIQUE INDEX "user_platform_roles_active_key" ON "user_platform_roles" USING btree ("user_id","role_id") WHERE "user_platform_roles"."revoked_at" is null;--> statement-breakpoint
CREATE INDEX "user_platform_roles_user_active_idx" ON "user_platform_roles" USING btree ("user_id","role_id") WHERE "user_platform_roles"."revoked_at" is null;--> statement-breakpoint
ALTER TABLE "users" ADD CONSTRAINT "users_email_canonical_check" CHECK ("users"."email" = lower(btrim("users"."email")));--> statement-breakpoint
ALTER TABLE "users" ADD CONSTRAINT "users_email_shape_check" CHECK (position('@' in "users"."email") > 1
        and char_length("users"."email") <= 320
        and "users"."email" !~ '[[:cntrl:]]');--> statement-breakpoint
ALTER TABLE "users" ADD CONSTRAINT "users_display_name_not_blank_check" CHECK (btrim("users"."display_name") <> ''
        and char_length("users"."display_name") <= 160
        and "users"."display_name" !~ '[[:cntrl:]]');--> statement-breakpoint
ALTER TABLE "tenants" ADD CONSTRAINT "tenants_slug_shape_check" CHECK ("tenants"."slug" ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$');--> statement-breakpoint
ALTER TABLE "tenants" ADD CONSTRAINT "tenants_name_shape_check" CHECK (btrim("tenants"."name") <> '' and char_length("tenants"."name") <= 160 and "tenants"."name" !~ '[[:cntrl:]]');--> statement-breakpoint
ALTER TABLE "tenants" ADD CONSTRAINT "tenants_timezone_shape_check" CHECK (char_length("tenants"."timezone") between 1 and 64 and "tenants"."timezone" !~ '[[:cntrl:]]');--> statement-breakpoint
ALTER TABLE "tenants" ADD CONSTRAINT "tenants_locale_shape_check" CHECK (char_length("tenants"."locale") <= 35
        and "tenants"."locale" ~ '^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$'
        and lower(split_part("tenants"."locale", '-', 1)) <> 'und');