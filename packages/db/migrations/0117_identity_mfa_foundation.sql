CREATE TABLE "auth_session_local_credential_provenance" (
	"tenant_id" uuid NOT NULL,
	"session_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"primary_kind" text DEFAULT 'local_credential' NOT NULL,
	"credential_id" uuid NOT NULL,
	"credential_revision" bigint NOT NULL,
	"authenticated_at" timestamp with time zone NOT NULL,
	CONSTRAINT "auth_session_local_credential_provenance_pkey" PRIMARY KEY("tenant_id","session_id"),
	CONSTRAINT "auth_session_local_credential_provenance_kind_check" CHECK ("auth_session_local_credential_provenance"."primary_kind" = 'local_credential'),
	CONSTRAINT "auth_session_local_credential_provenance_revision_check" CHECK ("auth_session_local_credential_provenance"."credential_revision" > 0)
);
--> statement-breakpoint
ALTER TABLE "auth_session_local_credential_provenance" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "auth_session_mfa_evidence" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"session_id" uuid NOT NULL,
	"local_credential_id" uuid,
	"totp_factor_id" uuid,
	"webauthn_credential_id" uuid,
	"recovery_code_set_id" uuid,
	"level" text NOT NULL,
	"kind" text NOT NULL,
	"provider_id" uuid,
	"binding_id" uuid,
	"authenticated_at" timestamp with time zone NOT NULL,
	"expires_at" timestamp with time zone,
	"factor_revision" bigint,
	"trust_rule_revision" bigint,
	CONSTRAINT "auth_session_mfa_evidence_session_id_key" UNIQUE("tenant_id","session_id","id"),
	CONSTRAINT "auth_session_mfa_evidence_id_uuidv7_check" CHECK ((uuid_extract_version("auth_session_mfa_evidence"."id") = 7) is true),
	CONSTRAINT "auth_session_mfa_evidence_typed_source_check" CHECK ("auth_session_mfa_evidence"."level" in ('primary', 'mfa', 'phishing_resistant')
        and (("auth_session_mfa_evidence"."kind" = 'local_credential'
          and "auth_session_mfa_evidence"."level" = 'primary'
          and "auth_session_mfa_evidence"."local_credential_id" is not null
          and "auth_session_mfa_evidence"."totp_factor_id" is null
          and "auth_session_mfa_evidence"."webauthn_credential_id" is null
          and "auth_session_mfa_evidence"."recovery_code_set_id" is null
          and "auth_session_mfa_evidence"."provider_id" is null
          and "auth_session_mfa_evidence"."binding_id" is null
          and "auth_session_mfa_evidence"."factor_revision" > 0
          and "auth_session_mfa_evidence"."trust_rule_revision" is null)
        or ("auth_session_mfa_evidence"."kind" = 'totp'
          and "auth_session_mfa_evidence"."level" = 'mfa'
          and "auth_session_mfa_evidence"."local_credential_id" is null
          and "auth_session_mfa_evidence"."totp_factor_id" is not null
          and "auth_session_mfa_evidence"."webauthn_credential_id" is null
          and "auth_session_mfa_evidence"."recovery_code_set_id" is null
          and "auth_session_mfa_evidence"."provider_id" is null
          and "auth_session_mfa_evidence"."binding_id" is null
          and "auth_session_mfa_evidence"."factor_revision" > 0
          and "auth_session_mfa_evidence"."trust_rule_revision" is null)
        or ("auth_session_mfa_evidence"."kind" = 'webauthn'
          and "auth_session_mfa_evidence"."local_credential_id" is null
          and "auth_session_mfa_evidence"."totp_factor_id" is null
          and "auth_session_mfa_evidence"."webauthn_credential_id" is not null
          and "auth_session_mfa_evidence"."recovery_code_set_id" is null
          and "auth_session_mfa_evidence"."provider_id" is null
          and "auth_session_mfa_evidence"."binding_id" is null
          and "auth_session_mfa_evidence"."factor_revision" > 0
          and "auth_session_mfa_evidence"."trust_rule_revision" is null)
        or ("auth_session_mfa_evidence"."kind" = 'recovery'
          and "auth_session_mfa_evidence"."level" = 'mfa'
          and "auth_session_mfa_evidence"."local_credential_id" is null
          and "auth_session_mfa_evidence"."totp_factor_id" is null
          and "auth_session_mfa_evidence"."webauthn_credential_id" is null
          and "auth_session_mfa_evidence"."recovery_code_set_id" is not null
          and "auth_session_mfa_evidence"."provider_id" is null
          and "auth_session_mfa_evidence"."binding_id" is null
          and "auth_session_mfa_evidence"."factor_revision" > 0
          and "auth_session_mfa_evidence"."trust_rule_revision" is null)
        or ("auth_session_mfa_evidence"."kind" = 'provider'
          and "auth_session_mfa_evidence"."local_credential_id" is null
          and "auth_session_mfa_evidence"."totp_factor_id" is null
          and "auth_session_mfa_evidence"."webauthn_credential_id" is null
          and "auth_session_mfa_evidence"."recovery_code_set_id" is null
          and "auth_session_mfa_evidence"."provider_id" is not null
          and "auth_session_mfa_evidence"."binding_id" is not null
          and "auth_session_mfa_evidence"."factor_revision" is null
          and "auth_session_mfa_evidence"."trust_rule_revision" > 0))),
	CONSTRAINT "auth_session_mfa_evidence_expiry_check" CHECK ("auth_session_mfa_evidence"."expires_at" is null or "auth_session_mfa_evidence"."expires_at" > "auth_session_mfa_evidence"."authenticated_at")
);
--> statement-breakpoint
ALTER TABLE "auth_session_mfa_evidence" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "auth_session_mfa_policy_pins" (
	"tenant_id" uuid NOT NULL,
	"session_id" uuid NOT NULL,
	"policy_id" uuid NOT NULL,
	"policy_revision" bigint NOT NULL,
	CONSTRAINT "auth_session_mfa_policy_pins_pkey" PRIMARY KEY("tenant_id","session_id","policy_id"),
	CONSTRAINT "auth_session_mfa_policy_pins_revision_check" CHECK ("auth_session_mfa_policy_pins"."policy_revision" > 0)
);
--> statement-breakpoint
ALTER TABLE "auth_session_mfa_policy_pins" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "auth_session_mfa_states" (
	"session_id" uuid PRIMARY KEY NOT NULL,
	"tenant_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"session_version" bigint NOT NULL,
	"identity_epoch" bigint NOT NULL,
	"recovery_restricted" boolean NOT NULL,
	"audience" text NOT NULL,
	"primary_kind" text NOT NULL,
	"session_invalidation_epoch" bigint NOT NULL,
	"issued_at" timestamp with time zone NOT NULL,
	CONSTRAINT "auth_session_mfa_states_tenant_session_key" UNIQUE("tenant_id","session_id"),
	CONSTRAINT "auth_session_mfa_states_primary_subject_key" UNIQUE("tenant_id","session_id","primary_kind","user_id"),
	CONSTRAINT "auth_session_mfa_states_version_check" CHECK ("auth_session_mfa_states"."session_version" > 0
        and "auth_session_mfa_states"."identity_epoch" > 0
        and "auth_session_mfa_states"."session_invalidation_epoch" > 0),
	CONSTRAINT "auth_session_mfa_states_audience_check" CHECK (btrim("auth_session_mfa_states"."audience") = "auth_session_mfa_states"."audience"
        and char_length("auth_session_mfa_states"."audience") between 1 and 256
        and "auth_session_mfa_states"."audience" !~ '[[:cntrl:]]'),
	CONSTRAINT "auth_session_mfa_states_primary_kind_check" CHECK ("auth_session_mfa_states"."primary_kind" in ('local_credential', 'passkey'))
);
--> statement-breakpoint
ALTER TABLE "auth_session_mfa_states" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "auth_session_passkey_provenance" (
	"tenant_id" uuid NOT NULL,
	"session_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"primary_kind" text DEFAULT 'passkey' NOT NULL,
	"credential_id" uuid NOT NULL,
	"credential_revision" bigint NOT NULL,
	"authenticated_at" timestamp with time zone NOT NULL,
	CONSTRAINT "auth_session_passkey_provenance_pkey" PRIMARY KEY("tenant_id","session_id"),
	CONSTRAINT "auth_session_passkey_provenance_kind_check" CHECK ("auth_session_passkey_provenance"."primary_kind" = 'passkey'),
	CONSTRAINT "auth_session_passkey_provenance_revision_check" CHECK ("auth_session_passkey_provenance"."credential_revision" > 0)
);
--> statement-breakpoint
ALTER TABLE "auth_session_passkey_provenance" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "mfa_policy_revisions" (
	"id" uuid NOT NULL,
	"revision" bigint NOT NULL,
	"tenant_id" uuid,
	"scope" text NOT NULL,
	"role_id" uuid,
	"security_group_id" uuid,
	"action" text,
	"level" text NOT NULL,
	"local_required" boolean DEFAULT false NOT NULL,
	"freshness_nanoseconds" bigint DEFAULT 0 NOT NULL,
	"enrollment_deadline" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"retired_at" timestamp with time zone,
	CONSTRAINT "mfa_policy_revisions_pkey" PRIMARY KEY("id","revision"),
	CONSTRAINT "mfa_policy_revisions_tenant_id_key" UNIQUE("tenant_id","id","revision"),
	CONSTRAINT "mfa_policy_revisions_id_uuidv7_check" CHECK ((uuid_extract_version("mfa_policy_revisions"."id") = 7) is true),
	CONSTRAINT "mfa_policy_revisions_revision_check" CHECK ("mfa_policy_revisions"."revision" > 0),
	CONSTRAINT "mfa_policy_revisions_scope_check" CHECK (("mfa_policy_revisions"."scope" = 'platform_floor'
          and "mfa_policy_revisions"."tenant_id" is null
          and "mfa_policy_revisions"."role_id" is null
          and "mfa_policy_revisions"."security_group_id" is null
          and "mfa_policy_revisions"."action" is null)
        or ("mfa_policy_revisions"."scope" = 'tenant_baseline'
          and "mfa_policy_revisions"."tenant_id" is not null
          and "mfa_policy_revisions"."role_id" is null
          and "mfa_policy_revisions"."security_group_id" is null
          and "mfa_policy_revisions"."action" is null)
        or ("mfa_policy_revisions"."scope" = 'role'
          and "mfa_policy_revisions"."tenant_id" is not null
          and "mfa_policy_revisions"."role_id" is not null
          and "mfa_policy_revisions"."security_group_id" is null
          and "mfa_policy_revisions"."action" is null)
        or ("mfa_policy_revisions"."scope" = 'security_group'
          and "mfa_policy_revisions"."tenant_id" is not null
          and "mfa_policy_revisions"."role_id" is null
          and "mfa_policy_revisions"."security_group_id" is not null
          and "mfa_policy_revisions"."action" is null)
        or ("mfa_policy_revisions"."scope" = 'action'
          and "mfa_policy_revisions"."tenant_id" is not null
          and "mfa_policy_revisions"."role_id" is null
          and "mfa_policy_revisions"."security_group_id" is null
          and "mfa_policy_revisions"."action" is not null
          and btrim("mfa_policy_revisions"."action") = "mfa_policy_revisions"."action"
          and char_length("mfa_policy_revisions"."action") between 1 and 256
          and "mfa_policy_revisions"."action" !~ '[[:cntrl:]]')),
	CONSTRAINT "mfa_policy_revisions_requirement_check" CHECK ("mfa_policy_revisions"."level" in ('primary', 'mfa', 'phishing_resistant')
        and "mfa_policy_revisions"."freshness_nanoseconds" between 0 and 31536000000000000
        and ("mfa_policy_revisions"."enrollment_deadline" is null
          or "mfa_policy_revisions"."enrollment_deadline" > "mfa_policy_revisions"."created_at")),
	CONSTRAINT "mfa_policy_revisions_retired_check" CHECK ("mfa_policy_revisions"."retired_at" is null or "mfa_policy_revisions"."retired_at" >= "mfa_policy_revisions"."created_at")
);
--> statement-breakpoint
ALTER TABLE "mfa_policy_revisions" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_mfa_authority_anchors" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"user_id" uuid,
	"flow" text NOT NULL,
	"identity_epoch" bigint,
	"session_id" uuid,
	"session_family_id" uuid,
	"continuation_id" uuid,
	"anchor_version" bigint,
	"anchor_expires_at" timestamp with time zone,
	"recovery_restricted" boolean DEFAULT false NOT NULL,
	"action" text NOT NULL,
	"audience" text NOT NULL,
	"requirement_level" text NOT NULL,
	"local_required" boolean DEFAULT false NOT NULL,
	"freshness_nanoseconds" bigint DEFAULT 0 NOT NULL,
	"enrollment_deadline" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_mfa_authority_anchors_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "tenant_mfa_authority_anchors_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_mfa_authority_anchors"."id") = 7) is true),
	CONSTRAINT "tenant_mfa_authority_anchors_user_epoch_check" CHECK (("tenant_mfa_authority_anchors"."user_id" is null and "tenant_mfa_authority_anchors"."identity_epoch" is null)
        or ("tenant_mfa_authority_anchors"."user_id" is not null and "tenant_mfa_authority_anchors"."identity_epoch" > 0)),
	CONSTRAINT "tenant_mfa_authority_anchors_flow_check" CHECK (("tenant_mfa_authority_anchors"."flow" = 'primary'
          and "tenant_mfa_authority_anchors"."session_id" is null
          and "tenant_mfa_authority_anchors"."session_family_id" is null
          and "tenant_mfa_authority_anchors"."continuation_id" is null
          and "tenant_mfa_authority_anchors"."anchor_version" is null
          and "tenant_mfa_authority_anchors"."anchor_expires_at" is null
          and not "tenant_mfa_authority_anchors"."recovery_restricted")
        or ("tenant_mfa_authority_anchors"."flow" = 'continuation'
          and "tenant_mfa_authority_anchors"."user_id" is not null
          and "tenant_mfa_authority_anchors"."session_id" is null
          and "tenant_mfa_authority_anchors"."session_family_id" is null
          and "tenant_mfa_authority_anchors"."continuation_id" is not null
          and "tenant_mfa_authority_anchors"."anchor_version" > 0
          and "tenant_mfa_authority_anchors"."anchor_expires_at" > "tenant_mfa_authority_anchors"."created_at"
          and not "tenant_mfa_authority_anchors"."recovery_restricted")
        or ("tenant_mfa_authority_anchors"."flow" = 'session'
          and "tenant_mfa_authority_anchors"."user_id" is not null
          and "tenant_mfa_authority_anchors"."session_id" is not null
          and "tenant_mfa_authority_anchors"."session_family_id" is not null
          and "tenant_mfa_authority_anchors"."continuation_id" is null
          and "tenant_mfa_authority_anchors"."anchor_version" > 0
          and "tenant_mfa_authority_anchors"."anchor_expires_at" > "tenant_mfa_authority_anchors"."created_at")),
	CONSTRAINT "tenant_mfa_authority_anchors_action_check" CHECK (btrim("tenant_mfa_authority_anchors"."action") = "tenant_mfa_authority_anchors"."action"
        and char_length("tenant_mfa_authority_anchors"."action") between 1 and 256
        and "tenant_mfa_authority_anchors"."action" !~ '[[:cntrl:]]'),
	CONSTRAINT "tenant_mfa_authority_anchors_audience_check" CHECK (btrim("tenant_mfa_authority_anchors"."audience") = "tenant_mfa_authority_anchors"."audience"
        and char_length("tenant_mfa_authority_anchors"."audience") between 1 and 256
        and "tenant_mfa_authority_anchors"."audience" !~ '[[:cntrl:]]'),
	CONSTRAINT "tenant_mfa_authority_anchors_requirement_check" CHECK ("tenant_mfa_authority_anchors"."requirement_level" in ('primary', 'mfa', 'phishing_resistant')
        and "tenant_mfa_authority_anchors"."freshness_nanoseconds" between 0 and 31536000000000000
        and ("tenant_mfa_authority_anchors"."enrollment_deadline" is null
          or "tenant_mfa_authority_anchors"."enrollment_deadline" > "tenant_mfa_authority_anchors"."created_at"))
);
--> statement-breakpoint
ALTER TABLE "tenant_mfa_authority_anchors" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_mfa_authority_evidence" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"anchor_id" uuid NOT NULL,
	"local_credential_id" uuid,
	"totp_factor_id" uuid,
	"webauthn_credential_id" uuid,
	"recovery_code_set_id" uuid,
	"level" text NOT NULL,
	"kind" text NOT NULL,
	"provider_id" uuid,
	"binding_id" uuid,
	"authenticated_at" timestamp with time zone NOT NULL,
	"expires_at" timestamp with time zone,
	"factor_revision" bigint,
	"trust_rule_revision" bigint,
	CONSTRAINT "tenant_mfa_authority_evidence_anchor_id_key" UNIQUE("tenant_id","anchor_id","id"),
	CONSTRAINT "tenant_mfa_authority_evidence_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_mfa_authority_evidence"."id") = 7) is true),
	CONSTRAINT "tenant_mfa_authority_evidence_level_kind_check" CHECK ("tenant_mfa_authority_evidence"."level" in ('primary', 'mfa', 'phishing_resistant')
        and (("tenant_mfa_authority_evidence"."kind" = 'local_credential'
          and "tenant_mfa_authority_evidence"."level" = 'primary'
          and "tenant_mfa_authority_evidence"."local_credential_id" is not null
          and "tenant_mfa_authority_evidence"."totp_factor_id" is null
          and "tenant_mfa_authority_evidence"."webauthn_credential_id" is null
          and "tenant_mfa_authority_evidence"."recovery_code_set_id" is null
          and "tenant_mfa_authority_evidence"."provider_id" is null
          and "tenant_mfa_authority_evidence"."binding_id" is null
          and "tenant_mfa_authority_evidence"."factor_revision" > 0
          and "tenant_mfa_authority_evidence"."trust_rule_revision" is null)
        or ("tenant_mfa_authority_evidence"."kind" = 'totp'
          and "tenant_mfa_authority_evidence"."level" = 'mfa'
          and "tenant_mfa_authority_evidence"."local_credential_id" is null
          and "tenant_mfa_authority_evidence"."totp_factor_id" is not null
          and "tenant_mfa_authority_evidence"."webauthn_credential_id" is null
          and "tenant_mfa_authority_evidence"."recovery_code_set_id" is null
          and "tenant_mfa_authority_evidence"."provider_id" is null
          and "tenant_mfa_authority_evidence"."binding_id" is null
          and "tenant_mfa_authority_evidence"."factor_revision" > 0
          and "tenant_mfa_authority_evidence"."trust_rule_revision" is null)
        or ("tenant_mfa_authority_evidence"."kind" = 'webauthn'
          and "tenant_mfa_authority_evidence"."local_credential_id" is null
          and "tenant_mfa_authority_evidence"."totp_factor_id" is null
          and "tenant_mfa_authority_evidence"."webauthn_credential_id" is not null
          and "tenant_mfa_authority_evidence"."recovery_code_set_id" is null
          and "tenant_mfa_authority_evidence"."provider_id" is null
          and "tenant_mfa_authority_evidence"."binding_id" is null
          and "tenant_mfa_authority_evidence"."factor_revision" > 0
          and "tenant_mfa_authority_evidence"."trust_rule_revision" is null)
        or ("tenant_mfa_authority_evidence"."kind" = 'recovery'
          and "tenant_mfa_authority_evidence"."level" = 'mfa'
          and "tenant_mfa_authority_evidence"."local_credential_id" is null
          and "tenant_mfa_authority_evidence"."totp_factor_id" is null
          and "tenant_mfa_authority_evidence"."webauthn_credential_id" is null
          and "tenant_mfa_authority_evidence"."recovery_code_set_id" is not null
          and "tenant_mfa_authority_evidence"."provider_id" is null
          and "tenant_mfa_authority_evidence"."binding_id" is null
          and "tenant_mfa_authority_evidence"."factor_revision" > 0
          and "tenant_mfa_authority_evidence"."trust_rule_revision" is null)
        or ("tenant_mfa_authority_evidence"."kind" = 'provider'
          and "tenant_mfa_authority_evidence"."local_credential_id" is null
          and "tenant_mfa_authority_evidence"."totp_factor_id" is null
          and "tenant_mfa_authority_evidence"."webauthn_credential_id" is null
          and "tenant_mfa_authority_evidence"."recovery_code_set_id" is null
          and "tenant_mfa_authority_evidence"."provider_id" is not null
          and "tenant_mfa_authority_evidence"."binding_id" is not null
          and "tenant_mfa_authority_evidence"."factor_revision" is null
          and "tenant_mfa_authority_evidence"."trust_rule_revision" > 0))),
	CONSTRAINT "tenant_mfa_authority_evidence_expiry_check" CHECK ("tenant_mfa_authority_evidence"."expires_at" is null or "tenant_mfa_authority_evidence"."expires_at" > "tenant_mfa_authority_evidence"."authenticated_at")
);
--> statement-breakpoint
ALTER TABLE "tenant_mfa_authority_evidence" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_mfa_authority_policy_pins" (
	"tenant_id" uuid NOT NULL,
	"anchor_id" uuid NOT NULL,
	"policy_id" uuid NOT NULL,
	"policy_revision" bigint NOT NULL,
	"scope" text NOT NULL,
	"role_id" uuid,
	"security_group_id" uuid,
	"action" text,
	CONSTRAINT "tenant_mfa_authority_policy_pins_pkey" PRIMARY KEY("tenant_id","anchor_id","scope","policy_id"),
	CONSTRAINT "tenant_mfa_authority_policy_pins_revision_check" CHECK ("tenant_mfa_authority_policy_pins"."policy_revision" > 0),
	CONSTRAINT "tenant_mfa_authority_policy_pins_scope_check" CHECK (("tenant_mfa_authority_policy_pins"."scope" in ('platform_floor', 'tenant_baseline')
          and "tenant_mfa_authority_policy_pins"."role_id" is null
          and "tenant_mfa_authority_policy_pins"."security_group_id" is null
          and "tenant_mfa_authority_policy_pins"."action" is null)
        or ("tenant_mfa_authority_policy_pins"."scope" = 'role'
          and "tenant_mfa_authority_policy_pins"."role_id" is not null
          and "tenant_mfa_authority_policy_pins"."security_group_id" is null
          and "tenant_mfa_authority_policy_pins"."action" is null)
        or ("tenant_mfa_authority_policy_pins"."scope" = 'security_group'
          and "tenant_mfa_authority_policy_pins"."role_id" is null
          and "tenant_mfa_authority_policy_pins"."security_group_id" is not null
          and "tenant_mfa_authority_policy_pins"."action" is null)
        or ("tenant_mfa_authority_policy_pins"."scope" = 'action'
          and "tenant_mfa_authority_policy_pins"."role_id" is null
          and "tenant_mfa_authority_policy_pins"."security_group_id" is null
          and "tenant_mfa_authority_policy_pins"."action" is not null
          and btrim("tenant_mfa_authority_policy_pins"."action") = "tenant_mfa_authority_policy_pins"."action"
          and char_length("tenant_mfa_authority_policy_pins"."action") between 1 and 256
          and "tenant_mfa_authority_policy_pins"."action" !~ '[[:cntrl:]]'))
);
--> statement-breakpoint
ALTER TABLE "tenant_mfa_authority_policy_pins" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_mfa_step_up_challenges" (
	"id" "bytea" PRIMARY KEY NOT NULL,
	"tenant_id" uuid NOT NULL,
	"authority_anchor_id" uuid NOT NULL,
	"browser_digest" "bytea" NOT NULL,
	"allowed_factors" text[] NOT NULL,
	"state" text DEFAULT 'pending' NOT NULL,
	"failure_reason" text,
	"completion_request_digest" "bytea",
	"result_snapshot" jsonb,
	"version" bigint DEFAULT 1 NOT NULL,
	"created_at" timestamp with time zone NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"claimed_at" timestamp with time zone,
	"completed_at" timestamp with time zone,
	"failed_at" timestamp with time zone,
	CONSTRAINT "tenant_mfa_step_up_challenges_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "tenant_mfa_step_up_challenges_id_check" CHECK (octet_length("tenant_mfa_step_up_challenges"."id") = 32),
	CONSTRAINT "tenant_mfa_step_up_challenges_browser_check" CHECK (octet_length("tenant_mfa_step_up_challenges"."browser_digest") = 32),
	CONSTRAINT "tenant_mfa_step_up_challenges_factors_check" CHECK ("tenant_mfa_step_up_challenges"."allowed_factors" = array['totp']::text[]
        or "tenant_mfa_step_up_challenges"."allowed_factors" = array['recovery_code']::text[]
        or "tenant_mfa_step_up_challenges"."allowed_factors" = array['totp', 'recovery_code']::text[]),
	CONSTRAINT "tenant_mfa_step_up_challenges_version_check" CHECK ("tenant_mfa_step_up_challenges"."version" > 0),
	CONSTRAINT "tenant_mfa_step_up_challenges_replay_check" CHECK (("tenant_mfa_step_up_challenges"."completion_request_digest" is null and "tenant_mfa_step_up_challenges"."result_snapshot" is null)
        or (octet_length("tenant_mfa_step_up_challenges"."completion_request_digest") = 32
          and jsonb_typeof("tenant_mfa_step_up_challenges"."result_snapshot") = 'object'
          and pg_column_size("tenant_mfa_step_up_challenges"."result_snapshot") between 2 and 2097152)),
	CONSTRAINT "tenant_mfa_step_up_challenges_lifecycle_check" CHECK ((("tenant_mfa_step_up_challenges"."state" = 'pending'
          and "tenant_mfa_step_up_challenges"."version" = 1
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
          and "tenant_mfa_step_up_challenges"."failure_reason" in ('factor_rejected', 'expired')
          and "tenant_mfa_step_up_challenges"."completion_request_digest" is null
          and "tenant_mfa_step_up_challenges"."result_snapshot" is null))),
	CONSTRAINT "tenant_mfa_step_up_challenges_timestamps_check" CHECK ("tenant_mfa_step_up_challenges"."expires_at" > "tenant_mfa_step_up_challenges"."created_at"
        and ("tenant_mfa_step_up_challenges"."claimed_at" is null or "tenant_mfa_step_up_challenges"."claimed_at" >= "tenant_mfa_step_up_challenges"."created_at")
        and ("tenant_mfa_step_up_challenges"."completed_at" is null or "tenant_mfa_step_up_challenges"."completed_at" >= "tenant_mfa_step_up_challenges"."claimed_at")
        and ("tenant_mfa_step_up_challenges"."failed_at" is null or "tenant_mfa_step_up_challenges"."failed_at" >= "tenant_mfa_step_up_challenges"."claimed_at"))
);
--> statement-breakpoint
ALTER TABLE "tenant_mfa_step_up_challenges" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_mfa_subjects" (
	"tenant_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"webauthn_user_handle" "bytea" NOT NULL,
	"identity_epoch" bigint DEFAULT 1 NOT NULL,
	"session_invalidation_epoch" bigint DEFAULT 1 NOT NULL,
	"version" bigint DEFAULT 1 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_mfa_subjects_pkey" PRIMARY KEY("tenant_id","user_id"),
	CONSTRAINT "tenant_mfa_subjects_user_handle_key" UNIQUE("webauthn_user_handle"),
	CONSTRAINT "tenant_mfa_subjects_user_handle_check" CHECK (octet_length("tenant_mfa_subjects"."webauthn_user_handle") = 32
        and encode("tenant_mfa_subjects"."webauthn_user_handle", 'hex') <> repeat('00', 32)),
	CONSTRAINT "tenant_mfa_subjects_epoch_check" CHECK ("tenant_mfa_subjects"."identity_epoch" > 0
        and "tenant_mfa_subjects"."session_invalidation_epoch" > 0
        and "tenant_mfa_subjects"."version" > 0),
	CONSTRAINT "tenant_mfa_subjects_updated_check" CHECK ("tenant_mfa_subjects"."updated_at" >= "tenant_mfa_subjects"."created_at")
);
--> statement-breakpoint
ALTER TABLE "tenant_mfa_subjects" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_post_primary_continuation_evidence" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"continuation_id" uuid NOT NULL,
	"local_credential_id" uuid,
	"totp_factor_id" uuid,
	"webauthn_credential_id" uuid,
	"recovery_code_set_id" uuid,
	"level" text NOT NULL,
	"kind" text NOT NULL,
	"provider_id" uuid,
	"binding_id" uuid,
	"authenticated_at" timestamp with time zone NOT NULL,
	"expires_at" timestamp with time zone,
	"factor_revision" bigint,
	"trust_rule_revision" bigint,
	CONSTRAINT "tenant_post_primary_continuation_evidence_key" UNIQUE("tenant_id","continuation_id","id"),
	CONSTRAINT "tenant_post_primary_continuation_evidence_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_post_primary_continuation_evidence"."id") = 7) is true),
	CONSTRAINT "tenant_post_primary_continuation_evidence_value_check" CHECK ("tenant_post_primary_continuation_evidence"."level" in ('primary', 'mfa', 'phishing_resistant')
        and (("tenant_post_primary_continuation_evidence"."kind" = 'local_credential'
            and "tenant_post_primary_continuation_evidence"."level" = 'primary'
            and "tenant_post_primary_continuation_evidence"."local_credential_id" is not null
            and "tenant_post_primary_continuation_evidence"."totp_factor_id" is null
            and "tenant_post_primary_continuation_evidence"."webauthn_credential_id" is null
            and "tenant_post_primary_continuation_evidence"."recovery_code_set_id" is null
            and "tenant_post_primary_continuation_evidence"."provider_id" is null
            and "tenant_post_primary_continuation_evidence"."binding_id" is null
            and "tenant_post_primary_continuation_evidence"."factor_revision" > 0
            and "tenant_post_primary_continuation_evidence"."trust_rule_revision" is null)
          or ("tenant_post_primary_continuation_evidence"."kind" = 'totp'
            and "tenant_post_primary_continuation_evidence"."level" = 'mfa'
            and "tenant_post_primary_continuation_evidence"."local_credential_id" is null
            and "tenant_post_primary_continuation_evidence"."totp_factor_id" is not null
            and "tenant_post_primary_continuation_evidence"."webauthn_credential_id" is null
            and "tenant_post_primary_continuation_evidence"."recovery_code_set_id" is null
            and "tenant_post_primary_continuation_evidence"."provider_id" is null
            and "tenant_post_primary_continuation_evidence"."binding_id" is null
            and "tenant_post_primary_continuation_evidence"."factor_revision" > 0
            and "tenant_post_primary_continuation_evidence"."trust_rule_revision" is null)
          or ("tenant_post_primary_continuation_evidence"."kind" = 'webauthn'
            and "tenant_post_primary_continuation_evidence"."local_credential_id" is null
            and "tenant_post_primary_continuation_evidence"."totp_factor_id" is null
            and "tenant_post_primary_continuation_evidence"."webauthn_credential_id" is not null
            and "tenant_post_primary_continuation_evidence"."recovery_code_set_id" is null
            and "tenant_post_primary_continuation_evidence"."provider_id" is null
            and "tenant_post_primary_continuation_evidence"."binding_id" is null
            and "tenant_post_primary_continuation_evidence"."factor_revision" > 0
            and "tenant_post_primary_continuation_evidence"."trust_rule_revision" is null)
          or ("tenant_post_primary_continuation_evidence"."kind" = 'recovery'
            and "tenant_post_primary_continuation_evidence"."level" = 'mfa'
            and "tenant_post_primary_continuation_evidence"."local_credential_id" is null
            and "tenant_post_primary_continuation_evidence"."totp_factor_id" is null
            and "tenant_post_primary_continuation_evidence"."webauthn_credential_id" is null
            and "tenant_post_primary_continuation_evidence"."recovery_code_set_id" is not null
            and "tenant_post_primary_continuation_evidence"."provider_id" is null
            and "tenant_post_primary_continuation_evidence"."binding_id" is null
            and "tenant_post_primary_continuation_evidence"."factor_revision" > 0
            and "tenant_post_primary_continuation_evidence"."trust_rule_revision" is null)
          or ("tenant_post_primary_continuation_evidence"."kind" = 'provider'
            and "tenant_post_primary_continuation_evidence"."local_credential_id" is null
            and "tenant_post_primary_continuation_evidence"."totp_factor_id" is null
            and "tenant_post_primary_continuation_evidence"."webauthn_credential_id" is null
            and "tenant_post_primary_continuation_evidence"."recovery_code_set_id" is null
            and "tenant_post_primary_continuation_evidence"."provider_id" is not null
            and "tenant_post_primary_continuation_evidence"."binding_id" is not null
            and "tenant_post_primary_continuation_evidence"."factor_revision" is null
            and "tenant_post_primary_continuation_evidence"."trust_rule_revision" > 0))),
	CONSTRAINT "tenant_post_primary_continuation_evidence_expiry_check" CHECK ("tenant_post_primary_continuation_evidence"."expires_at" is null or "tenant_post_primary_continuation_evidence"."expires_at" > "tenant_post_primary_continuation_evidence"."authenticated_at")
);
--> statement-breakpoint
ALTER TABLE "tenant_post_primary_continuation_evidence" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_post_primary_continuation_policy_pins" (
	"tenant_id" uuid NOT NULL,
	"continuation_id" uuid NOT NULL,
	"policy_id" uuid NOT NULL,
	"policy_revision" bigint NOT NULL,
	CONSTRAINT "tenant_post_primary_continuation_policy_pins_pkey" PRIMARY KEY("tenant_id","continuation_id","policy_id"),
	CONSTRAINT "tenant_post_primary_continuation_policy_pins_revision_check" CHECK ("tenant_post_primary_continuation_policy_pins"."policy_revision" > 0)
);
--> statement-breakpoint
ALTER TABLE "tenant_post_primary_continuation_policy_pins" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_post_primary_continuations" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"receipt_digest" "bytea" NOT NULL,
	"identity_epoch" bigint NOT NULL,
	"action" text NOT NULL,
	"audience" text NOT NULL,
	"primary_kind" text NOT NULL,
	"local_credential_id" uuid,
	"passkey_credential_id" uuid,
	"primary_revision" bigint NOT NULL,
	"session_invalidation_epoch" bigint NOT NULL,
	"state" text DEFAULT 'pending' NOT NULL,
	"version" bigint DEFAULT 1 NOT NULL,
	"created_at" timestamp with time zone NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"consumed_at" timestamp with time zone,
	"revoked_at" timestamp with time zone,
	"revoke_reason" text,
	CONSTRAINT "tenant_post_primary_continuations_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "tenant_post_primary_continuations_receipt_key" UNIQUE("receipt_digest"),
	CONSTRAINT "tenant_post_primary_continuations_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_post_primary_continuations"."id") = 7) is true),
	CONSTRAINT "tenant_post_primary_continuations_receipt_check" CHECK (octet_length("tenant_post_primary_continuations"."receipt_digest") = 32),
	CONSTRAINT "tenant_post_primary_continuations_version_check" CHECK ("tenant_post_primary_continuations"."identity_epoch" > 0
        and "tenant_post_primary_continuations"."primary_revision" > 0
        and "tenant_post_primary_continuations"."session_invalidation_epoch" > 0
        and "tenant_post_primary_continuations"."version" > 0),
	CONSTRAINT "tenant_post_primary_continuations_text_check" CHECK (btrim("tenant_post_primary_continuations"."action") = "tenant_post_primary_continuations"."action"
        and char_length("tenant_post_primary_continuations"."action") between 1 and 256
        and "tenant_post_primary_continuations"."action" !~ '[[:cntrl:]]'
        and btrim("tenant_post_primary_continuations"."audience") = "tenant_post_primary_continuations"."audience"
        and char_length("tenant_post_primary_continuations"."audience") between 1 and 256
        and "tenant_post_primary_continuations"."audience" !~ '[[:cntrl:]]'),
	CONSTRAINT "tenant_post_primary_continuations_primary_check" CHECK (("tenant_post_primary_continuations"."primary_kind" = 'local_credential'
          and "tenant_post_primary_continuations"."local_credential_id" is not null
          and "tenant_post_primary_continuations"."passkey_credential_id" is null)
        or ("tenant_post_primary_continuations"."primary_kind" = 'passkey'
          and "tenant_post_primary_continuations"."local_credential_id" is null
          and "tenant_post_primary_continuations"."passkey_credential_id" is not null)),
	CONSTRAINT "tenant_post_primary_continuations_lifecycle_check" CHECK ((("tenant_post_primary_continuations"."state" = 'pending'
          and "tenant_post_primary_continuations"."version" = 1
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
          and "tenant_post_primary_continuations"."revoke_reason" !~ '[[:cntrl:]]'))),
	CONSTRAINT "tenant_post_primary_continuations_timestamps_check" CHECK ("tenant_post_primary_continuations"."expires_at" > "tenant_post_primary_continuations"."created_at"
        and ("tenant_post_primary_continuations"."consumed_at" is null
          or "tenant_post_primary_continuations"."consumed_at" between "tenant_post_primary_continuations"."created_at" and "tenant_post_primary_continuations"."expires_at")
        and ("tenant_post_primary_continuations"."revoked_at" is null or "tenant_post_primary_continuations"."revoked_at" >= "tenant_post_primary_continuations"."created_at"))
);
--> statement-breakpoint
ALTER TABLE "tenant_post_primary_continuations" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_recovery_code_sets" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"digest_key_version" integer NOT NULL,
	"record_version" bigint DEFAULT 1 NOT NULL,
	"security_revision" bigint DEFAULT 1 NOT NULL,
	"completion_request_digest" "bytea" NOT NULL,
	"result_snapshot" jsonb NOT NULL,
	"status" text DEFAULT 'active' NOT NULL,
	"generated_at" timestamp with time zone NOT NULL,
	"revoked_at" timestamp with time zone,
	"revoke_reason" text,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_recovery_code_sets_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "tenant_recovery_code_sets_tenant_user_id_key" UNIQUE("tenant_id","user_id","id"),
	CONSTRAINT "tenant_recovery_code_sets_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_recovery_code_sets"."id") = 7) is true),
	CONSTRAINT "tenant_recovery_code_sets_revision_check" CHECK ("tenant_recovery_code_sets"."digest_key_version" between 1 and 32767
        and "tenant_recovery_code_sets"."record_version" > 0
        and "tenant_recovery_code_sets"."security_revision" > 0),
	CONSTRAINT "tenant_recovery_code_sets_replay_check" CHECK (octet_length("tenant_recovery_code_sets"."completion_request_digest") = 32
        and jsonb_typeof("tenant_recovery_code_sets"."result_snapshot") = 'object'
        and pg_column_size("tenant_recovery_code_sets"."result_snapshot") between 2 and 2097152),
	CONSTRAINT "tenant_recovery_code_sets_lifecycle_check" CHECK (("tenant_recovery_code_sets"."status" = 'active'
          and "tenant_recovery_code_sets"."revoked_at" is null
          and "tenant_recovery_code_sets"."revoke_reason" is null)
        or ("tenant_recovery_code_sets"."status" = 'revoked'
          and "tenant_recovery_code_sets"."revoked_at" is not null
          and "tenant_recovery_code_sets"."revoke_reason" is not null
          and "tenant_recovery_code_sets"."revoked_at" >= "tenant_recovery_code_sets"."generated_at"
          and btrim("tenant_recovery_code_sets"."revoke_reason") <> ''
          and char_length("tenant_recovery_code_sets"."revoke_reason") <= 500
          and "tenant_recovery_code_sets"."revoke_reason" !~ '[[:cntrl:]]')),
	CONSTRAINT "tenant_recovery_code_sets_updated_check" CHECK ("tenant_recovery_code_sets"."updated_at" >= "tenant_recovery_code_sets"."generated_at"
        and ("tenant_recovery_code_sets"."revoked_at" is null or "tenant_recovery_code_sets"."updated_at" >= "tenant_recovery_code_sets"."revoked_at"))
);
--> statement-breakpoint
ALTER TABLE "tenant_recovery_code_sets" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_recovery_codes" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"set_id" uuid NOT NULL,
	"code_digest" "bytea" NOT NULL,
	"consumed_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_recovery_codes_set_digest_key" UNIQUE("tenant_id","set_id","code_digest"),
	CONSTRAINT "tenant_recovery_codes_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_recovery_codes"."id") = 7) is true),
	CONSTRAINT "tenant_recovery_codes_digest_check" CHECK (octet_length("tenant_recovery_codes"."code_digest") = 32),
	CONSTRAINT "tenant_recovery_codes_consumed_check" CHECK ("tenant_recovery_codes"."consumed_at" is null or "tenant_recovery_codes"."consumed_at" >= "tenant_recovery_codes"."created_at")
);
--> statement-breakpoint
ALTER TABLE "tenant_recovery_codes" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_totp_enrollments" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"authority_anchor_id" uuid NOT NULL,
	"factor_id" uuid NOT NULL,
	"browser_digest" "bytea" NOT NULL,
	"secret_envelope" "bytea" NOT NULL,
	"key_version" integer NOT NULL,
	"state" text DEFAULT 'pending' NOT NULL,
	"completion_request_digest" "bytea",
	"result_snapshot" jsonb,
	"version" bigint DEFAULT 1 NOT NULL,
	"created_at" timestamp with time zone NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"claimed_at" timestamp with time zone,
	"completed_at" timestamp with time zone,
	"failed_at" timestamp with time zone,
	CONSTRAINT "tenant_totp_enrollments_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "tenant_totp_enrollments_factor_key" UNIQUE("tenant_id","factor_id"),
	CONSTRAINT "tenant_totp_enrollments_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_totp_enrollments"."id") = 7) is true),
	CONSTRAINT "tenant_totp_enrollments_factor_uuidv7_check" CHECK ((uuid_extract_version("tenant_totp_enrollments"."factor_id") = 7) is true),
	CONSTRAINT "tenant_totp_enrollments_material_check" CHECK (octet_length("tenant_totp_enrollments"."browser_digest") = 32
        and octet_length("tenant_totp_enrollments"."secret_envelope") between 17 and 16384
        and "tenant_totp_enrollments"."key_version" between 1 and 32767),
	CONSTRAINT "tenant_totp_enrollments_replay_check" CHECK (("tenant_totp_enrollments"."completion_request_digest" is null and "tenant_totp_enrollments"."result_snapshot" is null)
        or (octet_length("tenant_totp_enrollments"."completion_request_digest") = 32
          and jsonb_typeof("tenant_totp_enrollments"."result_snapshot") = 'object'
          and pg_column_size("tenant_totp_enrollments"."result_snapshot") between 2 and 2097152)),
	CONSTRAINT "tenant_totp_enrollments_lifecycle_check" CHECK ((("tenant_totp_enrollments"."state" = 'pending'
          and "tenant_totp_enrollments"."version" = 1
          and "tenant_totp_enrollments"."claimed_at" is null
          and "tenant_totp_enrollments"."completed_at" is null
          and "tenant_totp_enrollments"."failed_at" is null
          and "tenant_totp_enrollments"."completion_request_digest" is null
          and "tenant_totp_enrollments"."result_snapshot" is null)
        or ("tenant_totp_enrollments"."state" = 'claimed'
          and "tenant_totp_enrollments"."version" >= 2
          and "tenant_totp_enrollments"."claimed_at" is not null
          and "tenant_totp_enrollments"."completed_at" is null
          and "tenant_totp_enrollments"."failed_at" is null
          and "tenant_totp_enrollments"."completion_request_digest" is null
          and "tenant_totp_enrollments"."result_snapshot" is null)
        or ("tenant_totp_enrollments"."state" = 'completed'
          and "tenant_totp_enrollments"."version" >= 3
          and "tenant_totp_enrollments"."claimed_at" is not null
          and "tenant_totp_enrollments"."completed_at" is not null
          and "tenant_totp_enrollments"."failed_at" is null
          and "tenant_totp_enrollments"."completion_request_digest" is not null
          and "tenant_totp_enrollments"."result_snapshot" is not null)
        or ("tenant_totp_enrollments"."state" = 'failed'
          and "tenant_totp_enrollments"."version" >= 3
          and "tenant_totp_enrollments"."claimed_at" is not null
          and "tenant_totp_enrollments"."completed_at" is null
          and "tenant_totp_enrollments"."failed_at" is not null
          and "tenant_totp_enrollments"."completion_request_digest" is null
          and "tenant_totp_enrollments"."result_snapshot" is null))),
	CONSTRAINT "tenant_totp_enrollments_timestamps_check" CHECK ("tenant_totp_enrollments"."expires_at" > "tenant_totp_enrollments"."created_at"
        and ("tenant_totp_enrollments"."claimed_at" is null or "tenant_totp_enrollments"."claimed_at" >= "tenant_totp_enrollments"."created_at")
        and ("tenant_totp_enrollments"."completed_at" is null or "tenant_totp_enrollments"."completed_at" >= "tenant_totp_enrollments"."claimed_at")
        and ("tenant_totp_enrollments"."failed_at" is null or "tenant_totp_enrollments"."failed_at" >= "tenant_totp_enrollments"."claimed_at"))
);
--> statement-breakpoint
ALTER TABLE "tenant_totp_enrollments" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_totp_factors" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"secret_envelope" "bytea" NOT NULL,
	"key_version" integer NOT NULL,
	"otp_algorithm" text DEFAULT 'SHA1' NOT NULL,
	"digits" integer DEFAULT 6 NOT NULL,
	"period_seconds" integer DEFAULT 30 NOT NULL,
	"last_accepted_counter" bigint DEFAULT -1 NOT NULL,
	"record_version" bigint DEFAULT 1 NOT NULL,
	"security_revision" bigint DEFAULT 1 NOT NULL,
	"status" text DEFAULT 'active' NOT NULL,
	"confirmed_at" timestamp with time zone NOT NULL,
	"revoked_at" timestamp with time zone,
	"revoke_reason" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_totp_factors_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "tenant_totp_factors_tenant_user_id_key" UNIQUE("tenant_id","user_id","id"),
	CONSTRAINT "tenant_totp_factors_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_totp_factors"."id") = 7) is true),
	CONSTRAINT "tenant_totp_factors_envelope_check" CHECK (octet_length("tenant_totp_factors"."secret_envelope") between 17 and 16384),
	CONSTRAINT "tenant_totp_factors_key_version_check" CHECK ("tenant_totp_factors"."key_version" between 1 and 32767),
	CONSTRAINT "tenant_totp_factors_parameters_check" CHECK ("tenant_totp_factors"."otp_algorithm" in ('SHA1', 'SHA256', 'SHA512')
        and "tenant_totp_factors"."digits" in (6, 8)
        and "tenant_totp_factors"."period_seconds" between 15 and 120),
	CONSTRAINT "tenant_totp_factors_revision_check" CHECK ("tenant_totp_factors"."last_accepted_counter" >= -1
        and "tenant_totp_factors"."record_version" > 0
        and "tenant_totp_factors"."security_revision" > 0),
	CONSTRAINT "tenant_totp_factors_lifecycle_check" CHECK (("tenant_totp_factors"."status" = 'active'
          and "tenant_totp_factors"."revoked_at" is null
          and "tenant_totp_factors"."revoke_reason" is null)
        or ("tenant_totp_factors"."status" = 'revoked'
          and "tenant_totp_factors"."revoked_at" is not null
          and "tenant_totp_factors"."revoke_reason" is not null
          and "tenant_totp_factors"."revoked_at" >= "tenant_totp_factors"."confirmed_at"
          and btrim("tenant_totp_factors"."revoke_reason") <> ''
          and char_length("tenant_totp_factors"."revoke_reason") <= 500
          and "tenant_totp_factors"."revoke_reason" !~ '[[:cntrl:]]')),
	CONSTRAINT "tenant_totp_factors_timestamps_check" CHECK ("tenant_totp_factors"."confirmed_at" >= "tenant_totp_factors"."created_at"
        and "tenant_totp_factors"."updated_at" >= "tenant_totp_factors"."created_at"
        and ("tenant_totp_factors"."revoked_at" is null or "tenant_totp_factors"."updated_at" >= "tenant_totp_factors"."revoked_at"))
);
--> statement-breakpoint
ALTER TABLE "tenant_totp_factors" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_webauthn_ceremonies" (
	"id" "bytea" PRIMARY KEY NOT NULL,
	"tenant_id" uuid NOT NULL,
	"authority_anchor_id" uuid NOT NULL,
	"challenge_digest" "bytea" NOT NULL,
	"browser_digest" "bytea" NOT NULL,
	"rp_id" text NOT NULL,
	"rp_revision" bigint NOT NULL,
	"allowed_origins" text[] NOT NULL,
	"purpose" text NOT NULL,
	"mode" text,
	"user_handle_digest" "bytea",
	"require_user_presence" boolean NOT NULL,
	"user_verification" text NOT NULL,
	"resident_key" text NOT NULL,
	"attestation" text NOT NULL,
	"metadata_revision" bigint DEFAULT 0 NOT NULL,
	"state" text DEFAULT 'pending' NOT NULL,
	"failure_reason" text,
	"completion_request_digest" "bytea",
	"result_snapshot" jsonb,
	"version" bigint DEFAULT 1 NOT NULL,
	"created_at" timestamp with time zone NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"claimed_at" timestamp with time zone,
	"completed_at" timestamp with time zone,
	"failed_at" timestamp with time zone,
	CONSTRAINT "tenant_webauthn_ceremonies_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "tenant_webauthn_ceremonies_artifact_check" CHECK (octet_length("tenant_webauthn_ceremonies"."id") = 32
        and octet_length("tenant_webauthn_ceremonies"."challenge_digest") = 32
        and octet_length("tenant_webauthn_ceremonies"."browser_digest") = 32
        and ("tenant_webauthn_ceremonies"."user_handle_digest" is null
          or octet_length("tenant_webauthn_ceremonies"."user_handle_digest") = 32)),
	CONSTRAINT "tenant_webauthn_ceremonies_rp_check" CHECK (btrim("tenant_webauthn_ceremonies"."rp_id") = "tenant_webauthn_ceremonies"."rp_id"
        and char_length("tenant_webauthn_ceremonies"."rp_id") between 1 and 253
        and "tenant_webauthn_ceremonies"."rp_revision" > 0
        and cardinality("tenant_webauthn_ceremonies"."allowed_origins") between 1 and 16),
	CONSTRAINT "tenant_webauthn_ceremonies_purpose_check" CHECK (("tenant_webauthn_ceremonies"."purpose" = 'registration'
          and "tenant_webauthn_ceremonies"."mode" is null
          and "tenant_webauthn_ceremonies"."user_handle_digest" is not null)
        or ("tenant_webauthn_ceremonies"."purpose" in ('primary_authentication', 'continuation_authentication', 'step_up_authentication')
          and "tenant_webauthn_ceremonies"."mode" in ('known_user', 'discoverable')
          and ("tenant_webauthn_ceremonies"."mode" = 'discoverable' or "tenant_webauthn_ceremonies"."user_handle_digest" is not null))),
	CONSTRAINT "tenant_webauthn_ceremonies_policy_check" CHECK ("tenant_webauthn_ceremonies"."require_user_presence"
        and "tenant_webauthn_ceremonies"."user_verification" in ('preferred', 'required')
        and "tenant_webauthn_ceremonies"."resident_key" in ('preferred', 'required')
        and "tenant_webauthn_ceremonies"."attestation" in ('none', 'direct', 'enterprise')
        and (("tenant_webauthn_ceremonies"."attestation" = 'none' and "tenant_webauthn_ceremonies"."metadata_revision" = 0)
          or ("tenant_webauthn_ceremonies"."attestation" <> 'none' and "tenant_webauthn_ceremonies"."metadata_revision" > 0))),
	CONSTRAINT "tenant_webauthn_ceremonies_replay_check" CHECK (("tenant_webauthn_ceremonies"."completion_request_digest" is null and "tenant_webauthn_ceremonies"."result_snapshot" is null)
        or (octet_length("tenant_webauthn_ceremonies"."completion_request_digest") = 32
          and jsonb_typeof("tenant_webauthn_ceremonies"."result_snapshot") = 'object'
          and pg_column_size("tenant_webauthn_ceremonies"."result_snapshot") between 2 and 2097152)),
	CONSTRAINT "tenant_webauthn_ceremonies_lifecycle_check" CHECK ((("tenant_webauthn_ceremonies"."state" = 'pending'
          and "tenant_webauthn_ceremonies"."version" = 1
          and "tenant_webauthn_ceremonies"."claimed_at" is null
          and "tenant_webauthn_ceremonies"."completed_at" is null
          and "tenant_webauthn_ceremonies"."failed_at" is null
          and "tenant_webauthn_ceremonies"."failure_reason" is null
          and "tenant_webauthn_ceremonies"."completion_request_digest" is null
          and "tenant_webauthn_ceremonies"."result_snapshot" is null)
        or ("tenant_webauthn_ceremonies"."state" = 'claimed'
          and "tenant_webauthn_ceremonies"."version" >= 2
          and "tenant_webauthn_ceremonies"."claimed_at" is not null
          and "tenant_webauthn_ceremonies"."completed_at" is null
          and "tenant_webauthn_ceremonies"."failed_at" is null
          and "tenant_webauthn_ceremonies"."failure_reason" is null
          and "tenant_webauthn_ceremonies"."completion_request_digest" is null
          and "tenant_webauthn_ceremonies"."result_snapshot" is null)
        or ("tenant_webauthn_ceremonies"."state" = 'completed'
          and "tenant_webauthn_ceremonies"."version" >= 3
          and "tenant_webauthn_ceremonies"."claimed_at" is not null
          and "tenant_webauthn_ceremonies"."completed_at" is not null
          and "tenant_webauthn_ceremonies"."failed_at" is null
          and "tenant_webauthn_ceremonies"."failure_reason" is null
          and "tenant_webauthn_ceremonies"."completion_request_digest" is not null
          and "tenant_webauthn_ceremonies"."result_snapshot" is not null)
        or ("tenant_webauthn_ceremonies"."state" in ('failed', 'expired')
          and "tenant_webauthn_ceremonies"."version" >= 3
          and "tenant_webauthn_ceremonies"."claimed_at" is not null
          and "tenant_webauthn_ceremonies"."completed_at" is null
          and "tenant_webauthn_ceremonies"."failed_at" is not null
          and "tenant_webauthn_ceremonies"."failure_reason" in ('expired', 'malformed_response', 'verification_rejected', 'credential_rejected')
          and "tenant_webauthn_ceremonies"."completion_request_digest" is null
          and "tenant_webauthn_ceremonies"."result_snapshot" is null))),
	CONSTRAINT "tenant_webauthn_ceremonies_timestamps_check" CHECK ("tenant_webauthn_ceremonies"."version" > 0
        and "tenant_webauthn_ceremonies"."expires_at" > "tenant_webauthn_ceremonies"."created_at"
        and ("tenant_webauthn_ceremonies"."claimed_at" is null or "tenant_webauthn_ceremonies"."claimed_at" >= "tenant_webauthn_ceremonies"."created_at")
        and ("tenant_webauthn_ceremonies"."completed_at" is null or "tenant_webauthn_ceremonies"."completed_at" >= "tenant_webauthn_ceremonies"."claimed_at")
        and ("tenant_webauthn_ceremonies"."failed_at" is null or "tenant_webauthn_ceremonies"."failed_at" >= "tenant_webauthn_ceremonies"."claimed_at"))
);
--> statement-breakpoint
ALTER TABLE "tenant_webauthn_ceremonies" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_webauthn_ceremony_credentials" (
	"tenant_id" uuid NOT NULL,
	"ceremony_id" "bytea" NOT NULL,
	"ordinal" integer NOT NULL,
	"credential_id" "bytea" NOT NULL,
	CONSTRAINT "tenant_webauthn_ceremony_credentials_pkey" PRIMARY KEY("tenant_id","ceremony_id","ordinal"),
	CONSTRAINT "tenant_webauthn_ceremony_credentials_id_key" UNIQUE("tenant_id","ceremony_id","credential_id"),
	CONSTRAINT "tenant_webauthn_ceremony_credentials_value_check" CHECK ("tenant_webauthn_ceremony_credentials"."ordinal" between 0 and 127
        and octet_length("tenant_webauthn_ceremony_credentials"."credential_id") between 1 and 4096)
);
--> statement-breakpoint
ALTER TABLE "tenant_webauthn_ceremony_credentials" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_webauthn_credential_transports" (
	"tenant_id" uuid NOT NULL,
	"credential_id" uuid NOT NULL,
	"transport" text NOT NULL,
	CONSTRAINT "tenant_webauthn_credential_transports_pkey" PRIMARY KEY("tenant_id","credential_id","transport"),
	CONSTRAINT "tenant_webauthn_credential_transports_value_check" CHECK ("tenant_webauthn_credential_transports"."transport" in ('usb', 'nfc', 'ble', 'internal', 'hybrid', 'smart_card'))
);
--> statement-breakpoint
ALTER TABLE "tenant_webauthn_credential_transports" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_webauthn_credentials" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"credential_id" "bytea" NOT NULL,
	"public_key" "bytea" NOT NULL,
	"display_name" text NOT NULL,
	"user_handle_digest" "bytea" NOT NULL,
	"rp_id" text NOT NULL,
	"rp_revision" bigint NOT NULL,
	"sign_count" bigint DEFAULT 0 NOT NULL,
	"discoverable" boolean NOT NULL,
	"user_verification" boolean NOT NULL,
	"backup_eligible" boolean NOT NULL,
	"backed_up" boolean NOT NULL,
	"aaguid" "bytea" NOT NULL,
	"attestation_format" text NOT NULL,
	"attestation_type" text NOT NULL,
	"attestation_trusted" boolean NOT NULL,
	"metadata_revision" bigint DEFAULT 0 NOT NULL,
	"status" text DEFAULT 'active' NOT NULL,
	"version" bigint DEFAULT 1 NOT NULL,
	"created_at" timestamp with time zone NOT NULL,
	"last_used_at" timestamp with time zone,
	"revoked_at" timestamp with time zone,
	"revoke_reason" text,
	"updated_at" timestamp with time zone NOT NULL,
	CONSTRAINT "tenant_webauthn_credentials_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "tenant_webauthn_credentials_tenant_user_id_key" UNIQUE("tenant_id","user_id","id"),
	CONSTRAINT "tenant_webauthn_credentials_credential_id_key" UNIQUE("credential_id"),
	CONSTRAINT "tenant_webauthn_credentials_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_webauthn_credentials"."id") = 7) is true),
	CONSTRAINT "tenant_webauthn_credentials_material_check" CHECK (octet_length("tenant_webauthn_credentials"."credential_id") between 1 and 4096
        and octet_length("tenant_webauthn_credentials"."public_key") between 32 and 65536
        and octet_length("tenant_webauthn_credentials"."user_handle_digest") = 32
        and octet_length("tenant_webauthn_credentials"."aaguid") = 16),
	CONSTRAINT "tenant_webauthn_credentials_display_name_check" CHECK (btrim("tenant_webauthn_credentials"."display_name") = "tenant_webauthn_credentials"."display_name"
        and char_length("tenant_webauthn_credentials"."display_name") between 1 and 120
        and "tenant_webauthn_credentials"."display_name" !~ '[[:cntrl:]]'),
	CONSTRAINT "tenant_webauthn_credentials_rp_counter_check" CHECK (btrim("tenant_webauthn_credentials"."rp_id") = "tenant_webauthn_credentials"."rp_id"
        and char_length("tenant_webauthn_credentials"."rp_id") between 1 and 253
        and "tenant_webauthn_credentials"."rp_revision" > 0
        and "tenant_webauthn_credentials"."sign_count" between 0 and 4294967295),
	CONSTRAINT "tenant_webauthn_credentials_backup_check" CHECK (not "tenant_webauthn_credentials"."backed_up" or "tenant_webauthn_credentials"."backup_eligible"),
	CONSTRAINT "tenant_webauthn_credentials_attestation_check" CHECK (btrim("tenant_webauthn_credentials"."attestation_format") = "tenant_webauthn_credentials"."attestation_format"
        and char_length("tenant_webauthn_credentials"."attestation_format") between 1 and 64
        and "tenant_webauthn_credentials"."attestation_format" !~ '[[:cntrl:]]'
        and "tenant_webauthn_credentials"."attestation_type" in ('none', 'self', 'basic', 'enterprise')
        and "tenant_webauthn_credentials"."metadata_revision" >= 0),
	CONSTRAINT "tenant_webauthn_credentials_lifecycle_check" CHECK (("tenant_webauthn_credentials"."status" = 'active'
          and "tenant_webauthn_credentials"."revoked_at" is null
          and "tenant_webauthn_credentials"."revoke_reason" is null)
        or ("tenant_webauthn_credentials"."status" in ('revoked', 'clone_suspected')
          and "tenant_webauthn_credentials"."revoked_at" is not null
          and "tenant_webauthn_credentials"."revoke_reason" is not null
          and "tenant_webauthn_credentials"."revoked_at" >= "tenant_webauthn_credentials"."created_at"
          and btrim("tenant_webauthn_credentials"."revoke_reason") <> ''
          and char_length("tenant_webauthn_credentials"."revoke_reason") <= 500
          and "tenant_webauthn_credentials"."revoke_reason" !~ '[[:cntrl:]]')),
	CONSTRAINT "tenant_webauthn_credentials_timestamps_check" CHECK ("tenant_webauthn_credentials"."version" > 0
        and "tenant_webauthn_credentials"."updated_at" >= "tenant_webauthn_credentials"."created_at"
        and ("tenant_webauthn_credentials"."last_used_at" is null
          or ("tenant_webauthn_credentials"."last_used_at" >= "tenant_webauthn_credentials"."created_at"
            and "tenant_webauthn_credentials"."updated_at" >= "tenant_webauthn_credentials"."last_used_at"))
        and ("tenant_webauthn_credentials"."revoked_at" is null or "tenant_webauthn_credentials"."updated_at" >= "tenant_webauthn_credentials"."revoked_at"))
);
--> statement-breakpoint
ALTER TABLE "tenant_webauthn_credentials" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "auth_sessions" DROP CONSTRAINT "auth_sessions_method_check";--> statement-breakpoint
ALTER TABLE "auth_session_local_credential_provenance" ADD CONSTRAINT "auth_session_local_credential_provenance_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "auth_session_local_credential_provenance" ADD CONSTRAINT "auth_session_local_credential_provenance_state_fk" FOREIGN KEY ("tenant_id","session_id","primary_kind","user_id") REFERENCES "public"."auth_session_mfa_states"("tenant_id","session_id","primary_kind","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "auth_session_local_credential_provenance" ADD CONSTRAINT "auth_session_local_credential_provenance_credential_fk" FOREIGN KEY ("credential_id") REFERENCES "public"."local_break_glass_credentials"("id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "auth_session_mfa_evidence" ADD CONSTRAINT "auth_session_mfa_evidence_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "auth_session_mfa_evidence" ADD CONSTRAINT "auth_session_mfa_evidence_session_fk" FOREIGN KEY ("tenant_id","session_id") REFERENCES "public"."auth_session_mfa_states"("tenant_id","session_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "auth_session_mfa_evidence" ADD CONSTRAINT "auth_session_mfa_evidence_local_credential_fk" FOREIGN KEY ("local_credential_id") REFERENCES "public"."local_break_glass_credentials"("id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "auth_session_mfa_evidence" ADD CONSTRAINT "auth_session_mfa_evidence_totp_fk" FOREIGN KEY ("tenant_id","totp_factor_id") REFERENCES "public"."tenant_totp_factors"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "auth_session_mfa_evidence" ADD CONSTRAINT "auth_session_mfa_evidence_webauthn_fk" FOREIGN KEY ("tenant_id","webauthn_credential_id") REFERENCES "public"."tenant_webauthn_credentials"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "auth_session_mfa_evidence" ADD CONSTRAINT "auth_session_mfa_evidence_recovery_fk" FOREIGN KEY ("tenant_id","recovery_code_set_id") REFERENCES "public"."tenant_recovery_code_sets"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "auth_session_mfa_evidence" ADD CONSTRAINT "auth_session_mfa_evidence_provider_binding_fk" FOREIGN KEY ("tenant_id","binding_id","provider_id") REFERENCES "public"."tenant_auth_provider_bindings"("tenant_id","id","provider_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "auth_session_mfa_policy_pins" ADD CONSTRAINT "auth_session_mfa_policy_pins_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "auth_session_mfa_policy_pins" ADD CONSTRAINT "auth_session_mfa_policy_pins_session_fk" FOREIGN KEY ("tenant_id","session_id") REFERENCES "public"."auth_session_mfa_states"("tenant_id","session_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "auth_session_mfa_states" ADD CONSTRAINT "auth_session_mfa_states_session_id_auth_sessions_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."auth_sessions"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "auth_session_mfa_states" ADD CONSTRAINT "auth_session_mfa_states_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "auth_session_mfa_states" ADD CONSTRAINT "auth_session_mfa_states_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "auth_session_mfa_states" ADD CONSTRAINT "auth_session_mfa_states_subject_fk" FOREIGN KEY ("tenant_id","user_id") REFERENCES "public"."tenant_mfa_subjects"("tenant_id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "auth_session_passkey_provenance" ADD CONSTRAINT "auth_session_passkey_provenance_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "auth_session_passkey_provenance" ADD CONSTRAINT "auth_session_passkey_provenance_state_fk" FOREIGN KEY ("tenant_id","session_id","primary_kind","user_id") REFERENCES "public"."auth_session_mfa_states"("tenant_id","session_id","primary_kind","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "auth_session_passkey_provenance" ADD CONSTRAINT "auth_session_passkey_provenance_credential_fk" FOREIGN KEY ("tenant_id","user_id","credential_id") REFERENCES "public"."tenant_webauthn_credentials"("tenant_id","user_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "mfa_policy_revisions" ADD CONSTRAINT "mfa_policy_revisions_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "mfa_policy_revisions" ADD CONSTRAINT "mfa_policy_revisions_role_fk" FOREIGN KEY ("tenant_id","role_id") REFERENCES "public"."tenant_roles"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "mfa_policy_revisions" ADD CONSTRAINT "mfa_policy_revisions_security_group_fk" FOREIGN KEY ("tenant_id","security_group_id") REFERENCES "public"."tenant_security_groups"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_mfa_authority_anchors" ADD CONSTRAINT "tenant_mfa_authority_anchors_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_mfa_authority_anchors" ADD CONSTRAINT "tenant_mfa_authority_anchors_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_mfa_authority_anchors" ADD CONSTRAINT "tenant_mfa_authority_anchors_session_id_auth_sessions_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."auth_sessions"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_mfa_authority_anchors" ADD CONSTRAINT "tenant_mfa_authority_anchors_subject_fk" FOREIGN KEY ("tenant_id","user_id") REFERENCES "public"."tenant_mfa_subjects"("tenant_id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_mfa_authority_anchors" ADD CONSTRAINT "tenant_mfa_authority_anchors_continuation_fk" FOREIGN KEY ("tenant_id","continuation_id") REFERENCES "public"."tenant_post_primary_continuations"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_mfa_authority_evidence" ADD CONSTRAINT "tenant_mfa_authority_evidence_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_mfa_authority_evidence" ADD CONSTRAINT "tenant_mfa_authority_evidence_anchor_fk" FOREIGN KEY ("tenant_id","anchor_id") REFERENCES "public"."tenant_mfa_authority_anchors"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_mfa_authority_evidence" ADD CONSTRAINT "tenant_mfa_authority_evidence_local_credential_fk" FOREIGN KEY ("local_credential_id") REFERENCES "public"."local_break_glass_credentials"("id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_mfa_authority_evidence" ADD CONSTRAINT "tenant_mfa_authority_evidence_totp_fk" FOREIGN KEY ("tenant_id","totp_factor_id") REFERENCES "public"."tenant_totp_factors"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_mfa_authority_evidence" ADD CONSTRAINT "tenant_mfa_authority_evidence_webauthn_fk" FOREIGN KEY ("tenant_id","webauthn_credential_id") REFERENCES "public"."tenant_webauthn_credentials"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_mfa_authority_evidence" ADD CONSTRAINT "tenant_mfa_authority_evidence_recovery_fk" FOREIGN KEY ("tenant_id","recovery_code_set_id") REFERENCES "public"."tenant_recovery_code_sets"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_mfa_authority_evidence" ADD CONSTRAINT "tenant_mfa_authority_evidence_provider_binding_fk" FOREIGN KEY ("tenant_id","binding_id","provider_id") REFERENCES "public"."tenant_auth_provider_bindings"("tenant_id","id","provider_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_mfa_authority_policy_pins" ADD CONSTRAINT "tenant_mfa_authority_policy_pins_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_mfa_authority_policy_pins" ADD CONSTRAINT "tenant_mfa_authority_policy_pins_anchor_fk" FOREIGN KEY ("tenant_id","anchor_id") REFERENCES "public"."tenant_mfa_authority_anchors"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_mfa_authority_policy_pins" ADD CONSTRAINT "tenant_mfa_authority_policy_pins_role_fk" FOREIGN KEY ("tenant_id","role_id") REFERENCES "public"."tenant_roles"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_mfa_authority_policy_pins" ADD CONSTRAINT "tenant_mfa_authority_policy_pins_security_group_fk" FOREIGN KEY ("tenant_id","security_group_id") REFERENCES "public"."tenant_security_groups"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_mfa_step_up_challenges" ADD CONSTRAINT "tenant_mfa_step_up_challenges_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_mfa_step_up_challenges" ADD CONSTRAINT "tenant_mfa_step_up_challenges_anchor_fk" FOREIGN KEY ("tenant_id","authority_anchor_id") REFERENCES "public"."tenant_mfa_authority_anchors"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_mfa_subjects" ADD CONSTRAINT "tenant_mfa_subjects_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_mfa_subjects" ADD CONSTRAINT "tenant_mfa_subjects_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_mfa_subjects" ADD CONSTRAINT "tenant_mfa_subjects_membership_fk" FOREIGN KEY ("tenant_id","user_id") REFERENCES "public"."tenant_memberships"("tenant_id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_post_primary_continuation_evidence" ADD CONSTRAINT "tenant_post_primary_continuation_evidence_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_post_primary_continuation_evidence" ADD CONSTRAINT "tenant_post_primary_continuation_evidence_continuation_fk" FOREIGN KEY ("tenant_id","continuation_id") REFERENCES "public"."tenant_post_primary_continuations"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_post_primary_continuation_evidence" ADD CONSTRAINT "tenant_post_primary_continuation_evidence_local_credential_fk" FOREIGN KEY ("local_credential_id") REFERENCES "public"."local_break_glass_credentials"("id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_post_primary_continuation_evidence" ADD CONSTRAINT "tenant_post_primary_continuation_evidence_totp_fk" FOREIGN KEY ("tenant_id","totp_factor_id") REFERENCES "public"."tenant_totp_factors"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_post_primary_continuation_evidence" ADD CONSTRAINT "tenant_post_primary_continuation_evidence_webauthn_fk" FOREIGN KEY ("tenant_id","webauthn_credential_id") REFERENCES "public"."tenant_webauthn_credentials"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_post_primary_continuation_evidence" ADD CONSTRAINT "tenant_post_primary_continuation_evidence_recovery_fk" FOREIGN KEY ("tenant_id","recovery_code_set_id") REFERENCES "public"."tenant_recovery_code_sets"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_post_primary_continuation_evidence" ADD CONSTRAINT "tenant_post_primary_continuation_evidence_provider_binding_fk" FOREIGN KEY ("tenant_id","binding_id","provider_id") REFERENCES "public"."tenant_auth_provider_bindings"("tenant_id","id","provider_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_post_primary_continuation_policy_pins" ADD CONSTRAINT "tenant_post_primary_continuation_policy_pins_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_post_primary_continuation_policy_pins" ADD CONSTRAINT "tenant_post_primary_continuation_policy_pins_continuation_fk" FOREIGN KEY ("tenant_id","continuation_id") REFERENCES "public"."tenant_post_primary_continuations"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_post_primary_continuations" ADD CONSTRAINT "tenant_post_primary_continuations_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_post_primary_continuations" ADD CONSTRAINT "tenant_post_primary_continuations_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_post_primary_continuations" ADD CONSTRAINT "tenant_post_primary_continuations_subject_fk" FOREIGN KEY ("tenant_id","user_id") REFERENCES "public"."tenant_mfa_subjects"("tenant_id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_post_primary_continuations" ADD CONSTRAINT "tenant_post_primary_continuations_local_credential_fk" FOREIGN KEY ("local_credential_id") REFERENCES "public"."local_break_glass_credentials"("id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_post_primary_continuations" ADD CONSTRAINT "tenant_post_primary_continuations_passkey_fk" FOREIGN KEY ("tenant_id","user_id","passkey_credential_id") REFERENCES "public"."tenant_webauthn_credentials"("tenant_id","user_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_recovery_code_sets" ADD CONSTRAINT "tenant_recovery_code_sets_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_recovery_code_sets" ADD CONSTRAINT "tenant_recovery_code_sets_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_recovery_code_sets" ADD CONSTRAINT "tenant_recovery_code_sets_subject_fk" FOREIGN KEY ("tenant_id","user_id") REFERENCES "public"."tenant_mfa_subjects"("tenant_id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_recovery_codes" ADD CONSTRAINT "tenant_recovery_codes_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_recovery_codes" ADD CONSTRAINT "tenant_recovery_codes_set_fk" FOREIGN KEY ("tenant_id","set_id") REFERENCES "public"."tenant_recovery_code_sets"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_totp_enrollments" ADD CONSTRAINT "tenant_totp_enrollments_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_totp_enrollments" ADD CONSTRAINT "tenant_totp_enrollments_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_totp_enrollments" ADD CONSTRAINT "tenant_totp_enrollments_subject_fk" FOREIGN KEY ("tenant_id","user_id") REFERENCES "public"."tenant_mfa_subjects"("tenant_id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_totp_enrollments" ADD CONSTRAINT "tenant_totp_enrollments_anchor_fk" FOREIGN KEY ("tenant_id","authority_anchor_id") REFERENCES "public"."tenant_mfa_authority_anchors"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_totp_factors" ADD CONSTRAINT "tenant_totp_factors_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_totp_factors" ADD CONSTRAINT "tenant_totp_factors_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_totp_factors" ADD CONSTRAINT "tenant_totp_factors_subject_fk" FOREIGN KEY ("tenant_id","user_id") REFERENCES "public"."tenant_mfa_subjects"("tenant_id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_webauthn_ceremonies" ADD CONSTRAINT "tenant_webauthn_ceremonies_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_webauthn_ceremonies" ADD CONSTRAINT "tenant_webauthn_ceremonies_anchor_fk" FOREIGN KEY ("tenant_id","authority_anchor_id") REFERENCES "public"."tenant_mfa_authority_anchors"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_webauthn_ceremony_credentials" ADD CONSTRAINT "tenant_webauthn_ceremony_credentials_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_webauthn_ceremony_credentials" ADD CONSTRAINT "tenant_webauthn_ceremony_credentials_ceremony_fk" FOREIGN KEY ("tenant_id","ceremony_id") REFERENCES "public"."tenant_webauthn_ceremonies"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_webauthn_credential_transports" ADD CONSTRAINT "tenant_webauthn_credential_transports_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_webauthn_credential_transports" ADD CONSTRAINT "tenant_webauthn_credential_transports_credential_fk" FOREIGN KEY ("tenant_id","credential_id") REFERENCES "public"."tenant_webauthn_credentials"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_webauthn_credentials" ADD CONSTRAINT "tenant_webauthn_credentials_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_webauthn_credentials" ADD CONSTRAINT "tenant_webauthn_credentials_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_webauthn_credentials" ADD CONSTRAINT "tenant_webauthn_credentials_subject_fk" FOREIGN KEY ("tenant_id","user_id") REFERENCES "public"."tenant_mfa_subjects"("tenant_id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
CREATE INDEX "auth_session_mfa_evidence_session_idx" ON "auth_session_mfa_evidence" USING btree ("tenant_id","session_id","authenticated_at","id");--> statement-breakpoint
CREATE INDEX "auth_session_mfa_states_subject_idx" ON "auth_session_mfa_states" USING btree ("tenant_id","user_id","issued_at","session_id");--> statement-breakpoint
CREATE UNIQUE INDEX "mfa_policy_revisions_platform_live_key" ON "mfa_policy_revisions" USING btree ("scope") WHERE "mfa_policy_revisions"."scope" = 'platform_floor' and "mfa_policy_revisions"."retired_at" is null;--> statement-breakpoint
CREATE UNIQUE INDEX "mfa_policy_revisions_tenant_live_key" ON "mfa_policy_revisions" USING btree ("tenant_id","scope") WHERE "mfa_policy_revisions"."scope" = 'tenant_baseline' and "mfa_policy_revisions"."retired_at" is null;--> statement-breakpoint
CREATE UNIQUE INDEX "mfa_policy_revisions_role_live_key" ON "mfa_policy_revisions" USING btree ("tenant_id","role_id") WHERE "mfa_policy_revisions"."scope" = 'role' and "mfa_policy_revisions"."retired_at" is null;--> statement-breakpoint
CREATE UNIQUE INDEX "mfa_policy_revisions_security_group_live_key" ON "mfa_policy_revisions" USING btree ("tenant_id","security_group_id") WHERE "mfa_policy_revisions"."scope" = 'security_group' and "mfa_policy_revisions"."retired_at" is null;--> statement-breakpoint
CREATE UNIQUE INDEX "mfa_policy_revisions_action_live_key" ON "mfa_policy_revisions" USING btree ("tenant_id","action") WHERE "mfa_policy_revisions"."scope" = 'action' and "mfa_policy_revisions"."retired_at" is null;--> statement-breakpoint
CREATE INDEX "mfa_policy_revisions_tenant_history_idx" ON "mfa_policy_revisions" USING btree ("tenant_id","scope","id","revision");--> statement-breakpoint
CREATE INDEX "tenant_mfa_authority_anchors_session_idx" ON "tenant_mfa_authority_anchors" USING btree ("tenant_id","session_id","id");--> statement-breakpoint
CREATE INDEX "tenant_mfa_authority_anchors_continuation_idx" ON "tenant_mfa_authority_anchors" USING btree ("tenant_id","continuation_id","id");--> statement-breakpoint
CREATE INDEX "tenant_mfa_authority_evidence_anchor_idx" ON "tenant_mfa_authority_evidence" USING btree ("tenant_id","anchor_id","authenticated_at","id");--> statement-breakpoint
CREATE INDEX "tenant_mfa_step_up_challenges_expiry_idx" ON "tenant_mfa_step_up_challenges" USING btree ("expires_at","tenant_id","id") WHERE "tenant_mfa_step_up_challenges"."state" in ('pending', 'claimed');--> statement-breakpoint
CREATE INDEX "tenant_post_primary_continuations_subject_pending_idx" ON "tenant_post_primary_continuations" USING btree ("tenant_id","user_id","expires_at","id") WHERE "tenant_post_primary_continuations"."state" = 'pending';--> statement-breakpoint
CREATE UNIQUE INDEX "tenant_recovery_code_sets_user_active_key" ON "tenant_recovery_code_sets" USING btree ("tenant_id","user_id") WHERE "tenant_recovery_code_sets"."status" = 'active';--> statement-breakpoint
CREATE INDEX "tenant_recovery_codes_available_idx" ON "tenant_recovery_codes" USING btree ("tenant_id","set_id","created_at","id") WHERE "tenant_recovery_codes"."consumed_at" is null;--> statement-breakpoint
CREATE UNIQUE INDEX "tenant_totp_enrollments_user_pending_key" ON "tenant_totp_enrollments" USING btree ("tenant_id","user_id") WHERE "tenant_totp_enrollments"."state" in ('pending', 'claimed');--> statement-breakpoint
CREATE INDEX "tenant_totp_enrollments_expiry_idx" ON "tenant_totp_enrollments" USING btree ("expires_at","tenant_id","id") WHERE "tenant_totp_enrollments"."state" in ('pending', 'claimed');--> statement-breakpoint
CREATE INDEX "tenant_totp_factors_user_active_idx" ON "tenant_totp_factors" USING btree ("tenant_id","user_id","id") WHERE "tenant_totp_factors"."status" = 'active';--> statement-breakpoint
CREATE INDEX "tenant_webauthn_ceremonies_expiry_idx" ON "tenant_webauthn_ceremonies" USING btree ("expires_at","tenant_id","id") WHERE "tenant_webauthn_ceremonies"."state" in ('pending', 'claimed');--> statement-breakpoint
CREATE INDEX "tenant_webauthn_credentials_user_active_idx" ON "tenant_webauthn_credentials" USING btree ("tenant_id","user_id","id") WHERE "tenant_webauthn_credentials"."status" = 'active';--> statement-breakpoint
ALTER TABLE "auth_sessions" ADD CONSTRAINT "auth_sessions_method_check" CHECK ("auth_sessions"."authentication_method" in ('bootstrap_totp', 'passkey', 'totp', 'recovery_code'));