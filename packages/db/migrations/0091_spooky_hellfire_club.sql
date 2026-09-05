CREATE TYPE "public"."notification_audience" AS ENUM('operator', 'customer');--> statement-breakpoint
CREATE TYPE "public"."notification_channel" AS ENUM('email', 'webhook');--> statement-breakpoint
CREATE TYPE "public"."notification_delivery_status" AS ENUM('queued', 'leased', 'reserved', 'retry_scheduled', 'delivered', 'dead_lettered');--> statement-breakpoint
CREATE TYPE "public"."notification_event_type" AS ENUM('alert.created', 'alert.assigned', 'alert.claimed', 'alert.status_changed', 'alert.escalated', 'case.created', 'case.assigned', 'case.claimed', 'case.transferred', 'case.status_changed', 'comment.public_added', 'comment.private_added', 'contact.changed', 'sla.warning', 'sla.breached', 'task.assigned', 'evidence.added', 'webhook.custom');--> statement-breakpoint
CREATE TYPE "public"."notification_failure_class" AS ENUM('authentication', 'connectivity', 'rate_limited', 'render', 'security', 'timeout', 'tls', 'unknown', 'submission_uncertain');--> statement-breakpoint
CREATE TYPE "public"."notification_object_type" AS ENUM('alert', 'case', 'task', 'evidence', 'contact');--> statement-breakpoint
CREATE TYPE "public"."notification_secret_kind" AS ENUM('smtp_password', 'smtp_dkim_private_key', 'webhook_signing_key');--> statement-breakpoint
CREATE TYPE "public"."notification_smtp_security" AS ENUM('tls', 'starttls', 'plain_local');--> statement-breakpoint
CREATE TABLE "platform_notification_commands" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"actor_user_id" uuid NOT NULL,
	"operation" text NOT NULL,
	"key_digest" "bytea" NOT NULL,
	"request_digest" "bytea" NOT NULL,
	"result_resource_id" uuid NOT NULL,
	"result_version" integer NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone DEFAULT transaction_timestamp() + interval '24 hours' NOT NULL,
	CONSTRAINT "platform_notification_commands_replay_key" UNIQUE("actor_user_id","operation","key_digest"),
	CONSTRAINT "platform_notification_commands_bounds_check" CHECK ("platform_notification_commands"."operation" in ('smtp.version', 'smtp.test')
        and octet_length("platform_notification_commands"."key_digest") = 32
        and octet_length("platform_notification_commands"."request_digest") = 32
        and "platform_notification_commands"."result_version" between 1 and 2147483647
        and "platform_notification_commands"."expires_at" > "platform_notification_commands"."created_at")
);
--> statement-breakpoint
CREATE TABLE "platform_notification_secret_versions" (
	"secret_id" uuid NOT NULL,
	"version" integer NOT NULL,
	"kind" "notification_secret_kind" NOT NULL,
	"key_version" smallint NOT NULL,
	"nonce" "bytea" NOT NULL,
	"ciphertext" "bytea" NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_by_user_id" uuid NOT NULL,
	CONSTRAINT "platform_notification_secret_versions_pkey" PRIMARY KEY("secret_id","version"),
	CONSTRAINT "platform_notification_secret_versions_envelope_check" CHECK ((uuid_extract_version("platform_notification_secret_versions"."secret_id") = 7) is true
        and "platform_notification_secret_versions"."version" between 1 and 2147483647
        and "platform_notification_secret_versions"."key_version" between 1 and 32767
        and octet_length("platform_notification_secret_versions"."nonce") = 12
        and octet_length("platform_notification_secret_versions"."ciphertext") between 17 and 65552)
);
--> statement-breakpoint
CREATE TABLE "platform_notification_smtp_configuration_versions" (
	"configuration_id" uuid NOT NULL,
	"version" integer NOT NULL,
	"name" text NOT NULL,
	"host" text NOT NULL,
	"port" integer NOT NULL,
	"security" "notification_smtp_security" NOT NULL,
	"username" text,
	"password_secret_id" uuid,
	"password_secret_version" integer,
	"from_name" text NOT NULL,
	"from_email" text NOT NULL,
	"reply_to_email" text,
	"timeout_ms" integer NOT NULL,
	"maximum_connections" integer NOT NULL,
	"maximum_messages_per_connection" integer NOT NULL,
	"rate_limit_per_second" integer NOT NULL,
	"dkim_domain_name" text,
	"dkim_selector" text,
	"dkim_secret_id" uuid,
	"dkim_secret_version" integer,
	"enabled" boolean NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_by_user_id" uuid NOT NULL,
	CONSTRAINT "platform_notification_smtp_configuration_versions_pkey" PRIMARY KEY("configuration_id","version"),
	CONSTRAINT "platform_notification_smtp_versions_bounds_check" CHECK ("platform_notification_smtp_configuration_versions"."version" between 1 and 2147483647
        and btrim("platform_notification_smtp_configuration_versions"."name") <> '' and char_length("platform_notification_smtp_configuration_versions"."name") <= 160
        and "platform_notification_smtp_configuration_versions"."host" ~ '^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$'
        and "platform_notification_smtp_configuration_versions"."port" between 1 and 65535
        and ("platform_notification_smtp_configuration_versions"."username" is null) = ("platform_notification_smtp_configuration_versions"."password_secret_id" is null)
        and ("platform_notification_smtp_configuration_versions"."password_secret_id" is null) = ("platform_notification_smtp_configuration_versions"."password_secret_version" is null)
        and ("platform_notification_smtp_configuration_versions"."dkim_domain_name" is null) = ("platform_notification_smtp_configuration_versions"."dkim_selector" is null)
        and ("platform_notification_smtp_configuration_versions"."dkim_selector" is null) = ("platform_notification_smtp_configuration_versions"."dkim_secret_id" is null)
        and ("platform_notification_smtp_configuration_versions"."dkim_secret_id" is null) = ("platform_notification_smtp_configuration_versions"."dkim_secret_version" is null)
        and char_length("platform_notification_smtp_configuration_versions"."from_name") between 1 and 160
        and char_length("platform_notification_smtp_configuration_versions"."from_email") between 3 and 320
        and "platform_notification_smtp_configuration_versions"."timeout_ms" between 1000 and 120000
        and "platform_notification_smtp_configuration_versions"."maximum_connections" between 1 and 100
        and "platform_notification_smtp_configuration_versions"."maximum_messages_per_connection" between 1 and 10000
        and "platform_notification_smtp_configuration_versions"."rate_limit_per_second" between 1 and 10000)
);
--> statement-breakpoint
CREATE TABLE "platform_notification_smtp_configurations" (
	"id" uuid PRIMARY KEY NOT NULL,
	"current_version" integer DEFAULT 1 NOT NULL,
	"revoked_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_by_user_id" uuid NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "platform_notification_smtp_configurations_identity_check" CHECK ((uuid_extract_version("platform_notification_smtp_configurations"."id") = 7) is true
        and "platform_notification_smtp_configurations"."current_version" between 1 and 2147483647
        and "platform_notification_smtp_configurations"."updated_at" >= "platform_notification_smtp_configurations"."created_at")
);
--> statement-breakpoint
CREATE TABLE "tenant_notification_commands" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"actor_membership_id" uuid NOT NULL,
	"actor_user_id" uuid NOT NULL,
	"operation" text NOT NULL,
	"key_digest" "bytea" NOT NULL,
	"request_digest" "bytea" NOT NULL,
	"result_resource_id" uuid NOT NULL,
	"result_version" integer NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone DEFAULT transaction_timestamp() + interval '24 hours' NOT NULL,
	CONSTRAINT "tenant_notification_commands_replay_key" UNIQUE("tenant_id","actor_membership_id","operation","key_digest"),
	CONSTRAINT "tenant_notification_commands_bounds_check" CHECK ("tenant_notification_commands"."operation" in (
          'rule.create', 'rule.version', 'template.create',
          'template.version', 'template.duplicate', 'template.rollback',
          'template.test', 'smtp.version', 'smtp.test',
          'delivery.retry', 'webhook.create', 'webhook.version',
          'webhook.test'
        )
        and octet_length("tenant_notification_commands"."key_digest") = 32
        and octet_length("tenant_notification_commands"."request_digest") = 32
        and "tenant_notification_commands"."result_version" between 1 and 2147483647
        and "tenant_notification_commands"."expires_at" > "tenant_notification_commands"."created_at")
);
--> statement-breakpoint
ALTER TABLE "tenant_notification_commands" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_notification_deliveries" (
	"id" uuid PRIMARY KEY NOT NULL,
	"tenant_id" uuid NOT NULL,
	"event_id" uuid NOT NULL,
	"parent_delivery_id" uuid,
	"delivery_key" text NOT NULL,
	"rule_id" uuid,
	"rule_version" integer,
	"template_id" uuid,
	"template_version" integer,
	"smtp_configuration_scope" text,
	"smtp_configuration_id" uuid,
	"smtp_configuration_version" integer,
	"webhook_configuration_id" uuid,
	"webhook_configuration_version" integer,
	"webhook_signing_secret_id" uuid,
	"webhook_signing_secret_version" integer,
	"webhook_signing_key_version" integer,
	"webhook_payload_version" integer,
	"webhook_payload" jsonb,
	"channel" "notification_channel" NOT NULL,
	"audience" "notification_audience" NOT NULL,
	"recipient" text NOT NULL,
	"destination_redacted" text NOT NULL,
	"context" jsonb NOT NULL,
	"priority" integer NOT NULL,
	"deduplication_key" text NOT NULL,
	"grouping_key" text,
	"grouping_window_ms" bigint DEFAULT 0 NOT NULL,
	"grouping_maximum_items" integer DEFAULT 1 NOT NULL,
	"retry" jsonb NOT NULL,
	"status" "notification_delivery_status" DEFAULT 'queued' NOT NULL,
	"attempt_count" integer DEFAULT 0 NOT NULL,
	"maximum_attempts" integer NOT NULL,
	"next_attempt_at" timestamp with time zone,
	"lease_owner" text,
	"fence_token" uuid,
	"lease_until" timestamp with time zone,
	"stable_message_id" text,
	"reserved_at" timestamp with time zone,
	"delivered_at" timestamp with time zone,
	"failure_at" timestamp with time zone,
	"failure_class" "notification_failure_class",
	"failure_code" text,
	"provider_receipt" jsonb,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_notification_deliveries_tenant_id_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "tenant_notification_deliveries_tenant_delivery_key_key" UNIQUE("tenant_id","delivery_key"),
	CONSTRAINT "tenant_notification_deliveries_bounds_check" CHECK ((uuid_extract_version("tenant_notification_deliveries"."id") = 7) is true
        and "tenant_notification_deliveries"."delivery_key" ~ '^[0-9a-f]{64}$'
        and char_length("tenant_notification_deliveries"."recipient") between 3 and 320
        and char_length("tenant_notification_deliveries"."destination_redacted") between 3 and 320
        and jsonb_typeof("tenant_notification_deliveries"."context") = 'object'
        and octet_length("tenant_notification_deliveries"."context"::text) <= 65536
        and "tenant_notification_deliveries"."priority" between 0 and 100
        and char_length("tenant_notification_deliveries"."deduplication_key") between 1 and 240
        and ("tenant_notification_deliveries"."grouping_key" is null or char_length("tenant_notification_deliveries"."grouping_key") <= 240)
        and "tenant_notification_deliveries"."grouping_window_ms" between 0 and 2592000000
        and "tenant_notification_deliveries"."grouping_maximum_items" between 1 and 10000
        and jsonb_typeof("tenant_notification_deliveries"."retry") = 'object'
        and "tenant_notification_deliveries"."attempt_count" between 0 and 100
        and "tenant_notification_deliveries"."maximum_attempts" between 1 and 100
        and "tenant_notification_deliveries"."attempt_count" <= "tenant_notification_deliveries"."maximum_attempts"
        and ("tenant_notification_deliveries"."lease_owner" is null) = ("tenant_notification_deliveries"."fence_token" is null)
        and ("tenant_notification_deliveries"."fence_token" is null) = ("tenant_notification_deliveries"."lease_until" is null)
        and ("tenant_notification_deliveries"."stable_message_id" is null) = ("tenant_notification_deliveries"."reserved_at" is null)
        and ("tenant_notification_deliveries"."failure_code" is null or "tenant_notification_deliveries"."failure_code" ~ '^[a-z][a-z0-9_]{0,63}$')
        and ("tenant_notification_deliveries"."provider_receipt" is null or jsonb_typeof("tenant_notification_deliveries"."provider_receipt") = 'object')
        and ("tenant_notification_deliveries"."rule_id" is null) = ("tenant_notification_deliveries"."rule_version" is null)
        and ("tenant_notification_deliveries"."template_id" is null) = ("tenant_notification_deliveries"."template_version" is null)
        and (("tenant_notification_deliveries"."channel" = 'email'
          and "tenant_notification_deliveries"."smtp_configuration_scope" in ('tenant', 'platform')
          and "tenant_notification_deliveries"."smtp_configuration_id" is not null
          and "tenant_notification_deliveries"."smtp_configuration_version" is not null
          and "tenant_notification_deliveries"."webhook_configuration_id" is null
          and "tenant_notification_deliveries"."webhook_configuration_version" is null
          and "tenant_notification_deliveries"."webhook_signing_secret_id" is null
          and "tenant_notification_deliveries"."webhook_signing_secret_version" is null
          and "tenant_notification_deliveries"."webhook_signing_key_version" is null
          and "tenant_notification_deliveries"."webhook_payload_version" is null
          and "tenant_notification_deliveries"."webhook_payload" is null)
          or ("tenant_notification_deliveries"."channel" = 'webhook'
            and "tenant_notification_deliveries"."smtp_configuration_scope" is null
            and "tenant_notification_deliveries"."smtp_configuration_id" is null
            and "tenant_notification_deliveries"."smtp_configuration_version" is null
            and "tenant_notification_deliveries"."webhook_configuration_id" is not null
            and "tenant_notification_deliveries"."webhook_configuration_version" is not null
            and "tenant_notification_deliveries"."webhook_signing_secret_id" is not null
            and "tenant_notification_deliveries"."webhook_signing_secret_version" between 1 and 2147483647
            and "tenant_notification_deliveries"."webhook_signing_key_version" between 1 and 32767
            and "tenant_notification_deliveries"."webhook_payload_version" = 1
            and jsonb_typeof("tenant_notification_deliveries"."webhook_payload") = 'object'
            and octet_length("tenant_notification_deliveries"."webhook_payload"::text) <= 262144)))
);
--> statement-breakpoint
ALTER TABLE "tenant_notification_deliveries" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_notification_delivery_attempts" (
	"tenant_id" uuid NOT NULL,
	"delivery_id" uuid NOT NULL,
	"attempt" integer NOT NULL,
	"fence_token" uuid NOT NULL,
	"started_at" timestamp with time zone DEFAULT now() NOT NULL,
	"completed_at" timestamp with time zone,
	"outcome" text,
	"failure_class" "notification_failure_class",
	"provider_receipt" jsonb,
	CONSTRAINT "tenant_notification_delivery_attempts_pkey" PRIMARY KEY("tenant_id","delivery_id","attempt"),
	CONSTRAINT "tenant_notification_delivery_attempts_lifecycle_check" CHECK ("tenant_notification_delivery_attempts"."attempt" between 1 and 100
        and (uuid_extract_version("tenant_notification_delivery_attempts"."fence_token") = 7) is true
        and ("tenant_notification_delivery_attempts"."completed_at" is null) = ("tenant_notification_delivery_attempts"."outcome" is null)
        and ("tenant_notification_delivery_attempts"."outcome" is null or "tenant_notification_delivery_attempts"."outcome" in (
          'delivered', 'replayed', 'retried', 'dead_lettered',
          'uncertain', 'fenced'
        ))
        and ("tenant_notification_delivery_attempts"."provider_receipt" is null or jsonb_typeof("tenant_notification_delivery_attempts"."provider_receipt") = 'object'))
);
--> statement-breakpoint
ALTER TABLE "tenant_notification_delivery_attempts" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_notification_fanout_snapshots" (
	"tenant_id" uuid NOT NULL,
	"event_id" uuid NOT NULL,
	"rule_pins" jsonb NOT NULL,
	"webhook_configuration_pins" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"smtp_configuration_scope" text,
	"smtp_configuration_id" uuid,
	"smtp_configuration_version" integer,
	"snapshot_digest" "bytea" NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_notification_fanout_snapshots_pkey" PRIMARY KEY("tenant_id","event_id"),
	CONSTRAINT "tenant_notification_fanout_snapshots_bounds_check" CHECK (jsonb_typeof("tenant_notification_fanout_snapshots"."rule_pins") = 'array'
        and jsonb_array_length("tenant_notification_fanout_snapshots"."rule_pins") <= 1000
        and octet_length("tenant_notification_fanout_snapshots"."rule_pins"::text) <= 131072
        and jsonb_typeof("tenant_notification_fanout_snapshots"."webhook_configuration_pins") = 'array'
        and jsonb_array_length("tenant_notification_fanout_snapshots"."webhook_configuration_pins") <= 1000
        and octet_length("tenant_notification_fanout_snapshots"."webhook_configuration_pins"::text) <= 131072
        and ("tenant_notification_fanout_snapshots"."smtp_configuration_scope" is null)
          = ("tenant_notification_fanout_snapshots"."smtp_configuration_id" is null)
        and ("tenant_notification_fanout_snapshots"."smtp_configuration_id" is null)
          = ("tenant_notification_fanout_snapshots"."smtp_configuration_version" is null)
        and ("tenant_notification_fanout_snapshots"."smtp_configuration_scope" is null
          or "tenant_notification_fanout_snapshots"."smtp_configuration_scope" in ('tenant', 'platform'))
        and ("tenant_notification_fanout_snapshots"."smtp_configuration_version" is null
          or "tenant_notification_fanout_snapshots"."smtp_configuration_version" between 1 and 2147483647)
        and octet_length("tenant_notification_fanout_snapshots"."snapshot_digest") = 32)
);
--> statement-breakpoint
ALTER TABLE "tenant_notification_fanout_snapshots" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_notification_rule_versions" (
	"tenant_id" uuid NOT NULL,
	"rule_id" uuid NOT NULL,
	"version" integer NOT NULL,
	"name" text NOT NULL,
	"description" text DEFAULT '' NOT NULL,
	"event_type" "notification_event_type" NOT NULL,
	"object_type" "notification_object_type" NOT NULL,
	"condition" jsonb NOT NULL,
	"recipients" jsonb NOT NULL,
	"template_id" uuid NOT NULL,
	"template_version" integer NOT NULL,
	"channel" "notification_channel" NOT NULL,
	"priority" integer NOT NULL,
	"delay_ms" bigint NOT NULL,
	"quiet_hours" jsonb,
	"deduplication_window_ms" bigint NOT NULL,
	"grouping" jsonb NOT NULL,
	"retry" jsonb NOT NULL,
	"enabled" boolean NOT NULL,
	"effective_from" timestamp with time zone NOT NULL,
	"effective_until" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_by_membership_id" uuid NOT NULL,
	"created_by_user_id" uuid NOT NULL,
	CONSTRAINT "tenant_notification_rule_versions_pkey" PRIMARY KEY("tenant_id","rule_id","version"),
	CONSTRAINT "tenant_notification_rule_versions_bounds_check" CHECK ("tenant_notification_rule_versions"."version" between 1 and 2147483647
        and btrim("tenant_notification_rule_versions"."name") <> '' and char_length("tenant_notification_rule_versions"."name") <= 160
        and char_length("tenant_notification_rule_versions"."description") <= 2048
        and jsonb_typeof("tenant_notification_rule_versions"."condition") = 'object'
        and octet_length("tenant_notification_rule_versions"."condition"::text) <= 65536
        and jsonb_typeof("tenant_notification_rule_versions"."recipients") = 'array'
        and jsonb_array_length("tenant_notification_rule_versions"."recipients") between 1 and 256
        and octet_length("tenant_notification_rule_versions"."recipients"::text) <= 65536
        and "tenant_notification_rule_versions"."template_version" between 1 and 2147483647
        and "tenant_notification_rule_versions"."priority" between 0 and 100
        and "tenant_notification_rule_versions"."delay_ms" between 0 and 2592000000
        and "tenant_notification_rule_versions"."deduplication_window_ms" between 0 and 2592000000
        and ("tenant_notification_rule_versions"."quiet_hours" is null or jsonb_typeof("tenant_notification_rule_versions"."quiet_hours") = 'object')
        and jsonb_typeof("tenant_notification_rule_versions"."grouping") = 'object'
        and jsonb_typeof("tenant_notification_rule_versions"."retry") = 'object'
        and ("tenant_notification_rule_versions"."effective_until" is null or "tenant_notification_rule_versions"."effective_until" > "tenant_notification_rule_versions"."effective_from"))
);
--> statement-breakpoint
ALTER TABLE "tenant_notification_rule_versions" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_notification_rules" (
	"id" uuid PRIMARY KEY NOT NULL,
	"tenant_id" uuid NOT NULL,
	"current_version" integer DEFAULT 1 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_by_membership_id" uuid NOT NULL,
	"created_by_user_id" uuid NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_notification_rules_tenant_id_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "tenant_notification_rules_identity_check" CHECK ((uuid_extract_version("tenant_notification_rules"."id") = 7) is true
        and "tenant_notification_rules"."current_version" between 1 and 2147483647
        and "tenant_notification_rules"."updated_at" >= "tenant_notification_rules"."created_at")
);
--> statement-breakpoint
ALTER TABLE "tenant_notification_rules" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_notification_secret_versions" (
	"tenant_id" uuid NOT NULL,
	"secret_id" uuid NOT NULL,
	"version" integer NOT NULL,
	"kind" "notification_secret_kind" NOT NULL,
	"key_version" smallint NOT NULL,
	"nonce" "bytea" NOT NULL,
	"ciphertext" "bytea" NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_by_membership_id" uuid NOT NULL,
	"created_by_user_id" uuid NOT NULL,
	CONSTRAINT "tenant_notification_secret_versions_pkey" PRIMARY KEY("tenant_id","secret_id","version"),
	CONSTRAINT "tenant_notification_secret_versions_envelope_check" CHECK ((uuid_extract_version("tenant_notification_secret_versions"."secret_id") = 7) is true
        and "tenant_notification_secret_versions"."version" between 1 and 2147483647
        and "tenant_notification_secret_versions"."key_version" between 1 and 32767
        and octet_length("tenant_notification_secret_versions"."nonce") = 12
        and octet_length("tenant_notification_secret_versions"."ciphertext") between 17 and 65552)
);
--> statement-breakpoint
ALTER TABLE "tenant_notification_secret_versions" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_notification_smtp_configuration_versions" (
	"tenant_id" uuid NOT NULL,
	"configuration_id" uuid NOT NULL,
	"version" integer NOT NULL,
	"name" text NOT NULL,
	"host" text NOT NULL,
	"port" integer NOT NULL,
	"security" "notification_smtp_security" NOT NULL,
	"username" text,
	"password_secret_id" uuid,
	"password_secret_version" integer,
	"from_name" text NOT NULL,
	"from_email" text NOT NULL,
	"reply_to_email" text,
	"timeout_ms" integer NOT NULL,
	"maximum_connections" integer NOT NULL,
	"maximum_messages_per_connection" integer NOT NULL,
	"rate_limit_per_second" integer NOT NULL,
	"dkim_domain_name" text,
	"dkim_selector" text,
	"dkim_secret_id" uuid,
	"dkim_secret_version" integer,
	"enabled" boolean NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_by_membership_id" uuid NOT NULL,
	"created_by_user_id" uuid NOT NULL,
	CONSTRAINT "tenant_notification_smtp_configuration_versions_pkey" PRIMARY KEY("tenant_id","configuration_id","version"),
	CONSTRAINT "tenant_notification_smtp_versions_bounds_check" CHECK ("tenant_notification_smtp_configuration_versions"."version" between 1 and 2147483647
        and btrim("tenant_notification_smtp_configuration_versions"."name") <> '' and char_length("tenant_notification_smtp_configuration_versions"."name") <= 160
        and "tenant_notification_smtp_configuration_versions"."host" ~ '^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$'
        and "tenant_notification_smtp_configuration_versions"."port" between 1 and 65535
        and ("tenant_notification_smtp_configuration_versions"."username" is null) = ("tenant_notification_smtp_configuration_versions"."password_secret_id" is null)
        and ("tenant_notification_smtp_configuration_versions"."password_secret_id" is null) = ("tenant_notification_smtp_configuration_versions"."password_secret_version" is null)
        and ("tenant_notification_smtp_configuration_versions"."dkim_domain_name" is null) = ("tenant_notification_smtp_configuration_versions"."dkim_selector" is null)
        and ("tenant_notification_smtp_configuration_versions"."dkim_selector" is null) = ("tenant_notification_smtp_configuration_versions"."dkim_secret_id" is null)
        and ("tenant_notification_smtp_configuration_versions"."dkim_secret_id" is null) = ("tenant_notification_smtp_configuration_versions"."dkim_secret_version" is null)
        and char_length("tenant_notification_smtp_configuration_versions"."from_name") between 1 and 160
        and char_length("tenant_notification_smtp_configuration_versions"."from_email") between 3 and 320
        and ("tenant_notification_smtp_configuration_versions"."reply_to_email" is null or char_length("tenant_notification_smtp_configuration_versions"."reply_to_email") between 3 and 320)
        and "tenant_notification_smtp_configuration_versions"."timeout_ms" between 1000 and 120000
        and "tenant_notification_smtp_configuration_versions"."maximum_connections" between 1 and 100
        and "tenant_notification_smtp_configuration_versions"."maximum_messages_per_connection" between 1 and 10000
        and "tenant_notification_smtp_configuration_versions"."rate_limit_per_second" between 1 and 10000)
);
--> statement-breakpoint
ALTER TABLE "tenant_notification_smtp_configuration_versions" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_notification_smtp_configurations" (
	"id" uuid PRIMARY KEY NOT NULL,
	"tenant_id" uuid NOT NULL,
	"current_version" integer DEFAULT 1 NOT NULL,
	"revoked_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_by_membership_id" uuid NOT NULL,
	"created_by_user_id" uuid NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_notification_smtp_configurations_tenant_id_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "tenant_notification_smtp_configurations_one_per_tenant" UNIQUE("tenant_id"),
	CONSTRAINT "tenant_notification_smtp_configurations_identity_check" CHECK ((uuid_extract_version("tenant_notification_smtp_configurations"."id") = 7) is true
        and "tenant_notification_smtp_configurations"."current_version" between 1 and 2147483647
        and "tenant_notification_smtp_configurations"."updated_at" >= "tenant_notification_smtp_configurations"."created_at"
        and ("tenant_notification_smtp_configurations"."revoked_at" is null or "tenant_notification_smtp_configurations"."revoked_at" >= "tenant_notification_smtp_configurations"."created_at"))
);
--> statement-breakpoint
ALTER TABLE "tenant_notification_smtp_configurations" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_notification_template_versions" (
	"tenant_id" uuid NOT NULL,
	"template_id" uuid NOT NULL,
	"version" integer NOT NULL,
	"key" text NOT NULL,
	"name" text NOT NULL,
	"language" text NOT NULL,
	"subject" text NOT NULL,
	"html" text NOT NULL,
	"plain_text" text,
	"css" text,
	"sample_data" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"placeholders" text[] NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_by_membership_id" uuid NOT NULL,
	"created_by_user_id" uuid NOT NULL,
	CONSTRAINT "tenant_notification_template_versions_pkey" PRIMARY KEY("tenant_id","template_id","version"),
	CONSTRAINT "tenant_notification_template_versions_bounds_check" CHECK ("tenant_notification_template_versions"."version" between 1 and 2147483647
        and "tenant_notification_template_versions"."key" ~ '^[a-z][a-z0-9_.-]{1,126}[a-z0-9]$'
        and btrim("tenant_notification_template_versions"."name") <> '' and char_length("tenant_notification_template_versions"."name") <= 160
        and "tenant_notification_template_versions"."language" ~ '^[a-z]{2,3}(-[A-Z]{2})?$'
        and char_length("tenant_notification_template_versions"."subject") between 1 and 998
        and char_length("tenant_notification_template_versions"."html") between 1 and 200000
        and ("tenant_notification_template_versions"."plain_text" is null or char_length("tenant_notification_template_versions"."plain_text") <= 200000)
        and ("tenant_notification_template_versions"."css" is null or char_length("tenant_notification_template_versions"."css") <= 50000)
        and jsonb_typeof("tenant_notification_template_versions"."sample_data") = 'object'
        and octet_length("tenant_notification_template_versions"."sample_data"::text) <= 65536
        and cardinality("tenant_notification_template_versions"."placeholders") <= 256)
);
--> statement-breakpoint
ALTER TABLE "tenant_notification_template_versions" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_notification_templates" (
	"id" uuid PRIMARY KEY NOT NULL,
	"tenant_id" uuid NOT NULL,
	"key" text NOT NULL,
	"current_version" integer DEFAULT 1 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_by_membership_id" uuid NOT NULL,
	"created_by_user_id" uuid NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_notification_templates_tenant_id_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "tenant_notification_templates_tenant_id_key_key" UNIQUE("tenant_id","key"),
	CONSTRAINT "tenant_notification_templates_identity_check" CHECK ((uuid_extract_version("tenant_notification_templates"."id") = 7) is true
        and "tenant_notification_templates"."key" ~ '^[a-z][a-z0-9_.-]{1,126}[a-z0-9]$'
        and "tenant_notification_templates"."current_version" between 1 and 2147483647
        and "tenant_notification_templates"."updated_at" >= "tenant_notification_templates"."created_at")
);
--> statement-breakpoint
ALTER TABLE "tenant_notification_templates" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_notification_webhook_configuration_versions" (
	"tenant_id" uuid NOT NULL,
	"configuration_id" uuid NOT NULL,
	"version" integer NOT NULL,
	"name" text NOT NULL,
	"endpoint_url" text NOT NULL,
	"event_types" "notification_event_type"[] NOT NULL,
	"audience" "notification_audience" NOT NULL,
	"signing_secret_id" uuid NOT NULL,
	"signing_secret_version" integer NOT NULL,
	"timeout_ms" integer NOT NULL,
	"enabled" boolean NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_by_membership_id" uuid NOT NULL,
	"created_by_user_id" uuid NOT NULL,
	CONSTRAINT "tenant_notification_webhook_configuration_versions_pkey" PRIMARY KEY("tenant_id","configuration_id","version"),
	CONSTRAINT "tenant_notification_webhook_versions_bounds_check" CHECK ("tenant_notification_webhook_configuration_versions"."version" between 1 and 2147483647
        and btrim("tenant_notification_webhook_configuration_versions"."name") <> '' and char_length("tenant_notification_webhook_configuration_versions"."name") <= 160
        and char_length("tenant_notification_webhook_configuration_versions"."endpoint_url") between 8 and 2048
        and cardinality("tenant_notification_webhook_configuration_versions"."event_types") between 1 and 64
        and "tenant_notification_webhook_configuration_versions"."signing_secret_version" between 1 and 2147483647
        and "tenant_notification_webhook_configuration_versions"."timeout_ms" between 1000 and 120000)
);
--> statement-breakpoint
ALTER TABLE "tenant_notification_webhook_configuration_versions" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_notification_webhook_configurations" (
	"id" uuid PRIMARY KEY NOT NULL,
	"tenant_id" uuid NOT NULL,
	"current_version" integer DEFAULT 1 NOT NULL,
	"revoked_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_by_membership_id" uuid NOT NULL,
	"created_by_user_id" uuid NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_notification_webhooks_tenant_id_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "tenant_notification_webhooks_identity_check" CHECK ((uuid_extract_version("tenant_notification_webhook_configurations"."id") = 7) is true
        and "tenant_notification_webhook_configurations"."current_version" between 1 and 2147483647
        and "tenant_notification_webhook_configurations"."updated_at" >= "tenant_notification_webhook_configurations"."created_at")
);
--> statement-breakpoint
ALTER TABLE "tenant_notification_webhook_configurations" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "outbox_events" DROP CONSTRAINT "outbox_events_lock_consistency_check";--> statement-breakpoint
ALTER TABLE "outbox_events" ADD COLUMN "aggregate_version" integer;--> statement-breakpoint
ALTER TABLE "outbox_events" ADD COLUMN "actor_kind" "ticket_principal_kind";--> statement-breakpoint
ALTER TABLE "outbox_events" ADD COLUMN "actor_id" uuid;--> statement-breakpoint
ALTER TABLE "outbox_events" ADD COLUMN "producer" text;--> statement-breakpoint
ALTER TABLE "outbox_events" ADD COLUMN "maximum_audience" "notification_audience";--> statement-breakpoint
ALTER TABLE "outbox_events" ADD COLUMN "lease_token" uuid;--> statement-breakpoint
ALTER TABLE "outbox_events" ADD COLUMN "lease_until" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "outbox_events" ADD COLUMN "failure_category" text;--> statement-breakpoint
ALTER TABLE "outbox_events" ADD COLUMN "dead_lettered_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "outbox_events" ADD COLUMN "fanout_commit_digest" "bytea";--> statement-breakpoint
ALTER TABLE "platform_notification_commands" ADD CONSTRAINT "platform_notification_commands_actor_user_id_users_id_fk" FOREIGN KEY ("actor_user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "platform_notification_secret_versions" ADD CONSTRAINT "platform_notification_secret_versions_created_by_user_id_users_id_fk" FOREIGN KEY ("created_by_user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "platform_notification_smtp_configuration_versions" ADD CONSTRAINT "platform_notification_smtp_configuration_versions_created_by_user_id_users_id_fk" FOREIGN KEY ("created_by_user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "platform_notification_smtp_configuration_versions" ADD CONSTRAINT "platform_notification_smtp_configuration_versions_config_fk" FOREIGN KEY ("configuration_id") REFERENCES "public"."platform_notification_smtp_configurations"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "platform_notification_smtp_configuration_versions" ADD CONSTRAINT "platform_notification_smtp_password_secret_fk" FOREIGN KEY ("password_secret_id","password_secret_version") REFERENCES "public"."platform_notification_secret_versions"("secret_id","version") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "platform_notification_smtp_configuration_versions" ADD CONSTRAINT "platform_notification_smtp_dkim_secret_fk" FOREIGN KEY ("dkim_secret_id","dkim_secret_version") REFERENCES "public"."platform_notification_secret_versions"("secret_id","version") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "platform_notification_smtp_configurations" ADD CONSTRAINT "platform_notification_smtp_configurations_created_by_user_id_users_id_fk" FOREIGN KEY ("created_by_user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_commands" ADD CONSTRAINT "tenant_notification_commands_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_commands" ADD CONSTRAINT "tenant_notification_commands_actor_user_id_users_id_fk" FOREIGN KEY ("actor_user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_commands" ADD CONSTRAINT "tenant_notification_commands_actor_membership_fk" FOREIGN KEY ("tenant_id","actor_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_deliveries" ADD CONSTRAINT "tenant_notification_deliveries_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_deliveries" ADD CONSTRAINT "tenant_notification_deliveries_event_id_outbox_events_id_fk" FOREIGN KEY ("event_id") REFERENCES "public"."outbox_events"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_deliveries" ADD CONSTRAINT "tenant_notification_deliveries_parent_fk" FOREIGN KEY ("tenant_id","parent_delivery_id") REFERENCES "public"."tenant_notification_deliveries"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_deliveries" ADD CONSTRAINT "tenant_notification_deliveries_rule_fk" FOREIGN KEY ("tenant_id","rule_id","rule_version") REFERENCES "public"."tenant_notification_rule_versions"("tenant_id","rule_id","version") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_deliveries" ADD CONSTRAINT "tenant_notification_deliveries_template_fk" FOREIGN KEY ("tenant_id","template_id","template_version") REFERENCES "public"."tenant_notification_template_versions"("tenant_id","template_id","version") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_deliveries" ADD CONSTRAINT "tenant_notification_deliveries_webhook_fk" FOREIGN KEY ("tenant_id","webhook_configuration_id","webhook_configuration_version") REFERENCES "public"."tenant_notification_webhook_configuration_versions"("tenant_id","configuration_id","version") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_deliveries" ADD CONSTRAINT "tenant_notification_deliveries_webhook_secret_fk" FOREIGN KEY ("tenant_id","webhook_signing_secret_id","webhook_signing_secret_version") REFERENCES "public"."tenant_notification_secret_versions"("tenant_id","secret_id","version") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_delivery_attempts" ADD CONSTRAINT "tenant_notification_delivery_attempts_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_delivery_attempts" ADD CONSTRAINT "tenant_notification_delivery_attempts_delivery_fk" FOREIGN KEY ("tenant_id","delivery_id") REFERENCES "public"."tenant_notification_deliveries"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_fanout_snapshots" ADD CONSTRAINT "tenant_notification_fanout_snapshots_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_fanout_snapshots" ADD CONSTRAINT "tenant_notification_fanout_snapshots_event_id_outbox_events_id_fk" FOREIGN KEY ("event_id") REFERENCES "public"."outbox_events"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_rule_versions" ADD CONSTRAINT "tenant_notification_rule_versions_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_rule_versions" ADD CONSTRAINT "tenant_notification_rule_versions_created_by_user_id_users_id_fk" FOREIGN KEY ("created_by_user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_rule_versions" ADD CONSTRAINT "tenant_notification_rule_versions_rule_fk" FOREIGN KEY ("tenant_id","rule_id") REFERENCES "public"."tenant_notification_rules"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_rule_versions" ADD CONSTRAINT "tenant_notification_rule_versions_template_fk" FOREIGN KEY ("tenant_id","template_id","template_version") REFERENCES "public"."tenant_notification_template_versions"("tenant_id","template_id","version") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_rule_versions" ADD CONSTRAINT "tenant_notification_rule_versions_creator_membership_fk" FOREIGN KEY ("tenant_id","created_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_rules" ADD CONSTRAINT "tenant_notification_rules_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_rules" ADD CONSTRAINT "tenant_notification_rules_created_by_user_id_users_id_fk" FOREIGN KEY ("created_by_user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_rules" ADD CONSTRAINT "tenant_notification_rules_creator_membership_fk" FOREIGN KEY ("tenant_id","created_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_secret_versions" ADD CONSTRAINT "tenant_notification_secret_versions_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_secret_versions" ADD CONSTRAINT "tenant_notification_secret_versions_created_by_user_id_users_id_fk" FOREIGN KEY ("created_by_user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_secret_versions" ADD CONSTRAINT "tenant_notification_secret_versions_creator_membership_fk" FOREIGN KEY ("tenant_id","created_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_smtp_configuration_versions" ADD CONSTRAINT "tenant_notification_smtp_configuration_versions_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_smtp_configuration_versions" ADD CONSTRAINT "tenant_notification_smtp_configuration_versions_created_by_user_id_users_id_fk" FOREIGN KEY ("created_by_user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_smtp_configuration_versions" ADD CONSTRAINT "tenant_notification_smtp_configuration_versions_config_fk" FOREIGN KEY ("tenant_id","configuration_id") REFERENCES "public"."tenant_notification_smtp_configurations"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_smtp_configuration_versions" ADD CONSTRAINT "tenant_notification_smtp_password_secret_fk" FOREIGN KEY ("tenant_id","password_secret_id","password_secret_version") REFERENCES "public"."tenant_notification_secret_versions"("tenant_id","secret_id","version") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_smtp_configuration_versions" ADD CONSTRAINT "tenant_notification_smtp_dkim_secret_fk" FOREIGN KEY ("tenant_id","dkim_secret_id","dkim_secret_version") REFERENCES "public"."tenant_notification_secret_versions"("tenant_id","secret_id","version") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_smtp_configuration_versions" ADD CONSTRAINT "tenant_notification_smtp_versions_creator_membership_fk" FOREIGN KEY ("tenant_id","created_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_smtp_configurations" ADD CONSTRAINT "tenant_notification_smtp_configurations_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_smtp_configurations" ADD CONSTRAINT "tenant_notification_smtp_configurations_created_by_user_id_users_id_fk" FOREIGN KEY ("created_by_user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_smtp_configurations" ADD CONSTRAINT "tenant_notification_smtp_configurations_creator_membership_fk" FOREIGN KEY ("tenant_id","created_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_template_versions" ADD CONSTRAINT "tenant_notification_template_versions_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_template_versions" ADD CONSTRAINT "tenant_notification_template_versions_created_by_user_id_users_id_fk" FOREIGN KEY ("created_by_user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_template_versions" ADD CONSTRAINT "tenant_notification_template_versions_template_fk" FOREIGN KEY ("tenant_id","template_id") REFERENCES "public"."tenant_notification_templates"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_template_versions" ADD CONSTRAINT "tenant_notification_template_versions_creator_membership_fk" FOREIGN KEY ("tenant_id","created_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_templates" ADD CONSTRAINT "tenant_notification_templates_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_templates" ADD CONSTRAINT "tenant_notification_templates_created_by_user_id_users_id_fk" FOREIGN KEY ("created_by_user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_templates" ADD CONSTRAINT "tenant_notification_templates_creator_membership_fk" FOREIGN KEY ("tenant_id","created_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_webhook_configuration_versions" ADD CONSTRAINT "tenant_notification_webhook_configuration_versions_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_webhook_configuration_versions" ADD CONSTRAINT "tenant_notification_webhook_configuration_versions_created_by_user_id_users_id_fk" FOREIGN KEY ("created_by_user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_webhook_configuration_versions" ADD CONSTRAINT "tenant_notification_webhook_versions_config_fk" FOREIGN KEY ("tenant_id","configuration_id") REFERENCES "public"."tenant_notification_webhook_configurations"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_webhook_configuration_versions" ADD CONSTRAINT "tenant_notification_webhook_signing_secret_fk" FOREIGN KEY ("tenant_id","signing_secret_id","signing_secret_version") REFERENCES "public"."tenant_notification_secret_versions"("tenant_id","secret_id","version") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_webhook_configuration_versions" ADD CONSTRAINT "tenant_notification_webhook_versions_creator_membership_fk" FOREIGN KEY ("tenant_id","created_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_webhook_configurations" ADD CONSTRAINT "tenant_notification_webhook_configurations_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_webhook_configurations" ADD CONSTRAINT "tenant_notification_webhook_configurations_created_by_user_id_users_id_fk" FOREIGN KEY ("created_by_user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_webhook_configurations" ADD CONSTRAINT "tenant_notification_webhooks_creator_membership_fk" FOREIGN KEY ("tenant_id","created_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "tenant_notification_deliveries_claim_idx" ON "tenant_notification_deliveries" USING btree ("next_attempt_at","priority","created_at","id") WHERE "tenant_notification_deliveries"."status" in ('queued', 'retry_scheduled', 'leased', 'reserved');--> statement-breakpoint
CREATE INDEX "tenant_notification_deliveries_tenant_created_idx" ON "tenant_notification_deliveries" USING btree ("tenant_id","created_at","id");--> statement-breakpoint
CREATE INDEX "tenant_notification_rule_versions_fanout_idx" ON "tenant_notification_rule_versions" USING btree ("tenant_id","event_type","object_type","enabled","effective_from");--> statement-breakpoint
ALTER TABLE "outbox_events" ADD CONSTRAINT "outbox_events_tenant_id_id_key" UNIQUE("tenant_id","id");--> statement-breakpoint
ALTER TABLE "outbox_events" ADD CONSTRAINT "outbox_events_notification_v2_envelope_check" CHECK (not ("outbox_events"."event_type" like 'notification.%' and "outbox_events"."schema_version" = 2)
        or ("outbox_events"."aggregate_version" between 1 and 2147483647
          and "outbox_events"."actor_kind" is not null
          and ("outbox_events"."actor_kind" = 'system') = ("outbox_events"."actor_id" is null)
          and "outbox_events"."producer" ~ '^[a-z][a-z0-9_.-]{1,127}$'
          and "outbox_events"."maximum_audience" is not null
          and jsonb_typeof("outbox_events"."payload") = 'object'
          and "outbox_events"."payload" ? 'operatorContext'
          and jsonb_typeof("outbox_events"."payload" -> 'operatorContext') = 'object'
          and ("outbox_events"."maximum_audience" = 'customer') = ("outbox_events"."payload" ? 'customerContext')
          and (not ("outbox_events"."payload" ? 'customerContext')
            or jsonb_typeof("outbox_events"."payload" -> 'customerContext') = 'object')));--> statement-breakpoint
ALTER TABLE "outbox_events" ADD CONSTRAINT "outbox_events_fanout_bounds_check" CHECK (("outbox_events"."failure_category" is null
          or ("outbox_events"."failure_category" ~ '^[a-z][a-z0-9_]{0,63}$'))
        and ("outbox_events"."dead_lettered_at" is null or "outbox_events"."processed_at" is not null)
        and ("outbox_events"."lease_until" is null or "outbox_events"."processed_at" is null)
        and ("outbox_events"."fanout_commit_digest" is null
          or (octet_length("outbox_events"."fanout_commit_digest") = 32
            and "outbox_events"."processed_at" is not null)));--> statement-breakpoint
ALTER TABLE "outbox_events" ADD CONSTRAINT "outbox_events_lock_consistency_check" CHECK (("outbox_events"."locked_at" is null) = ("outbox_events"."locked_by" is null)
        and ("outbox_events"."lease_token" is null) = ("outbox_events"."lease_until" is null));--> statement-breakpoint
CREATE POLICY "tenant_notification_commands_api_tenant" ON "tenant_notification_commands" AS PERMISSIVE FOR ALL TO "periapsis_api" USING (
  "tenant_notification_commands"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenant_notification_commands"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "tenant_notification_commands"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenant_notification_commands"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "tenant_notification_deliveries_api_tenant" ON "tenant_notification_deliveries" AS PERMISSIVE FOR ALL TO "periapsis_api" USING (
  "tenant_notification_deliveries"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenant_notification_deliveries"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "tenant_notification_deliveries"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenant_notification_deliveries"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "tenant_notification_deliveries_notifier_tenant" ON "tenant_notification_deliveries" AS PERMISSIVE FOR ALL TO "periapsis_notifier" USING ("tenant_notification_deliveries"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK ("tenant_notification_deliveries"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid);--> statement-breakpoint
CREATE POLICY "tenant_notification_delivery_attempts_api_tenant" ON "tenant_notification_delivery_attempts" AS PERMISSIVE FOR ALL TO "periapsis_api" USING (
  "tenant_notification_delivery_attempts"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenant_notification_delivery_attempts"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "tenant_notification_delivery_attempts"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenant_notification_delivery_attempts"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "tenant_notification_delivery_attempts_notifier_tenant" ON "tenant_notification_delivery_attempts" AS PERMISSIVE FOR ALL TO "periapsis_notifier" USING ("tenant_notification_delivery_attempts"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK ("tenant_notification_delivery_attempts"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid);--> statement-breakpoint
CREATE POLICY "tenant_notification_fanout_snapshots_api_tenant" ON "tenant_notification_fanout_snapshots" AS PERMISSIVE FOR ALL TO "periapsis_api" USING (
  "tenant_notification_fanout_snapshots"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenant_notification_fanout_snapshots"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "tenant_notification_fanout_snapshots"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenant_notification_fanout_snapshots"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "tenant_notification_fanout_snapshots_notifier_tenant" ON "tenant_notification_fanout_snapshots" AS PERMISSIVE FOR ALL TO "periapsis_notifier" USING ("tenant_notification_fanout_snapshots"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK ("tenant_notification_fanout_snapshots"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid);--> statement-breakpoint
CREATE POLICY "tenant_notification_rule_versions_api_tenant" ON "tenant_notification_rule_versions" AS PERMISSIVE FOR ALL TO "periapsis_api" USING (
  "tenant_notification_rule_versions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenant_notification_rule_versions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "tenant_notification_rule_versions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenant_notification_rule_versions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "tenant_notification_rules_api_tenant" ON "tenant_notification_rules" AS PERMISSIVE FOR ALL TO "periapsis_api" USING (
  "tenant_notification_rules"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenant_notification_rules"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "tenant_notification_rules"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenant_notification_rules"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "tenant_notification_secret_versions_api_tenant" ON "tenant_notification_secret_versions" AS PERMISSIVE FOR ALL TO "periapsis_api" USING (
  "tenant_notification_secret_versions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenant_notification_secret_versions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "tenant_notification_secret_versions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenant_notification_secret_versions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "tenant_notification_smtp_configuration_versions_api_tenant" ON "tenant_notification_smtp_configuration_versions" AS PERMISSIVE FOR ALL TO "periapsis_api" USING (
  "tenant_notification_smtp_configuration_versions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenant_notification_smtp_configuration_versions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "tenant_notification_smtp_configuration_versions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenant_notification_smtp_configuration_versions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "tenant_notification_smtp_configurations_api_tenant" ON "tenant_notification_smtp_configurations" AS PERMISSIVE FOR ALL TO "periapsis_api" USING (
  "tenant_notification_smtp_configurations"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenant_notification_smtp_configurations"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "tenant_notification_smtp_configurations"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenant_notification_smtp_configurations"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "tenant_notification_template_versions_api_tenant" ON "tenant_notification_template_versions" AS PERMISSIVE FOR ALL TO "periapsis_api" USING (
  "tenant_notification_template_versions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenant_notification_template_versions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "tenant_notification_template_versions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenant_notification_template_versions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "tenant_notification_templates_api_tenant" ON "tenant_notification_templates" AS PERMISSIVE FOR ALL TO "periapsis_api" USING (
  "tenant_notification_templates"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenant_notification_templates"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "tenant_notification_templates"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenant_notification_templates"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "tenant_notification_webhook_versions_api_tenant" ON "tenant_notification_webhook_configuration_versions" AS PERMISSIVE FOR ALL TO "periapsis_api" USING (
  "tenant_notification_webhook_configuration_versions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenant_notification_webhook_configuration_versions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "tenant_notification_webhook_configuration_versions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenant_notification_webhook_configuration_versions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "tenant_notification_webhooks_api_tenant" ON "tenant_notification_webhook_configurations" AS PERMISSIVE FOR ALL TO "periapsis_api" USING (
  "tenant_notification_webhook_configurations"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenant_notification_webhook_configurations"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "tenant_notification_webhook_configurations"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenant_notification_webhook_configurations"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);