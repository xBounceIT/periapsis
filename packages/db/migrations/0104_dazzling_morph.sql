CREATE TYPE "public"."sla_clock_type" AS ENUM('elapsed', 'business');--> statement-breakpoint
CREATE TYPE "public"."sla_column_calculation" AS ENUM('due_at', 'remaining_seconds', 'state', 'consumed_percentage', 'breached_at');--> statement-breakpoint
CREATE TYPE "public"."sla_column_format" AS ENUM('datetime', 'duration', 'state_badge', 'percentage');--> statement-breakpoint
CREATE TYPE "public"."sla_event_outcome" AS ENUM('no_policy', 'assigned', 'updated');--> statement-breakpoint
CREATE TYPE "public"."sla_job_status" AS ENUM('queued', 'leased', 'retry_scheduled', 'completed', 'dead_lettered');--> statement-breakpoint
CREATE TYPE "public"."sla_metric_lifecycle" AS ENUM('pending', 'running', 'paused', 'completed');--> statement-breakpoint
CREATE TYPE "public"."sla_metric_state" AS ENUM('pending', 'on_track', 'at_risk', 'paused', 'breached', 'completed');--> statement-breakpoint
CREATE TYPE "public"."sla_object_type" AS ENUM('alert', 'case', 'task');--> statement-breakpoint
CREATE TYPE "public"."sla_override_kind" AS ENUM('extend', 'suspend', 'resume', 'complete', 'change_calendar', 'change_policy', 'recalculate');--> statement-breakpoint
CREATE TYPE "public"."sla_override_outcome" AS ENUM('metric_updated', 'policy_changed');--> statement-breakpoint
CREATE TYPE "public"."sla_reset_policy" AS ENUM('ignore', 'clear', 'restart');--> statement-breakpoint
CREATE TYPE "public"."sla_trigger_action_kind" AS ENUM('email', 'webhook', 'add_tag', 'change_priority', 'assign_operator_team', 'create_task', 'create_system_alert', 'domain_event');--> statement-breakpoint
CREATE TYPE "public"."sla_trigger_kind" AS ENUM('consumed_percent', 'remaining_duration', 'due', 'after_breach', 'repeated_after_breach', 'state_changed', 'resumed');--> statement-breakpoint
CREATE TYPE "public"."sla_warning_kind" AS ENUM('none', 'consumed_percent', 'remaining_duration');--> statement-breakpoint
CREATE TABLE "sla_business_calendar_versions" (
	"tenant_id" uuid NOT NULL,
	"calendar_id" uuid NOT NULL,
	"version" integer NOT NULL,
	"label" text NOT NULL,
	"timezone" text NOT NULL,
	"weekly_schedule" jsonb NOT NULL,
	"exceptions" jsonb NOT NULL,
	"revision_digest" "bytea" NOT NULL,
	"created_by_membership_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "sla_business_calendar_versions_pkey" PRIMARY KEY("tenant_id","calendar_id","version"),
	CONSTRAINT "sla_business_calendar_versions_version_check" CHECK ("sla_business_calendar_versions"."version" between 1 and 2147483646),
	CONSTRAINT "sla_business_calendar_versions_text_check" CHECK (btrim("sla_business_calendar_versions"."label") <> '' and octet_length("sla_business_calendar_versions"."label") <= 256
        and "sla_business_calendar_versions"."label" !~ '[[:cntrl:]]'
        and char_length("sla_business_calendar_versions"."timezone") <= 128
        and ("sla_business_calendar_versions"."timezone" = 'UTC' or "sla_business_calendar_versions"."timezone" ~ '^[A-Za-z][A-Za-z0-9_+.-]{0,62}(/[A-Za-z0-9_+.-]{1,63}){1,3}$')),
	CONSTRAINT "sla_business_calendar_versions_payload_check" CHECK (jsonb_typeof("sla_business_calendar_versions"."weekly_schedule") = 'array'
        and jsonb_array_length("sla_business_calendar_versions"."weekly_schedule") between 1 and 7
        and pg_column_size("sla_business_calendar_versions"."weekly_schedule") <= 65536
        and jsonb_typeof("sla_business_calendar_versions"."exceptions") = 'array'
        and jsonb_array_length("sla_business_calendar_versions"."exceptions") <= 36600
        and pg_column_size("sla_business_calendar_versions"."exceptions") <= 4194304
        and octet_length("sla_business_calendar_versions"."revision_digest") = 32)
);
--> statement-breakpoint
ALTER TABLE "sla_business_calendar_versions" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "sla_business_calendars" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"key" text NOT NULL,
	"active_version" integer DEFAULT 1 NOT NULL,
	"resource_version" integer DEFAULT 1 NOT NULL,
	"created_by_membership_id" uuid NOT NULL,
	"updated_by_membership_id" uuid NOT NULL,
	"archived_by_membership_id" uuid,
	"archived_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "sla_business_calendars_tenant_id_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "sla_business_calendars_tenant_key_key" UNIQUE("tenant_id","key"),
	CONSTRAINT "sla_business_calendars_id_check" CHECK ((uuid_extract_version("sla_business_calendars"."id") = 7) is true),
	CONSTRAINT "sla_business_calendars_key_check" CHECK ("sla_business_calendars"."key" ~ '^[a-z][a-z0-9_.-]{0,62}[a-z0-9]$'),
	CONSTRAINT "sla_business_calendars_version_check" CHECK ("sla_business_calendars"."active_version" between 1 and 2147483646 and "sla_business_calendars"."resource_version" between 1 and 2147483646),
	CONSTRAINT "sla_business_calendars_lifecycle_check" CHECK ("sla_business_calendars"."updated_at" >= "sla_business_calendars"."created_at"
        and ("sla_business_calendars"."archived_at" is null or "sla_business_calendars"."archived_at" between "sla_business_calendars"."created_at" and "sla_business_calendars"."updated_at")
        and ("sla_business_calendars"."archived_at" is null) = ("sla_business_calendars"."archived_by_membership_id" is null))
);
--> statement-breakpoint
ALTER TABLE "sla_business_calendars" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "sla_column_versions" (
	"tenant_id" uuid NOT NULL,
	"column_id" uuid NOT NULL,
	"version" integer NOT NULL,
	"label" text NOT NULL,
	"metric_definition_id" uuid NOT NULL,
	"calculation" "sla_column_calculation" NOT NULL,
	"format" "sla_column_format" NOT NULL,
	"sortable" boolean NOT NULL,
	"filterable" boolean NOT NULL,
	"customer_visible" boolean NOT NULL,
	"visible_role_keys" text[] NOT NULL,
	"position" integer NOT NULL,
	"style_rules" jsonb NOT NULL,
	"revision_digest" "bytea" NOT NULL,
	"created_by_membership_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "sla_column_versions_pkey" PRIMARY KEY("tenant_id","column_id","version"),
	CONSTRAINT "sla_column_versions_version_check" CHECK ("sla_column_versions"."version" between 1 and 2147483646),
	CONSTRAINT "sla_column_versions_shape_check" CHECK (btrim("sla_column_versions"."label") <> '' and octet_length("sla_column_versions"."label") <= 256
        and "sla_column_versions"."label" !~ '[[:cntrl:]]'
        and "sla_column_versions"."position" between 0 and 255
        and cardinality("sla_column_versions"."visible_role_keys") <= 128
        and array_position("sla_column_versions"."visible_role_keys", null) is null
        and array_to_string("sla_column_versions"."visible_role_keys", ',') ~ '^([a-z][a-z0-9_.-]{0,63}(,[a-z][a-z0-9_.-]{0,63})*)?$'
        and jsonb_typeof("sla_column_versions"."style_rules") = 'array'
        and jsonb_array_length("sla_column_versions"."style_rules") <= 64
        and pg_column_size("sla_column_versions"."style_rules") <= 65536
        and octet_length("sla_column_versions"."revision_digest") = 32)
);
--> statement-breakpoint
ALTER TABLE "sla_column_versions" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "sla_columns" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"key" text NOT NULL,
	"active_version" integer DEFAULT 1 NOT NULL,
	"resource_version" integer DEFAULT 1 NOT NULL,
	"created_by_membership_id" uuid NOT NULL,
	"updated_by_membership_id" uuid NOT NULL,
	"archived_by_membership_id" uuid,
	"archived_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "sla_columns_tenant_id_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "sla_columns_tenant_key_key" UNIQUE("tenant_id","key"),
	CONSTRAINT "sla_columns_id_check" CHECK ((uuid_extract_version("sla_columns"."id") = 7) is true),
	CONSTRAINT "sla_columns_key_check" CHECK ("sla_columns"."key" ~ '^[a-z][a-z0-9_.-]{0,62}[a-z0-9]$'),
	CONSTRAINT "sla_columns_version_check" CHECK ("sla_columns"."active_version" between 1 and 2147483646 and "sla_columns"."resource_version" between 1 and 2147483646),
	CONSTRAINT "sla_columns_lifecycle_check" CHECK ("sla_columns"."updated_at" >= "sla_columns"."created_at"
        and ("sla_columns"."archived_at" is null or "sla_columns"."archived_at" between "sla_columns"."created_at" and "sla_columns"."updated_at")
        and ("sla_columns"."archived_at" is null) = ("sla_columns"."archived_by_membership_id" is null))
);
--> statement-breakpoint
ALTER TABLE "sla_columns" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "sla_configuration_commands" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"actor_membership_id" uuid NOT NULL,
	"operation" text NOT NULL,
	"key_digest" "bytea" NOT NULL,
	"request_digest" "bytea" NOT NULL,
	"resource_id" uuid NOT NULL,
	"resource_version" integer NOT NULL,
	"active_version" integer,
	"archived" boolean NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone DEFAULT now() + interval '24 hours' NOT NULL,
	CONSTRAINT "sla_configuration_commands_tenant_id_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "sla_configuration_commands_replay_key" UNIQUE("tenant_id","actor_membership_id","operation","key_digest"),
	CONSTRAINT "sla_configuration_commands_id_check" CHECK ((uuid_extract_version("sla_configuration_commands"."id") = 7) is true),
	CONSTRAINT "sla_configuration_commands_operation_check" CHECK ("sla_configuration_commands"."operation" in (
        'sla.calendar.publish', 'sla.calendar.archive',
        'sla.policy.publish', 'sla.policy.archive',
        'sla.column.publish', 'sla.column.archive'
      )),
	CONSTRAINT "sla_configuration_commands_digest_check" CHECK (octet_length("sla_configuration_commands"."key_digest") = 32 and octet_length("sla_configuration_commands"."request_digest") = 32),
	CONSTRAINT "sla_configuration_commands_result_check" CHECK ("sla_configuration_commands"."resource_version" between 1 and 2147483646
        and ("sla_configuration_commands"."archived" = ("sla_configuration_commands"."active_version" is null))
        and ("sla_configuration_commands"."active_version" is null or "sla_configuration_commands"."active_version" between 1 and 2147483646)),
	CONSTRAINT "sla_configuration_commands_retention_check" CHECK ("sla_configuration_commands"."expires_at" > "sla_configuration_commands"."created_at"
        and "sla_configuration_commands"."expires_at" <= "sla_configuration_commands"."created_at" + interval '7 days')
);
--> statement-breakpoint
ALTER TABLE "sla_configuration_commands" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "sla_evaluation_jobs" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"sla_instance_id" uuid NOT NULL,
	"expected_aggregate_version" integer NOT NULL,
	"status" "sla_job_status" DEFAULT 'queued' NOT NULL,
	"available_at" timestamp with time zone NOT NULL,
	"attempt" integer DEFAULT 0 NOT NULL,
	"maximum_attempts" integer DEFAULT 12 NOT NULL,
	"worker_id" uuid,
	"lease_expires_at" timestamp with time zone,
	"fence" bigint DEFAULT 0 NOT NULL,
	"last_failure_code" text,
	"completed_at" timestamp with time zone,
	"dead_lettered_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "sla_evaluation_jobs_tenant_id_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "sla_evaluation_jobs_id_check" CHECK ((uuid_extract_version("sla_evaluation_jobs"."id") = 7) is true),
	CONSTRAINT "sla_evaluation_jobs_bounds_check" CHECK ("sla_evaluation_jobs"."expected_aggregate_version" between 1 and 2147483646
        and "sla_evaluation_jobs"."attempt" between 0 and 65535
        and "sla_evaluation_jobs"."maximum_attempts" between 1 and 65535
        and "sla_evaluation_jobs"."attempt" <= "sla_evaluation_jobs"."maximum_attempts"
        and "sla_evaluation_jobs"."fence" between 0 and 9223372036854775806
        and "sla_evaluation_jobs"."updated_at" >= "sla_evaluation_jobs"."created_at"
        and ("sla_evaluation_jobs"."last_failure_code" is null or "sla_evaluation_jobs"."last_failure_code" ~ '^[a-z][a-z0-9_.-]{0,127}$')),
	CONSTRAINT "sla_evaluation_jobs_state_check" CHECK (("sla_evaluation_jobs"."status" in ('queued', 'retry_scheduled')
          and "sla_evaluation_jobs"."worker_id" is null and "sla_evaluation_jobs"."lease_expires_at" is null
          and "sla_evaluation_jobs"."completed_at" is null and "sla_evaluation_jobs"."dead_lettered_at" is null)
        or ("sla_evaluation_jobs"."status" = 'leased' and "sla_evaluation_jobs"."worker_id" is not null
          and "sla_evaluation_jobs"."lease_expires_at" is not null and "sla_evaluation_jobs"."lease_expires_at" > "sla_evaluation_jobs"."updated_at"
          and "sla_evaluation_jobs"."completed_at" is null and "sla_evaluation_jobs"."dead_lettered_at" is null)
        or ("sla_evaluation_jobs"."status" = 'completed' and "sla_evaluation_jobs"."worker_id" is null and "sla_evaluation_jobs"."lease_expires_at" is null
          and "sla_evaluation_jobs"."completed_at" is not null and "sla_evaluation_jobs"."dead_lettered_at" is null)
        or ("sla_evaluation_jobs"."status" = 'dead_lettered' and "sla_evaluation_jobs"."worker_id" is null and "sla_evaluation_jobs"."lease_expires_at" is null
          and "sla_evaluation_jobs"."completed_at" is null and "sla_evaluation_jobs"."dead_lettered_at" is not null))
);
--> statement-breakpoint
ALTER TABLE "sla_evaluation_jobs" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "sla_instances" (
	"id" uuid PRIMARY KEY NOT NULL,
	"tenant_id" uuid NOT NULL,
	"object_type" "sla_object_type" NOT NULL,
	"object_id" uuid NOT NULL,
	"policy_id" uuid NOT NULL,
	"policy_version" integer NOT NULL,
	"aggregate_version" integer NOT NULL,
	"assignment_event_id" uuid NOT NULL,
	"created_at" timestamp with time zone NOT NULL,
	"updated_at" timestamp with time zone NOT NULL,
	"completed_at" timestamp with time zone,
	CONSTRAINT "sla_instances_tenant_id_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "sla_instances_tenant_id_policy_key" UNIQUE("tenant_id","id","policy_id","policy_version"),
	CONSTRAINT "sla_instances_tenant_object_key" UNIQUE("tenant_id","object_type","object_id"),
	CONSTRAINT "sla_instances_tenant_assignment_event_key" UNIQUE("tenant_id","assignment_event_id"),
	CONSTRAINT "sla_instances_id_check" CHECK ((uuid_extract_version("sla_instances"."id") = 7) is true),
	CONSTRAINT "sla_instances_assignment_id_check" CHECK ((uuid_extract_version("sla_instances"."assignment_event_id") = 7) is true),
	CONSTRAINT "sla_instances_version_check" CHECK ("sla_instances"."policy_version" between 1 and 2147483646 and "sla_instances"."aggregate_version" between 1 and 2147483646),
	CONSTRAINT "sla_instances_lifecycle_check" CHECK ("sla_instances"."updated_at" >= "sla_instances"."created_at"
        and ("sla_instances"."completed_at" is null or "sla_instances"."completed_at" between "sla_instances"."created_at" and "sla_instances"."updated_at"))
);
--> statement-breakpoint
ALTER TABLE "sla_instances" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "sla_materialized_column_values" (
	"tenant_id" uuid NOT NULL,
	"object_type" "sla_object_type" NOT NULL,
	"object_id" uuid NOT NULL,
	"sla_instance_id" uuid NOT NULL,
	"metric_instance_id" uuid NOT NULL,
	"column_id" uuid NOT NULL,
	"column_version" integer NOT NULL,
	"state_value" "sla_metric_state",
	"instant_value" timestamp with time zone,
	"duration_micros_value" bigint,
	"percentage_value" double precision,
	"style_key" text,
	"next_refresh_at" timestamp with time zone,
	"materialized_at" timestamp with time zone NOT NULL,
	CONSTRAINT "sla_materialized_column_values_pkey" PRIMARY KEY("tenant_id","object_type","object_id","column_id"),
	CONSTRAINT "sla_materialized_column_version_check" CHECK ("sla_materialized_column_values"."column_version" between 1 and 2147483646),
	CONSTRAINT "sla_materialized_column_typed_value_check" CHECK (num_nonnulls("sla_materialized_column_values"."state_value", "sla_materialized_column_values"."instant_value", "sla_materialized_column_values"."duration_micros_value", "sla_materialized_column_values"."percentage_value") = 1
        and ("sla_materialized_column_values"."duration_micros_value" is null or "sla_materialized_column_values"."duration_micros_value" between 0 and 3153600000000000)
        and ("sla_materialized_column_values"."percentage_value" is null or "sla_materialized_column_values"."percentage_value" between 0 and 100)
        and ("sla_materialized_column_values"."style_key" is null or "sla_materialized_column_values"."style_key" ~ '^[a-z][a-z0-9_.-]{0,62}[a-z0-9]$')
        and ("sla_materialized_column_values"."next_refresh_at" is null or "sla_materialized_column_values"."next_refresh_at" > "sla_materialized_column_values"."materialized_at"))
);
--> statement-breakpoint
ALTER TABLE "sla_materialized_column_values" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "sla_metric_definitions" (
	"tenant_id" uuid NOT NULL,
	"policy_id" uuid NOT NULL,
	"policy_version" integer NOT NULL,
	"id" uuid DEFAULT uuidv7() NOT NULL,
	"key" text NOT NULL,
	"label" text NOT NULL,
	"description" text DEFAULT '' NOT NULL,
	"duration_micros" bigint NOT NULL,
	"clock" "sla_clock_type" NOT NULL,
	"calendar_id" uuid,
	"calendar_version" integer,
	"start_event" text NOT NULL,
	"pause_event" text,
	"resume_event" text,
	"completion_event" text NOT NULL,
	"reset_event" text,
	"reset_policy" "sla_reset_policy" NOT NULL,
	"warning_kind" "sla_warning_kind" NOT NULL,
	"warning_consumed_percent" integer,
	"warning_remaining_micros" bigint,
	"breach_grace_micros" bigint NOT NULL,
	"display_format" text NOT NULL,
	"customer_visible" boolean NOT NULL,
	"api_visible" boolean NOT NULL,
	"position" integer NOT NULL,
	"definition_digest" "bytea" NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "sla_metric_definitions_pkey" PRIMARY KEY("tenant_id","policy_id","policy_version","id"),
	CONSTRAINT "sla_metric_definitions_tenant_id_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "sla_metric_definitions_policy_key_key" UNIQUE("tenant_id","policy_id","policy_version","key"),
	CONSTRAINT "sla_metric_definitions_policy_position_key" UNIQUE("tenant_id","policy_id","policy_version","position"),
	CONSTRAINT "sla_metric_definitions_id_check" CHECK ((uuid_extract_version("sla_metric_definitions"."id") = 7) is true),
	CONSTRAINT "sla_metric_definitions_identity_check" CHECK ("sla_metric_definitions"."key" ~ '^[a-z][a-z0-9_.-]{0,62}[a-z0-9]$' and "sla_metric_definitions"."policy_version" between 1 and 2147483646
        and "sla_metric_definitions"."position" between 0 and 31),
	CONSTRAINT "sla_metric_definitions_text_check" CHECK (btrim("sla_metric_definitions"."label") <> '' and octet_length("sla_metric_definitions"."label") <= 256
        and "sla_metric_definitions"."label" !~ '[[:cntrl:]]'
        and octet_length("sla_metric_definitions"."description") <= 8192
        and "sla_metric_definitions"."description" !~ '[[:cntrl:]]'
        and "sla_metric_definitions"."display_format" ~ '^[a-z][a-z0-9_.-]{0,127}$'),
	CONSTRAINT "sla_metric_definitions_duration_check" CHECK ("sla_metric_definitions"."duration_micros" between 1 and 3153600000000000
        and "sla_metric_definitions"."breach_grace_micros" between 0 and "sla_metric_definitions"."duration_micros"),
	CONSTRAINT "sla_metric_definitions_calendar_check" CHECK (("sla_metric_definitions"."clock" = 'elapsed' and "sla_metric_definitions"."calendar_id" is null and "sla_metric_definitions"."calendar_version" is null)
        or ("sla_metric_definitions"."clock" = 'business' and "sla_metric_definitions"."calendar_id" is not null and "sla_metric_definitions"."calendar_version" between 1 and 2147483646)),
	CONSTRAINT "sla_metric_definitions_events_check" CHECK ("sla_metric_definitions"."start_event" ~ '^[a-z][a-z0-9_.-]{0,62}[a-z0-9]$' and "sla_metric_definitions"."completion_event" ~ '^[a-z][a-z0-9_.-]{0,62}[a-z0-9]$'
        and "sla_metric_definitions"."start_event" <> "sla_metric_definitions"."completion_event"
        and ("sla_metric_definitions"."pause_event" is null) = ("sla_metric_definitions"."resume_event" is null)
        and ("sla_metric_definitions"."pause_event" is null or ("sla_metric_definitions"."pause_event" ~ '^[a-z][a-z0-9_.-]{0,62}[a-z0-9]$' and "sla_metric_definitions"."resume_event" ~ '^[a-z][a-z0-9_.-]{0,62}[a-z0-9]$'))
        and ("sla_metric_definitions"."reset_policy" = 'ignore') = ("sla_metric_definitions"."reset_event" is null)
        and ("sla_metric_definitions"."reset_event" is null or "sla_metric_definitions"."reset_event" ~ '^[a-z][a-z0-9_.-]{0,62}[a-z0-9]$')
        and ("sla_metric_definitions"."pause_event" is null or (
          "sla_metric_definitions"."pause_event" <> "sla_metric_definitions"."start_event"
          and "sla_metric_definitions"."pause_event" <> "sla_metric_definitions"."completion_event"
          and "sla_metric_definitions"."resume_event" <> "sla_metric_definitions"."start_event"
          and "sla_metric_definitions"."resume_event" <> "sla_metric_definitions"."completion_event"
          and "sla_metric_definitions"."pause_event" <> "sla_metric_definitions"."resume_event"
        ))
        and ("sla_metric_definitions"."reset_event" is null or (
          "sla_metric_definitions"."reset_event" <> "sla_metric_definitions"."start_event"
          and "sla_metric_definitions"."reset_event" <> "sla_metric_definitions"."completion_event"
          and ("sla_metric_definitions"."pause_event" is null or (
            "sla_metric_definitions"."reset_event" <> "sla_metric_definitions"."pause_event"
            and "sla_metric_definitions"."reset_event" <> "sla_metric_definitions"."resume_event"
          ))
        ))),
	CONSTRAINT "sla_metric_definitions_warning_check" CHECK (("sla_metric_definitions"."warning_kind" = 'none'
          and "sla_metric_definitions"."warning_consumed_percent" is null
          and "sla_metric_definitions"."warning_remaining_micros" is null)
        or ("sla_metric_definitions"."warning_kind" = 'consumed_percent'
          and "sla_metric_definitions"."warning_consumed_percent" between 1 and 99
          and "sla_metric_definitions"."warning_remaining_micros" is null)
        or ("sla_metric_definitions"."warning_kind" = 'remaining_duration'
          and "sla_metric_definitions"."warning_consumed_percent" is null
          and "sla_metric_definitions"."warning_remaining_micros" between 1 and "sla_metric_definitions"."duration_micros" - 1)),
	CONSTRAINT "sla_metric_definitions_digest_check" CHECK (octet_length("sla_metric_definitions"."definition_digest") = 32)
);
--> statement-breakpoint
ALTER TABLE "sla_metric_definitions" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "sla_metric_instances" (
	"id" uuid PRIMARY KEY NOT NULL,
	"tenant_id" uuid NOT NULL,
	"sla_instance_id" uuid NOT NULL,
	"definition_id" uuid NOT NULL,
	"policy_id" uuid NOT NULL,
	"policy_version" integer NOT NULL,
	"version" integer NOT NULL,
	"lifecycle" "sla_metric_lifecycle" NOT NULL,
	"state" "sla_metric_state" NOT NULL,
	"created_at" timestamp with time zone NOT NULL,
	"updated_at" timestamp with time zone NOT NULL,
	"extension_micros" bigint NOT NULL,
	"consumed_micros" bigint NOT NULL,
	"started_at" timestamp with time zone,
	"last_resumed_at" timestamp with time zone,
	"paused_at" timestamp with time zone,
	"completed_at" timestamp with time zone,
	"due_at" timestamp with time zone,
	"breach_threshold_at" timestamp with time zone,
	"breached_at" timestamp with time zone,
	"last_event_id" uuid,
	"last_event_key" text,
	"last_event_at" timestamp with time zone,
	"last_override_id" uuid,
	"last_override_digest" "bytea",
	CONSTRAINT "sla_metric_instances_tenant_id_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "sla_metric_instances_sla_definition_key" UNIQUE("tenant_id","sla_instance_id","definition_id"),
	CONSTRAINT "sla_metric_instances_id_check" CHECK ((uuid_extract_version("sla_metric_instances"."id") = 7) is true),
	CONSTRAINT "sla_metric_instances_version_check" CHECK ("sla_metric_instances"."policy_version" between 1 and 2147483646 and "sla_metric_instances"."version" between 1 and 2147483646),
	CONSTRAINT "sla_metric_instances_duration_check" CHECK ("sla_metric_instances"."extension_micros" between 0 and 3153600000000000
        and "sla_metric_instances"."consumed_micros" between 0 and 3153600000000000),
	CONSTRAINT "sla_metric_instances_event_check" CHECK (("sla_metric_instances"."last_event_id" is null) = ("sla_metric_instances"."last_event_key" is null)
        and ("sla_metric_instances"."last_event_id" is null) = ("sla_metric_instances"."last_event_at" is null)
        and ("sla_metric_instances"."last_event_id" is null or ((uuid_extract_version("sla_metric_instances"."last_event_id") = 7) is true and "sla_metric_instances"."last_event_key" ~ '^[a-z][a-z0-9_.-]{0,62}[a-z0-9]$'))),
	CONSTRAINT "sla_metric_instances_override_check" CHECK (("sla_metric_instances"."last_override_id" is null) = ("sla_metric_instances"."last_override_digest" is null)
        and ("sla_metric_instances"."last_override_id" is null or ((uuid_extract_version("sla_metric_instances"."last_override_id") = 7) is true and octet_length("sla_metric_instances"."last_override_digest") = 32))),
	CONSTRAINT "sla_metric_instances_lifecycle_check" CHECK ("sla_metric_instances"."updated_at" >= "sla_metric_instances"."created_at"
        and ("sla_metric_instances"."lifecycle" = 'pending'
          and "sla_metric_instances"."started_at" is null and "sla_metric_instances"."last_resumed_at" is null
          and "sla_metric_instances"."paused_at" is null and "sla_metric_instances"."completed_at" is null
          and "sla_metric_instances"."due_at" is null and "sla_metric_instances"."breach_threshold_at" is null
        or "sla_metric_instances"."lifecycle" = 'running'
          and "sla_metric_instances"."started_at" is not null and "sla_metric_instances"."last_resumed_at" is not null
          and "sla_metric_instances"."paused_at" is null and "sla_metric_instances"."completed_at" is null
          and "sla_metric_instances"."due_at" is not null and "sla_metric_instances"."breach_threshold_at" is not null
        or "sla_metric_instances"."lifecycle" = 'paused'
          and "sla_metric_instances"."started_at" is not null and "sla_metric_instances"."last_resumed_at" is null
          and "sla_metric_instances"."paused_at" is not null and "sla_metric_instances"."completed_at" is null
          and "sla_metric_instances"."due_at" is not null and "sla_metric_instances"."breach_threshold_at" is not null
        or "sla_metric_instances"."lifecycle" = 'completed'
          and "sla_metric_instances"."started_at" is not null and "sla_metric_instances"."last_resumed_at" is null
          and "sla_metric_instances"."paused_at" is null and "sla_metric_instances"."completed_at" is not null)
        and ("sla_metric_instances"."breached_at" is null or "sla_metric_instances"."started_at" is not null))
);
--> statement-breakpoint
ALTER TABLE "sla_metric_instances" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "sla_object_event_ledger" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"event_id" uuid NOT NULL,
	"object_type" "sla_object_type" NOT NULL,
	"object_id" uuid NOT NULL,
	"origin" text NOT NULL,
	"origin_id" uuid NOT NULL,
	"key_digest" "bytea" NOT NULL,
	"request_digest" "bytea" NOT NULL,
	"outcome" "sla_event_outcome" NOT NULL,
	"sla_instance_id" uuid,
	"aggregate_version" integer NOT NULL,
	"policy_id" uuid,
	"policy_version" integer NOT NULL,
	"occurred_at" timestamp with time zone NOT NULL,
	"committed_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "sla_object_event_ledger_tenant_id_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "sla_object_event_ledger_event_key" UNIQUE("tenant_id","event_id"),
	CONSTRAINT "sla_object_event_ledger_replay_key" UNIQUE("tenant_id","key_digest"),
	CONSTRAINT "sla_object_event_ledger_id_check" CHECK ((uuid_extract_version("sla_object_event_ledger"."id") = 7) is true),
	CONSTRAINT "sla_object_event_ledger_event_id_check" CHECK ((uuid_extract_version("sla_object_event_ledger"."event_id") = 7) is true),
	CONSTRAINT "sla_object_event_ledger_origin_check" CHECK ("sla_object_event_ledger"."origin" ~ '^[a-z][a-z0-9_.-]{0,127}$' and (uuid_extract_version("sla_object_event_ledger"."origin_id") = 7) is true),
	CONSTRAINT "sla_object_event_ledger_digest_check" CHECK (octet_length("sla_object_event_ledger"."key_digest") = 32 and octet_length("sla_object_event_ledger"."request_digest") = 32),
	CONSTRAINT "sla_object_event_ledger_outcome_check" CHECK (("sla_object_event_ledger"."outcome" = 'no_policy' and "sla_object_event_ledger"."sla_instance_id" is null
          and "sla_object_event_ledger"."aggregate_version" = 0 and "sla_object_event_ledger"."policy_id" is null and "sla_object_event_ledger"."policy_version" = 0)
        or ("sla_object_event_ledger"."outcome" = 'assigned' and "sla_object_event_ledger"."sla_instance_id" is not null
          and "sla_object_event_ledger"."aggregate_version" = 1 and "sla_object_event_ledger"."policy_id" is not null and "sla_object_event_ledger"."policy_version" between 1 and 2147483646)
        or ("sla_object_event_ledger"."outcome" = 'updated' and "sla_object_event_ledger"."sla_instance_id" is not null
          and "sla_object_event_ledger"."aggregate_version" between 2 and 2147483646
          and "sla_object_event_ledger"."policy_id" is not null and "sla_object_event_ledger"."policy_version" between 1 and 2147483646))
);
--> statement-breakpoint
ALTER TABLE "sla_object_event_ledger" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "sla_overrides" (
	"id" uuid PRIMARY KEY NOT NULL,
	"tenant_id" uuid NOT NULL,
	"actor_membership_id" uuid NOT NULL,
	"object_type" "sla_object_type" NOT NULL,
	"object_id" uuid NOT NULL,
	"sla_instance_id" uuid NOT NULL,
	"metric_instance_id" uuid,
	"kind" "sla_override_kind" NOT NULL,
	"reason" text NOT NULL,
	"key_digest" "bytea" NOT NULL,
	"request_digest" "bytea" NOT NULL,
	"command_digest" "bytea" NOT NULL,
	"simulation_digest" "bytea",
	"outcome" "sla_override_outcome" NOT NULL,
	"previous_version" integer NOT NULL,
	"current_version" integer NOT NULL,
	"aggregate_version" integer NOT NULL,
	"policy_id" uuid NOT NULL,
	"policy_version" integer NOT NULL,
	"permission_epoch" bigint NOT NULL,
	"subject_epoch" bigint NOT NULL,
	"previous_snapshot" jsonb NOT NULL,
	"current_snapshot" jsonb NOT NULL,
	"occurred_at" timestamp with time zone NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "sla_overrides_tenant_id_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "sla_overrides_replay_key" UNIQUE("tenant_id","actor_membership_id","key_digest"),
	CONSTRAINT "sla_overrides_id_check" CHECK ((uuid_extract_version("sla_overrides"."id") = 7) is true),
	CONSTRAINT "sla_overrides_reason_check" CHECK (btrim("sla_overrides"."reason") <> '' and octet_length("sla_overrides"."reason") <= 2048
        and "sla_overrides"."reason" !~ '[[:cntrl:]]'),
	CONSTRAINT "sla_overrides_digest_check" CHECK (octet_length("sla_overrides"."key_digest") = 32 and octet_length("sla_overrides"."request_digest") = 32
        and octet_length("sla_overrides"."command_digest") = 32
        and ("sla_overrides"."simulation_digest" is null or octet_length("sla_overrides"."simulation_digest") = 32)),
	CONSTRAINT "sla_overrides_result_check" CHECK ("sla_overrides"."previous_version" between 1 and 2147483646 and "sla_overrides"."current_version" between 1 and 2147483646
        and "sla_overrides"."aggregate_version" between 1 and 2147483646 and "sla_overrides"."policy_version" between 1 and 2147483646
        and "sla_overrides"."current_version" = "sla_overrides"."previous_version" + 1
        and "sla_overrides"."permission_epoch" between 1 and 9223372036854775806
        and "sla_overrides"."subject_epoch" between 1 and 9223372036854775806
        and jsonb_typeof("sla_overrides"."previous_snapshot") = 'object'
        and jsonb_typeof("sla_overrides"."current_snapshot") = 'object'
        and pg_column_size("sla_overrides"."previous_snapshot") <= 65536
        and pg_column_size("sla_overrides"."current_snapshot") <= 65536
        and (("sla_overrides"."outcome" = 'metric_updated' and "sla_overrides"."metric_instance_id" is not null)
          or ("sla_overrides"."outcome" = 'policy_changed' and "sla_overrides"."metric_instance_id" is null
            and "sla_overrides"."aggregate_version" = "sla_overrides"."current_version")))
);
--> statement-breakpoint
ALTER TABLE "sla_overrides" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "sla_policies" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"key" text NOT NULL,
	"active_version" integer DEFAULT 1 NOT NULL,
	"resource_version" integer DEFAULT 1 NOT NULL,
	"created_by_membership_id" uuid NOT NULL,
	"updated_by_membership_id" uuid NOT NULL,
	"archived_by_membership_id" uuid,
	"archived_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "sla_policies_tenant_id_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "sla_policies_tenant_key_key" UNIQUE("tenant_id","key"),
	CONSTRAINT "sla_policies_id_check" CHECK ((uuid_extract_version("sla_policies"."id") = 7) is true),
	CONSTRAINT "sla_policies_key_check" CHECK ("sla_policies"."key" ~ '^[a-z][a-z0-9_.-]{0,62}[a-z0-9]$'),
	CONSTRAINT "sla_policies_version_check" CHECK ("sla_policies"."active_version" between 1 and 2147483646 and "sla_policies"."resource_version" between 1 and 2147483646),
	CONSTRAINT "sla_policies_lifecycle_check" CHECK ("sla_policies"."updated_at" >= "sla_policies"."created_at"
        and ("sla_policies"."archived_at" is null or "sla_policies"."archived_at" between "sla_policies"."created_at" and "sla_policies"."updated_at")
        and ("sla_policies"."archived_at" is null) = ("sla_policies"."archived_by_membership_id" is null))
);
--> statement-breakpoint
ALTER TABLE "sla_policies" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "sla_policy_versions" (
	"tenant_id" uuid NOT NULL,
	"policy_id" uuid NOT NULL,
	"version" integer NOT NULL,
	"name" text NOT NULL,
	"description" text DEFAULT '' NOT NULL,
	"priority" integer NOT NULL,
	"object_types" "sla_object_type"[] NOT NULL,
	"match_rule" jsonb NOT NULL,
	"effective_from" timestamp with time zone NOT NULL,
	"effective_until" timestamp with time zone,
	"enabled" boolean NOT NULL,
	"apply_to_sla_engine_source" boolean DEFAULT false NOT NULL,
	"revision_digest" "bytea" NOT NULL,
	"created_by_membership_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "sla_policy_versions_pkey" PRIMARY KEY("tenant_id","policy_id","version"),
	CONSTRAINT "sla_policy_versions_version_check" CHECK ("sla_policy_versions"."version" between 1 and 2147483646),
	CONSTRAINT "sla_policy_versions_text_check" CHECK (btrim("sla_policy_versions"."name") <> '' and octet_length("sla_policy_versions"."name") <= 256
        and "sla_policy_versions"."name" !~ '[[:cntrl:]]'
        and octet_length("sla_policy_versions"."description") <= 8192
        and "sla_policy_versions"."description" !~ '[[:cntrl:]]'),
	CONSTRAINT "sla_policy_versions_payload_check" CHECK ("sla_policy_versions"."priority" between -1000000 and 1000000
        and cardinality("sla_policy_versions"."object_types") between 1 and 3
        and array_position("sla_policy_versions"."object_types", null) is null
        and jsonb_typeof("sla_policy_versions"."match_rule") = 'object'
        and pg_column_size("sla_policy_versions"."match_rule") <= 262144
        and ("sla_policy_versions"."effective_until" is null or "sla_policy_versions"."effective_until" > "sla_policy_versions"."effective_from")
        and octet_length("sla_policy_versions"."revision_digest") = 32)
);
--> statement-breakpoint
ALTER TABLE "sla_policy_versions" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "sla_trigger_cursors" (
	"tenant_id" uuid NOT NULL,
	"metric_instance_id" uuid NOT NULL,
	"trigger_definition_id" uuid NOT NULL,
	"initialized" boolean NOT NULL,
	"last_observed_at" timestamp with time zone,
	"last_state" "sla_metric_state",
	"last_percentage" double precision DEFAULT 0 NOT NULL,
	"last_remaining_micros" bigint DEFAULT 0 NOT NULL,
	"last_repeat_window" bigint DEFAULT -1 NOT NULL,
	"last_fired_at" timestamp with time zone,
	"fire_count" bigint DEFAULT 0 NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "sla_trigger_cursors_pkey" PRIMARY KEY("tenant_id","metric_instance_id","trigger_definition_id"),
	CONSTRAINT "sla_trigger_cursors_bounds_check" CHECK ("sla_trigger_cursors"."last_percentage" between 0 and 100
        and "sla_trigger_cursors"."last_remaining_micros" between 0 and 3153600000000000
        and "sla_trigger_cursors"."last_repeat_window" between -1 and 3153600000000000
        and "sla_trigger_cursors"."fire_count" between 0 and 9223372036854775806),
	CONSTRAINT "sla_trigger_cursors_state_check" CHECK ((not "sla_trigger_cursors"."initialized"
          and "sla_trigger_cursors"."last_observed_at" is null and "sla_trigger_cursors"."last_state" is null
          and "sla_trigger_cursors"."last_percentage" = 0 and "sla_trigger_cursors"."last_remaining_micros" = 0
          and "sla_trigger_cursors"."last_repeat_window" = -1 and "sla_trigger_cursors"."last_fired_at" is null and "sla_trigger_cursors"."fire_count" = 0)
        or ("sla_trigger_cursors"."initialized" and "sla_trigger_cursors"."last_observed_at" is not null and "sla_trigger_cursors"."last_state" is not null
          and ("sla_trigger_cursors"."last_fired_at" is null) = ("sla_trigger_cursors"."fire_count" = 0)
          and ("sla_trigger_cursors"."last_fired_at" is null or "sla_trigger_cursors"."last_fired_at" <= "sla_trigger_cursors"."last_observed_at")
          and ("sla_trigger_cursors"."last_repeat_window" < 0 or "sla_trigger_cursors"."fire_count" > 0)))
);
--> statement-breakpoint
ALTER TABLE "sla_trigger_cursors" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "sla_trigger_definitions" (
	"tenant_id" uuid NOT NULL,
	"policy_id" uuid NOT NULL,
	"policy_version" integer NOT NULL,
	"id" uuid DEFAULT uuidv7() NOT NULL,
	"metric_definition_id" uuid NOT NULL,
	"key" text NOT NULL,
	"kind" "sla_trigger_kind" NOT NULL,
	"consumed_percent" integer,
	"remaining_micros" bigint,
	"offset_micros" bigint,
	"repeat_interval_micros" bigint,
	"target_state" "sla_metric_state",
	"action_kind" "sla_trigger_action_kind" NOT NULL,
	"action_configuration_id" uuid,
	"action_value" text,
	"allow_recursive_sla" boolean DEFAULT false NOT NULL,
	"position" integer NOT NULL,
	"definition_digest" "bytea" NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "sla_trigger_definitions_pkey" PRIMARY KEY("tenant_id","policy_id","policy_version","id"),
	CONSTRAINT "sla_trigger_definitions_tenant_id_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "sla_trigger_definitions_policy_key_key" UNIQUE("tenant_id","policy_id","policy_version","key"),
	CONSTRAINT "sla_trigger_definitions_policy_position_key" UNIQUE("tenant_id","policy_id","policy_version","position"),
	CONSTRAINT "sla_trigger_definitions_id_check" CHECK ((uuid_extract_version("sla_trigger_definitions"."id") = 7) is true),
	CONSTRAINT "sla_trigger_definitions_identity_check" CHECK ("sla_trigger_definitions"."key" ~ '^[a-z][a-z0-9_.-]{0,62}[a-z0-9]$' and "sla_trigger_definitions"."policy_version" between 1 and 2147483646
        and "sla_trigger_definitions"."position" between 0 and 255 and octet_length("sla_trigger_definitions"."definition_digest") = 32),
	CONSTRAINT "sla_trigger_definitions_threshold_check" CHECK (("sla_trigger_definitions"."kind" = 'consumed_percent' and "sla_trigger_definitions"."consumed_percent" between 1 and 100
          and "sla_trigger_definitions"."remaining_micros" is null and "sla_trigger_definitions"."offset_micros" is null
          and "sla_trigger_definitions"."repeat_interval_micros" is null and "sla_trigger_definitions"."target_state" is null)
        or ("sla_trigger_definitions"."kind" = 'remaining_duration' and "sla_trigger_definitions"."consumed_percent" is null
          and "sla_trigger_definitions"."remaining_micros" >= 0 and "sla_trigger_definitions"."offset_micros" is null
          and "sla_trigger_definitions"."repeat_interval_micros" is null and "sla_trigger_definitions"."target_state" is null)
        or ("sla_trigger_definitions"."kind" = 'due' and "sla_trigger_definitions"."consumed_percent" is null
          and "sla_trigger_definitions"."remaining_micros" is null and "sla_trigger_definitions"."offset_micros" is null
          and "sla_trigger_definitions"."repeat_interval_micros" is null and "sla_trigger_definitions"."target_state" is null)
        or ("sla_trigger_definitions"."kind" = 'after_breach' and "sla_trigger_definitions"."consumed_percent" is null
          and "sla_trigger_definitions"."remaining_micros" is null and "sla_trigger_definitions"."offset_micros" >= 0
          and "sla_trigger_definitions"."repeat_interval_micros" is null and "sla_trigger_definitions"."target_state" is null)
        or ("sla_trigger_definitions"."kind" = 'repeated_after_breach' and "sla_trigger_definitions"."consumed_percent" is null
          and "sla_trigger_definitions"."remaining_micros" is null and "sla_trigger_definitions"."offset_micros" >= 0
          and "sla_trigger_definitions"."repeat_interval_micros" > 0 and "sla_trigger_definitions"."target_state" is null)
        or ("sla_trigger_definitions"."kind" = 'state_changed' and "sla_trigger_definitions"."consumed_percent" is null
          and "sla_trigger_definitions"."remaining_micros" is null and "sla_trigger_definitions"."offset_micros" is null
          and "sla_trigger_definitions"."repeat_interval_micros" is null and "sla_trigger_definitions"."target_state" is not null)
        or ("sla_trigger_definitions"."kind" = 'resumed' and "sla_trigger_definitions"."consumed_percent" is null
          and "sla_trigger_definitions"."remaining_micros" is null and "sla_trigger_definitions"."offset_micros" is null
          and "sla_trigger_definitions"."repeat_interval_micros" is null and "sla_trigger_definitions"."target_state" is null)),
	CONSTRAINT "sla_trigger_definitions_action_check" CHECK ((("sla_trigger_definitions"."action_kind" in ('email', 'webhook') and "sla_trigger_definitions"."action_configuration_id" is not null and "sla_trigger_definitions"."action_value" is null)
          or ("sla_trigger_definitions"."action_kind" in ('add_tag', 'change_priority', 'domain_event')
            and "sla_trigger_definitions"."action_configuration_id" is null and "sla_trigger_definitions"."action_value" is not null
            and "sla_trigger_definitions"."action_value" ~ '^[a-z][a-z0-9_.-]{0,62}[a-z0-9]$')
          or ("sla_trigger_definitions"."action_kind" = 'assign_operator_team' and "sla_trigger_definitions"."action_configuration_id" is not null and "sla_trigger_definitions"."action_value" is null)
          or ("sla_trigger_definitions"."action_kind" = 'create_task' and "sla_trigger_definitions"."action_configuration_id" is null
            and "sla_trigger_definitions"."action_value" is not null and octet_length("sla_trigger_definitions"."action_value") <= 2048)
          or ("sla_trigger_definitions"."action_kind" = 'create_system_alert' and "sla_trigger_definitions"."action_configuration_id" is null
            and "sla_trigger_definitions"."action_value" is not null and "sla_trigger_definitions"."action_value" ~ '^[a-z][a-z0-9_.-]{0,62}[a-z0-9]$'))
        and ("sla_trigger_definitions"."allow_recursive_sla" is false or "sla_trigger_definitions"."action_kind" = 'create_system_alert'))
);
--> statement-breakpoint
ALTER TABLE "sla_trigger_definitions" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "sla_trigger_occurrences" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"sla_instance_id" uuid NOT NULL,
	"metric_instance_id" uuid NOT NULL,
	"trigger_definition_id" uuid NOT NULL,
	"scheduled_at" timestamp with time zone NOT NULL,
	"deduplication_digest" "bytea" NOT NULL,
	"action_kind" "sla_trigger_action_kind" NOT NULL,
	"action_configuration_id" uuid,
	"action_value" text,
	"allow_recursive_sla" boolean NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "sla_trigger_occurrences_tenant_id_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "sla_trigger_occurrences_dedup_key" UNIQUE("tenant_id","deduplication_digest"),
	CONSTRAINT "sla_trigger_occurrences_id_check" CHECK ((uuid_extract_version("sla_trigger_occurrences"."id") = 7) is true),
	CONSTRAINT "sla_trigger_occurrences_digest_check" CHECK (octet_length("sla_trigger_occurrences"."deduplication_digest") = 32)
);
--> statement-breakpoint
ALTER TABLE "sla_trigger_occurrences" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "sla_business_calendar_versions" ADD CONSTRAINT "sla_business_calendar_versions_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_business_calendar_versions" ADD CONSTRAINT "sla_business_calendar_versions_shell_fk" FOREIGN KEY ("tenant_id","calendar_id") REFERENCES "public"."sla_business_calendars"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_business_calendar_versions" ADD CONSTRAINT "sla_business_calendar_versions_creator_fk" FOREIGN KEY ("tenant_id","created_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_business_calendars" ADD CONSTRAINT "sla_business_calendars_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_business_calendars" ADD CONSTRAINT "sla_business_calendars_creator_fk" FOREIGN KEY ("tenant_id","created_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_business_calendars" ADD CONSTRAINT "sla_business_calendars_updater_fk" FOREIGN KEY ("tenant_id","updated_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_business_calendars" ADD CONSTRAINT "sla_business_calendars_archiver_fk" FOREIGN KEY ("tenant_id","archived_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_column_versions" ADD CONSTRAINT "sla_column_versions_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_column_versions" ADD CONSTRAINT "sla_column_versions_shell_fk" FOREIGN KEY ("tenant_id","column_id") REFERENCES "public"."sla_columns"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_column_versions" ADD CONSTRAINT "sla_column_versions_metric_fk" FOREIGN KEY ("tenant_id","metric_definition_id") REFERENCES "public"."sla_metric_definitions"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_column_versions" ADD CONSTRAINT "sla_column_versions_creator_fk" FOREIGN KEY ("tenant_id","created_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_columns" ADD CONSTRAINT "sla_columns_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_columns" ADD CONSTRAINT "sla_columns_creator_fk" FOREIGN KEY ("tenant_id","created_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_columns" ADD CONSTRAINT "sla_columns_updater_fk" FOREIGN KEY ("tenant_id","updated_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_columns" ADD CONSTRAINT "sla_columns_archiver_fk" FOREIGN KEY ("tenant_id","archived_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_configuration_commands" ADD CONSTRAINT "sla_configuration_commands_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_configuration_commands" ADD CONSTRAINT "sla_configuration_commands_actor_fk" FOREIGN KEY ("tenant_id","actor_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_evaluation_jobs" ADD CONSTRAINT "sla_evaluation_jobs_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_evaluation_jobs" ADD CONSTRAINT "sla_evaluation_jobs_sla_fk" FOREIGN KEY ("tenant_id","sla_instance_id") REFERENCES "public"."sla_instances"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_instances" ADD CONSTRAINT "sla_instances_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_instances" ADD CONSTRAINT "sla_instances_policy_fk" FOREIGN KEY ("tenant_id","policy_id","policy_version") REFERENCES "public"."sla_policy_versions"("tenant_id","policy_id","version") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_materialized_column_values" ADD CONSTRAINT "sla_materialized_column_values_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_materialized_column_values" ADD CONSTRAINT "sla_materialized_column_values_sla_fk" FOREIGN KEY ("tenant_id","sla_instance_id") REFERENCES "public"."sla_instances"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_materialized_column_values" ADD CONSTRAINT "sla_materialized_column_values_metric_fk" FOREIGN KEY ("tenant_id","metric_instance_id") REFERENCES "public"."sla_metric_instances"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_materialized_column_values" ADD CONSTRAINT "sla_materialized_column_values_column_fk" FOREIGN KEY ("tenant_id","column_id","column_version") REFERENCES "public"."sla_column_versions"("tenant_id","column_id","version") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_metric_definitions" ADD CONSTRAINT "sla_metric_definitions_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_metric_definitions" ADD CONSTRAINT "sla_metric_definitions_policy_fk" FOREIGN KEY ("tenant_id","policy_id","policy_version") REFERENCES "public"."sla_policy_versions"("tenant_id","policy_id","version") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_metric_definitions" ADD CONSTRAINT "sla_metric_definitions_calendar_fk" FOREIGN KEY ("tenant_id","calendar_id","calendar_version") REFERENCES "public"."sla_business_calendar_versions"("tenant_id","calendar_id","version") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_metric_instances" ADD CONSTRAINT "sla_metric_instances_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_metric_instances" ADD CONSTRAINT "sla_metric_instances_sla_fk" FOREIGN KEY ("tenant_id","sla_instance_id","policy_id","policy_version") REFERENCES "public"."sla_instances"("tenant_id","id","policy_id","policy_version") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_metric_instances" ADD CONSTRAINT "sla_metric_instances_definition_fk" FOREIGN KEY ("tenant_id","definition_id") REFERENCES "public"."sla_metric_definitions"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_metric_instances" ADD CONSTRAINT "sla_metric_instances_policy_fk" FOREIGN KEY ("tenant_id","policy_id","policy_version") REFERENCES "public"."sla_policy_versions"("tenant_id","policy_id","version") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_object_event_ledger" ADD CONSTRAINT "sla_object_event_ledger_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_object_event_ledger" ADD CONSTRAINT "sla_object_event_ledger_sla_fk" FOREIGN KEY ("tenant_id","sla_instance_id") REFERENCES "public"."sla_instances"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_overrides" ADD CONSTRAINT "sla_overrides_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_overrides" ADD CONSTRAINT "sla_overrides_actor_fk" FOREIGN KEY ("tenant_id","actor_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_overrides" ADD CONSTRAINT "sla_overrides_sla_fk" FOREIGN KEY ("tenant_id","sla_instance_id") REFERENCES "public"."sla_instances"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_overrides" ADD CONSTRAINT "sla_overrides_metric_fk" FOREIGN KEY ("tenant_id","metric_instance_id") REFERENCES "public"."sla_metric_instances"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_overrides" ADD CONSTRAINT "sla_overrides_policy_fk" FOREIGN KEY ("tenant_id","policy_id","policy_version") REFERENCES "public"."sla_policy_versions"("tenant_id","policy_id","version") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_policies" ADD CONSTRAINT "sla_policies_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_policies" ADD CONSTRAINT "sla_policies_creator_fk" FOREIGN KEY ("tenant_id","created_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_policies" ADD CONSTRAINT "sla_policies_updater_fk" FOREIGN KEY ("tenant_id","updated_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_policies" ADD CONSTRAINT "sla_policies_archiver_fk" FOREIGN KEY ("tenant_id","archived_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_policy_versions" ADD CONSTRAINT "sla_policy_versions_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_policy_versions" ADD CONSTRAINT "sla_policy_versions_shell_fk" FOREIGN KEY ("tenant_id","policy_id") REFERENCES "public"."sla_policies"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_policy_versions" ADD CONSTRAINT "sla_policy_versions_creator_fk" FOREIGN KEY ("tenant_id","created_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_trigger_cursors" ADD CONSTRAINT "sla_trigger_cursors_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_trigger_cursors" ADD CONSTRAINT "sla_trigger_cursors_metric_fk" FOREIGN KEY ("tenant_id","metric_instance_id") REFERENCES "public"."sla_metric_instances"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_trigger_cursors" ADD CONSTRAINT "sla_trigger_cursors_definition_fk" FOREIGN KEY ("tenant_id","trigger_definition_id") REFERENCES "public"."sla_trigger_definitions"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_trigger_definitions" ADD CONSTRAINT "sla_trigger_definitions_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_trigger_definitions" ADD CONSTRAINT "sla_trigger_definitions_metric_fk" FOREIGN KEY ("tenant_id","policy_id","policy_version","metric_definition_id") REFERENCES "public"."sla_metric_definitions"("tenant_id","policy_id","policy_version","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_trigger_occurrences" ADD CONSTRAINT "sla_trigger_occurrences_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_trigger_occurrences" ADD CONSTRAINT "sla_trigger_occurrences_sla_fk" FOREIGN KEY ("tenant_id","sla_instance_id") REFERENCES "public"."sla_instances"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_trigger_occurrences" ADD CONSTRAINT "sla_trigger_occurrences_metric_fk" FOREIGN KEY ("tenant_id","metric_instance_id") REFERENCES "public"."sla_metric_instances"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sla_trigger_occurrences" ADD CONSTRAINT "sla_trigger_occurrences_definition_fk" FOREIGN KEY ("tenant_id","trigger_definition_id") REFERENCES "public"."sla_trigger_definitions"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "sla_business_calendars_inventory_idx" ON "sla_business_calendars" USING btree ("tenant_id","archived_at","key","id");--> statement-breakpoint
CREATE INDEX "sla_column_versions_metric_idx" ON "sla_column_versions" USING btree ("tenant_id","metric_definition_id","position","column_id");--> statement-breakpoint
CREATE INDEX "sla_columns_inventory_idx" ON "sla_columns" USING btree ("tenant_id","archived_at","key","id");--> statement-breakpoint
CREATE INDEX "sla_configuration_commands_expiry_idx" ON "sla_configuration_commands" USING btree ("expires_at");--> statement-breakpoint
CREATE UNIQUE INDEX "sla_evaluation_jobs_live_aggregate_key" ON "sla_evaluation_jobs" USING btree ("tenant_id","sla_instance_id") WHERE "sla_evaluation_jobs"."status" in ('queued', 'leased', 'retry_scheduled');--> statement-breakpoint
CREATE INDEX "sla_evaluation_jobs_claim_idx" ON "sla_evaluation_jobs" USING btree ("available_at","tenant_id","id") WHERE "sla_evaluation_jobs"."status" in ('queued', 'retry_scheduled');--> statement-breakpoint
CREATE INDEX "sla_evaluation_jobs_reclaim_idx" ON "sla_evaluation_jobs" USING btree ("lease_expires_at","tenant_id","id") WHERE "sla_evaluation_jobs"."status" = 'leased';--> statement-breakpoint
CREATE INDEX "sla_instances_object_projection_idx" ON "sla_instances" USING btree ("tenant_id","object_type","object_id","aggregate_version");--> statement-breakpoint
CREATE INDEX "sla_materialized_column_instant_sort_idx" ON "sla_materialized_column_values" USING btree ("tenant_id","object_type","column_id","instant_value","object_id");--> statement-breakpoint
CREATE INDEX "sla_materialized_column_duration_sort_idx" ON "sla_materialized_column_values" USING btree ("tenant_id","object_type","column_id","duration_micros_value","object_id");--> statement-breakpoint
CREATE INDEX "sla_materialized_column_percent_sort_idx" ON "sla_materialized_column_values" USING btree ("tenant_id","object_type","column_id","percentage_value","object_id");--> statement-breakpoint
CREATE INDEX "sla_materialized_column_state_filter_idx" ON "sla_materialized_column_values" USING btree ("tenant_id","object_type","column_id","state_value","object_id");--> statement-breakpoint
CREATE INDEX "sla_metric_instances_schedule_idx" ON "sla_metric_instances" USING btree ("tenant_id","lifecycle","due_at","id");--> statement-breakpoint
CREATE INDEX "sla_metric_instances_state_idx" ON "sla_metric_instances" USING btree ("tenant_id","state","due_at","id");--> statement-breakpoint
CREATE INDEX "sla_object_event_ledger_object_idx" ON "sla_object_event_ledger" USING btree ("tenant_id","object_type","object_id","occurred_at","event_id");--> statement-breakpoint
CREATE INDEX "sla_overrides_object_history_idx" ON "sla_overrides" USING btree ("tenant_id","object_type","object_id","occurred_at","id");--> statement-breakpoint
CREATE INDEX "sla_policies_inventory_idx" ON "sla_policies" USING btree ("tenant_id","archived_at","key","id");--> statement-breakpoint
CREATE INDEX "sla_policy_versions_match_idx" ON "sla_policy_versions" USING btree ("tenant_id","enabled","priority","effective_from","policy_id","version");--> statement-breakpoint
CREATE INDEX "sla_trigger_occurrences_history_idx" ON "sla_trigger_occurrences" USING btree ("tenant_id","sla_instance_id","scheduled_at","id");--> statement-breakpoint
CREATE POLICY "sla_business_calendar_versions_api_tenant" ON "sla_business_calendar_versions" AS PERMISSIVE FOR ALL TO "periapsis_api" USING (
  "sla_business_calendar_versions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_business_calendar_versions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "sla_business_calendar_versions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_business_calendar_versions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "sla_business_calendars_api_tenant" ON "sla_business_calendars" AS PERMISSIVE FOR ALL TO "periapsis_api" USING (
  "sla_business_calendars"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_business_calendars"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "sla_business_calendars"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_business_calendars"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "sla_column_versions_api_tenant" ON "sla_column_versions" AS PERMISSIVE FOR ALL TO "periapsis_api" USING (
  "sla_column_versions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_column_versions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "sla_column_versions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_column_versions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "sla_column_versions_worker_tenant" ON "sla_column_versions" AS PERMISSIVE FOR ALL TO "periapsis_worker" USING ("sla_column_versions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK ("sla_column_versions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid);--> statement-breakpoint
CREATE POLICY "sla_columns_api_tenant" ON "sla_columns" AS PERMISSIVE FOR ALL TO "periapsis_api" USING (
  "sla_columns"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_columns"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "sla_columns"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_columns"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "sla_configuration_commands_api_tenant" ON "sla_configuration_commands" AS PERMISSIVE FOR ALL TO "periapsis_api" USING (
  "sla_configuration_commands"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_configuration_commands"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "sla_configuration_commands"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_configuration_commands"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "sla_evaluation_jobs_worker_tenant" ON "sla_evaluation_jobs" AS PERMISSIVE FOR ALL TO "periapsis_worker" USING ("sla_evaluation_jobs"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK ("sla_evaluation_jobs"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid);--> statement-breakpoint
CREATE POLICY "sla_instances_api_tenant" ON "sla_instances" AS PERMISSIVE FOR ALL TO "periapsis_api" USING (
  "sla_instances"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_instances"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "sla_instances"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_instances"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "sla_instances_worker_tenant" ON "sla_instances" AS PERMISSIVE FOR ALL TO "periapsis_worker" USING ("sla_instances"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK ("sla_instances"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid);--> statement-breakpoint
CREATE POLICY "sla_materialized_columns_api_tenant" ON "sla_materialized_column_values" AS PERMISSIVE FOR ALL TO "periapsis_api" USING (
  "sla_materialized_column_values"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_materialized_column_values"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "sla_materialized_column_values"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_materialized_column_values"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "sla_materialized_columns_worker_tenant" ON "sla_materialized_column_values" AS PERMISSIVE FOR ALL TO "periapsis_worker" USING ("sla_materialized_column_values"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK ("sla_materialized_column_values"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid);--> statement-breakpoint
CREATE POLICY "sla_metric_definitions_api_tenant" ON "sla_metric_definitions" AS PERMISSIVE FOR ALL TO "periapsis_api" USING (
  "sla_metric_definitions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_metric_definitions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "sla_metric_definitions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_metric_definitions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "sla_metric_definitions_worker_tenant" ON "sla_metric_definitions" AS PERMISSIVE FOR ALL TO "periapsis_worker" USING ("sla_metric_definitions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK ("sla_metric_definitions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid);--> statement-breakpoint
CREATE POLICY "sla_metric_instances_api_tenant" ON "sla_metric_instances" AS PERMISSIVE FOR ALL TO "periapsis_api" USING (
  "sla_metric_instances"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_metric_instances"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "sla_metric_instances"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_metric_instances"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "sla_metric_instances_worker_tenant" ON "sla_metric_instances" AS PERMISSIVE FOR ALL TO "periapsis_worker" USING ("sla_metric_instances"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK ("sla_metric_instances"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid);--> statement-breakpoint
CREATE POLICY "sla_object_event_ledger_api_tenant" ON "sla_object_event_ledger" AS PERMISSIVE FOR ALL TO "periapsis_api" USING (
  "sla_object_event_ledger"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_object_event_ledger"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "sla_object_event_ledger"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_object_event_ledger"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "sla_overrides_api_tenant" ON "sla_overrides" AS PERMISSIVE FOR ALL TO "periapsis_api" USING (
  "sla_overrides"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_overrides"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "sla_overrides"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_overrides"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "sla_policies_api_tenant" ON "sla_policies" AS PERMISSIVE FOR ALL TO "periapsis_api" USING (
  "sla_policies"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_policies"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "sla_policies"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_policies"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "sla_policy_versions_api_tenant" ON "sla_policy_versions" AS PERMISSIVE FOR ALL TO "periapsis_api" USING (
  "sla_policy_versions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_policy_versions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "sla_policy_versions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_policy_versions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "sla_trigger_cursors_api_tenant" ON "sla_trigger_cursors" AS PERMISSIVE FOR ALL TO "periapsis_api" USING (
  "sla_trigger_cursors"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_trigger_cursors"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "sla_trigger_cursors"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_trigger_cursors"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "sla_trigger_cursors_worker_tenant" ON "sla_trigger_cursors" AS PERMISSIVE FOR ALL TO "periapsis_worker" USING ("sla_trigger_cursors"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK ("sla_trigger_cursors"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid);--> statement-breakpoint
CREATE POLICY "sla_trigger_definitions_api_tenant" ON "sla_trigger_definitions" AS PERMISSIVE FOR ALL TO "periapsis_api" USING (
  "sla_trigger_definitions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_trigger_definitions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "sla_trigger_definitions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_trigger_definitions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "sla_trigger_definitions_worker_tenant" ON "sla_trigger_definitions" AS PERMISSIVE FOR ALL TO "periapsis_worker" USING ("sla_trigger_definitions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK ("sla_trigger_definitions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid);--> statement-breakpoint
CREATE POLICY "sla_trigger_occurrences_api_tenant" ON "sla_trigger_occurrences" AS PERMISSIVE FOR ALL TO "periapsis_api" USING (
  "sla_trigger_occurrences"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_trigger_occurrences"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "sla_trigger_occurrences"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_trigger_occurrences"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "sla_trigger_occurrences_worker_tenant" ON "sla_trigger_occurrences" AS PERMISSIVE FOR ALL TO "periapsis_worker" USING ("sla_trigger_occurrences"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK ("sla_trigger_occurrences"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid);