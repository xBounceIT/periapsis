CREATE TYPE "public"."custom_field_audience" AS ENUM('customer', 'operator');--> statement-breakpoint
CREATE TYPE "public"."custom_field_data_type" AS ENUM('short_text', 'long_text', 'integer', 'decimal', 'boolean', 'date', 'datetime', 'duration', 'single_select', 'multi_select', 'url', 'email', 'ip', 'cidr', 'user', 'operator_team', 'customer_contact', 'asset_reference', 'ioc_reference', 'structured_json');--> statement-breakpoint
CREATE TYPE "public"."custom_field_migration_kind" AS ENUM('data_type', 'option_removal', 'constraints');--> statement-breakpoint
CREATE TYPE "public"."custom_field_migration_status" AS ENUM('planned', 'running', 'completed', 'failed', 'cancelled');--> statement-breakpoint
CREATE TYPE "public"."custom_field_object_type" AS ENUM('alert', 'case');--> statement-breakpoint
CREATE TYPE "public"."custom_field_value_presence" AS ENUM('null', 'present');--> statement-breakpoint
CREATE TYPE "public"."dfir_asset_criticality" AS ENUM('low', 'medium', 'high', 'critical');--> statement-breakpoint
CREATE TYPE "public"."dfir_custody_action" AS ENUM('collected', 'accessed', 'transferred', 'sealed', 'unsealed', 'scan_state_changed', 'retention_changed', 'legal_hold_placed', 'legal_hold_released', 'destroyed');--> statement-breakpoint
CREATE TYPE "public"."dfir_entity_kind" AS ENUM('alert', 'case', 'ioc', 'asset', 'evidence', 'task', 'attachment', 'external');--> statement-breakpoint
CREATE TYPE "public"."dfir_evidence_classification" AS ENUM('public', 'internal', 'confidential', 'restricted');--> statement-breakpoint
CREATE TYPE "public"."dfir_indicator_type" AS ENUM('ipv4', 'ipv6', 'domain', 'hostname', 'url', 'email', 'md5', 'sha1', 'sha256', 'sha512', 'filename', 'registry_key', 'process', 'mutex', 'cve', 'custom');--> statement-breakpoint
CREATE TYPE "public"."dfir_malicious_state" AS ENUM('unknown', 'benign', 'suspicious', 'confirmed');--> statement-breakpoint
CREATE TYPE "public"."dfir_scan_state" AS ENUM('pending_upload', 'uploaded', 'verifying', 'quarantined', 'scanning', 'available', 'rejected', 'scan_failed', 'retained', 'deleted');--> statement-breakpoint
CREATE TYPE "public"."dfir_task_priority" AS ENUM('low', 'medium', 'high', 'urgent');--> statement-breakpoint
CREATE TYPE "public"."dfir_task_status" AS ENUM('todo', 'in_progress', 'blocked', 'done', 'cancelled');--> statement-breakpoint
CREATE TYPE "public"."dfir_temporal_precision" AS ENUM('year', 'month', 'day', 'hour', 'minute', 'second', 'millisecond', 'microsecond');--> statement-breakpoint
CREATE TYPE "public"."dfir_tlp" AS ENUM('red', 'amber', 'green', 'clear');--> statement-breakpoint
CREATE TYPE "public"."dfir_visibility" AS ENUM('public', 'private');--> statement-breakpoint
CREATE TABLE "custom_field_definition_revisions" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"definition_id" uuid NOT NULL,
	"object_type" "custom_field_object_type" NOT NULL,
	"schema_version" bigint NOT NULL,
	"snapshot" jsonb NOT NULL,
	"created_by_membership_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "custom_field_definition_revisions_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "custom_field_definition_revisions_version_key" UNIQUE("tenant_id","definition_id","schema_version"),
	CONSTRAINT "custom_field_definition_revisions_id_uuidv7_check" CHECK ((uuid_extract_version("custom_field_definition_revisions"."id") = 7) is true),
	CONSTRAINT "custom_field_definition_revisions_version_check" CHECK ("custom_field_definition_revisions"."schema_version" between 1 and 9223372036854775806),
	CONSTRAINT "custom_field_definition_revisions_snapshot_check" CHECK (jsonb_typeof("custom_field_definition_revisions"."snapshot") = 'object' and pg_column_size("custom_field_definition_revisions"."snapshot") <= 262144)
);
--> statement-breakpoint
ALTER TABLE "custom_field_definition_revisions" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "custom_field_definitions" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"object_type" "custom_field_object_type" NOT NULL,
	"key" text NOT NULL,
	"label" text NOT NULL,
	"description" text DEFAULT '' NOT NULL,
	"data_type" "custom_field_data_type" NOT NULL,
	"required" boolean DEFAULT false NOT NULL,
	"nullable" boolean DEFAULT false NOT NULL,
	"has_default" boolean DEFAULT false NOT NULL,
	"default_value" jsonb,
	"minimum_length" integer,
	"maximum_length" integer,
	"minimum_number" text,
	"maximum_number" text,
	"validation_pattern" text,
	"show_in_create" boolean DEFAULT true NOT NULL,
	"show_in_detail" boolean DEFAULT true NOT NULL,
	"show_in_list" boolean DEFAULT false NOT NULL,
	"show_in_export" boolean DEFAULT false NOT NULL,
	"required_on_transitions" text[] DEFAULT ARRAY[]::text[] NOT NULL,
	"searchable" boolean DEFAULT false NOT NULL,
	"filterable" boolean DEFAULT false NOT NULL,
	"sortable" boolean DEFAULT false NOT NULL,
	"allow_structured_json" boolean DEFAULT false NOT NULL,
	"schema_version" bigint DEFAULT 1 NOT NULL,
	"created_by_membership_id" uuid NOT NULL,
	"updated_by_membership_id" uuid NOT NULL,
	"archived_by_membership_id" uuid,
	"archived_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "custom_field_definitions_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "custom_field_definitions_tenant_object_key_key" UNIQUE("tenant_id","object_type","key"),
	CONSTRAINT "custom_field_definitions_id_uuidv7_check" CHECK ((uuid_extract_version("custom_field_definitions"."id") = 7) is true),
	CONSTRAINT "custom_field_definitions_key_check" CHECK ("custom_field_definitions"."key" ~ '^[a-z][a-z0-9_.-]{0,63}$'),
	CONSTRAINT "custom_field_definitions_text_check" CHECK (btrim("custom_field_definitions"."label") <> '' and octet_length("custom_field_definitions"."label") <= 256
        and "custom_field_definitions"."label" !~ '[[:cntrl:]]'
        and octet_length("custom_field_definitions"."description") <= 8192
        and "custom_field_definitions"."description" !~ '[[:cntrl:]‪-‮⁦-⁩]'),
	CONSTRAINT "custom_field_definitions_default_check" CHECK (("custom_field_definitions"."has_default" and "custom_field_definitions"."default_value" is not null and pg_column_size("custom_field_definitions"."default_value") <= 65536)
        or (not "custom_field_definitions"."has_default" and "custom_field_definitions"."default_value" is null)),
	CONSTRAINT "custom_field_definitions_length_check" CHECK (("custom_field_definitions"."minimum_length" is null or "custom_field_definitions"."minimum_length" between 0 and 65536)
        and ("custom_field_definitions"."maximum_length" is null or "custom_field_definitions"."maximum_length" between 0 and 65536)
        and ("custom_field_definitions"."minimum_length" is null or "custom_field_definitions"."maximum_length" is null or "custom_field_definitions"."minimum_length" <= "custom_field_definitions"."maximum_length")),
	CONSTRAINT "custom_field_definitions_numeric_check" CHECK (("custom_field_definitions"."minimum_number" is null or "custom_field_definitions"."minimum_number" ~ '^-?(0|[1-9][0-9]*)(\.[0-9]+)?$')
        and ("custom_field_definitions"."maximum_number" is null or "custom_field_definitions"."maximum_number" ~ '^-?(0|[1-9][0-9]*)(\.[0-9]+)?$')
        and ("custom_field_definitions"."minimum_number" is null or octet_length("custom_field_definitions"."minimum_number") <= 256)
        and ("custom_field_definitions"."maximum_number" is null or octet_length("custom_field_definitions"."maximum_number") <= 256)),
	CONSTRAINT "custom_field_definitions_pattern_check" CHECK ("custom_field_definitions"."validation_pattern" is null or octet_length("custom_field_definitions"."validation_pattern") between 1 and 512),
	CONSTRAINT "custom_field_definitions_transition_check" CHECK (cardinality("custom_field_definitions"."required_on_transitions") <= 128),
	CONSTRAINT "custom_field_definitions_structured_json_check" CHECK (("custom_field_definitions"."data_type" = 'structured_json') = "custom_field_definitions"."allow_structured_json"),
	CONSTRAINT "custom_field_definitions_schema_version_check" CHECK ("custom_field_definitions"."schema_version" between 1 and 9223372036854775806),
	CONSTRAINT "custom_field_definitions_archive_check" CHECK (("custom_field_definitions"."archived_at" is null) = ("custom_field_definitions"."archived_by_membership_id" is null)
        and ("custom_field_definitions"."archived_at" is null or (not "custom_field_definitions"."required" and not "custom_field_definitions"."show_in_create"))),
	CONSTRAINT "custom_field_definitions_timestamps_check" CHECK ("custom_field_definitions"."updated_at" >= "custom_field_definitions"."created_at"
        and ("custom_field_definitions"."archived_at" is null or "custom_field_definitions"."archived_at" >= "custom_field_definitions"."created_at"))
);
--> statement-breakpoint
ALTER TABLE "custom_field_definitions" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "custom_field_layouts" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"object_type" "custom_field_object_type" NOT NULL,
	"audience" "custom_field_audience" NOT NULL,
	"schema_version" bigint DEFAULT 1 NOT NULL,
	"sections" jsonb NOT NULL,
	"updated_by_membership_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "custom_field_layouts_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "custom_field_layouts_tenant_object_audience_key" UNIQUE("tenant_id","object_type","audience"),
	CONSTRAINT "custom_field_layouts_id_uuidv7_check" CHECK ((uuid_extract_version("custom_field_layouts"."id") = 7) is true),
	CONSTRAINT "custom_field_layouts_version_check" CHECK ("custom_field_layouts"."schema_version" between 1 and 9223372036854775806),
	CONSTRAINT "custom_field_layouts_sections_check" CHECK (jsonb_typeof("custom_field_layouts"."sections") = 'array'
        and jsonb_array_length("custom_field_layouts"."sections") between 1 and 64
        and pg_column_size("custom_field_layouts"."sections") <= 262144),
	CONSTRAINT "custom_field_layouts_timestamps_check" CHECK ("custom_field_layouts"."updated_at" >= "custom_field_layouts"."created_at")
);
--> statement-breakpoint
ALTER TABLE "custom_field_layouts" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "custom_field_migrations" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"definition_id" uuid NOT NULL,
	"kind" "custom_field_migration_kind" NOT NULL,
	"from_data_type" "custom_field_data_type" NOT NULL,
	"to_data_type" "custom_field_data_type" NOT NULL,
	"from_schema_version" bigint NOT NULL,
	"to_schema_version" bigint NOT NULL,
	"status" "custom_field_migration_status" DEFAULT 'planned' NOT NULL,
	"plan_digest" text NOT NULL,
	"reason" text NOT NULL,
	"affected_values" bigint,
	"completed_at" timestamp with time zone,
	"created_by_membership_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "custom_field_migrations_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "custom_field_migrations_definition_version_key" UNIQUE("tenant_id","definition_id","to_schema_version"),
	CONSTRAINT "custom_field_migrations_id_uuidv7_check" CHECK ((uuid_extract_version("custom_field_migrations"."id") = 7) is true),
	CONSTRAINT "custom_field_migrations_version_check" CHECK ("custom_field_migrations"."from_schema_version" > 0 and "custom_field_migrations"."to_schema_version" = "custom_field_migrations"."from_schema_version" + 1),
	CONSTRAINT "custom_field_migrations_digest_check" CHECK ("custom_field_migrations"."plan_digest" ~ '^[0-9a-f]{64}$'),
	CONSTRAINT "custom_field_migrations_reason_check" CHECK (btrim("custom_field_migrations"."reason") <> '' and octet_length("custom_field_migrations"."reason") <= 2000 and "custom_field_migrations"."reason" !~ '[[:cntrl:]]'),
	CONSTRAINT "custom_field_migrations_completion_check" CHECK (("custom_field_migrations"."status" = 'completed') = ("custom_field_migrations"."completed_at" is not null)
        and ("custom_field_migrations"."affected_values" is null or "custom_field_migrations"."affected_values" >= 0)
        and "custom_field_migrations"."updated_at" >= "custom_field_migrations"."created_at")
);
--> statement-breakpoint
ALTER TABLE "custom_field_migrations" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "custom_field_options" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"definition_id" uuid NOT NULL,
	"key" text NOT NULL,
	"label" text NOT NULL,
	"position" integer NOT NULL,
	"introduced_in_schema_version" bigint NOT NULL,
	"archived_in_schema_version" bigint,
	"archived_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "custom_field_options_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "custom_field_options_definition_key_key" UNIQUE("tenant_id","definition_id","key"),
	CONSTRAINT "custom_field_options_definition_position_key" UNIQUE("tenant_id","definition_id","position"),
	CONSTRAINT "custom_field_options_id_uuidv7_check" CHECK ((uuid_extract_version("custom_field_options"."id") = 7) is true),
	CONSTRAINT "custom_field_options_key_check" CHECK ("custom_field_options"."key" ~ '^[a-z][a-z0-9_.-]{0,63}$'),
	CONSTRAINT "custom_field_options_label_check" CHECK (btrim("custom_field_options"."label") <> '' and octet_length("custom_field_options"."label") <= 256 and "custom_field_options"."label" !~ '[[:cntrl:]]'),
	CONSTRAINT "custom_field_options_position_check" CHECK ("custom_field_options"."position" between 0 and 65535),
	CONSTRAINT "custom_field_options_version_check" CHECK ("custom_field_options"."introduced_in_schema_version" > 0
        and ("custom_field_options"."archived_in_schema_version" is null or "custom_field_options"."archived_in_schema_version" > "custom_field_options"."introduced_in_schema_version")
        and ("custom_field_options"."archived_in_schema_version" is null) = ("custom_field_options"."archived_at" is null))
);
--> statement-breakpoint
ALTER TABLE "custom_field_options" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "custom_field_permissions" (
	"tenant_id" uuid NOT NULL,
	"definition_id" uuid NOT NULL,
	"audience" "custom_field_audience" NOT NULL,
	"can_read" boolean DEFAULT false NOT NULL,
	"can_create" boolean DEFAULT false NOT NULL,
	"can_update" boolean DEFAULT false NOT NULL,
	"schema_version" bigint NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "custom_field_permissions_key" UNIQUE("tenant_id","definition_id","audience"),
	CONSTRAINT "custom_field_permissions_write_requires_read_check" CHECK ((not "custom_field_permissions"."can_create" and not "custom_field_permissions"."can_update") or "custom_field_permissions"."can_read"),
	CONSTRAINT "custom_field_permissions_version_check" CHECK ("custom_field_permissions"."schema_version" between 1 and 9223372036854775806)
);
--> statement-breakpoint
ALTER TABLE "custom_field_permissions" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "custom_field_values" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"object_type" "custom_field_object_type" NOT NULL,
	"alert_id" uuid,
	"case_id" uuid,
	"definition_id" uuid NOT NULL,
	"definition_schema_version" bigint NOT NULL,
	"data_type" "custom_field_data_type" NOT NULL,
	"presence" "custom_field_value_presence" NOT NULL,
	"canonical_value" jsonb NOT NULL,
	"text_value" text,
	"integer_value" bigint,
	"decimal_value" numeric,
	"boolean_value" boolean,
	"date_value" date,
	"date_time_value" timestamp with time zone,
	"ip_value" "inet",
	"cidr_value" "cidr",
	"reference_id" uuid,
	"option_keys" text[],
	"structured_value" jsonb,
	"created_by_membership_id" uuid NOT NULL,
	"updated_by_membership_id" uuid NOT NULL,
	"version" bigint DEFAULT 1 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "custom_field_values_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "custom_field_values_id_uuidv7_check" CHECK ((uuid_extract_version("custom_field_values"."id") = 7) is true),
	CONSTRAINT "custom_field_values_subject_check" CHECK (("custom_field_values"."object_type" = 'alert' and "custom_field_values"."alert_id" is not null and "custom_field_values"."case_id" is null)
        or ("custom_field_values"."object_type" = 'case' and "custom_field_values"."case_id" is not null and "custom_field_values"."alert_id" is null)),
	CONSTRAINT "custom_field_values_version_check" CHECK ("custom_field_values"."definition_schema_version" > 0 and "custom_field_values"."version" > 0),
	CONSTRAINT "custom_field_values_size_check" CHECK (pg_column_size("custom_field_values"."canonical_value") <= 65536
        and ("custom_field_values"."option_keys" is null or cardinality("custom_field_values"."option_keys") <= 512)
        and ("custom_field_values"."structured_value" is null or (jsonb_typeof("custom_field_values"."structured_value") = 'object' and pg_column_size("custom_field_values"."structured_value") <= 65536))),
	CONSTRAINT "custom_field_values_null_shape_check" CHECK ("custom_field_values"."presence" <> 'null' or (
        "custom_field_values"."canonical_value" = 'null'::jsonb
        and "custom_field_values"."text_value" is null and "custom_field_values"."integer_value" is null
        and "custom_field_values"."decimal_value" is null and "custom_field_values"."boolean_value" is null
        and "custom_field_values"."date_value" is null and "custom_field_values"."date_time_value" is null
        and "custom_field_values"."ip_value" is null and "custom_field_values"."cidr_value" is null
        and "custom_field_values"."reference_id" is null and "custom_field_values"."option_keys" is null
        and "custom_field_values"."structured_value" is null
      )),
	CONSTRAINT "custom_field_values_present_shape_check" CHECK ("custom_field_values"."presence" <> 'present' or (
        case
          when "custom_field_values"."data_type" in ('short_text','long_text','url','email') then "custom_field_values"."text_value" is not null
          when "custom_field_values"."data_type" in ('integer','duration') then "custom_field_values"."integer_value" is not null
          when "custom_field_values"."data_type" = 'decimal' then "custom_field_values"."decimal_value" is not null
          when "custom_field_values"."data_type" = 'boolean' then "custom_field_values"."boolean_value" is not null
          when "custom_field_values"."data_type" = 'date' then "custom_field_values"."date_value" is not null
          when "custom_field_values"."data_type" = 'datetime' then "custom_field_values"."date_time_value" is not null
          when "custom_field_values"."data_type" = 'ip' then "custom_field_values"."ip_value" is not null
          when "custom_field_values"."data_type" = 'cidr' then "custom_field_values"."cidr_value" is not null
          when "custom_field_values"."data_type" in ('user','operator_team','customer_contact','asset_reference','ioc_reference') then "custom_field_values"."reference_id" is not null
          when "custom_field_values"."data_type" = 'single_select' then cardinality("custom_field_values"."option_keys") = 1
          when "custom_field_values"."data_type" = 'multi_select' then "custom_field_values"."option_keys" is not null
          when "custom_field_values"."data_type" = 'structured_json' then "custom_field_values"."structured_value" is not null
          else false
        end
      )),
	CONSTRAINT "custom_field_values_timestamps_check" CHECK ("custom_field_values"."updated_at" >= "custom_field_values"."created_at")
);
--> statement-breakpoint
ALTER TABLE "custom_field_values" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "dfir_activities" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"case_id" uuid NOT NULL,
	"resource_kind" "dfir_entity_kind" NOT NULL,
	"resource_id" uuid NOT NULL,
	"action" text NOT NULL,
	"summary" text NOT NULL,
	"actor_principal_kind" "ticket_principal_kind" NOT NULL,
	"actor_membership_id" uuid,
	"actor_user_id" uuid,
	"actor_service_account_id" uuid,
	"details" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"occurred_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "dfir_activities_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "dfir_activities_id_uuidv7_check" CHECK ((uuid_extract_version("dfir_activities"."id") = 7) is true),
	CONSTRAINT "dfir_activities_resource_check" CHECK ("dfir_activities"."resource_kind" <> 'external'),
	CONSTRAINT "dfir_activities_action_check" CHECK ("dfir_activities"."action" ~ '^dfir\.[a-z][a-z0-9_.-]{1,63}$'),
	CONSTRAINT "dfir_activities_summary_check" CHECK (octet_length("dfir_activities"."summary") between 1 and 512 and "dfir_activities"."summary" !~ '[[:cntrl:]]'),
	CONSTRAINT "dfir_activities_actor_check" CHECK (("dfir_activities"."actor_principal_kind" = 'human' and "dfir_activities"."actor_membership_id" is not null and "dfir_activities"."actor_user_id" is not null and "dfir_activities"."actor_service_account_id" is null) or ("dfir_activities"."actor_principal_kind" = 'service_account' and "dfir_activities"."actor_membership_id" is null and "dfir_activities"."actor_user_id" is null and "dfir_activities"."actor_service_account_id" is not null) or ("dfir_activities"."actor_principal_kind" = 'system' and "dfir_activities"."actor_membership_id" is null and "dfir_activities"."actor_user_id" is null and "dfir_activities"."actor_service_account_id" is null)),
	CONSTRAINT "dfir_activities_details_check" CHECK (jsonb_typeof("dfir_activities"."details") = 'object' and pg_column_size("dfir_activities"."details") <= 65536)
);
--> statement-breakpoint
ALTER TABLE "dfir_activities" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "dfir_asset_links" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"asset_id" uuid NOT NULL,
	"alert_id" uuid,
	"case_id" uuid,
	"created_by_membership_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "dfir_asset_links_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "dfir_asset_links_id_uuidv7_check" CHECK ((uuid_extract_version("dfir_asset_links"."id") = 7) is true),
	CONSTRAINT "dfir_asset_links_subject_check" CHECK (("dfir_asset_links"."alert_id" is null) <> ("dfir_asset_links"."case_id" is null))
);
--> statement-breakpoint
ALTER TABLE "dfir_asset_links" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "dfir_assets" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"hostname" text,
	"normalized_hostname" text,
	"fqdn" text,
	"normalized_fqdn" text,
	"ip_addresses" "inet"[] DEFAULT ARRAY[]::inet[] NOT NULL,
	"mac_addresses" "macaddr"[] DEFAULT ARRAY[]::macaddr[] NOT NULL,
	"mac8_addresses" "macaddr8"[] DEFAULT ARRAY[]::macaddr8[] NOT NULL,
	"original_identifiers" jsonb NOT NULL,
	"asset_type" text NOT NULL,
	"operating_system" text DEFAULT '' NOT NULL,
	"owner" text DEFAULT '' NOT NULL,
	"business_unit" text DEFAULT '' NOT NULL,
	"criticality" "dfir_asset_criticality" NOT NULL,
	"environment" text NOT NULL,
	"external_id" text,
	"tags" text[] DEFAULT ARRAY[]::text[] NOT NULL,
	"first_seen" timestamp with time zone NOT NULL,
	"last_seen" timestamp with time zone NOT NULL,
	"custom_attributes" jsonb,
	"created_by_membership_id" uuid NOT NULL,
	"updated_by_membership_id" uuid NOT NULL,
	"version" bigint DEFAULT 1 NOT NULL,
	"archived_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "dfir_assets_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "dfir_assets_id_uuidv7_check" CHECK ((uuid_extract_version("dfir_assets"."id") = 7) is true),
	CONSTRAINT "dfir_assets_identifier_check" CHECK ("dfir_assets"."hostname" is not null or "dfir_assets"."fqdn" is not null or cardinality("dfir_assets"."ip_addresses") > 0
        or cardinality("dfir_assets"."mac_addresses") > 0 or cardinality("dfir_assets"."mac8_addresses") > 0
        or "dfir_assets"."external_id" is not null),
	CONSTRAINT "dfir_assets_hostname_shape_check" CHECK (("dfir_assets"."hostname" is null) = ("dfir_assets"."normalized_hostname" is null)
        and ("dfir_assets"."fqdn" is null) = ("dfir_assets"."normalized_fqdn" is null)),
	CONSTRAINT "dfir_assets_metadata_check" CHECK ("dfir_assets"."asset_type" ~ '^[a-z][a-z0-9_.-]{0,63}$'
        and "dfir_assets"."environment" ~ '^[a-z][a-z0-9_.-]{0,63}$'
        and octet_length("dfir_assets"."operating_system") <= 512
        and octet_length("dfir_assets"."owner") <= 512 and octet_length("dfir_assets"."business_unit") <= 256
        and ("dfir_assets"."external_id" is null or octet_length("dfir_assets"."external_id") between 1 and 512)
        and cardinality("dfir_assets"."ip_addresses") + cardinality("dfir_assets"."mac_addresses") + cardinality("dfir_assets"."mac8_addresses") <= 512
        and cardinality("dfir_assets"."tags") <= 256 and "dfir_assets"."last_seen" >= "dfir_assets"."first_seen"
        and jsonb_typeof("dfir_assets"."original_identifiers") = 'object'
        and pg_column_size("dfir_assets"."original_identifiers") <= 65536
        and ("dfir_assets"."custom_attributes" is null or (jsonb_typeof("dfir_assets"."custom_attributes") = 'object' and pg_column_size("dfir_assets"."custom_attributes") <= 65536))),
	CONSTRAINT "dfir_assets_version_check" CHECK ("dfir_assets"."version" > 0),
	CONSTRAINT "dfir_assets_timestamps_check" CHECK ("dfir_assets"."updated_at" >= "dfir_assets"."created_at")
);
--> statement-breakpoint
ALTER TABLE "dfir_assets" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "dfir_attachments" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"subject_kind" "dfir_entity_kind" NOT NULL,
	"alert_id" uuid,
	"case_id" uuid,
	"ioc_id" uuid,
	"asset_id" uuid,
	"evidence_id" uuid,
	"task_id" uuid,
	"storage_object_id" uuid NOT NULL,
	"original_filename" text NOT NULL,
	"visibility" "dfir_visibility" NOT NULL,
	"scan_state" "dfir_scan_state" NOT NULL,
	"uploaded_by_membership_id" uuid NOT NULL,
	"uploaded_at" timestamp with time zone NOT NULL,
	"version" bigint DEFAULT 1 NOT NULL,
	CONSTRAINT "dfir_attachments_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "dfir_attachments_storage_key" UNIQUE("tenant_id","storage_object_id"),
	CONSTRAINT "dfir_attachments_id_uuidv7_check" CHECK ((uuid_extract_version("dfir_attachments"."id") = 7) is true),
	CONSTRAINT "dfir_attachments_subject_check" CHECK (num_nonnulls("dfir_attachments"."alert_id","dfir_attachments"."case_id","dfir_attachments"."ioc_id","dfir_attachments"."asset_id","dfir_attachments"."evidence_id","dfir_attachments"."task_id") = 1 and ("dfir_attachments"."subject_kind" = 'alert') = ("dfir_attachments"."alert_id" is not null) and ("dfir_attachments"."subject_kind" = 'case') = ("dfir_attachments"."case_id" is not null) and ("dfir_attachments"."subject_kind" = 'ioc') = ("dfir_attachments"."ioc_id" is not null) and ("dfir_attachments"."subject_kind" = 'asset') = ("dfir_attachments"."asset_id" is not null) and ("dfir_attachments"."subject_kind" = 'evidence') = ("dfir_attachments"."evidence_id" is not null) and ("dfir_attachments"."subject_kind" = 'task') = ("dfir_attachments"."task_id" is not null)),
	CONSTRAINT "dfir_attachments_filename_check" CHECK (octet_length("dfir_attachments"."original_filename") between 1 and 255 and "dfir_attachments"."original_filename" !~ '[/\\[:cntrl:]]' and "dfir_attachments"."original_filename" not in ('.','..')),
	CONSTRAINT "dfir_attachments_state_check" CHECK ("dfir_attachments"."scan_state" <> 'deleted' and "dfir_attachments"."version" > 0)
);
--> statement-breakpoint
ALTER TABLE "dfir_attachments" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "dfir_custody_events" (
	"id" uuid PRIMARY KEY NOT NULL,
	"tenant_id" uuid NOT NULL,
	"evidence_id" uuid NOT NULL,
	"sequence" bigint NOT NULL,
	"action" "dfir_custody_action" NOT NULL,
	"actor_principal_kind" "ticket_principal_kind" NOT NULL,
	"actor_id" uuid NOT NULL,
	"actor_membership_id" uuid,
	"actor_user_id" uuid,
	"actor_service_account_id" uuid,
	"reason" text NOT NULL,
	"state_value" text DEFAULT '' NOT NULL,
	"previous_hash" "bytea" NOT NULL,
	"event_hash" "bytea" NOT NULL,
	"occurred_at" timestamp with time zone NOT NULL,
	CONSTRAINT "dfir_custody_events_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "dfir_custody_events_evidence_sequence_key" UNIQUE("tenant_id","evidence_id","sequence"),
	CONSTRAINT "dfir_custody_events_id_uuidv7_check" CHECK ((uuid_extract_version("dfir_custody_events"."id") = 7) is true),
	CONSTRAINT "dfir_custody_events_sequence_check" CHECK ("dfir_custody_events"."sequence" > 0),
	CONSTRAINT "dfir_custody_events_actor_check" CHECK (("dfir_custody_events"."actor_principal_kind" = 'human' and "dfir_custody_events"."actor_membership_id" is not null and "dfir_custody_events"."actor_user_id" is not null and "dfir_custody_events"."actor_service_account_id" is null and "dfir_custody_events"."actor_id" = "dfir_custody_events"."actor_user_id") or ("dfir_custody_events"."actor_principal_kind" = 'service_account' and "dfir_custody_events"."actor_membership_id" is null and "dfir_custody_events"."actor_user_id" is null and "dfir_custody_events"."actor_service_account_id" is not null and "dfir_custody_events"."actor_id" = "dfir_custody_events"."actor_service_account_id") or ("dfir_custody_events"."actor_principal_kind" = 'system' and "dfir_custody_events"."actor_membership_id" is null and "dfir_custody_events"."actor_user_id" is null and "dfir_custody_events"."actor_service_account_id" is null)),
	CONSTRAINT "dfir_custody_events_reason_check" CHECK (btrim("dfir_custody_events"."reason") <> '' and octet_length("dfir_custody_events"."reason") <= 2000 and "dfir_custody_events"."reason" !~ '[[:cntrl:]]'),
	CONSTRAINT "dfir_custody_events_state_check" CHECK (octet_length("dfir_custody_events"."state_value") <= 512 and "dfir_custody_events"."state_value" !~ '[[:cntrl:]]'),
	CONSTRAINT "dfir_custody_events_hash_check" CHECK (octet_length("dfir_custody_events"."previous_hash") = 32 and octet_length("dfir_custody_events"."event_hash") = 32)
);
--> statement-breakpoint
ALTER TABLE "dfir_custody_events" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "dfir_evidence" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"case_id" uuid NOT NULL,
	"storage_object_id" uuid NOT NULL,
	"title" text NOT NULL,
	"description" text DEFAULT '' NOT NULL,
	"evidence_type" text NOT NULL,
	"classification" "dfir_evidence_classification" NOT NULL,
	"content_sha256" "bytea" NOT NULL,
	"size_bytes" bigint NOT NULL,
	"detected_mime" text NOT NULL,
	"collected_at" timestamp with time zone NOT NULL,
	"collected_by_membership_id" uuid NOT NULL,
	"source" text NOT NULL,
	"initial_retention_until" timestamp with time zone,
	"retention_until" timestamp with time zone,
	"initial_legal_hold" boolean DEFAULT false NOT NULL,
	"legal_hold" boolean DEFAULT false NOT NULL,
	"initial_scan_state" "dfir_scan_state" NOT NULL,
	"scan_state" "dfir_scan_state" NOT NULL,
	"sealed" boolean DEFAULT false NOT NULL,
	"destroyed" boolean DEFAULT false NOT NULL,
	"anchor_hash" "bytea" NOT NULL,
	"custody_head_hash" "bytea" NOT NULL,
	"custody_count" bigint DEFAULT 1 NOT NULL,
	"version" bigint DEFAULT 1 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "dfir_evidence_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "dfir_evidence_storage_object_key" UNIQUE("tenant_id","storage_object_id"),
	CONSTRAINT "dfir_evidence_id_uuidv7_check" CHECK ((uuid_extract_version("dfir_evidence"."id") = 7) is true),
	CONSTRAINT "dfir_evidence_text_check" CHECK (btrim("dfir_evidence"."title") <> '' and octet_length("dfir_evidence"."title") <= 512 and octet_length("dfir_evidence"."description") <= 16384 and "dfir_evidence"."evidence_type" ~ '^[a-z][a-z0-9_.-]{0,63}$' and octet_length("dfir_evidence"."source") between 1 and 512),
	CONSTRAINT "dfir_evidence_content_check" CHECK (octet_length("dfir_evidence"."content_sha256") = 32 and "dfir_evidence"."size_bytes" between 0 and 5497558138880 and octet_length("dfir_evidence"."detected_mime") between 3 and 512),
	CONSTRAINT "dfir_evidence_hash_check" CHECK (octet_length("dfir_evidence"."anchor_hash") = 32 and octet_length("dfir_evidence"."custody_head_hash") = 32),
	CONSTRAINT "dfir_evidence_retention_check" CHECK (("dfir_evidence"."initial_retention_until" is null or "dfir_evidence"."initial_retention_until" >= "dfir_evidence"."collected_at") and ("dfir_evidence"."retention_until" is null or "dfir_evidence"."retention_until" >= "dfir_evidence"."collected_at")),
	CONSTRAINT "dfir_evidence_destroyed_check" CHECK (not "dfir_evidence"."destroyed" or "dfir_evidence"."scan_state" = 'deleted'),
	CONSTRAINT "dfir_evidence_version_check" CHECK ("dfir_evidence"."version" = "dfir_evidence"."custody_count" and "dfir_evidence"."version" between 1 and 9223372036854775807),
	CONSTRAINT "dfir_evidence_timestamps_check" CHECK ("dfir_evidence"."updated_at" >= "dfir_evidence"."created_at")
);
--> statement-breakpoint
ALTER TABLE "dfir_evidence" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "dfir_ioc_links" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"ioc_id" uuid NOT NULL,
	"alert_id" uuid,
	"case_id" uuid,
	"created_by_membership_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "dfir_ioc_links_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "dfir_ioc_links_id_uuidv7_check" CHECK ((uuid_extract_version("dfir_ioc_links"."id") = 7) is true),
	CONSTRAINT "dfir_ioc_links_subject_check" CHECK (("dfir_ioc_links"."alert_id" is null) <> ("dfir_ioc_links"."case_id" is null))
);
--> statement-breakpoint
ALTER TABLE "dfir_ioc_links" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "dfir_iocs" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"type" "dfir_indicator_type" NOT NULL,
	"value" text NOT NULL,
	"normalized_value" text NOT NULL,
	"ip_value" "inet",
	"description" text DEFAULT '' NOT NULL,
	"source" text NOT NULL,
	"confidence" integer NOT NULL,
	"tlp" "dfir_tlp" NOT NULL,
	"first_seen" timestamp with time zone NOT NULL,
	"last_seen" timestamp with time zone NOT NULL,
	"malicious_state" "dfir_malicious_state" NOT NULL,
	"tags" text[] DEFAULT ARRAY[]::text[] NOT NULL,
	"enrichment" jsonb,
	"created_by_membership_id" uuid NOT NULL,
	"updated_by_membership_id" uuid NOT NULL,
	"version" bigint DEFAULT 1 NOT NULL,
	"archived_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "dfir_iocs_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "dfir_iocs_id_uuidv7_check" CHECK ((uuid_extract_version("dfir_iocs"."id") = 7) is true),
	CONSTRAINT "dfir_iocs_value_check" CHECK (btrim("dfir_iocs"."value") <> '' and octet_length("dfir_iocs"."value") <= 8192
        and btrim("dfir_iocs"."normalized_value") <> '' and octet_length("dfir_iocs"."normalized_value") <= 8192
        and "dfir_iocs"."value" !~ '[[:cntrl:]]' and "dfir_iocs"."normalized_value" !~ '[[:cntrl:]]'),
	CONSTRAINT "dfir_iocs_ip_shape_check" CHECK (("dfir_iocs"."type" in ('ipv4','ipv6')) = ("dfir_iocs"."ip_value" is not null)),
	CONSTRAINT "dfir_iocs_metadata_check" CHECK (octet_length("dfir_iocs"."description") <= 16384 and octet_length("dfir_iocs"."source") between 1 and 512
        and "dfir_iocs"."confidence" between 0 and 100 and "dfir_iocs"."last_seen" >= "dfir_iocs"."first_seen"
        and cardinality("dfir_iocs"."tags") <= 256
        and ("dfir_iocs"."enrichment" is null or (jsonb_typeof("dfir_iocs"."enrichment") = 'object' and pg_column_size("dfir_iocs"."enrichment") <= 65536))),
	CONSTRAINT "dfir_iocs_version_check" CHECK ("dfir_iocs"."version" > 0),
	CONSTRAINT "dfir_iocs_timestamps_check" CHECK ("dfir_iocs"."updated_at" >= "dfir_iocs"."created_at")
);
--> statement-breakpoint
ALTER TABLE "dfir_iocs" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "dfir_relationships" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"source_kind" "dfir_entity_kind" NOT NULL,
	"source_id" uuid,
	"source_external_type" text,
	"source_external_id" text,
	"target_kind" "dfir_entity_kind" NOT NULL,
	"target_id" uuid,
	"target_external_type" text,
	"target_external_id" text,
	"relationship_type" text NOT NULL,
	"metadata" jsonb,
	"created_by_membership_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "dfir_relationships_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "dfir_relationships_id_uuidv7_check" CHECK ((uuid_extract_version("dfir_relationships"."id") = 7) is true),
	CONSTRAINT "dfir_relationships_source_check" CHECK (("dfir_relationships"."source_kind" = 'external' and "dfir_relationships"."source_id" is null and "dfir_relationships"."source_external_type" ~ '^[a-z][a-z0-9_.-]{0,63}$' and octet_length("dfir_relationships"."source_external_id") between 1 and 2048) or ("dfir_relationships"."source_kind" <> 'external' and "dfir_relationships"."source_id" is not null and "dfir_relationships"."source_external_type" is null and "dfir_relationships"."source_external_id" is null)),
	CONSTRAINT "dfir_relationships_target_check" CHECK (("dfir_relationships"."target_kind" = 'external' and "dfir_relationships"."target_id" is null and "dfir_relationships"."target_external_type" ~ '^[a-z][a-z0-9_.-]{0,63}$' and octet_length("dfir_relationships"."target_external_id") between 1 and 2048) or ("dfir_relationships"."target_kind" <> 'external' and "dfir_relationships"."target_id" is not null and "dfir_relationships"."target_external_type" is null and "dfir_relationships"."target_external_id" is null)),
	CONSTRAINT "dfir_relationships_distinct_check" CHECK (row("dfir_relationships"."source_kind","dfir_relationships"."source_id","dfir_relationships"."source_external_type","dfir_relationships"."source_external_id") is distinct from row("dfir_relationships"."target_kind","dfir_relationships"."target_id","dfir_relationships"."target_external_type","dfir_relationships"."target_external_id")),
	CONSTRAINT "dfir_relationships_type_check" CHECK ("dfir_relationships"."relationship_type" ~ '^[a-z][a-z0-9_.-]{0,63}$'),
	CONSTRAINT "dfir_relationships_metadata_check" CHECK ("dfir_relationships"."metadata" is null or (jsonb_typeof("dfir_relationships"."metadata") = 'object' and pg_column_size("dfir_relationships"."metadata") <= 65536))
);
--> statement-breakpoint
ALTER TABLE "dfir_relationships" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "dfir_storage_objects" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"bucket" text NOT NULL,
	"object_key" text NOT NULL,
	"original_filename" text NOT NULL,
	"classification" "dfir_evidence_classification" NOT NULL,
	"state" "dfir_scan_state" DEFAULT 'pending_upload' NOT NULL,
	"content_sha256" "bytea",
	"size_bytes" bigint,
	"detected_mime" text,
	"verified_at" timestamp with time zone,
	"retention_until" timestamp with time zone,
	"legal_hold" boolean DEFAULT false NOT NULL,
	"created_by_membership_id" uuid NOT NULL,
	"version" bigint DEFAULT 1 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "dfir_storage_objects_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "dfir_storage_objects_location_key" UNIQUE("tenant_id","bucket","object_key"),
	CONSTRAINT "dfir_storage_objects_id_uuidv7_check" CHECK ((uuid_extract_version("dfir_storage_objects"."id") = 7) is true),
	CONSTRAINT "dfir_storage_objects_bucket_check" CHECK ("dfir_storage_objects"."bucket" ~ '^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$' and "dfir_storage_objects"."bucket" !~ '\.\.'),
	CONSTRAINT "dfir_storage_objects_key_check" CHECK (octet_length("dfir_storage_objects"."object_key") between 38 and 1024 and "dfir_storage_objects"."object_key" like "dfir_storage_objects"."tenant_id"::text || '/%' and "dfir_storage_objects"."object_key" !~ '(^|/)\.\.?(/|$)' and "dfir_storage_objects"."object_key" !~ '[\\[:cntrl:]]'),
	CONSTRAINT "dfir_storage_objects_filename_check" CHECK (octet_length("dfir_storage_objects"."original_filename") between 1 and 255 and "dfir_storage_objects"."original_filename" !~ '[/\\[:cntrl:]]' and "dfir_storage_objects"."original_filename" not in ('.','..')),
	CONSTRAINT "dfir_storage_objects_content_shape_check" CHECK (("dfir_storage_objects"."content_sha256" is null and "dfir_storage_objects"."size_bytes" is null and "dfir_storage_objects"."detected_mime" is null and "dfir_storage_objects"."verified_at" is null) or (octet_length("dfir_storage_objects"."content_sha256") = 32 and "dfir_storage_objects"."size_bytes" between 0 and 5497558138880 and octet_length("dfir_storage_objects"."detected_mime") between 3 and 512 and "dfir_storage_objects"."verified_at" is not null)),
	CONSTRAINT "dfir_storage_objects_retention_check" CHECK ("dfir_storage_objects"."retention_until" is null or "dfir_storage_objects"."retention_until" >= "dfir_storage_objects"."created_at"),
	CONSTRAINT "dfir_storage_objects_version_check" CHECK ("dfir_storage_objects"."version" between 1 and 9223372036854775806),
	CONSTRAINT "dfir_storage_objects_timestamps_check" CHECK ("dfir_storage_objects"."updated_at" >= "dfir_storage_objects"."created_at" and ("dfir_storage_objects"."verified_at" is null or "dfir_storage_objects"."verified_at" between "dfir_storage_objects"."created_at" and "dfir_storage_objects"."updated_at"))
);
--> statement-breakpoint
ALTER TABLE "dfir_storage_objects" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "dfir_tasks" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"case_id" uuid NOT NULL,
	"title" text NOT NULL,
	"description" text DEFAULT '' NOT NULL,
	"status" "dfir_task_status" DEFAULT 'todo' NOT NULL,
	"priority" "dfir_task_priority" DEFAULT 'medium' NOT NULL,
	"assignee_user_id" uuid,
	"operator_team_id" uuid,
	"operator_team_epoch_id" uuid,
	"due_at" timestamp with time zone,
	"checklist" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"completed_at" timestamp with time zone,
	"completed_by_user_id" uuid,
	"completion_data" jsonb,
	"comment_ids" uuid[] DEFAULT ARRAY[]::uuid[] NOT NULL,
	"sla_instance_id" uuid,
	"created_by_membership_id" uuid NOT NULL,
	"updated_by_membership_id" uuid NOT NULL,
	"version" bigint DEFAULT 1 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "dfir_tasks_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "dfir_tasks_id_uuidv7_check" CHECK ((uuid_extract_version("dfir_tasks"."id") = 7) is true),
	CONSTRAINT "dfir_tasks_text_check" CHECK (octet_length("dfir_tasks"."title") between 1 and 512 and octet_length("dfir_tasks"."description") <= 16384),
	CONSTRAINT "dfir_tasks_assignment_check" CHECK ("dfir_tasks"."assignee_user_id" is null or ("dfir_tasks"."operator_team_id" is not null and "dfir_tasks"."operator_team_epoch_id" is not null)),
	CONSTRAINT "dfir_tasks_team_check" CHECK (("dfir_tasks"."operator_team_id" is null) = ("dfir_tasks"."operator_team_epoch_id" is null)),
	CONSTRAINT "dfir_tasks_completion_check" CHECK (("dfir_tasks"."status" in ('done','cancelled')) = ("dfir_tasks"."completed_at" is not null and "dfir_tasks"."completed_by_user_id" is not null) and ("dfir_tasks"."status" in ('done','cancelled') or "dfir_tasks"."completion_data" is null)),
	CONSTRAINT "dfir_tasks_collection_check" CHECK (jsonb_typeof("dfir_tasks"."checklist") = 'array' and jsonb_array_length("dfir_tasks"."checklist") <= 100 and pg_column_size("dfir_tasks"."checklist") <= 65536 and cardinality("dfir_tasks"."comment_ids") <= 1000 and ("dfir_tasks"."completion_data" is null or (jsonb_typeof("dfir_tasks"."completion_data") = 'object' and pg_column_size("dfir_tasks"."completion_data") <= 65536))),
	CONSTRAINT "dfir_tasks_version_check" CHECK ("dfir_tasks"."version" between 1 and 9223372036854775807),
	CONSTRAINT "dfir_tasks_timestamps_check" CHECK ("dfir_tasks"."updated_at" >= "dfir_tasks"."created_at" and ("dfir_tasks"."completed_at" is null or "dfir_tasks"."completed_at" between "dfir_tasks"."created_at" and "dfir_tasks"."updated_at"))
);
--> statement-breakpoint
ALTER TABLE "dfir_tasks" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "dfir_timeline_asset_links" (
	"tenant_id" uuid NOT NULL,
	"timeline_event_id" uuid NOT NULL,
	"asset_id" uuid NOT NULL,
	CONSTRAINT "dfir_timeline_asset_links_key" UNIQUE("tenant_id","timeline_event_id","asset_id")
);
--> statement-breakpoint
ALTER TABLE "dfir_timeline_asset_links" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "dfir_timeline_events" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"case_id" uuid NOT NULL,
	"event_time" timestamp with time zone NOT NULL,
	"ingested_at" timestamp with time zone NOT NULL,
	"original_timezone" text NOT NULL,
	"precision" "dfir_temporal_precision" NOT NULL,
	"source" text NOT NULL,
	"category" text NOT NULL,
	"title" text NOT NULL,
	"description" text DEFAULT '' NOT NULL,
	"actor_user_id" uuid,
	"tags" text[] DEFAULT ARRAY[]::text[] NOT NULL,
	"created_by_membership_id" uuid NOT NULL,
	"version" bigint DEFAULT 1 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "dfir_timeline_events_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "dfir_timeline_events_id_uuidv7_check" CHECK ((uuid_extract_version("dfir_timeline_events"."id") = 7) is true),
	CONSTRAINT "dfir_timeline_events_text_check" CHECK (octet_length("dfir_timeline_events"."original_timezone") between 1 and 128 and octet_length("dfir_timeline_events"."source") between 1 and 512 and "dfir_timeline_events"."category" ~ '^[a-z][a-z0-9_.-]{0,63}$' and octet_length("dfir_timeline_events"."title") between 1 and 512 and octet_length("dfir_timeline_events"."description") <= 16384),
	CONSTRAINT "dfir_timeline_events_tags_check" CHECK (cardinality("dfir_timeline_events"."tags") <= 256),
	CONSTRAINT "dfir_timeline_events_version_check" CHECK ("dfir_timeline_events"."version" > 0 and "dfir_timeline_events"."updated_at" >= "dfir_timeline_events"."created_at")
);
--> statement-breakpoint
ALTER TABLE "dfir_timeline_events" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "dfir_timeline_evidence_links" (
	"tenant_id" uuid NOT NULL,
	"timeline_event_id" uuid NOT NULL,
	"evidence_id" uuid NOT NULL,
	CONSTRAINT "dfir_timeline_evidence_links_key" UNIQUE("tenant_id","timeline_event_id","evidence_id")
);
--> statement-breakpoint
ALTER TABLE "dfir_timeline_evidence_links" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "dfir_timeline_ioc_links" (
	"tenant_id" uuid NOT NULL,
	"timeline_event_id" uuid NOT NULL,
	"ioc_id" uuid NOT NULL,
	CONSTRAINT "dfir_timeline_ioc_links_key" UNIQUE("tenant_id","timeline_event_id","ioc_id")
);
--> statement-breakpoint
ALTER TABLE "dfir_timeline_ioc_links" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "alerts" DROP CONSTRAINT "alerts_business_text_check";--> statement-breakpoint
ALTER TABLE "cases" DROP CONSTRAINT "cases_text_check";--> statement-breakpoint
ALTER TABLE "custom_field_definition_revisions" ADD CONSTRAINT "custom_field_definition_revisions_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "custom_field_definition_revisions" ADD CONSTRAINT "custom_field_definition_revisions_definition_fk" FOREIGN KEY ("tenant_id","definition_id") REFERENCES "public"."custom_field_definitions"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "custom_field_definition_revisions" ADD CONSTRAINT "custom_field_definition_revisions_creator_fk" FOREIGN KEY ("tenant_id","created_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "custom_field_definitions" ADD CONSTRAINT "custom_field_definitions_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "custom_field_definitions" ADD CONSTRAINT "custom_field_definitions_creator_fk" FOREIGN KEY ("tenant_id","created_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "custom_field_definitions" ADD CONSTRAINT "custom_field_definitions_updater_fk" FOREIGN KEY ("tenant_id","updated_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "custom_field_definitions" ADD CONSTRAINT "custom_field_definitions_archiver_fk" FOREIGN KEY ("tenant_id","archived_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "custom_field_layouts" ADD CONSTRAINT "custom_field_layouts_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "custom_field_layouts" ADD CONSTRAINT "custom_field_layouts_updater_fk" FOREIGN KEY ("tenant_id","updated_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "custom_field_migrations" ADD CONSTRAINT "custom_field_migrations_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "custom_field_migrations" ADD CONSTRAINT "custom_field_migrations_definition_fk" FOREIGN KEY ("tenant_id","definition_id") REFERENCES "public"."custom_field_definitions"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "custom_field_migrations" ADD CONSTRAINT "custom_field_migrations_creator_fk" FOREIGN KEY ("tenant_id","created_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "custom_field_options" ADD CONSTRAINT "custom_field_options_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "custom_field_options" ADD CONSTRAINT "custom_field_options_definition_fk" FOREIGN KEY ("tenant_id","definition_id") REFERENCES "public"."custom_field_definitions"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "custom_field_permissions" ADD CONSTRAINT "custom_field_permissions_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "custom_field_permissions" ADD CONSTRAINT "custom_field_permissions_definition_fk" FOREIGN KEY ("tenant_id","definition_id") REFERENCES "public"."custom_field_definitions"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "custom_field_values" ADD CONSTRAINT "custom_field_values_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "custom_field_values" ADD CONSTRAINT "custom_field_values_definition_fk" FOREIGN KEY ("tenant_id","definition_id") REFERENCES "public"."custom_field_definitions"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "custom_field_values" ADD CONSTRAINT "custom_field_values_definition_revision_fk" FOREIGN KEY ("tenant_id","definition_id","definition_schema_version") REFERENCES "public"."custom_field_definition_revisions"("tenant_id","definition_id","schema_version") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "custom_field_values" ADD CONSTRAINT "custom_field_values_alert_fk" FOREIGN KEY ("tenant_id","alert_id") REFERENCES "public"."alerts"("tenant_id","id") ON DELETE cascade ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "custom_field_values" ADD CONSTRAINT "custom_field_values_case_fk" FOREIGN KEY ("tenant_id","case_id") REFERENCES "public"."cases"("tenant_id","id") ON DELETE cascade ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "custom_field_values" ADD CONSTRAINT "custom_field_values_creator_fk" FOREIGN KEY ("tenant_id","created_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "custom_field_values" ADD CONSTRAINT "custom_field_values_updater_fk" FOREIGN KEY ("tenant_id","updated_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_activities" ADD CONSTRAINT "dfir_activities_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dfir_activities" ADD CONSTRAINT "dfir_activities_case_fk" FOREIGN KEY ("tenant_id","case_id") REFERENCES "public"."cases"("tenant_id","id") ON DELETE cascade ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_activities" ADD CONSTRAINT "dfir_activities_membership_fk" FOREIGN KEY ("tenant_id","actor_membership_id","actor_user_id") REFERENCES "public"."tenant_memberships"("tenant_id","id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_activities" ADD CONSTRAINT "dfir_activities_service_account_fk" FOREIGN KEY ("tenant_id","actor_service_account_id") REFERENCES "public"."tenant_service_accounts"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_asset_links" ADD CONSTRAINT "dfir_asset_links_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dfir_asset_links" ADD CONSTRAINT "dfir_asset_links_asset_fk" FOREIGN KEY ("tenant_id","asset_id") REFERENCES "public"."dfir_assets"("tenant_id","id") ON DELETE cascade ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_asset_links" ADD CONSTRAINT "dfir_asset_links_alert_fk" FOREIGN KEY ("tenant_id","alert_id") REFERENCES "public"."alerts"("tenant_id","id") ON DELETE cascade ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_asset_links" ADD CONSTRAINT "dfir_asset_links_case_fk" FOREIGN KEY ("tenant_id","case_id") REFERENCES "public"."cases"("tenant_id","id") ON DELETE cascade ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_asset_links" ADD CONSTRAINT "dfir_asset_links_creator_fk" FOREIGN KEY ("tenant_id","created_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_assets" ADD CONSTRAINT "dfir_assets_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dfir_assets" ADD CONSTRAINT "dfir_assets_creator_fk" FOREIGN KEY ("tenant_id","created_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_assets" ADD CONSTRAINT "dfir_assets_updater_fk" FOREIGN KEY ("tenant_id","updated_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_attachments" ADD CONSTRAINT "dfir_attachments_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dfir_attachments" ADD CONSTRAINT "dfir_attachments_alert_fk" FOREIGN KEY ("tenant_id","alert_id") REFERENCES "public"."alerts"("tenant_id","id") ON DELETE cascade ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_attachments" ADD CONSTRAINT "dfir_attachments_case_fk" FOREIGN KEY ("tenant_id","case_id") REFERENCES "public"."cases"("tenant_id","id") ON DELETE cascade ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_attachments" ADD CONSTRAINT "dfir_attachments_ioc_fk" FOREIGN KEY ("tenant_id","ioc_id") REFERENCES "public"."dfir_iocs"("tenant_id","id") ON DELETE cascade ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_attachments" ADD CONSTRAINT "dfir_attachments_asset_fk" FOREIGN KEY ("tenant_id","asset_id") REFERENCES "public"."dfir_assets"("tenant_id","id") ON DELETE cascade ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_attachments" ADD CONSTRAINT "dfir_attachments_evidence_fk" FOREIGN KEY ("tenant_id","evidence_id") REFERENCES "public"."dfir_evidence"("tenant_id","id") ON DELETE cascade ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_attachments" ADD CONSTRAINT "dfir_attachments_task_fk" FOREIGN KEY ("tenant_id","task_id") REFERENCES "public"."dfir_tasks"("tenant_id","id") ON DELETE cascade ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_attachments" ADD CONSTRAINT "dfir_attachments_storage_fk" FOREIGN KEY ("tenant_id","storage_object_id") REFERENCES "public"."dfir_storage_objects"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_attachments" ADD CONSTRAINT "dfir_attachments_uploader_fk" FOREIGN KEY ("tenant_id","uploaded_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_custody_events" ADD CONSTRAINT "dfir_custody_events_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dfir_custody_events" ADD CONSTRAINT "dfir_custody_events_evidence_fk" FOREIGN KEY ("tenant_id","evidence_id") REFERENCES "public"."dfir_evidence"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_custody_events" ADD CONSTRAINT "dfir_custody_events_membership_fk" FOREIGN KEY ("tenant_id","actor_membership_id","actor_user_id") REFERENCES "public"."tenant_memberships"("tenant_id","id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_custody_events" ADD CONSTRAINT "dfir_custody_events_service_account_fk" FOREIGN KEY ("tenant_id","actor_service_account_id") REFERENCES "public"."tenant_service_accounts"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_evidence" ADD CONSTRAINT "dfir_evidence_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dfir_evidence" ADD CONSTRAINT "dfir_evidence_case_fk" FOREIGN KEY ("tenant_id","case_id") REFERENCES "public"."cases"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_evidence" ADD CONSTRAINT "dfir_evidence_storage_fk" FOREIGN KEY ("tenant_id","storage_object_id") REFERENCES "public"."dfir_storage_objects"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_evidence" ADD CONSTRAINT "dfir_evidence_collector_fk" FOREIGN KEY ("tenant_id","collected_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_ioc_links" ADD CONSTRAINT "dfir_ioc_links_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dfir_ioc_links" ADD CONSTRAINT "dfir_ioc_links_ioc_fk" FOREIGN KEY ("tenant_id","ioc_id") REFERENCES "public"."dfir_iocs"("tenant_id","id") ON DELETE cascade ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_ioc_links" ADD CONSTRAINT "dfir_ioc_links_alert_fk" FOREIGN KEY ("tenant_id","alert_id") REFERENCES "public"."alerts"("tenant_id","id") ON DELETE cascade ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_ioc_links" ADD CONSTRAINT "dfir_ioc_links_case_fk" FOREIGN KEY ("tenant_id","case_id") REFERENCES "public"."cases"("tenant_id","id") ON DELETE cascade ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_ioc_links" ADD CONSTRAINT "dfir_ioc_links_creator_fk" FOREIGN KEY ("tenant_id","created_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_iocs" ADD CONSTRAINT "dfir_iocs_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dfir_iocs" ADD CONSTRAINT "dfir_iocs_creator_fk" FOREIGN KEY ("tenant_id","created_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_iocs" ADD CONSTRAINT "dfir_iocs_updater_fk" FOREIGN KEY ("tenant_id","updated_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_relationships" ADD CONSTRAINT "dfir_relationships_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dfir_relationships" ADD CONSTRAINT "dfir_relationships_creator_fk" FOREIGN KEY ("tenant_id","created_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_storage_objects" ADD CONSTRAINT "dfir_storage_objects_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dfir_storage_objects" ADD CONSTRAINT "dfir_storage_objects_creator_fk" FOREIGN KEY ("tenant_id","created_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_tasks" ADD CONSTRAINT "dfir_tasks_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dfir_tasks" ADD CONSTRAINT "dfir_tasks_case_fk" FOREIGN KEY ("tenant_id","case_id") REFERENCES "public"."cases"("tenant_id","id") ON DELETE cascade ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_tasks" ADD CONSTRAINT "dfir_tasks_assignee_fk" FOREIGN KEY ("tenant_id","assignee_user_id") REFERENCES "public"."tenant_memberships"("tenant_id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_tasks" ADD CONSTRAINT "dfir_tasks_team_epoch_fk" FOREIGN KEY ("tenant_id","operator_team_epoch_id","operator_team_id") REFERENCES "public"."operator_team_assignment_epochs"("tenant_id","id","operator_team_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_tasks" ADD CONSTRAINT "dfir_tasks_completer_fk" FOREIGN KEY ("tenant_id","completed_by_user_id") REFERENCES "public"."tenant_memberships"("tenant_id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_tasks" ADD CONSTRAINT "dfir_tasks_creator_fk" FOREIGN KEY ("tenant_id","created_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_tasks" ADD CONSTRAINT "dfir_tasks_updater_fk" FOREIGN KEY ("tenant_id","updated_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_timeline_asset_links" ADD CONSTRAINT "dfir_timeline_asset_links_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dfir_timeline_asset_links" ADD CONSTRAINT "dfir_timeline_asset_links_event_fk" FOREIGN KEY ("tenant_id","timeline_event_id") REFERENCES "public"."dfir_timeline_events"("tenant_id","id") ON DELETE cascade ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_timeline_asset_links" ADD CONSTRAINT "dfir_timeline_asset_links_asset_fk" FOREIGN KEY ("tenant_id","asset_id") REFERENCES "public"."dfir_assets"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_timeline_events" ADD CONSTRAINT "dfir_timeline_events_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dfir_timeline_events" ADD CONSTRAINT "dfir_timeline_events_case_fk" FOREIGN KEY ("tenant_id","case_id") REFERENCES "public"."cases"("tenant_id","id") ON DELETE cascade ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_timeline_events" ADD CONSTRAINT "dfir_timeline_events_actor_fk" FOREIGN KEY ("tenant_id","actor_user_id") REFERENCES "public"."tenant_memberships"("tenant_id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_timeline_events" ADD CONSTRAINT "dfir_timeline_events_creator_fk" FOREIGN KEY ("tenant_id","created_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_timeline_evidence_links" ADD CONSTRAINT "dfir_timeline_evidence_links_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dfir_timeline_evidence_links" ADD CONSTRAINT "dfir_timeline_evidence_links_event_fk" FOREIGN KEY ("tenant_id","timeline_event_id") REFERENCES "public"."dfir_timeline_events"("tenant_id","id") ON DELETE cascade ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_timeline_evidence_links" ADD CONSTRAINT "dfir_timeline_evidence_links_evidence_fk" FOREIGN KEY ("tenant_id","evidence_id") REFERENCES "public"."dfir_evidence"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_timeline_ioc_links" ADD CONSTRAINT "dfir_timeline_ioc_links_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dfir_timeline_ioc_links" ADD CONSTRAINT "dfir_timeline_ioc_links_event_fk" FOREIGN KEY ("tenant_id","timeline_event_id") REFERENCES "public"."dfir_timeline_events"("tenant_id","id") ON DELETE cascade ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_timeline_ioc_links" ADD CONSTRAINT "dfir_timeline_ioc_links_ioc_fk" FOREIGN KEY ("tenant_id","ioc_id") REFERENCES "public"."dfir_iocs"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
CREATE INDEX "custom_field_definitions_inventory_idx" ON "custom_field_definitions" USING btree ("tenant_id","object_type","archived_at","key","id");--> statement-breakpoint
CREATE INDEX "custom_field_migrations_status_idx" ON "custom_field_migrations" USING btree ("tenant_id","status","created_at","id");--> statement-breakpoint
CREATE INDEX "custom_field_options_inventory_idx" ON "custom_field_options" USING btree ("tenant_id","definition_id","position","id");--> statement-breakpoint
CREATE UNIQUE INDEX "custom_field_values_alert_definition_key" ON "custom_field_values" USING btree ("tenant_id","alert_id","definition_id") WHERE "custom_field_values"."alert_id" is not null;--> statement-breakpoint
CREATE UNIQUE INDEX "custom_field_values_case_definition_key" ON "custom_field_values" USING btree ("tenant_id","case_id","definition_id") WHERE "custom_field_values"."case_id" is not null;--> statement-breakpoint
CREATE INDEX "custom_field_values_definition_text_idx" ON "custom_field_values" USING btree ("tenant_id","definition_id","text_value","id");--> statement-breakpoint
CREATE INDEX "custom_field_values_definition_integer_idx" ON "custom_field_values" USING btree ("tenant_id","definition_id","integer_value","id");--> statement-breakpoint
CREATE INDEX "custom_field_values_definition_decimal_idx" ON "custom_field_values" USING btree ("tenant_id","definition_id","decimal_value","id");--> statement-breakpoint
CREATE INDEX "custom_field_values_definition_datetime_idx" ON "custom_field_values" USING btree ("tenant_id","definition_id","date_time_value","id");--> statement-breakpoint
CREATE INDEX "dfir_activities_case_idx" ON "dfir_activities" USING btree ("tenant_id","case_id","occurred_at","id");--> statement-breakpoint
CREATE UNIQUE INDEX "dfir_asset_links_alert_key" ON "dfir_asset_links" USING btree ("tenant_id","asset_id","alert_id") WHERE "dfir_asset_links"."alert_id" is not null;--> statement-breakpoint
CREATE UNIQUE INDEX "dfir_asset_links_case_key" ON "dfir_asset_links" USING btree ("tenant_id","asset_id","case_id") WHERE "dfir_asset_links"."case_id" is not null;--> statement-breakpoint
CREATE UNIQUE INDEX "dfir_assets_live_external_key" ON "dfir_assets" USING btree ("tenant_id","external_id") WHERE "dfir_assets"."external_id" is not null and "dfir_assets"."archived_at" is null;--> statement-breakpoint
CREATE INDEX "dfir_assets_inventory_idx" ON "dfir_assets" USING btree ("tenant_id","archived_at","criticality","updated_at","id");--> statement-breakpoint
CREATE INDEX "dfir_assets_hostname_idx" ON "dfir_assets" USING btree ("tenant_id","normalized_hostname","id");--> statement-breakpoint
CREATE INDEX "dfir_assets_fqdn_idx" ON "dfir_assets" USING btree ("tenant_id","normalized_fqdn","id");--> statement-breakpoint
CREATE INDEX "dfir_attachments_case_idx" ON "dfir_attachments" USING btree ("tenant_id","case_id","uploaded_at","id");--> statement-breakpoint
CREATE INDEX "dfir_attachments_alert_idx" ON "dfir_attachments" USING btree ("tenant_id","alert_id","uploaded_at","id");--> statement-breakpoint
CREATE INDEX "dfir_custody_events_evidence_idx" ON "dfir_custody_events" USING btree ("tenant_id","evidence_id","sequence");--> statement-breakpoint
CREATE INDEX "dfir_evidence_case_idx" ON "dfir_evidence" USING btree ("tenant_id","case_id","collected_at","id");--> statement-breakpoint
CREATE UNIQUE INDEX "dfir_ioc_links_alert_key" ON "dfir_ioc_links" USING btree ("tenant_id","ioc_id","alert_id") WHERE "dfir_ioc_links"."alert_id" is not null;--> statement-breakpoint
CREATE UNIQUE INDEX "dfir_ioc_links_case_key" ON "dfir_ioc_links" USING btree ("tenant_id","ioc_id","case_id") WHERE "dfir_ioc_links"."case_id" is not null;--> statement-breakpoint
CREATE UNIQUE INDEX "dfir_iocs_live_observable_key" ON "dfir_iocs" USING btree ("tenant_id","type","normalized_value") WHERE "dfir_iocs"."archived_at" is null;--> statement-breakpoint
CREATE INDEX "dfir_iocs_inventory_idx" ON "dfir_iocs" USING btree ("tenant_id","archived_at","type","updated_at","id");--> statement-breakpoint
CREATE INDEX "dfir_iocs_ip_idx" ON "dfir_iocs" USING btree ("tenant_id","ip_value","id");--> statement-breakpoint
CREATE INDEX "dfir_relationships_source_idx" ON "dfir_relationships" USING btree ("tenant_id","source_kind","source_id","created_at","id");--> statement-breakpoint
CREATE INDEX "dfir_relationships_target_idx" ON "dfir_relationships" USING btree ("tenant_id","target_kind","target_id","created_at","id");--> statement-breakpoint
CREATE INDEX "dfir_storage_objects_scan_queue_idx" ON "dfir_storage_objects" USING btree ("tenant_id","state","updated_at","id");--> statement-breakpoint
CREATE INDEX "dfir_tasks_case_status_idx" ON "dfir_tasks" USING btree ("tenant_id","case_id","status","due_at","id");--> statement-breakpoint
CREATE INDEX "dfir_tasks_assignee_idx" ON "dfir_tasks" USING btree ("tenant_id","assignee_user_id","status","id");--> statement-breakpoint
CREATE INDEX "dfir_timeline_events_case_time_idx" ON "dfir_timeline_events" USING btree ("tenant_id","case_id","event_time","id");--> statement-breakpoint
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_business_text_check" CHECK (btrim("alerts"."priority") <> '' and char_length("alerts"."priority") <= 64
        and btrim("alerts"."category") <> '' and char_length("alerts"."category") <= 120
        and btrim("alerts"."source") <> '' and char_length("alerts"."source") <= 120
        and "alerts"."source_type" ~ '^[a-z][a-z0-9_-]{0,79}$'
        and ("alerts"."classification" is null or char_length("alerts"."classification") <= 120)
        and ("alerts"."deduplication_key" is null or (btrim("alerts"."deduplication_key") <> '' and char_length("alerts"."deduplication_key") <= 240)));--> statement-breakpoint
ALTER TABLE "cases" ADD CONSTRAINT "cases_text_check" CHECK (char_length("cases"."description") <= 20000 and char_length("cases"."summary") <= 2000);--> statement-breakpoint
CREATE POLICY "custom_field_definition_revisions_api_tenant" ON "custom_field_definition_revisions" AS PERMISSIVE FOR ALL TO "periapsis_api" USING (
  "custom_field_definition_revisions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "custom_field_definition_revisions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "custom_field_definition_revisions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "custom_field_definition_revisions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "custom_field_definitions_api_tenant" ON "custom_field_definitions" AS PERMISSIVE FOR ALL TO "periapsis_api" USING (
  "custom_field_definitions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "custom_field_definitions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "custom_field_definitions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "custom_field_definitions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "custom_field_layouts_api_tenant" ON "custom_field_layouts" AS PERMISSIVE FOR ALL TO "periapsis_api" USING (
  "custom_field_layouts"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "custom_field_layouts"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "custom_field_layouts"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "custom_field_layouts"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "custom_field_migrations_api_tenant" ON "custom_field_migrations" AS PERMISSIVE FOR ALL TO "periapsis_api" USING (
  "custom_field_migrations"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "custom_field_migrations"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "custom_field_migrations"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "custom_field_migrations"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "custom_field_options_api_tenant" ON "custom_field_options" AS PERMISSIVE FOR ALL TO "periapsis_api" USING (
  "custom_field_options"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "custom_field_options"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "custom_field_options"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "custom_field_options"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "custom_field_permissions_api_tenant" ON "custom_field_permissions" AS PERMISSIVE FOR ALL TO "periapsis_api" USING (
  "custom_field_permissions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "custom_field_permissions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "custom_field_permissions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "custom_field_permissions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "custom_field_values_api_tenant" ON "custom_field_values" AS PERMISSIVE FOR ALL TO "periapsis_api" USING (
  "custom_field_values"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "custom_field_values"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "custom_field_values"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "custom_field_values"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "dfir_activities_api_tenant" ON "dfir_activities" AS PERMISSIVE FOR SELECT TO "periapsis_api" USING (
  "dfir_activities"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_activities"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "dfir_activities_worker_tenant" ON "dfir_activities" AS PERMISSIVE FOR SELECT TO "periapsis_worker" USING ("dfir_activities"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid);--> statement-breakpoint
CREATE POLICY "dfir_asset_links_api_tenant" ON "dfir_asset_links" AS PERMISSIVE FOR ALL TO "periapsis_api" USING (
  "dfir_asset_links"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_asset_links"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "dfir_asset_links"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_asset_links"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "dfir_assets_api_tenant" ON "dfir_assets" AS PERMISSIVE FOR ALL TO "periapsis_api" USING (
  "dfir_assets"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_assets"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "dfir_assets"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_assets"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "dfir_attachments_api_tenant" ON "dfir_attachments" AS PERMISSIVE FOR ALL TO "periapsis_api" USING (
  "dfir_attachments"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_attachments"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "dfir_attachments"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_attachments"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "dfir_custody_events_api_tenant" ON "dfir_custody_events" AS PERMISSIVE FOR SELECT TO "periapsis_api" USING (
  "dfir_custody_events"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_custody_events"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "dfir_custody_events_worker_tenant" ON "dfir_custody_events" AS PERMISSIVE FOR SELECT TO "periapsis_worker" USING ("dfir_custody_events"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid);--> statement-breakpoint
CREATE POLICY "dfir_evidence_api_tenant" ON "dfir_evidence" AS PERMISSIVE FOR ALL TO "periapsis_api" USING (
  "dfir_evidence"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_evidence"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "dfir_evidence"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_evidence"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "dfir_evidence_worker_tenant" ON "dfir_evidence" AS PERMISSIVE FOR ALL TO "periapsis_worker" USING ("dfir_evidence"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK ("dfir_evidence"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid);--> statement-breakpoint
CREATE POLICY "dfir_ioc_links_api_tenant" ON "dfir_ioc_links" AS PERMISSIVE FOR ALL TO "periapsis_api" USING (
  "dfir_ioc_links"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_ioc_links"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "dfir_ioc_links"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_ioc_links"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "dfir_iocs_api_tenant" ON "dfir_iocs" AS PERMISSIVE FOR ALL TO "periapsis_api" USING (
  "dfir_iocs"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_iocs"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "dfir_iocs"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_iocs"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "dfir_relationships_api_tenant" ON "dfir_relationships" AS PERMISSIVE FOR ALL TO "periapsis_api" USING (
  "dfir_relationships"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_relationships"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "dfir_relationships"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_relationships"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "dfir_storage_objects_api_tenant" ON "dfir_storage_objects" AS PERMISSIVE FOR ALL TO "periapsis_api" USING (
  "dfir_storage_objects"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_storage_objects"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "dfir_storage_objects"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_storage_objects"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "dfir_storage_objects_worker_tenant" ON "dfir_storage_objects" AS PERMISSIVE FOR ALL TO "periapsis_worker" USING ("dfir_storage_objects"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK ("dfir_storage_objects"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid);--> statement-breakpoint
CREATE POLICY "dfir_tasks_api_tenant" ON "dfir_tasks" AS PERMISSIVE FOR ALL TO "periapsis_api" USING (
  "dfir_tasks"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_tasks"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "dfir_tasks"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_tasks"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "dfir_timeline_asset_links_api_tenant" ON "dfir_timeline_asset_links" AS PERMISSIVE FOR ALL TO "periapsis_api" USING (
  "dfir_timeline_asset_links"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_timeline_asset_links"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "dfir_timeline_asset_links"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_timeline_asset_links"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "dfir_timeline_events_api_tenant" ON "dfir_timeline_events" AS PERMISSIVE FOR ALL TO "periapsis_api" USING (
  "dfir_timeline_events"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_timeline_events"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "dfir_timeline_events"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_timeline_events"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "dfir_timeline_evidence_links_api_tenant" ON "dfir_timeline_evidence_links" AS PERMISSIVE FOR ALL TO "periapsis_api" USING (
  "dfir_timeline_evidence_links"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_timeline_evidence_links"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "dfir_timeline_evidence_links"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_timeline_evidence_links"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
CREATE POLICY "dfir_timeline_ioc_links_api_tenant" ON "dfir_timeline_ioc_links" AS PERMISSIVE FOR ALL TO "periapsis_api" USING (
  "dfir_timeline_ioc_links"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_timeline_ioc_links"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "dfir_timeline_ioc_links"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_timeline_ioc_links"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);